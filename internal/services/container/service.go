// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package container provides container management services.
package container

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	configservice "github.com/fr4nsys/usulnet/internal/services/config"
	hostservice "github.com/fr4nsys/usulnet/internal/services/host"
)

// ServiceConfig contains container service configuration.
type ServiceConfig struct {
	// StopTimeout is the default timeout for stopping containers
	StopTimeout time.Duration

	// SyncInterval is how often to sync container state from Docker
	SyncInterval time.Duration

	// StatsRetention is how long to keep container stats
	StatsRetention time.Duration

	// LogRetention is how long to keep container logs in DB
	LogRetention time.Duration

	// MaxLogLines is the maximum log lines to store per container
	MaxLogLines int
}

// DefaultConfig returns default service configuration.
func DefaultConfig() ServiceConfig {
	return ServiceConfig{
		StopTimeout:    30 * time.Second,
		SyncInterval:   30 * time.Second,
		StatsRetention: 24 * time.Hour,
		LogRetention:   7 * 24 * time.Hour,
		MaxLogLines:    10000,
	}
}

// Service provides container management operations.
type Service struct {
	repo        *postgres.ContainerRepository
	hostService *hostservice.Service
	config      ServiceConfig
	logger        *logger.Logger
	configService *configservice.Service

	stopCh  chan struct{}
	stopped bool
}

// NewService creates a new container service.
func NewService(
	repo *postgres.ContainerRepository,
	hostService *hostservice.Service,
	config ServiceConfig,
	log *logger.Logger,
) *Service {
	if log == nil {
		log = logger.Nop()
	}

	return &Service{
		repo:        repo,
		hostService: hostService,
		config:      config,
		logger:      log.Named("container"),
		stopCh:      make(chan struct{}),
	}
}

// ============================================================================
// Lifecycle
// ============================================================================

// Start starts background workers.
func (s *Service) Start(ctx context.Context) error {
	s.logger.Info("starting container service",
		"sync_interval", s.config.SyncInterval,
	)

	// Start sync worker
	go s.syncWorker(ctx)

	// Start cleanup worker
	go s.cleanupWorker(ctx)

	return nil
}

// Stop stops the service.
func (s *Service) Stop() error {
	if s.stopped {
		return nil
	}
	s.stopped = true
	close(s.stopCh)
	s.logger.Info("container service stopped")
	return nil
}

// ============================================================================
// CRUD Operations
// ============================================================================

// List retrieves containers with filtering and pagination.
func (s *Service) List(ctx context.Context, opts postgres.ContainerListOptions) ([]*models.Container, int64, error) {
	return s.repo.List(ctx, opts)
}

// ListByHost retrieves all containers for a host.
func (s *Service) ListByHost(ctx context.Context, hostID uuid.UUID) ([]*models.Container, error) {
	return s.repo.ListByHost(ctx, hostID)
}

// Get retrieves a container by ID.
func (s *Service) Get(ctx context.Context, hostID uuid.UUID, containerID string) (*models.Container, error) {
	return s.repo.GetByHostAndID(ctx, hostID, containerID)
}

// GetByName retrieves a container by name.
func (s *Service) GetByName(ctx context.Context, hostID uuid.UUID, name string) (*models.Container, error) {
	return s.repo.GetByName(ctx, hostID, name)
}

// GetDockerClient returns the Docker client for the host.
// Returns docker.ClientAPI which may be a direct client or a remote agent proxy.
func (s *Service) GetDockerClient(ctx context.Context, hostID uuid.UUID) (docker.ClientAPI, error) {
	return s.hostService.GetClient(ctx, hostID)
}

// GetLive retrieves live container information directly from Docker.
func (s *Service) GetLive(ctx context.Context, hostID uuid.UUID, containerID string) (*models.Container, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	inspect, err := client.ContainerGet(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("inspect container: %w", err)
	}

	return s.detailsToContainerModel(hostID, inspect), nil
}

// ============================================================================
// Container Lifecycle Operations
// ============================================================================

// Start starts a container.
func (s *Service) StartContainer(ctx context.Context, hostID uuid.UUID, containerID string) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	if err := client.ContainerStart(ctx, containerID); err != nil {
		return fmt.Errorf("start container: %w", err)
	}

	// Update cached state
	s.repo.UpdateState(ctx, containerID, models.ContainerStateRunning, "Up")

	s.logger.Info("container started",
		"host_id", hostID,
		"container_id", containerID,
	)

	return nil
}

// Stop stops a container.
func (s *Service) StopContainer(ctx context.Context, hostID uuid.UUID, containerID string) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	timeout := int(s.config.StopTimeout.Seconds())
	if err := client.ContainerStop(ctx, containerID, &timeout); err != nil {
		return fmt.Errorf("stop container: %w", err)
	}

	// Update cached state
	s.repo.UpdateState(ctx, containerID, models.ContainerStateExited, "Exited")

	s.logger.Info("container stopped",
		"host_id", hostID,
		"container_id", containerID,
	)

	return nil
}

// Restart restarts a container.
func (s *Service) Restart(ctx context.Context, hostID uuid.UUID, containerID string) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	timeout := int(s.config.StopTimeout.Seconds())
	if err := client.ContainerRestart(ctx, containerID, &timeout); err != nil {
		return fmt.Errorf("restart container: %w", err)
	}

	// Update cached state
	s.repo.UpdateState(ctx, containerID, models.ContainerStateRunning, "Up")

	s.logger.Info("container restarted",
		"host_id", hostID,
		"container_id", containerID,
	)

	return nil
}

// Pause pauses a container.
func (s *Service) Pause(ctx context.Context, hostID uuid.UUID, containerID string) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	if err := client.ContainerPause(ctx, containerID); err != nil {
		return fmt.Errorf("pause container: %w", err)
	}

	s.repo.UpdateState(ctx, containerID, models.ContainerStatePaused, "Paused")

	s.logger.Info("container paused",
		"host_id", hostID,
		"container_id", containerID,
	)

	return nil
}

// Unpause unpauses a container.
func (s *Service) Unpause(ctx context.Context, hostID uuid.UUID, containerID string) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	if err := client.ContainerUnpause(ctx, containerID); err != nil {
		return fmt.Errorf("unpause container: %w", err)
	}

	s.repo.UpdateState(ctx, containerID, models.ContainerStateRunning, "Up")

	s.logger.Info("container unpaused",
		"host_id", hostID,
		"container_id", containerID,
	)

	return nil
}

// Kill kills a container.
func (s *Service) Kill(ctx context.Context, hostID uuid.UUID, containerID string, signal string) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	if signal == "" {
		signal = "SIGKILL"
	}

	if err := client.ContainerKill(ctx, containerID, signal); err != nil {
		return fmt.Errorf("kill container: %w", err)
	}

	s.logger.Info("container killed",
		"host_id", hostID,
		"container_id", containerID,
		"signal", signal,
	)

	return nil
}

// Remove removes a container.
func (s *Service) Remove(ctx context.Context, hostID uuid.UUID, containerID string, force bool, removeVolumes bool) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

if err := client.ContainerRemove(ctx, containerID, force, removeVolumes); err != nil {
		return fmt.Errorf("remove container: %w", err)
	}

	// Remove from cache
	s.repo.Delete(ctx, containerID)

	s.logger.Info("container removed",
		"host_id", hostID,
		"container_id", containerID,
		"force", force,
	)

	return nil
}

// ============================================================================
// Container Creation
// ============================================================================

// CreateInput contains parameters for creating a container.
type CreateInput struct {
	Name          string
	Image         string
	Env           []string
	Labels        map[string]string
	Ports         []models.ContainerPort
	Volumes       []models.ContainerMount
	Networks      []string
	RestartPolicy string
	Cmd           []string
	Entrypoint    []string
	WorkingDir    string
	User          string
	Hostname      string
	DomainName    string
	Privileged    bool
	NetworkMode   string
	// Resource limits
	MemoryLimit   int64
	MemorySwap    int64
	CPUShares     int64
	CPUQuota      int64
	CPUPeriod     int64
}

// Create creates a new container.
func (s *Service) Create(ctx context.Context, hostID uuid.UUID, input *CreateInput) (*models.Container, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	// Build port bindings
	portBindings := make(map[string][]docker.PortBinding)
	for _, p := range input.Ports {
		portKey := fmt.Sprintf("%d/%s", p.ContainerPort, p.Protocol)
		if p.HostPort > 0 {
			portBindings[portKey] = append(portBindings[portKey], docker.PortBinding{
				HostIP:   p.HostIP,
				HostPort: fmt.Sprintf("%d", p.HostPort),
			})
		}
	}

	// Build volume binds
	var binds []string
	for _, v := range input.Volumes {
		bind := fmt.Sprintf("%s:%s", v.Source, v.Target)
		if v.ReadOnly {
			bind += ":ro"
		}
		binds = append(binds, bind)
	}

	// Build create options
	createOpts := docker.ContainerCreateOptions{
		Name:         input.Name,
		Image:        input.Image,
		Cmd:          input.Cmd,
		Env:          input.Env,
		Labels:       input.Labels,
		WorkingDir:   input.WorkingDir,
		User:         input.User,
		Binds:        binds,
		PortBindings: portBindings,
		NetworkMode:  input.NetworkMode,
		Privileged:   input.Privileged,
		Memory:       input.MemoryLimit,
		MemorySwap:   input.MemorySwap,
		CPUShares:    input.CPUShares,
		CPUPeriod:    input.CPUPeriod,
		CPUQuota:     input.CPUQuota,
	}

	// Set restart policy
	if input.RestartPolicy != "" {
		createOpts.RestartPolicy = docker.RestartPolicy{
			Name: input.RestartPolicy,
		}
	}

	// Set network
	if len(input.Networks) > 0 {
		createOpts.NetworkID = input.Networks[0]
	}

	// Create container
	containerID, err := client.ContainerCreate(ctx, createOpts)
	if err != nil {
		return nil, fmt.Errorf("create container: %w", err)
	}

	// Get full container info
	details, err := client.ContainerGet(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("inspect created container: %w", err)
	}

	// Convert to model and cache
	containerModel := s.detailsToContainerModel(hostID, details)
	if err := s.repo.Upsert(ctx, containerModel); err != nil {
		s.logger.Warn("failed to cache created container", "error", err)
	}

	s.logger.Info("container created",
		"host_id", hostID,
		"container_id", containerID,
		"name", input.Name,
	)

	return containerModel, nil
}

// detailsToContainerModel converts ContainerDetails to Container model
func (s *Service) detailsToContainerModel(hostID uuid.UUID, d *docker.ContainerDetails) *models.Container {
	c := &models.Container{
		ID:     d.ID,
		HostID: hostID,
		Name:   d.Name,
		Image:  d.Image,
		Status: d.Status,
		State:  models.ContainerState(d.State),
		Labels: d.Labels,
	}
	if d.ImageID != "" {
		c.ImageID = &d.ImageID
	}
	if !d.Created.IsZero() {
		c.CreatedAtDocker = &d.Created
	}

	// Copy network attachments
	for _, n := range d.Networks {
		c.Networks = append(c.Networks, models.NetworkAttachment{
			NetworkID:   n.NetworkID,
			NetworkName: n.NetworkName,
			IPAddress:   n.IPAddress,
			Gateway:     n.Gateway,
			MacAddress:  n.MacAddress,
			Aliases:     n.Aliases,
		})
	}

	// Copy port mappings
	for _, p := range d.Ports {
		c.Ports = append(c.Ports, models.PortMapping{
			PrivatePort: p.PrivatePort,
			PublicPort:  p.PublicPort,
			Type:        p.Type,
			IP:          p.IP,
		})
	}

	// Copy mount points
	for _, m := range d.Mounts {
		c.Mounts = append(c.Mounts, models.MountPoint{
			Type:        m.Type,
			Source:      m.Source,
			Destination: m.Destination,
			Mode:        m.Mode,
			RW:          m.RW,
			Propagation: m.Propagation,
		})
	}

	return c
}


// ============================================================================
// Container Recreation (for updates)
// ============================================================================

// RecreateOptions contains options for recreating a container.
type RecreateOptions struct {
	// PullImage pulls the image before recreating
	PullImage bool
	// ImageTag is the new image tag (defaults to current)
	ImageTag string
	// PreserveName keeps the same name
	PreserveName bool
	// CreateBackup creates a snapshot before recreating
	CreateBackup bool
}

// Recreate recreates a container with a new image (used for updates).
// Based on Portainer's recreate pattern.
func (s *Service) Recreate(ctx context.Context, hostID uuid.UUID, containerID string, opts RecreateOptions) (*models.Container, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	// Get current container info
	oldDetails, err := client.ContainerGet(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("inspect container: %w", err)
	}

	// Determine new image
	newImage := oldDetails.Image
	if opts.ImageTag != "" {
		newImage = opts.ImageTag
	}

	// Pull new image if requested
	if opts.PullImage {
		s.logger.Info("pulling image for recreate", "image", newImage)
		if err := client.ImagePullSync(ctx, newImage, docker.ImagePullOptions{}); err != nil {
			return nil, fmt.Errorf("pull image: %w", err)
		}
	}

	// Store old container name for restore
	oldName := strings.TrimPrefix(oldDetails.Name, "/")

	// Rename old container (to avoid name conflict)
	tempName := fmt.Sprintf("%s-old-%d", oldName, time.Now().Unix())
	if err := client.ContainerRename(ctx, containerID, tempName); err != nil {
		return nil, fmt.Errorf("rename old container: %w", err)
	}

	// Stop old container if running
	wasRunning := oldDetails.State == "running"
	if wasRunning {
		timeout := int(s.config.StopTimeout.Seconds())
		if err := client.ContainerStop(ctx, containerID, &timeout); err != nil {
			client.ContainerRename(ctx, containerID, oldName)
			return nil, fmt.Errorf("stop old container: %w", err)
		}
	}

	// Get container name for new container
	containerName := oldName
	if !opts.PreserveName {
		containerName = fmt.Sprintf("%s-%d", oldName, time.Now().Unix())
	}

	// Build port bindings from old container
	portBindings := make(map[string][]docker.PortBinding)
	for _, p := range oldDetails.Ports {
		key := fmt.Sprintf("%d/%s", p.PrivatePort, p.Type)
		if p.PublicPort > 0 {
			portBindings[key] = append(portBindings[key], docker.PortBinding{
				HostIP:   p.IP,
				HostPort: fmt.Sprintf("%d", p.PublicPort),
			})
		}
	}

	// Build create options
	createOpts := docker.ContainerCreateOptions{
		Name:         containerName,
		Image:        newImage,
		Labels:       oldDetails.Labels,
		PortBindings: portBindings,
	}

	// Preserve binds, devices, and other host config
	if oldDetails.HostConfig != nil {
		createOpts.Binds = oldDetails.HostConfig.Binds
		createOpts.NetworkMode = oldDetails.HostConfig.NetworkMode
		createOpts.Privileged = oldDetails.HostConfig.Privileged
		createOpts.Devices = oldDetails.HostConfig.Devices
	}

	// Preserve env, cmd, and hostname from config
	if oldDetails.Config != nil {
		createOpts.Env = oldDetails.Config.Env
		createOpts.Cmd = oldDetails.Config.Cmd
		createOpts.WorkingDir = oldDetails.Config.WorkingDir
		createOpts.User = oldDetails.Config.User
		createOpts.Hostname = oldDetails.Config.Hostname
	}

	// Create new container
	newContainerID, err := client.ContainerCreate(ctx, createOpts)
	if err != nil {
		client.ContainerRename(ctx, containerID, oldName)
		if wasRunning {
			client.ContainerStart(ctx, containerID)
		}
		return nil, fmt.Errorf("create new container: %w", err)
	}

	// Connect to networks
	for _, net := range oldDetails.Networks {
		if net.NetworkName == "bridge" || net.NetworkName == "host" || net.NetworkName == "none" {
			continue
		}
		err := client.NetworkConnect(ctx, net.NetworkID, docker.NetworkConnectOptions{
			ContainerID: newContainerID,
		})
		if err != nil {
			s.logger.Warn("failed to connect network", "network", net.NetworkName, "error", err)
		}
	}

	// Start new container if old was running
	if wasRunning {
		if err := client.ContainerStart(ctx, newContainerID); err != nil {
			client.ContainerRemove(ctx, newContainerID, true, false)
			client.ContainerRename(ctx, containerID, oldName)
			client.ContainerStart(ctx, containerID)
			return nil, fmt.Errorf("start new container: %w", err)
		}
	}

	// Remove old container
	if err := client.ContainerRemove(ctx, containerID, true, true); err != nil {
		s.logger.Warn("failed to remove old container", "container", containerID, "error", err)
	}

	// Get new container info
	newDetails, err := client.ContainerGet(ctx, newContainerID)
	if err != nil {
		return nil, fmt.Errorf("inspect new container: %w", err)
	}

	containerModel := s.detailsToContainerModel(hostID, newDetails)
	if err := s.repo.Upsert(ctx, containerModel); err != nil {
		s.logger.Warn("failed to cache recreated container", "error", err)
	}

	s.logger.Info("container recreated",
		"host_id", hostID,
		"old_id", containerID,
		"new_id", newContainerID,
		"image", newImage,
	)

	return containerModel, nil
}


// ============================================================================
// Logs
// ============================================================================

// LogOptions contains options for retrieving logs.
type LogOptions struct {
	Stdout     bool
	Stderr     bool
	Since      string
	Until      string
	Timestamps bool
	Follow     bool
	Tail       string
}

// GetLogs retrieves container logs.
func (s *Service) GetLogs(ctx context.Context, hostID uuid.UUID, containerID string, opts LogOptions) (io.ReadCloser, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	dockerOpts := docker.LogOptions{
		Stdout: opts.Stdout,
		Stderr: opts.Stderr,
		Since:      opts.Since,
		Until:      opts.Until,
		Timestamps: opts.Timestamps,
		Follow:     opts.Follow,
		Tail:       opts.Tail,
	}

	return client.ContainerLogs(ctx, containerID, dockerOpts)
}

// ============================================================================
// Stats
// ============================================================================

// GetStats retrieves live container stats.
func (s *Service) GetStats(ctx context.Context, hostID uuid.UUID, containerID string) (*models.ContainerStats, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	stats, err := client.ContainerStatsOnce(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("get container stats: %w", err)
	}

	return &models.ContainerStats{
		ContainerID:    containerID,
		HostID:         hostID,
		CPUPercent:     stats.CPUPercent,
		MemoryUsage:    int64(stats.MemoryUsage),
		MemoryLimit:    int64(stats.MemoryLimit),
		MemoryPercent:  stats.MemoryPercent,
		NetworkRxBytes: int64(stats.NetworkRx),
		NetworkTxBytes: int64(stats.NetworkTx),
		BlockRead:      int64(stats.BlockRead),
		BlockWrite:     int64(stats.BlockWrite),
		PIDs:           int(stats.PIDs),
		CollectedAt:    time.Now().UTC(),
	}, nil
}

// GetStatsHistory retrieves cached stats history.
func (s *Service) GetStatsHistory(ctx context.Context, containerID string, since time.Time, limit int) ([]*models.ContainerStats, error) {
	return s.repo.GetStatsHistory(ctx, containerID, since, limit)
}

// ============================================================================
// Exec
// ============================================================================

// ExecConfig contains exec configuration.
type ExecConfig struct {
	Cmd          []string
	AttachStdin  bool
	AttachStdout bool
	AttachStderr bool
	Tty          bool
	Env          []string
	WorkingDir   string
	User         string
	Privileged   bool
}

// ExecCreate creates an exec instance.
func (s *Service) ExecCreate(ctx context.Context, hostID uuid.UUID, containerID string, config ExecConfig) (string, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return "", err
	}

	execConfig := docker.ExecConfig{
		Cmd:          config.Cmd,
		AttachStdin:  config.AttachStdin,
		AttachStdout: config.AttachStdout,
		AttachStderr: config.AttachStderr,
		Tty:          config.Tty,
		Env:          config.Env,
		WorkingDir:   config.WorkingDir,
		User:         config.User,
		Privileged:   config.Privileged,
	}

	resp, err := client.ExecCreate(ctx, containerID, execConfig)
	if err != nil {
		return "", fmt.Errorf("create exec: %w", err)
	}

	return resp.ID, nil
}

// ============================================================================
// Sync Operations
// ============================================================================

// SyncHost synchronizes container state for a host.
func (s *Service) SyncHost(ctx context.Context, hostID uuid.UUID) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	// List all containers from Docker
	containers, err := client.ContainerList(ctx, docker.ContainerListOptions{All: true})
	if err != nil {
		return fmt.Errorf("list containers: %w", err)
	}

	// Get current cached IDs
	cachedIDs, err := s.repo.GetContainerIDs(ctx, hostID)
	if err != nil {
		s.logger.Warn("failed to get cached container IDs", "error", err)
		cachedIDs = []string{}
	}

	// Build set of current IDs
	currentIDs := make(map[string]bool)
	for _, c := range containers {
		currentIDs[c.ID] = true
	}

	// Find containers to remove from cache (no longer exist in Docker)
	for _, id := range cachedIDs {
		if !currentIDs[id] {
			s.repo.Delete(ctx, id)
		}
	}

	// Upsert all current containers
	for _, c := range containers {
		inspect, err := client.ContainerGet(ctx, c.ID)
		if err != nil {
			s.logger.Warn("failed to inspect container during sync",
				"container_id", c.ID,
				"error", err,
			)
			continue
		}

		model := s.detailsToContainerModel(hostID, inspect)
		if err := s.repo.Upsert(ctx, model); err != nil {
			s.logger.Warn("failed to upsert container during sync",
				"container_id", c.ID,
				"error", err,
			)
		}
	}

	s.logger.Debug("host containers synced",
		"host_id", hostID,
		"count", len(containers),
	)

	return nil
}

// ============================================================================
// Filters & Search
// ============================================================================

// ListWithUpdates retrieves containers with available updates.
func (s *Service) ListWithUpdates(ctx context.Context, hostID *uuid.UUID) ([]*models.Container, error) {
	return s.repo.ListWithUpdatesAvailable(ctx, hostID)
}

// ListBySecurityGrade retrieves containers by security grade.
func (s *Service) ListBySecurityGrade(ctx context.Context, grade string, hostID *uuid.UUID) ([]*models.Container, error) {
	return s.repo.ListBySecurityGrade(ctx, grade, hostID)
}

// GetStats retrieves container statistics.
func (s *Service) GetContainerStats(ctx context.Context, hostID *uuid.UUID) (*postgres.ContainerStats, error) {
	return s.repo.GetStats(ctx, hostID)
}

// ============================================================================
// Internal Methods
// ============================================================================

func parseDockerTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

func (s *Service) syncWorker(ctx context.Context) {
	if s.config.SyncInterval <= 0 {
		return
	}

	ticker := time.NewTicker(s.config.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.syncAllHosts(ctx)
		}
	}
}

func (s *Service) syncAllHosts(ctx context.Context) {
	hosts, _, err := s.hostService.List(ctx, postgres.HostListOptions{Status: "online"})
	if err != nil {
		s.logger.Error("failed to list online hosts for sync", "error", err)
		return
	}

	for _, host := range hosts {
		if err := s.SyncHost(ctx, host.ID); err != nil {
			s.logger.Warn("failed to sync host containers",
				"host_id", host.ID,
				"error", err,
			)
		}
	}
}

func (s *Service) cleanupWorker(ctx context.Context) {
	if s.config.StatsRetention <= 0 && s.config.LogRetention <= 0 {
		return
	}

	// Run cleanup daily
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			// Cleanup old stats
			if s.config.StatsRetention > 0 {
				count, err := s.repo.DeleteOldStats(ctx, s.config.StatsRetention)
				if err != nil {
					s.logger.Error("failed to cleanup old stats", "error", err)
				} else if count > 0 {
					s.logger.Info("cleaned up old container stats", "count", count)
				}
			}

			// Cleanup old logs
			if s.config.LogRetention > 0 {
				count, err := s.repo.DeleteOldLogs(ctx, s.config.LogRetention)
				if err != nil {
					s.logger.Error("failed to cleanup old logs", "error", err)
				} else if count > 0 {
					s.logger.Info("cleaned up old container logs", "count", count)
				}
			}
		}
	}
}

// ============================================================================
// Filters by label
// ============================================================================

// ListByLabel retrieves containers with a specific label.
func (s *Service) ListByLabel(ctx context.Context, hostID uuid.UUID, key, value string) ([]*models.Container, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	filterMap := map[string][]string{
		"label": {fmt.Sprintf("%s=%s", key, value)},
	}

	containers, err := client.ContainerList(ctx, docker.ContainerListOptions{
		All:     true,
		Filters: filterMap,
	})
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	var result []*models.Container
	for _, c := range containers {
		inspect, err := client.ContainerGet(ctx, c.ID)
		if err != nil {
			continue
		}
		result = append(result, s.detailsToContainerModel(hostID, inspect))
	}

	return result, nil
}

// ============================================================================
// Prune
// ============================================================================

// ============================================================================
// Bulk Operations
// ============================================================================

// BulkOperationResult represents the result of a bulk operation.
type BulkOperationResult struct {
	ContainerID string `json:"container_id"`
	Name        string `json:"name"`
	Success     bool   `json:"success"`
	Error       string `json:"error,omitempty"`
}

// BulkOperationResults represents the results of a bulk operation.
type BulkOperationResults struct {
	Total      int                    `json:"total"`
	Successful int                    `json:"successful"`
	Failed     int                    `json:"failed"`
	Results    []BulkOperationResult  `json:"results"`
}

// BulkStart starts multiple containers.
func (s *Service) BulkStart(ctx context.Context, hostID uuid.UUID, containerIDs []string) (*BulkOperationResults, error) {
	results := &BulkOperationResults{
		Total:   len(containerIDs),
		Results: make([]BulkOperationResult, 0, len(containerIDs)),
	}

	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	for _, id := range containerIDs {
		result := BulkOperationResult{ContainerID: id}

		// Get container name for better error reporting
		if c, err := s.Get(ctx, hostID, id); err == nil && c != nil {
			result.Name = c.Name
		}

		if err := client.ContainerStart(ctx, id); err != nil {
			result.Success = false
			result.Error = err.Error()
			results.Failed++
		} else {
			result.Success = true
			results.Successful++
			s.repo.UpdateState(ctx, id, models.ContainerStateRunning, "Up")
		}
		results.Results = append(results.Results, result)
	}

	s.logger.Info("bulk start completed",
		"host_id", hostID,
		"total", results.Total,
		"successful", results.Successful,
		"failed", results.Failed,
	)

	return results, nil
}

// BulkStop stops multiple containers.
func (s *Service) BulkStop(ctx context.Context, hostID uuid.UUID, containerIDs []string) (*BulkOperationResults, error) {
	results := &BulkOperationResults{
		Total:   len(containerIDs),
		Results: make([]BulkOperationResult, 0, len(containerIDs)),
	}

	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	timeout := int(s.config.StopTimeout.Seconds())

	for _, id := range containerIDs {
		result := BulkOperationResult{ContainerID: id}

		if c, err := s.Get(ctx, hostID, id); err == nil && c != nil {
			result.Name = c.Name
		}

		if err := client.ContainerStop(ctx, id, &timeout); err != nil {
			result.Success = false
			result.Error = err.Error()
			results.Failed++
		} else {
			result.Success = true
			results.Successful++
			s.repo.UpdateState(ctx, id, models.ContainerStateExited, "Exited")
		}
		results.Results = append(results.Results, result)
	}

	s.logger.Info("bulk stop completed",
		"host_id", hostID,
		"total", results.Total,
		"successful", results.Successful,
		"failed", results.Failed,
	)

	return results, nil
}

// BulkRestart restarts multiple containers.
func (s *Service) BulkRestart(ctx context.Context, hostID uuid.UUID, containerIDs []string) (*BulkOperationResults, error) {
	results := &BulkOperationResults{
		Total:   len(containerIDs),
		Results: make([]BulkOperationResult, 0, len(containerIDs)),
	}

	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	timeout := int(s.config.StopTimeout.Seconds())

	for _, id := range containerIDs {
		result := BulkOperationResult{ContainerID: id}

		if c, err := s.Get(ctx, hostID, id); err == nil && c != nil {
			result.Name = c.Name
		}

		if err := client.ContainerRestart(ctx, id, &timeout); err != nil {
			result.Success = false
			result.Error = err.Error()
			results.Failed++
		} else {
			result.Success = true
			results.Successful++
			s.repo.UpdateState(ctx, id, models.ContainerStateRunning, "Up")
		}
		results.Results = append(results.Results, result)
	}

	s.logger.Info("bulk restart completed",
		"host_id", hostID,
		"total", results.Total,
		"successful", results.Successful,
		"failed", results.Failed,
	)

	return results, nil
}

// BulkPause pauses multiple containers.
func (s *Service) BulkPause(ctx context.Context, hostID uuid.UUID, containerIDs []string) (*BulkOperationResults, error) {
	results := &BulkOperationResults{
		Total:   len(containerIDs),
		Results: make([]BulkOperationResult, 0, len(containerIDs)),
	}

	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	for _, id := range containerIDs {
		result := BulkOperationResult{ContainerID: id}

		if c, err := s.Get(ctx, hostID, id); err == nil && c != nil {
			result.Name = c.Name
		}

		if err := client.ContainerPause(ctx, id); err != nil {
			result.Success = false
			result.Error = err.Error()
			results.Failed++
		} else {
			result.Success = true
			results.Successful++
			s.repo.UpdateState(ctx, id, models.ContainerStatePaused, "Paused")
		}
		results.Results = append(results.Results, result)
	}

	s.logger.Info("bulk pause completed",
		"host_id", hostID,
		"total", results.Total,
		"successful", results.Successful,
		"failed", results.Failed,
	)

	return results, nil
}

// BulkUnpause unpauses multiple containers.
func (s *Service) BulkUnpause(ctx context.Context, hostID uuid.UUID, containerIDs []string) (*BulkOperationResults, error) {
	results := &BulkOperationResults{
		Total:   len(containerIDs),
		Results: make([]BulkOperationResult, 0, len(containerIDs)),
	}

	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	for _, id := range containerIDs {
		result := BulkOperationResult{ContainerID: id}

		if c, err := s.Get(ctx, hostID, id); err == nil && c != nil {
			result.Name = c.Name
		}

		if err := client.ContainerUnpause(ctx, id); err != nil {
			result.Success = false
			result.Error = err.Error()
			results.Failed++
		} else {
			result.Success = true
			results.Successful++
			s.repo.UpdateState(ctx, id, models.ContainerStateRunning, "Up")
		}
		results.Results = append(results.Results, result)
	}

	s.logger.Info("bulk unpause completed",
		"host_id", hostID,
		"total", results.Total,
		"successful", results.Successful,
		"failed", results.Failed,
	)

	return results, nil
}

// BulkRemove removes multiple containers.
func (s *Service) BulkRemove(ctx context.Context, hostID uuid.UUID, containerIDs []string, force bool, removeVolumes bool) (*BulkOperationResults, error) {
	results := &BulkOperationResults{
		Total:   len(containerIDs),
		Results: make([]BulkOperationResult, 0, len(containerIDs)),
	}

	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	for _, id := range containerIDs {
		result := BulkOperationResult{ContainerID: id}

		if c, err := s.Get(ctx, hostID, id); err == nil && c != nil {
			result.Name = c.Name
		}

		if err := client.ContainerRemove(ctx, id, force, removeVolumes); err != nil {
			result.Success = false
			result.Error = err.Error()
			results.Failed++
		} else {
			result.Success = true
			results.Successful++
			s.repo.Delete(ctx, id)
		}
		results.Results = append(results.Results, result)
	}

	s.logger.Info("bulk remove completed",
		"host_id", hostID,
		"total", results.Total,
		"successful", results.Successful,
		"failed", results.Failed,
		"force", force,
	)

	return results, nil
}

// BulkKill kills multiple containers.
func (s *Service) BulkKill(ctx context.Context, hostID uuid.UUID, containerIDs []string, signal string) (*BulkOperationResults, error) {
	results := &BulkOperationResults{
		Total:   len(containerIDs),
		Results: make([]BulkOperationResult, 0, len(containerIDs)),
	}

	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	if signal == "" {
		signal = "SIGKILL"
	}

	for _, id := range containerIDs {
		result := BulkOperationResult{ContainerID: id}

		if c, err := s.Get(ctx, hostID, id); err == nil && c != nil {
			result.Name = c.Name
		}

		if err := client.ContainerKill(ctx, id, signal); err != nil {
			result.Success = false
			result.Error = err.Error()
			results.Failed++
		} else {
			result.Success = true
			results.Successful++
		}
		results.Results = append(results.Results, result)
	}

	s.logger.Info("bulk kill completed",
		"host_id", hostID,
		"total", results.Total,
		"successful", results.Successful,
		"failed", results.Failed,
		"signal", signal,
	)

	return results, nil
}

// Prune removes stopped containers.
func (s *Service) Prune(ctx context.Context, hostID uuid.UUID) (int64, uint64, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return 0, 0, err
	}

	spaceReclaimed, deletedIDs, err := client.ContainerPrune(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("prune containers: %w", err)
	}

	// Remove from cache
	for _, id := range deletedIDs {
		s.repo.Delete(ctx, id)
	}

	s.logger.Info("containers pruned",
		"host_id", hostID,
		"count", len(deletedIDs),
		"space_reclaimed", spaceReclaimed,
	)

	return int64(len(deletedIDs)), spaceReclaimed, nil
}

// ============================================================================
// File Copy Operations
// ============================================================================

// CopyToContainer copies content to a container at the specified path.
// The content should be a tar archive.
func (s *Service) CopyToContainer(ctx context.Context, hostID uuid.UUID, containerID, dstPath string, content io.Reader) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	if err := client.ContainerCopyToContainer(ctx, containerID, dstPath, content); err != nil {
		return fmt.Errorf("copy to container: %w", err)
	}

	s.logger.Debug("copied content to container",
		"host_id", hostID,
		"container_id", containerID,
		"dst_path", dstPath,
	)

	return nil
}

// CopyFromContainer copies content from a container at the specified path.
// Returns a tar archive reader and file stat information.
func (s *Service) CopyFromContainer(ctx context.Context, hostID uuid.UUID, containerID, srcPath string) (io.ReadCloser, *models.ContainerPathStat, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, nil, err
	}

	reader, stat, err := client.ContainerCopyFromContainer(ctx, containerID, srcPath)
	if err != nil {
		return nil, nil, fmt.Errorf("copy from container: %w", err)
	}

	s.logger.Debug("copied content from container",
		"host_id", hostID,
		"container_id", containerID,
		"src_path", srcPath,
		"name", stat.Name,
		"size", stat.Size,
	)

	pathStat := &models.ContainerPathStat{
		Name:       stat.Name,
		Size:       stat.Size,
		Mode:       uint32(stat.Mode),
		Mtime:      stat.Mtime,
		LinkTarget: stat.LinkTarget,
	}

	return reader, pathStat, nil
}

// ============================================================================
// Container Update Operations
// ============================================================================

// ResourceUpdateInput contains resource limits to update on a running container.
type ResourceUpdateInput struct {
	Memory            int64  `json:"memory,omitempty"`             // Memory limit in bytes
	MemorySwap        int64  `json:"memory_swap,omitempty"`        // Total memory (memory + swap), -1 for unlimited
	MemoryReservation int64  `json:"memory_reservation,omitempty"` // Soft memory limit
	NanoCPUs          int64  `json:"nano_cpus,omitempty"`          // CPU quota in units of 10^-9 CPUs
	CPUShares         int64  `json:"cpu_shares,omitempty"`         // CPU shares (relative weight)
	CPUPeriod         int64  `json:"cpu_period,omitempty"`         // CPU CFS period (microseconds)
	CPUQuota          int64  `json:"cpu_quota,omitempty"`          // CPU CFS quota (microseconds)
	CpusetCpus        string `json:"cpuset_cpus,omitempty"`        // CPUs in which to allow execution (e.g., "0-3", "0,1")
	CpusetMems        string `json:"cpuset_mems,omitempty"`        // MEMs in which to allow execution
	PidsLimit         *int64 `json:"pids_limit,omitempty"`         // PIDs limit
}

// UpdateResources updates a container's resource limits without restarting.
func (s *Service) UpdateResources(ctx context.Context, hostID uuid.UUID, containerID string, input ResourceUpdateInput) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	resources := docker.Resources{
		Memory:            input.Memory,
		MemorySwap:        input.MemorySwap,
		MemoryReservation: input.MemoryReservation,
		NanoCPUs:          input.NanoCPUs,
		CPUShares:         input.CPUShares,
		CPUPeriod:         input.CPUPeriod,
		CPUQuota:          input.CPUQuota,
		CpusetCpus:        input.CpusetCpus,
		CpusetMems:        input.CpusetMems,
		PidsLimit:         input.PidsLimit,
	}

	if err := client.ContainerUpdate(ctx, containerID, resources); err != nil {
		return fmt.Errorf("update container resources: %w", err)
	}

	s.logger.Info("container resources updated",
		"host_id", hostID,
		"container_id", containerID,
		"memory", input.Memory,
		"nano_cpus", input.NanoCPUs,
	)

	return nil
}

// UpdateSecurityInfo updates the security score and grade for a container.
func (s *Service) UpdateSecurityInfo(ctx context.Context, containerID string, score int, grade string) error {
	if s.repo == nil {
		return nil
	}
	return s.repo.UpdateSecurityInfo(ctx, containerID, score, grade)
}

// ============================================================================
// Container Commit Operations
// ============================================================================

// CommitInput contains options for committing a container to an image.
type CommitInput struct {
	Comment   string            `json:"comment,omitempty"`
	Author    string            `json:"author,omitempty"`
	Reference string            `json:"reference"` // image:tag
	Pause     bool              `json:"pause"`
	Changes   []string          `json:"changes,omitempty"` // Dockerfile instructions
	Labels    map[string]string `json:"labels,omitempty"`
}

// CommitResult contains the result of a container commit.
type CommitResult struct {
	ImageID string `json:"image_id"`
}

// Commit creates a new image from a container's changes.
func (s *Service) Commit(ctx context.Context, hostID uuid.UUID, containerID string, input CommitInput) (*CommitResult, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	imageID, err := client.ContainerCommit(ctx, containerID, docker.CommitOptions{
		Reference: input.Reference,
		Comment:   input.Comment,
		Author:    input.Author,
		Pause:     input.Pause,
		Changes:   input.Changes,
	})
	if err != nil {
		return nil, fmt.Errorf("commit container: %w", err)
	}

	s.logger.Info("container committed to image",
		"host_id", hostID,
		"container_id", containerID,
		"image_id", imageID,
		"reference", input.Reference,
	)

	return &CommitResult{ImageID: imageID}, nil
}

// ============================================================================
// Container Export/Import Operations
// ============================================================================

// Export exports a container's filesystem as a tar archive.
func (s *Service) Export(ctx context.Context, hostID uuid.UUID, containerID string) (io.ReadCloser, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	reader, err := client.ContainerExport(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("export container: %w", err)
	}

	s.logger.Info("container exported",
		"host_id", hostID,
		"container_id", containerID,
	)

	return reader, nil
}

// ImportInput contains parameters for importing a container filesystem as an image.
type ImportInput struct {
	// ImageRef is the reference for the new image (e.g., "myimage:latest")
	ImageRef string `json:"image_ref"`
	// Message is an optional commit message
	Message string `json:"message,omitempty"`
	// Changes are Dockerfile instructions to apply (e.g., ["CMD /bin/bash"])
	Changes []string `json:"changes,omitempty"`
}

// ImportResult contains the result of an import operation.
type ImportResult struct {
	ImageID string `json:"image_id"`
}

// Import imports a container filesystem tarball as an image.
func (s *Service) Import(ctx context.Context, hostID uuid.UUID, tarball io.Reader, input ImportInput) (*ImportResult, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	// Create import source from the tarball
	source := docker.ImageImportSource{
		Source:     tarball,
		SourceName: "-", // stdin
	}

	reader, err := client.ImageImport(ctx, source, input.ImageRef, input.Changes)
	if err != nil {
		return nil, fmt.Errorf("import container: %w", err)
	}
	defer reader.Close()

	// Read response to get image ID
	// The response is a JSON stream with progress info
	var imageID string
	decoder := json.NewDecoder(reader)
	for decoder.More() {
		var msg struct {
			Status   string `json:"status"`
			Progress string `json:"progress,omitempty"`
			ID       string `json:"id,omitempty"`
		}
		if err := decoder.Decode(&msg); err != nil {
			continue
		}
		if msg.ID != "" {
			imageID = msg.ID
		}
	}

	s.logger.Info("container filesystem imported as image",
		"host_id", hostID,
		"image_ref", input.ImageRef,
		"image_id", imageID,
	)

	return &ImportResult{
		ImageID: imageID,
	}, nil
}

// ============================================================================
// Container File Browser
// ============================================================================

// ContainerFile represents a file or directory in a container.
type ContainerFile struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	IsDir      bool      `json:"is_dir"`
	Size       int64     `json:"size"`
	SizeHuman  string    `json:"size_human"`
	Mode       string    `json:"mode"`
	ModTime    time.Time `json:"mod_time"`
	ModTimeAgo string    `json:"mod_time_ago"`
	Owner      string    `json:"owner"`
	Group      string    `json:"group"`
	LinkTarget string    `json:"link_target,omitempty"`
	IsSymlink  bool      `json:"is_symlink"`
}

// ContainerFileContent represents the content of a file in a container.
type ContainerFileContent struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	Size      int64  `json:"size"`
	Truncated bool   `json:"truncated"`
	Binary    bool   `json:"binary"`
}

const maxContainerFileSize = 1024 * 1024 // 1MB max for file content

// BrowseContainer lists files in a container at the given path.
func (s *Service) BrowseContainer(ctx context.Context, hostID uuid.UUID, containerID, path string) ([]ContainerFile, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	// Sanitize path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Use ls with specific options for parsing
	// -l: long format
	// -a: include hidden files
	// --time-style=+%Y-%m-%dT%H:%M:%S: ISO format for dates
	// We try GNU ls first, then fallback to basic ls
	output, exitCode, err := client.RunShellCommand(ctx, containerID,
		fmt.Sprintf("ls -la --time-style=+%%Y-%%m-%%dT%%H:%%M:%%S %q 2>/dev/null || ls -la %q", path, path))
	if err != nil {
		return nil, fmt.Errorf("list directory: %w", err)
	}
	if exitCode != 0 {
		return nil, fmt.Errorf("failed to list directory: %s", output)
	}

	return s.parseContainerLS(output, path), nil
}

// parseContainerLS parses the output of ls -la command.
func (s *Service) parseContainerLS(output, basePath string) []ContainerFile {
	var files []ContainerFile
	lines := strings.Split(strings.TrimSpace(output), "\n")
	now := time.Now()

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "total") {
			continue
		}

		// Parse ls -l output
		// Format: drwxr-xr-x  2 root root 4096 2024-01-15T10:30:00 filename
		// Or:     drwxr-xr-x  2 root root 4096 Jan 15 10:30 filename
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}

		mode := fields[0]
		owner := fields[2]
		group := fields[3]

		// Parse size
		var size int64
		fmt.Sscanf(fields[4], "%d", &size)

		// Parse filename (could contain spaces)
		var name string
		var modTime time.Time

		// Check if using ISO time format
		if len(fields) >= 6 && strings.Contains(fields[5], "T") {
			// ISO format: 2024-01-15T10:30:00
			modTime, _ = time.Parse("2006-01-02T15:04:05", fields[5])
			name = strings.Join(fields[6:], " ")
		} else if len(fields) >= 8 {
			// Traditional format: Jan 15 10:30 or Jan 15 2024
			dateStr := strings.Join(fields[5:8], " ")
			modTime, _ = time.Parse("Jan 2 15:04", dateStr)
			if modTime.IsZero() {
				modTime, _ = time.Parse("Jan 2 2006", dateStr)
			}
			if modTime.Year() == 0 {
				modTime = modTime.AddDate(now.Year(), 0, 0)
			}
			name = strings.Join(fields[8:], " ")
		}

		if name == "" || name == "." || name == ".." {
			continue
		}

		// Check for symlink
		var linkTarget string
		isSymlink := mode[0] == 'l'
		if isSymlink && strings.Contains(name, " -> ") {
			parts := strings.SplitN(name, " -> ", 2)
			name = parts[0]
			if len(parts) > 1 {
				linkTarget = parts[1]
			}
		}

		// Build full path
		fullPath := basePath
		if !strings.HasSuffix(fullPath, "/") {
			fullPath += "/"
		}
		fullPath += name

		files = append(files, ContainerFile{
			Name:       name,
			Path:       fullPath,
			IsDir:      mode[0] == 'd',
			Size:       size,
			SizeHuman:  humanizeSize(size),
			Mode:       mode,
			ModTime:    modTime,
			ModTimeAgo: timeAgo(modTime),
			Owner:      owner,
			Group:      group,
			LinkTarget: linkTarget,
			IsSymlink:  isSymlink,
		})
	}

	return files
}

// ReadContainerFile reads the content of a file in a container.
func (s *Service) ReadContainerFile(ctx context.Context, hostID uuid.UUID, containerID, path string, maxSize int64) (*ContainerFileContent, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	if maxSize <= 0 || maxSize > maxContainerFileSize {
		maxSize = maxContainerFileSize
	}

	// First check if the file exists and get its size
	statOutput, exitCode, err := client.RunShellCommand(ctx, containerID, fmt.Sprintf("stat -c '%%s' %q 2>/dev/null || stat -f '%%z' %q", path, path))
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}
	if exitCode != 0 {
		return nil, fmt.Errorf("file not found: %s", path)
	}

	var fileSize int64
	fmt.Sscanf(strings.TrimSpace(statOutput), "%d", &fileSize)

	// Check if file is too large
	truncated := fileSize > maxSize

	// Read file content using cat or head
	var cmd string
	if truncated {
		cmd = fmt.Sprintf("head -c %d %q", maxSize, path)
	} else {
		cmd = fmt.Sprintf("cat %q", path)
	}

	content, exitCode, err := client.RunShellCommand(ctx, containerID, cmd)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	if exitCode != 0 {
		return nil, fmt.Errorf("failed to read file: %s", content)
	}

	// Check if content appears binary (contains null bytes or high proportion of non-printable chars)
	binary := isBinaryContent(content)

	return &ContainerFileContent{
		Path:      path,
		Content:   content,
		Size:      fileSize,
		Truncated: truncated,
		Binary:    binary,
	}, nil
}

// WriteContainerFile writes content to a file in a container.
func (s *Service) WriteContainerFile(ctx context.Context, hostID uuid.UUID, containerID, path, content string) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	// Use printf with base64 encoding to avoid shell escaping issues
	// First encode the content
	encoded := base64Encode(content)

	// Write using echo | base64 -d > file
	cmd := fmt.Sprintf("echo '%s' | base64 -d > %q", encoded, path)
	output, exitCode, err := client.RunShellCommand(ctx, containerID, cmd)
	if err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("failed to write file: %s", output)
	}

	s.logger.Debug("wrote file in container",
		"host_id", hostID,
		"container_id", containerID,
		"path", path,
		"size", len(content),
	)

	return nil
}

// DeleteContainerFile deletes a file or directory in a container.
func (s *Service) DeleteContainerFile(ctx context.Context, hostID uuid.UUID, containerID, path string, recursive bool) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	cmd := "rm"
	if recursive {
		cmd = "rm -rf"
	}

	output, exitCode, err := client.RunShellCommand(ctx, containerID, fmt.Sprintf("%s %q", cmd, path))
	if err != nil {
		return fmt.Errorf("delete file: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("failed to delete file: %s", output)
	}

	s.logger.Debug("deleted file in container",
		"host_id", hostID,
		"container_id", containerID,
		"path", path,
		"recursive", recursive,
	)

	return nil
}

// CreateContainerDirectory creates a directory in a container.
func (s *Service) CreateContainerDirectory(ctx context.Context, hostID uuid.UUID, containerID, path string) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	output, exitCode, err := client.RunShellCommand(ctx, containerID, fmt.Sprintf("mkdir -p %q", path))
	if err != nil {
		return fmt.Errorf("create directory: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("failed to create directory: %s", output)
	}

	s.logger.Debug("created directory in container",
		"host_id", hostID,
		"container_id", containerID,
		"path", path,
	)

	return nil
}

// DownloadContainerFile downloads a file from a container as a reader.
func (s *Service) DownloadContainerFile(ctx context.Context, hostID uuid.UUID, containerID, path string) (io.ReadCloser, int64, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, 0, err
	}

	// Get file size first
	statOutput, exitCode, _ := client.RunShellCommand(ctx, containerID, fmt.Sprintf("stat -c '%%s' %q 2>/dev/null || stat -f '%%z' %q", path, path))
	var fileSize int64
	if exitCode == 0 {
		fmt.Sscanf(strings.TrimSpace(statOutput), "%d", &fileSize)
	}

	// Use docker cp via ContainerCopyFromContainer
	reader, _, err := client.ContainerCopyFromContainer(ctx, containerID, path)
	if err != nil {
		return nil, 0, fmt.Errorf("download file: %w", err)
	}

	return reader, fileSize, nil
}

// Helper functions

func humanizeSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

func timeAgo(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	diff := time.Since(t)
	switch {
	case diff < time.Minute:
		return "just now"
	case diff < time.Hour:
		mins := int(diff.Minutes())
		if mins == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", mins)
	case diff < 24*time.Hour:
		hours := int(diff.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	case diff < 7*24*time.Hour:
		days := int(diff.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	default:
		return t.Format("Jan 2, 2006")
	}
}

func isBinaryContent(content string) bool {
	// Check for null bytes
	if strings.Contains(content, "\x00") {
		return true
	}
	// Check proportion of non-printable characters
	nonPrintable := 0
	for _, c := range content {
		if c < 32 && c != '\t' && c != '\n' && c != '\r' {
			nonPrintable++
		}
	}
	return len(content) > 0 && float64(nonPrintable)/float64(len(content)) > 0.1
}

func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
