// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package web provides the web UI layer for USULNET.
package web

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/fr4nsys/usulnet/internal/docker"
	giteapkg "github.com/fr4nsys/usulnet/internal/integrations/gitea"
	"github.com/fr4nsys/usulnet/internal/integrations/npm"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/totp"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	authsvc "github.com/fr4nsys/usulnet/internal/services/auth"
	backupsvc "github.com/fr4nsys/usulnet/internal/services/backup"
	configsvc "github.com/fr4nsys/usulnet/internal/services/config"
	containersvc "github.com/fr4nsys/usulnet/internal/services/container"
	gitsvc "github.com/fr4nsys/usulnet/internal/services/git"
	hostsvc "github.com/fr4nsys/usulnet/internal/services/host"
	imagesvc "github.com/fr4nsys/usulnet/internal/services/image"
	"github.com/fr4nsys/usulnet/internal/scheduler"
	"github.com/fr4nsys/usulnet/internal/services/monitoring"
	networksvc "github.com/fr4nsys/usulnet/internal/services/network"
	proxysvc "github.com/fr4nsys/usulnet/internal/services/proxy"
	securitysvc "github.com/fr4nsys/usulnet/internal/services/security"
	sshsvc "github.com/fr4nsys/usulnet/internal/services/ssh"
	stacksvc "github.com/fr4nsys/usulnet/internal/services/stack"
	storagesvc "github.com/fr4nsys/usulnet/internal/services/storage"
	teamsvc "github.com/fr4nsys/usulnet/internal/services/team"
	updatesvc "github.com/fr4nsys/usulnet/internal/services/update"
	volumesvc "github.com/fr4nsys/usulnet/internal/services/volume"
)

// ServiceRegistry holds all backend services and provides adapted interfaces for the web layer.
type ServiceRegistry struct {
	// Backend services
	containerSvc *containersvc.Service
	imageSvc     *imagesvc.Service
	volumeSvc    *volumesvc.Service
	networkSvc   *networksvc.Service
	stackSvc     *stacksvc.Service
	backupSvc    *backupsvc.Service
	configSvc    *configsvc.Service
	securitySvc  *securitysvc.Service
	updateSvc    *updatesvc.Service
	hostSvc      *hostsvc.Service
	authSvc      *authsvc.Service
	npmSvc       *npm.Service
	proxySvc     *proxysvc.Service
	storageSvc   *storagesvc.Service
	teamSvc      *teamsvc.Service
	giteaSvc     *giteapkg.Service
	gitSvc       *gitsvc.Service
	sshSvc       *sshsvc.Service
	metricsSvc   MetricsServiceFull
	alertSvc     *monitoring.AlertService
	schedulerSvc *scheduler.Scheduler

	// User repository for user management
	userRepo *postgres.UserRepository

	// Encryptor for TOTP secrets
	encryptor *crypto.AESEncryptor

	// Session store for auth validation
	sessionStore *WebSessionStore

	// Docker client for events
	dockerClient *docker.Client

	// Default host ID for standalone mode
	defaultHostID uuid.UUID
}

// NewServiceRegistry creates a new service registry.
func NewServiceRegistry(defaultHostID uuid.UUID) *ServiceRegistry {
	return &ServiceRegistry{
		defaultHostID: defaultHostID,
	}
}

// SetContainerService sets the container service.
func (r *ServiceRegistry) SetContainerService(svc *containersvc.Service) {
	r.containerSvc = svc
}

// SetImageService sets the image service.
func (r *ServiceRegistry) SetImageService(svc *imagesvc.Service) {
	r.imageSvc = svc
}

// SetVolumeService sets the volume service.
func (r *ServiceRegistry) SetVolumeService(svc *volumesvc.Service) {
	r.volumeSvc = svc
}

// SetNetworkService sets the network service.
func (r *ServiceRegistry) SetNetworkService(svc *networksvc.Service) {
	r.networkSvc = svc
}

// SetStackService sets the stack service.
func (r *ServiceRegistry) SetStackService(svc *stacksvc.Service) {
	r.stackSvc = svc
}

// SetBackupService sets the backup service.
func (r *ServiceRegistry) SetBackupService(svc *backupsvc.Service) {
	r.backupSvc = svc
}

// SetConfigService sets the config service.
func (r *ServiceRegistry) SetConfigService(svc *configsvc.Service) {
	r.configSvc = svc
}

// SetSecurityService sets the security service.
func (r *ServiceRegistry) SetSecurityService(svc *securitysvc.Service) {
	r.securitySvc = svc
}

// SetUpdateService sets the update service.
func (r *ServiceRegistry) SetUpdateService(svc *updatesvc.Service) {
	r.updateSvc = svc
}

// SetHostService sets the host service.
func (r *ServiceRegistry) SetHostService(svc *hostsvc.Service) {
	r.hostSvc = svc
}

// SetAuthService sets the auth service.
func (r *ServiceRegistry) SetAuthService(svc *authsvc.Service) {
	r.authSvc = svc
}

// SetNPMService sets the NPM integration service.
func (r *ServiceRegistry) SetNPMService(svc *npm.Service) {
	r.npmSvc = svc
}

// SetProxyService sets the Caddy-based proxy service.
func (r *ServiceRegistry) SetProxyService(svc *proxysvc.Service) {
	r.proxySvc = svc
}

// SetStorageService sets the S3-compatible storage service.
func (r *ServiceRegistry) SetStorageService(svc *storagesvc.Service) {
	r.storageSvc = svc
}

// SetTeamService sets the team service.
func (r *ServiceRegistry) SetTeamService(svc *teamsvc.Service) {
	r.teamSvc = svc
}

// SetGiteaService sets the Gitea integration service.
func (r *ServiceRegistry) SetGiteaService(svc *giteapkg.Service) {
	r.giteaSvc = svc
}

// SetGitService sets the unified Git service.
func (r *ServiceRegistry) SetGitService(svc *gitsvc.Service) {
	r.gitSvc = svc
}

// SetMetricsService sets the metrics service.
func (r *ServiceRegistry) SetMetricsService(svc MetricsServiceFull) {
	r.metricsSvc = svc
}

// SetSSHService sets the SSH service.
func (r *ServiceRegistry) SetSSHService(svc *sshsvc.Service) {
	r.sshSvc = svc
}

// SetAlertService sets the alert monitoring service.
func (r *ServiceRegistry) SetAlertService(svc *monitoring.AlertService) {
	r.alertSvc = svc
}

// SetSchedulerService sets the scheduler service.
func (r *ServiceRegistry) SetSchedulerService(svc *scheduler.Scheduler) {
	r.schedulerSvc = svc
}

// SetUserRepository sets the user repository for user management.
func (r *ServiceRegistry) SetUserRepository(repo *postgres.UserRepository) {
	r.userRepo = repo
}

func (r *ServiceRegistry) SetEncryptor(enc *crypto.AESEncryptor) {
	r.encryptor = enc
}

// SetSessionStore sets the session store for auth validation.
func (r *ServiceRegistry) SetSessionStore(store *WebSessionStore) {
	r.sessionStore = store
}

// SetDockerClient sets the Docker client for events streaming.
func (r *ServiceRegistry) SetDockerClient(c *docker.Client) {
	r.dockerClient = c
}

// resolveHostID extracts the active host ID from context, falling back to the default.
// This enables all service adapters to route operations to the host selected by the user.
func resolveHostID(ctx context.Context, defaultID uuid.UUID) uuid.UUID {
	activeHostID := GetActiveHostIDFromContext(ctx)
	if activeHostID != "" {
		if id, err := uuid.Parse(activeHostID); err == nil {
			return id
		}
	}
	return defaultID
}

// ============================================================================
// Services interface implementation
// ============================================================================

func (r *ServiceRegistry) Containers() ContainerService {
	return &containerAdapter{svc: r.containerSvc, hostID: r.defaultHostID}
}

func (r *ServiceRegistry) Images() ImageService {
	return &imageAdapter{svc: r.imageSvc, hostID: r.defaultHostID}
}

func (r *ServiceRegistry) Volumes() VolumeService {
	return &volumeAdapter{svc: r.volumeSvc, containerSvc: r.containerSvc, hostID: r.defaultHostID}
}

func (r *ServiceRegistry) Networks() NetworkService {
	return &networkAdapter{svc: r.networkSvc, hostID: r.defaultHostID}
}

func (r *ServiceRegistry) Stacks() StackService {
	return &stackAdapter{svc: r.stackSvc, hostID: r.defaultHostID}
}

func (r *ServiceRegistry) Backups() BackupService {
	return &backupAdapter{svc: r.backupSvc, hostID: r.defaultHostID}
}

func (r *ServiceRegistry) Config() ConfigService {
	return &configAdapter{svc: r.configSvc}
}

func (r *ServiceRegistry) Security() SecurityService {
	return &securityAdapter{svc: r.securitySvc, hostSvc: r.hostSvc, containerSvc: r.containerSvc, hostID: r.defaultHostID}
}

func (r *ServiceRegistry) Updates() UpdateService {
	return &updateAdapter{svc: r.updateSvc, hostID: r.defaultHostID}
}

func (r *ServiceRegistry) Hosts() HostService {
	return &hostAdapter{svc: r.hostSvc, hostID: r.defaultHostID}
}

func (r *ServiceRegistry) Events() EventService {
	return &eventAdapter{dockerClient: r.dockerClient}
}

func (r *ServiceRegistry) Proxy() ProxyService {
	// Prefer Caddy-based proxy if configured
	if r.proxySvc != nil {
		return newCaddyProxyAdapter(r.proxySvc)
	}
	// Fallback to NPM adapter
	return &proxyAdapter{npmSvc: r.npmSvc, hostID: r.defaultHostID}
}

func (r *ServiceRegistry) Storage() StorageService {
	if r.storageSvc == nil {
		return nil
	}
	return &storageAdapter{svc: r.storageSvc}
}

func (r *ServiceRegistry) Auth() AuthService {
	return &authAdapter{svc: r.authSvc, sessionStore: r.sessionStore}
}

func (r *ServiceRegistry) Users() UserService {
	return &userAdapter{repo: r.userRepo, authSvc: r.authSvc, encryptor: r.encryptor}
}

func (r *ServiceRegistry) Stats() StatsService {
	return &statsAdapter{
		containerSvc: r.containerSvc,
		imageSvc:     r.imageSvc,
		volumeSvc:    r.volumeSvc,
		networkSvc:   r.networkSvc,
		stackSvc:     r.stackSvc,
		securitySvc:  r.securitySvc,
		hostSvc:      r.hostSvc,
		hostID:       r.defaultHostID,
	}
}

func (r *ServiceRegistry) Teams() TeamService {
	return r.teamSvc
}

// Gitea returns the Gitea integration service, or nil if not configured.
func (r *ServiceRegistry) Gitea() GiteaService {
	if r.giteaSvc == nil {
		return nil
	}
	return r.giteaSvc
}

// Git returns the unified Git service, or nil if not configured.
func (r *ServiceRegistry) Git() GitService {
	if r.gitSvc == nil {
		return nil
	}
	return r.gitSvc
}

// Metrics returns the metrics service, or nil if not configured.
func (r *ServiceRegistry) Metrics() MetricsServiceFull {
	return r.metricsSvc
}

// SSH returns the SSH service, or nil if not configured.
func (r *ServiceRegistry) SSH() *sshsvc.Service {
	return r.sshSvc
}

// Alerts returns the alert monitoring service, or nil if not configured.
func (r *ServiceRegistry) Alerts() AlertsService {
	if r.alertSvc == nil {
		return nil
	}
	return r.alertSvc
}

// Scheduler returns the scheduler service, or nil if not configured.
func (r *ServiceRegistry) Scheduler() *scheduler.Scheduler {
	return r.schedulerSvc
}

// ============================================================================
// Container Adapter
// ============================================================================

type containerAdapter struct {
	svc    *containersvc.Service
	hostID uuid.UUID
}

func (a *containerAdapter) List(ctx context.Context, filters map[string]string) ([]ContainerView, error) {
	if a.svc == nil {
		return nil, nil
	}

	hostID := resolveHostID(ctx, a.hostID)
	opts := postgres.ContainerListOptions{
		HostID:  &hostID,
		Page:    1,
		PerPage: 500,
	}
	if search := filters["search"]; search != "" {
		opts.Search = search
	}
	if search := filters["name"]; search != "" {
		opts.Search = search
	}
	if stateStr := filters["state"]; stateStr != "" {
		state := models.ContainerState(stateStr)
		opts.State = &state
	}

	containers, _, err := a.svc.List(ctx, opts)
	if err != nil {
		return nil, err
	}

	views := make([]ContainerView, 0, len(containers))
	for _, c := range containers {
		views = append(views, containerToView(c))
	}
	return views, nil
}

func (a *containerAdapter) Get(ctx context.Context, id string) (*ContainerView, error) {
	if a.svc == nil {
		return nil, nil
	}

	c, err := a.svc.Get(ctx, resolveHostID(ctx, a.hostID), id)
	if err != nil {
		return nil, err
	}

	view := containerToView(c)
	return &view, nil
}

func (a *containerAdapter) Start(ctx context.Context, id string) error {
	if a.svc == nil {
		return nil
	}
	return a.svc.StartContainer(ctx, resolveHostID(ctx, a.hostID), id)
}

func (a *containerAdapter) Stop(ctx context.Context, id string) error {
	if a.svc == nil {
		return nil
	}
	return a.svc.StopContainer(ctx, resolveHostID(ctx, a.hostID), id)
}

func (a *containerAdapter) Restart(ctx context.Context, id string) error {
	if a.svc == nil {
		return nil
	}
	return a.svc.Restart(ctx, resolveHostID(ctx, a.hostID), id)
}

func (a *containerAdapter) Pause(ctx context.Context, id string) error {
	if a.svc == nil {
		return nil
	}
	return a.svc.Pause(ctx, resolveHostID(ctx, a.hostID), id)
}

func (a *containerAdapter) Unpause(ctx context.Context, id string) error {
	if a.svc == nil {
		return nil
	}
	return a.svc.Unpause(ctx, resolveHostID(ctx, a.hostID), id)
}

func (a *containerAdapter) Kill(ctx context.Context, id string) error {
	if a.svc == nil {
		return nil
	}
	return a.svc.Kill(ctx, resolveHostID(ctx, a.hostID), id, "SIGKILL")
}

func (a *containerAdapter) Remove(ctx context.Context, id string, force bool) error {
	if a.svc == nil {
		return nil
	}
	return a.svc.Remove(ctx, resolveHostID(ctx, a.hostID), id, force, false)
}

func (a *containerAdapter) Rename(ctx context.Context, id, name string) error {
	// Not implemented in current service
	return nil
}

// BulkOperationResult represents the result of a single container operation.
type BulkOperationResult struct {
	ContainerID string
	Name        string
	Success     bool
	Error       string
}

// BulkOperationResults represents the results of a bulk operation.
type BulkOperationResults struct {
	Total      int
	Successful int
	Failed     int
	Results    []BulkOperationResult
}

func (a *containerAdapter) BulkStart(ctx context.Context, containerIDs []string) (*BulkOperationResults, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}

	results, err := a.svc.BulkStart(ctx, resolveHostID(ctx, a.hostID), containerIDs)
	if err != nil {
		return nil, err
	}

	return convertBulkResults(results), nil
}

func (a *containerAdapter) BulkStop(ctx context.Context, containerIDs []string) (*BulkOperationResults, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}

	results, err := a.svc.BulkStop(ctx, resolveHostID(ctx, a.hostID), containerIDs)
	if err != nil {
		return nil, err
	}

	return convertBulkResults(results), nil
}

func (a *containerAdapter) BulkRestart(ctx context.Context, containerIDs []string) (*BulkOperationResults, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}

	results, err := a.svc.BulkRestart(ctx, resolveHostID(ctx, a.hostID), containerIDs)
	if err != nil {
		return nil, err
	}

	return convertBulkResults(results), nil
}

func (a *containerAdapter) BulkPause(ctx context.Context, containerIDs []string) (*BulkOperationResults, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}

	results, err := a.svc.BulkPause(ctx, resolveHostID(ctx, a.hostID), containerIDs)
	if err != nil {
		return nil, err
	}

	return convertBulkResults(results), nil
}

func (a *containerAdapter) BulkUnpause(ctx context.Context, containerIDs []string) (*BulkOperationResults, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}

	results, err := a.svc.BulkUnpause(ctx, resolveHostID(ctx, a.hostID), containerIDs)
	if err != nil {
		return nil, err
	}

	return convertBulkResults(results), nil
}

func (a *containerAdapter) BulkKill(ctx context.Context, containerIDs []string) (*BulkOperationResults, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}

	results, err := a.svc.BulkKill(ctx, resolveHostID(ctx, a.hostID), containerIDs, "SIGKILL")
	if err != nil {
		return nil, err
	}

	return convertBulkResults(results), nil
}

func (a *containerAdapter) BulkRemove(ctx context.Context, containerIDs []string, force bool) (*BulkOperationResults, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}

	results, err := a.svc.BulkRemove(ctx, resolveHostID(ctx, a.hostID), containerIDs, force, false)
	if err != nil {
		return nil, err
	}

	return convertBulkResults(results), nil
}

func convertBulkResults(results *containersvc.BulkOperationResults) *BulkOperationResults {
	converted := &BulkOperationResults{
		Total:      results.Total,
		Successful: results.Successful,
		Failed:     results.Failed,
		Results:    make([]BulkOperationResult, len(results.Results)),
	}

	for i, r := range results.Results {
		converted.Results[i] = BulkOperationResult{
			ContainerID: r.ContainerID,
			Name:        r.Name,
			Success:     r.Success,
			Error:       r.Error,
		}
	}

	return converted
}

func (a *containerAdapter) Create(ctx context.Context, input *ContainerCreateInput) (string, error) {
	if a.svc == nil {
		return "", fmt.Errorf("container service not available")
	}

	// Parse ports
	var ports []models.ContainerPort
	for _, p := range input.Ports {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		parts := strings.SplitN(p, ":", 2)
		if len(parts) != 2 {
			continue
		}
		hostPort, err1 := strconv.ParseUint(parts[0], 10, 16)
		containerPort, err2 := strconv.ParseUint(parts[1], 10, 16)
		if err1 != nil || err2 != nil {
			continue
		}
		ports = append(ports, models.ContainerPort{
			HostPort:      uint16(hostPort),
			ContainerPort: uint16(containerPort),
			Protocol:      "tcp",
		})
	}

	// Parse volumes
	var volumes []models.ContainerMount
	for _, v := range input.Volumes {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		parts := strings.SplitN(v, ":", 2)
		if len(parts) != 2 {
			continue
		}
		volumes = append(volumes, models.ContainerMount{
			Source: parts[0],
			Target: parts[1],
			Type:   "bind",
		})
	}

	// Parse environment
	var env []string
	for _, line := range strings.Split(input.Environment, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && strings.Contains(line, "=") {
			env = append(env, line)
		}
	}

	// Parse command
	var cmd []string
	if input.Command != "" {
		cmd = strings.Fields(input.Command)
	}

	// Build networks
	var networks []string
	if input.Network != "" {
		networks = []string{input.Network}
	}

	svcInput := &containersvc.CreateInput{
		Name:          input.Name,
		Image:         input.Image,
		Ports:         ports,
		Volumes:       volumes,
		Env:           env,
		Cmd:           cmd,
		Networks:      networks,
		RestartPolicy: input.RestartPolicy,
		Privileged:    input.Privileged,
	}

	container, err := a.svc.Create(ctx, resolveHostID(ctx, a.hostID), svcInput)
	if err != nil {
		return "", err
	}
	return container.ID, nil
}

func (a *containerAdapter) GetDockerClient(ctx context.Context) (docker.ClientAPI, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}
	return a.svc.GetDockerClient(ctx, resolveHostID(ctx, a.hostID))
}

func (a *containerAdapter) GetHostID() uuid.UUID {
	return a.hostID
}

func (a *containerAdapter) BrowseFiles(ctx context.Context, containerID, path string) ([]ContainerFileView, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}
	files, err := a.svc.BrowseContainer(ctx, resolveHostID(ctx, a.hostID), containerID, path)
	if err != nil {
		return nil, err
	}
	views := make([]ContainerFileView, len(files))
	for i, f := range files {
		views[i] = ContainerFileView{
			Name: f.Name, Path: f.Path, IsDir: f.IsDir, Size: f.Size,
			SizeHuman: f.SizeHuman, Mode: f.Mode, ModTime: f.ModTime.Format(time.RFC3339),
			ModTimeAgo: f.ModTimeAgo, Owner: f.Owner, Group: f.Group,
			LinkTarget: f.LinkTarget, IsSymlink: f.IsSymlink,
		}
	}
	return views, nil
}

func (a *containerAdapter) ReadFile(ctx context.Context, containerID, path string) (*ContainerFileContentView, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}
	content, err := a.svc.ReadContainerFile(ctx, resolveHostID(ctx, a.hostID), containerID, path, 10*1024*1024)
	if err != nil {
		return nil, err
	}
	return &ContainerFileContentView{
		Path: content.Path, Content: content.Content, Size: content.Size,
		Truncated: content.Truncated, Binary: content.Binary,
	}, nil
}

func (a *containerAdapter) WriteFile(ctx context.Context, containerID, path, content string) error {
	if a.svc == nil {
		return fmt.Errorf("container service not available")
	}
	return a.svc.WriteContainerFile(ctx, resolveHostID(ctx, a.hostID), containerID, path, content)
}

func (a *containerAdapter) DeleteFile(ctx context.Context, containerID, path string, recursive bool) error {
	if a.svc == nil {
		return fmt.Errorf("container service not available")
	}
	return a.svc.DeleteContainerFile(ctx, resolveHostID(ctx, a.hostID), containerID, path, recursive)
}

func (a *containerAdapter) CreateDirectory(ctx context.Context, containerID, path string) error {
	if a.svc == nil {
		return fmt.Errorf("container service not available")
	}
	return a.svc.CreateContainerDirectory(ctx, resolveHostID(ctx, a.hostID), containerID, path)
}

func (a *containerAdapter) GetLogs(ctx context.Context, id string, tail int) ([]string, error) {
	if a.svc == nil {
		return nil, nil
	}

	reader, err := a.svc.GetLogs(ctx, resolveHostID(ctx, a.hostID), id, containersvc.LogOptions{
		Tail:       strconv.Itoa(tail),
		Timestamps: true,
		Stdout:     true,
		Stderr:     true,
	})
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	// Split by newlines
	lines := splitLines(string(data))
	return lines, nil
}

// ============================================================================
// Image Adapter
// ============================================================================

type imageAdapter struct {
	svc    *imagesvc.Service
	hostID uuid.UUID
}

func (a *imageAdapter) List(ctx context.Context) ([]ImageView, error) {
	if a.svc == nil {
		return nil, nil
	}

	images, err := a.svc.List(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return nil, err
	}

	views := make([]ImageView, 0, len(images))
	for _, img := range images {
		views = append(views, imageToView(img))
	}
	return views, nil
}

func (a *imageAdapter) Get(ctx context.Context, id string) (*ImageView, error) {
	if a.svc == nil {
		return nil, nil
	}

	img, err := a.svc.Get(ctx, resolveHostID(ctx, a.hostID), id)
	if err != nil {
		return nil, err
	}

	view := imageToView(img)
	return &view, nil
}

func (a *imageAdapter) Remove(ctx context.Context, id string, force bool) error {
	if a.svc == nil {
		return nil
	}
	return a.svc.Remove(ctx, resolveHostID(ctx, a.hostID), id, force)
}

func (a *imageAdapter) Prune(ctx context.Context) (int64, error) {
	if a.svc == nil {
		return 0, nil
	}
	result, err := a.svc.Prune(ctx, resolveHostID(ctx, a.hostID), true)
	if err != nil {
		return 0, err
	}
	return result.SpaceReclaimed, nil
}

func (a *imageAdapter) Pull(ctx context.Context, reference string) error {
	if a.svc == nil {
		return fmt.Errorf("image service not available")
	}
	return a.svc.Pull(ctx, resolveHostID(ctx, a.hostID), reference, nil)
}

// ============================================================================
// Volume Adapter
// ============================================================================

type volumeAdapter struct {
	svc          *volumesvc.Service
	containerSvc *containersvc.Service
	hostID       uuid.UUID
}

func (a *volumeAdapter) List(ctx context.Context) ([]VolumeView, error) {
	if a.svc == nil {
		return nil, nil
	}

	volumes, err := a.svc.List(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return nil, err
	}

	// Cross-reference with containers to get InUse and UsedBy
	volumeUsage := make(map[string][]string) // volume name → container names
	if a.containerSvc != nil {
		containers, err := a.containerSvc.ListByHost(ctx, resolveHostID(ctx, a.hostID))
		if err == nil {
			for _, c := range containers {
				for _, m := range c.Mounts {
					if m.Type == "volume" {
						volumeUsage[m.Source] = append(volumeUsage[m.Source], c.Name)
					}
				}
			}
		}
	}

	views := make([]VolumeView, 0, len(volumes))
	for _, v := range volumes {
		view := volumeToView(v)
		if usedBy, ok := volumeUsage[v.Name]; ok {
			view.InUse = true
			view.UsedBy = usedBy
		}
		views = append(views, view)
	}
	return views, nil
}

func (a *volumeAdapter) Get(ctx context.Context, name string) (*VolumeView, error) {
	if a.svc == nil {
		return nil, nil
	}

	v, err := a.svc.Get(ctx, resolveHostID(ctx, a.hostID), name)
	if err != nil {
		return nil, err
	}

	view := volumeToView(v)

	// Cross-reference with containers to get UsedBy
	if a.containerSvc != nil {
		containers, err := a.containerSvc.ListByHost(ctx, resolveHostID(ctx, a.hostID))
		if err == nil {
			for _, c := range containers {
				for _, m := range c.Mounts {
					if m.Type == "volume" && m.Source == name {
						view.InUse = true
						view.UsedBy = append(view.UsedBy, c.Name)
					}
				}
			}
		}
	}

	return &view, nil
}

func (a *volumeAdapter) Create(ctx context.Context, name, driver string, labels map[string]string) error {
	if a.svc == nil {
		return nil
	}

	input := &models.CreateVolumeInput{
		Name:   name,
		Driver: driver,
		Labels: labels,
	}
	_, err := a.svc.Create(ctx, resolveHostID(ctx, a.hostID), input)
	return err
}

func (a *volumeAdapter) Remove(ctx context.Context, name string, force bool) error {
	if a.svc == nil {
		return nil
	}
	return a.svc.Delete(ctx, resolveHostID(ctx, a.hostID), name, force)
}

func (a *volumeAdapter) Prune(ctx context.Context) (int64, error) {
	if a.svc == nil {
		return 0, nil
	}
	result, err := a.svc.Prune(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return 0, err
	}
	return result.SpaceReclaimed, nil
}

func (a *volumeAdapter) Browse(ctx context.Context, volumeName, path string) ([]VolumeFileEntry, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("volume service not available")
	}
	files, err := a.svc.BrowseVolume(ctx, resolveHostID(ctx, a.hostID), volumeName, path)
	if err != nil {
		return nil, err
	}
	entries := make([]VolumeFileEntry, len(files))
	for i, f := range files {
		entries[i] = VolumeFileEntry{
			Name:      f.Name,
			Path:      f.Path,
			IsDir:     f.IsDir,
			Size:      f.Size,
			SizeHuman: f.SizeHuman,
			Mode:      f.Mode,
			ModTime:   f.ModTime.Format("2006-01-02 15:04:05"),
		}
	}
	return entries, nil
}

// ============================================================================
// Network Adapter
// ============================================================================

type networkAdapter struct {
	svc    *networksvc.Service
	hostID uuid.UUID
}

func (a *networkAdapter) List(ctx context.Context) ([]NetworkView, error) {
	if a.svc == nil {
		return nil, nil
	}

	networks, err := a.svc.List(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return nil, err
	}

	views := make([]NetworkView, 0, len(networks))
	for _, n := range networks {
		views = append(views, networkToView(n))
	}
	return views, nil
}

func (a *networkAdapter) Get(ctx context.Context, id string) (*NetworkView, error) {
	if a.svc == nil {
		return nil, nil
	}

	n, err := a.svc.Get(ctx, resolveHostID(ctx, a.hostID), id)
	if err != nil {
		return nil, err
	}

	view := networkToView(n)
	return &view, nil
}

func (a *networkAdapter) GetModel(ctx context.Context, id string) (*models.Network, error) {
	if a.svc == nil {
		return nil, nil
	}
	return a.svc.Get(ctx, resolveHostID(ctx, a.hostID), id)
}

func (a *networkAdapter) Create(ctx context.Context, name, driver string, opts map[string]string) error {
	if a.svc == nil {
		return nil
	}

	input := &models.CreateNetworkInput{
		Name:   name,
		Driver: driver,
	}
	_, err := a.svc.Create(ctx, resolveHostID(ctx, a.hostID), input)
	return err
}

func (a *networkAdapter) Remove(ctx context.Context, id string) error {
	if a.svc == nil {
		return nil
	}
	return a.svc.Delete(ctx, resolveHostID(ctx, a.hostID), id)
}

func (a *networkAdapter) Connect(ctx context.Context, networkID, containerID string) error {
	if a.svc == nil {
		return nil
	}
	return a.svc.Connect(ctx, resolveHostID(ctx, a.hostID), networkID, containerID, nil)
}

func (a *networkAdapter) Disconnect(ctx context.Context, networkID, containerID string) error {
	if a.svc == nil {
		return nil
	}
	return a.svc.Disconnect(ctx, resolveHostID(ctx, a.hostID), networkID, containerID, false)
}

func (a *networkAdapter) Prune(ctx context.Context) (int64, error) {
	if a.svc == nil {
		return 0, nil
	}
	result, err := a.svc.Prune(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return 0, err
	}
	return int64(len(result.ItemsDeleted)), nil
}

func (a *networkAdapter) GetTopology(ctx context.Context) (*TopologyData, error) {
	if a.svc == nil {
		return nil, nil
	}

	topo, err := a.svc.GetTopology(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return nil, err
	}

	// Convert map[string][]string to TopologyData with Nodes/Edges
	data := &TopologyData{
		Nodes: make([]TopologyNode, 0),
		Edges: make([]TopologyEdge, 0),
	}

	// Add network nodes and edges
	for networkID, containerIDs := range topo {
		// Add network node
		data.Nodes = append(data.Nodes, TopologyNode{
			ID:    networkID,
			Label: networkID,
			Type:  "network",
		})

		// Add edges to containers
		for _, containerID := range containerIDs {
			// Add container node if not exists (simplified, may have duplicates)
			data.Nodes = append(data.Nodes, TopologyNode{
				ID:    containerID,
				Label: containerID,
				Type:  "container",
			})

			data.Edges = append(data.Edges, TopologyEdge{
				From: networkID,
				To:   containerID,
			})
		}
	}

	return data, nil
}

// ============================================================================
// Stack Adapter
// ============================================================================

type stackAdapter struct {
	svc    *stacksvc.Service
	hostID uuid.UUID
}

func (a *stackAdapter) List(ctx context.Context) ([]StackView, error) {
	if a.svc == nil {
		return nil, nil
	}

	// Get managed stacks from database
	stacks, _, err := a.svc.List(ctx, postgres.StackListOptions{Page: 1, PerPage: 100})
	if err != nil {
		return nil, err
	}

	// Track managed stack names to avoid duplicates
	managedNames := make(map[string]bool)
	views := make([]StackView, 0, len(stacks))

	for _, s := range stacks {
		managedNames[s.Name] = true
		view := stackToView(s)

		// Enrich with live container data from Docker
		containers, err := a.svc.GetContainers(ctx, s.ID)
		if err == nil && len(containers) > 0 {
			running := 0
			var names []string
			for _, c := range containers {
				names = append(names, c.Name)
				if c.State == models.ContainerStateRunning {
					running++
				}
			}
			view.ContainerNames = names
			view.RunningCount = running
			if view.ServiceCount == 0 {
				view.ServiceCount = len(containers)
			}
			// Update status based on live data
			if running == 0 {
				view.Status = string(models.StackStatusInactive)
			} else if running < view.ServiceCount {
				view.Status = string(models.StackStatusPartial)
			} else {
				view.Status = string(models.StackStatusActive)
			}
		}

		views = append(views, view)
	}

	// Discover external Docker Compose projects (not managed by usulnet)
	discovered, err := a.svc.DiscoverComposeProjects(ctx, resolveHostID(ctx, a.hostID))
	if err == nil && len(discovered) > 0 {
		for _, d := range discovered {
			// Skip if already managed by usulnet
			if managedNames[d.Name] {
				continue
			}

			// Determine status
			status := string(models.StackStatusInactive)
			if d.RunningCount > 0 && d.RunningCount >= d.ServiceCount {
				status = string(models.StackStatusActive)
			} else if d.RunningCount > 0 {
				status = string(models.StackStatusPartial)
			}

			view := StackView{
				Name:         d.Name,
				Status:       status,
				ServiceCount: d.ServiceCount,
				RunningCount: d.RunningCount,
				Path:         d.WorkingDir,
				IsExternal:   true, // Mark as external/discovered
			}

			// Add service/container names
			var containerNames []string
			for _, svc := range d.Services {
				containerNames = append(containerNames, svc.Name)
			}
			view.ContainerNames = containerNames

			views = append(views, view)
		}
	}

	return views, nil
}

func (a *stackAdapter) Get(ctx context.Context, name string) (*StackView, error) {
	if a.svc == nil {
		return nil, nil
	}

	// First try to get from database (managed stacks)
	s, err := a.svc.GetByName(ctx, resolveHostID(ctx, a.hostID), name)
	if err == nil && s != nil {
		view := stackToView(s)
		return &view, nil
	}

	// Not found in database, check for external/discovered stacks
	discovered, discErr := a.svc.DiscoverComposeProjects(ctx, resolveHostID(ctx, a.hostID))
	if discErr == nil {
		for _, d := range discovered {
			if d.Name == name {
				// Found as external stack
				status := string(models.StackStatusInactive)
				if d.RunningCount > 0 && d.RunningCount >= d.ServiceCount {
					status = string(models.StackStatusActive)
				} else if d.RunningCount > 0 {
					status = string(models.StackStatusPartial)
				}

				view := StackView{
					Name:         d.Name,
					Status:       status,
					ServiceCount: d.ServiceCount,
					RunningCount: d.RunningCount,
					Path:         d.WorkingDir,
					IsExternal:   true,
				}

				var containerNames []string
				for _, svc := range d.Services {
					containerNames = append(containerNames, svc.Name)
				}
				view.ContainerNames = containerNames

				return &view, nil
			}
		}
	}

	// Return original error if not found anywhere
	return nil, err
}

func (a *stackAdapter) Deploy(ctx context.Context, name, composeFile string) error {
	if a.svc == nil {
		return nil
	}

	input := &models.CreateStackInput{
		Name:        name,
		ComposeFile: composeFile,
	}

	slog.Info("stackAdapter.Deploy: creating stack", "name", name)
	stack, err := a.svc.Create(ctx, resolveHostID(ctx, a.hostID), input)
	if err != nil {
		slog.Error("stackAdapter.Deploy: create failed", "name", name, "error", err)
		return err
	}
	slog.Info("stackAdapter.Deploy: stack created, deploying", "name", name, "id", stack.ID)

	result, err := a.svc.Deploy(ctx, stack.ID)
	if err != nil {
		slog.Error("stackAdapter.Deploy: deploy returned error", "name", name, "error", err)
		return err
	}
	if result != nil && !result.Success {
		slog.Error("stackAdapter.Deploy: deploy failed",
			"name", name,
			"output", result.Output,
			"error", result.Error,
		)
		return fmt.Errorf("docker compose failed: %s\nOutput: %s", result.Error, result.Output)
	}
	slog.Info("stackAdapter.Deploy: deploy succeeded", "name", name)
	return nil
}

func (a *stackAdapter) Start(ctx context.Context, name string) error {
	if a.svc == nil {
		return nil
	}

	s, err := a.svc.GetByName(ctx, resolveHostID(ctx, a.hostID), name)
	if err != nil {
		return err
	}

	return a.svc.Start(ctx, s.ID)
}

func (a *stackAdapter) Stop(ctx context.Context, name string) error {
	if a.svc == nil {
		return nil
	}

	s, err := a.svc.GetByName(ctx, resolveHostID(ctx, a.hostID), name)
	if err != nil {
		return err
	}

	return a.svc.Stop(ctx, s.ID, false)
}

func (a *stackAdapter) Restart(ctx context.Context, name string) error {
	if a.svc == nil {
		return nil
	}

	s, err := a.svc.GetByName(ctx, resolveHostID(ctx, a.hostID), name)
	if err != nil {
		return err
	}

	return a.svc.Restart(ctx, s.ID)
}

func (a *stackAdapter) Remove(ctx context.Context, name string) error {
	if a.svc == nil {
		return nil
	}

	s, err := a.svc.GetByName(ctx, resolveHostID(ctx, a.hostID), name)
	if err != nil {
		return err
	}

	return a.svc.Delete(ctx, s.ID, false)
}

func (a *stackAdapter) GetServices(ctx context.Context, name string) ([]StackServiceView, error) {
	if a.svc == nil {
		return nil, nil
	}

	// First try to get from database (managed stacks)
	s, err := a.svc.GetByName(ctx, resolveHostID(ctx, a.hostID), name)
	var containers []*models.Container

	if err == nil && s != nil {
		// Get live containers for this managed stack
		containers, err = a.svc.GetContainers(ctx, s.ID)
		if err != nil {
			containers = nil // Continue without container data
		}
	} else {
		// External stack: get containers by project label
		discovered, discErr := a.svc.DiscoverComposeProjects(ctx, resolveHostID(ctx, a.hostID))
		if discErr == nil {
			for _, d := range discovered {
				if d.Name == name {
					// Convert discovered services to container views
					for _, svc := range d.Services {
						containers = append(containers, &models.Container{
							ID:     svc.ContainerID,
							Name:   svc.Name,
							Image:  svc.Image,
							Status: svc.Status,
							State:  models.ContainerState(svc.State),
							Labels: map[string]string{
								"com.docker.compose.service": svc.Name,
							},
						})
					}
					break
				}
			}
		}
		// Reset error since we found services
		if len(containers) > 0 {
			err = nil
		}
	}

	// Build views from live containers (keyed by compose service name)
	viewMap := make(map[string]*StackServiceView)
	for _, c := range containers {
		svcName := c.Labels["com.docker.compose.service"]
		if svcName == "" {
			continue
		}

		view := &StackServiceView{
			Name:          svcName,
			Image:         c.Image,
			ContainerID:   c.ID,
			ContainerName: c.Name,
			Status:        c.Status,
			State:         string(c.State),
			Replicas:      "1/1",
		}
		// Build port strings
		for _, p := range c.Ports {
			if p.PublicPort > 0 {
				view.Ports = append(view.Ports, fmt.Sprintf("%d:%d/%s", p.PublicPort, p.PrivatePort, p.Type))
			} else {
				view.Ports = append(view.Ports, fmt.Sprintf("%d/%s", p.PrivatePort, p.Type))
			}
		}
		viewMap[svcName] = view
	}

	// Enrich with live status from compose ps (only for managed stacks)
	if s != nil {
		status, statusErr := a.svc.GetStatus(ctx, s.ID)
		if statusErr == nil && status != nil {
			for _, ss := range status.Services {
				if v, ok := viewMap[ss.Name]; ok {
					v.Replicas = fmt.Sprintf("%d/%d", ss.Running, ss.Desired)
					if ss.Status != "" {
						v.Status = ss.Status
					}
				} else {
					// Service exists in compose but has no container yet
					state := "stopped"
					if ss.Running > 0 {
						state = "running"
					}
					viewMap[ss.Name] = &StackServiceView{
						Name:     ss.Name,
						Status:   ss.Status,
						State:    state,
						Replicas: fmt.Sprintf("%d/%d", ss.Running, ss.Desired),
					}
				}
			}
		}
	}

	// Convert map to sorted slice
	var views []StackServiceView
	for _, v := range viewMap {
		views = append(views, *v)
	}

	// If no data from containers or status, parse compose file for service names (only for managed stacks)
	if len(views) == 0 && s != nil && s.ComposeFile != "" {
		type composeStruct struct {
			Services map[string]struct {
				Image string `yaml:"image"`
			} `yaml:"services"`
		}
		var cs composeStruct
		if err := yaml.Unmarshal([]byte(s.ComposeFile), &cs); err == nil {
			for svcName, svcDef := range cs.Services {
				views = append(views, StackServiceView{
					Name:     svcName,
					Image:    svcDef.Image,
					Status:   "unknown",
					State:    "unknown",
					Replicas: "0/1",
				})
			}
		}
	}

	return views, nil
}

func (a *stackAdapter) GetComposeConfig(ctx context.Context, name string) (string, error) {
	if a.svc == nil {
		return "", nil
	}

	s, err := a.svc.GetByName(ctx, resolveHostID(ctx, a.hostID), name)
	if err != nil {
		return "", err
	}

	config, err := a.svc.GetComposeConfig(ctx, s.ID)
	if err != nil {
		// Fallback to stored compose file
		return s.ComposeFile, nil
	}
	return config, nil
}

func (a *stackAdapter) ListVersions(ctx context.Context, name string) ([]StackVersionView, error) {
	if a.svc == nil {
		return nil, nil
	}

	s, err := a.svc.GetByName(ctx, resolveHostID(ctx, a.hostID), name)
	if err != nil {
		return nil, err
	}

	versions, err := a.svc.ListVersions(ctx, s.ID)
	if err != nil {
		return nil, err
	}

	views := make([]StackVersionView, 0, len(versions))
	for _, v := range versions {
		views = append(views, StackVersionView{
			Version:    v.Version,
			Comment:    v.Comment,
			CreatedAt:  v.CreatedAt.Format("Jan 2, 2006 15:04"),
			CreatedBy:  "", // UserID would need to be resolved to name
			IsDeployed: v.IsDeployed,
		})
	}

	return views, nil
}

// ============================================================================
// Backup Adapter
// ============================================================================

type backupAdapter struct {
	svc    *backupsvc.Service
	hostID uuid.UUID
}

func (a *backupAdapter) List(ctx context.Context, containerID string) ([]BackupView, error) {
	if a.svc == nil {
		return nil, nil
	}

	opts := models.BackupListOptions{
		Limit: 100,
	}
	if containerID != "" {
		opts.TargetID = &containerID
	}

	backups, _, err := a.svc.List(ctx, opts)
	if err != nil {
		return nil, err
	}

	views := make([]BackupView, 0, len(backups))
	for _, b := range backups {
		views = append(views, backupToView(b))
	}
	return views, nil
}

func (a *backupAdapter) Get(ctx context.Context, id string) (*BackupView, error) {
	if a.svc == nil {
		return nil, nil
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}

	b, err := a.svc.Get(ctx, uid)
	if err != nil {
		return nil, err
	}

	view := backupToView(b)
	return &view, nil
}

func (a *backupAdapter) Create(ctx context.Context, containerID string) (*BackupView, error) {
	if a.svc == nil {
		return nil, nil
	}

	result, err := a.svc.Create(ctx, backupsvc.CreateOptions{
		HostID:   resolveHostID(ctx, a.hostID),
		TargetID: containerID,
		Type:     models.BackupTypeContainer,
		Trigger:  models.BackupTriggerManual,
	})
	if err != nil {
		return nil, err
	}

	view := backupToView(result.Backup)
	return &view, nil
}

func (a *backupAdapter) Restore(ctx context.Context, id string) error {
	if a.svc == nil {
		return nil
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return err
	}

	_, err = a.svc.Restore(ctx, backupsvc.RestoreOptions{
		BackupID: uid,
	})
	return err
}

func (a *backupAdapter) Remove(ctx context.Context, id string) error {
	if a.svc == nil {
		return nil
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return err
	}

	return a.svc.Delete(ctx, uid)
}

func (a *backupAdapter) Download(ctx context.Context, id string) (string, error) {
	if a.svc == nil {
		return "", nil
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return "", err
	}

	info, err := a.svc.Download(ctx, uid)
	if err != nil {
		return "", err
	}

	// Close reader - handler uses filename/path to serve the file directly
	if info.Reader != nil {
		info.Reader.Close()
	}

	return info.Filename, nil
}

func (a *backupAdapter) DownloadStream(ctx context.Context, id string) (io.ReadCloser, string, int64, error) {
	if a.svc == nil {
		return nil, "", 0, fmt.Errorf("backup service not configured")
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, "", 0, err
	}

	info, err := a.svc.Download(ctx, uid)
	if err != nil {
		return nil, "", 0, err
	}

	return info.Reader, info.Filename, info.Size, nil
}

func (a *backupAdapter) CreateWithOptions(ctx context.Context, opts BackupCreateInput) (*BackupView, error) {
	if a.svc == nil {
		return nil, nil
	}

	backupType := models.BackupTypeContainer
	switch opts.Type {
	case "volume":
		backupType = models.BackupTypeVolume
	case "stack":
		backupType = models.BackupTypeStack
	case "container":
		backupType = models.BackupTypeContainer
	}

	compression := models.BackupCompressionGzip
	switch opts.Compression {
	case "none":
		compression = models.BackupCompressionNone
	case "zstd":
		compression = models.BackupCompressionZstd
	case "gzip":
		compression = models.BackupCompressionGzip
	}

	createOpts := backupsvc.CreateOptions{
		HostID:        resolveHostID(ctx, a.hostID),
		Type:          backupType,
		TargetID:      opts.TargetID,
		TargetName:    opts.TargetName,
		Trigger:       models.BackupTriggerManual,
		Compression:   compression,
		Encrypt:       opts.Encrypt,
		StopContainer: opts.StopContainer,
	}
	if opts.RetentionDays > 0 {
		createOpts.RetentionDays = &opts.RetentionDays
	}

	result, err := a.svc.Create(ctx, createOpts)
	if err != nil {
		return nil, err
	}

	view := backupToView(result.Backup)
	return &view, nil
}

func (a *backupAdapter) GetStats(ctx context.Context) (*BackupStatsView, error) {
	if a.svc == nil {
		return nil, nil
	}

	hostID := resolveHostID(ctx, a.hostID)
	stats, err := a.svc.GetStats(ctx, &hostID)
	if err != nil {
		return nil, err
	}

	view := &BackupStatsView{
		TotalBackups:     stats.TotalBackups,
		CompletedBackups: stats.CompletedBackups,
		FailedBackups:    stats.FailedBackups,
		TotalSize:        stats.TotalSize,
		TotalSizeHuman:   humanSize(stats.TotalSize),
	}
	if stats.LastBackupAt != nil {
		view.LastBackupAt = humanTime(*stats.LastBackupAt)
	}
	return view, nil
}

func (a *backupAdapter) GetStorageInfo(ctx context.Context) (*BackupStorageView, error) {
	if a.svc == nil {
		return nil, nil
	}

	info, err := a.svc.GetStorageInfo(ctx)
	if err != nil {
		return nil, err
	}

	view := &BackupStorageView{
		Type:            info.Type,
		Path:            info.LocalPath,
		TotalSpace:      info.TotalSize,
		TotalSpaceHuman: humanSize(info.TotalSize),
		UsedSpace:       info.UsedSize,
		UsedSpaceHuman:  humanSize(info.UsedSize),
		BackupCount:     int64(info.BackupCount),
	}
	if info.TotalSize > 0 {
		view.UsagePercent = float64(info.UsedSize) / float64(info.TotalSize) * 100
	}
	return view, nil
}

func (a *backupAdapter) ListSchedules(ctx context.Context) ([]BackupScheduleView, error) {
	if a.svc == nil {
		return nil, nil
	}

	hostID := resolveHostID(ctx, a.hostID)
	schedules, err := a.svc.ListSchedules(ctx, &hostID)
	if err != nil {
		return nil, err
	}

	views := make([]BackupScheduleView, 0, len(schedules))
	for _, s := range schedules {
		view := BackupScheduleView{
			ID:            s.ID.String(),
			Type:          string(s.Type),
			TargetID:      s.TargetID,
			TargetName:    s.TargetName,
			Schedule:      s.Schedule,
			Compression:   string(s.Compression),
			Encrypted:     s.Encrypted,
			RetentionDays: s.RetentionDays,
			MaxBackups:    s.MaxBackups,
			IsEnabled:     s.IsEnabled,
			CreatedAt:     humanTime(s.CreatedAt),
		}
		if s.LastRunAt != nil {
			view.LastRunAt = humanTime(*s.LastRunAt)
		}
		if s.LastRunStatus != nil {
			view.LastRunStatus = string(*s.LastRunStatus)
		}
		if s.NextRunAt != nil {
			view.NextRunAt = humanTime(*s.NextRunAt)
		}
		views = append(views, view)
	}
	return views, nil
}

func (a *backupAdapter) CreateSchedule(ctx context.Context, input BackupScheduleInput) (*BackupScheduleView, error) {
	if a.svc == nil {
		return nil, nil
	}

	backupType := models.BackupTypeContainer
	switch input.Type {
	case "volume":
		backupType = models.BackupTypeVolume
	case "stack":
		backupType = models.BackupTypeStack
	}

	compression := models.BackupCompressionGzip
	switch input.Compression {
	case "none":
		compression = models.BackupCompressionNone
	case "zstd":
		compression = models.BackupCompressionZstd
	}

	hostID := resolveHostID(ctx, a.hostID)
	schedule, err := a.svc.CreateSchedule(ctx, models.CreateBackupScheduleInput{
		Type:          backupType,
		TargetID:      input.TargetID,
		Schedule:      input.Schedule,
		Compression:   compression,
		Encrypted:     input.Encrypted,
		RetentionDays: input.RetentionDays,
		MaxBackups:    input.MaxBackups,
		IsEnabled:     true,
	}, hostID, nil)
	if err != nil {
		return nil, err
	}

	view := &BackupScheduleView{
		ID:            schedule.ID.String(),
		Type:          string(schedule.Type),
		TargetID:      schedule.TargetID,
		TargetName:    schedule.TargetName,
		Schedule:      schedule.Schedule,
		Compression:   string(schedule.Compression),
		Encrypted:     schedule.Encrypted,
		RetentionDays: schedule.RetentionDays,
		MaxBackups:    schedule.MaxBackups,
		IsEnabled:     schedule.IsEnabled,
		CreatedAt:     humanTime(schedule.CreatedAt),
	}
	if schedule.NextRunAt != nil {
		view.NextRunAt = humanTime(*schedule.NextRunAt)
	}
	return view, nil
}

func (a *backupAdapter) DeleteSchedule(ctx context.Context, id string) error {
	if a.svc == nil {
		return nil
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return err
	}

	return a.svc.DeleteSchedule(ctx, uid)
}

func (a *backupAdapter) RunSchedule(ctx context.Context, id string) error {
	if a.svc == nil {
		return nil
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return err
	}

	_, err = a.svc.RunSchedule(ctx, uid)
	return err
}

// ============================================================================
// Config Adapter
// ============================================================================

type configAdapter struct {
	svc *configsvc.Service
}

func (a *configAdapter) ListVariables(ctx context.Context, scope, scopeID string) ([]ConfigVarView, error) {
	if a.svc == nil {
		return nil, nil
	}

	opts := models.VariableListOptions{
		Limit: 500,
	}
	if scope != "" {
		s := models.VariableScope(scope)
		opts.Scope = &s
	}
	if scopeID != "" {
		opts.ScopeID = &scopeID
	}

	vars, _, err := a.svc.ListVariables(ctx, opts)
	if err != nil {
		return nil, err
	}

	views := make([]ConfigVarView, 0, len(vars))
	for _, v := range vars {
		view := ConfigVarView{
			ID:        v.ID.String(),
			Name:      v.Name,
			Value:     v.Value,
			IsSecret:  v.IsSecret(),
			VarType:   string(v.Type),
			Scope:     string(v.Scope),
			UpdatedAt: v.UpdatedAt.Format("2006-01-02 15:04:05"),
		}
		if v.ScopeID != nil {
			view.ScopeID = *v.ScopeID
		}
		if v.IsSecret() {
			view.Value = "••••••••" // Mask secrets in list view
		}
		views = append(views, view)
	}
	return views, nil
}

func (a *configAdapter) GetVariable(ctx context.Context, id string) (*ConfigVarView, error) {
	if a.svc == nil {
		return nil, nil
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid variable ID: %w", err)
	}

	v, err := a.svc.GetVariable(ctx, uid)
	if err != nil {
		return nil, err
	}

	view := &ConfigVarView{
		ID:        v.ID.String(),
		Name:      v.Name,
		Value:     v.Value,
		IsSecret:  v.IsSecret(),
		VarType:   string(v.Type),
		Scope:     string(v.Scope),
		UpdatedAt: v.UpdatedAt.Format("2006-01-02 15:04:05"),
	}
	if v.ScopeID != nil {
		view.ScopeID = *v.ScopeID
	}
	if v.IsSecret() {
		view.Value = "••••••••"
	}
	return view, nil
}

func (a *configAdapter) CreateVariable(ctx context.Context, v *ConfigVarView) error {
	if a.svc == nil {
		return nil
	}

	input := models.CreateVariableInput{
		Name:  v.Name,
		Value: v.Value,
		Type:  models.VariableType(v.VarType),
		Scope: models.VariableScope(v.Scope),
	}
	if v.ScopeID != "" {
		input.ScopeID = &v.ScopeID
	}

	_, err := a.svc.CreateVariable(ctx, input, nil)
	return err
}

func (a *configAdapter) UpdateVariable(ctx context.Context, v *ConfigVarView) error {
	if a.svc == nil {
		return nil
	}

	uid, err := uuid.Parse(v.ID)
	if err != nil {
		return fmt.Errorf("invalid variable ID: %w", err)
	}

	input := models.UpdateVariableInput{}
	if v.Value != "" && v.Value != "••••••••" {
		input.Value = &v.Value
	}

	_, err = a.svc.UpdateVariable(ctx, uid, input, nil)
	return err
}

func (a *configAdapter) DeleteVariable(ctx context.Context, id string) error {
	if a.svc == nil {
		return nil
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid variable ID: %w", err)
	}

	return a.svc.DeleteVariable(ctx, uid, nil)
}

func (a *configAdapter) ListTemplates(ctx context.Context) ([]interface{}, error) {
	if a.svc == nil {
		return nil, nil
	}

	templates, _, err := a.svc.ListTemplates(ctx, nil, 100, 0)
	if err != nil {
		return nil, err
	}

	result := make([]interface{}, 0, len(templates))
	for _, t := range templates {
		result = append(result, map[string]interface{}{
			"id":          t.ID.String(),
			"name":        t.Name,
			"description": t.Description,
			"created_at":  t.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	return result, nil
}

func (a *configAdapter) GetAuditLogs(ctx context.Context, limit int) ([]interface{}, error) {
	if a.svc == nil {
		return nil, nil
	}

	logs, _, err := a.svc.GetAuditLog(ctx, postgres.AuditListOptions{
		Limit: limit,
	})
	if err != nil {
		return nil, err
	}

	result := make([]interface{}, 0, len(logs))
	for _, l := range logs {
		entry := map[string]interface{}{
			"id":          l.ID,
			"action":      l.Action,
			"entity_type": l.EntityType,
			"entity_id":   l.EntityID,
			"entity_name": l.EntityName,
			"created_at":  l.CreatedAt.Format("2006-01-02 15:04:05"),
		}
		if l.Username != nil {
			entry["username"] = *l.Username
		}
		result = append(result, entry)
	}
	return result, nil
}

// ============================================================================
// Security Adapter
// ============================================================================

type securityAdapter struct {
	svc          *securitysvc.Service
	hostSvc      *hostsvc.Service
	containerSvc *containersvc.Service
	hostID       uuid.UUID
}

func (a *securityAdapter) IsTrivyAvailable() bool {
	if a.svc == nil {
		return false
	}
	return a.svc.IsTrivyAvailable()
}

func (a *securityAdapter) GetOverview(ctx context.Context) (*SecurityOverviewData, error) {
	if a.svc == nil {
		return nil, nil
	}

	hostID := resolveHostID(ctx, a.hostID)
	summary, err := a.svc.GetSecuritySummary(ctx, &hostID)
	if err != nil {
		return nil, err
	}

	// Convert severity counts
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	if summary.SeverityCounts != nil {
		criticalCount = summary.SeverityCounts[models.IssueSeverityCritical]
		highCount = summary.SeverityCounts[models.IssueSeverityHigh]
		mediumCount = summary.SeverityCounts[models.IssueSeverityMedium]
		lowCount = summary.SeverityCounts[models.IssueSeverityLow]
	}

	// Convert grade distribution
	gradeA := 0
	gradeB := 0
	gradeC := 0
	gradeD := 0
	gradeF := 0

	if summary.GradeDistribution != nil {
		gradeA = summary.GradeDistribution[models.SecurityGradeA]
		gradeB = summary.GradeDistribution[models.SecurityGradeB]
		gradeC = summary.GradeDistribution[models.SecurityGradeC]
		gradeD = summary.GradeDistribution[models.SecurityGradeD]
		gradeF = summary.GradeDistribution[models.SecurityGradeF]
	}

	return &SecurityOverviewData{
		TotalScanned:   summary.TotalContainers,
		AverageScore:   summary.AverageScore,
		GradeA:         gradeA,
		GradeB:         gradeB,
		GradeC:         gradeC,
		GradeD:         gradeD,
		GradeF:         gradeF,
		CriticalCount:  criticalCount,
		HighCount:      highCount,
		MediumCount:    mediumCount,
		LowCount:       lowCount,
		TrivyAvailable: a.IsTrivyAvailable(),
	}, nil
}

func (a *securityAdapter) ListScans(ctx context.Context) ([]SecurityScanView, error) {
	if a.svc == nil {
		return nil, nil
	}

	scans, _, err := a.svc.ListScans(ctx, securitysvc.ListScansOptions{Limit: 100})
	if err != nil {
		return nil, err
	}

	views := make([]SecurityScanView, 0, len(scans))
	for _, s := range scans {
		views = append(views, securityScanToView(s))
	}
	return views, nil
}

func (a *securityAdapter) ListContainersWithSecurity(ctx context.Context) ([]ContainerSecurityView, error) {
	if a.hostSvc == nil {
		return nil, nil
	}

	// Get Docker client
	dockerClient, err := a.hostSvc.GetClient(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return nil, fmt.Errorf("failed to get docker client: %w", err)
	}

	// List all containers (including stopped)
	containers, err := dockerClient.ContainerList(ctx, docker.ContainerListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	// Build a map of latest scans by container ID
	scanMap := make(map[string]*models.SecurityScan)
	if a.svc != nil {
		scans, _, _ := a.svc.ListScans(ctx, securitysvc.ListScansOptions{Limit: 500})
		for _, scan := range scans {
			existing, ok := scanMap[scan.ContainerID]
			if !ok || scan.CreatedAt.After(existing.CreatedAt) {
				scanMap[scan.ContainerID] = scan
			}
		}
	}

	// Convert to views
	views := make([]ContainerSecurityView, 0, len(containers))
	for _, c := range containers {
		view := ContainerSecurityView{
			ID:    c.ID,
			Name:  c.Name,
			Image: c.Image,
			State: c.State,
		}

		// Check if there's a scan for this container
		if scan, ok := scanMap[c.ID]; ok {
			view.HasScan = true
			view.Score = scan.Score
			view.Grade = string(scan.Grade)
			view.IssueCount = scan.IssueCount
			view.LastScanned = scan.CompletedAt.Format("Jan 02 15:04")
		}

		views = append(views, view)
	}

	return views, nil
}

func (a *securityAdapter) GetScan(ctx context.Context, containerID string) (*SecurityScanView, error) {
	if a.svc == nil {
		return nil, nil
	}

	scan, err := a.svc.GetLatestScan(ctx, containerID)
	if err != nil {
		return nil, err
	}

	view := securityScanToView(scan)
	return &view, nil
}

func (a *securityAdapter) Scan(ctx context.Context, containerID string) (*SecurityScanView, error) {
	if a.svc == nil || a.hostSvc == nil {
		return nil, fmt.Errorf("security service not initialized")
	}

	// Get Docker client for this host
	dockerClient, err := a.hostSvc.GetClient(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return nil, fmt.Errorf("failed to get docker client: %w", err)
	}

	// Get raw Docker inspect data
	inspectData, err := dockerClient.ContainerInspectRaw(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	// Run security scan
	scan, err := a.svc.ScanContainerJSON(ctx, inspectData, resolveHostID(ctx, a.hostID))
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	// Update container record with security score
	if a.containerSvc != nil && scan != nil {
		if updateErr := a.containerSvc.UpdateSecurityInfo(ctx, containerID, scan.Score, string(scan.Grade)); updateErr != nil {
			// Log but don't fail the scan
			_ = updateErr
		}
	}

	view := securityScanToView(scan)
	return &view, nil
}

func (a *securityAdapter) ScanAll(ctx context.Context) error {
	if a.svc == nil || a.hostSvc == nil {
		return fmt.Errorf("security service not initialized")
	}

	// Get Docker client
	dockerClient, err := a.hostSvc.GetClient(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return fmt.Errorf("failed to get docker client: %w", err)
	}

	// List all running containers
	containers, err := dockerClient.ContainerList(ctx, docker.ContainerListOptions{All: false})
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	// Scan each container
	for _, c := range containers {
		inspectData, err := dockerClient.ContainerInspectRaw(ctx, c.ID)
		if err != nil {
			continue // skip containers we can't inspect
		}
		if _, err := a.svc.ScanContainerJSON(ctx, inspectData, resolveHostID(ctx, a.hostID)); err != nil {
			continue // skip failed scans
		}
	}

	return nil
}

func (a *securityAdapter) ListIssues(ctx context.Context) ([]IssueView, error) {
	if a.svc == nil {
		return nil, nil
	}

	issues, _, err := a.svc.GetHostIssues(ctx, resolveHostID(ctx, a.hostID), securitysvc.ListIssuesOptions{Limit: 100})
	if err != nil {
		return nil, err
	}

	views := make([]IssueView, 0, len(issues))
	for _, i := range issues {
		views = append(views, issueToView(i))
	}
	return views, nil
}

func parseIssueID(id string) (int64, error) {
	return strconv.ParseInt(id, 10, 64)
}

func (a *securityAdapter) IgnoreIssue(ctx context.Context, id string) error {
	if a.svc == nil {
		return nil
	}

	issueID, err := parseIssueID(id)
	if err != nil {
		return err
	}

	return a.svc.UpdateIssueStatus(ctx, issueID, models.IssueStatusIgnored, nil)
}

func (a *securityAdapter) ResolveIssue(ctx context.Context, id string) error {
	if a.svc == nil {
		return nil
	}

	issueID, err := parseIssueID(id)
	if err != nil {
		return err
	}

	return a.svc.UpdateIssueStatus(ctx, issueID, models.IssueStatusResolved, nil)
}

func (a *securityAdapter) GetTrends(ctx context.Context, days int) (*SecurityTrendsViewData, error) {
	if a.svc == nil {
		return nil, nil
	}
	if days <= 0 {
		days = 30
	}

	// Get score history (global average across all containers)
	points, err := a.svc.GetGlobalScoreHistory(ctx, days)
	if err != nil {
		return nil, err
	}

	history := make([]TrendPointView, 0, len(points))
	for _, p := range points {
		history = append(history, TrendPointView{
			Date:  p.Timestamp.Format("Jan 02"),
			Score: p.Value,
		})
	}

	// Get overview for summary
	overview, err := a.GetOverview(ctx)
	if err != nil {
		overview = &SecurityOverviewData{}
	}

	// Get per-container trends (latest scans)
	scans, _ := a.ListScans(ctx)
	containerTrends := make([]ContainerTrendViewData, 0, len(scans))
	for _, s := range scans {
		ct := ContainerTrendViewData{
			Name:         s.ContainerName,
			CurrentScore: s.Score,
			CurrentGrade: s.Grade,
		}
		// Get previous scan for this container to calculate change
		prevScans, _ := a.svc.GetContainerScans(ctx, s.ContainerID, 2)
		if len(prevScans) >= 2 {
			ct.PreviousScore = prevScans[1].Score
			ct.Change = ct.CurrentScore - ct.PreviousScore
		}
		containerTrends = append(containerTrends, ct)
	}

	return &SecurityTrendsViewData{
		Overview:        *overview,
		ScoreHistory:    history,
		ContainerTrends: containerTrends,
		Days:            days,
	}, nil
}

func (a *securityAdapter) GenerateReport(ctx context.Context, format string) ([]byte, string, error) {
	if a.svc == nil {
		return nil, "", fmt.Errorf("security service not available")
	}

	var reportFormat securitysvc.ReportFormat
	var contentType string

	switch format {
	case "html":
		reportFormat = securitysvc.ReportFormatHTML
		contentType = "text/html; charset=utf-8"
	case "json":
		reportFormat = securitysvc.ReportFormatJSON
		contentType = "application/json"
	case "markdown", "md":
		reportFormat = securitysvc.ReportFormatMarkdown
		contentType = "text/markdown; charset=utf-8"
	default:
		reportFormat = securitysvc.ReportFormatHTML
		contentType = "text/html; charset=utf-8"
	}

	opts := &securitysvc.ReportOptions{
		Format:          reportFormat,
		IncludeDetails:  true,
		GroupBySeverity: true,
		MinSeverity:     models.IssueSeverityLow,
	}

	data, err := a.svc.GenerateReport(ctx, resolveHostID(ctx, a.hostID), opts)
	if err != nil {
		return nil, "", err
	}

	return data, contentType, nil
}

// ============================================================================
// Update Adapter
// ============================================================================

type updateAdapter struct {
	svc    *updatesvc.Service
	hostID uuid.UUID
}

func (a *updateAdapter) ListAvailable(ctx context.Context) ([]UpdateView, error) {
	if a.svc == nil {
		return nil, nil
	}
	result, err := a.svc.CheckForUpdates(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	views := make([]UpdateView, 0, len(result.Updates))
	for _, u := range result.Updates {
		if !u.NeedsUpdate() {
			continue
		}
		v := UpdateView{
			ContainerID:    u.ContainerID,
			ContainerName:  u.ContainerName,
			Image:          u.Image,
			CurrentVersion: u.CurrentVersion,
			LatestVersion:  u.LatestVersion,
			CheckedAt:      u.CheckedAt.Format("2006-01-02 15:04"),
		}
		if u.Changelog != nil {
			v.Changelog = u.Changelog.Body
			v.ChangelogURL = u.Changelog.URL
		}
		views = append(views, v)
	}
	return views, nil
}

func (a *updateAdapter) CheckAll(ctx context.Context) error {
	if a.svc == nil {
		return nil
	}
	_, err := a.svc.CheckForUpdates(ctx, resolveHostID(ctx, a.hostID))
	return err
}

func (a *updateAdapter) GetChangelog(ctx context.Context, containerID string) (string, error) {
	if a.svc == nil {
		return "", nil
	}
	update, err := a.svc.CheckContainerForUpdate(ctx, resolveHostID(ctx, a.hostID), containerID)
	if err != nil {
		return "", err
	}
	if update != nil && update.Changelog != nil {
		return update.Changelog.Body, nil
	}
	return "", nil
}

func (a *updateAdapter) Apply(ctx context.Context, containerID string, backup bool, targetVersion string) error {
	if a.svc == nil {
		return nil
	}
	opts := &models.UpdateOptions{
		ContainerID:   containerID,
		TargetVersion: targetVersion,
		BackupVolumes: backup,
		SecurityScan:  true,
	}
	_, err := a.svc.UpdateContainer(ctx, resolveHostID(ctx, a.hostID), opts)
	return err
}

func (a *updateAdapter) Rollback(ctx context.Context, updateID string) error {
	if a.svc == nil {
		return nil
	}
	uid, err := uuid.Parse(updateID)
	if err != nil {
		return fmt.Errorf("invalid update ID: %w", err)
	}
	opts := &models.RollbackOptions{
		UpdateID:      uid,
		RestoreBackup: true,
	}
	_, err = a.svc.RollbackUpdate(ctx, opts)
	return err
}

func (a *updateAdapter) GetHistory(ctx context.Context) ([]UpdateHistoryView, error) {
	if a.svc == nil {
		return nil, nil
	}
	updates, err := a.svc.GetHistory(ctx, resolveHostID(ctx, a.hostID), "", 50)
	if err != nil {
		return nil, err
	}
	views := make([]UpdateHistoryView, 0, len(updates))
	for _, u := range updates {
		v := UpdateHistoryView{
			ID:            u.ID.String(),
			ContainerName: u.TargetName,
			FromVersion:   u.FromVersion,
			ToVersion:     u.ToVersion,
			Status:        string(u.Status),
			UpdatedAt:     u.CreatedAt.Format("2006-01-02 15:04"),
		}
		if u.DurationMs != nil {
			dur := time.Duration(*u.DurationMs) * time.Millisecond
			v.Duration = dur.Round(time.Second).String()
		}
		views = append(views, v)
	}
	return views, nil
}

// ============================================================================
// Host Adapter
// ============================================================================

type hostAdapter struct {
	svc    *hostsvc.Service
	hostID uuid.UUID
}

func (a *hostAdapter) GetDockerInfo(ctx context.Context) (*DockerInfoView, error) {
	if a.svc == nil {
		return nil, nil
	}
	info, err := a.svc.GetDockerInfo(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return nil, err
	}
	return &DockerInfoView{
		ID:                info.ID,
		Name:              info.Name,
		ServerVersion:     info.ServerVersion,
		APIVersion:        info.APIVersion,
		OS:                info.OperatingSystem,
		OSType:            info.OSType,
		Architecture:      info.Architecture,
		KernelVersion:     info.KernelVersion,
		Containers:        info.Containers,
		ContainersRunning: info.ContainersRunning,
		ContainersPaused:  info.ContainersPaused,
		ContainersStopped: info.ContainersStopped,
		Images:            info.Images,
		MemTotal:          info.MemTotal,
		NCPU:              info.NCPU,
		DockerRootDir:     info.DockerRootDir,
		Swarm:             info.SwarmActive,
	}, nil
}

func (a *hostAdapter) List(ctx context.Context) ([]HostView, error) {
	if a.svc == nil {
		return nil, nil
	}

	summaries, err := a.svc.ListSummaries(ctx)
	if err != nil {
		return nil, err
	}

	views := make([]HostView, 0, len(summaries))
	for _, s := range summaries {
		v := HostView{
			ID:                s.ID.String(),
			Name:              s.Name,
			EndpointType:      string(s.EndpointType),
			Status:            string(s.Status),
			TLSEnabled:        s.TLSEnabled,
			Containers:        s.ContainerCount,
			ContainersRunning: s.RunningCount,
			LastSeen:          s.CreatedAt,
		}
		if s.DisplayName != nil {
			v.DisplayName = *s.DisplayName
		}
		if s.EndpointURL != nil {
			v.Endpoint = *s.EndpointURL
		} else if s.EndpointType == models.EndpointLocal {
			v.Endpoint = "unix:///var/run/docker.sock"
		}
		if s.DockerVersion != nil {
			v.DockerVersion = *s.DockerVersion
		}
		if s.OSType != nil {
			v.OS = *s.OSType
		}
		if s.Architecture != nil {
			v.Arch = *s.Architecture
		}
		if s.TotalCPUs != nil {
			v.CPUs = *s.TotalCPUs
		}
		if s.TotalMemory != nil {
			v.Memory = *s.TotalMemory
			mb := *s.TotalMemory / (1024 * 1024)
			if mb >= 1024 {
				v.MemoryHuman = fmt.Sprintf("%.1f GB", float64(mb)/1024)
			} else {
				v.MemoryHuman = fmt.Sprintf("%d MB", mb)
			}
		}
		if s.LastSeenAt != nil {
			v.LastSeen = *s.LastSeenAt
			dur := time.Since(*s.LastSeenAt)
			switch {
			case dur < time.Minute:
				v.LastSeenHuman = "just now"
			case dur < time.Hour:
				v.LastSeenHuman = fmt.Sprintf("%dm ago", int(dur.Minutes()))
			case dur < 24*time.Hour:
				v.LastSeenHuman = fmt.Sprintf("%dh ago", int(dur.Hours()))
			default:
				v.LastSeenHuman = s.LastSeenAt.Format("2006-01-02 15:04")
			}
		}
		views = append(views, v)
	}

	return views, nil
}

func (a *hostAdapter) Get(ctx context.Context, id string) (*HostView, error) {
	if a.svc == nil {
		return nil, nil
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid host ID: %w", err)
	}
	h, err := a.svc.Get(ctx, uid)
	if err != nil {
		return nil, err
	}
	v := &HostView{
		ID:           h.ID.String(),
		Name:         h.Name,
		EndpointType: string(h.EndpointType),
		Status:       string(h.Status),
		TLSEnabled:   h.TLSEnabled,
	}
	if h.DisplayName != nil {
		v.DisplayName = *h.DisplayName
	}
	if h.EndpointURL != nil {
		v.Endpoint = *h.EndpointURL
	} else if h.EndpointType == models.EndpointLocal {
		v.Endpoint = "unix:///var/run/docker.sock"
	}
	if h.DockerVersion != nil {
		v.DockerVersion = *h.DockerVersion
	}
	if h.OSType != nil {
		v.OS = *h.OSType
	}
	if h.Architecture != nil {
		v.Arch = *h.Architecture
	}
	if h.TotalCPUs != nil {
		v.CPUs = *h.TotalCPUs
	}
	if h.TotalMemory != nil {
		v.Memory = *h.TotalMemory
		mb := *h.TotalMemory / (1024 * 1024)
		if mb >= 1024 {
			v.MemoryHuman = fmt.Sprintf("%.1f GB", float64(mb)/1024)
		} else {
			v.MemoryHuman = fmt.Sprintf("%d MB", mb)
		}
	}
	if h.LastSeenAt != nil {
		v.LastSeen = *h.LastSeenAt
		dur := time.Since(*h.LastSeenAt)
		switch {
		case dur < time.Minute:
			v.LastSeenHuman = "just now"
		case dur < time.Hour:
			v.LastSeenHuman = fmt.Sprintf("%dm ago", int(dur.Minutes()))
		case dur < 24*time.Hour:
			v.LastSeenHuman = fmt.Sprintf("%dh ago", int(dur.Hours()))
		default:
			v.LastSeenHuman = h.LastSeenAt.Format("2006-01-02 15:04")
		}
	}
	return v, nil
}

func (a *hostAdapter) Create(ctx context.Context, hv *HostView) (string, error) {
	if a.svc == nil {
		return "", fmt.Errorf("host service not initialized")
	}
	input := &models.CreateHostInput{
		Name:         hv.Name,
		EndpointType: models.HostEndpointType(hv.EndpointType),
		TLSEnabled:   hv.TLSEnabled,
	}
	if hv.Endpoint != "" {
		input.EndpointURL = &hv.Endpoint
	}
	if hv.DisplayName != "" {
		input.DisplayName = &hv.DisplayName
	}
	host, err := a.svc.Create(ctx, input)
	if err != nil {
		return "", err
	}
	return host.ID.String(), nil
}

func (a *hostAdapter) Update(ctx context.Context, hv *HostView) error {
	if a.svc == nil {
		return nil
	}
	uid, err := uuid.Parse(hv.ID)
	if err != nil {
		return fmt.Errorf("invalid host ID: %w", err)
	}
	input := &models.UpdateHostInput{}
	if hv.DisplayName != "" {
		input.DisplayName = &hv.DisplayName
	}
	if hv.Endpoint != "" {
		input.EndpointURL = &hv.Endpoint
	}
	// Always pass TLS enabled state so it can be toggled off
	input.TLSEnabled = &hv.TLSEnabled
	_, err = a.svc.Update(ctx, uid, input)
	return err
}

func (a *hostAdapter) Remove(ctx context.Context, id string) error {
	if a.svc == nil {
		return nil
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid host ID: %w", err)
	}
	return a.svc.Delete(ctx, uid)
}

func (a *hostAdapter) Test(ctx context.Context, id string) error {
	// Host service health checks run automatically
	return nil
}

func (a *hostAdapter) GenerateAgentToken(ctx context.Context, id string) (string, error) {
	if a.svc == nil {
		return "", fmt.Errorf("host service not initialized")
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		return "", fmt.Errorf("invalid host ID: %w", err)
	}
	return a.svc.GenerateAgentToken(ctx, uid)
}

// ============================================================================
// Event Adapter (Docker events)
// ============================================================================

type eventAdapter struct {
	dockerClient *docker.Client
}

func (a *eventAdapter) List(ctx context.Context, limit int) ([]EventView, error) {
	if a.dockerClient == nil {
		return nil, nil
	}
	since := time.Now().Add(-1 * time.Hour)
	dockerEvents, err := a.dockerClient.GetEvents(ctx, since)
	if err != nil {
		// Gracefully degrade - don't break the page if Docker events fail
		return nil, nil
	}

	// Build list from newest first
	var events []EventView
	for i := len(dockerEvents) - 1; i >= 0; i-- {
		e := dockerEvents[i]
		events = append(events, EventView{
			ID:        fmt.Sprintf("%d", e.Time.UnixNano()),
			Type:      e.Type,
			Action:    e.Action,
			ActorID:   e.ActorID,
			ActorName: e.ActorName,
			ActorType: e.Type,
			Message:   fmt.Sprintf("%s %s: %s", e.Type, e.Action, e.ActorName),
			Timestamp: e.Time,
			TimeHuman: timeAgo(e.Time),
		})
		if len(events) >= limit {
			break
		}
	}
	return events, nil
}

func (a *eventAdapter) Stream(ctx context.Context) (<-chan EventView, error) {
	if a.dockerClient == nil {
		ch := make(chan EventView)
		close(ch)
		return ch, nil
	}

	eventCh, errCh := a.dockerClient.StreamEvents(ctx)
	viewCh := make(chan EventView, 64)

	go func() {
		defer close(viewCh)
		for {
			select {
			case e, ok := <-eventCh:
				if !ok {
					return
				}
				view := EventView{
					ID:        fmt.Sprintf("%d", e.Time.UnixNano()),
					Type:      e.Type,
					Action:    e.Action,
					ActorID:   e.ActorID,
					ActorName: e.ActorName,
					ActorType: e.Type,
					Message:   fmt.Sprintf("%s %s: %s", e.Type, e.Action, e.ActorName),
					Timestamp: e.Time,
					TimeHuman: timeAgo(e.Time),
				}
				select {
				case viewCh <- view:
				case <-ctx.Done():
					return
				}
			case <-errCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	return viewCh, nil
}

// ============================================================================
// Proxy Adapter (NPM integration)
// ============================================================================

type proxyAdapter struct {
	npmSvc *npm.Service
	hostID uuid.UUID
}

// hasSSLCertificate checks if a CertificateID interface{} value represents a valid certificate.
// NPM returns CertificateID as int, string "new", or null from JSON.
func hasSSLCertificate(v interface{}) bool {
	if v == nil {
		return false
	}
	switch val := v.(type) {
	case float64:
		return val > 0
	case int:
		return val > 0
	case string:
		return val != "" && val != "0"
	default:
		return false
	}
}

func (a *proxyAdapter) ListHosts(ctx context.Context) ([]ProxyHostView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}

	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}

	hosts, err := client.ListProxyHosts(ctx)
	if err != nil {
		return nil, err
	}

	views := make([]ProxyHostView, 0, len(hosts))
	for _, h := range hosts {
		domain := ""
		if len(h.DomainNames) > 0 {
			domain = h.DomainNames[0]
		}
		views = append(views, ProxyHostView{
			ID:          h.ID,
			Domain:      domain,
			ForwardHost: h.ForwardHost,
			ForwardPort: h.ForwardPort,
			SSLEnabled:  hasSSLCertificate(h.CertificateID),
			Enabled:     h.Enabled,
		})
	}
	return views, nil
}

func (a *proxyAdapter) GetHost(ctx context.Context, id int) (*ProxyHostView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}

	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}

	h, err := client.GetProxyHost(ctx, id)
	if err != nil {
		return nil, err
	}

	domain := ""
	if len(h.DomainNames) > 0 {
		domain = h.DomainNames[0]
	}
	return &ProxyHostView{
		ID:          h.ID,
		Domain:      domain,
		ForwardHost: h.ForwardHost,
		ForwardPort: h.ForwardPort,
		SSLEnabled:  hasSSLCertificate(h.CertificateID),
		Enabled:     h.Enabled,
	}, nil
}

func (a *proxyAdapter) CreateHost(ctx context.Context, h *ProxyHostView) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}

	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}

	host := &npm.ProxyHost{
		DomainNames:   []string{h.Domain},
		ForwardScheme: "http",
		ForwardHost:   h.ForwardHost,
		ForwardPort:   h.ForwardPort,
		Enabled:       true,
	}

	created, err := client.CreateProxyHost(ctx, host)
	if err != nil {
		return err
	}
	h.ID = created.ID
	return nil
}

func (a *proxyAdapter) UpdateHost(ctx context.Context, h *ProxyHostView) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}

	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}

	host := &npm.ProxyHost{
		DomainNames:   []string{h.Domain},
		ForwardScheme: "http",
		ForwardHost:   h.ForwardHost,
		ForwardPort:   h.ForwardPort,
		Enabled:       h.Enabled,
	}

	_, err = client.UpdateProxyHost(ctx, h.ID, host)
	return err
}

func (a *proxyAdapter) RemoveHost(ctx context.Context, id int) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}

	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}

	return client.DeleteProxyHost(ctx, id)
}

func (a *proxyAdapter) EnableHost(ctx context.Context, id int) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}

	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}

	return client.EnableProxyHost(ctx, id)
}

func (a *proxyAdapter) DisableHost(ctx context.Context, id int) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}

	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}

	return client.DisableProxyHost(ctx, id)
}

func (a *proxyAdapter) Sync(ctx context.Context) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	return a.npmSvc.TestConnection(ctx, resolveHostID(ctx, a.hostID).String())
}

// --- NPM Connection Management ---

func (a *proxyAdapter) GetConnection(ctx context.Context) (*models.NPMConnection, error) {
	if a.npmSvc == nil {
		return nil, nil // Not configured, return nil
	}
	conn, err := a.npmSvc.GetConnection(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, nil // Not found is normal
	}
	return conn, nil
}

func (a *proxyAdapter) SetupConnection(ctx context.Context, baseURL, email, password, userID string) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not enabled")
	}
	_, err := a.npmSvc.ConfigureConnection(ctx, resolveHostID(ctx, a.hostID).String(), &npm.ConnectionCreate{
		HostID:        resolveHostID(ctx, a.hostID).String(),
		BaseURL:       baseURL,
		AdminEmail:    email,
		AdminPassword: password,
	}, userID)
	return err
}

func (a *proxyAdapter) UpdateConnectionConfig(ctx context.Context, connID string, baseURL, email, password *string, enabled *bool, userID string) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not enabled")
	}
	_, err := a.npmSvc.UpdateConnection(ctx, connID, &npm.ConnectionUpdate{
		BaseURL:       baseURL,
		AdminEmail:    email,
		AdminPassword: password,
		IsEnabled:     enabled,
	}, userID)
	return err
}

func (a *proxyAdapter) DeleteConnection(ctx context.Context, connID string) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not enabled")
	}
	return a.npmSvc.DeleteConnection(ctx, connID)
}

func (a *proxyAdapter) IsConnected(ctx context.Context) bool {
	if a.npmSvc == nil {
		return false
	}
	conn, err := a.npmSvc.GetConnection(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil || conn == nil {
		return false
	}
	return conn.IsEnabled && conn.HealthStatus == "healthy"
}

// --- Redirections ---

func (a *proxyAdapter) ListRedirections(ctx context.Context) ([]RedirectionHostView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}
	redirs, err := client.ListRedirectionHosts(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]RedirectionHostView, 0, len(redirs))
	for _, r := range redirs {
		domain := ""
		if len(r.DomainNames) > 0 {
			domain = r.DomainNames[0]
		}
		certID := 0
		if v, ok := r.CertificateID.(float64); ok {
			certID = int(v)
		}
		views = append(views, RedirectionHostView{
			ID:              r.ID,
			DomainNames:     r.DomainNames,
			Domain:          domain,
			ForwardScheme:   r.ForwardScheme,
			ForwardDomain:   r.ForwardDomainName,
			ForwardHTTPCode: r.ForwardHTTPCode,
			Enabled:         r.Enabled,
			PreservePath:    r.PreservePath,
			SSLForced:       r.SSLForced,
			CertificateID:   certID,
		})
	}
	return views, nil
}

func (a *proxyAdapter) GetRedirection(ctx context.Context, id int) (*RedirectionHostView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}
	r, err := client.GetRedirectionHost(ctx, id)
	if err != nil {
		return nil, err
	}
	domain := ""
	if len(r.DomainNames) > 0 {
		domain = r.DomainNames[0]
	}
	certID := 0
	if v, ok := r.CertificateID.(float64); ok {
		certID = int(v)
	}
	return &RedirectionHostView{
		ID:              r.ID,
		DomainNames:     r.DomainNames,
		Domain:          domain,
		ForwardScheme:   r.ForwardScheme,
		ForwardDomain:   r.ForwardDomainName,
		ForwardHTTPCode: r.ForwardHTTPCode,
		Enabled:         r.Enabled,
		PreservePath:    r.PreservePath,
		SSLForced:       r.SSLForced,
		CertificateID:   certID,
	}, nil
}

func (a *proxyAdapter) CreateRedirection(ctx context.Context, rv *RedirectionHostView) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	domainNames := rv.DomainNames
	if len(domainNames) == 0 && rv.Domain != "" {
		domainNames = []string{rv.Domain}
	}
	r := &npm.RedirectionHost{
		DomainNames:       domainNames,
		ForwardScheme:     rv.ForwardScheme,
		ForwardDomainName: rv.ForwardDomain,
		ForwardHTTPCode:   rv.ForwardHTTPCode,
		PreservePath:      rv.PreservePath,
		SSLForced:         rv.SSLForced,
		CertificateID:     rv.CertificateID,
		Enabled:           true,
	}
	created, err := client.CreateRedirectionHost(ctx, r)
	if err != nil {
		return err
	}
	rv.ID = created.ID
	return nil
}

func (a *proxyAdapter) UpdateRedirection(ctx context.Context, rv *RedirectionHostView) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	domainNames := rv.DomainNames
	if len(domainNames) == 0 && rv.Domain != "" {
		domainNames = []string{rv.Domain}
	}
	r := &npm.RedirectionHost{
		DomainNames:       domainNames,
		ForwardScheme:     rv.ForwardScheme,
		ForwardDomainName: rv.ForwardDomain,
		ForwardHTTPCode:   rv.ForwardHTTPCode,
		PreservePath:      rv.PreservePath,
		SSLForced:         rv.SSLForced,
		CertificateID:     rv.CertificateID,
		Enabled:           rv.Enabled,
	}
	_, err = client.UpdateRedirectionHost(ctx, rv.ID, r)
	return err
}

func (a *proxyAdapter) DeleteRedirection(ctx context.Context, id int) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	return client.DeleteRedirectionHost(ctx, id)
}

// --- Streams ---

func (a *proxyAdapter) ListStreams(ctx context.Context) ([]StreamView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}
	streams, err := client.ListStreams(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]StreamView, 0, len(streams))
	for _, s := range streams {
		views = append(views, StreamView{
			ID:            s.ID,
			IncomingPort:  s.IncomingPort,
			ForwardingHost: s.ForwardingHost,
			ForwardingPort: s.ForwardingPort,
			TCPForwarding: s.TCPForwarding,
			UDPForwarding: s.UDPForwarding,
			Enabled:       s.Enabled,
		})
	}
	return views, nil
}

func (a *proxyAdapter) GetStream(ctx context.Context, id int) (*StreamView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}
	s, err := client.GetStream(ctx, id)
	if err != nil {
		return nil, err
	}
	return &StreamView{
		ID:            s.ID,
		IncomingPort:  s.IncomingPort,
		ForwardingHost: s.ForwardingHost,
		ForwardingPort: s.ForwardingPort,
		TCPForwarding: s.TCPForwarding,
		UDPForwarding: s.UDPForwarding,
		Enabled:       s.Enabled,
	}, nil
}

func (a *proxyAdapter) CreateStream(ctx context.Context, sv *StreamView) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	s := &npm.Stream{
		IncomingPort:   sv.IncomingPort,
		ForwardingHost: sv.ForwardingHost,
		ForwardingPort: sv.ForwardingPort,
		TCPForwarding:  sv.TCPForwarding,
		UDPForwarding:  sv.UDPForwarding,
		Enabled:        true,
	}
	created, err := client.CreateStream(ctx, s)
	if err != nil {
		return err
	}
	sv.ID = created.ID
	return nil
}

func (a *proxyAdapter) UpdateStream(ctx context.Context, sv *StreamView) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	s := &npm.Stream{
		IncomingPort:   sv.IncomingPort,
		ForwardingHost: sv.ForwardingHost,
		ForwardingPort: sv.ForwardingPort,
		TCPForwarding:  sv.TCPForwarding,
		UDPForwarding:  sv.UDPForwarding,
		Enabled:        sv.Enabled,
	}
	_, err = client.UpdateStream(ctx, sv.ID, s)
	return err
}

func (a *proxyAdapter) DeleteStream(ctx context.Context, id int) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	return client.DeleteStream(ctx, id)
}

// --- Dead Hosts ---

func (a *proxyAdapter) ListDeadHosts(ctx context.Context) ([]DeadHostView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}
	dead, err := client.ListDeadHosts(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]DeadHostView, 0, len(dead))
	for _, d := range dead {
		domain := ""
		if len(d.DomainNames) > 0 {
			domain = d.DomainNames[0]
		}
		certID := 0
		if v, ok := d.CertificateID.(float64); ok {
			certID = int(v)
		}
		views = append(views, DeadHostView{
			ID:          d.ID,
			DomainNames: d.DomainNames,
			Domain:      domain,
			SSLForced:   d.SSLForced,
			CertID:      certID,
			Enabled:     d.Enabled,
		})
	}
	return views, nil
}

func (a *proxyAdapter) CreateDeadHost(ctx context.Context, dv *DeadHostView) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	domainNames := dv.DomainNames
	if len(domainNames) == 0 && dv.Domain != "" {
		domainNames = []string{dv.Domain}
	}
	d := &npm.DeadHost{
		DomainNames: domainNames,
		SSLForced:   dv.SSLForced,
		Enabled:     true,
	}
	if dv.CertID > 0 {
		d.CertificateID = dv.CertID
	}
	created, err := client.CreateDeadHost(ctx, d)
	if err != nil {
		return err
	}
	dv.ID = created.ID
	return nil
}

func (a *proxyAdapter) DeleteDeadHost(ctx context.Context, id int) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	return client.DeleteDeadHost(ctx, id)
}

// --- Certificates ---

func (a *proxyAdapter) ListCertificates(ctx context.Context) ([]CertificateView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}
	certs, err := client.ListCertificates(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]CertificateView, 0, len(certs))
	for _, c := range certs {
		views = append(views, CertificateView{
			ID:        c.ID,
			NiceName:  c.NiceName,
			Provider:  c.Provider,
			ExpiresOn: c.ExpiresOn,
		})
	}
	return views, nil
}

func (a *proxyAdapter) GetCertificate(ctx context.Context, id int) (*CertificateView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}
	c, err := client.GetCertificate(ctx, id)
	if err != nil {
		return nil, err
	}
	return &CertificateView{
		ID:          c.ID,
		NiceName:    c.NiceName,
		Provider:    c.Provider,
		ExpiresOn:   c.ExpiresOn,
		DomainNames: c.DomainNames,
	}, nil
}

func (a *proxyAdapter) RequestLECertificate(ctx context.Context, domains []string, email string, agree bool, dnsChallenge bool, dnsProvider, dnsCredentials string, propagation int) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}

	req := &npm.CertificateRequest{
		DomainNames:      domains,
		LetsencryptEmail: email,
		LetsencryptAgree: agree,
		DNSChallenge:     dnsChallenge,
		DNSProvider:      dnsProvider,
		PropagationSeconds: propagation,
	}
	if dnsCredentials != "" {
		req.DNSProviderCredentials = dnsCredentials
	}

	_, err = client.RequestLetsEncryptCertificate(ctx, req)
	return err
}

func (a *proxyAdapter) UploadCustomCertificate(ctx context.Context, niceName string, cert, key, intermediate []byte) error {
	// Custom certificate upload not yet supported by NPM client
	return fmt.Errorf("custom certificate upload not yet implemented")
}

func (a *proxyAdapter) RenewCertificate(ctx context.Context, id int) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	_, err = client.RenewCertificate(ctx, id)
	return err
}

func (a *proxyAdapter) DeleteCertificate(ctx context.Context, id int) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	return client.DeleteCertificate(ctx, id)
}

// --- Access Lists ---

func (a *proxyAdapter) ListAccessLists(ctx context.Context) ([]AccessListView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}
	lists, err := client.ListAccessLists(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]AccessListView, 0, len(lists))
	for _, l := range lists {
		views = append(views, AccessListView{
			ID:          l.ID,
			Name:        l.Name,
			PassAuth:    l.PassAuth,
			SatisfyAny:  l.SatisfyAny,
			ClientCount: toInt(l.Meta["clients"]),
			ItemCount:   toInt(l.Meta["items"]),
		})
	}
	return views, nil
}

func (a *proxyAdapter) GetAccessList(ctx context.Context, id int) (*AccessListDetailView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}
	l, err := client.GetAccessList(ctx, id)
	if err != nil {
		return nil, err
	}
	items := make([]AccessListItemView, 0, len(l.Items))
	for _, i := range l.Items {
		items = append(items, AccessListItemView{
			Username: i.Username,
			Password: i.Password,
		})
	}
	clients := make([]AccessListClientView, 0, len(l.Clients))
	for _, c := range l.Clients {
		clients = append(clients, AccessListClientView{
			Address: c.Address,
			Directive: c.Directive,
		})
	}
	return &AccessListDetailView{
		ID:         l.ID,
		Name:       l.Name,
		PassAuth:   l.PassAuth,
		SatisfyAny: l.SatisfyAny,
		Items:      items,
		Clients:    clients,
	}, nil
}

func (a *proxyAdapter) CreateAccessList(ctx context.Context, av *AccessListDetailView) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	items := make([]npm.AccessListItem, 0, len(av.Items))
	for _, i := range av.Items {
		items = append(items, npm.AccessListItem{Username: i.Username, Password: i.Password})
	}
	clients := make([]npm.AccessListClient, 0, len(av.Clients))
	for _, c := range av.Clients {
		clients = append(clients, npm.AccessListClient{Address: c.Address, Directive: c.Directive})
	}
	l := &npm.AccessList{
		Name:       av.Name,
		PassAuth:   av.PassAuth,
		SatisfyAny: av.SatisfyAny,
		Items:      items,
		Clients:    clients,
	}
	created, err := client.CreateAccessList(ctx, l)
	if err != nil {
		return err
	}
	av.ID = created.ID
	return nil
}

func (a *proxyAdapter) UpdateAccessList(ctx context.Context, av *AccessListDetailView) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	items := make([]npm.AccessListItem, 0, len(av.Items))
	for _, i := range av.Items {
		items = append(items, npm.AccessListItem{Username: i.Username, Password: i.Password})
	}
	clients := make([]npm.AccessListClient, 0, len(av.Clients))
	for _, c := range av.Clients {
		clients = append(clients, npm.AccessListClient{Address: c.Address, Directive: c.Directive})
	}
	l := &npm.AccessList{
		Name:       av.Name,
		PassAuth:   av.PassAuth,
		SatisfyAny: av.SatisfyAny,
		Items:      items,
		Clients:    clients,
	}
	_, err = client.UpdateAccessList(ctx, av.ID, l)
	return err
}

func (a *proxyAdapter) DeleteAccessList(ctx context.Context, id int) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	return client.DeleteAccessList(ctx, id)
}

// --- Audit Logs ---

func (a *proxyAdapter) ListAuditLogs(ctx context.Context, limit, offset int) ([]AuditLogView, int, error) {
	if a.npmSvc == nil {
		return nil, 0, fmt.Errorf("NPM integration not configured")
	}
	logs, total, err := a.npmSvc.GetAuditLogs(ctx, resolveHostID(ctx, a.hostID).String(), limit, offset)
	if err != nil {
		return nil, 0, err
	}
	views := make([]AuditLogView, 0, len(logs))
	for _, l := range logs {
		views = append(views, AuditLogView{
			ID:           l.ID,
			Operation:    l.Operation,
			ResourceType: l.ResourceType,
			ResourceID:   l.ResourceID,
			ResourceName: l.ResourceName,
			CreatedAt:    l.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	return views, total, nil
}

// toInt safely converts interface{} to int for access list meta counts
func toInt(v interface{}) int {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case int64:
		return int(val)
	default:
		return 0
	}
}

// ============================================================================
// Auth Adapter
// ============================================================================

type authAdapter struct {
	svc          *authsvc.Service
	sessionStore *WebSessionStore
}

// ValidateSession implements the AuthService interface required by middleware.
// It validates that the session's user still exists and is active.
func (a *authAdapter) ValidateSession(ctx context.Context, sessionID string) (*UserContext, error) {
	// If we have a session store, we can look up the session data
	if a.sessionStore != nil && a.sessionStore.redisStore != nil {
		session, err := a.sessionStore.redisStore.Get(ctx, sessionID)
		if err != nil || session == nil {
			return nil, fmt.Errorf("session not found")
		}
		
		return &UserContext{
			ID:       session.UserID,
			Username: session.Username,
			Role:     session.Role,
		}, nil
	}
	
	// Fallback: if no session store, return error
	return nil, fmt.Errorf("session store not available")
}

// GetUserByID implements the AuthService interface required by middleware.
func (a *authAdapter) GetUserByID(ctx context.Context, userID string) (*UserContext, error) {
	if a.svc == nil {
		return nil, nil
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}

	user, err := a.svc.GetUserByID(ctx, uid)
	if err != nil {
		return nil, err
	}

	email := ""
	if user.Email != nil {
		email = *user.Email
	}

	return &UserContext{
		ID:       user.ID.String(),
		Username: user.Username,
		Email:    email,
		Role:     string(user.Role),
	}, nil
}

// Login performs user authentication.
func (a *authAdapter) Login(ctx context.Context, username, password, userAgent, ipAddress string) (*UserContext, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("auth service not available")
	}

	result, err := a.svc.Login(ctx, authsvc.LoginInput{
		Username:  username,
		Password:  password,
		UserAgent: userAgent,
		IPAddress: ipAddress,
	})
	if err != nil {
		return nil, err
	}

	email := ""
	if result.User.Email != nil {
		email = *result.User.Email
	}

	user := &UserContext{
		ID:       result.User.ID.String(),
		Username: result.User.Username,
		Email:    email,
		Role:     string(result.User.Role),
	}

	return user, nil
}

// VerifyCredentials checks username/password without creating a session (for 2FA first step).
func (a *authAdapter) VerifyCredentials(ctx context.Context, username, password, userAgent, ipAddress string) (*UserContext, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("auth service not available")
	}

	user, err := a.svc.VerifyCredentials(ctx, authsvc.LoginInput{
		Username:  username,
		Password:  password,
		UserAgent: userAgent,
		IPAddress: ipAddress,
	})
	if err != nil {
		return nil, err
	}

	email := ""
	if user.Email != nil {
		email = *user.Email
	}

	return &UserContext{
		ID:       user.ID.String(),
		Username: user.Username,
		Email:    email,
		Role:     string(user.Role),
	}, nil
}

// CreateSessionForUser creates a session for an already-authenticated user (after 2FA verification).
func (a *authAdapter) CreateSessionForUser(ctx context.Context, userID, userAgent, ipAddress string) (*UserContext, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("auth service not available")
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	user, err := a.svc.GetUserByID(ctx, uid)
	if err != nil {
		return nil, err
	}

	result, err := a.svc.CreateSessionForUser(ctx, user, authsvc.LoginInput{
		Username:  user.Username,
		UserAgent: userAgent,
		IPAddress: ipAddress,
	})
	if err != nil {
		return nil, err
	}

	email := ""
	if result.User.Email != nil {
		email = *result.User.Email
	}

	return &UserContext{
		ID:       result.User.ID.String(),
		Username: result.User.Username,
		Email:    email,
		Role:     string(result.User.Role),
	}, nil
}

// Logout ends a user session.
func (a *authAdapter) Logout(ctx context.Context, sessionID string) error {
	if a.svc == nil {
		return nil
	}

	sid, err := uuid.Parse(sessionID)
	if err != nil {
		return err
	}

	return a.svc.Logout(ctx, sid)
}

// ValidateToken validates an access token.
func (a *authAdapter) ValidateToken(ctx context.Context, token string) (*UserContext, error) {
	if a.svc == nil {
		return nil, nil
	}

	claims, err := a.svc.ValidateAccessToken(token)
	if err != nil {
		return nil, err
	}

	return &UserContext{
		ID:       claims.UserID,
		Username: claims.Username,
		Email:    claims.Email,
		Role:     string(claims.Role),
	}, nil
}

// ============================================================================
// Stats Adapter
// ============================================================================

type statsAdapter struct {
	containerSvc *containersvc.Service
	imageSvc     *imagesvc.Service
	volumeSvc    *volumesvc.Service
	networkSvc   *networksvc.Service
	stackSvc     *stacksvc.Service
	securitySvc  *securitysvc.Service
	hostSvc      *hostsvc.Service
	hostID       uuid.UUID
}

func (a *statsAdapter) GetGlobalStats(ctx context.Context) (*GlobalStats, error) {
	stats := &GlobalStats{}

	// Resolve host for all stats queries
	statsHostID := resolveHostID(ctx, a.hostID)

	// Containers - use Docker Info for accurate counts if host service available
	if a.hostSvc != nil {
		info, err := a.hostSvc.GetDockerInfo(ctx, statsHostID)
		if err == nil && info != nil {
			stats.ContainersTotal = info.Containers
			stats.ContainersRunning = info.ContainersRunning
			stats.ContainersStopped = info.ContainersStopped
			stats.ContainersPaused = info.ContainersPaused
		}
	} else if a.containerSvc != nil {
		// Fallback: count from database
		runningState := models.ContainerStateRunning
		stoppedState := models.ContainerStateExited
		pausedState := models.ContainerStatePaused

		runningContainers, _, _ := a.containerSvc.List(ctx, postgres.ContainerListOptions{
			HostID:  &statsHostID,
			State:   &runningState,
			Page:    1,
			PerPage: 1000,
		})
		stoppedContainers, _, _ := a.containerSvc.List(ctx, postgres.ContainerListOptions{
			HostID:  &statsHostID,
			State:   &stoppedState,
			Page:    1,
			PerPage: 1000,
		})
		pausedContainers, _, _ := a.containerSvc.List(ctx, postgres.ContainerListOptions{
			HostID:  &statsHostID,
			State:   &pausedState,
			Page:    1,
			PerPage: 1000,
		})

		stats.ContainersRunning = len(runningContainers)
		stats.ContainersStopped = len(stoppedContainers)
		stats.ContainersPaused = len(pausedContainers)
		stats.ContainersTotal = stats.ContainersRunning + stats.ContainersStopped + stats.ContainersPaused
	}

	// Images
	if a.imageSvc != nil {
		images, _ := a.imageSvc.List(ctx, resolveHostID(ctx, a.hostID))
		stats.ImagesCount = len(images)
	}

	// Volumes
	if a.volumeSvc != nil {
		volumes, _ := a.volumeSvc.List(ctx, resolveHostID(ctx, a.hostID))
		stats.VolumesCount = len(volumes)
	}

	// Networks
	if a.networkSvc != nil {
		networks, _ := a.networkSvc.List(ctx, resolveHostID(ctx, a.hostID))
		stats.NetworksCount = len(networks)
	}

	// Stacks
	if a.stackSvc != nil {
		stacks, _, _ := a.stackSvc.List(ctx, postgres.StackListOptions{Page: 1, PerPage: 1000})
		stats.StacksCount = len(stacks)
	}

	// Security
	if a.securitySvc != nil {
		secHostID := resolveHostID(ctx, a.hostID)
		summary, _ := a.securitySvc.GetSecuritySummary(ctx, &secHostID)
		if summary != nil {
			if summary.SeverityCounts != nil {
				stats.SecurityIssues = summary.SeverityCounts[models.IssueSeverityCritical] +
					summary.SeverityCounts[models.IssueSeverityHigh]
			}
			stats.SecurityScore = int(summary.AverageScore)
			stats.SecurityGrade = securityScoreToGrade(int(summary.AverageScore))
		}
	}

	return stats, nil
}

// securityScoreToGrade converts a numeric security score to a letter grade.
func securityScoreToGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	case score > 0:
		return "F"
	default:
		return "-"
	}
}

// ============================================================================
// User adapter
// ============================================================================

type userAdapter struct {
	repo      *postgres.UserRepository
	authSvc   *authsvc.Service
	encryptor *crypto.AESEncryptor
}

func (a *userAdapter) List(ctx context.Context, search string, role string) ([]UserView, int64, error) {
	if a.repo == nil {
		return nil, 0, fmt.Errorf("user repository not configured")
	}

	opts := postgres.UserListOptions{
		Page:    1,
		PerPage: 500,
		Search:  search,
	}
	if role != "" {
		r := models.UserRole(role)
		opts.Role = &r
	}

	users, total, err := a.repo.List(ctx, opts)
	if err != nil {
		return nil, 0, err
	}

	views := make([]UserView, 0, len(users))
	for _, u := range users {
		views = append(views, userModelToView(u))
	}

	return views, total, nil
}

func (a *userAdapter) Get(ctx context.Context, id string) (*UserView, error) {
	if a.repo == nil {
		return nil, fmt.Errorf("user repository not configured")
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	u, err := a.repo.GetByID(ctx, uid)
	if err != nil {
		return nil, err
	}

	v := userModelToView(u)
	return &v, nil
}

func (a *userAdapter) Create(ctx context.Context, username, email, password, role string) (*UserView, error) {
	if a.repo == nil {
		return nil, fmt.Errorf("user repository not configured")
	}

	// Hash password
	hash, err := crypto.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &models.User{
		ID:           uuid.New(),
		Username:     username,
		PasswordHash: hash,
		Role:         models.UserRole(role),
		IsActive:     true,
		IsLDAP:       false,
	}
	if email != "" {
		user.Email = &email
	}

	if err := a.repo.Create(ctx, user); err != nil {
		return nil, err
	}

	v := userModelToView(user)
	return &v, nil
}

func (a *userAdapter) Update(ctx context.Context, id string, email *string, role *string, isActive *bool) error {
	if a.repo == nil {
		return fmt.Errorf("user repository not configured")
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}

	user, err := a.repo.GetByID(ctx, uid)
	if err != nil {
		return err
	}

	if email != nil {
		user.Email = email
	}
	if role != nil {
		user.Role = models.UserRole(*role)
	}
	if isActive != nil {
		user.IsActive = *isActive
	}

	return a.repo.Update(ctx, user)
}

func (a *userAdapter) Delete(ctx context.Context, id string) error {
	if a.repo == nil {
		return fmt.Errorf("user repository not configured")
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}
	return a.repo.Delete(ctx, uid)
}

func (a *userAdapter) Enable(ctx context.Context, id string) error {
	active := true
	return a.Update(ctx, id, nil, nil, &active)
}

func (a *userAdapter) Disable(ctx context.Context, id string) error {
	active := false
	return a.Update(ctx, id, nil, nil, &active)
}

func (a *userAdapter) Unlock(ctx context.Context, id string) error {
	if a.repo == nil {
		return fmt.Errorf("user repository not configured")
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}
	return a.repo.Unlock(ctx, uid)
}

func (a *userAdapter) ResetPassword(ctx context.Context, id string, newPassword string) error {
	if a.authSvc == nil {
		return fmt.Errorf("auth service not configured")
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}
	return a.authSvc.ResetPassword(ctx, uid, newPassword)
}

func (a *userAdapter) GetStats(ctx context.Context) (*UserStatsView, error) {
	if a.repo == nil {
		return nil, fmt.Errorf("user repository not configured")
	}

	stats, err := a.repo.GetStats(ctx)
	if err != nil {
		return nil, err
	}

	return &UserStatsView{
		Total:    stats.Total,
		Active:   stats.Active,
		Inactive: stats.Inactive,
		LDAP:     stats.LDAP,
		Local:    stats.Local,
		Locked:   stats.Locked,
		Admins:   stats.Admins,
	}, nil
}

func userModelToView(u *models.User) UserView {
	v := UserView{
		ID:        u.ID.String(),
		Username:  u.Username,
		Role:      string(u.Role),
		IsActive:  u.IsActive,
		IsLDAP:    u.IsLDAP,
		IsLocked:  u.IsLocked(),
		HasTOTP:   u.HasTOTP(),
		LastLogin: u.LastLoginAt,
		CreatedAt: u.CreatedAt,
	}
	if u.Email != nil {
		v.Email = *u.Email
	}
	if u.LDAPDN != nil {
		v.LDAPDN = *u.LDAPDN
	}
	return v
}

// ============================================================================
// TOTP Methods
// ============================================================================

func (a *userAdapter) SetupTOTP(ctx context.Context, userID string) (string, string, error) {
	if a.repo == nil || a.encryptor == nil {
		return "", "", fmt.Errorf("totp not configured")
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		return "", "", fmt.Errorf("invalid user ID: %w", err)
	}

	user, err := a.repo.GetByID(ctx, uid)
	if err != nil {
		return "", "", err
	}

	// Generate new secret
	secret, err := totp.GenerateSecret()
	if err != nil {
		return "", "", err
	}

	// Encrypt and store
	encrypted, err := a.encryptor.EncryptString(secret)
	if err != nil {
		return "", "", fmt.Errorf("encrypt totp secret: %w", err)
	}

	if err := a.repo.SetTOTPSecret(ctx, uid, encrypted); err != nil {
		return "", "", err
	}

	account := user.Username
	if user.Email != nil && *user.Email != "" {
		account = *user.Email
	}
	qrURI := totp.OTPAuthURI(secret, account, "")

	return secret, qrURI, nil
}

func (a *userAdapter) VerifyAndEnableTOTP(ctx context.Context, userID string, code string) error {
	if a.repo == nil || a.encryptor == nil {
		return fmt.Errorf("totp not configured")
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}

	user, err := a.repo.GetByID(ctx, uid)
	if err != nil {
		return err
	}

	if user.TOTPSecret == nil || *user.TOTPSecret == "" {
		return fmt.Errorf("totp not set up")
	}

	// Decrypt secret
	secret, err := a.encryptor.DecryptString(*user.TOTPSecret)
	if err != nil {
		return fmt.Errorf("decrypt totp secret: %w", err)
	}

	// Validate code
	valid, err := totp.Validate(code, secret)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("invalid totp code")
	}

	return a.repo.EnableTOTP(ctx, uid)
}

func (a *userAdapter) ValidateTOTPCode(ctx context.Context, userID string, code string) (bool, error) {
	if a.repo == nil || a.encryptor == nil {
		return false, fmt.Errorf("totp not configured")
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		return false, fmt.Errorf("invalid user ID: %w", err)
	}

	user, err := a.repo.GetByID(ctx, uid)
	if err != nil {
		return false, err
	}

	if !user.HasTOTP() {
		return false, fmt.Errorf("totp not enabled")
	}

	secret, err := a.encryptor.DecryptString(*user.TOTPSecret)
	if err != nil {
		return false, fmt.Errorf("decrypt totp secret: %w", err)
	}

	return totp.Validate(code, secret)
}

func (a *userAdapter) DisableTOTP(ctx context.Context, userID string, code string) error {
	// Validate current code before disabling
	valid, err := a.ValidateTOTPCode(ctx, userID, code)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("invalid totp code")
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}

	return a.repo.DisableTOTP(ctx, uid)
}

func (a *userAdapter) HasTOTP(ctx context.Context, userID string) (bool, error) {
	if a.repo == nil {
		return false, fmt.Errorf("user repository not configured")
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		return false, fmt.Errorf("invalid user ID: %w", err)
	}

	user, err := a.repo.GetByID(ctx, uid)
	if err != nil {
		return false, err
	}

	return user.HasTOTP(), nil
}
