// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package docker

import (
	"context"
	"io"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
        "github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"

	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ContainerListOptions specifies options for listing containers
type ContainerListOptions struct {
	// All includes stopped containers
	All bool

	// Limit limits the number of containers returned
	Limit int

	// Filters to apply (e.g., {"status": ["running"], "label": ["env=prod"]})
	Filters map[string][]string

	// Size includes container size information (slower)
	Size bool
}

// ContainerCreateOptions specifies options for creating a container
type ContainerCreateOptions struct {
	Name       string
	Image      string
	Hostname   string
	Cmd        []string
	Env        []string
	Labels     map[string]string
	WorkingDir string
	User       string
	Tty        bool
	OpenStdin  bool
	
	// Host configuration
	Binds         []string
	PortBindings  map[string][]PortBinding
	NetworkMode   string
	RestartPolicy RestartPolicy
	AutoRemove    bool
	Privileged    bool
	CapAdd        []string
	CapDrop       []string
	DNS           []string
	ExtraHosts    []string
	
	// Resource limits
	Memory     int64
	MemorySwap int64
	CPUShares  int64
	CPUPeriod  int64
	CPUQuota   int64
	NanoCPUs   int64

	// Devices (GPU/USB passthrough)
	Devices []DeviceMapping

	// Healthcheck
	Healthcheck *HealthConfig

	// Networking
	NetworkID      string
	NetworkAliases []string
	IPAddress      string
}

// ContainerList returns a list of containers
func (c *Client) ContainerList(ctx context.Context, opts ContainerListOptions) ([]Container, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	// Build filters
	f := filters.NewArgs()
	for key, values := range opts.Filters {
		for _, v := range values {
			f.Add(key, v)
		}
	}

	listOpts := container.ListOptions{
		All:     opts.All,
		Limit:   opts.Limit,
		Filters: f,
		Size:    opts.Size,
	}

	containers, err := c.cli.ContainerList(ctx, listOpts)
	if err != nil {
		log.Error("Failed to list containers", "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to list containers")
	}

	result := make([]Container, len(containers))
	for i, cont := range containers {
		result[i] = ContainerFromSummary(cont)
	}

	log.Debug("Listed containers", "count", len(result), "all", opts.All)
	return result, nil
}

// ContainerGet returns a single container by ID or name
func (c *Client) ContainerGet(ctx context.Context, containerID string) (*ContainerDetails, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	inspect, err := c.cli.ContainerInspect(ctx, containerID)
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		log.Error("Failed to inspect container", "container_id", containerID, "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to inspect container")
	}

	details := ContainerFromInspect(inspect)
	return &details, nil
}

// ContainerInspectRaw returns the raw Docker types.ContainerJSON for a container.
// Used by security scanner which needs the full Docker API response.
func (c *Client) ContainerInspectRaw(ctx context.Context, containerID string) (types.ContainerJSON, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return types.ContainerJSON{}, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	inspect, err := c.cli.ContainerInspect(ctx, containerID)
	if err != nil {
		if client.IsErrNotFound(err) {
			return types.ContainerJSON{}, errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		return types.ContainerJSON{}, errors.Wrap(err, errors.CodeInternal, "failed to inspect container")
	}

	return inspect, nil
}

// ContainerCreate creates a new container
func (c *Client) ContainerCreate(ctx context.Context, opts ContainerCreateOptions) (string, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return "", errors.New(errors.CodeDockerConnection, "client is closed")
	}

	// Build container config
	config := &container.Config{
		Hostname:   opts.Hostname,
		Image:      opts.Image,
		Cmd:        opts.Cmd,
		Env:        opts.Env,
		Labels:     opts.Labels,
		WorkingDir: opts.WorkingDir,
		User:       opts.User,
		Tty:        opts.Tty,
		OpenStdin:  opts.OpenStdin,
	}

	// Build healthcheck config
	if opts.Healthcheck != nil {
		config.Healthcheck = &container.HealthConfig{
			Test:        opts.Healthcheck.Test,
			Interval:    opts.Healthcheck.Interval,
			Timeout:     opts.Healthcheck.Timeout,
			StartPeriod: opts.Healthcheck.StartPeriod,
			Retries:     opts.Healthcheck.Retries,
		}
	}

	// Build device mappings
	var devices []container.DeviceMapping
	for _, d := range opts.Devices {
		devices = append(devices, container.DeviceMapping{
			PathOnHost:        d.PathOnHost,
			PathInContainer:   d.PathInContainer,
			CgroupPermissions: d.CgroupPermissions,
		})
	}

	// Build host config
	hostConfig := &container.HostConfig{
		Binds:       opts.Binds,
		NetworkMode: container.NetworkMode(opts.NetworkMode),
		RestartPolicy: container.RestartPolicy{
			Name:              container.RestartPolicyMode(opts.RestartPolicy.Name),
			MaximumRetryCount: opts.RestartPolicy.MaximumRetryCount,
		},
		AutoRemove: opts.AutoRemove,
		Privileged: opts.Privileged,
		CapAdd:     opts.CapAdd,
		CapDrop:    opts.CapDrop,
		DNS:        opts.DNS,
		ExtraHosts: opts.ExtraHosts,
		Resources: container.Resources{
			Memory:     opts.Memory,
			MemorySwap: opts.MemorySwap,
			CPUShares:  opts.CPUShares,
			CPUPeriod:  opts.CPUPeriod,
			CPUQuota:   opts.CPUQuota,
			NanoCPUs:   opts.NanoCPUs,
			Devices:    devices,
		},
	}

	// Build port bindings
	if len(opts.PortBindings) > 0 {
		hostConfig.PortBindings = make(nat.PortMap)
		for port, bindings := range opts.PortBindings {
			var portBindings []nat.PortBinding
			for _, b := range bindings {
				portBindings = append(portBindings, nat.PortBinding{
					HostIP:   b.HostIP,
					HostPort: b.HostPort,
				})
			}
			hostConfig.PortBindings[nat.Port(port)] = portBindings
		}
	}

	// Build network config
	var networkConfig *network.NetworkingConfig
	if opts.NetworkID != "" {
		networkConfig = &network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{
				opts.NetworkID: {
					Aliases:   opts.NetworkAliases,
					IPAddress: opts.IPAddress,
				},
			},
		}
	}

	resp, err := c.cli.ContainerCreate(ctx, config, hostConfig, networkConfig, nil, opts.Name)
	if err != nil {
		log.Error("Failed to create container", "name", opts.Name, "image", opts.Image, "error", err)
		return "", errors.Wrap(err, errors.CodeInternal, "failed to create container")
	}

	// Log warnings if any
	for _, warning := range resp.Warnings {
		log.Warn("Container creation warning", "container_id", resp.ID, "warning", warning)
	}

	log.Info("Container created", "container_id", resp.ID, "name", opts.Name, "image", opts.Image)
	return resp.ID, nil
}

// ContainerStart starts a stopped container
func (c *Client) ContainerStart(ctx context.Context, containerID string) error {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	if err := c.cli.ContainerStart(ctx, containerID, container.StartOptions{}); err != nil {
		if client.IsErrNotFound(err) {
			return errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		log.Error("Failed to start container", "container_id", containerID, "error", err)
		return errors.Wrap(err, errors.CodeInternal, "failed to start container")
	}

	log.Info("Container started", "container_id", containerID)
	return nil
}

// ContainerStop stops a running container
func (c *Client) ContainerStop(ctx context.Context, containerID string, timeout *int) error {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	stopOpts := container.StopOptions{}
	if timeout != nil {
		stopOpts.Timeout = timeout
	}

	if err := c.cli.ContainerStop(ctx, containerID, stopOpts); err != nil {
		if client.IsErrNotFound(err) {
			return errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		log.Error("Failed to stop container", "container_id", containerID, "error", err)
		return errors.Wrap(err, errors.CodeInternal, "failed to stop container")
	}

	log.Info("Container stopped", "container_id", containerID)
	return nil
}

// ContainerRestart restarts a container
func (c *Client) ContainerRestart(ctx context.Context, containerID string, timeout *int) error {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	stopOpts := container.StopOptions{}
	if timeout != nil {
		stopOpts.Timeout = timeout
	}

	if err := c.cli.ContainerRestart(ctx, containerID, stopOpts); err != nil {
		if client.IsErrNotFound(err) {
			return errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		log.Error("Failed to restart container", "container_id", containerID, "error", err)
		return errors.Wrap(err, errors.CodeInternal, "failed to restart container")
	}

	log.Info("Container restarted", "container_id", containerID)
	return nil
}

// ContainerKill sends a signal to a container
func (c *Client) ContainerKill(ctx context.Context, containerID string, signal string) error {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	if signal == "" {
		signal = "SIGKILL"
	}

	if err := c.cli.ContainerKill(ctx, containerID, signal); err != nil {
		if client.IsErrNotFound(err) {
			return errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		log.Error("Failed to kill container", "container_id", containerID, "signal", signal, "error", err)
		return errors.Wrap(err, errors.CodeInternal, "failed to kill container")
	}

	log.Info("Container killed", "container_id", containerID, "signal", signal)
	return nil
}

// ContainerPause pauses a running container
func (c *Client) ContainerPause(ctx context.Context, containerID string) error {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	if err := c.cli.ContainerPause(ctx, containerID); err != nil {
		if client.IsErrNotFound(err) {
			return errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		log.Error("Failed to pause container", "container_id", containerID, "error", err)
		return errors.Wrap(err, errors.CodeInternal, "failed to pause container")
	}

	log.Info("Container paused", "container_id", containerID)
	return nil
}

// ContainerUnpause unpauses a paused container
func (c *Client) ContainerUnpause(ctx context.Context, containerID string) error {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	if err := c.cli.ContainerUnpause(ctx, containerID); err != nil {
		if client.IsErrNotFound(err) {
			return errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		log.Error("Failed to unpause container", "container_id", containerID, "error", err)
		return errors.Wrap(err, errors.CodeInternal, "failed to unpause container")
	}

	log.Info("Container unpaused", "container_id", containerID)
	return nil
}

// ContainerRename renames a container
func (c *Client) ContainerRename(ctx context.Context, containerID, newName string) error {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	if err := c.cli.ContainerRename(ctx, containerID, newName); err != nil {
		if client.IsErrNotFound(err) {
			return errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		log.Error("Failed to rename container", "container_id", containerID, "new_name", newName, "error", err)
		return errors.Wrap(err, errors.CodeInternal, "failed to rename container")
	}

	log.Info("Container renamed", "container_id", containerID, "new_name", newName)
	return nil
}

// ContainerRemove removes a container
func (c *Client) ContainerRemove(ctx context.Context, containerID string, force bool, removeVolumes bool) error {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	if err := c.cli.ContainerRemove(ctx, containerID, container.RemoveOptions{
		Force:         force,
		RemoveVolumes: removeVolumes,
	}); err != nil {
		if client.IsErrNotFound(err) {
			return errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		log.Error("Failed to remove container", "container_id", containerID, "error", err)
		return errors.Wrap(err, errors.CodeInternal, "failed to remove container")
	}

	log.Info("Container removed", "container_id", containerID, "force", force)
	return nil
}

// ContainerWait waits for a container to exit and returns the exit code
func (c *Client) ContainerWait(ctx context.Context, containerID string) (int64, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return -1, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	statusCh, errCh := c.cli.ContainerWait(ctx, containerID, container.WaitConditionNotRunning)

	select {
	case err := <-errCh:
		if err != nil {
			if client.IsErrNotFound(err) {
				return -1, errors.New(errors.CodeContainerNotFound, "container not found").
					WithDetail("container_id", containerID)
			}
			return -1, errors.Wrap(err, errors.CodeInternal, "failed to wait for container")
		}
	case status := <-statusCh:
		return status.StatusCode, nil
	case <-ctx.Done():
		return -1, errors.Wrap(ctx.Err(), errors.CodeTimeout, "context cancelled while waiting for container")
	}

	return -1, nil
}

// ContainerUpdate updates a container's resource limits
func (c *Client) ContainerUpdate(ctx context.Context, containerID string, resources Resources) error {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	updateConfig := container.UpdateConfig{
		Resources: container.Resources{
			Memory:            resources.Memory,
			MemorySwap:        resources.MemorySwap,
			MemoryReservation: resources.MemoryReservation,
			NanoCPUs:          resources.NanoCPUs,
			CPUShares:         resources.CPUShares,
			CPUPeriod:         resources.CPUPeriod,
			CPUQuota:          resources.CPUQuota,
			CpusetCpus:        resources.CpusetCpus,
			CpusetMems:        resources.CpusetMems,
			PidsLimit:         resources.PidsLimit,
		},
	}

	_, err := c.cli.ContainerUpdate(ctx, containerID, updateConfig)
	if err != nil {
		if client.IsErrNotFound(err) {
			return errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		log.Error("Failed to update container", "container_id", containerID, "error", err)
		return errors.Wrap(err, errors.CodeInternal, "failed to update container")
	}

	log.Info("Container updated", "container_id", containerID)
	return nil
}

// ContainerPrune removes stopped containers
func (c *Client) ContainerPrune(ctx context.Context, pruneFilters map[string][]string) (uint64, []string, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return 0, nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	f := filters.NewArgs()
	for key, values := range pruneFilters {
		for _, v := range values {
			f.Add(key, v)
		}
	}

	report, err := c.cli.ContainersPrune(ctx, f)
	if err != nil {
		log.Error("Failed to prune containers", "error", err)
		return 0, nil, errors.Wrap(err, errors.CodeInternal, "failed to prune containers")
	}

	log.Info("Containers pruned", "deleted", len(report.ContainersDeleted), "space_reclaimed", report.SpaceReclaimed)
	return report.SpaceReclaimed, report.ContainersDeleted, nil
}

// ContainerTop returns processes running in a container
func (c *Client) ContainerTop(ctx context.Context, containerID string, psArgs string) ([][]string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	var args []string
	if psArgs != "" {
		args = []string{psArgs}
	}

	top, err := c.cli.ContainerTop(ctx, containerID, args)
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get container processes")
	}

	// Prepend titles as first row
	result := make([][]string, 0, len(top.Processes)+1)
	result = append(result, top.Titles)
	result = append(result, top.Processes...)

	return result, nil
}

// ContainerDiff returns changes to a container's filesystem
func (c *Client) ContainerDiff(ctx context.Context, containerID string) ([]container.FilesystemChange, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	changes, err := c.cli.ContainerDiff(ctx, containerID)
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get container diff")
	}

	return changes, nil
}

// ContainerExport exports a container's filesystem as a tar archive
func (c *Client) ContainerExport(ctx context.Context, containerID string) (io.ReadCloser, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	reader, err := c.cli.ContainerExport(ctx, containerID)
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to export container")
	}

	return reader, nil
}

// ContainerCommit creates a new image from a container
func (c *Client) ContainerCommit(ctx context.Context, containerID string, options CommitOptions) (string, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return "", errors.New(errors.CodeDockerConnection, "client is closed")
	}

	commitOptions := container.CommitOptions{
		Reference: options.Reference,
		Comment:   options.Comment,
		Author:    options.Author,
		Pause:     options.Pause,
		Changes:   options.Changes,
	}

	resp, err := c.cli.ContainerCommit(ctx, containerID, commitOptions)
	if err != nil {
		if client.IsErrNotFound(err) {
			return "", errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		log.Error("Failed to commit container", "container_id", containerID, "error", err)
		return "", errors.Wrap(err, errors.CodeInternal, "failed to commit container")
	}

	log.Info("Container committed", "container_id", containerID, "image_id", resp.ID)
	return resp.ID, nil
}

// ContainerCopyToContainer copies content to a container
func (c *Client) ContainerCopyToContainer(ctx context.Context, containerID, dstPath string, content io.Reader) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	err := c.cli.CopyToContainer(ctx, containerID, dstPath, content, container.CopyToContainerOptions{})
	if err != nil {
		if client.IsErrNotFound(err) {
			return errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		return errors.Wrap(err, errors.CodeInternal, "failed to copy to container")
	}

	return nil
}

// ContainerCopyFromContainer copies content from a container
func (c *Client) ContainerCopyFromContainer(ctx context.Context, containerID, srcPath string) (io.ReadCloser, container.PathStat, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, container.PathStat{}, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	reader, stat, err := c.cli.CopyFromContainer(ctx, containerID, srcPath)
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, container.PathStat{}, errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		return nil, container.PathStat{}, errors.Wrap(err, errors.CodeInternal, "failed to copy from container")
	}

	return reader, stat, nil
}

// WaitForHealthy waits for a container to become healthy
func (c *Client) WaitForHealthy(ctx context.Context, containerID string, timeout time.Duration) error {
	log := logger.FromContext(ctx)

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return errors.Wrap(ctx.Err(), errors.CodeTimeout, "context cancelled while waiting for container health")
		case <-ticker.C:
			if time.Now().After(deadline) {
				return errors.New(errors.CodeHealthCheckFailed, "timeout waiting for container to become healthy").
					WithDetail("container_id", containerID).
					WithDetail("timeout", timeout.String())
			}

			details, err := c.ContainerGet(ctx, containerID)
			if err != nil {
				return err
			}

			switch details.Health {
			case "healthy":
				log.Info("Container is healthy", "container_id", containerID)
				return nil
			case "unhealthy":
				return errors.New(errors.CodeHealthCheckFailed, "container is unhealthy").
					WithDetail("container_id", containerID)
			case "":
				// No healthcheck configured, consider it healthy
				log.Debug("Container has no healthcheck, considering healthy", "container_id", containerID)
				return nil
			default:
				// "starting" or other states, continue waiting
				log.Debug("Waiting for container health", "container_id", containerID, "health", details.Health)
			}
		}
	}
}

