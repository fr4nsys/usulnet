// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package docker

import (
	"context"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/volume"
        "github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/client"

	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// VolumeListOptions specifies options for listing volumes
type VolumeListOptions struct {
	// Filters to apply (e.g., {"driver": ["local"], "label": ["env=prod"]})
	Filters map[string][]string
}

// VolumeCreateOptions specifies options for creating volumes
type VolumeCreateOptions struct {
	// Name is the volume name (optional, Docker generates one if empty)
	Name string

	// Driver is the volume driver (default: "local")
	Driver string

	// DriverOpts are driver-specific options
	DriverOpts map[string]string

	// Labels are metadata labels
	Labels map[string]string
}

// VolumeList returns a list of volumes
func (c *Client) VolumeList(ctx context.Context, opts VolumeListOptions) ([]Volume, error) {
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

	listOpts := volume.ListOptions{
		Filters: f,
	}

	resp, err := c.cli.VolumeList(ctx, listOpts)
	if err != nil {
		log.Error("Failed to list volumes", "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to list volumes")
	}

	result := make([]Volume, len(resp.Volumes))
	for i, vol := range resp.Volumes {
		result[i] = VolumeFromDocker(*vol)
	}

	log.Debug("Listed volumes", "count", len(result))
	return result, nil
}

// VolumeGet returns detailed information about a volume
func (c *Client) VolumeGet(ctx context.Context, volumeName string) (*Volume, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	vol, err := c.cli.VolumeInspect(ctx, volumeName)
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, errors.New(errors.CodeVolumeNotFound, "volume not found").
				WithDetail("volume_name", volumeName)
		}
		log.Error("Failed to inspect volume", "volume_name", volumeName, "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to inspect volume")
	}

	result := VolumeFromDocker(vol)
	return &result, nil
}

// VolumeCreate creates a new volume
func (c *Client) VolumeCreate(ctx context.Context, opts VolumeCreateOptions) (*Volume, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	createOpts := volume.CreateOptions{
		Name:       opts.Name,
		Driver:     opts.Driver,
		DriverOpts: opts.DriverOpts,
		Labels:     opts.Labels,
	}

	// Set default driver if not specified
	if createOpts.Driver == "" {
		createOpts.Driver = "local"
	}

	vol, err := c.cli.VolumeCreate(ctx, createOpts)
	if err != nil {
		log.Error("Failed to create volume", "name", opts.Name, "driver", opts.Driver, "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to create volume")
	}

	log.Info("Volume created", "name", vol.Name, "driver", vol.Driver)

	result := VolumeFromDocker(vol)
	return &result, nil
}

// VolumeRemove removes a volume
func (c *Client) VolumeRemove(ctx context.Context, volumeName string, force bool) error {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	if err := c.cli.VolumeRemove(ctx, volumeName, force); err != nil {
		if client.IsErrNotFound(err) {
			return errors.New(errors.CodeVolumeNotFound, "volume not found").
				WithDetail("volume_name", volumeName)
		}
		log.Error("Failed to remove volume", "volume_name", volumeName, "error", err)
		return errors.Wrap(err, errors.CodeInternal, "failed to remove volume")
	}

	log.Info("Volume removed", "volume_name", volumeName)
	return nil
}

// VolumePrune removes unused volumes
func (c *Client) VolumePrune(ctx context.Context, pruneFilters map[string][]string) (uint64, []string, error) {
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

	report, err := c.cli.VolumesPrune(ctx, f)
	if err != nil {
		log.Error("Failed to prune volumes", "error", err)
		return 0, nil, errors.Wrap(err, errors.CodeInternal, "failed to prune volumes")
	}

	log.Info("Volumes pruned", "deleted", len(report.VolumesDeleted), "space_reclaimed", report.SpaceReclaimed)
	return report.SpaceReclaimed, report.VolumesDeleted, nil
}

// VolumeExists checks if a volume exists
func (c *Client) VolumeExists(ctx context.Context, volumeName string) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return false, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	_, err := c.cli.VolumeInspect(ctx, volumeName)
	if err != nil {
		if client.IsErrNotFound(err) {
			return false, nil
		}
		return false, errors.Wrap(err, errors.CodeInternal, "failed to check volume existence")
	}

	return true, nil
}

// VolumeUpdate updates a volume's configuration
// Note: Most volume drivers don't support updates, this updates cluster volumes (Swarm)
func (c *Client) VolumeUpdate(ctx context.Context, volumeName string, version uint64, opts volume.UpdateOptions) error {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	if err := c.cli.VolumeUpdate(ctx, volumeName, swarm.Version{Index: version}, opts); err != nil {
		if client.IsErrNotFound(err) {
			return errors.New(errors.CodeVolumeNotFound, "volume not found").
				WithDetail("volume_name", volumeName)
		}
		log.Error("Failed to update volume", "volume_name", volumeName, "error", err)
		return errors.Wrap(err, errors.CodeInternal, "failed to update volume")
	}

	log.Info("Volume updated", "volume_name", volumeName)
	return nil
}

// VolumeUsedBy returns a list of containers using a volume
func (c *Client) VolumeUsedBy(ctx context.Context, volumeName string) ([]string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	// Get all containers (including stopped)
	containers, err := c.cli.ContainerList(ctx, container.ListOptions{
		All: true,
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to list containers")
	}

	var usingContainers []string
	for _, cont := range containers {
		for _, mount := range cont.Mounts {
			if mount.Name == volumeName {
				name := cont.Names[0]
				if len(name) > 0 && name[0] == '/' {
					name = name[1:]
				}
				usingContainers = append(usingContainers, name)
				break
			}
		}
	}

	return usingContainers, nil
}

// VolumeSize calculates the size of a volume
// Note: This may not be supported by all volume drivers
func (c *Client) VolumeSize(ctx context.Context, volumeName string) (int64, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return 0, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	vol, err := c.cli.VolumeInspect(ctx, volumeName)
	if err != nil {
		if client.IsErrNotFound(err) {
			return 0, errors.New(errors.CodeVolumeNotFound, "volume not found").
				WithDetail("volume_name", volumeName)
		}
		return 0, errors.Wrap(err, errors.CodeInternal, "failed to inspect volume")
	}

	if vol.UsageData != nil {
		return vol.UsageData.Size, nil
	}

	// Size not available
	return -1, nil
}

// VolumeListByLabel returns volumes matching specific labels
func (c *Client) VolumeListByLabel(ctx context.Context, labels map[string]string) ([]Volume, error) {
	filters := make(map[string][]string)
	for key, value := range labels {
		filters["label"] = append(filters["label"], key+"="+value)
	}

	return c.VolumeList(ctx, VolumeListOptions{Filters: filters})
}

// VolumeListByDriver returns volumes using a specific driver
func (c *Client) VolumeListByDriver(ctx context.Context, driver string) ([]Volume, error) {
	return c.VolumeList(ctx, VolumeListOptions{
		Filters: map[string][]string{
			"driver": {driver},
		},
	})
}

// VolumeListDangling returns dangling (unused) volumes
func (c *Client) VolumeListDangling(ctx context.Context) ([]Volume, error) {
	return c.VolumeList(ctx, VolumeListOptions{
		Filters: map[string][]string{
			"dangling": {"true"},
		},
	})
}
