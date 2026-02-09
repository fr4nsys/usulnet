// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package inventory provides Docker resource inventory collection for the agent.
package inventory

import (
	"context"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Collector collects Docker resource inventory.
type Collector struct {
	docker  *docker.Client
	log     *logger.Logger
	agentID string
	hostID  string

	// Caching
	lastInventory *protocol.Inventory
	lastCollected time.Time
	cacheTTL      time.Duration
	cacheMu       sync.RWMutex
}

// CollectorConfig configures the inventory collector.
type CollectorConfig struct {
	AgentID  string
	HostID   string
	CacheTTL time.Duration
}

// NewCollector creates a new inventory collector.
func NewCollector(dockerClient *docker.Client, cfg CollectorConfig, log *logger.Logger) *Collector {
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 30 * time.Second
	}

	return &Collector{
		docker:   dockerClient,
		log:      log.Named("inventory"),
		agentID:  cfg.AgentID,
		hostID:   cfg.HostID,
		cacheTTL: cfg.CacheTTL,
	}
}

// Collect collects full inventory.
func (c *Collector) Collect(ctx context.Context) (*protocol.Inventory, error) {
	c.log.Debug("Collecting inventory")
	start := time.Now()

	inv := &protocol.Inventory{
		AgentID:     c.agentID,
		HostID:      c.hostID,
		CollectedAt: time.Now().UTC(),
	}

	// Collect in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error

	// Containers
	wg.Add(1)
	go func() {
		defer wg.Done()
		containers, err := c.collectContainers(ctx)
		mu.Lock()
		if err != nil {
			errs = append(errs, err)
		} else {
			inv.Containers = containers
		}
		mu.Unlock()
	}()

	// Images
	wg.Add(1)
	go func() {
		defer wg.Done()
		images, err := c.collectImages(ctx)
		mu.Lock()
		if err != nil {
			errs = append(errs, err)
		} else {
			inv.Images = images
		}
		mu.Unlock()
	}()

	// Volumes
	wg.Add(1)
	go func() {
		defer wg.Done()
		volumes, err := c.collectVolumes(ctx)
		mu.Lock()
		if err != nil {
			errs = append(errs, err)
		} else {
			inv.Volumes = volumes
		}
		mu.Unlock()
	}()

	// Networks
	wg.Add(1)
	go func() {
		defer wg.Done()
		networks, err := c.collectNetworks(ctx)
		mu.Lock()
		if err != nil {
			errs = append(errs, err)
		} else {
			inv.Networks = networks
		}
		mu.Unlock()
	}()

	// System info
	wg.Add(1)
	go func() {
		defer wg.Done()
		sysInfo, err := c.collectSystemInfo(ctx)
		mu.Lock()
		if err != nil {
			errs = append(errs, err)
		} else {
			inv.SystemInfo = sysInfo
		}
		mu.Unlock()
	}()

	wg.Wait()

	// Cache the result
	c.cacheMu.Lock()
	c.lastInventory = inv
	c.lastCollected = time.Now()
	c.cacheMu.Unlock()

	c.log.Debug("Inventory collected",
		"containers", len(inv.Containers),
		"images", len(inv.Images),
		"volumes", len(inv.Volumes),
		"networks", len(inv.Networks),
		"duration", time.Since(start),
		"errors", len(errs),
	)

	return inv, nil
}

// GetCached returns cached inventory if still valid.
func (c *Collector) GetCached() (*protocol.Inventory, bool) {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()

	if c.lastInventory == nil {
		return nil, false
	}

	if time.Since(c.lastCollected) > c.cacheTTL {
		return nil, false
	}

	return c.lastInventory, true
}

// collectContainers collects container inventory.
func (c *Collector) collectContainers(ctx context.Context) ([]protocol.ContainerInfo, error) {
	cli := c.docker.Raw()

	containers, err := cli.ContainerList(ctx, container.ListOptions{
		All: true,
	})
	if err != nil {
		return nil, err
	}

	result := make([]protocol.ContainerInfo, 0, len(containers))
	for _, cnt := range containers {
		info := protocol.ContainerInfo{
			ID:          cnt.ID,
			Names:       cnt.Names,
			Image:       cnt.Image,
			ImageID:     cnt.ImageID,
			Command:     cnt.Command,
			Created:     cnt.Created,
			State:       cnt.State,
			Status:      cnt.Status,
			Labels:      cnt.Labels,
			NetworkMode: string(cnt.HostConfig.NetworkMode),
		}

		// Convert ports
		for _, p := range cnt.Ports {
			info.Ports = append(info.Ports, protocol.PortBinding{
				IP:          p.IP,
				PrivatePort: p.PrivatePort,
				PublicPort:  p.PublicPort,
				Type:        p.Type,
			})
		}

		// Convert mounts
		for _, m := range cnt.Mounts {
			info.Mounts = append(info.Mounts, protocol.MountInfo{
				Type:        string(m.Type),
				Name:        m.Name,
				Source:      m.Source,
				Destination: m.Destination,
				Mode:        m.Mode,
				RW:          m.RW,
			})
		}

		result = append(result, info)
	}

	return result, nil
}

// collectImages collects image inventory.
func (c *Collector) collectImages(ctx context.Context) ([]protocol.ImageInfo, error) {
	cli := c.docker.Raw()

	images, err := cli.ImageList(ctx, image.ListOptions{
		All: true,
	})
	if err != nil {
		return nil, err
	}

	result := make([]protocol.ImageInfo, 0, len(images))
	for _, img := range images {
		result = append(result, protocol.ImageInfo{
			ID:          img.ID,
			RepoTags:    img.RepoTags,
			RepoDigests: img.RepoDigests,
			Created:     img.Created,
			Size:        img.Size,
			VirtualSize: img.VirtualSize,
			Labels:      img.Labels,
		})
	}

	return result, nil
}

// collectVolumes collects volume inventory.
func (c *Collector) collectVolumes(ctx context.Context) ([]protocol.VolumeInfo, error) {
	cli := c.docker.Raw()

	volumes, err := cli.VolumeList(ctx, volume.ListOptions{})
	if err != nil {
		return nil, err
	}

	result := make([]protocol.VolumeInfo, 0, len(volumes.Volumes))
	for _, vol := range volumes.Volumes {
		info := protocol.VolumeInfo{
			Name:       vol.Name,
			Driver:     vol.Driver,
			Mountpoint: vol.Mountpoint,
			CreatedAt:  vol.CreatedAt,
			Labels:     vol.Labels,
			Scope:      vol.Scope,
		}

		if vol.UsageData != nil {
			info.UsageData = &protocol.VolumeUsageData{
				Size:     vol.UsageData.Size,
				RefCount: vol.UsageData.RefCount,
			}
		}

		result = append(result, info)
	}

	return result, nil
}

// collectNetworks collects network inventory.
func (c *Collector) collectNetworks(ctx context.Context) ([]protocol.NetworkInfo, error) {
	cli := c.docker.Raw()

	networks, err := cli.NetworkList(ctx, network.ListOptions{})
	if err != nil {
		return nil, err
	}

	result := make([]protocol.NetworkInfo, 0, len(networks))
	for _, net := range networks {
		info := protocol.NetworkInfo{
			ID:         net.ID,
			Name:       net.Name,
			Driver:     net.Driver,
			Scope:      net.Scope,
			Internal:   net.Internal,
			Attachable: net.Attachable,
			Ingress:    net.Ingress,
			EnableIPv6: net.EnableIPv6,
			Labels:     net.Labels,
		}

		// IPAM config
		if net.IPAM.Config != nil && len(net.IPAM.Config) > 0 {
			info.IPAM = &protocol.IPAMConfig{
				Driver: net.IPAM.Driver,
			}
			for _, cfg := range net.IPAM.Config {
				info.IPAM.Config = append(info.IPAM.Config, protocol.IPAMPool{
					Subnet:  cfg.Subnet,
					Gateway: cfg.Gateway,
				})
			}
		}

		// Connected containers
		if len(net.Containers) > 0 {
			info.Containers = make(map[string]string)
			for id, endpoint := range net.Containers {
				info.Containers[id] = endpoint.Name
			}
		}

		result = append(result, info)
	}

	return result, nil
}

// collectSystemInfo collects Docker system information.
func (c *Collector) collectSystemInfo(ctx context.Context) (*protocol.SystemInfo, error) {
	info, err := c.docker.Info(ctx)
	if err != nil {
		return nil, err
	}

	return &protocol.SystemInfo{
		ID:                info.ID,
		Name:              info.Name,
		ServerVersion:     info.ServerVersion,
		APIVersion:        info.APIVersion,
		OS:                info.OS,
		Arch:              info.Architecture,
		KernelVersion:     info.KernelVersion,
		ContainersTotal:   info.Containers,
		ContainersRunning: info.ContainersRunning,
		ContainersPaused:  info.ContainersPaused,
		ContainersStopped: info.ContainersStopped,
		Images:            info.Images,
		MemoryTotal:       info.MemTotal,
		CPUs:              info.NCPU,
	}, nil
}

// QuickStats returns quick stats for heartbeat.
func (c *Collector) QuickStats(ctx context.Context) (*protocol.QuickStats, error) {
	info, err := c.docker.Info(ctx)
	if err != nil {
		return nil, err
	}

	return &protocol.QuickStats{
		ContainersRunning: info.ContainersRunning,
		ContainersStopped: info.ContainersStopped,
		ContainersTotal:   info.Containers,
		ImagesCount:       info.Images,
		MemoryTotalBytes:  info.MemTotal,
	}, nil
}

// CollectContainersOnly collects only container inventory.
func (c *Collector) CollectContainersOnly(ctx context.Context) ([]protocol.ContainerInfo, error) {
	return c.collectContainers(ctx)
}

// CollectImagesOnly collects only image inventory.
func (c *Collector) CollectImagesOnly(ctx context.Context) ([]protocol.ImageInfo, error) {
	return c.collectImages(ctx)
}

// CollectByFilter collects containers matching a filter.
func (c *Collector) CollectByFilter(ctx context.Context, f filters.Args) ([]protocol.ContainerInfo, error) {
	cli := c.docker.Raw()

	containers, err := cli.ContainerList(ctx, container.ListOptions{
		All:     true,
		Filters: f,
	})
	if err != nil {
		return nil, err
	}

	result := make([]protocol.ContainerInfo, 0, len(containers))
	for _, cnt := range containers {
		result = append(result, protocol.ContainerInfo{
			ID:      cnt.ID,
			Names:   cnt.Names,
			Image:   cnt.Image,
			ImageID: cnt.ImageID,
			State:   cnt.State,
			Status:  cnt.Status,
			Labels:  cnt.Labels,
		})
	}

	return result, nil
}

// InventoryDiff represents changes between inventories.
type InventoryDiff struct {
	AddedContainers   []string
	RemovedContainers []string
	ChangedContainers []string
	AddedImages       []string
	RemovedImages     []string
	AddedVolumes      []string
	RemovedVolumes    []string
	AddedNetworks     []string
	RemovedNetworks   []string
}

// Diff compares two inventories and returns differences.
func Diff(old, new *protocol.Inventory) *InventoryDiff {
	diff := &InventoryDiff{}

	// Compare containers
	oldContainers := make(map[string]protocol.ContainerInfo)
	for _, c := range old.Containers {
		oldContainers[c.ID] = c
	}

	newContainers := make(map[string]protocol.ContainerInfo)
	for _, c := range new.Containers {
		newContainers[c.ID] = c

		if oldC, exists := oldContainers[c.ID]; !exists {
			diff.AddedContainers = append(diff.AddedContainers, c.ID)
		} else if oldC.State != c.State {
			diff.ChangedContainers = append(diff.ChangedContainers, c.ID)
		}
	}

	for id := range oldContainers {
		if _, exists := newContainers[id]; !exists {
			diff.RemovedContainers = append(diff.RemovedContainers, id)
		}
	}

	// Compare images
	oldImages := make(map[string]bool)
	for _, img := range old.Images {
		oldImages[img.ID] = true
	}

	newImages := make(map[string]bool)
	for _, img := range new.Images {
		newImages[img.ID] = true
		if !oldImages[img.ID] {
			diff.AddedImages = append(diff.AddedImages, img.ID)
		}
	}

	for id := range oldImages {
		if !newImages[id] {
			diff.RemovedImages = append(diff.RemovedImages, id)
		}
	}

	// Compare volumes
	oldVolumes := make(map[string]bool)
	for _, vol := range old.Volumes {
		oldVolumes[vol.Name] = true
	}

	newVolumes := make(map[string]bool)
	for _, vol := range new.Volumes {
		newVolumes[vol.Name] = true
		if !oldVolumes[vol.Name] {
			diff.AddedVolumes = append(diff.AddedVolumes, vol.Name)
		}
	}

	for name := range oldVolumes {
		if !newVolumes[name] {
			diff.RemovedVolumes = append(diff.RemovedVolumes, name)
		}
	}

	// Compare networks
	oldNetworks := make(map[string]bool)
	for _, net := range old.Networks {
		oldNetworks[net.ID] = true
	}

	newNetworks := make(map[string]bool)
	for _, net := range new.Networks {
		newNetworks[net.ID] = true
		if !oldNetworks[net.ID] {
			diff.AddedNetworks = append(diff.AddedNetworks, net.ID)
		}
	}

	for id := range oldNetworks {
		if !newNetworks[id] {
			diff.RemovedNetworks = append(diff.RemovedNetworks, id)
		}
	}

	return diff
}

// HasChanges returns true if there are any differences.
func (d *InventoryDiff) HasChanges() bool {
	return len(d.AddedContainers) > 0 ||
		len(d.RemovedContainers) > 0 ||
		len(d.ChangedContainers) > 0 ||
		len(d.AddedImages) > 0 ||
		len(d.RemovedImages) > 0 ||
		len(d.AddedVolumes) > 0 ||
		len(d.RemovedVolumes) > 0 ||
		len(d.AddedNetworks) > 0 ||
		len(d.RemovedNetworks) > 0
}
