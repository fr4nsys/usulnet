// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package docker

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"

	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ContainerStats returns a channel of real-time container statistics
// The channel is closed when the context is cancelled
func (c *Client) ContainerStats(ctx context.Context, containerID string) (<-chan ContainerStats, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	resp, err := c.cli.ContainerStats(ctx, containerID, true) // stream = true
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		log.Error("Failed to get container stats", "container_id", containerID, "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get container stats")
	}

	statsCh := make(chan ContainerStats, 10)

	go func() {
		defer close(statsCh)
		defer resp.Body.Close()

		decoder := json.NewDecoder(resp.Body)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			var stats container.StatsResponse
			if err := decoder.Decode(&stats); err != nil {
				// Stream ended
				return
			}

			containerStats := StatsFromResponse(containerID, &stats)

			select {
			case statsCh <- containerStats:
			case <-ctx.Done():
				return
			}
		}
	}()

	return statsCh, nil
}

// ContainerStatsOnce returns a single stats snapshot (no streaming)
func (c *Client) ContainerStatsOnce(ctx context.Context, containerID string) (*ContainerStats, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	resp, err := c.cli.ContainerStatsOneShot(ctx, containerID)
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		log.Error("Failed to get container stats", "container_id", containerID, "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get container stats")
	}
	defer resp.Body.Close()

	var stats container.StatsResponse
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode stats")
	}

	containerStats := StatsFromResponse(containerID, &stats)
	return &containerStats, nil
}

// MultiContainerStats returns stats for multiple containers simultaneously
func (c *Client) MultiContainerStats(ctx context.Context, containerIDs []string) (map[string]*ContainerStats, error) {
	results := make(map[string]*ContainerStats)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, id := range containerIDs {
		wg.Add(1)
		go func(containerID string) {
			defer wg.Done()

			stats, err := c.ContainerStatsOnce(ctx, containerID)
			if err != nil {
				return // Skip containers we can't get stats for
			}

			mu.Lock()
			results[containerID] = stats
			mu.Unlock()
		}(id)
	}

	wg.Wait()
	return results, nil
}

// AllContainerStats returns stats for all running containers
func (c *Client) AllContainerStats(ctx context.Context) (map[string]*ContainerStats, error) {
	// Get list of running containers
	containers, err := c.ContainerList(ctx, ContainerListOptions{
		All: false, // Only running
	})
	if err != nil {
		return nil, err
	}

	containerIDs := make([]string, len(containers))
	for i, cont := range containers {
		containerIDs[i] = cont.ID
	}

	return c.MultiContainerStats(ctx, containerIDs)
}

// StatsAggregator aggregates stats from multiple containers
type StatsAggregator struct {
	TotalCPUPercent    float64
	TotalMemoryUsage   uint64
	TotalMemoryLimit   uint64
	TotalNetworkRx     uint64
	TotalNetworkTx     uint64
	TotalBlockRead     uint64
	TotalBlockWrite    uint64
	TotalPIDs          uint64
	ContainerCount     int
	HealthyCount       int
	UnhealthyCount     int
	Timestamp          time.Time
}

// AggregateStats aggregates stats from a map of container stats
func AggregateStats(stats map[string]*ContainerStats) *StatsAggregator {
	agg := &StatsAggregator{
		Timestamp:      time.Now(),
		ContainerCount: len(stats),
	}

	for _, s := range stats {
		if s == nil {
			continue
		}
		agg.TotalCPUPercent += s.CPUPercent
		agg.TotalMemoryUsage += s.MemoryUsage
		agg.TotalMemoryLimit += s.MemoryLimit
		agg.TotalNetworkRx += s.NetworkRx
		agg.TotalNetworkTx += s.NetworkTx
		agg.TotalBlockRead += s.BlockRead
		agg.TotalBlockWrite += s.BlockWrite
		agg.TotalPIDs += s.PIDs
	}

	return agg
}

// StatsCollector continuously collects stats from containers
type StatsCollector struct {
	client   *Client
	interval time.Duration
	statsCh  chan map[string]*ContainerStats
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// NewStatsCollector creates a new stats collector
func (c *Client) NewStatsCollector(interval time.Duration) *StatsCollector {
	if interval < time.Second {
		interval = time.Second
	}

	return &StatsCollector{
		client:   c,
		interval: interval,
		statsCh:  make(chan map[string]*ContainerStats, 10),
	}
}

// Start begins collecting stats at the configured interval
func (sc *StatsCollector) Start(ctx context.Context) {
	ctx, sc.cancel = context.WithCancel(ctx)

	sc.wg.Add(1)
	go func() {
		defer sc.wg.Done()
		defer close(sc.statsCh)

		ticker := time.NewTicker(sc.interval)
		defer ticker.Stop()

		// Collect immediately on start
		if stats, err := sc.client.AllContainerStats(ctx); err == nil {
			select {
			case sc.statsCh <- stats:
			case <-ctx.Done():
				return
			}
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats, err := sc.client.AllContainerStats(ctx)
				if err != nil {
					continue
				}

				select {
				case sc.statsCh <- stats:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
}

// Stats returns the channel of collected stats
func (sc *StatsCollector) Stats() <-chan map[string]*ContainerStats {
	return sc.statsCh
}

// Stop stops the stats collector
func (sc *StatsCollector) Stop() {
	if sc.cancel != nil {
		sc.cancel()
	}
	sc.wg.Wait()
}

// ResourceUsageSummary represents a summary of resource usage
type ResourceUsageSummary struct {
	ContainerID   string
	ContainerName string
	CPUPercent    float64
	MemoryUsage   uint64
	MemoryLimit   uint64
	MemoryPercent float64
	NetworkRx     uint64
	NetworkTx     uint64
	BlockRead     uint64
	BlockWrite    uint64
	PIDs          uint64
	State         string
}

// GetResourceUsageSummary returns a summary of resource usage for all containers
func (c *Client) GetResourceUsageSummary(ctx context.Context) ([]ResourceUsageSummary, error) {
	// Get all containers (including stopped for state info)
	containers, err := c.ContainerList(ctx, ContainerListOptions{All: true})
	if err != nil {
		return nil, err
	}

	// Get stats for running containers
	stats, err := c.AllContainerStats(ctx)
	if err != nil {
		return nil, err
	}

	var result []ResourceUsageSummary

	for _, cont := range containers {
		summary := ResourceUsageSummary{
			ContainerID:   cont.ID,
			ContainerName: cont.Name,
			State:         cont.State,
		}

		if s, ok := stats[cont.ID]; ok && s != nil {
			summary.CPUPercent = s.CPUPercent
			summary.MemoryUsage = s.MemoryUsage
			summary.MemoryLimit = s.MemoryLimit
			summary.MemoryPercent = s.MemoryPercent
			summary.NetworkRx = s.NetworkRx
			summary.NetworkTx = s.NetworkTx
			summary.BlockRead = s.BlockRead
			summary.BlockWrite = s.BlockWrite
			summary.PIDs = s.PIDs
		}

		result = append(result, summary)
	}

	return result, nil
}

// TopConsumers returns the top N containers by CPU or memory usage
type ResourceType string

const (
	ResourceCPU    ResourceType = "cpu"
	ResourceMemory ResourceType = "memory"
)

func (c *Client) TopConsumers(ctx context.Context, resourceType ResourceType, limit int) ([]ResourceUsageSummary, error) {
	summaries, err := c.GetResourceUsageSummary(ctx)
	if err != nil {
		return nil, err
	}

	// Sort by resource type
	switch resourceType {
	case ResourceCPU:
		sortByCPU(summaries)
	case ResourceMemory:
		sortByMemory(summaries)
	}

	if limit > 0 && limit < len(summaries) {
		summaries = summaries[:limit]
	}

	return summaries, nil
}

// sortByCPU sorts summaries by CPU usage (descending)
func sortByCPU(summaries []ResourceUsageSummary) {
	for i := 0; i < len(summaries)-1; i++ {
		for j := i + 1; j < len(summaries); j++ {
			if summaries[j].CPUPercent > summaries[i].CPUPercent {
				summaries[i], summaries[j] = summaries[j], summaries[i]
			}
		}
	}
}

// sortByMemory sorts summaries by memory usage (descending)
func sortByMemory(summaries []ResourceUsageSummary) {
	for i := 0; i < len(summaries)-1; i++ {
		for j := i + 1; j < len(summaries); j++ {
			if summaries[j].MemoryUsage > summaries[i].MemoryUsage {
				summaries[i], summaries[j] = summaries[j], summaries[i]
			}
		}
	}
}

// ContainerResourceAlert represents a resource threshold alert
type ContainerResourceAlert struct {
	ContainerID   string
	ContainerName string
	AlertType     string
	CurrentValue  float64
	Threshold     float64
	Message       string
	Timestamp     time.Time
}

// CheckResourceThresholds checks if any containers exceed resource thresholds
func (c *Client) CheckResourceThresholds(ctx context.Context, cpuThreshold, memoryThreshold float64) ([]ContainerResourceAlert, error) {
	summaries, err := c.GetResourceUsageSummary(ctx)
	if err != nil {
		return nil, err
	}

	var alerts []ContainerResourceAlert

	for _, s := range summaries {
		if s.State != "running" {
			continue
		}

		if cpuThreshold > 0 && s.CPUPercent > cpuThreshold {
			alerts = append(alerts, ContainerResourceAlert{
				ContainerID:   s.ContainerID,
				ContainerName: s.ContainerName,
				AlertType:     "cpu_high",
				CurrentValue:  s.CPUPercent,
				Threshold:     cpuThreshold,
				Message:       "CPU usage exceeds threshold",
				Timestamp:     time.Now(),
			})
		}

		if memoryThreshold > 0 && s.MemoryPercent > memoryThreshold {
			alerts = append(alerts, ContainerResourceAlert{
				ContainerID:   s.ContainerID,
				ContainerName: s.ContainerName,
				AlertType:     "memory_high",
				CurrentValue:  s.MemoryPercent,
				Threshold:     memoryThreshold,
				Message:       "Memory usage exceeds threshold",
				Timestamp:     time.Now(),
			})
		}
	}

	return alerts, nil
}
