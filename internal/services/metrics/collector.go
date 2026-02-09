// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package metrics

import (
	"context"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	dockerpkg "github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
)

// DockerClientProvider returns a Docker client for a given host.
type DockerClientProvider interface {
	GetClient(ctx context.Context, hostID uuid.UUID) (dockerpkg.ClientAPI, error)
}

// Collector gathers host and container metrics via Docker API + /proc.
type Collector struct {
	clientProvider DockerClientProvider
	logger         *logger.Logger
}

// NewCollector creates a metrics collector.
func NewCollector(provider DockerClientProvider, log *logger.Logger) *Collector {
	return &Collector{
		clientProvider: provider,
		logger:         log.Named("metrics-collector"),
	}
}

// CollectHostMetrics gathers system-level metrics from Docker info + filesystem.
func (c *Collector) CollectHostMetrics(ctx context.Context, hostID uuid.UUID) (*workers.HostMetrics, error) {
	client, err := c.clientProvider.GetClient(ctx, hostID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get docker client for host")
	}

	info, err := client.Info(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get docker info")
	}

	now := time.Now()
	metrics := &workers.HostMetrics{
		HostID:            hostID,
		MemoryTotal:       info.MemTotal,
		ContainersTotal:   info.Containers,
		ContainersRunning: info.ContainersRunning,
		ContainersStopped: info.ContainersStopped,
		ImagesTotal:       info.Images,
		CollectedAt:       now,
	}

	// Disk usage for Docker root dir (or / fallback)
	rootDir := info.DockerRootDir
	if rootDir == "" {
		rootDir = "/"
	}
	du, de := diskUsage(rootDir)
	if de == nil {
		metrics.DiskUsed = du.Used
		metrics.DiskTotal = du.Total
		if du.Total > 0 {
			metrics.DiskPercent = float64(du.Used) / float64(du.Total) * 100
		}
	}

	// CPU usage from /proc/stat (only works when running on same host)
	cpuPct, cpuErr := readCPUPercent()
	if cpuErr == nil {
		metrics.CPUUsagePercent = cpuPct
	}

	// Memory from /proc/meminfo
	memUsed, memErr := readMemoryUsed()
	if memErr == nil {
		metrics.MemoryUsed = memUsed
		if metrics.MemoryTotal > 0 {
			metrics.MemoryPercent = float64(memUsed) / float64(metrics.MemoryTotal) * 100
		}
	}

	// Network aggregate from containers
	allStats, err := client.AllContainerStats(ctx)
	if err == nil {
		var rxTotal, txTotal int64
		for _, s := range allStats {
			if s != nil {
				rxTotal += int64(s.NetworkRx)
				txTotal += int64(s.NetworkTx)
			}
		}
		metrics.NetworkRxBytes = rxTotal
		metrics.NetworkTxBytes = txTotal
	}

	// Volume count
	volumes, vErr := client.VolumeList(ctx, dockerpkg.VolumeListOptions{})
	if vErr == nil {
		metrics.VolumesTotal = len(volumes)
	}

	return metrics, nil
}

// CollectContainerMetrics gathers per-container stats from Docker API.
func (c *Collector) CollectContainerMetrics(ctx context.Context, hostID uuid.UUID) ([]*workers.ContainerMetrics, error) {
	client, err := c.clientProvider.GetClient(ctx, hostID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get docker client")
	}

	containers, err := client.ContainerList(ctx, dockerpkg.ContainerListOptions{All: true})
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to list containers")
	}

	statsMap, _ := client.AllContainerStats(ctx)

	now := time.Now()
	result := make([]*workers.ContainerMetrics, 0, len(containers))

	for _, cont := range containers {
		cm := &workers.ContainerMetrics{
			ContainerID:   cont.ID,
			ContainerName: cont.Name,
			State:         cont.State,
			Health:        cont.Health,
			CollectedAt:   now,
		}

		// Uptime if running
		if cont.State == "running" && !cont.Created.IsZero() {
			cm.Uptime = int64(now.Sub(cont.Created).Seconds())
		}

		// Stats from Docker API
		if s, ok := statsMap[cont.ID]; ok && s != nil {
			cm.CPUUsagePercent = s.CPUPercent
			cm.MemoryUsed = int64(s.MemoryUsage)
			cm.MemoryLimit = int64(s.MemoryLimit)
			if s.MemoryLimit > 0 {
				cm.MemoryPercent = float64(s.MemoryUsage) / float64(s.MemoryLimit) * 100
			}
			cm.NetworkRxBytes = int64(s.NetworkRx)
			cm.NetworkTxBytes = int64(s.NetworkTx)
			cm.BlockRead = int64(s.BlockRead)
			cm.BlockWrite = int64(s.BlockWrite)
			cm.PIDs = int(s.PIDs)
		}

		result = append(result, cm)
	}

	return result, nil
}

// ============================================================================
// System metrics helpers (Linux /proc + syscall)
// ============================================================================

type diskInfo struct {
	Total int64
	Used  int64
}

// diskUsage reads filesystem stats via syscall.Statfs.
func diskUsage(path string) (*diskInfo, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return nil, err
	}
	total := int64(stat.Blocks) * int64(stat.Bsize)
	free := int64(stat.Bavail) * int64(stat.Bsize)
	return &diskInfo{
		Total: total,
		Used:  total - free,
	}, nil
}

// readCPUPercent reads CPU usage from /proc/stat.
// Takes two samples 200ms apart for a delta calculation.
func readCPUPercent() (float64, error) {
	idle1, total1, err := readCPUSample()
	if err != nil {
		return 0, err
	}
	time.Sleep(200 * time.Millisecond)
	idle2, total2, err := readCPUSample()
	if err != nil {
		return 0, err
	}

	idleDelta := float64(idle2 - idle1)
	totalDelta := float64(total2 - total1)
	if totalDelta == 0 {
		return 0, nil
	}
	return (1.0 - idleDelta/totalDelta) * 100, nil
}

// readCPUSample reads a single /proc/stat cpu line.
func readCPUSample() (idle, total uint64, err error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return 0, 0, errors.New(errors.CodeInternal, "unexpected /proc/stat format")
		}
		// fields: cpu user nice system idle iowait irq softirq steal guest guest_nice
		var vals [10]uint64
		for i := 1; i < len(fields) && i <= 10; i++ {
			v, _ := strconv.ParseUint(fields[i], 10, 64)
			vals[i-1] = v
		}
		for _, v := range vals {
			total += v
		}
		idle = vals[3] // idle field
		if len(fields) > 5 {
			idle += vals[4] // iowait
		}
		return idle, total, nil
	}
	return 0, 0, errors.New(errors.CodeInternal, "cpu line not found in /proc/stat")
}

// readMemoryUsed reads used memory from /proc/meminfo.
func readMemoryUsed() (int64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}

	var memTotal, memAvailable int64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseInt(fields[1], 10, 64)
		val *= 1024 // kB → bytes
		switch fields[0] {
		case "MemTotal:":
			memTotal = val
		case "MemAvailable:":
			memAvailable = val
		}
	}

	if memTotal == 0 {
		return 0, errors.New(errors.CodeInternal, "could not parse /proc/meminfo")
	}
	return memTotal - memAvailable, nil
}
