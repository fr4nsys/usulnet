// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	dockerClient "github.com/docker/docker/client"
	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/web/templates/pages/monitoring"
)

// MonitoringPage renders the main monitoring dashboard.
func (h *Handler) MonitoringPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cli, err := h.getDockerClient(r)
	if err != nil {
		h.RenderError(w, r, http.StatusInternalServerError, "Error", "Docker connection failed")
		return
	}

	// Gather host info
	info, err := cli.Info(ctx)
	if err != nil {
		h.RenderError(w, r, http.StatusInternalServerError, "Error", "Failed to get Docker info")
		return
	}

	host := monitoring.HostStats{
		Containers:    info.Containers,
		Running:       info.ContainersRunning,
		Paused:        info.ContainersPaused,
		Stopped:       info.ContainersStopped,
		Images:        info.Images,
		DockerVersion: info.ServerVersion,
		Hostname:      info.Name,
		OS:            fmt.Sprintf("%s %s", info.OperatingSystem, info.Architecture),
		KernelVersion: info.KernelVersion,
		CPUCores:      info.NCPU,
		MemTotal:      uint64(info.MemTotal),
	}

	// Fetch disk usage from system df
	du, err := cli.DiskUsage(ctx, types.DiskUsageOptions{})
	if err == nil {
		for _, v := range du.Volumes {
			if v.UsageData.Size > 0 {
				host.DiskUsed += uint64(v.UsageData.Size)
			}
		}
	}

	// Get container list with stats snapshot
	containers, err := cli.ContainerList(ctx, container.ListOptions{All: false})
	if err != nil {
		h.RenderError(w, r, http.StatusInternalServerError, "Error", "Failed to list containers")
		return
	}

	stats := make([]monitoring.ContainerStat, 0, len(containers))
	for _, c := range containers {
		cs := containerToStat(ctx, cli, c)
		stats = append(stats, cs)

		// Aggregate for host CPU/mem
		host.CPUPercent += cs.CPUPercent
		if host.MemTotal > 0 {
			host.MemUsed += cs.MemUsage
		}
	}

	// Calculate host memory percent from container aggregation (approximation)
	if host.MemTotal > 0 {
		host.MemPercent = float64(host.MemUsed) / float64(host.MemTotal) * 100
	}

	data := monitoring.MonitoringData{
		PageData:   h.prepareTemplPageData(r, "Monitoring", "monitoring"),
		Host:       host,
		Containers: stats,
	}

	monitoring.Monitoring(data).Render(ctx, w)
}

// MonitoringContainerPage renders the detail monitoring page for a single container.
func (h *Handler) MonitoringContainerPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	containerID := chi.URLParam(r, "id")

	cli, err := h.getDockerClient(r)
	if err != nil {
		h.RenderError(w, r, http.StatusInternalServerError, "Error", "Docker connection failed")
		return
	}

	// Inspect container
	inspect, err := cli.ContainerInspect(ctx, containerID)
	if err != nil {
		h.RenderError(w, r, http.StatusNotFound, "Error", "Container not found")
		return
	}

	// Get one-shot stats
	statsJSON, err := cli.ContainerStats(ctx, containerID, false)
	if err != nil {
		h.RenderError(w, r, http.StatusInternalServerError, "Error", "Failed to get container stats")
		return
	}
	defer statsJSON.Body.Close()

	var stat container.StatsResponse
	if err := decodeStats(statsJSON.Body, &stat); err != nil {
		// Non-fatal: proceed with zero stats
		stat = container.StatsResponse{}
	}

	cs := buildContainerStat(inspect, stat)

	// Get top processes (only for running containers)
	var processes []monitoring.ProcessInfo
	if inspect.State.Running {
		top, err := cli.ContainerTop(ctx, containerID, []string{"aux"})
		if err == nil {
			processes = parseTopOutput(top)
		}
	}

	// Host memory for context
	info, _ := cli.Info(ctx)

	data := monitoring.ContainerDetailData{
		PageData:   h.prepareTemplPageData(r, cs.Name+" — Monitoring", "monitoring"),
		Container:  cs,
		Processes:  processes,
		HostMemory: uint64(info.MemTotal),
	}

	monitoring.ContainerDetail(data).Render(ctx, w)
}

// ============================================================================
// Helpers
// ============================================================================

// containerToStat converts a Docker container list entry to ContainerStat by fetching a one-shot stats snapshot.
func containerToStat(ctx context.Context, cli *dockerClient.Client, c types.Container) monitoring.ContainerStat {
	cs := monitoring.ContainerStat{
		ID:    c.ID[:12],
		Name:  strings.TrimPrefix(firstOrDefault(c.Names, "/"+c.ID[:12]), "/"),
		Image: c.Image,
		State: c.State,
	}

	// Calculate uptime
	if c.State == "running" {
		created := time.Unix(c.Created, 0)
		cs.Uptime = formatDuration(time.Since(created))
	}

	// Quick stats snapshot (stream=false for a single read)
	ctxTimeout, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	statsResp, err := cli.ContainerStats(ctxTimeout, c.ID, false)
	if err != nil {
		return cs
	}
	defer statsResp.Body.Close()

	var stat container.StatsResponse
	if err := decodeStats(statsResp.Body, &stat); err != nil {
		return cs
	}

	cs.CPUPercent = calculateCPUPercent(stat)
	cs.MemUsage = stat.MemoryStats.Usage
	cs.MemLimit = stat.MemoryStats.Limit
	if cs.MemLimit > 0 {
		cs.MemPercent = float64(cs.MemUsage) / float64(cs.MemLimit) * 100
	}
	cs.PIDs = stat.PidsStats.Current

	// Network
	for _, net := range stat.Networks {
		cs.NetRx += net.RxBytes
		cs.NetTx += net.TxBytes
	}

	// Block I/O
	for _, bio := range stat.BlkioStats.IoServiceBytesRecursive {
		switch bio.Op {
		case "read", "Read":
			cs.BlockRead += bio.Value
		case "write", "Write":
			cs.BlockWrite += bio.Value
		}
	}

	return cs
}

// buildContainerStat creates a ContainerStat from inspect + stats data for the detail page.
func buildContainerStat(inspect types.ContainerJSON, stat container.StatsResponse) monitoring.ContainerStat {
	name := strings.TrimPrefix(inspect.Name, "/")
	cs := monitoring.ContainerStat{
		ID:    inspect.ID[:12],
		Name:  name,
		Image: inspect.Config.Image,
		State: inspect.State.Status,
	}

	if inspect.State.Running {
		started, _ := time.Parse(time.RFC3339Nano, inspect.State.StartedAt)
		if !started.IsZero() {
			cs.Uptime = formatDuration(time.Since(started))
		}
	}

	cs.CPUPercent = calculateCPUPercent(stat)
	cs.MemUsage = stat.MemoryStats.Usage
	cs.MemLimit = stat.MemoryStats.Limit
	if cs.MemLimit > 0 {
		cs.MemPercent = float64(cs.MemUsage) / float64(cs.MemLimit) * 100
	}
	cs.PIDs = stat.PidsStats.Current

	for _, net := range stat.Networks {
		cs.NetRx += net.RxBytes
		cs.NetTx += net.TxBytes
	}

	for _, bio := range stat.BlkioStats.IoServiceBytesRecursive {
		switch bio.Op {
		case "read", "Read":
			cs.BlockRead += bio.Value
		case "write", "Write":
			cs.BlockWrite += bio.Value
		}
	}

	return cs
}

// calculateCPUPercent computes CPU usage percentage from Docker stats.
// This is the same formula used by docker stats CLI.
func calculateCPUPercent(stat container.StatsResponse) float64 {
	cpuDelta := float64(stat.CPUStats.CPUUsage.TotalUsage - stat.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stat.CPUStats.SystemUsage - stat.PreCPUStats.SystemUsage)
	if systemDelta <= 0 || cpuDelta < 0 {
		return 0
	}
	onlineCPUs := float64(stat.CPUStats.OnlineCPUs)
	if onlineCPUs == 0 {
		onlineCPUs = float64(len(stat.CPUStats.CPUUsage.PercpuUsage))
	}
	if onlineCPUs == 0 {
		onlineCPUs = 1
	}
	return (cpuDelta / systemDelta) * onlineCPUs * 100.0
}

// parseTopOutput converts `docker top` output to ProcessInfo slice.
func parseTopOutput(top container.ContainerTopOKBody) []monitoring.ProcessInfo {
	procs := make([]monitoring.ProcessInfo, 0, len(top.Processes))

	// Find column indices
	pidIdx, userIdx, cpuIdx, memIdx, vszIdx, rssIdx, cmdIdx := -1, -1, -1, -1, -1, -1, -1
	for i, title := range top.Titles {
		switch strings.ToUpper(title) {
		case "PID":
			pidIdx = i
		case "USER":
			userIdx = i
		case "%CPU":
			cpuIdx = i
		case "%MEM":
			memIdx = i
		case "VSZ":
			vszIdx = i
		case "RSS":
			rssIdx = i
		case "COMMAND", "CMD":
			cmdIdx = i
		}
	}

	for _, row := range top.Processes {
		p := monitoring.ProcessInfo{}
		if pidIdx >= 0 && pidIdx < len(row) {
			fmt.Sscanf(row[pidIdx], "%d", &p.PID)
		}
		if userIdx >= 0 && userIdx < len(row) {
			p.User = row[userIdx]
		}
		if cpuIdx >= 0 && cpuIdx < len(row) {
			fmt.Sscanf(row[cpuIdx], "%f", &p.CPU)
		}
		if memIdx >= 0 && memIdx < len(row) {
			fmt.Sscanf(row[memIdx], "%f", &p.Mem)
		}
		if vszIdx >= 0 && vszIdx < len(row) {
			var v uint64
			fmt.Sscanf(row[vszIdx], "%d", &v)
			p.VSZ = v * 1024 // VSZ is in KB
		}
		if rssIdx >= 0 && rssIdx < len(row) {
			var v uint64
			fmt.Sscanf(row[rssIdx], "%d", &v)
			p.RSS = v * 1024 // RSS is in KB
		}
		if cmdIdx >= 0 && cmdIdx < len(row) {
			p.Command = row[cmdIdx]
		}
		procs = append(procs, p)
	}
	return procs
}

// decodeStats reads a stats JSON response from the Docker API.
func decodeStats(reader interface{ Read([]byte) (int, error) }, stat *container.StatsResponse) error {
	decoder := jsonDecoder(reader)
	return decoder.Decode(stat)
}

// formatDuration produces human-readable durations like "2d 4h", "45m", "12s".
func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm", minutes)
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}

func firstOrDefault(names []string, def string) string {
	if len(names) > 0 {
		return names[0]
	}
	return def
}
