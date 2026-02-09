// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	dockerClient "github.com/docker/docker/client"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

// ============================================================================
// WebSocket Upgrader
// ============================================================================

var monitoringUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// ============================================================================
// JSON message types sent over WebSocket
// ============================================================================

type wsMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type wsHostStats struct {
	CPUPercent float64 `json:"cpu_percent"`
	MemPercent float64 `json:"mem_percent"`
	MemUsed    uint64  `json:"mem_used"`
	MemTotal   uint64  `json:"mem_total"`
}

type wsContainerStats struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Image      string  `json:"image"`
	State      string  `json:"state"`
	CPUPercent float64 `json:"cpu_percent"`
	MemUsage   uint64  `json:"mem_usage"`
	MemLimit   uint64  `json:"mem_limit"`
	MemPercent float64 `json:"mem_percent"`
	NetRx      uint64  `json:"net_rx"`
	NetTx      uint64  `json:"net_tx"`
	BlockRead  uint64  `json:"block_read"`
	BlockWrite uint64  `json:"block_write"`
	PIDs       uint64  `json:"pids"`
	Uptime     string  `json:"uptime"`
}

type wsStatsPayload struct {
	Host       wsHostStats        `json:"host"`
	Containers []wsContainerStats `json:"containers"`
}

type wsProcessInfo struct {
	PID     int     `json:"pid"`
	User    string  `json:"user"`
	CPU     float64 `json:"cpu"`
	Mem     float64 `json:"mem"`
	VSZ     uint64  `json:"vsz"`
	RSS     uint64  `json:"rss"`
	Command string  `json:"command"`
}

// ============================================================================
// Global Monitoring Dashboard — streams all container stats
// ============================================================================

// WsMonitoringStats handles WebSocket connections for the global monitoring dashboard.
// Endpoint: /ws/monitoring/stats
func (h *Handler) WsMonitoringStats(w http.ResponseWriter, r *http.Request) {
	conn, err := monitoringUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	cli, err := h.getDockerClient(r)
	if err != nil {
		conn.WriteJSON(wsMessage{Type: "error", Data: "Docker connection failed"})
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Read pump: detect client disconnect
	go func() {
		defer cancel()
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			payload, err := collectAllStats(ctx, cli)
			if err != nil {
				continue // skip this tick on error
			}
			msg := wsMessage{Type: "stats", Data: payload}
			if err := conn.WriteJSON(msg); err != nil {
				return
			}
		}
	}
}

// collectAllStats gathers stats for all running containers and host summary.
func collectAllStats(ctx context.Context, cli *dockerClient.Client) (*wsStatsPayload, error) {
	containers, err := cli.ContainerList(ctx, container.ListOptions{All: false})
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	info, err := cli.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("docker info: %w", err)
	}

	payload := &wsStatsPayload{
		Host: wsHostStats{
			MemTotal: uint64(info.MemTotal),
		},
		Containers: make([]wsContainerStats, 0, len(containers)),
	}

	// Collect stats concurrently with a bounded pool
	type result struct {
		stat wsContainerStats
		err  error
	}

	sem := make(chan struct{}, 10) // max 10 concurrent stat calls
	results := make(chan result, len(containers))
	var wg sync.WaitGroup

	for _, c := range containers {
		wg.Add(1)
		go func(c types.Container) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			cs := fetchContainerWsStats(ctx, cli, c)
			results <- result{stat: cs}
		}(c)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for res := range results {
		payload.Containers = append(payload.Containers, res.stat)
		payload.Host.CPUPercent += res.stat.CPUPercent
		payload.Host.MemUsed += res.stat.MemUsage
	}

	if payload.Host.MemTotal > 0 {
		payload.Host.MemPercent = float64(payload.Host.MemUsed) / float64(payload.Host.MemTotal) * 100
	}

	return payload, nil
}

// fetchContainerWsStats gets a one-shot stats snapshot for a single container.
func fetchContainerWsStats(ctx context.Context, cli *dockerClient.Client, c types.Container) wsContainerStats {
	cs := wsContainerStats{
		ID:    c.ID[:12],
		Name:  strings.TrimPrefix(firstOrDefault(c.Names, "/"+c.ID[:12]), "/"),
		Image: c.Image,
		State: c.State,
	}

	if c.State == "running" {
		created := time.Unix(c.Created, 0)
		cs.Uptime = formatDuration(time.Since(created))
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	statsResp, err := cli.ContainerStats(ctxTimeout, c.ID, false)
	if err != nil {
		return cs
	}
	defer statsResp.Body.Close()

	var stat container.StatsResponse
	dec := json.NewDecoder(statsResp.Body)
	if err := dec.Decode(&stat); err != nil {
		return cs
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

// ============================================================================
// Per-Container Monitoring — streams stats for a single container
// ============================================================================

// WsMonitoringContainer handles WebSocket connections for a single container's monitoring.
// Endpoint: /ws/monitoring/container/{id}
func (h *Handler) WsMonitoringContainer(w http.ResponseWriter, r *http.Request) {
	containerID := chi.URLParam(r, "id")

	conn, err := monitoringUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	cli, err := h.getDockerClient(r)
	if err != nil {
		conn.WriteJSON(wsMessage{Type: "error", Data: "Docker connection failed"})
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Read pump
	go func() {
		defer cancel()
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				return
			}
		}
	}()

	// Use Docker streaming stats (stream=true) for efficiency on single container
	statsResp, err := cli.ContainerStats(ctx, containerID, true)
	if err != nil {
		conn.WriteJSON(wsMessage{Type: "error", Data: "Failed to get container stats"})
		return
	}
	defer statsResp.Body.Close()

	dec := json.NewDecoder(statsResp.Body)

	// Also periodically send process list
	procTicker := time.NewTicker(5 * time.Second)
	defer procTicker.Stop()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-procTicker.C:
				sendProcessList(ctx, cli, conn, containerID)
			}
		}
	}()

	// Stream stats
	for {
		var stat container.StatsResponse
		if err := dec.Decode(&stat); err != nil {
			if err == io.EOF || ctx.Err() != nil {
				return
			}
			continue
		}

		cs := statsJSONToWs(stat, containerID)
		msg := wsMessage{Type: "container_stats", Data: cs}
		if err := conn.WriteJSON(msg); err != nil {
			return
		}
	}
}

// statsJSONToWs converts a Docker StatsJSON to our WebSocket container stats struct.
func statsJSONToWs(stat container.StatsResponse, containerID string) wsContainerStats {
	cs := wsContainerStats{
		ID: containerID,
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

// sendProcessList sends the process list for a container over the WebSocket.
func sendProcessList(ctx context.Context, cli *dockerClient.Client, conn *websocket.Conn, containerID string) {
	top, err := cli.ContainerTop(ctx, containerID, []string{"aux"})
	if err != nil {
		return
	}

	procs := make([]wsProcessInfo, 0, len(top.Processes))

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
		p := wsProcessInfo{}
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
			p.VSZ = v * 1024
		}
		if rssIdx >= 0 && rssIdx < len(row) {
			var v uint64
			fmt.Sscanf(row[rssIdx], "%d", &v)
			p.RSS = v * 1024
		}
		if cmdIdx >= 0 && cmdIdx < len(row) {
			p.Command = row[cmdIdx]
		}
		procs = append(procs, p)
	}

	conn.WriteJSON(wsMessage{Type: "processes", Data: procs})
}
