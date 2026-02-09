// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/fr4nsys/usulnet/internal/models"
	metricspkg "github.com/fr4nsys/usulnet/internal/services/metrics"
	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
)

// ============================================================================
// Monitoring Page (GET /monitoring)
// ============================================================================

// MonitoringTempl renders the main monitoring page with current host + container stats.
// Phase 8 will add Templ templates; for now returns JSON.
func (h *Handler) MonitoringTempl(w http.ResponseWriter, r *http.Request) {
	metricsSvc := h.services.Metrics()
	if metricsSvc == nil {
		h.renderJSONError(w, http.StatusServiceUnavailable, "metrics service not configured")
		return
	}

	hostID := h.getDefaultHostID(r)
	if hostID == uuid.Nil {
		h.renderJSONError(w, http.StatusBadRequest, "no host configured")
		return
	}

	ctx := r.Context()

	// Collect current host metrics
	hostMetrics, err := metricsSvc.GetCurrentHostMetrics(ctx, hostID)
	if err != nil {
		h.renderJSONError(w, http.StatusInternalServerError, "failed to collect host metrics: "+err.Error())
		return
	}

	// Collect current container metrics
	containerMetrics, err := metricsSvc.GetCurrentContainerMetrics(ctx, hostID)
	if err != nil {
		h.renderJSONError(w, http.StatusInternalServerError, "failed to collect container metrics: "+err.Error())
		return
	}

	data := MonitoringPageResponse{
		Host:       formatHostStats(hostMetrics),
		Containers: formatContainerStats(containerMetrics),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}

	h.renderJSON(w, http.StatusOK, data)
}

// ============================================================================
// Host Stats Partial (GET /monitoring/host)
// ============================================================================

// MonitoringHostPartial returns host stats as HTMX partial or JSON.
func (h *Handler) MonitoringHostPartial(w http.ResponseWriter, r *http.Request) {
	metricsSvc := h.services.Metrics()
	if metricsSvc == nil {
		h.renderJSONError(w, http.StatusServiceUnavailable, "metrics service not configured")
		return
	}

	hostID := h.getDefaultHostID(r)
	if hostID == uuid.Nil {
		h.renderJSONError(w, http.StatusBadRequest, "no host configured")
		return
	}

	hostMetrics, err := metricsSvc.GetCurrentHostMetrics(r.Context(), hostID)
	if err != nil {
		h.renderJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.renderJSON(w, http.StatusOK, formatHostStats(hostMetrics))
}

// ============================================================================
// Container Stats Partial (GET /monitoring/containers)
// ============================================================================

// MonitoringContainersPartial returns per-container stats as HTMX partial or JSON.
func (h *Handler) MonitoringContainersPartial(w http.ResponseWriter, r *http.Request) {
	metricsSvc := h.services.Metrics()
	if metricsSvc == nil {
		h.renderJSONError(w, http.StatusServiceUnavailable, "metrics service not configured")
		return
	}

	hostID := h.getDefaultHostID(r)
	if hostID == uuid.Nil {
		h.renderJSONError(w, http.StatusBadRequest, "no host configured")
		return
	}

	containerMetrics, err := metricsSvc.GetCurrentContainerMetrics(r.Context(), hostID)
	if err != nil {
		h.renderJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.renderJSON(w, http.StatusOK, formatContainerStats(containerMetrics))
}

// ============================================================================
// History JSON (GET /monitoring/history)
// ============================================================================

// MonitoringHistoryJSON returns time-series data for Chart.js rendering.
// Query params: type=host|container, container_id=xxx, range=1h|6h|24h|7d, interval=1m|5m|1h|1d
func (h *Handler) MonitoringHistoryJSON(w http.ResponseWriter, r *http.Request) {
	metricsSvc := h.services.Metrics()
	if metricsSvc == nil {
		h.renderJSONError(w, http.StatusServiceUnavailable, "metrics service not configured")
		return
	}

	hostID := h.getDefaultHostID(r)
	if hostID == uuid.Nil {
		h.renderJSONError(w, http.StatusBadRequest, "no host configured")
		return
	}

	metricType := r.URL.Query().Get("type")
	if metricType == "" {
		metricType = "host"
	}

	// Parse time range
	rangeStr := r.URL.Query().Get("range")
	from, to := parseTimeRange(rangeStr)

	interval := r.URL.Query().Get("interval")
	if interval == "" {
		interval = inferInterval(rangeStr)
	}

	ctx := r.Context()

	if metricType == "container" {
		containerID := r.URL.Query().Get("container_id")
		if containerID == "" {
			h.renderJSONError(w, http.StatusBadRequest, "container_id required for container history")
			return
		}

		snapshots, err := metricsSvc.GetContainerHistory(ctx, containerID, from, to, interval)
		if err != nil {
			h.renderJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		h.renderJSON(w, http.StatusOK, formatHistoryResponse("container", snapshots))
		return
	}

	// Default: host history
	snapshots, err := metricsSvc.GetHostHistory(ctx, hostID, from, to, interval)
	if err != nil {
		h.renderJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.renderJSON(w, http.StatusOK, formatHistoryResponse("host", snapshots))
}

// ============================================================================
// WebSocket Live Metrics (GET /ws/metrics)
// ============================================================================

// WSMetrics streams live host + container metrics over WebSocket.
// Sends a JSON message every N seconds (default 5s, configurable via ?interval=).
func (h *Handler) WSMetrics(w http.ResponseWriter, r *http.Request) {
	metricsSvc := h.services.Metrics()
	if metricsSvc == nil {
		http.Error(w, "metrics service not configured", http.StatusServiceUnavailable)
		return
	}

	hostID := h.getDefaultHostID(r)
	if hostID == uuid.Nil {
		http.Error(w, "no host configured", http.StatusBadRequest)
		return
	}

	// Parse refresh interval
	intervalSec := 5
	if v := r.URL.Query().Get("interval"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 60 {
			intervalSec = n
		}
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Reader goroutine: detect client disconnect
	go func() {
		defer cancel()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer ticker.Stop()

	// Send immediately, then on tick
	h.sendMetricsSnapshot(ctx, conn, metricsSvc, hostID)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := h.sendMetricsSnapshot(ctx, conn, metricsSvc, hostID); err != nil {
				return
			}
		}
	}
}

func (h *Handler) sendMetricsSnapshot(ctx context.Context, conn *websocket.Conn, svc MetricsServiceFull, hostID uuid.UUID) error {
	// Host metrics
	hostMetrics, err := svc.GetCurrentHostMetrics(ctx, hostID)
	if err == nil && hostMetrics != nil {
		msg := WSMetricsMessage{
			Type: "host",
			Data: formatHostStats(hostMetrics),
		}
		if err := conn.WriteJSON(msg); err != nil {
			return err
		}
	}

	// Container metrics
	containerMetrics, err := svc.GetCurrentContainerMetrics(ctx, hostID)
	if err == nil {
		msg := WSMetricsMessage{
			Type: "containers",
			Data: formatContainerStats(containerMetrics),
		}
		if err := conn.WriteJSON(msg); err != nil {
			return err
		}
	}

	return nil
}

// ============================================================================
// Prometheus Endpoint (GET /metrics)
// ============================================================================

// PrometheusMetrics returns metrics in Prometheus text exposition format.
// Public endpoint (no auth), suitable for Prometheus scraping.
func (h *Handler) PrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	metricsSvc := h.services.Metrics()
	if metricsSvc == nil {
		http.Error(w, "metrics service not configured", http.StatusServiceUnavailable)
		return
	}

	text, err := metricsSvc.GetPrometheusMetrics(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(text))
}

// ============================================================================
// Response Types
// ============================================================================

type MonitoringPageResponse struct {
	Host       HostStatsData        `json:"host"`
	Containers []ContainerStatsData `json:"containers"`
	Timestamp  string               `json:"timestamp"`
}

type HostStatsData struct {
	CPUPercent        float64 `json:"cpu_percent"`
	MemoryUsed        string  `json:"memory_used"`
	MemoryTotal       string  `json:"memory_total"`
	MemoryPercent     float64 `json:"memory_percent"`
	DiskUsed          string  `json:"disk_used"`
	DiskTotal         string  `json:"disk_total"`
	DiskPercent       float64 `json:"disk_percent"`
	NetworkRx         string  `json:"network_rx"`
	NetworkTx         string  `json:"network_tx"`
	ContainersRunning int     `json:"containers_running"`
	ContainersTotal   int     `json:"containers_total"`
	ContainersStopped int     `json:"containers_stopped"`
	ImagesTotal       int     `json:"images_total"`
	VolumesTotal      int     `json:"volumes_total"`
}

type ContainerStatsData struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	State         string  `json:"state"`
	Health        string  `json:"health,omitempty"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryUsed    string  `json:"memory_used"`
	MemoryLimit   string  `json:"memory_limit"`
	MemoryPercent float64 `json:"memory_percent"`
	NetworkRx     string  `json:"network_rx"`
	NetworkTx     string  `json:"network_tx"`
	BlockRead     string  `json:"block_read"`
	BlockWrite    string  `json:"block_write"`
	PIDs          int     `json:"pids"`
	Uptime        string  `json:"uptime,omitempty"`
}

type WSMetricsMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type HistoryResponse struct {
	Type       string           `json:"type"`
	Timestamps []string         `json:"timestamps"`
	Series     map[string][]float64 `json:"series"`
}

// ============================================================================
// Formatting helpers
// ============================================================================

func formatHostStats(h *workers.HostMetrics) HostStatsData {
	if h == nil {
		return HostStatsData{}
	}
	return HostStatsData{
		CPUPercent:        round2(h.CPUUsagePercent),
		MemoryUsed:        metricspkg.FormatBytes(h.MemoryUsed),
		MemoryTotal:       metricspkg.FormatBytes(h.MemoryTotal),
		MemoryPercent:     round2(h.MemoryPercent),
		DiskUsed:          metricspkg.FormatBytes(h.DiskUsed),
		DiskTotal:         metricspkg.FormatBytes(h.DiskTotal),
		DiskPercent:       round2(h.DiskPercent),
		NetworkRx:         metricspkg.FormatBytes(h.NetworkRxBytes),
		NetworkTx:         metricspkg.FormatBytes(h.NetworkTxBytes),
		ContainersRunning: h.ContainersRunning,
		ContainersTotal:   h.ContainersTotal,
		ContainersStopped: h.ContainersStopped,
		ImagesTotal:       h.ImagesTotal,
		VolumesTotal:      h.VolumesTotal,
	}
}

func formatContainerStats(cms []*workers.ContainerMetrics) []ContainerStatsData {
	result := make([]ContainerStatsData, 0, len(cms))
	for _, cm := range cms {
		if cm == nil {
			continue
		}
		result = append(result, ContainerStatsData{
			ID:            cm.ContainerID,
			Name:          cm.ContainerName,
			State:         cm.State,
			Health:        cm.Health,
			CPUPercent:    round2(cm.CPUUsagePercent),
			MemoryUsed:    metricspkg.FormatBytes(cm.MemoryUsed),
			MemoryLimit:   metricspkg.FormatBytes(cm.MemoryLimit),
			MemoryPercent: round2(cm.MemoryPercent),
			NetworkRx:     metricspkg.FormatBytes(cm.NetworkRxBytes),
			NetworkTx:     metricspkg.FormatBytes(cm.NetworkTxBytes),
			BlockRead:     metricspkg.FormatBytes(cm.BlockRead),
			BlockWrite:    metricspkg.FormatBytes(cm.BlockWrite),
			PIDs:          cm.PIDs,
			Uptime:        metricspkg.FormatUptime(cm.Uptime),
		})
	}
	return result
}

func formatHistoryResponse(metricType string, snapshots []*models.MetricsSnapshot) HistoryResponse {
	resp := HistoryResponse{
		Type:       metricType,
		Timestamps: make([]string, 0, len(snapshots)),
		Series:     make(map[string][]float64),
	}

	for _, s := range snapshots {
		resp.Timestamps = append(resp.Timestamps, s.CollectedAt.UTC().Format(time.RFC3339))

		appendSeries(resp.Series, "cpu_percent", s.CPUPercent)
		appendSeries(resp.Series, "memory_percent", s.MemoryPercent)

		if metricType == "host" {
			appendSeries(resp.Series, "disk_percent", s.DiskPercent)
			appendSeriesI64(resp.Series, "network_rx", s.NetworkRxBytes)
			appendSeriesI64(resp.Series, "network_tx", s.NetworkTxBytes)
		} else {
			appendSeriesI64(resp.Series, "memory_used", s.MemoryUsed)
			appendSeriesI64(resp.Series, "network_rx", s.NetworkRxBytes)
			appendSeriesI64(resp.Series, "network_tx", s.NetworkTxBytes)
			appendSeriesI64(resp.Series, "block_read", s.BlockRead)
			appendSeriesI64(resp.Series, "block_write", s.BlockWrite)
		}
	}

	return resp
}

func appendSeries(m map[string][]float64, key string, v *float64) {
	val := 0.0
	if v != nil {
		val = *v
	}
	m[key] = append(m[key], val)
}

func appendSeriesI64(m map[string][]float64, key string, v *int64) {
	val := 0.0
	if v != nil {
		val = float64(*v)
	}
	m[key] = append(m[key], val)
}

// parseTimeRange converts range strings like "1h", "6h", "24h", "7d" into from/to times.
func parseTimeRange(rangeStr string) (from, to time.Time) {
	to = time.Now()
	switch rangeStr {
	case "1h":
		from = to.Add(-1 * time.Hour)
	case "6h":
		from = to.Add(-6 * time.Hour)
	case "24h":
		from = to.Add(-24 * time.Hour)
	case "7d":
		from = to.AddDate(0, 0, -7)
	case "30d":
		from = to.AddDate(0, 0, -30)
	default:
		from = to.Add(-1 * time.Hour)
	}
	return from, to
}

// inferInterval selects an appropriate aggregation interval for the given range.
func inferInterval(rangeStr string) string {
	switch rangeStr {
	case "1h":
		return "1m"
	case "6h":
		return "5m"
	case "24h":
		return "15m"
	case "7d":
		return "1h"
	case "30d":
		return "1d"
	default:
		return "1m"
	}
}

func round2(v float64) float64 {
	return float64(int(v*100)) / 100
}

// renderJSON writes a JSON response.
func (h *Handler) renderJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// renderJSONError writes a JSON error response.
func (h *Handler) renderJSONError(w http.ResponseWriter, status int, msg string) {
	h.renderJSON(w, status, map[string]string{"error": msg})
}
