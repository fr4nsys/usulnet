// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"context"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// SystemHandler handles system-related endpoints.
type SystemHandler struct {
	BaseHandler
	version        string
	commit         string
	buildTime      string
	startedAt      time.Time
	healthCheckers map[string]HealthChecker
	mu             sync.RWMutex
}

// HealthChecker is a function that checks the health of a component.
type HealthChecker func(ctx context.Context) *HealthStatus

// NewSystemHandler creates a new system handler.
func NewSystemHandler(version, commit, buildTime string, log *logger.Logger) *SystemHandler {
	return &SystemHandler{
		BaseHandler:    NewBaseHandler(log),
		version:        version,
		commit:         commit,
		buildTime:      buildTime,
		startedAt:      time.Now(),
		healthCheckers: make(map[string]HealthChecker),
	}
}

// RegisterHealthChecker registers a health checker for a component.
func (h *SystemHandler) RegisterHealthChecker(name string, checker HealthChecker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.healthCheckers[name] = checker
}

// Routes returns the system routes.
func (h *SystemHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/health", h.Health)
	r.Get("/health/live", h.Liveness)
	r.Get("/health/ready", h.Readiness)
	r.Get("/version", h.Version)
	r.Get("/info", h.Info)
	r.Get("/metrics", h.Metrics)

	return r
}

// ============================================================================
// Response types
// ============================================================================

// HealthResponse represents the health check response.
type HealthResponse struct {
	Status     string                   `json:"status"`
	Version    string                   `json:"version"`
	Uptime     int64                    `json:"uptime_seconds"`
	Components map[string]*HealthStatus `json:"components,omitempty"`
}

// HealthStatus represents the health status of a component.
type HealthStatus struct {
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	Latency   int64  `json:"latency_ms,omitempty"`
	CheckedAt string `json:"checked_at,omitempty"`
}

// VersionResponse represents version information.
type VersionResponse struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	BuildTime string `json:"build_time,omitempty"`
	GoVersion string `json:"go_version"`
}

// SystemInfoResponse represents system information.
type SystemInfoResponse struct {
	Version     string         `json:"version"`
	Commit      string         `json:"commit,omitempty"`
	BuildTime   string         `json:"build_time,omitempty"`
	GoVersion   string         `json:"go_version"`
	OS          string         `json:"os"`
	Arch        string         `json:"arch"`
	NumCPU      int            `json:"num_cpu"`
	NumGoroutine int           `json:"num_goroutine"`
	Uptime      int64          `json:"uptime_seconds"`
	StartedAt   string         `json:"started_at"`
	Memory      *MemoryInfo    `json:"memory"`
}

// MemoryInfo represents memory statistics.
type MemoryInfo struct {
	Alloc      uint64 `json:"alloc_bytes"`
	TotalAlloc uint64 `json:"total_alloc_bytes"`
	Sys        uint64 `json:"sys_bytes"`
	NumGC      uint32 `json:"num_gc"`
}

// MetricsResponse represents basic metrics.
type MetricsResponse struct {
	Uptime        int64  `json:"uptime_seconds"`
	NumGoroutine  int    `json:"num_goroutine"`
	MemoryAlloc   uint64 `json:"memory_alloc_bytes"`
	MemorySys     uint64 `json:"memory_sys_bytes"`
	NumGC         uint32 `json:"num_gc"`
	NumCPU        int    `json:"num_cpu"`
}

// ============================================================================
// Handlers
// ============================================================================

// Health handles GET /api/v1/system/health
// Returns the health status of all components.
func (h *SystemHandler) Health(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	health := &HealthResponse{
		Status:     "healthy",
		Version:    h.version,
		Uptime:     int64(time.Since(h.startedAt).Seconds()),
		Components: make(map[string]*HealthStatus),
	}

	h.mu.RLock()
	checkers := make(map[string]HealthChecker, len(h.healthCheckers))
	for name, checker := range h.healthCheckers {
		checkers[name] = checker
	}
	h.mu.RUnlock()

	// Run health checks with timeout
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var mu sync.Mutex

	for name, checker := range checkers {
		wg.Add(1)
		go func(name string, checker HealthChecker) {
			defer wg.Done()

			start := time.Now()
			status := checker(checkCtx)
			if status == nil {
				status = &HealthStatus{
					Status: "unknown",
				}
			}
			status.Latency = time.Since(start).Milliseconds()
			status.CheckedAt = time.Now().UTC().Format(time.RFC3339)

			mu.Lock()
			health.Components[name] = status
			mu.Unlock()
		}(name, checker)
	}

	wg.Wait()

	// Determine overall status
	for _, status := range health.Components {
		switch status.Status {
		case "unhealthy":
			health.Status = "unhealthy"
		case "degraded":
			if health.Status != "unhealthy" {
				health.Status = "degraded"
			}
		}
	}

	// Set appropriate status code
	statusCode := http.StatusOK
	if health.Status == "unhealthy" {
		statusCode = http.StatusServiceUnavailable
	} else if health.Status == "degraded" {
		statusCode = http.StatusOK // Still return 200 for degraded
	}

	h.JSON(w, statusCode, health)
}

// Liveness handles GET /api/v1/system/health/live
// Returns 200 if the service is alive.
func (h *SystemHandler) Liveness(w http.ResponseWriter, r *http.Request) {
	h.OK(w, map[string]string{"status": "alive"})
}

// Readiness handles GET /api/v1/system/health/ready
// Returns 200 if the service is ready to accept traffic.
func (h *SystemHandler) Readiness(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.mu.RLock()
	checkers := make(map[string]HealthChecker, len(h.healthCheckers))
	for name, checker := range h.healthCheckers {
		checkers[name] = checker
	}
	h.mu.RUnlock()

	// Check critical components
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	ready := true
	for name, checker := range checkers {
		status := checker(checkCtx)
		if status != nil && status.Status == "unhealthy" {
			h.logger.Warn("readiness check failed", "component", name, "status", status.Status)
			ready = false
			break
		}
	}

	if ready {
		h.OK(w, map[string]string{"status": "ready"})
	} else {
		h.JSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
	}
}

// Version handles GET /api/v1/system/version
// Returns version information.
func (h *SystemHandler) Version(w http.ResponseWriter, r *http.Request) {
	h.OK(w, VersionResponse{
		Version:   h.version,
		Commit:    h.commit,
		BuildTime: h.buildTime,
		GoVersion: runtime.Version(),
	})
}

// Info handles GET /api/v1/system/info
// Returns detailed system information.
func (h *SystemHandler) Info(w http.ResponseWriter, r *http.Request) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	h.OK(w, SystemInfoResponse{
		Version:      h.version,
		Commit:       h.commit,
		BuildTime:    h.buildTime,
		GoVersion:    runtime.Version(),
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		NumCPU:       runtime.NumCPU(),
		NumGoroutine: runtime.NumGoroutine(),
		Uptime:       int64(time.Since(h.startedAt).Seconds()),
		StartedAt:    h.startedAt.UTC().Format(time.RFC3339),
		Memory: &MemoryInfo{
			Alloc:      memStats.Alloc,
			TotalAlloc: memStats.TotalAlloc,
			Sys:        memStats.Sys,
			NumGC:      memStats.NumGC,
		},
	})
}

// Metrics handles GET /api/v1/system/metrics
// Returns basic metrics in JSON format.
func (h *SystemHandler) Metrics(w http.ResponseWriter, r *http.Request) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	h.OK(w, MetricsResponse{
		Uptime:       int64(time.Since(h.startedAt).Seconds()),
		NumGoroutine: runtime.NumGoroutine(),
		MemoryAlloc:  memStats.Alloc,
		MemorySys:    memStats.Sys,
		NumGC:        memStats.NumGC,
		NumCPU:       runtime.NumCPU(),
	})
}

// ============================================================================
// Health Checker Helpers
// ============================================================================

// DatabaseHealthChecker creates a health checker for database connections.
func DatabaseHealthChecker(pingFn func(ctx context.Context) error) HealthChecker {
	return func(ctx context.Context) *HealthStatus {
		start := time.Now()
		err := pingFn(ctx)
		latency := time.Since(start).Milliseconds()

		if err != nil {
			return &HealthStatus{
				Status:    "unhealthy",
				Message:   err.Error(),
				Latency:   latency,
				CheckedAt: time.Now().UTC().Format(time.RFC3339),
			}
		}
		return &HealthStatus{
			Status:    "healthy",
			Latency:   latency,
			CheckedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}
}

// RedisHealthChecker creates a health checker for Redis connections.
func RedisHealthChecker(pingFn func(ctx context.Context) error) HealthChecker {
	return DatabaseHealthChecker(pingFn) // Same logic
}

// DockerHealthChecker creates a health checker for Docker connections.
func DockerHealthChecker(pingFn func(ctx context.Context) error) HealthChecker {
	return DatabaseHealthChecker(pingFn) // Same logic
}

// NATSHealthChecker creates a health checker for NATS connections.
func NATSHealthChecker(isConnectedFn func() bool) HealthChecker {
	return func(ctx context.Context) *HealthStatus {
		if isConnectedFn() {
			return &HealthStatus{
				Status:    "healthy",
				CheckedAt: time.Now().UTC().Format(time.RFC3339),
			}
		}
		return &HealthStatus{
			Status:    "unhealthy",
			Message:   "not connected",
			CheckedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}
}
