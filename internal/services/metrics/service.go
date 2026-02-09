// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package metrics

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
)

// Service implements metrics collection, storage, and querying.
// Satisfies workers.MetricsService for the scheduler worker
// and the extended interface for web handlers.
type Service struct {
	repo      *postgres.MetricsRepository
	collector *Collector
	logger    *logger.Logger

	// Cache of latest snapshot per host to avoid DB reads for Prometheus.
	mu            sync.RWMutex
	latestHost    map[uuid.UUID]*workers.HostMetrics
	latestContainers map[uuid.UUID][]*workers.ContainerMetrics
}

// NewService creates a new metrics service.
func NewService(
	repo *postgres.MetricsRepository,
	collector *Collector,
	log *logger.Logger,
) *Service {
	return &Service{
		repo:             repo,
		collector:        collector,
		logger:           log.Named("metrics-service"),
		latestHost:       make(map[uuid.UUID]*workers.HostMetrics),
		latestContainers: make(map[uuid.UUID][]*workers.ContainerMetrics),
	}
}

// ============================================================================
// workers.MetricsService implementation (used by scheduler worker)
// ============================================================================

// CollectHostMetrics collects system metrics for a host.
func (s *Service) CollectHostMetrics(ctx context.Context, hostID uuid.UUID) (*workers.HostMetrics, error) {
	m, err := s.collector.CollectHostMetrics(ctx, hostID)
	if err != nil {
		return nil, err
	}

	// Cache latest
	s.mu.Lock()
	s.latestHost[hostID] = m
	s.mu.Unlock()

	return m, nil
}

// CollectContainerMetrics collects metrics for all containers on a host.
func (s *Service) CollectContainerMetrics(ctx context.Context, hostID uuid.UUID) ([]*workers.ContainerMetrics, error) {
	cms, err := s.collector.CollectContainerMetrics(ctx, hostID)
	if err != nil {
		return nil, err
	}

	// Cache latest
	s.mu.Lock()
	s.latestContainers[hostID] = cms
	s.mu.Unlock()

	return cms, nil
}

// StoreMetrics persists a complete metrics snapshot.
func (s *Service) StoreMetrics(ctx context.Context, snapshot *workers.MetricsSnapshot) error {
	var dbSnapshots []*models.MetricsSnapshot

	// Host snapshot
	if snapshot.Host != nil {
		dbSnapshots = append(dbSnapshots, hostMetricsToModel(snapshot.HostID, snapshot.Host, snapshot.CollectedAt))
	}

	// Container snapshots
	for _, cm := range snapshot.Containers {
		dbSnapshots = append(dbSnapshots, containerMetricsToModel(snapshot.HostID, cm, snapshot.CollectedAt))
	}

	if len(dbSnapshots) == 0 {
		return nil
	}

	return s.repo.InsertBatch(ctx, dbSnapshots)
}

// ============================================================================
// Extended methods (for web handlers)
// ============================================================================

// GetHostHistory returns aggregated host metrics for chart rendering.
func (s *Service) GetHostHistory(ctx context.Context, hostID uuid.UUID, from, to time.Time, interval string) ([]*models.MetricsSnapshot, error) {
	return s.repo.GetHostHistory(ctx, hostID, from, to, interval)
}

// GetContainerHistory returns aggregated container metrics for charts.
func (s *Service) GetContainerHistory(ctx context.Context, containerID string, from, to time.Time, interval string) ([]*models.MetricsSnapshot, error) {
	return s.repo.GetContainerHistory(ctx, containerID, from, to, interval)
}

// GetCurrentHostMetrics returns live host metrics (collect, don't store).
func (s *Service) GetCurrentHostMetrics(ctx context.Context, hostID uuid.UUID) (*workers.HostMetrics, error) {
	// Try cache first (less than 10s old)
	s.mu.RLock()
	cached, ok := s.latestHost[hostID]
	s.mu.RUnlock()
	if ok && cached != nil && time.Since(cached.CollectedAt) < 10*time.Second {
		return cached, nil
	}

	return s.CollectHostMetrics(ctx, hostID)
}

// GetCurrentContainerMetrics returns live container metrics.
func (s *Service) GetCurrentContainerMetrics(ctx context.Context, hostID uuid.UUID) ([]*workers.ContainerMetrics, error) {
	s.mu.RLock()
	cached, ok := s.latestContainers[hostID]
	s.mu.RUnlock()
	if ok && len(cached) > 0 && time.Since(cached[0].CollectedAt) < 10*time.Second {
		return cached, nil
	}

	return s.CollectContainerMetrics(ctx, hostID)
}

// GetLatestStoredHost returns the most recent stored host metrics from DB.
func (s *Service) GetLatestStoredHost(ctx context.Context, hostID uuid.UUID) (*models.MetricsSnapshot, error) {
	return s.repo.GetLatestHost(ctx, hostID)
}

// GetLatestStoredContainers returns the most recent stored container metrics from DB.
func (s *Service) GetLatestStoredContainers(ctx context.Context, hostID uuid.UUID) ([]*models.MetricsSnapshot, error) {
	return s.repo.GetLatestContainers(ctx, hostID)
}

// CleanupOldMetrics deletes metrics older than retentionDays.
func (s *Service) CleanupOldMetrics(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays < 1 {
		retentionDays = 30 // default 30 days
	}
	deleted, err := s.repo.CleanupOldMetrics(ctx, retentionDays)
	if err != nil {
		return 0, err
	}
	if deleted > 0 {
		s.logger.Info("metrics cleanup completed", "deleted", deleted, "retention_days", retentionDays)
	}
	return deleted, nil
}

// GetPrometheusMetrics returns metrics in Prometheus text exposition format.
func (s *Service) GetPrometheusMetrics(ctx context.Context) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return FormatPrometheus(s.latestHost, s.latestContainers), nil
}

// ============================================================================
// Conversions: workers types → DB models
// ============================================================================

func hostMetricsToModel(hostID uuid.UUID, h *workers.HostMetrics, collectedAt time.Time) *models.MetricsSnapshot {
	if collectedAt.IsZero() {
		collectedAt = h.CollectedAt
	}
	return &models.MetricsSnapshot{
		ID:                uuid.New(),
		HostID:            hostID,
		MetricType:        models.MetricTypeHost,
		CPUPercent:        ptr(h.CPUUsagePercent),
		MemoryUsed:        ptrI64(h.MemoryUsed),
		MemoryTotal:       ptrI64(h.MemoryTotal),
		MemoryPercent:     ptr(h.MemoryPercent),
		NetworkRxBytes:    ptrI64(h.NetworkRxBytes),
		NetworkTxBytes:    ptrI64(h.NetworkTxBytes),
		DiskUsed:          ptrI64(h.DiskUsed),
		DiskTotal:         ptrI64(h.DiskTotal),
		DiskPercent:       ptr(h.DiskPercent),
		ContainersTotal:   ptrInt(h.ContainersTotal),
		ContainersRunning: ptrInt(h.ContainersRunning),
		ContainersStopped: ptrInt(h.ContainersStopped),
		ImagesTotal:       ptrInt(h.ImagesTotal),
		VolumesTotal:      ptrInt(h.VolumesTotal),
		CollectedAt:       collectedAt,
	}
}

func containerMetricsToModel(hostID uuid.UUID, cm *workers.ContainerMetrics, collectedAt time.Time) *models.MetricsSnapshot {
	if collectedAt.IsZero() {
		collectedAt = cm.CollectedAt
	}
	return &models.MetricsSnapshot{
		ID:             uuid.New(),
		HostID:         hostID,
		MetricType:     models.MetricTypeContainer,
		ContainerID:    ptrStr(cm.ContainerID),
		ContainerName:  ptrStr(cm.ContainerName),
		CPUPercent:     ptr(cm.CPUUsagePercent),
		MemoryUsed:     ptrI64(cm.MemoryUsed),
		MemoryTotal:    ptrI64(cm.MemoryLimit),
		MemoryPercent:  ptr(cm.MemoryPercent),
		NetworkRxBytes: ptrI64(cm.NetworkRxBytes),
		NetworkTxBytes: ptrI64(cm.NetworkTxBytes),
		BlockRead:      ptrI64(cm.BlockRead),
		BlockWrite:     ptrI64(cm.BlockWrite),
		PIDs:           ptrInt(cm.PIDs),
		State:          ptrStr(cm.State),
		Health:         ptrStr(cm.Health),
		UptimeSeconds:  ptrI64(cm.Uptime),
		CollectedAt:    collectedAt,
	}
}

// ============================================================================
// Helpers
// ============================================================================

// FormatBytes converts bytes to human-readable string.
func FormatBytes(b int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)
	switch {
	case b >= TB:
		return fmt.Sprintf("%.1f TB", float64(b)/float64(TB))
	case b >= GB:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// FormatUptime converts seconds to human-readable duration.
func FormatUptime(seconds int64) string {
	d := time.Duration(seconds) * time.Second
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}

func ptr(v float64) *float64 { return &v }
func ptrI64(v int64) *int64  { return &v }
func ptrInt(v int) *int      { return &v }
func ptrStr(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
