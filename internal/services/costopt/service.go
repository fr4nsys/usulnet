// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package costopt

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Repository defines the persistence interface for resource usage and optimization data.
type Repository interface {
	CreateSample(ctx context.Context, s *models.ResourceUsageSample) error
	CreateSamples(ctx context.Context, samples []*models.ResourceUsageSample) error
	GetContainerUsageSummary(ctx context.Context, containerID string, since time.Time) (*models.ContainerUsageSummary, error)
	ListContainerSummaries(ctx context.Context, since time.Time, limit int) ([]*models.ContainerUsageSummary, error)
	UpsertHourly(ctx context.Context, h *models.ResourceUsageHourly) error
	UpsertDaily(ctx context.Context, d *models.ResourceUsageDaily) error
	GetHourlyUsage(ctx context.Context, containerID string, since time.Time) ([]*models.ResourceUsageHourly, error)
	GetDailyUsage(ctx context.Context, containerID string, since time.Time) ([]*models.ResourceUsageDaily, error)
	CreateRecommendation(ctx context.Context, r *models.ResourceRecommendation) error
	ListRecommendations(ctx context.Context, opts models.RecommendationListOptions) ([]*models.ResourceRecommendation, int, error)
	ResolveRecommendation(ctx context.Context, id uuid.UUID, status string, resolvedBy *uuid.UUID) error
	GetOptStats(ctx context.Context) (*models.ResourceOptStats, error)
	DeleteOldSamples(ctx context.Context, before time.Time) (int64, error)
	ClearOpenRecommendations(ctx context.Context) error
}

// Service handles resource usage tracking and cost optimization recommendations.
type Service struct {
	repo   Repository
	logger *logger.Logger
}

// NewService creates a new cost optimization service.
func NewService(repo Repository, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		repo:   repo,
		logger: log.Named("costopt"),
	}
}

// RecordSample persists a single resource usage sample.
func (s *Service) RecordSample(ctx context.Context, sample *models.ResourceUsageSample) error {
	if err := s.repo.CreateSample(ctx, sample); err != nil {
		return fmt.Errorf("recording usage sample: %w", err)
	}
	return nil
}

// RecordSamples persists multiple resource usage samples in bulk.
func (s *Service) RecordSamples(ctx context.Context, samples []*models.ResourceUsageSample) error {
	if err := s.repo.CreateSamples(ctx, samples); err != nil {
		return fmt.Errorf("recording usage samples: %w", err)
	}
	return nil
}

// GetContainerUsage returns a usage summary for a single container over the given number of days.
func (s *Service) GetContainerUsage(ctx context.Context, containerID string, days int) (*models.ContainerUsageSummary, error) {
	since := time.Now().AddDate(0, 0, -days)
	return s.repo.GetContainerUsageSummary(ctx, containerID, since)
}

// ListContainerSummaries returns usage summaries for all containers over the given number of days.
func (s *Service) ListContainerSummaries(ctx context.Context, days, limit int) ([]*models.ContainerUsageSummary, error) {
	since := time.Now().AddDate(0, 0, -days)
	return s.repo.ListContainerSummaries(ctx, since, limit)
}

// GetHourlyUsage returns hourly aggregated usage for a container over the given number of hours.
func (s *Service) GetHourlyUsage(ctx context.Context, containerID string, hours int) ([]*models.ResourceUsageHourly, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	return s.repo.GetHourlyUsage(ctx, containerID, since)
}

// GetDailyUsage returns daily aggregated usage for a container over the given number of days.
func (s *Service) GetDailyUsage(ctx context.Context, containerID string, days int) ([]*models.ResourceUsageDaily, error) {
	since := time.Now().AddDate(0, 0, -days)
	return s.repo.GetDailyUsage(ctx, containerID, since)
}

// GenerateRecommendations analyzes container usage summaries and creates rightsizing recommendations.
// It clears existing open recommendations before generating new ones. Returns the count of created recommendations.
func (s *Service) GenerateRecommendations(ctx context.Context, summaries []*models.ContainerUsageSummary) (int, error) {
	if err := s.repo.ClearOpenRecommendations(ctx); err != nil {
		return 0, fmt.Errorf("clearing open recommendations: %w", err)
	}

	count := 0
	for _, summary := range summaries {
		// Check for oversized memory (using less than 30% of limit)
		if summary.MemoryLimit > 0 && summary.MemoryAvg > 0 && float64(summary.MemoryAvg)/float64(summary.MemoryLimit) < 0.3 {
			rec := &models.ResourceRecommendation{
				ContainerID:      summary.ContainerID,
				ContainerName:    summary.ContainerName,
				Type:             models.RecommendDownsizeMemory,
				Severity:         "warning",
				Reason:           "memory usage is below 30% of limit",
				CurrentValue:     formatBytes(summary.MemoryLimit),
				RecommendedValue: formatBytes(summary.MemoryLimit / 2),
			}
			if err := s.repo.CreateRecommendation(ctx, rec); err != nil {
				s.logger.Error("failed to create memory downsize recommendation",
					"container_id", summary.ContainerID,
					"error", err,
				)
				continue
			}
			count++
		}

		// Check for low CPU usage
		if summary.CPUAvg < 10 && summary.CPUPeak < 30 {
			rec := &models.ResourceRecommendation{
				ContainerID:   summary.ContainerID,
				ContainerName: summary.ContainerName,
				Type:          models.RecommendDownsizeCPU,
				Severity:      "info",
				Reason:        "avg CPU usage below 10%",
			}
			if err := s.repo.CreateRecommendation(ctx, rec); err != nil {
				s.logger.Error("failed to create CPU downsize recommendation",
					"container_id", summary.ContainerID,
					"error", err,
				)
				continue
			}
			count++
		}

		// Check for idle containers
		if summary.CPUAvg < 1 && summary.CPUPeak < 5 && time.Since(summary.LastSeen) > 7*24*time.Hour {
			rec := &models.ResourceRecommendation{
				ContainerID:   summary.ContainerID,
				ContainerName: summary.ContainerName,
				Type:          models.RecommendRemoveIdle,
				Severity:      "warning",
				Reason:        "no significant activity for 7+ days",
			}
			if err := s.repo.CreateRecommendation(ctx, rec); err != nil {
				s.logger.Error("failed to create idle removal recommendation",
					"container_id", summary.ContainerID,
					"error", err,
				)
				continue
			}
			count++
		}

		// Check for missing memory limits
		if summary.MemoryLimit == 0 {
			rec := &models.ResourceRecommendation{
				ContainerID:   summary.ContainerID,
				ContainerName: summary.ContainerName,
				Type:          models.RecommendAddLimit,
				Severity:      "info",
				Reason:        "no memory limit set",
			}
			if err := s.repo.CreateRecommendation(ctx, rec); err != nil {
				s.logger.Error("failed to create add-limit recommendation",
					"container_id", summary.ContainerID,
					"error", err,
				)
				continue
			}
			count++
		}
	}

	s.logger.Info("recommendations generated", "count", count, "containers_analyzed", len(summaries))
	return count, nil
}

// ListRecommendations returns recommendations with filtering and pagination.
func (s *Service) ListRecommendations(ctx context.Context, opts models.RecommendationListOptions) ([]*models.ResourceRecommendation, int, error) {
	return s.repo.ListRecommendations(ctx, opts)
}

// ApplyRecommendation marks a recommendation as applied by the given user.
func (s *Service) ApplyRecommendation(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	if err := s.repo.ResolveRecommendation(ctx, id, "applied", userID); err != nil {
		return fmt.Errorf("applying recommendation: %w", err)
	}
	return nil
}

// DismissRecommendation marks a recommendation as dismissed by the given user.
func (s *Service) DismissRecommendation(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	if err := s.repo.ResolveRecommendation(ctx, id, "dismissed", userID); err != nil {
		return fmt.Errorf("dismissing recommendation: %w", err)
	}
	return nil
}

// GetStats returns aggregated optimization statistics.
func (s *Service) GetStats(ctx context.Context) (*models.ResourceOptStats, error) {
	return s.repo.GetOptStats(ctx)
}

// CleanupOldSamples deletes usage samples older than the given retention period.
func (s *Service) CleanupOldSamples(ctx context.Context, retentionDays int) (int64, error) {
	before := time.Now().AddDate(0, 0, -retentionDays)
	deleted, err := s.repo.DeleteOldSamples(ctx, before)
	if err != nil {
		return 0, fmt.Errorf("cleaning up old samples: %w", err)
	}
	return deleted, nil
}

// formatBytes converts a byte count to a human-readable string.
func formatBytes(bytes int64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
	)

	switch {
	case bytes >= gb:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(gb))
	case bytes >= mb:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(mb))
	case bytes >= kb:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(kb))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
