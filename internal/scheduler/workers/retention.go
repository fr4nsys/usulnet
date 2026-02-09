// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package workers

import (
	"context"
	"fmt"
	"time"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// RetentionService interface for database retention operations.
// Each method calls the corresponding PostgreSQL function and returns rows deleted.
type RetentionService interface {
	CleanupOldMetrics(ctx context.Context, retentionDays int) (int64, error)
	CleanupOldContainerStats(ctx context.Context, retentionDays int) (int64, error)
	CleanupOldHostMetrics(ctx context.Context, retentionDays int) (int64, error)
	CleanupOldAuditLog(ctx context.Context, retentionDays int) (int64, error)
	CleanupOldJobEvents(ctx context.Context, retentionDays int) (int64, error)
	CleanupOldNotificationLogs(ctx context.Context, retentionDays int) (int64, error)
	CleanupExpiredSessions(ctx context.Context) (int64, error)
	CleanupExpiredPasswordResetTokens(ctx context.Context) (int64, error)
}

// RetentionWorker handles database retention cleanup jobs
type RetentionWorker struct {
	BaseWorker
	retentionService RetentionService
	logger           *logger.Logger
}

// RetentionPayload represents payload for retention job
type RetentionPayload struct {
	// Override default retention days per table (0 = use SQL function default)
	MetricsDays          int `json:"metrics_days,omitempty"`
	ContainerStatsDays   int `json:"container_stats_days,omitempty"`
	HostMetricsDays      int `json:"host_metrics_days,omitempty"`
	AuditLogDays         int `json:"audit_log_days,omitempty"`
	JobEventsDays        int `json:"job_events_days,omitempty"`
	NotificationLogsDays int `json:"notification_logs_days,omitempty"`
}

// RetentionResult holds the result of a retention cleanup
type RetentionResult struct {
	StartedAt   time.Time                  `json:"started_at"`
	CompletedAt time.Time                  `json:"completed_at"`
	Duration    time.Duration              `json:"duration"`
	Tables      map[string]RetentionDetail `json:"tables"`
	TotalRows   int64                      `json:"total_rows_deleted"`
	Errors      []string                   `json:"errors,omitempty"`
}

// RetentionDetail holds per-table cleanup results
type RetentionDetail struct {
	RowsDeleted   int64 `json:"rows_deleted"`
	RetentionDays int   `json:"retention_days"`
}

// NewRetentionWorker creates a new retention worker
func NewRetentionWorker(retentionService RetentionService, log *logger.Logger) *RetentionWorker {
	if log == nil {
		log = logger.Nop()
	}

	return &RetentionWorker{
		BaseWorker:       NewBaseWorker(models.JobTypeRetention),
		retentionService: retentionService,
		logger:           log.Named("retention-worker"),
	}
}

// Execute performs the retention cleanup job
func (w *RetentionWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	log := w.logger.With("job_id", job.ID)

	var payload RetentionPayload
	if err := job.GetPayload(&payload); err != nil {
		// Payload is optional; use defaults
		log.Debug("no payload, using default retention days")
	}

	log.Info("starting database retention cleanup")

	result := &RetentionResult{
		StartedAt: time.Now(),
		Tables:    make(map[string]RetentionDetail),
	}

	// Define cleanup tasks with their default retention days
	type cleanupTask struct {
		name          string
		retentionDays int
		defaultDays   int
		fn            func(ctx context.Context, days int) (int64, error)
	}

	tasks := []cleanupTask{
		{"metrics_snapshots", payload.MetricsDays, 30, w.retentionService.CleanupOldMetrics},
		{"container_stats", payload.ContainerStatsDays, 7, w.retentionService.CleanupOldContainerStats},
		{"host_metrics", payload.HostMetricsDays, 30, w.retentionService.CleanupOldHostMetrics},
		{"audit_log", payload.AuditLogDays, 90, w.retentionService.CleanupOldAuditLog},
		{"job_events", payload.JobEventsDays, 7, w.retentionService.CleanupOldJobEvents},
		{"notification_logs", payload.NotificationLogsDays, 30, w.retentionService.CleanupOldNotificationLogs},
	}

	for i, task := range tasks {
		if ctx.Err() != nil {
			return nil, errors.Wrap(ctx.Err(), errors.CodeInternal, "retention cancelled")
		}

		days := task.defaultDays
		if task.retentionDays > 0 {
			days = task.retentionDays
		}

		deleted, err := task.fn(ctx, days)
		if err != nil {
			errMsg := fmt.Sprintf("%s: %v", task.name, err)
			result.Errors = append(result.Errors, errMsg)
			log.Warn("retention cleanup failed for table", "table", task.name, "error", err)
		} else {
			result.Tables[task.name] = RetentionDetail{
				RowsDeleted:   deleted,
				RetentionDays: days,
			}
			result.TotalRows += deleted
			if deleted > 0 {
				log.Info("cleaned up old rows",
					"table", task.name,
					"rows_deleted", deleted,
					"retention_days", days,
				)
			}
		}

		// Report progress
		progress := ((i + 1) * 80) / len(tasks)
		msg := fmt.Sprintf("Cleaned %s (%d rows)", task.name, deleted)
		job.Progress = progress
		job.ProgressMessage = &msg
	}

	// Cleanup expired sessions and tokens (no retention days parameter)
	if deleted, err := w.retentionService.CleanupExpiredSessions(ctx); err != nil {
		result.Errors = append(result.Errors, "expired_sessions: "+err.Error())
	} else {
		result.Tables["expired_sessions"] = RetentionDetail{RowsDeleted: deleted}
		result.TotalRows += deleted
	}

	if deleted, err := w.retentionService.CleanupExpiredPasswordResetTokens(ctx); err != nil {
		result.Errors = append(result.Errors, "expired_tokens: "+err.Error())
	} else {
		result.Tables["expired_password_reset_tokens"] = RetentionDetail{RowsDeleted: deleted}
		result.TotalRows += deleted
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)

	log.Info("retention cleanup completed",
		"total_rows_deleted", result.TotalRows,
		"tables_cleaned", len(result.Tables),
		"duration", result.Duration,
	)

	return result, nil
}
