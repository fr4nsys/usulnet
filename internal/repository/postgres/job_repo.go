// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
)

// JobRepository handles job persistence in PostgreSQL
type JobRepository struct {
	db *DB
}

// NewJobRepository creates a new job repository
func NewJobRepository(db *DB) *JobRepository {
	return &JobRepository{db: db}
}

// ============================================================================
// Job CRUD Operations
// ============================================================================

// Create creates a new job
func (r *JobRepository) Create(ctx context.Context, job *models.Job) error {
	query := `
		INSERT INTO jobs (
			id, type, status, priority, host_id, target_id, target_name,
			payload, result, error_message, progress, progress_message,
			attempts, max_attempts, scheduled_at, started_at, completed_at,
			created_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
			$15, $16, $17, $18, $19, $20
		)
	`

	_, err := r.db.Pool().Exec(ctx, query,
		job.ID,
		job.Type,
		job.Status,
		job.Priority,
		job.HostID,
		job.TargetID,
		job.TargetName,
		job.Payload,
		job.Result,
		job.ErrorMessage,
		job.Progress,
		job.ProgressMessage,
		job.Attempts,
		job.MaxAttempts,
		job.ScheduledAt,
		job.StartedAt,
		job.CompletedAt,
		job.CreatedBy,
		job.CreatedAt,
		job.UpdatedAt,
	)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to create job")
	}

	return nil
}

// Get retrieves a job by ID
func (r *JobRepository) Get(ctx context.Context, id uuid.UUID) (*models.Job, error) {
	query := `
		SELECT 
			id, type, status, priority, host_id, target_id, target_name,
			payload, result, error_message, progress, progress_message,
			attempts, max_attempts, scheduled_at, started_at, completed_at,
			created_by, created_at, updated_at
		FROM jobs
		WHERE id = $1
	`

	job := &models.Job{}
	err := r.db.Pool().QueryRow(ctx, query, id).Scan(
		&job.ID,
		&job.Type,
		&job.Status,
		&job.Priority,
		&job.HostID,
		&job.TargetID,
		&job.TargetName,
		&job.Payload,
		&job.Result,
		&job.ErrorMessage,
		&job.Progress,
		&job.ProgressMessage,
		&job.Attempts,
		&job.MaxAttempts,
		&job.ScheduledAt,
		&job.StartedAt,
		&job.CompletedAt,
		&job.CreatedBy,
		&job.CreatedAt,
		&job.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.New(errors.CodeNotFound, "job not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get job")
	}

	return job, nil
}

// Update updates a job
func (r *JobRepository) Update(ctx context.Context, job *models.Job) error {
	query := `
		UPDATE jobs SET
			status = $2,
			progress = $3,
			progress_message = $4,
			result = $5,
			error_message = $6,
			attempts = $7,
			started_at = $8,
			completed_at = $9,
			updated_at = $10
		WHERE id = $1
	`

	job.UpdatedAt = time.Now()

	result, err := r.db.Pool().Exec(ctx, query,
		job.ID,
		job.Status,
		job.Progress,
		job.ProgressMessage,
		job.Result,
		job.ErrorMessage,
		job.Attempts,
		job.StartedAt,
		job.CompletedAt,
		job.UpdatedAt,
	)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to update job")
	}

	if result.RowsAffected() == 0 {
		return errors.New(errors.CodeNotFound, "job not found")
	}

	return nil
}

// Delete deletes a job
func (r *JobRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM jobs WHERE id = $1`

	result, err := r.db.Pool().Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to delete job")
	}

	if result.RowsAffected() == 0 {
		return errors.New(errors.CodeNotFound, "job not found")
	}

	return nil
}

// List retrieves jobs with filtering
func (r *JobRepository) List(ctx context.Context, opts models.JobListOptions) ([]*models.Job, int, error) {
	// Build query
	baseQuery := `
		FROM jobs
		WHERE 1=1
	`
	args := []interface{}{}
	argIdx := 1

	if opts.Type != nil {
		baseQuery += ` AND type = $` + itoa(argIdx)
		args = append(args, *opts.Type)
		argIdx++
	}

	if opts.Status != nil {
		baseQuery += ` AND status = $` + itoa(argIdx)
		args = append(args, *opts.Status)
		argIdx++
	}

	if opts.HostID != nil {
		baseQuery += ` AND host_id = $` + itoa(argIdx)
		args = append(args, *opts.HostID)
		argIdx++
	}

	if opts.TargetID != nil {
		baseQuery += ` AND target_id = $` + itoa(argIdx)
		args = append(args, *opts.TargetID)
		argIdx++
	}

	if opts.Before != nil {
		baseQuery += ` AND created_at < $` + itoa(argIdx)
		args = append(args, *opts.Before)
		argIdx++
	}

	if opts.After != nil {
		baseQuery += ` AND created_at > $` + itoa(argIdx)
		args = append(args, *opts.After)
		argIdx++
	}

	// Get total count
	countQuery := `SELECT COUNT(*) ` + baseQuery
	var total int
	err := r.db.Pool().QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeInternal, "failed to count jobs")
	}

	// Get results
	selectQuery := `
		SELECT 
			id, type, status, priority, host_id, target_id, target_name,
			payload, result, error_message, progress, progress_message,
			attempts, max_attempts, scheduled_at, started_at, completed_at,
			created_by, created_at, updated_at
	` + baseQuery + `
		ORDER BY created_at DESC
	`

	if opts.Limit > 0 {
		selectQuery += ` LIMIT $` + itoa(argIdx)
		args = append(args, opts.Limit)
		argIdx++
	}

	if opts.Offset > 0 {
		selectQuery += ` OFFSET $` + itoa(argIdx)
		args = append(args, opts.Offset)
	}

	rows, err := r.db.Pool().Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeInternal, "failed to list jobs")
	}
	defer rows.Close()

	jobs := make([]*models.Job, 0)
	for rows.Next() {
		job := &models.Job{}
		err := rows.Scan(
			&job.ID,
			&job.Type,
			&job.Status,
			&job.Priority,
			&job.HostID,
			&job.TargetID,
			&job.TargetName,
			&job.Payload,
			&job.Result,
			&job.ErrorMessage,
			&job.Progress,
			&job.ProgressMessage,
			&job.Attempts,
			&job.MaxAttempts,
			&job.ScheduledAt,
			&job.StartedAt,
			&job.CompletedAt,
			&job.CreatedBy,
			&job.CreatedAt,
			&job.UpdatedAt,
		)
		if err != nil {
			return nil, 0, errors.Wrap(err, errors.CodeInternal, "failed to scan job")
		}
		jobs = append(jobs, job)
	}

	return jobs, total, nil
}

// GetStats returns job statistics
func (r *JobRepository) GetStats(ctx context.Context) (*models.JobStats, error) {
	stats := &models.JobStats{
		ByType: make(map[string]int64),
	}

	// Get counts by status
	query := `
		SELECT 
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE status = 'pending') AS pending,
			COUNT(*) FILTER (WHERE status = 'running') AS running,
			COUNT(*) FILTER (WHERE status = 'completed') AS completed,
			COUNT(*) FILTER (WHERE status = 'failed') AS failed
		FROM jobs
	`

	err := r.db.Pool().QueryRow(ctx, query).Scan(
		&stats.TotalJobs,
		&stats.PendingJobs,
		&stats.RunningJobs,
		&stats.CompletedJobs,
		&stats.FailedJobs,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get job stats")
	}

	// Get counts by type
	typeQuery := `
		SELECT type, COUNT(*) 
		FROM jobs 
		GROUP BY type
	`

	rows, err := r.db.Pool().Query(ctx, typeQuery)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get job type stats")
	}
	defer rows.Close()

	for rows.Next() {
		var jobType string
		var count int64
		if err := rows.Scan(&jobType, &count); err != nil {
			continue
		}
		stats.ByType[jobType] = count
	}

	// Calculate success rate
	if stats.CompletedJobs+stats.FailedJobs > 0 {
		stats.SuccessRate = float64(stats.CompletedJobs) / float64(stats.CompletedJobs+stats.FailedJobs)
	}

	// Get average duration
	durationQuery := `
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (completed_at - started_at))), 0)
		FROM jobs
		WHERE status = 'completed' AND started_at IS NOT NULL AND completed_at IS NOT NULL
	`

	var avgSeconds float64
	err = r.db.Pool().QueryRow(ctx, durationQuery).Scan(&avgSeconds)
	if err == nil {
		stats.AvgDuration = time.Duration(avgSeconds * float64(time.Second))
	}

	return stats, nil
}

// ============================================================================
// Scheduled Job Operations
// ============================================================================

// CreateScheduledJob creates a new scheduled job
func (r *JobRepository) CreateScheduledJob(ctx context.Context, job *models.ScheduledJob) error {
	query := `
		INSERT INTO scheduled_jobs (
			id, name, type, schedule, host_id, target_id, target_name,
			payload, priority, max_attempts, is_enabled, last_run_at,
			last_run_status, next_run_at, run_count, fail_count,
			created_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
		)
	`

	_, err := r.db.Pool().Exec(ctx, query,
		job.ID,
		job.Name,
		job.Type,
		job.Schedule,
		job.HostID,
		job.TargetID,
		job.TargetName,
		job.Payload,
		job.Priority,
		job.MaxAttempts,
		job.IsEnabled,
		job.LastRunAt,
		job.LastRunStatus,
		job.NextRunAt,
		job.RunCount,
		job.FailCount,
		job.CreatedBy,
		job.CreatedAt,
		job.UpdatedAt,
	)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to create scheduled job")
	}

	return nil
}

// GetScheduledJob retrieves a scheduled job by ID
func (r *JobRepository) GetScheduledJob(ctx context.Context, id uuid.UUID) (*models.ScheduledJob, error) {
	query := `
		SELECT 
			id, name, type, schedule, host_id, target_id, target_name,
			payload, priority, max_attempts, is_enabled, last_run_at,
			last_run_status, next_run_at, run_count, fail_count,
			created_by, created_at, updated_at
		FROM scheduled_jobs
		WHERE id = $1
	`

	job := &models.ScheduledJob{}
	err := r.db.Pool().QueryRow(ctx, query, id).Scan(
		&job.ID,
		&job.Name,
		&job.Type,
		&job.Schedule,
		&job.HostID,
		&job.TargetID,
		&job.TargetName,
		&job.Payload,
		&job.Priority,
		&job.MaxAttempts,
		&job.IsEnabled,
		&job.LastRunAt,
		&job.LastRunStatus,
		&job.NextRunAt,
		&job.RunCount,
		&job.FailCount,
		&job.CreatedBy,
		&job.CreatedAt,
		&job.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.New(errors.CodeNotFound, "scheduled job not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get scheduled job")
	}

	return job, nil
}

// UpdateScheduledJob updates a scheduled job
func (r *JobRepository) UpdateScheduledJob(ctx context.Context, job *models.ScheduledJob) error {
	query := `
		UPDATE scheduled_jobs SET
			name = $2,
			schedule = $3,
			payload = $4,
			priority = $5,
			max_attempts = $6,
			is_enabled = $7,
			next_run_at = $8,
			updated_at = $9
		WHERE id = $1
	`

	job.UpdatedAt = time.Now()

	result, err := r.db.Pool().Exec(ctx, query,
		job.ID,
		job.Name,
		job.Schedule,
		job.Payload,
		job.Priority,
		job.MaxAttempts,
		job.IsEnabled,
		job.NextRunAt,
		job.UpdatedAt,
	)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to update scheduled job")
	}

	if result.RowsAffected() == 0 {
		return errors.New(errors.CodeNotFound, "scheduled job not found")
	}

	return nil
}

// DeleteScheduledJob deletes a scheduled job
func (r *JobRepository) DeleteScheduledJob(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM scheduled_jobs WHERE id = $1`

	result, err := r.db.Pool().Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to delete scheduled job")
	}

	if result.RowsAffected() == 0 {
		return errors.New(errors.CodeNotFound, "scheduled job not found")
	}

	return nil
}

// ListScheduledJobs lists scheduled jobs with optional filter
func (r *JobRepository) ListScheduledJobs(ctx context.Context, enabled *bool) ([]*models.ScheduledJob, error) {
	query := `
		SELECT 
			id, name, type, schedule, host_id, target_id, target_name,
			payload, priority, max_attempts, is_enabled, last_run_at,
			last_run_status, next_run_at, run_count, fail_count,
			created_by, created_at, updated_at
		FROM scheduled_jobs
	`
	args := []interface{}{}

	if enabled != nil {
		query += ` WHERE is_enabled = $1`
		args = append(args, *enabled)
	}

	query += ` ORDER BY name`

	rows, err := r.db.Pool().Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to list scheduled jobs")
	}
	defer rows.Close()

	jobs := make([]*models.ScheduledJob, 0)
	for rows.Next() {
		job := &models.ScheduledJob{}
		err := rows.Scan(
			&job.ID,
			&job.Name,
			&job.Type,
			&job.Schedule,
			&job.HostID,
			&job.TargetID,
			&job.TargetName,
			&job.Payload,
			&job.Priority,
			&job.MaxAttempts,
			&job.IsEnabled,
			&job.LastRunAt,
			&job.LastRunStatus,
			&job.NextRunAt,
			&job.RunCount,
			&job.FailCount,
			&job.CreatedBy,
			&job.CreatedAt,
			&job.UpdatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to scan scheduled job")
		}
		jobs = append(jobs, job)
	}

	return jobs, nil
}

// UpdateScheduledJobLastRun updates the last run information
func (r *JobRepository) UpdateScheduledJobLastRun(ctx context.Context, id uuid.UUID, status models.JobStatus, nextRun *time.Time) error {
	query := `
		UPDATE scheduled_jobs SET
			last_run_at = NOW(),
			last_run_status = $2,
			next_run_at = $3,
			run_count = run_count + 1,
			fail_count = CASE WHEN $2 = 'failed' THEN fail_count + 1 ELSE fail_count END,
			updated_at = NOW()
		WHERE id = $1
	`

	_, err := r.db.Pool().Exec(ctx, query, id, status, nextRun)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to update scheduled job last run")
	}

	return nil
}

// ============================================================================
// Helpers
// ============================================================================

func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}
