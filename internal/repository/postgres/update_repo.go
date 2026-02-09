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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
)

// UpdateRepository handles database operations for updates
type UpdateRepository struct {
	pool *pgxpool.Pool
}

// NewUpdateRepository creates a new update repository
func NewUpdateRepository(pool *pgxpool.Pool) *UpdateRepository {
	return &UpdateRepository{pool: pool}
}

// ============================================================================
// Update CRUD Operations
// ============================================================================

// Create creates a new update record
func (r *UpdateRepository) Create(ctx context.Context, update *models.Update) error {
	query := `
		INSERT INTO updates (
			id, host_id, type, target_id, target_name, image,
			from_version, to_version, from_digest, to_digest,
			status, trigger, backup_id, changelog_url, changelog_body,
			security_score_before, security_score_after, health_check_passed,
			rollback_reason, error_message, duration_ms,
			created_by, started_at, completed_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10,
			$11, $12, $13, $14, $15,
			$16, $17, $18,
			$19, $20, $21,
			$22, $23, $24, $25
		)`

	if update.ID == uuid.Nil {
		update.ID = uuid.New()
	}
	if update.CreatedAt.IsZero() {
		update.CreatedAt = time.Now()
	}

	_, err := r.pool.Exec(ctx, query,
		update.ID, update.HostID, update.Type, update.TargetID, update.TargetName, update.Image,
		update.FromVersion, update.ToVersion, update.FromDigest, update.ToDigest,
		update.Status, update.Trigger, update.BackupID, update.ChangelogURL, update.ChangelogBody,
		update.SecurityScoreBefore, update.SecurityScoreAfter, update.HealthCheckPassed,
		update.RollbackReason, update.ErrorMessage, update.DurationMs,
		update.CreatedBy, update.StartedAt, update.CompletedAt, update.CreatedAt,
	)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to create update")
	}

	return nil
}

// Get retrieves an update by ID
func (r *UpdateRepository) Get(ctx context.Context, id uuid.UUID) (*models.Update, error) {
	query := `
		SELECT 
			id, host_id, type, target_id, target_name, image,
			from_version, to_version, from_digest, to_digest,
			status, trigger, backup_id, changelog_url, changelog_body,
			security_score_before, security_score_after, health_check_passed,
			rollback_reason, error_message, duration_ms,
			created_by, started_at, completed_at, created_at
		FROM updates
		WHERE id = $1`

	update := &models.Update{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&update.ID, &update.HostID, &update.Type, &update.TargetID, &update.TargetName, &update.Image,
		&update.FromVersion, &update.ToVersion, &update.FromDigest, &update.ToDigest,
		&update.Status, &update.Trigger, &update.BackupID, &update.ChangelogURL, &update.ChangelogBody,
		&update.SecurityScoreBefore, &update.SecurityScoreAfter, &update.HealthCheckPassed,
		&update.RollbackReason, &update.ErrorMessage, &update.DurationMs,
		&update.CreatedBy, &update.StartedAt, &update.CompletedAt, &update.CreatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.New(errors.CodeNotFound, "update not found").
				WithDetail("update_id", id.String())
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get update")
	}

	return update, nil
}

// Update updates an existing update record
func (r *UpdateRepository) Update(ctx context.Context, update *models.Update) error {
	query := `
		UPDATE updates SET
			status = $2,
			to_version = $3,
			to_digest = $4,
			backup_id = $5,
			changelog_url = $6,
			changelog_body = $7,
			security_score_before = $8,
			security_score_after = $9,
			health_check_passed = $10,
			rollback_reason = $11,
			error_message = $12,
			duration_ms = $13,
			started_at = $14,
			completed_at = $15
		WHERE id = $1`

	result, err := r.pool.Exec(ctx, query,
		update.ID,
		update.Status,
		update.ToVersion,
		update.ToDigest,
		update.BackupID,
		update.ChangelogURL,
		update.ChangelogBody,
		update.SecurityScoreBefore,
		update.SecurityScoreAfter,
		update.HealthCheckPassed,
		update.RollbackReason,
		update.ErrorMessage,
		update.DurationMs,
		update.StartedAt,
		update.CompletedAt,
	)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to update update record")
	}

	if result.RowsAffected() == 0 {
		return errors.New(errors.CodeNotFound, "update not found")
	}

	return nil
}

// UpdateStatus updates only the status of an update
func (r *UpdateRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.UpdateStatus, errorMsg *string) error {
	var query string
	var args []interface{}

	if status.IsTerminal() {
		query = `
			UPDATE updates 
			SET status = $2, error_message = $3, completed_at = NOW()
			WHERE id = $1`
		args = []interface{}{id, status, errorMsg}
	} else {
		query = `UPDATE updates SET status = $2, error_message = $3 WHERE id = $1`
		args = []interface{}{id, status, errorMsg}
	}

	result, err := r.pool.Exec(ctx, query, args...)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to update status")
	}

	if result.RowsAffected() == 0 {
		return errors.New(errors.CodeNotFound, "update not found")
	}

	return nil
}

// Delete deletes an update record
func (r *UpdateRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM updates WHERE id = $1`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to delete update")
	}

	if result.RowsAffected() == 0 {
		return errors.New(errors.CodeNotFound, "update not found")
	}

	return nil
}

// List retrieves updates with filtering
func (r *UpdateRepository) List(ctx context.Context, opts models.UpdateListOptions) ([]*models.Update, int64, error) {
	// Build WHERE clause
	where := "WHERE 1=1"
	args := []interface{}{}
	argNum := 1

	if opts.HostID != nil {
		where += fmt.Sprintf(" AND host_id = $%d", argNum)
		args = append(args, *opts.HostID)
		argNum++
	}

	if opts.TargetID != nil {
		where += fmt.Sprintf(" AND target_id = $%d", argNum)
		args = append(args, *opts.TargetID)
		argNum++
	}

	if opts.Status != nil {
		where += fmt.Sprintf(" AND status = $%d", argNum)
		args = append(args, *opts.Status)
		argNum++
	}

	if opts.Trigger != nil {
		where += fmt.Sprintf(" AND trigger = $%d", argNum)
		args = append(args, *opts.Trigger)
		argNum++
	}

	if opts.Before != nil {
		where += fmt.Sprintf(" AND created_at < $%d", argNum)
		args = append(args, *opts.Before)
		argNum++
	}

	if opts.After != nil {
		where += fmt.Sprintf(" AND created_at > $%d", argNum)
		args = append(args, *opts.After)
		argNum++
	}

	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM updates %s", where)
	var total int64
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeInternal, "failed to count updates")
	}

	// Get records with pagination
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}

	query := fmt.Sprintf(`
		SELECT 
			id, host_id, type, target_id, target_name, image,
			from_version, to_version, from_digest, to_digest,
			status, trigger, backup_id, changelog_url, changelog_body,
			security_score_before, security_score_after, health_check_passed,
			rollback_reason, error_message, duration_ms,
			created_by, started_at, completed_at, created_at
		FROM updates
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`,
		where, argNum, argNum+1)

	args = append(args, limit, offset)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeInternal, "failed to list updates")
	}
	defer rows.Close()

	updates := make([]*models.Update, 0)
	for rows.Next() {
		update := &models.Update{}
		err := rows.Scan(
			&update.ID, &update.HostID, &update.Type, &update.TargetID, &update.TargetName, &update.Image,
			&update.FromVersion, &update.ToVersion, &update.FromDigest, &update.ToDigest,
			&update.Status, &update.Trigger, &update.BackupID, &update.ChangelogURL, &update.ChangelogBody,
			&update.SecurityScoreBefore, &update.SecurityScoreAfter, &update.HealthCheckPassed,
			&update.RollbackReason, &update.ErrorMessage, &update.DurationMs,
			&update.CreatedBy, &update.StartedAt, &update.CompletedAt, &update.CreatedAt,
		)
		if err != nil {
			return nil, 0, errors.Wrap(err, errors.CodeInternal, "failed to scan update")
		}
		updates = append(updates, update)
	}

	return updates, total, nil
}

// GetByTarget retrieves updates for a specific target
func (r *UpdateRepository) GetByTarget(ctx context.Context, hostID uuid.UUID, targetID string, limit int) ([]*models.Update, error) {
	if limit <= 0 {
		limit = 10
	}

	query := `
		SELECT 
			id, host_id, type, target_id, target_name, image,
			from_version, to_version, from_digest, to_digest,
			status, trigger, backup_id, changelog_url, changelog_body,
			security_score_before, security_score_after, health_check_passed,
			rollback_reason, error_message, duration_ms,
			created_by, started_at, completed_at, created_at
		FROM updates
		WHERE host_id = $1 AND target_id = $2
		ORDER BY created_at DESC
		LIMIT $3`

	rows, err := r.pool.Query(ctx, query, hostID, targetID, limit)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get updates by target")
	}
	defer rows.Close()

	updates := make([]*models.Update, 0)
	for rows.Next() {
		update := &models.Update{}
		err := rows.Scan(
			&update.ID, &update.HostID, &update.Type, &update.TargetID, &update.TargetName, &update.Image,
			&update.FromVersion, &update.ToVersion, &update.FromDigest, &update.ToDigest,
			&update.Status, &update.Trigger, &update.BackupID, &update.ChangelogURL, &update.ChangelogBody,
			&update.SecurityScoreBefore, &update.SecurityScoreAfter, &update.HealthCheckPassed,
			&update.RollbackReason, &update.ErrorMessage, &update.DurationMs,
			&update.CreatedBy, &update.StartedAt, &update.CompletedAt, &update.CreatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to scan update")
		}
		updates = append(updates, update)
	}

	return updates, nil
}

// GetLatestByTarget retrieves the most recent update for a target
func (r *UpdateRepository) GetLatestByTarget(ctx context.Context, hostID uuid.UUID, targetID string) (*models.Update, error) {
	query := `
		SELECT 
			id, host_id, type, target_id, target_name, image,
			from_version, to_version, from_digest, to_digest,
			status, trigger, backup_id, changelog_url, changelog_body,
			security_score_before, security_score_after, health_check_passed,
			rollback_reason, error_message, duration_ms,
			created_by, started_at, completed_at, created_at
		FROM updates
		WHERE host_id = $1 AND target_id = $2
		ORDER BY created_at DESC
		LIMIT 1`

	update := &models.Update{}
	err := r.pool.QueryRow(ctx, query, hostID, targetID).Scan(
		&update.ID, &update.HostID, &update.Type, &update.TargetID, &update.TargetName, &update.Image,
		&update.FromVersion, &update.ToVersion, &update.FromDigest, &update.ToDigest,
		&update.Status, &update.Trigger, &update.BackupID, &update.ChangelogURL, &update.ChangelogBody,
		&update.SecurityScoreBefore, &update.SecurityScoreAfter, &update.HealthCheckPassed,
		&update.RollbackReason, &update.ErrorMessage, &update.DurationMs,
		&update.CreatedBy, &update.StartedAt, &update.CompletedAt, &update.CreatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get latest update")
	}

	return update, nil
}

// GetRollbackCandidate finds an update that can be rolled back
func (r *UpdateRepository) GetRollbackCandidate(ctx context.Context, hostID uuid.UUID, targetID string) (*models.Update, error) {
	query := `
		SELECT 
			id, host_id, type, target_id, target_name, image,
			from_version, to_version, from_digest, to_digest,
			status, trigger, backup_id, changelog_url, changelog_body,
			security_score_before, security_score_after, health_check_passed,
			rollback_reason, error_message, duration_ms,
			created_by, started_at, completed_at, created_at
		FROM updates
		WHERE host_id = $1 
			AND target_id = $2 
			AND status = 'completed'
			AND backup_id IS NOT NULL
			AND created_at > NOW() - INTERVAL '24 hours'
		ORDER BY created_at DESC
		LIMIT 1`

	update := &models.Update{}
	err := r.pool.QueryRow(ctx, query, hostID, targetID).Scan(
		&update.ID, &update.HostID, &update.Type, &update.TargetID, &update.TargetName, &update.Image,
		&update.FromVersion, &update.ToVersion, &update.FromDigest, &update.ToDigest,
		&update.Status, &update.Trigger, &update.BackupID, &update.ChangelogURL, &update.ChangelogBody,
		&update.SecurityScoreBefore, &update.SecurityScoreAfter, &update.HealthCheckPassed,
		&update.RollbackReason, &update.ErrorMessage, &update.DurationMs,
		&update.CreatedBy, &update.StartedAt, &update.CompletedAt, &update.CreatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get rollback candidate")
	}

	return update, nil
}

// GetStats retrieves update statistics
func (r *UpdateRepository) GetStats(ctx context.Context, hostID *uuid.UUID) (*models.UpdateStats, error) {
	var where string
	var args []interface{}

	if hostID != nil {
		where = "WHERE host_id = $1"
		args = append(args, *hostID)
	}

	query := fmt.Sprintf(`
		SELECT 
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE status = 'completed') AS successful,
			COUNT(*) FILTER (WHERE status = 'failed') AS failed,
			COUNT(*) FILTER (WHERE status = 'rolled_back') AS rolled_back,
			COALESCE(AVG(duration_ms) FILTER (WHERE duration_ms IS NOT NULL), 0) AS avg_duration,
			MAX(created_at) AS last_update
		FROM updates
		%s`, where)

	stats := &models.UpdateStats{
		ByStatus:  make(map[string]int),
		ByTrigger: make(map[string]int),
	}

	var lastUpdate *time.Time
	err := r.pool.QueryRow(ctx, query, args...).Scan(
		&stats.TotalUpdates,
		&stats.SuccessfulCount,
		&stats.FailedCount,
		&stats.RolledBackCount,
		&stats.AvgDurationMs,
		&lastUpdate,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get update stats")
	}
	stats.LastUpdateAt = lastUpdate

	// Get counts by status
	statusQuery := fmt.Sprintf(`
		SELECT status, COUNT(*) 
		FROM updates %s 
		GROUP BY status`, where)

	rows, err := r.pool.Query(ctx, statusQuery, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get status counts")
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			continue
		}
		stats.ByStatus[status] = count
	}

	// Get counts by trigger
	triggerQuery := fmt.Sprintf(`
		SELECT trigger, COUNT(*) 
		FROM updates %s 
		GROUP BY trigger`, where)

	rows, err = r.pool.Query(ctx, triggerQuery, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get trigger counts")
	}
	defer rows.Close()

	for rows.Next() {
		var trigger string
		var count int
		if err := rows.Scan(&trigger, &count); err != nil {
			continue
		}
		stats.ByTrigger[trigger] = count
	}

	return stats, nil
}

// DeleteOlderThan deletes updates older than the specified time
func (r *UpdateRepository) DeleteOlderThan(ctx context.Context, before time.Time) (int64, error) {
	query := `DELETE FROM updates WHERE created_at < $1`

	result, err := r.pool.Exec(ctx, query, before)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternal, "failed to delete old updates")
	}

	return result.RowsAffected(), nil
}

// ============================================================================
// Update Policy Operations
// ============================================================================

// CreatePolicy creates a new update policy
func (r *UpdateRepository) CreatePolicy(ctx context.Context, policy *models.UpdatePolicy) error {
	query := `
		INSERT INTO update_policies (
			id, host_id, target_type, target_id, target_name,
			is_enabled, auto_update, auto_backup, include_prerelease,
			schedule, notify_on_update, notify_on_failure,
			max_retries, health_check_wait, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12,
			$13, $14, $15, $16
		)`

	if policy.ID == uuid.Nil {
		policy.ID = uuid.New()
	}
	now := time.Now()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now

	_, err := r.pool.Exec(ctx, query,
		policy.ID, policy.HostID, policy.TargetType, policy.TargetID, policy.TargetName,
		policy.IsEnabled, policy.AutoUpdate, policy.AutoBackup, policy.IncludePrerelease,
		policy.Schedule, policy.NotifyOnUpdate, policy.NotifyOnFailure,
		policy.MaxRetries, policy.HealthCheckWait, policy.CreatedAt, policy.UpdatedAt,
	)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to create update policy")
	}

	return nil
}

// GetPolicy retrieves an update policy by ID
func (r *UpdateRepository) GetPolicy(ctx context.Context, id uuid.UUID) (*models.UpdatePolicy, error) {
	query := `
		SELECT 
			id, host_id, target_type, target_id, target_name,
			is_enabled, auto_update, auto_backup, include_prerelease,
			schedule, notify_on_update, notify_on_failure,
			max_retries, health_check_wait, created_at, updated_at
		FROM update_policies
		WHERE id = $1`

	policy := &models.UpdatePolicy{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&policy.ID, &policy.HostID, &policy.TargetType, &policy.TargetID, &policy.TargetName,
		&policy.IsEnabled, &policy.AutoUpdate, &policy.AutoBackup, &policy.IncludePrerelease,
		&policy.Schedule, &policy.NotifyOnUpdate, &policy.NotifyOnFailure,
		&policy.MaxRetries, &policy.HealthCheckWait, &policy.CreatedAt, &policy.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.New(errors.CodeNotFound, "update policy not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get update policy")
	}

	return policy, nil
}

// GetPolicyByTarget retrieves an update policy by target
func (r *UpdateRepository) GetPolicyByTarget(ctx context.Context, hostID uuid.UUID, targetType models.UpdateType, targetID string) (*models.UpdatePolicy, error) {
	query := `
		SELECT 
			id, host_id, target_type, target_id, target_name,
			is_enabled, auto_update, auto_backup, include_prerelease,
			schedule, notify_on_update, notify_on_failure,
			max_retries, health_check_wait, created_at, updated_at
		FROM update_policies
		WHERE host_id = $1 AND target_type = $2 AND target_id = $3`

	policy := &models.UpdatePolicy{}
	err := r.pool.QueryRow(ctx, query, hostID, targetType, targetID).Scan(
		&policy.ID, &policy.HostID, &policy.TargetType, &policy.TargetID, &policy.TargetName,
		&policy.IsEnabled, &policy.AutoUpdate, &policy.AutoBackup, &policy.IncludePrerelease,
		&policy.Schedule, &policy.NotifyOnUpdate, &policy.NotifyOnFailure,
		&policy.MaxRetries, &policy.HealthCheckWait, &policy.CreatedAt, &policy.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get update policy by target")
	}

	return policy, nil
}

// UpdatePolicy updates an existing update policy
func (r *UpdateRepository) UpdatePolicy(ctx context.Context, policy *models.UpdatePolicy) error {
	query := `
		UPDATE update_policies SET
			is_enabled = $2,
			auto_update = $3,
			auto_backup = $4,
			include_prerelease = $5,
			schedule = $6,
			notify_on_update = $7,
			notify_on_failure = $8,
			max_retries = $9,
			health_check_wait = $10,
			updated_at = NOW()
		WHERE id = $1`

	result, err := r.pool.Exec(ctx, query,
		policy.ID,
		policy.IsEnabled,
		policy.AutoUpdate,
		policy.AutoBackup,
		policy.IncludePrerelease,
		policy.Schedule,
		policy.NotifyOnUpdate,
		policy.NotifyOnFailure,
		policy.MaxRetries,
		policy.HealthCheckWait,
	)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to update policy")
	}

	if result.RowsAffected() == 0 {
		return errors.New(errors.CodeNotFound, "update policy not found")
	}

	return nil
}

// DeletePolicy deletes an update policy
func (r *UpdateRepository) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM update_policies WHERE id = $1`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to delete policy")
	}

	if result.RowsAffected() == 0 {
		return errors.New(errors.CodeNotFound, "update policy not found")
	}

	return nil
}

// ListPolicies retrieves all policies for a host
func (r *UpdateRepository) ListPolicies(ctx context.Context, hostID *uuid.UUID) ([]*models.UpdatePolicy, error) {
	var query string
	var args []interface{}

	if hostID != nil {
		query = `
			SELECT 
				id, host_id, target_type, target_id, target_name,
				is_enabled, auto_update, auto_backup, include_prerelease,
				schedule, notify_on_update, notify_on_failure,
				max_retries, health_check_wait, created_at, updated_at
			FROM update_policies
			WHERE host_id = $1
			ORDER BY target_name`
		args = []interface{}{*hostID}
	} else {
		query = `
			SELECT 
				id, host_id, target_type, target_id, target_name,
				is_enabled, auto_update, auto_backup, include_prerelease,
				schedule, notify_on_update, notify_on_failure,
				max_retries, health_check_wait, created_at, updated_at
			FROM update_policies
			ORDER BY host_id, target_name`
	}

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to list policies")
	}
	defer rows.Close()

	policies := make([]*models.UpdatePolicy, 0)
	for rows.Next() {
		policy := &models.UpdatePolicy{}
		err := rows.Scan(
			&policy.ID, &policy.HostID, &policy.TargetType, &policy.TargetID, &policy.TargetName,
			&policy.IsEnabled, &policy.AutoUpdate, &policy.AutoBackup, &policy.IncludePrerelease,
			&policy.Schedule, &policy.NotifyOnUpdate, &policy.NotifyOnFailure,
			&policy.MaxRetries, &policy.HealthCheckWait, &policy.CreatedAt, &policy.UpdatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to scan policy")
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

// GetAutoUpdatePolicies retrieves all enabled auto-update policies
func (r *UpdateRepository) GetAutoUpdatePolicies(ctx context.Context) ([]*models.UpdatePolicy, error) {
	query := `
		SELECT 
			id, host_id, target_type, target_id, target_name,
			is_enabled, auto_update, auto_backup, include_prerelease,
			schedule, notify_on_update, notify_on_failure,
			max_retries, health_check_wait, created_at, updated_at
		FROM update_policies
		WHERE is_enabled = true AND auto_update = true
		ORDER BY host_id, target_name`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get auto-update policies")
	}
	defer rows.Close()

	policies := make([]*models.UpdatePolicy, 0)
	for rows.Next() {
		policy := &models.UpdatePolicy{}
		err := rows.Scan(
			&policy.ID, &policy.HostID, &policy.TargetType, &policy.TargetID, &policy.TargetName,
			&policy.IsEnabled, &policy.AutoUpdate, &policy.AutoBackup, &policy.IncludePrerelease,
			&policy.Schedule, &policy.NotifyOnUpdate, &policy.NotifyOnFailure,
			&policy.MaxRetries, &policy.HealthCheckWait, &policy.CreatedAt, &policy.UpdatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to scan policy")
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

// ============================================================================
// Webhook Operations
// ============================================================================

// CreateWebhook creates a new update webhook
func (r *UpdateRepository) CreateWebhook(ctx context.Context, webhook *models.UpdateWebhook) error {
	query := `
		INSERT INTO update_webhooks (
			id, host_id, target_type, target_id, token, is_enabled, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`

	if webhook.ID == uuid.Nil {
		webhook.ID = uuid.New()
	}
	if webhook.CreatedAt.IsZero() {
		webhook.CreatedAt = time.Now()
	}

	_, err := r.pool.Exec(ctx, query,
		webhook.ID, webhook.HostID, webhook.TargetType, webhook.TargetID,
		webhook.Token, webhook.IsEnabled, webhook.CreatedAt,
	)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to create webhook")
	}

	return nil
}

// GetWebhookByToken retrieves a webhook by its token
func (r *UpdateRepository) GetWebhookByToken(ctx context.Context, token string) (*models.UpdateWebhook, error) {
	query := `
		SELECT id, host_id, target_type, target_id, token, is_enabled, last_used_at, created_at
		FROM update_webhooks
		WHERE token = $1`

	webhook := &models.UpdateWebhook{}
	err := r.pool.QueryRow(ctx, query, token).Scan(
		&webhook.ID, &webhook.HostID, &webhook.TargetType, &webhook.TargetID,
		&webhook.Token, &webhook.IsEnabled, &webhook.LastUsedAt, &webhook.CreatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.New(errors.CodeNotFound, "webhook not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get webhook")
	}

	return webhook, nil
}

// UpdateWebhookLastUsed updates the last used timestamp
func (r *UpdateRepository) UpdateWebhookLastUsed(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE update_webhooks SET last_used_at = NOW() WHERE id = $1`

	_, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to update webhook last used")
	}

	return nil
}

// DeleteWebhook deletes a webhook
func (r *UpdateRepository) DeleteWebhook(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM update_webhooks WHERE id = $1`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to delete webhook")
	}

	if result.RowsAffected() == 0 {
		return errors.New(errors.CodeNotFound, "webhook not found")
	}

	return nil
}

// ListWebhooks retrieves webhooks for a host
func (r *UpdateRepository) ListWebhooks(ctx context.Context, hostID uuid.UUID) ([]*models.UpdateWebhook, error) {
	query := `
		SELECT id, host_id, target_type, target_id, token, is_enabled, last_used_at, created_at
		FROM update_webhooks
		WHERE host_id = $1
		ORDER BY created_at DESC`

	rows, err := r.pool.Query(ctx, query, hostID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to list webhooks")
	}
	defer rows.Close()

	webhooks := make([]*models.UpdateWebhook, 0)
	for rows.Next() {
		webhook := &models.UpdateWebhook{}
		err := rows.Scan(
			&webhook.ID, &webhook.HostID, &webhook.TargetType, &webhook.TargetID,
			&webhook.Token, &webhook.IsEnabled, &webhook.LastUsedAt, &webhook.CreatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to scan webhook")
		}
		webhooks = append(webhooks, webhook)
	}

	return webhooks, nil
}
