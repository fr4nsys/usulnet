// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// GitSyncRepository
// ============================================================================

// GitSyncRepository handles CRUD for bidirectional git sync configurations,
// events, and conflicts.
type GitSyncRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewGitSyncRepository creates a new GitSyncRepository.
func NewGitSyncRepository(db *DB, log *logger.Logger) *GitSyncRepository {
	return &GitSyncRepository{
		db:     db,
		logger: log.Named("git_sync_repo"),
	}
}

// gitSyncConfigColumns is the standard column list for git_sync_configs queries.
const gitSyncConfigColumns = `id, connection_id, repository_id, name, repo_full_name,
	sync_direction, target_path,
	stack_name, file_pattern, branch, auto_commit, auto_deploy,
	commit_message_template, conflict_strategy, is_enabled,
	last_sync_at, last_sync_status, last_sync_error, sync_count,
	created_by, created_at, updated_at`

// scanGitSyncConfig scans a single row into a models.GitSyncConfig.
func scanGitSyncConfig(row pgx.Row) (*models.GitSyncConfig, error) {
	var c models.GitSyncConfig
	err := row.Scan(
		&c.ID, &c.ConnectionID, &c.RepositoryID, &c.Name, &c.RepoFullName,
		&c.SyncDirection, &c.TargetPath,
		&c.StackName, &c.FilePattern, &c.Branch, &c.AutoCommit, &c.AutoDeploy,
		&c.CommitMessageTemplate, &c.ConflictStrategy, &c.IsEnabled,
		&c.LastSyncAt, &c.LastSyncStatus, &c.LastSyncError, &c.SyncCount,
		&c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// scanGitSyncConfigRows scans multiple rows into a slice of models.GitSyncConfig.
func scanGitSyncConfigRows(rows pgx.Rows) ([]*models.GitSyncConfig, error) {
	var configs []*models.GitSyncConfig
	for rows.Next() {
		var c models.GitSyncConfig
		err := rows.Scan(
			&c.ID, &c.ConnectionID, &c.RepositoryID, &c.Name, &c.RepoFullName,
			&c.SyncDirection, &c.TargetPath,
			&c.StackName, &c.FilePattern, &c.Branch, &c.AutoCommit, &c.AutoDeploy,
			&c.CommitMessageTemplate, &c.ConflictStrategy, &c.IsEnabled,
			&c.LastSyncAt, &c.LastSyncStatus, &c.LastSyncError, &c.SyncCount,
			&c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		configs = append(configs, &c)
	}
	return configs, rows.Err()
}

// CreateConfig inserts a new git sync configuration.
func (r *GitSyncRepository) CreateConfig(ctx context.Context, c *models.GitSyncConfig) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO git_sync_configs (
			id, connection_id, repository_id, name, repo_full_name,
			sync_direction, target_path,
			stack_name, file_pattern, branch, auto_commit, auto_deploy,
			commit_message_template, conflict_strategy, is_enabled, created_by
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7,
			$8, $9, $10, $11, $12,
			$13, $14, $15, $16
		)`,
		c.ID, c.ConnectionID, c.RepositoryID, c.Name, c.RepoFullName,
		c.SyncDirection, c.TargetPath,
		c.StackName, c.FilePattern, c.Branch, c.AutoCommit, c.AutoDeploy,
		c.CommitMessageTemplate, c.ConflictStrategy, c.IsEnabled, c.CreatedBy,
	)
	if err != nil {
		r.logger.Error("Failed to create git sync config", "name", c.Name, "error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create git sync config")
	}

	return nil
}

// GetConfig retrieves a git sync configuration by ID.
func (r *GitSyncRepository) GetConfig(ctx context.Context, id uuid.UUID) (*models.GitSyncConfig, error) {
	query := fmt.Sprintf(`SELECT %s FROM git_sync_configs WHERE id = $1`, gitSyncConfigColumns)
	c, err := scanGitSyncConfig(r.db.QueryRow(ctx, query, id))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("git sync config")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get git sync config")
	}
	return c, nil
}

// ListConfigs returns all git sync configurations ordered by name.
func (r *GitSyncRepository) ListConfigs(ctx context.Context) ([]*models.GitSyncConfig, error) {
	query := fmt.Sprintf(`SELECT %s FROM git_sync_configs ORDER BY name ASC`, gitSyncConfigColumns)
	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list git sync configs")
	}
	defer rows.Close()

	configs, err := scanGitSyncConfigRows(rows)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan git sync config rows")
	}
	return configs, nil
}

// ListConfigsByConnection returns git sync configurations for a specific connection.
func (r *GitSyncRepository) ListConfigsByConnection(ctx context.Context, connectionID uuid.UUID) ([]*models.GitSyncConfig, error) {
	query := fmt.Sprintf(`SELECT %s FROM git_sync_configs WHERE connection_id = $1 ORDER BY name ASC`, gitSyncConfigColumns)
	rows, err := r.db.Query(ctx, query, connectionID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list git sync configs by connection")
	}
	defer rows.Close()

	configs, err := scanGitSyncConfigRows(rows)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan git sync config rows")
	}
	return configs, nil
}

// UpdateConfig updates all editable fields of a git sync configuration.
func (r *GitSyncRepository) UpdateConfig(ctx context.Context, c *models.GitSyncConfig) error {
	result, err := r.db.Exec(ctx, `
		UPDATE git_sync_configs
		SET name = $1, sync_direction = $2, target_path = $3, stack_name = $4,
			file_pattern = $5, branch = $6, auto_commit = $7, auto_deploy = $8,
			commit_message_template = $9, conflict_strategy = $10, is_enabled = $11
		WHERE id = $12`,
		c.Name, c.SyncDirection, c.TargetPath, c.StackName,
		c.FilePattern, c.Branch, c.AutoCommit, c.AutoDeploy,
		c.CommitMessageTemplate, c.ConflictStrategy, c.IsEnabled,
		c.ID,
	)
	if err != nil {
		r.logger.Error("Failed to update git sync config", "id", c.ID, "error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update git sync config")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("git sync config")
	}
	return nil
}

// DeleteConfig deletes a git sync configuration by ID.
func (r *GitSyncRepository) DeleteConfig(ctx context.Context, id uuid.UUID) error {
	result, err := r.db.Exec(ctx, `DELETE FROM git_sync_configs WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete git sync config")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("git sync config")
	}
	return nil
}

// UpdateSyncStatus updates the sync status fields after a sync operation.
func (r *GitSyncRepository) UpdateSyncStatus(ctx context.Context, id uuid.UUID, status string, syncError string) error {
	result, err := r.db.Exec(ctx, `
		UPDATE git_sync_configs
		SET last_sync_at = NOW(), last_sync_status = $1, last_sync_error = $2,
			sync_count = sync_count + 1
		WHERE id = $3`,
		status, syncError, id,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update git sync status")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("git sync config")
	}
	return nil
}

// ToggleConfig toggles the is_enabled flag and returns the new state.
func (r *GitSyncRepository) ToggleConfig(ctx context.Context, id uuid.UUID) (bool, error) {
	var newState bool
	err := r.db.QueryRow(ctx, `
		UPDATE git_sync_configs SET is_enabled = NOT is_enabled WHERE id = $1
		RETURNING is_enabled`, id).Scan(&newState)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, errors.NotFound("git sync config")
		}
		return false, errors.Wrap(err, errors.CodeDatabaseError, "failed to toggle git sync config")
	}
	return newState, nil
}

// CreateEvent inserts a new git sync event.
func (r *GitSyncRepository) CreateEvent(ctx context.Context, e *models.GitSyncEvent) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO git_sync_events (
			id, config_id, direction, event_type, status,
			commit_sha, commit_message, files_changed, diff_summary,
			error_message, metadata
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11
		)`,
		e.ID, e.ConfigID, e.Direction, e.EventType, e.Status,
		e.CommitSHA, e.CommitMessage, e.FilesChanged, e.DiffSummary,
		e.ErrorMessage, e.Metadata,
	)
	if err != nil {
		r.logger.Error("Failed to create git sync event",
			"config_id", e.ConfigID, "event_type", e.EventType, "error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create git sync event")
	}
	return nil
}

// ListEvents returns recent sync events for a configuration.
func (r *GitSyncRepository) ListEvents(ctx context.Context, configID uuid.UUID, limit int) ([]*models.GitSyncEvent, error) {
	if limit <= 0 {
		limit = 50
	}

	rows, err := r.db.Query(ctx, `
		SELECT id, config_id, direction, event_type, status,
			commit_sha, commit_message, files_changed, diff_summary,
			error_message, metadata, created_at
		FROM git_sync_events
		WHERE config_id = $1
		ORDER BY created_at DESC
		LIMIT $2`, configID, limit)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list git sync events")
	}
	defer rows.Close()

	var events []*models.GitSyncEvent
	for rows.Next() {
		var e models.GitSyncEvent
		if err := rows.Scan(
			&e.ID, &e.ConfigID, &e.Direction, &e.EventType, &e.Status,
			&e.CommitSHA, &e.CommitMessage, &e.FilesChanged, &e.DiffSummary,
			&e.ErrorMessage, &e.Metadata, &e.CreatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan git sync event row")
		}
		events = append(events, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to iterate git sync event rows")
	}
	return events, nil
}

// CreateConflict inserts a new git sync conflict.
func (r *GitSyncRepository) CreateConflict(ctx context.Context, c *models.GitSyncConflict) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO git_sync_conflicts (
			id, config_id, event_id, file_path,
			git_content, ui_content, base_content, resolution
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8
		)`,
		c.ID, c.ConfigID, c.EventID, c.FilePath,
		c.GitContent, c.UIContent, c.BaseContent, c.Resolution,
	)
	if err != nil {
		r.logger.Error("Failed to create git sync conflict",
			"config_id", c.ConfigID, "file_path", c.FilePath, "error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create git sync conflict")
	}
	return nil
}

// ListConflicts returns conflicts for a configuration, optionally filtered by resolution.
func (r *GitSyncRepository) ListConflicts(ctx context.Context, configID uuid.UUID, resolution string) ([]*models.GitSyncConflict, error) {
	var args []interface{}
	args = append(args, configID)

	query := `
		SELECT id, config_id, event_id, file_path,
			git_content, ui_content, base_content, resolution,
			resolved_by, resolved_at, merged_content, created_at
		FROM git_sync_conflicts
		WHERE config_id = $1`

	if resolution != "" {
		query += ` AND resolution = $2`
		args = append(args, resolution)
	}

	query += ` ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list git sync conflicts")
	}
	defer rows.Close()

	var conflicts []*models.GitSyncConflict
	for rows.Next() {
		var c models.GitSyncConflict
		if err := rows.Scan(
			&c.ID, &c.ConfigID, &c.EventID, &c.FilePath,
			&c.GitContent, &c.UIContent, &c.BaseContent, &c.Resolution,
			&c.ResolvedBy, &c.ResolvedAt, &c.MergedContent, &c.CreatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan git sync conflict row")
		}
		conflicts = append(conflicts, &c)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to iterate git sync conflict rows")
	}
	return conflicts, nil
}

// ResolveConflict sets the resolution, resolved_by, resolved_at, and merged_content for a conflict.
func (r *GitSyncRepository) ResolveConflict(ctx context.Context, id uuid.UUID, resolution string, resolvedBy uuid.UUID, mergedContent *string) error {
	result, err := r.db.Exec(ctx, `
		UPDATE git_sync_conflicts
		SET resolution = $1, resolved_by = $2, resolved_at = NOW(), merged_content = $3
		WHERE id = $4`,
		resolution, resolvedBy, mergedContent, id,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to resolve git sync conflict")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("git sync conflict")
	}
	return nil
}

// GetConflict retrieves a single conflict by ID.
func (r *GitSyncRepository) GetConflict(ctx context.Context, id uuid.UUID) (*models.GitSyncConflict, error) {
	var c models.GitSyncConflict
	err := r.db.QueryRow(ctx, `
		SELECT id, config_id, event_id, file_path,
			git_content, ui_content, base_content, resolution,
			resolved_by, resolved_at, merged_content, created_at
		FROM git_sync_conflicts
		WHERE id = $1`, id).Scan(
		&c.ID, &c.ConfigID, &c.EventID, &c.FilePath,
		&c.GitContent, &c.UIContent, &c.BaseContent, &c.Resolution,
		&c.ResolvedBy, &c.ResolvedAt, &c.MergedContent, &c.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("git sync conflict")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get git sync conflict")
	}
	return &c, nil
}

// ============================================================================
// EphemeralEnvironmentRepository
// ============================================================================

// EphemeralEnvironmentRepository handles CRUD for branch-based ephemeral
// environments.
type EphemeralEnvironmentRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewEphemeralEnvironmentRepository creates a new EphemeralEnvironmentRepository.
func NewEphemeralEnvironmentRepository(db *DB, log *logger.Logger) *EphemeralEnvironmentRepository {
	return &EphemeralEnvironmentRepository{
		db:     db,
		logger: log.Named("ephemeral_env_repo"),
	}
}

// ephemeralEnvColumns is the standard column list for ephemeral_environments queries.
const ephemeralEnvColumns = `id, name, connection_id, repository_id, branch, repo_full_name,
	commit_sha, stack_name, compose_file, environment, port_mappings,
	status, url, ttl_minutes, auto_destroy,
	expires_at, started_at, stopped_at, error_message,
	resource_limits, labels, created_by, created_at, updated_at`

// scanEphemeralEnv scans a single row into a models.EphemeralEnvironment.
func scanEphemeralEnv(row pgx.Row) (*models.EphemeralEnvironment, error) {
	var e models.EphemeralEnvironment
	err := row.Scan(
		&e.ID, &e.Name, &e.ConnectionID, &e.RepositoryID, &e.Branch, &e.RepoFullName,
		&e.CommitSHA, &e.StackName, &e.ComposeFile, &e.Environment, &e.PortMappings,
		&e.Status, &e.URL, &e.TTLMinutes, &e.AutoDestroy,
		&e.ExpiresAt, &e.StartedAt, &e.StoppedAt, &e.ErrorMessage,
		&e.ResourceLimits, &e.Labels, &e.CreatedBy, &e.CreatedAt, &e.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// scanEphemeralEnvRows scans multiple rows into a slice of models.EphemeralEnvironment.
func scanEphemeralEnvRows(rows pgx.Rows) ([]*models.EphemeralEnvironment, error) {
	var envs []*models.EphemeralEnvironment
	for rows.Next() {
		var e models.EphemeralEnvironment
		err := rows.Scan(
			&e.ID, &e.Name, &e.ConnectionID, &e.RepositoryID, &e.Branch, &e.RepoFullName,
			&e.CommitSHA, &e.StackName, &e.ComposeFile, &e.Environment, &e.PortMappings,
			&e.Status, &e.URL, &e.TTLMinutes, &e.AutoDestroy,
			&e.ExpiresAt, &e.StartedAt, &e.StoppedAt, &e.ErrorMessage,
			&e.ResourceLimits, &e.Labels, &e.CreatedBy, &e.CreatedAt, &e.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		envs = append(envs, &e)
	}
	return envs, rows.Err()
}

// Create inserts a new ephemeral environment.
func (r *EphemeralEnvironmentRepository) Create(ctx context.Context, e *models.EphemeralEnvironment) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO ephemeral_environments (
			id, name, connection_id, repository_id, branch, repo_full_name,
			commit_sha, stack_name, compose_file, environment, port_mappings,
			status, url, ttl_minutes, auto_destroy,
			expires_at, error_message, resource_limits, labels, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11,
			$12, $13, $14, $15,
			$16, $17, $18, $19, $20
		)`,
		e.ID, e.Name, e.ConnectionID, e.RepositoryID, e.Branch, e.RepoFullName,
		e.CommitSHA, e.StackName, e.ComposeFile, e.Environment, e.PortMappings,
		e.Status, e.URL, e.TTLMinutes, e.AutoDestroy,
		e.ExpiresAt, e.ErrorMessage, e.ResourceLimits, e.Labels, e.CreatedBy,
	)
	if err != nil {
		r.logger.Error("Failed to create ephemeral environment",
			"name", e.Name, "branch", e.Branch, "error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create ephemeral environment")
	}
	return nil
}

// GetByID retrieves an ephemeral environment by ID.
func (r *EphemeralEnvironmentRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.EphemeralEnvironment, error) {
	query := fmt.Sprintf(`SELECT %s FROM ephemeral_environments WHERE id = $1`, ephemeralEnvColumns)
	e, err := scanEphemeralEnv(r.db.QueryRow(ctx, query, id))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("ephemeral environment")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get ephemeral environment")
	}
	return e, nil
}

// List retrieves ephemeral environments with optional filtering and pagination.
func (r *EphemeralEnvironmentRepository) List(ctx context.Context, opts models.EphemeralEnvListOptions) ([]*models.EphemeralEnvironment, error) {
	var conditions []string
	var args []interface{}
	argNum := 1

	if opts.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argNum))
		args = append(args, opts.Status)
		argNum++
	}
	if opts.Branch != "" {
		conditions = append(conditions, fmt.Sprintf("branch = $%d", argNum))
		args = append(args, opts.Branch)
		argNum++
	}
	if opts.RepositoryID != "" {
		conditions = append(conditions, fmt.Sprintf("repository_id = $%d", argNum))
		args = append(args, opts.RepositoryID)
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	if opts.Limit <= 0 {
		opts.Limit = 50
	}

	query := fmt.Sprintf(`
		SELECT %s FROM ephemeral_environments
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`,
		ephemeralEnvColumns, whereClause, argNum, argNum+1)

	args = append(args, opts.Limit, opts.Offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list ephemeral environments")
	}
	defer rows.Close()

	envs, err := scanEphemeralEnvRows(rows)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan ephemeral environment rows")
	}
	return envs, nil
}

// UpdateStatus updates the status and error message for an ephemeral environment.
// It also sets the appropriate timestamp: started_at for running, stopped_at for
// stopped/expired/failed.
func (r *EphemeralEnvironmentRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.EphemeralEnvironmentStatus, errorMsg string) error {
	now := time.Now()

	var query string
	var args []interface{}

	switch status {
	case models.EphemeralStatusRunning:
		query = `
			UPDATE ephemeral_environments
			SET status = $1, error_message = $2, started_at = $3
			WHERE id = $4`
		args = []interface{}{status, errorMsg, now, id}
	case models.EphemeralStatusStopped, models.EphemeralStatusExpired, models.EphemeralStatusFailed:
		query = `
			UPDATE ephemeral_environments
			SET status = $1, error_message = $2, stopped_at = $3
			WHERE id = $4`
		args = []interface{}{status, errorMsg, now, id}
	default:
		query = `
			UPDATE ephemeral_environments
			SET status = $1, error_message = $2
			WHERE id = $3`
		args = []interface{}{status, errorMsg, id}
	}

	result, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update ephemeral environment status")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("ephemeral environment")
	}
	return nil
}

// UpdateTTL persists the new TTL and expiry time for an ephemeral environment.
func (r *EphemeralEnvironmentRepository) UpdateTTL(ctx context.Context, id uuid.UUID, ttlMinutes int, expiresAt time.Time) error {
	result, err := r.db.Exec(ctx, `
		UPDATE ephemeral_environments
		SET ttl_minutes = $1, expires_at = $2, updated_at = NOW()
		WHERE id = $3`, ttlMinutes, expiresAt, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update ephemeral environment TTL")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("ephemeral environment")
	}
	return nil
}

// SetURL updates the access URL for an ephemeral environment.
func (r *EphemeralEnvironmentRepository) SetURL(ctx context.Context, id uuid.UUID, url string) error {
	result, err := r.db.Exec(ctx, `
		UPDATE ephemeral_environments SET url = $1 WHERE id = $2`, url, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to set ephemeral environment URL")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("ephemeral environment")
	}
	return nil
}

// Delete removes an ephemeral environment by ID.
func (r *EphemeralEnvironmentRepository) Delete(ctx context.Context, id uuid.UUID) error {
	result, err := r.db.Exec(ctx, `DELETE FROM ephemeral_environments WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete ephemeral environment")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("ephemeral environment")
	}
	return nil
}

// ListExpired returns all running environments that have passed their expiry time.
func (r *EphemeralEnvironmentRepository) ListExpired(ctx context.Context) ([]*models.EphemeralEnvironment, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM ephemeral_environments
		WHERE status = 'running' AND expires_at IS NOT NULL AND expires_at < NOW()
		ORDER BY expires_at ASC`, ephemeralEnvColumns)

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list expired ephemeral environments")
	}
	defer rows.Close()

	envs, err := scanEphemeralEnvRows(rows)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan expired ephemeral environment rows")
	}
	return envs, nil
}

// CountByStatus returns the count of ephemeral environments grouped by status.
func (r *EphemeralEnvironmentRepository) CountByStatus(ctx context.Context) (map[string]int, error) {
	rows, err := r.db.Query(ctx, `
		SELECT status, COUNT(*) AS count
		FROM ephemeral_environments
		GROUP BY status`)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to count ephemeral environments by status")
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan ephemeral environment status count")
		}
		counts[status] = count
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to iterate ephemeral environment status counts")
	}
	return counts, nil
}

// CreateLog inserts a new ephemeral environment log entry.
func (r *EphemeralEnvironmentRepository) CreateLog(ctx context.Context, l *models.EphemeralEnvironmentLog) error {
	if l.ID == uuid.Nil {
		l.ID = uuid.New()
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO ephemeral_environment_logs (
			id, environment_id, phase, message, level, metadata
		) VALUES ($1, $2, $3, $4, $5, $6)`,
		l.ID, l.EnvironmentID, l.Phase, l.Message, l.Level, l.Metadata,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create ephemeral environment log")
	}
	return nil
}

// ListLogs returns recent log entries for an ephemeral environment.
func (r *EphemeralEnvironmentRepository) ListLogs(ctx context.Context, environmentID uuid.UUID, limit int) ([]*models.EphemeralEnvironmentLog, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := r.db.Query(ctx, `
		SELECT id, environment_id, phase, message, level, metadata, created_at
		FROM ephemeral_environment_logs
		WHERE environment_id = $1
		ORDER BY created_at DESC
		LIMIT $2`, environmentID, limit)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list ephemeral environment logs")
	}
	defer rows.Close()

	var logs []*models.EphemeralEnvironmentLog
	for rows.Next() {
		var l models.EphemeralEnvironmentLog
		if err := rows.Scan(
			&l.ID, &l.EnvironmentID, &l.Phase, &l.Message, &l.Level, &l.Metadata, &l.CreatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan ephemeral environment log row")
		}
		logs = append(logs, &l)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to iterate ephemeral environment log rows")
	}
	return logs, nil
}

// ============================================================================
// ManifestBuilderRepository
// ============================================================================

// ManifestBuilderRepository handles CRUD for manifest templates, builder
// sessions, and reusable components.
type ManifestBuilderRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewManifestBuilderRepository creates a new ManifestBuilderRepository.
func NewManifestBuilderRepository(db *DB, log *logger.Logger) *ManifestBuilderRepository {
	return &ManifestBuilderRepository{
		db:     db,
		logger: log.Named("manifest_builder_repo"),
	}
}

// manifestTemplateColumns is the standard column list for manifest_templates queries.
const manifestTemplateColumns = `id, name, description, format, category, icon, version,
	content, variables, is_public, is_builtin, usage_count, tags,
	created_by, created_at, updated_at`

// scanManifestTemplate scans a single row into a models.ManifestTemplate.
func scanManifestTemplate(row pgx.Row) (*models.ManifestTemplate, error) {
	var t models.ManifestTemplate
	err := row.Scan(
		&t.ID, &t.Name, &t.Description, &t.Format, &t.Category, &t.Icon, &t.Version,
		&t.Content, &t.Variables, &t.IsPublic, &t.IsBuiltin, &t.UsageCount, &t.Tags,
		&t.CreatedBy, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// scanManifestTemplateRows scans multiple rows into a slice of models.ManifestTemplate.
func scanManifestTemplateRows(rows pgx.Rows) ([]*models.ManifestTemplate, error) {
	var templates []*models.ManifestTemplate
	for rows.Next() {
		var t models.ManifestTemplate
		err := rows.Scan(
			&t.ID, &t.Name, &t.Description, &t.Format, &t.Category, &t.Icon, &t.Version,
			&t.Content, &t.Variables, &t.IsPublic, &t.IsBuiltin, &t.UsageCount, &t.Tags,
			&t.CreatedBy, &t.CreatedAt, &t.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		templates = append(templates, &t)
	}
	return templates, rows.Err()
}

// CreateTemplate inserts a new manifest template.
func (r *ManifestBuilderRepository) CreateTemplate(ctx context.Context, t *models.ManifestTemplate) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO manifest_templates (
			id, name, description, format, category, icon, version,
			content, variables, is_public, is_builtin, tags, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12, $13
		)`,
		t.ID, t.Name, t.Description, t.Format, t.Category, t.Icon, t.Version,
		t.Content, t.Variables, t.IsPublic, t.IsBuiltin, t.Tags, t.CreatedBy,
	)
	if err != nil {
		if IsDuplicateKeyError(err) {
			return errors.AlreadyExists("manifest template")
		}
		r.logger.Error("Failed to create manifest template", "name", t.Name, "error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create manifest template")
	}
	return nil
}

// GetTemplate retrieves a manifest template by ID.
func (r *ManifestBuilderRepository) GetTemplate(ctx context.Context, id uuid.UUID) (*models.ManifestTemplate, error) {
	query := fmt.Sprintf(`SELECT %s FROM manifest_templates WHERE id = $1`, manifestTemplateColumns)
	t, err := scanManifestTemplate(r.db.QueryRow(ctx, query, id))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("manifest template")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get manifest template")
	}
	return t, nil
}

// ListTemplates returns manifest templates, optionally filtered by format and category.
func (r *ManifestBuilderRepository) ListTemplates(ctx context.Context, format string, category string) ([]*models.ManifestTemplate, error) {
	var conditions []string
	var args []interface{}
	argNum := 1

	if format != "" {
		conditions = append(conditions, fmt.Sprintf("format = $%d", argNum))
		args = append(args, format)
		argNum++
	}
	if category != "" {
		conditions = append(conditions, fmt.Sprintf("category = $%d", argNum))
		args = append(args, category)
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(`SELECT %s FROM manifest_templates %s ORDER BY name ASC`,
		manifestTemplateColumns, whereClause)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list manifest templates")
	}
	defer rows.Close()

	templates, err := scanManifestTemplateRows(rows)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan manifest template rows")
	}
	return templates, nil
}

// UpdateTemplate updates an existing manifest template.
func (r *ManifestBuilderRepository) UpdateTemplate(ctx context.Context, t *models.ManifestTemplate) error {
	result, err := r.db.Exec(ctx, `
		UPDATE manifest_templates
		SET name = $1, description = $2, format = $3, category = $4,
			icon = $5, version = $6, content = $7, variables = $8,
			is_public = $9, tags = $10
		WHERE id = $11`,
		t.Name, t.Description, t.Format, t.Category,
		t.Icon, t.Version, t.Content, t.Variables,
		t.IsPublic, t.Tags,
		t.ID,
	)
	if err != nil {
		r.logger.Error("Failed to update manifest template", "id", t.ID, "error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update manifest template")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("manifest template")
	}
	return nil
}

// DeleteTemplate removes a manifest template by ID.
func (r *ManifestBuilderRepository) DeleteTemplate(ctx context.Context, id uuid.UUID) error {
	result, err := r.db.Exec(ctx, `DELETE FROM manifest_templates WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete manifest template")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("manifest template")
	}
	return nil
}

// IncrementTemplateUsage atomically increments the usage count for a template.
func (r *ManifestBuilderRepository) IncrementTemplateUsage(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE manifest_templates SET usage_count = usage_count + 1 WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to increment manifest template usage count")
	}
	return nil
}

// ListTemplateCategories returns all distinct template categories.
func (r *ManifestBuilderRepository) ListTemplateCategories(ctx context.Context) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT category FROM manifest_templates ORDER BY category ASC`)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list manifest template categories")
	}
	defer rows.Close()

	var categories []string
	for rows.Next() {
		var cat string
		if err := rows.Scan(&cat); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan manifest template category")
		}
		categories = append(categories, cat)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to iterate manifest template categories")
	}
	return categories, nil
}

// manifestSessionColumns is the standard column list for manifest_builder_sessions queries.
const manifestSessionColumns = `id, name, user_id, template_id, format,
	canvas_state, services, networks, volumes,
	generated_manifest, validation_errors, is_saved,
	last_git_push_at, last_deploy_at, created_at, updated_at`

// scanManifestSession scans a single row into a models.ManifestBuilderSession.
func scanManifestSession(row pgx.Row) (*models.ManifestBuilderSession, error) {
	var s models.ManifestBuilderSession
	err := row.Scan(
		&s.ID, &s.Name, &s.UserID, &s.TemplateID, &s.Format,
		&s.CanvasState, &s.Services, &s.Networks, &s.Volumes,
		&s.GeneratedManifest, &s.ValidationErrors, &s.IsSaved,
		&s.LastGitPushAt, &s.LastDeployAt, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// CreateSession inserts a new manifest builder session.
func (r *ManifestBuilderRepository) CreateSession(ctx context.Context, s *models.ManifestBuilderSession) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO manifest_builder_sessions (
			id, name, user_id, template_id, format,
			canvas_state, services, networks, volumes,
			generated_manifest, validation_errors, is_saved
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12
		)`,
		s.ID, s.Name, s.UserID, s.TemplateID, s.Format,
		s.CanvasState, s.Services, s.Networks, s.Volumes,
		s.GeneratedManifest, s.ValidationErrors, s.IsSaved,
	)
	if err != nil {
		r.logger.Error("Failed to create manifest builder session",
			"name", s.Name, "user_id", s.UserID, "error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create manifest builder session")
	}
	return nil
}

// GetSession retrieves a manifest builder session by ID.
func (r *ManifestBuilderRepository) GetSession(ctx context.Context, id uuid.UUID) (*models.ManifestBuilderSession, error) {
	query := fmt.Sprintf(`SELECT %s FROM manifest_builder_sessions WHERE id = $1`, manifestSessionColumns)
	s, err := scanManifestSession(r.db.QueryRow(ctx, query, id))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("manifest builder session")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get manifest builder session")
	}
	return s, nil
}

// ListSessions returns all manifest builder sessions for a user.
func (r *ManifestBuilderRepository) ListSessions(ctx context.Context, userID uuid.UUID) ([]*models.ManifestBuilderSession, error) {
	query := fmt.Sprintf(`SELECT %s FROM manifest_builder_sessions WHERE user_id = $1 ORDER BY updated_at DESC`,
		manifestSessionColumns)

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list manifest builder sessions")
	}
	defer rows.Close()

	var sessions []*models.ManifestBuilderSession
	for rows.Next() {
		var s models.ManifestBuilderSession
		if err := rows.Scan(
			&s.ID, &s.Name, &s.UserID, &s.TemplateID, &s.Format,
			&s.CanvasState, &s.Services, &s.Networks, &s.Volumes,
			&s.GeneratedManifest, &s.ValidationErrors, &s.IsSaved,
			&s.LastGitPushAt, &s.LastDeployAt, &s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan manifest builder session row")
		}
		sessions = append(sessions, &s)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to iterate manifest builder session rows")
	}
	return sessions, nil
}

// UpdateSession updates an existing manifest builder session.
func (r *ManifestBuilderRepository) UpdateSession(ctx context.Context, s *models.ManifestBuilderSession) error {
	result, err := r.db.Exec(ctx, `
		UPDATE manifest_builder_sessions
		SET name = $1, template_id = $2, format = $3,
			canvas_state = $4, services = $5, networks = $6, volumes = $7,
			generated_manifest = $8, validation_errors = $9, is_saved = $10,
			last_git_push_at = $11, last_deploy_at = $12
		WHERE id = $13`,
		s.Name, s.TemplateID, s.Format,
		s.CanvasState, s.Services, s.Networks, s.Volumes,
		s.GeneratedManifest, s.ValidationErrors, s.IsSaved,
		s.LastGitPushAt, s.LastDeployAt,
		s.ID,
	)
	if err != nil {
		r.logger.Error("Failed to update manifest builder session", "id", s.ID, "error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update manifest builder session")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("manifest builder session")
	}
	return nil
}

// DeleteSession removes a manifest builder session by ID.
func (r *ManifestBuilderRepository) DeleteSession(ctx context.Context, id uuid.UUID) error {
	result, err := r.db.Exec(ctx, `DELETE FROM manifest_builder_sessions WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete manifest builder session")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("manifest builder session")
	}
	return nil
}

// manifestComponentColumns is the standard column list for manifest_builder_components queries.
const manifestComponentColumns = `id, name, description, category, icon,
	default_config, ports, volumes, environment, health_check, depends_on,
	is_builtin, created_by, created_at, updated_at`

// scanManifestComponent scans a single row into a models.ManifestBuilderComponent.
func scanManifestComponent(row pgx.Row) (*models.ManifestBuilderComponent, error) {
	var c models.ManifestBuilderComponent
	err := row.Scan(
		&c.ID, &c.Name, &c.Description, &c.Category, &c.Icon,
		&c.DefaultConfig, &c.Ports, &c.Volumes, &c.Environment, &c.HealthCheck, &c.DependsOn,
		&c.IsBuiltin, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// scanManifestComponentRows scans multiple rows into a slice of models.ManifestBuilderComponent.
func scanManifestComponentRows(rows pgx.Rows) ([]*models.ManifestBuilderComponent, error) {
	var components []*models.ManifestBuilderComponent
	for rows.Next() {
		var c models.ManifestBuilderComponent
		err := rows.Scan(
			&c.ID, &c.Name, &c.Description, &c.Category, &c.Icon,
			&c.DefaultConfig, &c.Ports, &c.Volumes, &c.Environment, &c.HealthCheck, &c.DependsOn,
			&c.IsBuiltin, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		components = append(components, &c)
	}
	return components, rows.Err()
}

// CreateComponent inserts a new manifest builder component.
func (r *ManifestBuilderRepository) CreateComponent(ctx context.Context, c *models.ManifestBuilderComponent) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO manifest_builder_components (
			id, name, description, category, icon,
			default_config, ports, volumes, environment, health_check, depends_on,
			is_builtin, created_by
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10, $11,
			$12, $13
		)`,
		c.ID, c.Name, c.Description, c.Category, c.Icon,
		c.DefaultConfig, c.Ports, c.Volumes, c.Environment, c.HealthCheck, c.DependsOn,
		c.IsBuiltin, c.CreatedBy,
	)
	if err != nil {
		if IsDuplicateKeyError(err) {
			return errors.AlreadyExists("manifest builder component")
		}
		r.logger.Error("Failed to create manifest builder component", "name", c.Name, "error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create manifest builder component")
	}
	return nil
}

// GetComponent retrieves a manifest builder component by ID.
func (r *ManifestBuilderRepository) GetComponent(ctx context.Context, id uuid.UUID) (*models.ManifestBuilderComponent, error) {
	query := fmt.Sprintf(`SELECT %s FROM manifest_builder_components WHERE id = $1`, manifestComponentColumns)
	c, err := scanManifestComponent(r.db.QueryRow(ctx, query, id))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("manifest builder component")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get manifest builder component")
	}
	return c, nil
}

// ListComponents returns manifest builder components, optionally filtered by category.
func (r *ManifestBuilderRepository) ListComponents(ctx context.Context, category string) ([]*models.ManifestBuilderComponent, error) {
	var query string
	var args []interface{}

	if category != "" {
		query = fmt.Sprintf(`SELECT %s FROM manifest_builder_components WHERE category = $1 ORDER BY name ASC`,
			manifestComponentColumns)
		args = append(args, category)
	} else {
		query = fmt.Sprintf(`SELECT %s FROM manifest_builder_components ORDER BY name ASC`,
			manifestComponentColumns)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list manifest builder components")
	}
	defer rows.Close()

	components, err := scanManifestComponentRows(rows)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan manifest builder component rows")
	}
	return components, nil
}

// DeleteComponent removes a manifest builder component by ID.
func (r *ManifestBuilderRepository) DeleteComponent(ctx context.Context, id uuid.UUID) error {
	result, err := r.db.Exec(ctx, `DELETE FROM manifest_builder_components WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete manifest builder component")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("manifest builder component")
	}
	return nil
}

// builtinComponent defines a built-in component for seeding.
type builtinComponent struct {
	Name          string
	Description   string
	Category      string
	Icon          string
	DefaultConfig map[string]interface{}
	Ports         []map[string]interface{}
	Volumes       []map[string]interface{}
	Environment   []map[string]interface{}
	HealthCheck   map[string]interface{}
	DependsOn     []string
}

// SeedBuiltinComponents seeds common Docker service blocks into the components
// library. It only inserts components where a component with the same name and
// is_builtin = true does not already exist.
func (r *ManifestBuilderRepository) SeedBuiltinComponents(ctx context.Context) error {
	components := []builtinComponent{
		{
			Name:        "postgres",
			Description: "PostgreSQL relational database",
			Category:    "database",
			Icon:        "fa-database",
			DefaultConfig: map[string]interface{}{
				"image":   "postgres:16-alpine",
				"restart": "unless-stopped",
			},
			Ports: []map[string]interface{}{
				{"host": 5432, "container": 5432, "protocol": "tcp"},
			},
			Volumes: []map[string]interface{}{
				{"source": "postgres_data", "target": "/var/lib/postgresql/data", "type": "volume"},
			},
			Environment: []map[string]interface{}{
				{"name": "POSTGRES_DB", "value": "app", "required": true},
				{"name": "POSTGRES_USER", "value": "postgres", "required": true},
				{"name": "POSTGRES_PASSWORD", "value": "", "required": true},
			},
			HealthCheck: map[string]interface{}{
				"test": "pg_isready -U postgres", "interval": "10s", "timeout": "5s", "retries": 5,
			},
		},
		{
			Name:        "redis",
			Description: "Redis in-memory data store",
			Category:    "database",
			Icon:        "fa-bolt",
			DefaultConfig: map[string]interface{}{
				"image":   "redis:7-alpine",
				"restart": "unless-stopped",
			},
			Ports: []map[string]interface{}{
				{"host": 6379, "container": 6379, "protocol": "tcp"},
			},
			Volumes: []map[string]interface{}{
				{"source": "redis_data", "target": "/data", "type": "volume"},
			},
			Environment: []map[string]interface{}{},
			HealthCheck: map[string]interface{}{
				"test": "redis-cli ping", "interval": "10s", "timeout": "5s", "retries": 5,
			},
		},
		{
			Name:        "nginx",
			Description: "Nginx web server and reverse proxy",
			Category:    "web",
			Icon:        "fa-server",
			DefaultConfig: map[string]interface{}{
				"image":   "nginx:alpine",
				"restart": "unless-stopped",
			},
			Ports: []map[string]interface{}{
				{"host": 80, "container": 80, "protocol": "tcp"},
				{"host": 443, "container": 443, "protocol": "tcp"},
			},
			Volumes: []map[string]interface{}{
				{"source": "./nginx.conf", "target": "/etc/nginx/nginx.conf", "type": "bind", "read_only": true},
			},
			Environment: []map[string]interface{}{},
			HealthCheck: map[string]interface{}{
				"test": "curl -f http://localhost/ || exit 1", "interval": "30s", "timeout": "10s", "retries": 3,
			},
		},
		{
			Name:        "traefik",
			Description: "Traefik reverse proxy and load balancer",
			Category:    "web",
			Icon:        "fa-route",
			DefaultConfig: map[string]interface{}{
				"image":   "traefik:v3.0",
				"restart": "unless-stopped",
			},
			Ports: []map[string]interface{}{
				{"host": 80, "container": 80, "protocol": "tcp"},
				{"host": 443, "container": 443, "protocol": "tcp"},
				{"host": 8080, "container": 8080, "protocol": "tcp"},
			},
			Volumes: []map[string]interface{}{
				{"source": "/var/run/docker.sock", "target": "/var/run/docker.sock", "type": "bind", "read_only": true},
			},
			Environment: []map[string]interface{}{},
			HealthCheck: map[string]interface{}{
				"test": "traefik healthcheck", "interval": "30s", "timeout": "10s", "retries": 3,
			},
		},
		{
			Name:        "mysql",
			Description: "MySQL relational database",
			Category:    "database",
			Icon:        "fa-database",
			DefaultConfig: map[string]interface{}{
				"image":   "mysql:8.0",
				"restart": "unless-stopped",
			},
			Ports: []map[string]interface{}{
				{"host": 3306, "container": 3306, "protocol": "tcp"},
			},
			Volumes: []map[string]interface{}{
				{"source": "mysql_data", "target": "/var/lib/mysql", "type": "volume"},
			},
			Environment: []map[string]interface{}{
				{"name": "MYSQL_ROOT_PASSWORD", "value": "", "required": true},
				{"name": "MYSQL_DATABASE", "value": "app", "required": true},
				{"name": "MYSQL_USER", "value": "app", "required": false},
				{"name": "MYSQL_PASSWORD", "value": "", "required": false},
			},
			HealthCheck: map[string]interface{}{
				"test": "mysqladmin ping -h localhost", "interval": "10s", "timeout": "5s", "retries": 5,
			},
		},
		{
			Name:        "mongodb",
			Description: "MongoDB document database",
			Category:    "database",
			Icon:        "fa-leaf",
			DefaultConfig: map[string]interface{}{
				"image":   "mongo:7",
				"restart": "unless-stopped",
			},
			Ports: []map[string]interface{}{
				{"host": 27017, "container": 27017, "protocol": "tcp"},
			},
			Volumes: []map[string]interface{}{
				{"source": "mongo_data", "target": "/data/db", "type": "volume"},
			},
			Environment: []map[string]interface{}{
				{"name": "MONGO_INITDB_ROOT_USERNAME", "value": "admin", "required": true},
				{"name": "MONGO_INITDB_ROOT_PASSWORD", "value": "", "required": true},
			},
			HealthCheck: map[string]interface{}{
				"test": "mongosh --eval 'db.adminCommand(\"ping\")'", "interval": "10s", "timeout": "5s", "retries": 5,
			},
		},
		{
			Name:        "grafana",
			Description: "Grafana observability and dashboards",
			Category:    "monitoring",
			Icon:        "fa-chart-line",
			DefaultConfig: map[string]interface{}{
				"image":   "grafana/grafana:latest",
				"restart": "unless-stopped",
			},
			Ports: []map[string]interface{}{
				{"host": 3000, "container": 3000, "protocol": "tcp"},
			},
			Volumes: []map[string]interface{}{
				{"source": "grafana_data", "target": "/var/lib/grafana", "type": "volume"},
			},
			Environment: []map[string]interface{}{
				{"name": "GF_SECURITY_ADMIN_USER", "value": "admin", "required": false},
				{"name": "GF_SECURITY_ADMIN_PASSWORD", "value": "", "required": false},
			},
			HealthCheck: map[string]interface{}{
				"test": "curl -f http://localhost:3000/api/health || exit 1", "interval": "30s", "timeout": "10s", "retries": 3,
			},
		},
		{
			Name:        "prometheus",
			Description: "Prometheus monitoring and alerting toolkit",
			Category:    "monitoring",
			Icon:        "fa-fire",
			DefaultConfig: map[string]interface{}{
				"image":   "prom/prometheus:latest",
				"restart": "unless-stopped",
			},
			Ports: []map[string]interface{}{
				{"host": 9090, "container": 9090, "protocol": "tcp"},
			},
			Volumes: []map[string]interface{}{
				{"source": "prometheus_data", "target": "/prometheus", "type": "volume"},
				{"source": "./prometheus.yml", "target": "/etc/prometheus/prometheus.yml", "type": "bind", "read_only": true},
			},
			Environment: []map[string]interface{}{},
			HealthCheck: map[string]interface{}{
				"test": "wget --no-verbose --tries=1 --spider http://localhost:9090/-/healthy || exit 1", "interval": "30s", "timeout": "10s", "retries": 3,
			},
		},
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to begin transaction for seeding components")
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	for _, comp := range components {
		defaultConfigJSON, err := json.Marshal(comp.DefaultConfig)
		if err != nil {
			return fmt.Errorf("failed to marshal default config for %s: %w", comp.Name, err)
		}
		portsJSON, err := json.Marshal(comp.Ports)
		if err != nil {
			return fmt.Errorf("failed to marshal ports for %s: %w", comp.Name, err)
		}
		volumesJSON, err := json.Marshal(comp.Volumes)
		if err != nil {
			return fmt.Errorf("failed to marshal volumes for %s: %w", comp.Name, err)
		}
		envJSON, err := json.Marshal(comp.Environment)
		if err != nil {
			return fmt.Errorf("failed to marshal environment for %s: %w", comp.Name, err)
		}
		var healthCheckJSON []byte
		if comp.HealthCheck != nil {
			healthCheckJSON, err = json.Marshal(comp.HealthCheck)
			if err != nil {
				return fmt.Errorf("failed to marshal health check for %s: %w", comp.Name, err)
			}
		}
		dependsOnJSON, err := json.Marshal(comp.DependsOn)
		if err != nil {
			return fmt.Errorf("failed to marshal depends_on for %s: %w", comp.Name, err)
		}

		// JSONB columns bound as string; health_check is nullable so it
		// goes through nullableJSONBytes to preserve SQL NULL when the
		// component has no healthcheck. See encodeJSONObject in
		// recon_repo.go for the simple-protocol rationale.
		_, err = tx.Exec(ctx, `
			INSERT INTO manifest_builder_components (
				id, name, description, category, icon,
				default_config, ports, volumes, environment, health_check, depends_on,
				is_builtin
			)
			SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, true
			WHERE NOT EXISTS (
				SELECT 1 FROM manifest_builder_components
				WHERE name = $2 AND is_builtin = true
			)`,
			uuid.New(), comp.Name, comp.Description, comp.Category, comp.Icon,
			string(defaultConfigJSON), string(portsJSON), string(volumesJSON),
			string(envJSON), nullableJSONBytes(healthCheckJSON), string(dependsOnJSON),
		)
		if err != nil {
			return errors.Wrap(err, errors.CodeDatabaseError,
				fmt.Sprintf("failed to seed builtin component %s", comp.Name))
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to commit builtin component seed")
	}

	r.logger.Info("Seeded builtin manifest builder components", "count", len(components))
	return nil
}
