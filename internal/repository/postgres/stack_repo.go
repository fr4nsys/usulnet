// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package postgres provides PostgreSQL repository implementations.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/models"
)

// StackRepository handles stack database operations.
type StackRepository struct {
	db *DB
}

// NewStackRepository creates a new stack repository.
func NewStackRepository(db *DB) *StackRepository {
	return &StackRepository{db: db}
}

// ============================================================================
// CRUD Operations
// ============================================================================

// Create creates a new stack.
func (r *StackRepository) Create(ctx context.Context, stack *models.Stack) error {
	query := `
		INSERT INTO stacks (
			id, host_id, name, type, status, project_dir, compose_file, env_file,
			variables, service_count, running_count, git_repo, git_branch, git_commit,
			last_deployed_at, last_deployed_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`

	now := time.Now().UTC()
	stack.CreatedAt = now
	stack.UpdatedAt = now

	if stack.ID == uuid.Nil {
		stack.ID = uuid.New()
	}

	_, err := r.db.Exec(ctx, query,
		stack.ID,
		stack.HostID,
		stack.Name,
		stack.Type,
		stack.Status,
		stack.ProjectDir,
		stack.ComposeFile,
		stack.EnvFile,
		stack.Variables,
		stack.ServiceCount,
		stack.RunningCount,
		stack.GitRepo,
		stack.GitBranch,
		stack.GitCommit,
		stack.LastDeployedAt,
		stack.LastDeployedBy,
		stack.CreatedAt,
		stack.UpdatedAt,
	)

	if err != nil {
		if IsDuplicateKeyError(err) {
			return apperrors.AlreadyExists("stack")
		}
		return fmt.Errorf("create stack: %w", err)
	}

	return nil
}

// GetByID retrieves a stack by ID.
func (r *StackRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Stack, error) {
	query := `
		SELECT id, host_id, name, type, status, project_dir, compose_file, env_file,
			   variables, service_count, running_count, git_repo, git_branch, git_commit,
			   last_deployed_at, last_deployed_by, created_at, updated_at
		FROM stacks
		WHERE id = $1`

	return r.scanStack(r.db.QueryRow(ctx, query, id))
}

// GetByName retrieves a stack by name within a host.
func (r *StackRepository) GetByName(ctx context.Context, hostID uuid.UUID, name string) (*models.Stack, error) {
	query := `
		SELECT id, host_id, name, type, status, project_dir, compose_file, env_file,
			   variables, service_count, running_count, git_repo, git_branch, git_commit,
			   last_deployed_at, last_deployed_by, created_at, updated_at
		FROM stacks
		WHERE host_id = $1 AND name = $2`

	return r.scanStack(r.db.QueryRow(ctx, query, hostID, name))
}

// Update updates a stack.
func (r *StackRepository) Update(ctx context.Context, stack *models.Stack) error {
	query := `
		UPDATE stacks SET
			type = $2,
			project_dir = $3,
			compose_file = $4,
			env_file = $5,
			variables = $6,
			git_repo = $7,
			git_branch = $8,
			git_commit = $9,
			updated_at = $10
		WHERE id = $1`

	stack.UpdatedAt = time.Now().UTC()

	result, err := r.db.Exec(ctx, query,
		stack.ID,
		stack.Type,
		stack.ProjectDir,
		stack.ComposeFile,
		stack.EnvFile,
		stack.Variables,
		stack.GitRepo,
		stack.GitBranch,
		stack.GitCommit,
		stack.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("update stack: %w", err)
	}

	if result.RowsAffected() == 0 {
		return apperrors.NotFound("stack")
	}

	return nil
}

// Delete removes a stack.
func (r *StackRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM stacks WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete stack: %w", err)
	}

	if result.RowsAffected() == 0 {
		return apperrors.NotFound("stack")
	}

	return nil
}

// ExistsByName checks if a stack with the given name exists for a host.
func (r *StackRepository) ExistsByName(ctx context.Context, hostID uuid.UUID, name string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM stacks WHERE host_id = $1 AND name = $2)`

	var exists bool
	if err := r.db.QueryRow(ctx, query, hostID, name).Scan(&exists); err != nil {
		return false, fmt.Errorf("check stack exists: %w", err)
	}

	return exists, nil
}

// scanStack scans a row into a Stack model.
func (r *StackRepository) scanStack(row pgx.Row) (*models.Stack, error) {
	stack := &models.Stack{}
	err := row.Scan(
		&stack.ID,
		&stack.HostID,
		&stack.Name,
		&stack.Type,
		&stack.Status,
		&stack.ProjectDir,
		&stack.ComposeFile,
		&stack.EnvFile,
		&stack.Variables,
		&stack.ServiceCount,
		&stack.RunningCount,
		&stack.GitRepo,
		&stack.GitBranch,
		&stack.GitCommit,
		&stack.LastDeployedAt,
		&stack.LastDeployedBy,
		&stack.CreatedAt,
		&stack.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.NotFound("stack")
		}
		return nil, fmt.Errorf("scan stack: %w", err)
	}

	return stack, nil
}

// ============================================================================
// List Operations
// ============================================================================

// StackListOptions contains options for listing stacks.
type StackListOptions struct {
	Page     int
	PerPage  int
	HostID   *uuid.UUID
	Search   string
	Status   *models.StackStatus
	Type     *models.StackType
	SortBy   string
	SortDesc bool

	// Scoping fields (opt-in model)
	// When ScopeEnabled is true, only show stacks that are in AllowedIDs
	// OR that are not in AssignedIDs (unassigned = visible to all).
	ScopeEnabled bool
	AllowedIDs   []uuid.UUID // stack IDs the user's teams have access to
	AssignedIDs  []uuid.UUID // stack IDs that ANY team has claimed
}

// List retrieves stacks with pagination and filtering.
func (r *StackRepository) List(ctx context.Context, opts StackListOptions) ([]*models.Stack, int64, error) {
	// Build WHERE clause
	var conditions []string
	var args []interface{}
	argNum := 1

	if opts.HostID != nil {
		conditions = append(conditions, fmt.Sprintf("host_id = $%d", argNum))
		args = append(args, *opts.HostID)
		argNum++
	}

	if opts.Search != "" {
		conditions = append(conditions, fmt.Sprintf("LOWER(name) LIKE LOWER($%d)", argNum))
		args = append(args, "%"+opts.Search+"%")
		argNum++
	}

	if opts.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argNum))
		args = append(args, *opts.Status)
		argNum++
	}

	if opts.Type != nil {
		conditions = append(conditions, fmt.Sprintf("type = $%d", argNum))
		args = append(args, *opts.Type)
		argNum++
	}

	// Resource scoping: show allowed stacks OR unassigned stacks
	if opts.ScopeEnabled {
		if len(opts.AssignedIDs) == 0 {
			// No resources assigned to any team → everything visible (no filter)
		} else if len(opts.AllowedIDs) == 0 {
			// User has no allowed stacks → only show unassigned
			conditions = append(conditions, fmt.Sprintf("NOT (id = ANY($%d))", argNum))
			args = append(args, opts.AssignedIDs)
			argNum++
		} else {
			// Show allowed OR unassigned
			conditions = append(conditions, fmt.Sprintf(
				"(id = ANY($%d) OR NOT (id = ANY($%d)))",
				argNum, argNum+1,
			))
			args = append(args, opts.AllowedIDs, opts.AssignedIDs)
			argNum += 2
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM stacks %s", whereClause)
	var total int64
	if err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count stacks: %w", err)
	}

	// Build ORDER BY
	sortField := "name"
	allowedSortFields := map[string]bool{
		"name": true, "status": true, "type": true, "created_at": true,
		"updated_at": true, "last_deployed_at": true, "service_count": true,
	}
	if opts.SortBy != "" && allowedSortFields[opts.SortBy] {
		sortField = opts.SortBy
	}

	sortOrder := "ASC"
	if opts.SortDesc {
		sortOrder = "DESC"
	}

	// Pagination
	if opts.Page < 1 {
		opts.Page = 1
	}
	if opts.PerPage < 1 || opts.PerPage > 100 {
		opts.PerPage = 20
	}
	offset := (opts.Page - 1) * opts.PerPage

	// Query stacks
	query := fmt.Sprintf(`
		SELECT id, host_id, name, type, status, project_dir, compose_file, env_file,
			   variables, service_count, running_count, git_repo, git_branch, git_commit,
			   last_deployed_at, last_deployed_by, created_at, updated_at
		FROM stacks
		%s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d`,
		whereClause, sortField, sortOrder, argNum, argNum+1,
	)
	args = append(args, opts.PerPage, offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list stacks: %w", err)
	}
	defer rows.Close()

	stacks, err := r.scanStacks(rows)
	if err != nil {
		return nil, 0, err
	}

	return stacks, total, nil
}

// ListByHost retrieves all stacks for a host.
func (r *StackRepository) ListByHost(ctx context.Context, hostID uuid.UUID) ([]*models.Stack, error) {
	stacks, _, err := r.List(ctx, StackListOptions{
		HostID:  &hostID,
		PerPage: 10000,
	})
	return stacks, err
}

// ListActive retrieves all active stacks.
func (r *StackRepository) ListActive(ctx context.Context) ([]*models.Stack, error) {
	status := models.StackStatusActive
	stacks, _, err := r.List(ctx, StackListOptions{
		Status:  &status,
		PerPage: 10000,
	})
	return stacks, err
}

// scanStacks scans multiple rows into Stack models.
func (r *StackRepository) scanStacks(rows pgx.Rows) ([]*models.Stack, error) {
	var stacks []*models.Stack
	for rows.Next() {
		stack := &models.Stack{}
		if err := rows.Scan(
			&stack.ID,
			&stack.HostID,
			&stack.Name,
			&stack.Type,
			&stack.Status,
			&stack.ProjectDir,
			&stack.ComposeFile,
			&stack.EnvFile,
			&stack.Variables,
			&stack.ServiceCount,
			&stack.RunningCount,
			&stack.GitRepo,
			&stack.GitBranch,
			&stack.GitCommit,
			&stack.LastDeployedAt,
			&stack.LastDeployedBy,
			&stack.CreatedAt,
			&stack.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan stack: %w", err)
		}
		stacks = append(stacks, stack)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate stacks: %w", err)
	}

	return stacks, nil
}

// ============================================================================
// Status Operations
// ============================================================================

// UpdateStatus updates the status of a stack.
func (r *StackRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.StackStatus) error {
	query := `
		UPDATE stacks SET
			status = $2,
			updated_at = $3
		WHERE id = $1`

	now := time.Now().UTC()
	result, err := r.db.Exec(ctx, query, id, status, now)
	if err != nil {
		return fmt.Errorf("update stack status: %w", err)
	}

	if result.RowsAffected() == 0 {
		return apperrors.NotFound("stack")
	}

	// Update last_deployed_at if deploying
	if status == models.StackStatusActive {
		r.db.Exec(ctx, "UPDATE stacks SET last_deployed_at = $2 WHERE id = $1", id, now)
	}

	return nil
}

// UpdateCounts updates the service and running counts for a stack.
func (r *StackRepository) UpdateCounts(ctx context.Context, id uuid.UUID, serviceCount, runningCount int) error {
	query := `UPDATE stacks SET service_count = $2, running_count = $3, updated_at = $4 WHERE id = $1`

	_, err := r.db.Exec(ctx, query, id, serviceCount, runningCount, time.Now().UTC())
	return err
}

// ============================================================================
// Statistics
// ============================================================================

// StackStats contains stack statistics.
type StackStats struct {
	Total    int64 `json:"total"`
	Active   int64 `json:"active"`
	Inactive int64 `json:"inactive"`
	Partial  int64 `json:"partial"`
	Error    int64 `json:"error"`
}

// GetStats retrieves stack statistics.
func (r *StackRepository) GetStats(ctx context.Context, hostID *uuid.UUID) (*StackStats, error) {
	query := `
		SELECT 
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE status = 'active') as active,
			COUNT(*) FILTER (WHERE status = 'inactive') as inactive,
			COUNT(*) FILTER (WHERE status = 'partial') as partial,
			COUNT(*) FILTER (WHERE status = 'error') as error
		FROM stacks`

	args := []interface{}{}
	if hostID != nil {
		query += " WHERE host_id = $1"
		args = append(args, *hostID)
	}

	stats := &StackStats{}
	err := r.db.QueryRow(ctx, query, args...).Scan(
		&stats.Total,
		&stats.Active,
		&stats.Inactive,
		&stats.Partial,
		&stats.Error,
	)

	if err != nil {
		return nil, fmt.Errorf("get stack stats: %w", err)
	}

	return stats, nil
}

// ============================================================================
// Deploy History (uses stack_logs table from migration)
// ============================================================================

// InsertDeployHistory inserts a deploy history record.
func (r *StackRepository) InsertDeployHistory(ctx context.Context, history *models.StackDeployHistory) error {
	query := `
		INSERT INTO stack_logs (
			stack_id, operation, status, output, error_msg, user_id, started_at, completed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id`

	var userID *uuid.UUID
	if history.TriggeredBy != "" {
		if uid, err := uuid.Parse(history.TriggeredBy); err == nil {
			userID = &uid
		}
	}

	err := r.db.QueryRow(ctx, query,
		history.StackID,
		"deploy",
		history.Status,
		history.Output,
		history.ErrorMessage,
		userID,
		history.StartedAt,
		history.FinishedAt,
	).Scan(&history.ID)

	if err != nil {
		return fmt.Errorf("insert deploy history: %w", err)
	}

	return nil
}

// GetDeployHistory retrieves deploy history for a stack.
func (r *StackRepository) GetDeployHistory(ctx context.Context, stackID uuid.UUID, limit int) ([]*models.StackDeployHistory, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	query := `
		SELECT id, stack_id, status, output, error_msg, started_at, completed_at,
			   COALESCE(user_id::text, '') as triggered_by
		FROM stack_logs
		WHERE stack_id = $1
		ORDER BY started_at DESC
		LIMIT $2`

	rows, err := r.db.Query(ctx, query, stackID, limit)
	if err != nil {
		return nil, fmt.Errorf("get deploy history: %w", err)
	}
	defer rows.Close()

	var history []*models.StackDeployHistory
	for rows.Next() {
		h := &models.StackDeployHistory{}
		if err := rows.Scan(
			&h.ID,
			&h.StackID,
			&h.Status,
			&h.Output,
			&h.ErrorMessage,
			&h.StartedAt,
			&h.FinishedAt,
			&h.TriggeredBy,
		); err != nil {
			return nil, fmt.Errorf("scan deploy history: %w", err)
		}
		history = append(history, h)
	}

	return history, rows.Err()
}

// GetLastDeploy retrieves the last deploy for a stack.
func (r *StackRepository) GetLastDeploy(ctx context.Context, stackID uuid.UUID) (*models.StackDeployHistory, error) {
	query := `
		SELECT id, stack_id, status, output, error_msg, started_at, completed_at,
			   COALESCE(user_id::text, '') as triggered_by
		FROM stack_logs
		WHERE stack_id = $1
		ORDER BY started_at DESC
		LIMIT 1`

	h := &models.StackDeployHistory{}
	err := r.db.QueryRow(ctx, query, stackID).Scan(
		&h.ID,
		&h.StackID,
		&h.Status,
		&h.Output,
		&h.ErrorMessage,
		&h.StartedAt,
		&h.FinishedAt,
		&h.TriggeredBy,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.NotFound("deploy history")
		}
		return nil, fmt.Errorf("get last deploy: %w", err)
	}

	return h, nil
}

// DeleteOldDeployHistory deletes old deploy history.
func (r *StackRepository) DeleteOldDeployHistory(ctx context.Context, olderThan time.Duration) (int64, error) {
	query := `DELETE FROM stack_logs WHERE started_at < $1`

	threshold := time.Now().UTC().Add(-olderThan)
	result, err := r.db.Exec(ctx, query, threshold)
	if err != nil {
		return 0, fmt.Errorf("delete old deploy history: %w", err)
	}

	return result.RowsAffected(), nil
}
