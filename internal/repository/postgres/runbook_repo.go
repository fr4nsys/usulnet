// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"fmt"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/google/uuid"
)

// RunbookRepository handles CRUD operations for runbooks.
type RunbookRepository struct {
	db *DB
}

// NewRunbookRepository creates a new runbook repository.
func NewRunbookRepository(db *DB) *RunbookRepository {
	return &RunbookRepository{db: db}
}

// Create creates a new runbook.
func (r *RunbookRepository) Create(ctx context.Context, rb *models.Runbook) error {
	if rb.ID == uuid.Nil {
		rb.ID = uuid.New()
	}
	if rb.Version == 0 {
		rb.Version = 1
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO runbooks (id, name, description, category, steps, is_enabled, version, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		rb.ID, rb.Name, rb.Description, rb.Category, rb.Steps,
		rb.IsEnabled, rb.Version, rb.CreatedBy,
	)
	return err
}

// GetByID retrieves a runbook by ID.
func (r *RunbookRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Runbook, error) {
	rb := &models.Runbook{}
	err := r.db.QueryRow(ctx, `
		SELECT id, name, description, category, steps, is_enabled, version,
			created_by, created_at, updated_at
		FROM runbooks WHERE id = $1`, id).Scan(
		&rb.ID, &rb.Name, &rb.Description, &rb.Category, &rb.Steps,
		&rb.IsEnabled, &rb.Version, &rb.CreatedBy, &rb.CreatedAt, &rb.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return rb, nil
}

// List returns runbooks with filtering.
func (r *RunbookRepository) List(ctx context.Context, opts models.RunbookListOptions) ([]*models.Runbook, int64, error) {
	query := `SELECT id, name, description, category, steps, is_enabled, version, created_by, created_at, updated_at FROM runbooks WHERE 1=1`
	countQuery := `SELECT COUNT(*) FROM runbooks WHERE 1=1`
	var args []interface{}
	argIdx := 1

	if opts.Category != nil {
		clause := fmt.Sprintf(" AND category = $%d", argIdx)
		query += clause
		countQuery += clause
		args = append(args, *opts.Category)
		argIdx++
	}
	if opts.IsEnabled != nil {
		clause := fmt.Sprintf(" AND is_enabled = $%d", argIdx)
		query += clause
		countQuery += clause
		args = append(args, *opts.IsEnabled)
		argIdx++
	}

	var total int64
	if err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query += " ORDER BY name ASC"
	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, opts.Limit)
		argIdx++
	}
	if opts.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, opts.Offset)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var runbooks []*models.Runbook
	for rows.Next() {
		rb := &models.Runbook{}
		if err := rows.Scan(
			&rb.ID, &rb.Name, &rb.Description, &rb.Category, &rb.Steps,
			&rb.IsEnabled, &rb.Version, &rb.CreatedBy, &rb.CreatedAt, &rb.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		runbooks = append(runbooks, rb)
	}
	return runbooks, total, nil
}

// Update updates a runbook.
func (r *RunbookRepository) Update(ctx context.Context, rb *models.Runbook) error {
	_, err := r.db.Exec(ctx, `
		UPDATE runbooks SET
			name=$2, description=$3, category=$4, steps=$5, is_enabled=$6, version=$7
		WHERE id=$1`,
		rb.ID, rb.Name, rb.Description, rb.Category, rb.Steps, rb.IsEnabled, rb.Version,
	)
	return err
}

// Delete deletes a runbook.
func (r *RunbookRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM runbooks WHERE id = $1`, id)
	return err
}

// CreateExecution creates a runbook execution record.
func (r *RunbookRepository) CreateExecution(ctx context.Context, exec *models.RunbookExecution) error {
	if exec.ID == uuid.Nil {
		exec.ID = uuid.New()
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO runbook_executions (id, runbook_id, status, trigger, trigger_ref, step_results, started_at, executed_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		exec.ID, exec.RunbookID, exec.Status, exec.Trigger, exec.TriggerRef,
		exec.StepResults, exec.StartedAt, exec.ExecutedBy,
	)
	return err
}

// UpdateExecution updates a runbook execution.
func (r *RunbookRepository) UpdateExecution(ctx context.Context, exec *models.RunbookExecution) error {
	_, err := r.db.Exec(ctx, `
		UPDATE runbook_executions SET status=$2, step_results=$3, finished_at=$4
		WHERE id=$1`,
		exec.ID, exec.Status, exec.StepResults, exec.FinishedAt,
	)
	return err
}

// ListExecutions returns executions for a runbook.
func (r *RunbookRepository) ListExecutions(ctx context.Context, runbookID uuid.UUID, limit int) ([]*models.RunbookExecution, error) {
	q := `SELECT id, runbook_id, status, trigger, trigger_ref, step_results, started_at, finished_at, executed_by, created_at
		FROM runbook_executions WHERE runbook_id = $1 ORDER BY started_at DESC`
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := r.db.Query(ctx, q, runbookID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var execs []*models.RunbookExecution
	for rows.Next() {
		e := &models.RunbookExecution{}
		if err := rows.Scan(
			&e.ID, &e.RunbookID, &e.Status, &e.Trigger, &e.TriggerRef,
			&e.StepResults, &e.StartedAt, &e.FinishedAt, &e.ExecutedBy, &e.CreatedAt,
		); err != nil {
			return nil, err
		}
		execs = append(execs, e)
	}
	return execs, nil
}

// GetExecution retrieves a single execution by ID.
func (r *RunbookRepository) GetExecution(ctx context.Context, id uuid.UUID) (*models.RunbookExecution, error) {
	e := &models.RunbookExecution{}
	err := r.db.QueryRow(ctx, `
		SELECT id, runbook_id, status, trigger, trigger_ref, step_results, started_at, finished_at, executed_by, created_at
		FROM runbook_executions WHERE id = $1`, id).Scan(
		&e.ID, &e.RunbookID, &e.Status, &e.Trigger, &e.TriggerRef,
		&e.StepResults, &e.StartedAt, &e.FinishedAt, &e.ExecutedBy, &e.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// GetCategories returns distinct runbook categories.
func (r *RunbookRepository) GetCategories(ctx context.Context) ([]string, error) {
	rows, err := r.db.Query(ctx, `SELECT DISTINCT category FROM runbooks WHERE category != '' ORDER BY category`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cats []string
	for rows.Next() {
		var cat string
		if err := rows.Scan(&cat); err != nil {
			return nil, err
		}
		cats = append(cats, cat)
	}
	return cats, nil
}

// AutoDeployRuleRepository handles CRUD for auto-deploy rules.
type AutoDeployRuleRepository struct {
	db *DB
}

// NewAutoDeployRuleRepository creates a new auto-deploy rule repository.
func NewAutoDeployRuleRepository(db *DB) *AutoDeployRuleRepository {
	return &AutoDeployRuleRepository{db: db}
}

// Create creates an auto-deploy rule.
func (r *AutoDeployRuleRepository) Create(ctx context.Context, rule *models.AutoDeployRule) error {
	if rule.ID == uuid.Nil {
		rule.ID = uuid.New()
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO auto_deploy_rules (id, name, source_type, source_repo, source_branch, target_stack_id, target_service, action, is_enabled, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		rule.ID, rule.Name, rule.SourceType, rule.SourceRepo, rule.SourceBranch,
		rule.TargetStackID, rule.TargetService, rule.Action, rule.IsEnabled, rule.CreatedBy,
	)
	return err
}

// List returns all auto-deploy rules.
func (r *AutoDeployRuleRepository) List(ctx context.Context) ([]*models.AutoDeployRule, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, source_type, source_repo, source_branch, target_stack_id, target_service,
			action, is_enabled, last_triggered_at, created_by, created_at, updated_at
		FROM auto_deploy_rules ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*models.AutoDeployRule
	for rows.Next() {
		rule := &models.AutoDeployRule{}
		if err := rows.Scan(
			&rule.ID, &rule.Name, &rule.SourceType, &rule.SourceRepo, &rule.SourceBranch,
			&rule.TargetStackID, &rule.TargetService, &rule.Action, &rule.IsEnabled,
			&rule.LastTriggeredAt, &rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt,
		); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// GetByID retrieves an auto-deploy rule by ID.
func (r *AutoDeployRuleRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.AutoDeployRule, error) {
	rule := &models.AutoDeployRule{}
	err := r.db.QueryRow(ctx, `
		SELECT id, name, source_type, source_repo, source_branch, target_stack_id, target_service,
			action, is_enabled, last_triggered_at, created_by, created_at, updated_at
		FROM auto_deploy_rules WHERE id = $1`, id).Scan(
		&rule.ID, &rule.Name, &rule.SourceType, &rule.SourceRepo, &rule.SourceBranch,
		&rule.TargetStackID, &rule.TargetService, &rule.Action, &rule.IsEnabled,
		&rule.LastTriggeredAt, &rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return rule, nil
}

// Delete deletes an auto-deploy rule.
func (r *AutoDeployRuleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM auto_deploy_rules WHERE id = $1`, id)
	return err
}

// MatchRules finds matching auto-deploy rules for a given source type and repo.
func (r *AutoDeployRuleRepository) MatchRules(ctx context.Context, sourceType, sourceRepo string, branch *string) ([]*models.AutoDeployRule, error) {
	q := `SELECT id, name, source_type, source_repo, source_branch, target_stack_id, target_service,
		action, is_enabled, last_triggered_at, created_by, created_at, updated_at
		FROM auto_deploy_rules WHERE is_enabled = true AND source_type = $1 AND source_repo = $2`
	args := []interface{}{sourceType, sourceRepo}

	if branch != nil {
		q += ` AND (source_branch = $3 OR source_branch IS NULL)`
		args = append(args, *branch)
	}

	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*models.AutoDeployRule
	for rows.Next() {
		rule := &models.AutoDeployRule{}
		if err := rows.Scan(
			&rule.ID, &rule.Name, &rule.SourceType, &rule.SourceRepo, &rule.SourceBranch,
			&rule.TargetStackID, &rule.TargetService, &rule.Action, &rule.IsEnabled,
			&rule.LastTriggeredAt, &rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt,
		); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}
