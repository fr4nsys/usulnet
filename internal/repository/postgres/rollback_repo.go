// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	stderrors "errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// RollbackPolicyRepository
// ============================================================================

// RollbackPolicyRepository persists rollback_policies rows.
type RollbackPolicyRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewRollbackPolicyRepository creates a new policy repository.
func NewRollbackPolicyRepository(db *DB, log *logger.Logger) *RollbackPolicyRepository {
	if log == nil {
		log = logger.Nop()
	}
	return &RollbackPolicyRepository{
		db:     db,
		logger: log.Named("rollback_policy_repo"),
	}
}

// Create inserts a new rollback policy.
func (r *RollbackPolicyRepository) Create(ctx context.Context, p *models.RollbackPolicy) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	now := time.Now()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now

	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO rollback_policies (
			id, name, description, enabled,
			scope, scope_stack_id, scope_value,
			trigger_kind, failure_threshold, window_seconds,
			last_good_strategy, cooldown_seconds, dry_run,
			created_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7,
			$8, $9, $10,
			$11, $12, $13,
			$14, $15, $16
		)`,
		p.ID, p.Name, p.Description, p.Enabled,
		string(p.Scope), p.ScopeStackID, p.ScopeValue,
		string(p.TriggerKind), p.FailureThreshold, p.WindowSeconds,
		string(p.LastGoodStrategy), p.CooldownSeconds, p.DryRun,
		p.CreatedBy, p.CreatedAt, p.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "rollback: create policy")
	}
	return nil
}

// GetByID returns the policy with the given ID.
func (r *RollbackPolicyRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.RollbackPolicy, error) {
	var p models.RollbackPolicy
	var scope, trigger, strategy string
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, name, description, enabled,
			scope, scope_stack_id, scope_value,
			trigger_kind, failure_threshold, window_seconds,
			last_good_strategy, cooldown_seconds, dry_run,
			created_by, created_at, updated_at
		FROM rollback_policies WHERE id = $1`, id,
	).Scan(
		&p.ID, &p.Name, &p.Description, &p.Enabled,
		&scope, &p.ScopeStackID, &p.ScopeValue,
		&trigger, &p.FailureThreshold, &p.WindowSeconds,
		&strategy, &p.CooldownSeconds, &p.DryRun,
		&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if stderrors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("rollback policy")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "rollback: get policy")
	}
	p.Scope = models.RollbackScope(scope)
	p.TriggerKind = models.RollbackTriggerKind(trigger)
	p.LastGoodStrategy = models.RollbackStrategy(strategy)
	return &p, nil
}

// List returns all policies ordered by name.
func (r *RollbackPolicyRepository) List(ctx context.Context) ([]models.RollbackPolicy, error) {
	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, name, description, enabled,
			scope, scope_stack_id, scope_value,
			trigger_kind, failure_threshold, window_seconds,
			last_good_strategy, cooldown_seconds, dry_run,
			created_by, created_at, updated_at
		FROM rollback_policies
		ORDER BY name ASC`,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "rollback: list policies")
	}
	defer rows.Close()

	var policies []models.RollbackPolicy
	for rows.Next() {
		var p models.RollbackPolicy
		var scope, trigger, strategy string
		if err := rows.Scan(
			&p.ID, &p.Name, &p.Description, &p.Enabled,
			&scope, &p.ScopeStackID, &p.ScopeValue,
			&trigger, &p.FailureThreshold, &p.WindowSeconds,
			&strategy, &p.CooldownSeconds, &p.DryRun,
			&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "rollback: scan policy")
		}
		p.Scope = models.RollbackScope(scope)
		p.TriggerKind = models.RollbackTriggerKind(trigger)
		p.LastGoodStrategy = models.RollbackStrategy(strategy)
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "rollback: iterate policies")
	}
	return policies, nil
}

// ListEnabled returns only enabled policies. Used by the worker's
// matching loop to avoid scanning the full table on every event.
func (r *RollbackPolicyRepository) ListEnabled(ctx context.Context) ([]models.RollbackPolicy, error) {
	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, name, description, enabled,
			scope, scope_stack_id, scope_value,
			trigger_kind, failure_threshold, window_seconds,
			last_good_strategy, cooldown_seconds, dry_run,
			created_by, created_at, updated_at
		FROM rollback_policies
		WHERE enabled = true
		ORDER BY name ASC`,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "rollback: list enabled policies")
	}
	defer rows.Close()

	var policies []models.RollbackPolicy
	for rows.Next() {
		var p models.RollbackPolicy
		var scope, trigger, strategy string
		if err := rows.Scan(
			&p.ID, &p.Name, &p.Description, &p.Enabled,
			&scope, &p.ScopeStackID, &p.ScopeValue,
			&trigger, &p.FailureThreshold, &p.WindowSeconds,
			&strategy, &p.CooldownSeconds, &p.DryRun,
			&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "rollback: scan policy")
		}
		p.Scope = models.RollbackScope(scope)
		p.TriggerKind = models.RollbackTriggerKind(trigger)
		p.LastGoodStrategy = models.RollbackStrategy(strategy)
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "rollback: iterate enabled policies")
	}
	return policies, nil
}

// Update overwrites a policy.
func (r *RollbackPolicyRepository) Update(ctx context.Context, p *models.RollbackPolicy) error {
	p.UpdatedAt = time.Now()
	tag, err := r.db.Pool().Exec(ctx, `
		UPDATE rollback_policies SET
			name=$2, description=$3, enabled=$4,
			scope=$5, scope_stack_id=$6, scope_value=$7,
			trigger_kind=$8, failure_threshold=$9, window_seconds=$10,
			last_good_strategy=$11, cooldown_seconds=$12, dry_run=$13,
			updated_at=$14
		WHERE id=$1`,
		p.ID, p.Name, p.Description, p.Enabled,
		string(p.Scope), p.ScopeStackID, p.ScopeValue,
		string(p.TriggerKind), p.FailureThreshold, p.WindowSeconds,
		string(p.LastGoodStrategy), p.CooldownSeconds, p.DryRun,
		p.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "rollback: update policy")
	}
	if tag.RowsAffected() == 0 {
		return errors.NotFound("rollback policy")
	}
	return nil
}

// Delete removes a policy. Executions are cascade-deleted.
func (r *RollbackPolicyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Pool().Exec(ctx, `DELETE FROM rollback_policies WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "rollback: delete policy")
	}
	if tag.RowsAffected() == 0 {
		return errors.NotFound("rollback policy")
	}
	return nil
}

// ============================================================================
// RollbackExecutionRepository
// ============================================================================

// RollbackExecutionRepository persists rollback_executions rows.
type RollbackExecutionRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewRollbackExecutionRepository creates a new execution repository.
func NewRollbackExecutionRepository(db *DB, log *logger.Logger) *RollbackExecutionRepository {
	if log == nil {
		log = logger.Nop()
	}
	return &RollbackExecutionRepository{
		db:     db,
		logger: log.Named("rollback_execution_repo"),
	}
}

// Create inserts a new execution row.
func (r *RollbackExecutionRepository) Create(ctx context.Context, e *models.RollbackExecution) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	now := time.Now()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	e.UpdatedAt = now

	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO rollback_executions (
			id, policy_id, stack_id, change_event_id, trigger_kind,
			from_version, to_version, status, reason, error,
			started_at, finished_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12, $13, $14
		)`,
		e.ID, e.PolicyID, e.StackID, e.ChangeEventID, string(e.TriggerKind),
		e.FromVersion, e.ToVersion, string(e.Status), e.Reason, e.Error,
		e.StartedAt, e.FinishedAt, e.CreatedAt, e.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "rollback: create execution")
	}
	return nil
}

// Update overwrites mutable fields on an existing execution row.
func (r *RollbackExecutionRepository) Update(ctx context.Context, e *models.RollbackExecution) error {
	e.UpdatedAt = time.Now()
	tag, err := r.db.Pool().Exec(ctx, `
		UPDATE rollback_executions SET
			from_version=$2, to_version=$3, status=$4, reason=$5, error=$6,
			started_at=$7, finished_at=$8, updated_at=$9
		WHERE id=$1`,
		e.ID,
		e.FromVersion, e.ToVersion, string(e.Status), e.Reason, e.Error,
		e.StartedAt, e.FinishedAt, e.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "rollback: update execution")
	}
	if tag.RowsAffected() == 0 {
		return errors.NotFound("rollback execution")
	}
	return nil
}

// GetByID returns the execution with the given ID.
func (r *RollbackExecutionRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.RollbackExecution, error) {
	var e models.RollbackExecution
	var trigger, status string
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, policy_id, stack_id, change_event_id, trigger_kind,
			from_version, to_version, status, reason, error,
			started_at, finished_at, created_at, updated_at
		FROM rollback_executions WHERE id = $1`, id,
	).Scan(
		&e.ID, &e.PolicyID, &e.StackID, &e.ChangeEventID, &trigger,
		&e.FromVersion, &e.ToVersion, &status, &e.Reason, &e.Error,
		&e.StartedAt, &e.FinishedAt, &e.CreatedAt, &e.UpdatedAt,
	)
	if err != nil {
		if stderrors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("rollback execution")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "rollback: get execution")
	}
	e.TriggerKind = models.RollbackTriggerKind(trigger)
	e.Status = models.RollbackExecutionStatus(status)
	return &e, nil
}

// List returns executions filtered by the given options. Total count
// reflects the filter before pagination is applied.
func (r *RollbackExecutionRepository) List(ctx context.Context, opts models.RollbackExecutionListOptions) ([]models.RollbackExecution, int, error) {
	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	if opts.Offset < 0 {
		opts.Offset = 0
	}

	var where []string
	var args []any
	idx := 1
	if opts.PolicyID != nil {
		where = append(where, "policy_id = $"+strconv.Itoa(idx))
		args = append(args, *opts.PolicyID)
		idx++
	}
	if opts.StackID != nil {
		where = append(where, "stack_id = $"+strconv.Itoa(idx))
		args = append(args, *opts.StackID)
		idx++
	}
	if opts.Status != "" {
		where = append(where, "status = $"+strconv.Itoa(idx))
		args = append(args, string(opts.Status))
		idx++
	}
	whereClause := ""
	if len(where) > 0 {
		whereClause = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := r.db.Pool().QueryRow(ctx,
		"SELECT COUNT(*) FROM rollback_executions"+whereClause, args...,
	).Scan(&total); err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "rollback: count executions")
	}

	args = append(args, opts.Limit, opts.Offset)
	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, policy_id, stack_id, change_event_id, trigger_kind,
			from_version, to_version, status, reason, error,
			started_at, finished_at, created_at, updated_at
		FROM rollback_executions`+whereClause+`
		ORDER BY created_at DESC
		LIMIT $`+strconv.Itoa(idx)+` OFFSET $`+itoa(idx+1), args...,
	)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "rollback: list executions")
	}
	defer rows.Close()

	var executions []models.RollbackExecution
	for rows.Next() {
		var e models.RollbackExecution
		var trigger, status string
		if err := rows.Scan(
			&e.ID, &e.PolicyID, &e.StackID, &e.ChangeEventID, &trigger,
			&e.FromVersion, &e.ToVersion, &status, &e.Reason, &e.Error,
			&e.StartedAt, &e.FinishedAt, &e.CreatedAt, &e.UpdatedAt,
		); err != nil {
			return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "rollback: scan execution")
		}
		e.TriggerKind = models.RollbackTriggerKind(trigger)
		e.Status = models.RollbackExecutionStatus(status)
		executions = append(executions, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "rollback: iterate executions")
	}
	return executions, total, nil
}

// MostRecentForStack returns the most recent execution for the given
// stack (any status). Used by the service's cooldown check.
func (r *RollbackExecutionRepository) MostRecentForStack(ctx context.Context, stackID uuid.UUID) (*models.RollbackExecution, error) {
	var e models.RollbackExecution
	var trigger, status string
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, policy_id, stack_id, change_event_id, trigger_kind,
			from_version, to_version, status, reason, error,
			started_at, finished_at, created_at, updated_at
		FROM rollback_executions
		WHERE stack_id = $1
		ORDER BY created_at DESC
		LIMIT 1`, stackID,
	).Scan(
		&e.ID, &e.PolicyID, &e.StackID, &e.ChangeEventID, &trigger,
		&e.FromVersion, &e.ToVersion, &status, &e.Reason, &e.Error,
		&e.StartedAt, &e.FinishedAt, &e.CreatedAt, &e.UpdatedAt,
	)
	if err != nil {
		if stderrors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "rollback: most recent execution")
	}
	e.TriggerKind = models.RollbackTriggerKind(trigger)
	e.Status = models.RollbackExecutionStatus(status)
	return &e, nil
}

// ============================================================================
// RollbackAuditRepository — append-only.
//
// Only Append is exposed. Reads use List/Recent. There is no Update or
// Delete method by design: the table is enforced as append-only by the
// rollback_audit_log_append_only_trigger Postgres trigger (migration
// 054). Adding a write path here would also need a SECURITY DEFINER
// helper — out of scope for this session.
// ============================================================================

// RollbackAuditRepository writes append-only audit rows.
type RollbackAuditRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewRollbackAuditRepository creates a new audit repository.
func NewRollbackAuditRepository(db *DB, log *logger.Logger) *RollbackAuditRepository {
	if log == nil {
		log = logger.Nop()
	}
	return &RollbackAuditRepository{
		db:     db,
		logger: log.Named("rollback_audit_repo"),
	}
}

// Append inserts a single audit row. The migration's BEFORE
// UPDATE/DELETE/TRUNCATE trigger blocks every other mutation; this is
// the only writer to the table.
func (r *RollbackAuditRepository) Append(ctx context.Context, e *models.RollbackAuditEntry) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO rollback_audit_log (
			id, policy_id, execution_id, stack_id, actor_id,
			action, details, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		e.ID, e.PolicyID, e.ExecutionID, e.StackID, e.ActorID,
		e.Action, e.Details, e.CreatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "rollback: append audit")
	}
	return nil
}

// List returns paginated audit rows, newest first. Optional filters
// narrow by policy or stack; pass uuid.Nil to skip a filter.
func (r *RollbackAuditRepository) List(ctx context.Context, policyID, stackID uuid.UUID, limit, offset int) ([]models.RollbackAuditEntry, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	var where []string
	var args []any
	idx := 1
	if policyID != uuid.Nil {
		where = append(where, "policy_id = $"+strconv.Itoa(idx))
		args = append(args, policyID)
		idx++
	}
	if stackID != uuid.Nil {
		where = append(where, "stack_id = $"+strconv.Itoa(idx))
		args = append(args, stackID)
		idx++
	}
	whereClause := ""
	if len(where) > 0 {
		whereClause = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := r.db.Pool().QueryRow(ctx,
		"SELECT COUNT(*) FROM rollback_audit_log"+whereClause, args...,
	).Scan(&total); err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "rollback: count audit")
	}

	args = append(args, limit, offset)
	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, policy_id, execution_id, stack_id, actor_id,
			action, details, created_at
		FROM rollback_audit_log`+whereClause+`
		ORDER BY created_at DESC
		LIMIT $`+strconv.Itoa(idx)+` OFFSET $`+itoa(idx+1), args...,
	)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "rollback: list audit")
	}
	defer rows.Close()

	var entries []models.RollbackAuditEntry
	for rows.Next() {
		var entry models.RollbackAuditEntry
		if err := rows.Scan(
			&entry.ID, &entry.PolicyID, &entry.ExecutionID, &entry.StackID, &entry.ActorID,
			&entry.Action, &entry.Details, &entry.CreatedAt,
		); err != nil {
			return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "rollback: scan audit")
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "rollback: iterate audit")
	}
	return entries, total, nil
}
