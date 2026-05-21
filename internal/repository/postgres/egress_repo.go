// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	stderrors "errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// EgressPolicyRepository
// ============================================================================

// EgressPolicyRepository persists L7 egress filtering rules. Rows are
// scoped per host; first-created-first-matched at evaluation time.
type EgressPolicyRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewEgressPolicyRepository wires the repo.
func NewEgressPolicyRepository(db *DB, log *logger.Logger) *EgressPolicyRepository {
	if log == nil {
		log = logger.Nop()
	}
	return &EgressPolicyRepository{
		db:     db,
		logger: log.Named("egress_policy_repo"),
	}
}

// Create inserts a policy. The caller may pre-assign ID; otherwise a v4
// UUID is generated.
func (r *EgressPolicyRepository) Create(ctx context.Context, p *models.EgressPolicy) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	now := time.Now()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO egress_policies (id, host_id, target_glob, allow, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, p.ID, p.HostID, p.TargetGlob, p.Allow, p.CreatedAt, p.UpdatedAt)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "egress: create policy")
	}
	return nil
}

// ListByHost returns every policy for a host in created_at ascending
// order — the same order the evaluator scans, so the result is the
// rule book the operator sees in the UI.
func (r *EgressPolicyRepository) ListByHost(ctx context.Context, hostID uuid.UUID) ([]models.EgressPolicy, error) {
	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, host_id, target_glob, allow, created_at, updated_at
		FROM egress_policies
		WHERE host_id = $1
		ORDER BY created_at ASC
	`, hostID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "egress: list policies")
	}
	defer rows.Close()

	out := make([]models.EgressPolicy, 0)
	for rows.Next() {
		var p models.EgressPolicy
		if err := rows.Scan(&p.ID, &p.HostID, &p.TargetGlob, &p.Allow, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "egress: scan policy")
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "egress: iterate policies")
	}
	return out, nil
}

// GetByID fetches one policy. Returns ErrNotFound when no row matches.
func (r *EgressPolicyRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.EgressPolicy, error) {
	var p models.EgressPolicy
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, host_id, target_glob, allow, created_at, updated_at
		FROM egress_policies
		WHERE id = $1
	`, id).Scan(&p.ID, &p.HostID, &p.TargetGlob, &p.Allow, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if stderrors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New(errors.CodeNotFound, "egress: policy not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "egress: get policy")
	}
	return &p, nil
}

// Delete removes a policy. Returns ErrNotFound when the id is unknown.
func (r *EgressPolicyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Pool().Exec(ctx, `DELETE FROM egress_policies WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "egress: delete policy")
	}
	if tag.RowsAffected() == 0 {
		return errors.New(errors.CodeNotFound, "egress: policy not found")
	}
	return nil
}

// ============================================================================
// EgressAuditRepository
// ============================================================================

// EgressAuditRepository persists denied-request records.
type EgressAuditRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewEgressAuditRepository wires the audit repo.
func NewEgressAuditRepository(db *DB, log *logger.Logger) *EgressAuditRepository {
	if log == nil {
		log = logger.Nop()
	}
	return &EgressAuditRepository{
		db:     db,
		logger: log.Named("egress_audit_repo"),
	}
}

// Insert records a single deny event. Errors are returned to the caller
// — the proxy goroutine logs them at warn level and continues serving,
// because a database hiccup should not break egress evaluation.
func (r *EgressAuditRepository) Insert(ctx context.Context, entry *models.EgressAuditLog) error {
	if entry.ID == uuid.Nil {
		entry.ID = uuid.New()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now()
	}
	if entry.Decision == "" {
		entry.Decision = "deny"
	}
	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO egress_audit_log (id, host_id, target, method, decision, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, entry.ID, entry.HostID, entry.Target, entry.Method, entry.Decision, entry.CreatedAt)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "egress: insert audit")
	}
	return nil
}

// ListByHost returns the most-recent N deny events for a host, newest
// first. Used by the web UI's "recent denies" panel.
func (r *EgressAuditRepository) ListByHost(ctx context.Context, hostID uuid.UUID, limit int) ([]models.EgressAuditLog, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, host_id, target, method, decision, created_at
		FROM egress_audit_log
		WHERE host_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, hostID, limit)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "egress: list audit")
	}
	defer rows.Close()

	out := make([]models.EgressAuditLog, 0, limit)
	for rows.Next() {
		var e models.EgressAuditLog
		if err := rows.Scan(&e.ID, &e.HostID, &e.Target, &e.Method, &e.Decision, &e.CreatedAt); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "egress: scan audit")
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "egress: iterate audit")
	}
	return out, nil
}
