// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// Type aliases pointing to shared model types.
type CompliancePolicy = models.CompliancePolicyRecord
type ComplianceViolation = models.ComplianceViolationRecord

// ComplianceRepository handles CRUD for compliance policies and violations.
type ComplianceRepository struct {
	db *DB
}

// NewComplianceRepository creates a new compliance repository.
func NewComplianceRepository(db *DB) *ComplianceRepository {
	return &ComplianceRepository{db: db}
}

// CreatePolicy creates a new compliance policy.
func (r *ComplianceRepository) CreatePolicy(ctx context.Context, p *CompliancePolicy) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO compliance_policies (id, name, description, category, severity, rule, is_enabled, is_enforced, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		p.ID, p.Name, p.Description, p.Category, p.Severity, p.Rule, p.IsEnabled, p.IsEnforced, p.CreatedBy,
	)
	return err
}

// GetPolicy retrieves a policy by ID.
func (r *ComplianceRepository) GetPolicy(ctx context.Context, id uuid.UUID) (*CompliancePolicy, error) {
	p := &CompliancePolicy{}
	err := r.db.QueryRow(ctx, `
		SELECT id, name, description, category, severity, rule, is_enabled, is_enforced,
			last_check_at, created_by, created_at, updated_at
		FROM compliance_policies WHERE id = $1`, id).Scan(
		&p.ID, &p.Name, &p.Description, &p.Category, &p.Severity, &p.Rule,
		&p.IsEnabled, &p.IsEnforced, &p.LastCheckAt, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// ListPolicies returns all compliance policies.
func (r *ComplianceRepository) ListPolicies(ctx context.Context) ([]*CompliancePolicy, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, description, category, severity, rule, is_enabled, is_enforced,
			last_check_at, created_by, created_at, updated_at
		FROM compliance_policies ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []*CompliancePolicy
	for rows.Next() {
		p := &CompliancePolicy{}
		if err := rows.Scan(
			&p.ID, &p.Name, &p.Description, &p.Category, &p.Severity, &p.Rule,
			&p.IsEnabled, &p.IsEnforced, &p.LastCheckAt, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, nil
}

// UpdatePolicy updates a compliance policy.
func (r *ComplianceRepository) UpdatePolicy(ctx context.Context, p *CompliancePolicy) error {
	_, err := r.db.Exec(ctx, `
		UPDATE compliance_policies SET
			name=$2, description=$3, category=$4, severity=$5, rule=$6,
			is_enabled=$7, is_enforced=$8, last_check_at=$9
		WHERE id=$1`,
		p.ID, p.Name, p.Description, p.Category, p.Severity, p.Rule,
		p.IsEnabled, p.IsEnforced, p.LastCheckAt,
	)
	return err
}

// DeletePolicy deletes a compliance policy and its violations.
func (r *ComplianceRepository) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM compliance_policies WHERE id = $1`, id)
	return err
}

// TogglePolicy toggles a policy's enabled status.
func (r *ComplianceRepository) TogglePolicy(ctx context.Context, id uuid.UUID) (bool, error) {
	var newState bool
	err := r.db.QueryRow(ctx, `
		UPDATE compliance_policies SET is_enabled = NOT is_enabled WHERE id = $1
		RETURNING is_enabled`, id).Scan(&newState)
	return newState, err
}

// UpdateLastCheck updates the last check timestamp for a policy.
func (r *ComplianceRepository) UpdateLastCheck(ctx context.Context, id uuid.UUID, t time.Time) error {
	_, err := r.db.Exec(ctx, `UPDATE compliance_policies SET last_check_at = $2 WHERE id = $1`, id, t)
	return err
}

// CreateViolation creates a violation record.
func (r *ComplianceRepository) CreateViolation(ctx context.Context, v *ComplianceViolation) error {
	if v.ID == uuid.Nil {
		v.ID = uuid.New()
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO compliance_violations (id, policy_id, policy_name, container_id, container_name, severity, message, details, status, detected_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		v.ID, v.PolicyID, v.PolicyName, v.ContainerID, v.ContainerName,
		v.Severity, v.Message, v.Details, v.Status, v.DetectedAt,
	)
	return err
}

// ListViolations returns violations with optional status filter.
func (r *ComplianceRepository) ListViolations(ctx context.Context, status *string) ([]*ComplianceViolation, error) {
	query := `SELECT id, policy_id, policy_name, container_id, container_name, severity, message, details, status, detected_at, resolved_at, resolved_by
		FROM compliance_violations`
	var args []interface{}
	if status != nil {
		query += ` WHERE status = $1`
		args = append(args, *status)
	}
	query += ` ORDER BY detected_at DESC`

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var violations []*ComplianceViolation
	for rows.Next() {
		v := &ComplianceViolation{}
		if err := rows.Scan(
			&v.ID, &v.PolicyID, &v.PolicyName, &v.ContainerID, &v.ContainerName,
			&v.Severity, &v.Message, &v.Details, &v.Status, &v.DetectedAt,
			&v.ResolvedAt, &v.ResolvedBy,
		); err != nil {
			return nil, err
		}
		violations = append(violations, v)
	}
	return violations, nil
}

// UpdateViolationStatus updates a violation's status.
func (r *ComplianceRepository) UpdateViolationStatus(ctx context.Context, id uuid.UUID, status string, resolvedBy *uuid.UUID) error {
	if status == "resolved" || status == "exempted" {
		now := time.Now()
		_, err := r.db.Exec(ctx, `
			UPDATE compliance_violations SET status=$2, resolved_at=$3, resolved_by=$4 WHERE id=$1`,
			id, status, now, resolvedBy,
		)
		return err
	}
	_, err := r.db.Exec(ctx, `UPDATE compliance_violations SET status=$2 WHERE id=$1`, id, status)
	return err
}

// ViolationExistsForPolicy checks if an open violation exists for a policy and container.
func (r *ComplianceRepository) ViolationExistsForPolicy(ctx context.Context, policyID uuid.UUID, containerID string) (bool, error) {
	var exists bool
	err := r.db.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM compliance_violations
			WHERE policy_id=$1 AND container_id=$2 AND status='open'
		)`, policyID, containerID).Scan(&exists)
	return exists, err
}

// CountViolationsByPolicy returns open violation count per policy.
func (r *ComplianceRepository) CountViolationsByPolicy(ctx context.Context, policyID uuid.UUID) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM compliance_violations
		WHERE policy_id=$1 AND status='open'`, policyID).Scan(&count)
	return count, err
}

// CountViolationsByStatus returns counts grouped by status.
func (r *ComplianceRepository) CountViolationsByStatus(ctx context.Context) (map[string]int, error) {
	rows, err := r.db.Query(ctx, `SELECT status, COUNT(*) FROM compliance_violations GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		counts[status] = count
	}
	return counts, nil
}
