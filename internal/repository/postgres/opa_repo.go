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
)

// OPARepository handles CRUD for OPA policies and evaluation results.
type OPARepository struct {
	db *DB
}

// NewOPARepository creates a new OPA repository.
func NewOPARepository(db *DB) *OPARepository {
	return &OPARepository{db: db}
}

// opaPolicyColumns is the standard column list for opa_policies queries.
const opaPolicyColumns = `id, name, description, category, rego_code, is_enabled, is_enforcing,
	severity, last_evaluated_at, evaluation_count, violation_count,
	created_by, created_at, updated_at`

// scanOPAPolicy scans a pgx.Row into a models.OPAPolicy.
func scanOPAPolicy(row pgx.Row) (*models.OPAPolicy, error) {
	p := &models.OPAPolicy{}
	err := row.Scan(
		&p.ID, &p.Name, &p.Description, &p.Category, &p.RegoCode,
		&p.IsEnabled, &p.IsEnforcing, &p.Severity, &p.LastEvaluatedAt,
		&p.EvaluationCount, &p.ViolationCount, &p.CreatedBy,
		&p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// scanOPAPolicyRows scans multiple pgx.Rows into a slice of models.OPAPolicy.
func scanOPAPolicyRows(rows pgx.Rows) ([]*models.OPAPolicy, error) {
	var policies []*models.OPAPolicy
	for rows.Next() {
		p := &models.OPAPolicy{}
		err := rows.Scan(
			&p.ID, &p.Name, &p.Description, &p.Category, &p.RegoCode,
			&p.IsEnabled, &p.IsEnforcing, &p.Severity, &p.LastEvaluatedAt,
			&p.EvaluationCount, &p.ViolationCount, &p.CreatedBy,
			&p.CreatedAt, &p.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, nil
}

// CreatePolicy creates a new OPA policy.
func (r *OPARepository) CreatePolicy(ctx context.Context, p *models.OPAPolicy) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	now := time.Now()
	p.CreatedAt = now
	p.UpdatedAt = now

	_, err := r.db.Exec(ctx, `
		INSERT INTO opa_policies (
			id, name, description, category, rego_code,
			is_enabled, is_enforcing, severity,
			evaluation_count, violation_count,
			created_by, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		p.ID, p.Name, p.Description, p.Category, p.RegoCode,
		p.IsEnabled, p.IsEnforcing, p.Severity,
		p.EvaluationCount, p.ViolationCount,
		p.CreatedBy, p.CreatedAt, p.UpdatedAt,
	)
	return err
}

// GetPolicy retrieves an OPA policy by ID.
func (r *OPARepository) GetPolicy(ctx context.Context, id uuid.UUID) (*models.OPAPolicy, error) {
	row := r.db.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM opa_policies WHERE id = $1`, opaPolicyColumns),
		id,
	)
	return scanOPAPolicy(row)
}

// GetPolicyByName retrieves an OPA policy by its unique name.
func (r *OPARepository) GetPolicyByName(ctx context.Context, name string) (*models.OPAPolicy, error) {
	row := r.db.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM opa_policies WHERE name = $1`, opaPolicyColumns),
		name,
	)
	return scanOPAPolicy(row)
}

// ListPolicies returns OPA policies with an optional category filter.
// If category is empty, all policies are returned.
func (r *OPARepository) ListPolicies(ctx context.Context, category string) ([]*models.OPAPolicy, error) {
	var (
		rows pgx.Rows
		err  error
	)

	if category != "" {
		rows, err = r.db.Query(ctx,
			fmt.Sprintf(`SELECT %s FROM opa_policies WHERE category = $1 ORDER BY name ASC`, opaPolicyColumns),
			category,
		)
	} else {
		rows, err = r.db.Query(ctx,
			fmt.Sprintf(`SELECT %s FROM opa_policies ORDER BY name ASC`, opaPolicyColumns),
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanOPAPolicyRows(rows)
}

// UpdatePolicy updates an existing OPA policy.
func (r *OPARepository) UpdatePolicy(ctx context.Context, p *models.OPAPolicy) error {
	p.UpdatedAt = time.Now()
	_, err := r.db.Exec(ctx, `
		UPDATE opa_policies SET
			name=$2, description=$3, category=$4, rego_code=$5,
			is_enabled=$6, is_enforcing=$7, severity=$8,
			updated_at=$9
		WHERE id=$1`,
		p.ID, p.Name, p.Description, p.Category, p.RegoCode,
		p.IsEnabled, p.IsEnforcing, p.Severity,
		p.UpdatedAt,
	)
	return err
}

// DeletePolicy deletes an OPA policy by ID.
func (r *OPARepository) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM opa_policies WHERE id = $1`, id)
	return err
}

// TogglePolicy sets the enabled state of a policy.
func (r *OPARepository) TogglePolicy(ctx context.Context, id uuid.UUID, enabled bool) error {
	_, err := r.db.Exec(ctx, `
		UPDATE opa_policies SET is_enabled = $2, updated_at = $3
		WHERE id = $1`,
		id, enabled, time.Now(),
	)
	return err
}

// IncrementEvaluation atomically increments the evaluation counter for a policy.
// When isViolation is true, the violation counter is also incremented.
func (r *OPARepository) IncrementEvaluation(ctx context.Context, policyID uuid.UUID, isViolation bool) error {
	now := time.Now()
	if isViolation {
		_, err := r.db.Exec(ctx, `
			UPDATE opa_policies SET
				evaluation_count = evaluation_count + 1,
				violation_count  = violation_count  + 1,
				last_evaluated_at = $2
			WHERE id = $1`,
			policyID, now,
		)
		return err
	}
	_, err := r.db.Exec(ctx, `
		UPDATE opa_policies SET
			evaluation_count  = evaluation_count + 1,
			last_evaluated_at = $2
		WHERE id = $1`,
		policyID, now,
	)
	return err
}

// ============================================================================
// Evaluation Results
// ============================================================================

// opaResultColumns is the standard column list for opa_evaluation_results queries.
const opaResultColumns = `id, policy_id, target_type, target_id, target_name,
	decision, violations, input_hash, evaluated_at`

// scanOPAResultRows scans multiple pgx.Rows into a slice of models.OPAEvaluationResult.
func scanOPAResultRows(rows pgx.Rows) ([]*models.OPAEvaluationResult, error) {
	var results []*models.OPAEvaluationResult
	for rows.Next() {
		r := &models.OPAEvaluationResult{}
		err := rows.Scan(
			&r.ID, &r.PolicyID, &r.TargetType, &r.TargetID, &r.TargetName,
			&r.Decision, &r.Violations, &r.InputHash, &r.EvaluatedAt,
		)
		if err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, nil
}

// SaveResult persists an OPA evaluation result.
func (r *OPARepository) SaveResult(ctx context.Context, result *models.OPAEvaluationResult) error {
	if result.EvaluatedAt.IsZero() {
		result.EvaluatedAt = time.Now()
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO opa_evaluation_results (
			policy_id, target_type, target_id, target_name,
			decision, violations, input_hash, evaluated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		result.PolicyID, result.TargetType, result.TargetID, result.TargetName,
		result.Decision, result.Violations, result.InputHash, result.EvaluatedAt,
	)
	return err
}

// ListResults returns the most recent evaluation results for a given policy,
// ordered by evaluated_at descending and limited by the provided count.
func (r *OPARepository) ListResults(ctx context.Context, policyID uuid.UUID, limit int) ([]*models.OPAEvaluationResult, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.db.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM opa_evaluation_results
			WHERE policy_id = $1
			ORDER BY evaluated_at DESC
			LIMIT $2`, opaResultColumns),
		policyID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanOPAResultRows(rows)
}

// GetResultsByTarget returns evaluation results for a specific target,
// ordered by evaluated_at descending.
func (r *OPARepository) GetResultsByTarget(ctx context.Context, targetType, targetID string) ([]*models.OPAEvaluationResult, error) {
	rows, err := r.db.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM opa_evaluation_results
			WHERE target_type = $1 AND target_id = $2
			ORDER BY evaluated_at DESC`, opaResultColumns),
		targetType, targetID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanOPAResultRows(rows)
}
