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
type LifecyclePolicy = models.LifecyclePolicyRecord
type LifecycleHistoryEntry = models.LifecycleHistoryRecord

// LifecycleRepository handles CRUD for lifecycle policies and history.
type LifecycleRepository struct {
	db *DB
}

// NewLifecycleRepository creates a new lifecycle repository.
func NewLifecycleRepository(db *DB) *LifecycleRepository {
	return &LifecycleRepository{db: db}
}

// CreatePolicy creates a new lifecycle policy.
func (r *LifecycleRepository) CreatePolicy(ctx context.Context, p *LifecyclePolicy) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO lifecycle_policies (id, name, description, resource_type, action, schedule,
			is_enabled, only_dangling, only_stopped, only_unused, max_age_days, keep_latest,
			exclude_labels, include_labels, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		p.ID, p.Name, p.Description, p.ResourceType, p.Action, p.Schedule,
		p.IsEnabled, p.OnlyDangling, p.OnlyStopped, p.OnlyUnused, p.MaxAgeDays, p.KeepLatest,
		p.ExcludeLabels, p.IncludeLabels, p.CreatedBy,
	)
	return err
}

// GetPolicy retrieves a policy by ID.
func (r *LifecycleRepository) GetPolicy(ctx context.Context, id uuid.UUID) (*LifecyclePolicy, error) {
	p := &LifecyclePolicy{}
	err := r.db.QueryRow(ctx, `
		SELECT id, name, description, resource_type, action, schedule, is_enabled,
			only_dangling, only_stopped, only_unused, max_age_days, keep_latest,
			exclude_labels, include_labels, last_executed_at, last_result, created_by, created_at, updated_at
		FROM lifecycle_policies WHERE id = $1`, id).Scan(
		&p.ID, &p.Name, &p.Description, &p.ResourceType, &p.Action, &p.Schedule, &p.IsEnabled,
		&p.OnlyDangling, &p.OnlyStopped, &p.OnlyUnused, &p.MaxAgeDays, &p.KeepLatest,
		&p.ExcludeLabels, &p.IncludeLabels, &p.LastExecutedAt, &p.LastResult, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// ListPolicies returns all lifecycle policies.
func (r *LifecycleRepository) ListPolicies(ctx context.Context) ([]*LifecyclePolicy, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, description, resource_type, action, schedule, is_enabled,
			only_dangling, only_stopped, only_unused, max_age_days, keep_latest,
			exclude_labels, include_labels, last_executed_at, last_result, created_by, created_at, updated_at
		FROM lifecycle_policies ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []*LifecyclePolicy
	for rows.Next() {
		p := &LifecyclePolicy{}
		if err := rows.Scan(
			&p.ID, &p.Name, &p.Description, &p.ResourceType, &p.Action, &p.Schedule, &p.IsEnabled,
			&p.OnlyDangling, &p.OnlyStopped, &p.OnlyUnused, &p.MaxAgeDays, &p.KeepLatest,
			&p.ExcludeLabels, &p.IncludeLabels, &p.LastExecutedAt, &p.LastResult, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, nil
}

// DeletePolicy deletes a lifecycle policy.
func (r *LifecycleRepository) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM lifecycle_policies WHERE id = $1`, id)
	return err
}

// TogglePolicy toggles a policy's enabled status.
func (r *LifecycleRepository) TogglePolicy(ctx context.Context, id uuid.UUID) (bool, error) {
	var newState bool
	err := r.db.QueryRow(ctx, `
		UPDATE lifecycle_policies SET is_enabled = NOT is_enabled WHERE id = $1
		RETURNING is_enabled`, id).Scan(&newState)
	return newState, err
}

// UpdateLastExecution updates the execution status for a policy.
func (r *LifecycleRepository) UpdateLastExecution(ctx context.Context, id uuid.UUID, executedAt time.Time, result string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE lifecycle_policies SET last_executed_at=$2, last_result=$3 WHERE id=$1`,
		id, executedAt, result,
	)
	return err
}

// CreateHistoryEntry records a lifecycle execution.
func (r *LifecycleRepository) CreateHistoryEntry(ctx context.Context, h *LifecycleHistoryEntry) error {
	if h.ID == uuid.Nil {
		h.ID = uuid.New()
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO lifecycle_history (id, policy_id, policy_name, resource_type, action, items_removed, space_freed, status, duration_ms, error_message, executed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		h.ID, h.PolicyID, h.PolicyName, h.ResourceType, h.Action,
		h.ItemsRemoved, h.SpaceFreed, h.Status, h.DurationMs, h.ErrorMessage, h.ExecutedAt,
	)
	return err
}

// ListHistory returns recent lifecycle execution history.
func (r *LifecycleRepository) ListHistory(ctx context.Context, limit int) ([]*LifecycleHistoryEntry, error) {
	query := `SELECT id, policy_id, policy_name, resource_type, action, items_removed, space_freed,
		status, duration_ms, error_message, executed_at
		FROM lifecycle_history ORDER BY executed_at DESC`
	if limit > 0 {
		query += ` LIMIT $1`
		rows, err := r.db.Query(ctx, query, limit)
		if err != nil {
			return nil, err
		}
		return scanLifecycleHistory(rows)
	}
	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	return scanLifecycleHistory(rows)
}

// TotalSpaceReclaimed returns total space freed by all lifecycle executions.
func (r *LifecycleRepository) TotalSpaceReclaimed(ctx context.Context) (int64, error) {
	var total int64
	err := r.db.QueryRow(ctx, `SELECT COALESCE(SUM(space_freed), 0) FROM lifecycle_history`).Scan(&total)
	return total, err
}

func scanLifecycleHistory(rows interface {
	Next() bool
	Scan(...interface{}) error
	Close()
}) ([]*LifecycleHistoryEntry, error) {
	defer rows.Close()
	var entries []*LifecycleHistoryEntry
	for rows.Next() {
		h := &LifecycleHistoryEntry{}
		if err := rows.Scan(
			&h.ID, &h.PolicyID, &h.PolicyName, &h.ResourceType, &h.Action,
			&h.ItemsRemoved, &h.SpaceFreed, &h.Status, &h.DurationMs, &h.ErrorMessage, &h.ExecutedAt,
		); err != nil {
			return nil, err
		}
		entries = append(entries, h)
	}
	return entries, nil
}
