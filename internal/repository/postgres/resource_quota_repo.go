// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// Type alias pointing to shared model type.
type ResourceQuota = models.ResourceQuotaRecord

// ResourceQuotaRepository handles CRUD for resource quotas.
type ResourceQuotaRepository struct {
	db *DB
}

// NewResourceQuotaRepository creates a new resource quota repository.
func NewResourceQuotaRepository(db *DB) *ResourceQuotaRepository {
	return &ResourceQuotaRepository{db: db}
}

// Create creates a new resource quota.
func (r *ResourceQuotaRepository) Create(ctx context.Context, q *ResourceQuota) error {
	if q.ID == uuid.Nil {
		q.ID = uuid.New()
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO resource_quotas (id, name, scope, scope_name, resource_type, limit_value, alert_at, is_enabled, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		q.ID, q.Name, q.Scope, q.ScopeName, q.ResourceType, q.LimitValue, q.AlertAt, q.IsEnabled, q.CreatedBy,
	)
	return err
}

// GetByID retrieves a quota by ID.
func (r *ResourceQuotaRepository) GetByID(ctx context.Context, id uuid.UUID) (*ResourceQuota, error) {
	q := &ResourceQuota{}
	err := r.db.QueryRow(ctx, `
		SELECT id, name, scope, scope_name, resource_type, limit_value, alert_at, is_enabled,
			created_by, created_at, updated_at
		FROM resource_quotas WHERE id = $1`, id).Scan(
		&q.ID, &q.Name, &q.Scope, &q.ScopeName, &q.ResourceType, &q.LimitValue, &q.AlertAt, &q.IsEnabled,
		&q.CreatedBy, &q.CreatedAt, &q.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return q, nil
}

// List returns all resource quotas.
func (r *ResourceQuotaRepository) List(ctx context.Context) ([]*ResourceQuota, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, scope, scope_name, resource_type, limit_value, alert_at, is_enabled,
			created_by, created_at, updated_at
		FROM resource_quotas ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var quotas []*ResourceQuota
	for rows.Next() {
		q := &ResourceQuota{}
		if err := rows.Scan(
			&q.ID, &q.Name, &q.Scope, &q.ScopeName, &q.ResourceType, &q.LimitValue, &q.AlertAt, &q.IsEnabled,
			&q.CreatedBy, &q.CreatedAt, &q.UpdatedAt,
		); err != nil {
			return nil, err
		}
		quotas = append(quotas, q)
	}
	return quotas, nil
}

// Delete deletes a resource quota.
func (r *ResourceQuotaRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM resource_quotas WHERE id = $1`, id)
	return err
}

// Toggle toggles a quota's enabled status.
func (r *ResourceQuotaRepository) Toggle(ctx context.Context, id uuid.UUID) (bool, error) {
	var newState bool
	err := r.db.QueryRow(ctx, `
		UPDATE resource_quotas SET is_enabled = NOT is_enabled WHERE id = $1
		RETURNING is_enabled`, id).Scan(&newState)
	return newState, err
}

// ListByScope returns quotas for a specific scope.
func (r *ResourceQuotaRepository) ListByScope(ctx context.Context, scope string) ([]*ResourceQuota, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, scope, scope_name, resource_type, limit_value, alert_at, is_enabled,
			created_by, created_at, updated_at
		FROM resource_quotas WHERE scope = $1 AND is_enabled = true ORDER BY name ASC`, scope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var quotas []*ResourceQuota
	for rows.Next() {
		q := &ResourceQuota{}
		if err := rows.Scan(
			&q.ID, &q.Name, &q.Scope, &q.ScopeName, &q.ResourceType, &q.LimitValue, &q.AlertAt, &q.IsEnabled,
			&q.CreatedBy, &q.CreatedAt, &q.UpdatedAt,
		); err != nil {
			return nil, err
		}
		quotas = append(quotas, q)
	}
	return quotas, nil
}
