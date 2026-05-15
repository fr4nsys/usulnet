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
type ManagedSecret = models.ManagedSecretRecord

// ManagedSecretRepository handles CRUD for managed secrets.
type ManagedSecretRepository struct {
	db *DB
}

// NewManagedSecretRepository creates a new managed secret repository.
func NewManagedSecretRepository(db *DB) *ManagedSecretRepository {
	return &ManagedSecretRepository{db: db}
}

// Create creates a new managed secret.
func (r *ManagedSecretRepository) Create(ctx context.Context, s *ManagedSecret) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO managed_secrets (id, name, description, type, scope, scope_target, encrypted_value, rotation_days, expires_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		s.ID, s.Name, s.Description, s.Type, s.Scope, s.ScopeTarget,
		s.EncryptedValue, s.RotationDays, s.ExpiresAt, s.CreatedBy,
	)
	return err
}

// GetByID retrieves a secret by ID.
func (r *ManagedSecretRepository) GetByID(ctx context.Context, id uuid.UUID) (*ManagedSecret, error) {
	s := &ManagedSecret{}
	err := r.db.QueryRow(ctx, `
		SELECT id, name, description, type, scope, scope_target, encrypted_value,
			rotation_days, expires_at, last_rotated_at, linked_count, created_by, created_at, updated_at
		FROM managed_secrets WHERE id = $1`, id).Scan(
		&s.ID, &s.Name, &s.Description, &s.Type, &s.Scope, &s.ScopeTarget,
		&s.EncryptedValue, &s.RotationDays, &s.ExpiresAt, &s.LastRotatedAt,
		&s.LinkedCount, &s.CreatedBy, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// List returns all managed secrets.
func (r *ManagedSecretRepository) List(ctx context.Context) ([]*ManagedSecret, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, description, type, scope, scope_target, encrypted_value,
			rotation_days, expires_at, last_rotated_at, linked_count, created_by, created_at, updated_at
		FROM managed_secrets ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var secrets []*ManagedSecret
	for rows.Next() {
		s := &ManagedSecret{}
		if err := rows.Scan(
			&s.ID, &s.Name, &s.Description, &s.Type, &s.Scope, &s.ScopeTarget,
			&s.EncryptedValue, &s.RotationDays, &s.ExpiresAt, &s.LastRotatedAt,
			&s.LinkedCount, &s.CreatedBy, &s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, err
		}
		secrets = append(secrets, s)
	}
	return secrets, nil
}

// Update updates a managed secret.
func (r *ManagedSecretRepository) Update(ctx context.Context, s *ManagedSecret) error {
	_, err := r.db.Exec(ctx, `
		UPDATE managed_secrets SET
			name=$2, description=$3, type=$4, scope=$5, scope_target=$6,
			encrypted_value=$7, rotation_days=$8, expires_at=$9, last_rotated_at=$10, linked_count=$11
		WHERE id=$1`,
		s.ID, s.Name, s.Description, s.Type, s.Scope, s.ScopeTarget,
		s.EncryptedValue, s.RotationDays, s.ExpiresAt, s.LastRotatedAt, s.LinkedCount,
	)
	return err
}

// Delete deletes a managed secret.
func (r *ManagedSecretRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM managed_secrets WHERE id = $1`, id)
	return err
}

// ListExpiring returns secrets expiring within the given days.
func (r *ManagedSecretRepository) ListExpiring(ctx context.Context, withinDays int) ([]*ManagedSecret, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, description, type, scope, scope_target, encrypted_value,
			rotation_days, expires_at, last_rotated_at, linked_count, created_by, created_at, updated_at
		FROM managed_secrets
		WHERE expires_at IS NOT NULL AND expires_at <= NOW() + ($1 || ' days')::INTERVAL
		ORDER BY expires_at ASC`, withinDays)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var secrets []*ManagedSecret
	for rows.Next() {
		s := &ManagedSecret{}
		if err := rows.Scan(
			&s.ID, &s.Name, &s.Description, &s.Type, &s.Scope, &s.ScopeTarget,
			&s.EncryptedValue, &s.RotationDays, &s.ExpiresAt, &s.LastRotatedAt,
			&s.LinkedCount, &s.CreatedBy, &s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, err
		}
		secrets = append(secrets, s)
	}
	return secrets, nil
}
