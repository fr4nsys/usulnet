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

// RegistryRepository handles CRUD operations for container registries.
type RegistryRepository struct {
	db *DB
}

// NewRegistryRepository creates a new registry repository.
func NewRegistryRepository(db *DB) *RegistryRepository {
	return &RegistryRepository{db: db}
}

// Create creates a new registry.
func (r *RegistryRepository) Create(ctx context.Context, input models.CreateRegistryInput) (*models.Registry, error) {
	reg := &models.Registry{
		ID:        uuid.New(),
		Name:      input.Name,
		URL:       input.URL,
		Username:  input.Username,
		Password:  input.Password,
		IsDefault: input.IsDefault,
	}

	// If setting as default, unset other defaults first
	if reg.IsDefault {
		r.db.Exec(ctx, `UPDATE registries SET is_default = false WHERE is_default = true`)
	}

	err := r.db.QueryRow(ctx, `
		INSERT INTO registries (id, name, url, username, password, is_default)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING created_at, updated_at`,
		reg.ID, reg.Name, reg.URL, reg.Username, reg.Password, reg.IsDefault,
	).Scan(&reg.CreatedAt, &reg.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create registry: %w", err)
	}

	return reg, nil
}

// GetByID retrieves a registry by ID.
func (r *RegistryRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Registry, error) {
	reg := &models.Registry{}
	err := r.db.QueryRow(ctx, `
		SELECT id, name, url, username, password, is_default, created_at, updated_at
		FROM registries WHERE id = $1`, id).Scan(
		&reg.ID, &reg.Name, &reg.URL, &reg.Username, &reg.Password,
		&reg.IsDefault, &reg.CreatedAt, &reg.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return reg, nil
}

// List returns all registries.
func (r *RegistryRepository) List(ctx context.Context) ([]*models.Registry, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, url, username, password, is_default, created_at, updated_at
		FROM registries ORDER BY is_default DESC, name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var registries []*models.Registry
	for rows.Next() {
		reg := &models.Registry{}
		if err := rows.Scan(
			&reg.ID, &reg.Name, &reg.URL, &reg.Username, &reg.Password,
			&reg.IsDefault, &reg.CreatedAt, &reg.UpdatedAt,
		); err != nil {
			return nil, err
		}
		registries = append(registries, reg)
	}
	return registries, nil
}

// Update updates a registry.
func (r *RegistryRepository) Update(ctx context.Context, id uuid.UUID, input models.CreateRegistryInput) (*models.Registry, error) {
	if input.IsDefault {
		r.db.Exec(ctx, `UPDATE registries SET is_default = false WHERE is_default = true AND id != $1`, id)
	}

	reg := &models.Registry{}
	err := r.db.QueryRow(ctx, `
		UPDATE registries SET name=$2, url=$3, username=$4, password=$5, is_default=$6
		WHERE id=$1
		RETURNING id, name, url, username, password, is_default, created_at, updated_at`,
		id, input.Name, input.URL, input.Username, input.Password, input.IsDefault,
	).Scan(
		&reg.ID, &reg.Name, &reg.URL, &reg.Username, &reg.Password,
		&reg.IsDefault, &reg.CreatedAt, &reg.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("update registry: %w", err)
	}
	return reg, nil
}

// Delete deletes a registry.
func (r *RegistryRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM registries WHERE id = $1`, id)
	return err
}

// GetDefault returns the default registry, if any.
func (r *RegistryRepository) GetDefault(ctx context.Context) (*models.Registry, error) {
	reg := &models.Registry{}
	err := r.db.QueryRow(ctx, `
		SELECT id, name, url, username, password, is_default, created_at, updated_at
		FROM registries WHERE is_default = true LIMIT 1`).Scan(
		&reg.ID, &reg.Name, &reg.URL, &reg.Username, &reg.Password,
		&reg.IsDefault, &reg.CreatedAt, &reg.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return reg, nil
}
