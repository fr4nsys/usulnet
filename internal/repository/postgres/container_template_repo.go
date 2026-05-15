// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// Type alias pointing to shared model type.
type ContainerTemplate = models.ContainerTemplateRecord

// ContainerTemplateRepository handles CRUD for container templates.
type ContainerTemplateRepository struct {
	db *DB
}

// NewContainerTemplateRepository creates a new container template repository.
func NewContainerTemplateRepository(db *DB) *ContainerTemplateRepository {
	return &ContainerTemplateRepository{db: db}
}

// Create creates a new container template.
func (r *ContainerTemplateRepository) Create(ctx context.Context, t *ContainerTemplate) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	if t.EnvVars == nil {
		t.EnvVars = json.RawMessage("[]")
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO container_templates (id, name, description, category, image, tag, ports, volumes,
			env_vars, network, restart_policy, command, is_public, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		t.ID, t.Name, t.Description, t.Category, t.Image, t.Tag,
		t.Ports, t.Volumes, string(t.EnvVars), t.Network, t.RestartPolicy,
		t.Command, t.IsPublic, t.CreatedBy,
	)
	return err
}

// GetByID retrieves a template by ID.
func (r *ContainerTemplateRepository) GetByID(ctx context.Context, id uuid.UUID) (*ContainerTemplate, error) {
	t := &ContainerTemplate{}
	err := r.db.QueryRow(ctx, `
		SELECT id, name, description, category, image, tag, ports, volumes,
			env_vars, network, restart_policy, command, is_public, usage_count,
			created_by, created_at, updated_at
		FROM container_templates WHERE id = $1`, id).Scan(
		&t.ID, &t.Name, &t.Description, &t.Category, &t.Image, &t.Tag,
		&t.Ports, &t.Volumes, &t.EnvVars, &t.Network, &t.RestartPolicy,
		&t.Command, &t.IsPublic, &t.UsageCount, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// List returns all container templates.
func (r *ContainerTemplateRepository) List(ctx context.Context) ([]*ContainerTemplate, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, description, category, image, tag, ports, volumes,
			env_vars, network, restart_policy, command, is_public, usage_count,
			created_by, created_at, updated_at
		FROM container_templates ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []*ContainerTemplate
	for rows.Next() {
		t := &ContainerTemplate{}
		if err := rows.Scan(
			&t.ID, &t.Name, &t.Description, &t.Category, &t.Image, &t.Tag,
			&t.Ports, &t.Volumes, &t.EnvVars, &t.Network, &t.RestartPolicy,
			&t.Command, &t.IsPublic, &t.UsageCount, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, err
		}
		templates = append(templates, t)
	}
	return templates, nil
}

// Delete deletes a container template.
func (r *ContainerTemplateRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM container_templates WHERE id = $1`, id)
	return err
}

// IncrementUsage increments the usage count for a template.
func (r *ContainerTemplateRepository) IncrementUsage(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `UPDATE container_templates SET usage_count = usage_count + 1 WHERE id = $1`, id)
	return err
}

// ListByCategory returns templates filtered by category.
func (r *ContainerTemplateRepository) ListByCategory(ctx context.Context, category string) ([]*ContainerTemplate, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, description, category, image, tag, ports, volumes,
			env_vars, network, restart_policy, command, is_public, usage_count,
			created_by, created_at, updated_at
		FROM container_templates WHERE category = $1 ORDER BY name ASC`, category)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []*ContainerTemplate
	for rows.Next() {
		t := &ContainerTemplate{}
		if err := rows.Scan(
			&t.ID, &t.Name, &t.Description, &t.Category, &t.Image, &t.Tag,
			&t.Ports, &t.Volumes, &t.EnvVars, &t.Network, &t.RestartPolicy,
			&t.Command, &t.IsPublic, &t.UsageCount, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, err
		}
		templates = append(templates, t)
	}
	return templates, nil
}

// GetCategories returns distinct template categories.
func (r *ContainerTemplateRepository) GetCategories(ctx context.Context) ([]string, error) {
	rows, err := r.db.Query(ctx, `SELECT DISTINCT category FROM container_templates WHERE category != '' ORDER BY category`)
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
