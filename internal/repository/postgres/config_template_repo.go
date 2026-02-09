// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ConfigTemplateRepository implements config.TemplateRepository
type ConfigTemplateRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewConfigTemplateRepository creates a new ConfigTemplateRepository
func NewConfigTemplateRepository(db *DB, log *logger.Logger) *ConfigTemplateRepository {
	return &ConfigTemplateRepository{
		db:     db,
		logger: log.Named("config_template_repo"),
	}
}

// Create inserts a new configuration template
func (r *ConfigTemplateRepository) Create(ctx context.Context, t *models.ConfigTemplate) error {
	log := logger.FromContext(ctx)

	// If this is set as default, unset other defaults first
	if t.IsDefault {
		if err := r.unsetDefault(ctx); err != nil {
			return err
		}
	}

	query := `
		INSERT INTO config_templates (
			id, name, description, is_default, variable_count,
			created_by, updated_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		)`

	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	now := time.Now()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	if t.UpdatedAt.IsZero() {
		t.UpdatedAt = now
	}

	_, err := r.db.Exec(ctx, query,
		t.ID,
		t.Name,
		t.Description,
		t.IsDefault,
		t.VariableCount,
		t.CreatedBy,
		t.UpdatedBy,
		t.CreatedAt,
		t.UpdatedAt,
	)

	if err != nil {
		if IsDuplicateKeyError(err) {
			return errors.AlreadyExists("template").WithDetail("name", t.Name)
		}
		log.Error("Failed to create config template",
			"template_id", t.ID,
			"name", t.Name,
			"error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create config template")
	}

	log.Debug("Config template created",
		"template_id", t.ID,
		"name", t.Name)

	return nil
}

// GetByID retrieves a configuration template by ID
func (r *ConfigTemplateRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ConfigTemplate, error) {
	query := `
		SELECT id, name, description, is_default, variable_count,
			created_by, updated_by, created_at, updated_at
		FROM config_templates
		WHERE id = $1`

	row := r.db.QueryRow(ctx, query, id)
	return r.scanTemplate(row)
}

// GetByName retrieves a configuration template by name
func (r *ConfigTemplateRepository) GetByName(ctx context.Context, name string) (*models.ConfigTemplate, error) {
	query := `
		SELECT id, name, description, is_default, variable_count,
			created_by, updated_by, created_at, updated_at
		FROM config_templates
		WHERE name = $1`

	row := r.db.QueryRow(ctx, query, name)
	return r.scanTemplate(row)
}

// GetDefault retrieves the default template
func (r *ConfigTemplateRepository) GetDefault(ctx context.Context) (*models.ConfigTemplate, error) {
	query := `
		SELECT id, name, description, is_default, variable_count,
			created_by, updated_by, created_at, updated_at
		FROM config_templates
		WHERE is_default = TRUE
		LIMIT 1`

	row := r.db.QueryRow(ctx, query)
	t, err := r.scanTemplate(row)
	if err != nil {
		if errors.Is(err, errors.ErrNotFound) {
			return nil, nil // No default is not an error
		}
		return nil, err
	}
	return t, nil
}

// Update updates an existing configuration template
func (r *ConfigTemplateRepository) Update(ctx context.Context, t *models.ConfigTemplate) error {
	log := logger.FromContext(ctx)

	// If setting as default, unset other defaults first
	if t.IsDefault {
		if err := r.unsetDefaultExcept(ctx, t.ID); err != nil {
			return err
		}
	}

	query := `
		UPDATE config_templates
		SET name = $2,
			description = $3,
			is_default = $4,
			updated_by = $5,
			updated_at = $6
		WHERE id = $1`

	t.UpdatedAt = time.Now()

	result, err := r.db.Exec(ctx, query,
		t.ID,
		t.Name,
		t.Description,
		t.IsDefault,
		t.UpdatedBy,
		t.UpdatedAt,
	)

	if err != nil {
		if IsDuplicateKeyError(err) {
			return errors.AlreadyExists("template").WithDetail("name", t.Name)
		}
		log.Error("Failed to update config template",
			"template_id", t.ID,
			"error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update config template")
	}

	if result.RowsAffected() == 0 {
		return errors.NotFound("template")
	}

	log.Debug("Config template updated",
		"template_id", t.ID,
		"name", t.Name)

	return nil
}

// Delete removes a configuration template and its variables
func (r *ConfigTemplateRepository) Delete(ctx context.Context, id uuid.UUID) error {
	log := logger.FromContext(ctx)

	// First, get template name for variable deletion
	t, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Begin transaction
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to begin transaction")
	}
	defer tx.Rollback(ctx)

	// Delete associated variables
	_, err = tx.Exec(ctx,
		`DELETE FROM config_variables WHERE scope = 'template' AND scope_id = $1`,
		t.Name)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete template variables")
	}

	// Delete template
	result, err := tx.Exec(ctx,
		`DELETE FROM config_templates WHERE id = $1`,
		id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete config template")
	}

	if result.RowsAffected() == 0 {
		return errors.NotFound("template")
	}

	if err := tx.Commit(ctx); err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to commit transaction")
	}

	log.Debug("Config template deleted", "template_id", id, "name", t.Name)
	return nil
}

// List retrieves all templates with optional filtering
func (r *ConfigTemplateRepository) List(ctx context.Context, search *string, limit, offset int) ([]*models.ConfigTemplate, int, error) {
	// Build WHERE clause
	var conditions []string
	var args []interface{}
	argNum := 1

	if search != nil && *search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argNum, argNum))
		args = append(args, "%"+*search+"%")
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM config_templates %s", whereClause)
	var total int
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count templates")
	}

	// Set defaults
	if limit <= 0 {
		limit = 50
	}

	// Build main query
	query := fmt.Sprintf(`
		SELECT id, name, description, is_default, variable_count,
			created_by, updated_by, created_at, updated_at
		FROM config_templates
		%s
		ORDER BY is_default DESC, name
		LIMIT $%d OFFSET $%d`,
		whereClause, argNum, argNum+1)

	args = append(args, limit, offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to list templates")
	}
	defer rows.Close()

	templates, err := r.scanTemplates(rows)
	if err != nil {
		return nil, 0, err
	}

	return templates, total, nil
}

// ListAll retrieves all templates
func (r *ConfigTemplateRepository) ListAll(ctx context.Context) ([]*models.ConfigTemplate, error) {
	query := `
		SELECT id, name, description, is_default, variable_count,
			created_by, updated_by, created_at, updated_at
		FROM config_templates
		ORDER BY is_default DESC, name`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list all templates")
	}
	defer rows.Close()

	return r.scanTemplates(rows)
}

// SetDefault sets a template as the default
func (r *ConfigTemplateRepository) SetDefault(ctx context.Context, id uuid.UUID) error {
	log := logger.FromContext(ctx)

	// Begin transaction
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to begin transaction")
	}
	defer tx.Rollback(ctx)

	// Unset all defaults
	_, err = tx.Exec(ctx, `UPDATE config_templates SET is_default = FALSE WHERE is_default = TRUE`)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to unset defaults")
	}

	// Set new default
	result, err := tx.Exec(ctx,
		`UPDATE config_templates SET is_default = TRUE, updated_at = $2 WHERE id = $1`,
		id, time.Now())
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to set default template")
	}

	if result.RowsAffected() == 0 {
		return errors.NotFound("template")
	}

	if err := tx.Commit(ctx); err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to commit transaction")
	}

	log.Debug("Config template set as default", "template_id", id)
	return nil
}

// CopyTemplate creates a copy of a template with all its variables
func (r *ConfigTemplateRepository) CopyTemplate(ctx context.Context, sourceID uuid.UUID, newName string, createdBy *uuid.UUID) (*models.ConfigTemplate, error) {
	log := logger.FromContext(ctx)

	// Get source template
	source, err := r.GetByID(ctx, sourceID)
	if err != nil {
		return nil, err
	}

	// Begin transaction
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to begin transaction")
	}
	defer tx.Rollback(ctx)

	// Create new template
	now := time.Now()
	newTemplate := &models.ConfigTemplate{
		ID:          uuid.New(),
		Name:        newName,
		Description: source.Description,
		IsDefault:   false,
		CreatedBy:   createdBy,
		UpdatedBy:   createdBy,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO config_templates (
			id, name, description, is_default, variable_count,
			created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		newTemplate.ID,
		newTemplate.Name,
		newTemplate.Description,
		newTemplate.IsDefault,
		0,
		newTemplate.CreatedBy,
		newTemplate.UpdatedBy,
		newTemplate.CreatedAt,
		newTemplate.UpdatedAt,
	)
	if err != nil {
		if IsDuplicateKeyError(err) {
			return nil, errors.AlreadyExists("template").WithDetail("name", newName)
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create template copy")
	}

	// Copy variables
	_, err = tx.Exec(ctx, `
		INSERT INTO config_variables (
			id, name, value, type, scope, scope_id, description,
			is_required, default_value, version, created_by, updated_by,
			created_at, updated_at
		)
		SELECT 
			gen_random_uuid(), name, value, type, scope, $2, description,
			is_required, default_value, 1, $3, $3, $4, $4
		FROM config_variables
		WHERE scope = 'template' AND scope_id = $1`,
		source.Name, newName, createdBy, now,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to copy template variables")
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to commit transaction")
	}

	// Fetch the new template to get accurate variable_count
	newTemplate, _ = r.GetByName(ctx, newName)

	log.Debug("Config template copied",
		"source_id", sourceID,
		"source_name", source.Name,
		"new_id", newTemplate.ID,
		"new_name", newName)

	return newTemplate, nil
}

// Exists checks if a template exists by name
func (r *ConfigTemplateRepository) Exists(ctx context.Context, name string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM config_templates WHERE name = $1)`
	var exists bool
	err := r.db.QueryRow(ctx, query, name).Scan(&exists)
	if err != nil {
		return false, errors.Wrap(err, errors.CodeDatabaseError, "failed to check template existence")
	}
	return exists, nil
}

// unsetDefault unsets all default templates
func (r *ConfigTemplateRepository) unsetDefault(ctx context.Context) error {
	_, err := r.db.Exec(ctx, `UPDATE config_templates SET is_default = FALSE WHERE is_default = TRUE`)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to unset default templates")
	}
	return nil
}

// unsetDefaultExcept unsets all default templates except the specified one
func (r *ConfigTemplateRepository) unsetDefaultExcept(ctx context.Context, exceptID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE config_templates SET is_default = FALSE WHERE is_default = TRUE AND id != $1`,
		exceptID)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to unset default templates")
	}
	return nil
}

// scanTemplate scans a single row into a ConfigTemplate
func (r *ConfigTemplateRepository) scanTemplate(row pgx.Row) (*models.ConfigTemplate, error) {
	t := &models.ConfigTemplate{}

	err := row.Scan(
		&t.ID,
		&t.Name,
		&t.Description,
		&t.IsDefault,
		&t.VariableCount,
		&t.CreatedBy,
		&t.UpdatedBy,
		&t.CreatedAt,
		&t.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("template")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan template")
	}

	return t, nil
}

// scanTemplates scans multiple rows into ConfigTemplates
func (r *ConfigTemplateRepository) scanTemplates(rows pgx.Rows) ([]*models.ConfigTemplate, error) {
	var templates []*models.ConfigTemplate

	for rows.Next() {
		t := &models.ConfigTemplate{}

		err := rows.Scan(
			&t.ID,
			&t.Name,
			&t.Description,
			&t.IsDefault,
			&t.VariableCount,
			&t.CreatedBy,
			&t.UpdatedBy,
			&t.CreatedAt,
			&t.UpdatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan template")
		}

		templates = append(templates, t)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "error iterating templates")
	}

	return templates, nil
}
