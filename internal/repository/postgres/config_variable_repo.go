// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ConfigVariableRepository implements config.VariableRepository
type ConfigVariableRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewConfigVariableRepository creates a new ConfigVariableRepository
func NewConfigVariableRepository(db *DB, log *logger.Logger) *ConfigVariableRepository {
	return &ConfigVariableRepository{
		db:     db,
		logger: log.Named("config_variable_repo"),
	}
}

// Create inserts a new configuration variable
func (r *ConfigVariableRepository) Create(ctx context.Context, v *models.ConfigVariable) error {
	log := logger.FromContext(ctx)

	query := `
		INSERT INTO config_variables (
			id, name, value, type, scope, scope_id, description,
			is_required, default_value, version, created_by, updated_by,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12,
			$13, $14
		)`

	if v.ID == uuid.Nil {
		v.ID = uuid.New()
	}
	now := time.Now()
	if v.CreatedAt.IsZero() {
		v.CreatedAt = now
	}
	if v.UpdatedAt.IsZero() {
		v.UpdatedAt = now
	}
	if v.Version == 0 {
		v.Version = 1
	}

	_, err := r.db.Exec(ctx, query,
		v.ID,
		v.Name,
		v.Value,
		string(v.Type),
		string(v.Scope),
		v.ScopeID,
		v.Description,
		v.IsRequired,
		v.DefaultValue,
		v.Version,
		v.CreatedBy,
		v.UpdatedBy,
		v.CreatedAt,
		v.UpdatedAt,
	)

	if err != nil {
		if IsDuplicateKeyError(err) {
			return errors.AlreadyExists("variable").WithDetail("name", v.Name)
		}
		log.Error("Failed to create config variable",
			"variable_id", v.ID,
			"name", v.Name,
			"error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create config variable")
	}

	log.Debug("Config variable created",
		"variable_id", v.ID,
		"name", v.Name,
		"scope", v.Scope)

	return nil
}

// GetByID retrieves a configuration variable by ID
func (r *ConfigVariableRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ConfigVariable, error) {
	query := `
		SELECT id, name, value, type, scope, scope_id, description,
			is_required, default_value, version, created_by, updated_by,
			created_at, updated_at
		FROM config_variables
		WHERE id = $1`

	row := r.db.QueryRow(ctx, query, id)
	return r.scanVariable(row)
}

// GetByName retrieves a configuration variable by name and scope
func (r *ConfigVariableRepository) GetByName(ctx context.Context, name string, scope models.VariableScope, scopeID *string) (*models.ConfigVariable, error) {
	var query string
	var args []interface{}

	if scopeID == nil {
		query = `
			SELECT id, name, value, type, scope, scope_id, description,
				is_required, default_value, version, created_by, updated_by,
				created_at, updated_at
			FROM config_variables
			WHERE name = $1 AND scope = $2 AND scope_id IS NULL`
		args = []interface{}{name, string(scope)}
	} else {
		query = `
			SELECT id, name, value, type, scope, scope_id, description,
				is_required, default_value, version, created_by, updated_by,
				created_at, updated_at
			FROM config_variables
			WHERE name = $1 AND scope = $2 AND scope_id = $3`
		args = []interface{}{name, string(scope), *scopeID}
	}

	row := r.db.QueryRow(ctx, query, args...)
	return r.scanVariable(row)
}

// Update updates an existing configuration variable
func (r *ConfigVariableRepository) Update(ctx context.Context, v *models.ConfigVariable) error {
	log := logger.FromContext(ctx)

	query := `
		UPDATE config_variables
		SET value = $2,
			description = $3,
			is_required = $4,
			default_value = $5,
			updated_by = $6,
			updated_at = $7
		WHERE id = $1`

	v.UpdatedAt = time.Now()

	result, err := r.db.Exec(ctx, query,
		v.ID,
		v.Value,
		v.Description,
		v.IsRequired,
		v.DefaultValue,
		v.UpdatedBy,
		v.UpdatedAt,
	)

	if err != nil {
		log.Error("Failed to update config variable",
			"variable_id", v.ID,
			"error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update config variable")
	}

	if result.RowsAffected() == 0 {
		return errors.NotFound("variable")
	}

	log.Debug("Config variable updated",
		"variable_id", v.ID,
		"name", v.Name)

	return nil
}

// Delete removes a configuration variable
func (r *ConfigVariableRepository) Delete(ctx context.Context, id uuid.UUID) error {
	log := logger.FromContext(ctx)

	query := `DELETE FROM config_variables WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete config variable")
	}

	if result.RowsAffected() == 0 {
		return errors.NotFound("variable")
	}

	log.Debug("Config variable deleted", "variable_id", id)
	return nil
}

// List retrieves variables with filtering and pagination
func (r *ConfigVariableRepository) List(ctx context.Context, opts models.VariableListOptions) ([]*models.ConfigVariable, int, error) {
	// Build WHERE clause
	var conditions []string
	var args []interface{}
	argNum := 1

	if opts.Scope != nil {
		conditions = append(conditions, fmt.Sprintf("scope = $%d", argNum))
		args = append(args, string(*opts.Scope))
		argNum++
	}

	if opts.ScopeID != nil {
		conditions = append(conditions, fmt.Sprintf("scope_id = $%d", argNum))
		args = append(args, *opts.ScopeID)
		argNum++
	}

	if opts.Type != nil {
		conditions = append(conditions, fmt.Sprintf("type = $%d", argNum))
		args = append(args, string(*opts.Type))
		argNum++
	}

	if opts.Search != nil && *opts.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argNum, argNum))
		args = append(args, "%"+*opts.Search+"%")
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM config_variables %s", whereClause)
	var total int
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count variables")
	}

	// Set defaults
	if opts.Limit <= 0 {
		opts.Limit = 50
	}

	// Build main query
	query := fmt.Sprintf(`
		SELECT id, name, value, type, scope, scope_id, description,
			is_required, default_value, version, created_by, updated_by,
			created_at, updated_at
		FROM config_variables
		%s
		ORDER BY scope, name
		LIMIT $%d OFFSET $%d`,
		whereClause, argNum, argNum+1)

	args = append(args, opts.Limit, opts.Offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to list variables")
	}
	defer rows.Close()

	variables, err := r.scanVariables(rows)
	if err != nil {
		return nil, 0, err
	}

	return variables, total, nil
}

// ListByScope retrieves all variables for a given scope
func (r *ConfigVariableRepository) ListByScope(ctx context.Context, scope models.VariableScope, scopeID *string) ([]*models.ConfigVariable, error) {
	var query string
	var args []interface{}

	if scopeID == nil {
		query = `
			SELECT id, name, value, type, scope, scope_id, description,
				is_required, default_value, version, created_by, updated_by,
				created_at, updated_at
			FROM config_variables
			WHERE scope = $1 AND scope_id IS NULL
			ORDER BY name`
		args = []interface{}{string(scope)}
	} else {
		query = `
			SELECT id, name, value, type, scope, scope_id, description,
				is_required, default_value, version, created_by, updated_by,
				created_at, updated_at
			FROM config_variables
			WHERE scope = $1 AND scope_id = $2
			ORDER BY name`
		args = []interface{}{string(scope), *scopeID}
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list variables by scope")
	}
	defer rows.Close()

	return r.scanVariables(rows)
}

// ListGlobal retrieves all global variables
func (r *ConfigVariableRepository) ListGlobal(ctx context.Context) ([]*models.ConfigVariable, error) {
	return r.ListByScope(ctx, models.VariableScopeGlobal, nil)
}

// ResolveForContainer resolves all applicable variables for a container
// Returns merged variables in order: global -> template -> container-specific
func (r *ConfigVariableRepository) ResolveForContainer(ctx context.Context, containerID string, templateName *string) ([]*models.ConfigVariable, error) {
	query := `
		WITH resolved AS (
			-- Global variables (lowest priority)
			SELECT id, name, value, type, scope, scope_id, description,
				is_required, default_value, version, created_by, updated_by,
				created_at, updated_at, 1 as priority
			FROM config_variables
			WHERE scope = 'global'
			
			UNION ALL
			
			-- Template variables (medium priority)
			SELECT id, name, value, type, scope, scope_id, description,
				is_required, default_value, version, created_by, updated_by,
				created_at, updated_at, 2 as priority
			FROM config_variables
			WHERE scope = 'template' AND scope_id = $1
			
			UNION ALL
			
			-- Container-specific variables (highest priority)
			SELECT id, name, value, type, scope, scope_id, description,
				is_required, default_value, version, created_by, updated_by,
				created_at, updated_at, 3 as priority
			FROM config_variables
			WHERE scope = 'container' AND scope_id = $2
		)
		SELECT DISTINCT ON (name)
			id, name, value, type, scope, scope_id, description,
			is_required, default_value, version, created_by, updated_by,
			created_at, updated_at
		FROM resolved
		ORDER BY name, priority DESC`

	var args []interface{}
	if templateName != nil {
		args = []interface{}{*templateName, containerID}
	} else {
		args = []interface{}{"", containerID}
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to resolve variables")
	}
	defer rows.Close()

	return r.scanVariables(rows)
}

// GetHistory retrieves the version history of a variable
func (r *ConfigVariableRepository) GetHistory(ctx context.Context, variableID uuid.UUID, limit int) ([]*models.VariableHistory, error) {
	if limit <= 0 {
		limit = 20
	}

	query := `
		SELECT id, variable_id, version, value, updated_by, updated_at
		FROM config_variable_history
		WHERE variable_id = $1
		ORDER BY version DESC
		LIMIT $2`

	rows, err := r.db.Query(ctx, query, variableID, limit)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get variable history")
	}
	defer rows.Close()

	var history []*models.VariableHistory
	for rows.Next() {
		h := &models.VariableHistory{}
		err := rows.Scan(
			&h.ID,
			&h.VariableID,
			&h.Version,
			&h.Value,
			&h.UpdatedBy,
			&h.UpdatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan variable history")
		}
		history = append(history, h)
	}

	return history, nil
}

// GetHistoryVersion retrieves a specific version of a variable
func (r *ConfigVariableRepository) GetHistoryVersion(ctx context.Context, variableID uuid.UUID, version int) (*models.VariableHistory, error) {
	query := `
		SELECT id, variable_id, version, value, updated_by, updated_at
		FROM config_variable_history
		WHERE variable_id = $1 AND version = $2`

	row := r.db.QueryRow(ctx, query, variableID, version)

	h := &models.VariableHistory{}
	err := row.Scan(
		&h.ID,
		&h.VariableID,
		&h.Version,
		&h.Value,
		&h.UpdatedBy,
		&h.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("variable history version")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get variable history version")
	}

	return h, nil
}

// ComputeHash computes a SHA-256 hash of variable names and values
func (r *ConfigVariableRepository) ComputeHash(variables []*models.ConfigVariable) string {
	h := sha256.New()
	for _, v := range variables {
		h.Write([]byte(v.Name))
		h.Write([]byte("="))
		h.Write([]byte(v.Value))
		h.Write([]byte("\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// BulkCreate inserts multiple variables in a transaction
func (r *ConfigVariableRepository) BulkCreate(ctx context.Context, variables []*models.ConfigVariable) error {
	log := logger.FromContext(ctx)

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to begin transaction")
	}
	defer tx.Rollback(ctx)

	query := `
		INSERT INTO config_variables (
			id, name, value, type, scope, scope_id, description,
			is_required, default_value, version, created_by, updated_by,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12,
			$13, $14
		)`

	now := time.Now()
	for _, v := range variables {
		if v.ID == uuid.Nil {
			v.ID = uuid.New()
		}
		if v.CreatedAt.IsZero() {
			v.CreatedAt = now
		}
		if v.UpdatedAt.IsZero() {
			v.UpdatedAt = now
		}
		if v.Version == 0 {
			v.Version = 1
		}

		_, err := tx.Exec(ctx, query,
			v.ID,
			v.Name,
			v.Value,
			string(v.Type),
			string(v.Scope),
			v.ScopeID,
			v.Description,
			v.IsRequired,
			v.DefaultValue,
			v.Version,
			v.CreatedBy,
			v.UpdatedBy,
			v.CreatedAt,
			v.UpdatedAt,
		)
		if err != nil {
			if IsDuplicateKeyError(err) {
				return errors.AlreadyExists("variable").WithDetail("name", v.Name)
			}
			return errors.Wrap(err, errors.CodeDatabaseError, "failed to create variable")
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to commit transaction")
	}

	log.Debug("Bulk created config variables", "count", len(variables))
	return nil
}

// DeleteByScope removes all variables in a scope
func (r *ConfigVariableRepository) DeleteByScope(ctx context.Context, scope models.VariableScope, scopeID *string) (int64, error) {
	log := logger.FromContext(ctx)

	var query string
	var args []interface{}

	if scopeID == nil {
		query = `DELETE FROM config_variables WHERE scope = $1 AND scope_id IS NULL`
		args = []interface{}{string(scope)}
	} else {
		query = `DELETE FROM config_variables WHERE scope = $1 AND scope_id = $2`
		args = []interface{}{string(scope), *scopeID}
	}

	result, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to delete variables by scope")
	}

	count := result.RowsAffected()
	if count > 0 {
		log.Info("Deleted variables by scope",
			"scope", scope,
			"scope_id", scopeID,
			"count", count)
	}

	return count, nil
}

// scanVariable scans a single row into a ConfigVariable
func (r *ConfigVariableRepository) scanVariable(row pgx.Row) (*models.ConfigVariable, error) {
	v := &models.ConfigVariable{}
	var varType, scope string

	err := row.Scan(
		&v.ID,
		&v.Name,
		&v.Value,
		&varType,
		&scope,
		&v.ScopeID,
		&v.Description,
		&v.IsRequired,
		&v.DefaultValue,
		&v.Version,
		&v.CreatedBy,
		&v.UpdatedBy,
		&v.CreatedAt,
		&v.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("variable")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan variable")
	}

	v.Type = models.VariableType(varType)
	v.Scope = models.VariableScope(scope)

	return v, nil
}

// scanVariables scans multiple rows into ConfigVariables
func (r *ConfigVariableRepository) scanVariables(rows pgx.Rows) ([]*models.ConfigVariable, error) {
	var variables []*models.ConfigVariable

	for rows.Next() {
		v := &models.ConfigVariable{}
		var varType, scope string

		err := rows.Scan(
			&v.ID,
			&v.Name,
			&v.Value,
			&varType,
			&scope,
			&v.ScopeID,
			&v.Description,
			&v.IsRequired,
			&v.DefaultValue,
			&v.Version,
			&v.CreatedBy,
			&v.UpdatedBy,
			&v.CreatedAt,
			&v.UpdatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan variable")
		}

		v.Type = models.VariableType(varType)
		v.Scope = models.VariableScope(scope)
		variables = append(variables, v)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "error iterating variables")
	}

	return variables, nil
}
