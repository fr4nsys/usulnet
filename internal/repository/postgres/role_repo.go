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
	"github.com/lib/pq"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// RoleRepository handles role database operations
type RoleRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewRoleRepository creates a new RoleRepository
func NewRoleRepository(db *DB, log *logger.Logger) *RoleRepository {
	return &RoleRepository{
		db:     db,
		logger: log.Named("role_repo"),
	}
}

// Create creates a new role
func (r *RoleRepository) Create(ctx context.Context, role *models.Role) error {
	query := `
		INSERT INTO roles (
			id, name, display_name, description, permissions,
			is_system, is_active, priority, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		)`

	if role.ID == uuid.Nil {
		role.ID = uuid.New()
	}
	now := time.Now()
	role.CreatedAt = now
	role.UpdatedAt = now

	_, err := r.db.Exec(ctx, query,
		role.ID,
		role.Name,
		role.DisplayName,
		role.Description,
		pq.Array(role.Permissions),
		role.IsSystem,
		role.IsActive,
		role.Priority,
		role.CreatedAt,
		role.UpdatedAt,
	)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return errors.New(errors.CodeConflict, "role with this name already exists")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create role")
	}

	return nil
}

// GetByID retrieves a role by ID
func (r *RoleRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	query := `
		SELECT id, name, display_name, description, permissions,
			is_system, is_active, priority, created_at, updated_at
		FROM roles
		WHERE id = $1`

	row := r.db.QueryRow(ctx, query, id)
	return r.scanRole(row)
}

// GetByName retrieves a role by name
func (r *RoleRepository) GetByName(ctx context.Context, name string) (*models.Role, error) {
	query := `
		SELECT id, name, display_name, description, permissions,
			is_system, is_active, priority, created_at, updated_at
		FROM roles
		WHERE name = $1`

	row := r.db.QueryRow(ctx, query, strings.ToLower(name))
	return r.scanRole(row)
}

// Update updates a role
func (r *RoleRepository) Update(ctx context.Context, role *models.Role) error {
	query := `
		UPDATE roles SET
			display_name = $2,
			description = $3,
			permissions = $4,
			is_active = $5,
			priority = $6,
			updated_at = $7
		WHERE id = $1 AND is_system = false`

	role.UpdatedAt = time.Now()

	result, err := r.db.Exec(ctx, query,
		role.ID,
		role.DisplayName,
		role.Description,
		pq.Array(role.Permissions),
		role.IsActive,
		role.Priority,
		role.UpdatedAt,
	)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update role")
	}

	if result.RowsAffected() == 0 {
		// Check if it's a system role
		existing, err := r.GetByID(ctx, role.ID)
		if err != nil {
			return errors.NotFound("role")
		}
		if existing.IsSystem {
			return errors.Forbidden("cannot modify system roles")
		}
		return errors.NotFound("role")
	}

	return nil
}

// Delete deletes a role
func (r *RoleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	// First check if it's a system role
	role, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if role.IsSystem {
		return errors.Forbidden("cannot delete system roles")
	}

	// Check if any users are using this role
	var userCount int
	err = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE role_id = $1", id).Scan(&userCount)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to check role usage")
	}

	if userCount > 0 {
		return errors.New(errors.CodeConflict, fmt.Sprintf("cannot delete role: %d users are assigned to this role", userCount))
	}

	query := `DELETE FROM roles WHERE id = $1 AND is_system = false`
	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete role")
	}

	if result.RowsAffected() == 0 {
		return errors.NotFound("role")
	}

	return nil
}

// RoleListOptions represents options for listing roles
type RoleListOptions struct {
	IncludeInactive bool
	IncludeSystem   bool
	Limit           int
	Offset          int
}

// List retrieves roles with filtering
func (r *RoleRepository) List(ctx context.Context, opts RoleListOptions) ([]*models.Role, int, error) {
	var conditions []string
	var args []interface{}
	argNum := 1

	if !opts.IncludeInactive {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argNum))
		args = append(args, true)
		argNum++
	}

	if !opts.IncludeSystem {
		conditions = append(conditions, fmt.Sprintf("is_system = $%d", argNum))
		args = append(args, false)
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM roles %s", whereClause)
	var total int
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count roles")
	}

	// Set defaults
	if opts.Limit <= 0 {
		opts.Limit = 50
	}

	// Build main query
	query := fmt.Sprintf(`
		SELECT id, name, display_name, description, permissions,
			is_system, is_active, priority, created_at, updated_at
		FROM roles
		%s
		ORDER BY priority DESC, name ASC
		LIMIT $%d OFFSET $%d`,
		whereClause, argNum, argNum+1)

	args = append(args, opts.Limit, opts.Offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to list roles")
	}
	defer rows.Close()

	roles, err := r.scanRoles(rows)
	if err != nil {
		return nil, 0, err
	}

	return roles, total, nil
}

// GetAll retrieves all active roles
func (r *RoleRepository) GetAll(ctx context.Context) ([]*models.Role, error) {
	query := `
		SELECT id, name, display_name, description, permissions,
			is_system, is_active, priority, created_at, updated_at
		FROM roles
		WHERE is_active = true
		ORDER BY priority DESC, name ASC`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get all roles")
	}
	defer rows.Close()

	return r.scanRoles(rows)
}

// GetSystemRoles retrieves all system roles
func (r *RoleRepository) GetSystemRoles(ctx context.Context) ([]*models.Role, error) {
	query := `
		SELECT id, name, display_name, description, permissions,
			is_system, is_active, priority, created_at, updated_at
		FROM roles
		WHERE is_system = true
		ORDER BY priority DESC`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get system roles")
	}
	defer rows.Close()

	return r.scanRoles(rows)
}

// CountCustomRoles counts non-system (custom) roles.
func (r *RoleRepository) CountCustomRoles(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM roles WHERE is_system = false`).Scan(&count)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count custom roles")
	}
	return count, nil
}

// CountUsersWithRole counts users assigned to a role
func (r *RoleRepository) CountUsersWithRole(ctx context.Context, roleID uuid.UUID) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE role_id = $1", roleID).Scan(&count)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count users with role")
	}
	return count, nil
}

// scanRole scans a single row into a Role
func (r *RoleRepository) scanRole(row pgx.Row) (*models.Role, error) {
	role := &models.Role{}

	err := row.Scan(
		&role.ID,
		&role.Name,
		&role.DisplayName,
		&role.Description,
		&role.Permissions,
		&role.IsSystem,
		&role.IsActive,
		&role.Priority,
		&role.CreatedAt,
		&role.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("role")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan role")
	}

	return role, nil
}

// scanRoles scans multiple rows into Roles
func (r *RoleRepository) scanRoles(rows pgx.Rows) ([]*models.Role, error) {
	var roles []*models.Role

	for rows.Next() {
		role := &models.Role{}

		err := rows.Scan(
			&role.ID,
			&role.Name,
			&role.DisplayName,
			&role.Description,
			&role.Permissions,
			&role.IsSystem,
			&role.IsActive,
			&role.Priority,
			&role.CreatedAt,
			&role.UpdatedAt,
		)

		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan role")
		}

		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "error iterating roles")
	}

	return roles, nil
}
