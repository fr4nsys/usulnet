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
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// LDAPConfigRepository handles LDAP config database operations
type LDAPConfigRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewLDAPConfigRepository creates a new LDAPConfigRepository
func NewLDAPConfigRepository(db *DB, log *logger.Logger) *LDAPConfigRepository {
	return &LDAPConfigRepository{
		db:     db,
		logger: log.Named("ldap_config_repo"),
	}
}

// CreateLDAPConfigInput represents input for creating an LDAP config
type CreateLDAPConfigInput struct {
	Name          string
	Host          string
	Port          int
	UseTLS        bool
	StartTLS      bool
	SkipTLSVerify bool
	BindDN        string
	BindPassword  string // Should be encrypted before storing
	BaseDN        string
	UserFilter    string
	UsernameAttr  string
	EmailAttr     string
	GroupFilter   string
	GroupAttr     string
	AdminGroup    string
	OperatorGroup string
	DefaultRole   string
	IsEnabled     bool
}

// Create inserts a new LDAP config
func (r *LDAPConfigRepository) Create(ctx context.Context, input *CreateLDAPConfigInput) (*models.LDAPConfig, error) {
	id := uuid.New()
	now := time.Now()

	query := `
		INSERT INTO ldap_configs (
			id, name, host, port, use_tls, start_tls, skip_tls_verify,
			bind_dn, bind_password, base_dn, user_filter, username_attr, email_attr,
			group_filter, group_attr, admin_group, operator_group,
			default_role, is_enabled, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
		)
		RETURNING id, created_at, updated_at`

	config := &models.LDAPConfig{
		ID:            id,
		Name:          input.Name,
		Host:          input.Host,
		Port:          input.Port,
		UseTLS:        input.UseTLS,
		StartTLS:      input.StartTLS,
		SkipTLSVerify: input.SkipTLSVerify,
		BindDN:        input.BindDN,
		BindPassword:  input.BindPassword,
		BaseDN:        input.BaseDN,
		UserFilter:    input.UserFilter,
		UsernameAttr:  input.UsernameAttr,
		EmailAttr:     input.EmailAttr,
		GroupFilter:   input.GroupFilter,
		GroupAttr:     input.GroupAttr,
		AdminGroup:    input.AdminGroup,
		OperatorGroup: input.OperatorGroup,
		DefaultRole:   models.UserRole(input.DefaultRole),
		IsEnabled:     input.IsEnabled,
	}

	err := r.db.QueryRow(ctx, query,
		id, input.Name, input.Host, input.Port, input.UseTLS, input.StartTLS, input.SkipTLSVerify,
		input.BindDN, input.BindPassword, input.BaseDN, input.UserFilter, input.UsernameAttr, input.EmailAttr,
		input.GroupFilter, input.GroupAttr, input.AdminGroup, input.OperatorGroup,
		input.DefaultRole, input.IsEnabled, now, now,
	).Scan(&config.ID, &config.CreatedAt, &config.UpdatedAt)

	if err != nil {
		if IsDuplicateKeyError(err) {
			return nil, errors.New(errors.CodeConflict, "LDAP provider with this name already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create LDAP config")
	}

	return config, nil
}

// GetByID retrieves an LDAP config by ID
func (r *LDAPConfigRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.LDAPConfig, error) {
	query := `
		SELECT id, name, host, port, use_tls, start_tls, skip_tls_verify,
			bind_dn, bind_password, base_dn, user_filter, username_attr, email_attr,
			group_filter, group_attr, admin_group, operator_group,
			default_role, is_enabled, created_at, updated_at
		FROM ldap_configs
		WHERE id = $1`

	config := &models.LDAPConfig{}

	err := r.db.QueryRow(ctx, query, id).Scan(
		&config.ID, &config.Name, &config.Host, &config.Port, &config.UseTLS, &config.StartTLS, &config.SkipTLSVerify,
		&config.BindDN, &config.BindPassword, &config.BaseDN, &config.UserFilter, &config.UsernameAttr, &config.EmailAttr,
		&config.GroupFilter, &config.GroupAttr, &config.AdminGroup, &config.OperatorGroup,
		&config.DefaultRole, &config.IsEnabled, &config.CreatedAt, &config.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.New(errors.CodeNotFound, "LDAP config not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get LDAP config")
	}

	return config, nil
}

// GetByName retrieves an LDAP config by name
func (r *LDAPConfigRepository) GetByName(ctx context.Context, name string) (*models.LDAPConfig, error) {
	query := `
		SELECT id, name, host, port, use_tls, start_tls, skip_tls_verify,
			bind_dn, bind_password, base_dn, user_filter, username_attr, email_attr,
			group_filter, group_attr, admin_group, operator_group,
			default_role, is_enabled, created_at, updated_at
		FROM ldap_configs
		WHERE name = $1`

	config := &models.LDAPConfig{}

	err := r.db.QueryRow(ctx, query, name).Scan(
		&config.ID, &config.Name, &config.Host, &config.Port, &config.UseTLS, &config.StartTLS, &config.SkipTLSVerify,
		&config.BindDN, &config.BindPassword, &config.BaseDN, &config.UserFilter, &config.UsernameAttr, &config.EmailAttr,
		&config.GroupFilter, &config.GroupAttr, &config.AdminGroup, &config.OperatorGroup,
		&config.DefaultRole, &config.IsEnabled, &config.CreatedAt, &config.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.New(errors.CodeNotFound, "LDAP config not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get LDAP config")
	}

	return config, nil
}

// List retrieves all LDAP configs
func (r *LDAPConfigRepository) List(ctx context.Context) ([]*models.LDAPConfig, error) {
	query := `
		SELECT id, name, host, port, use_tls, start_tls, skip_tls_verify,
			bind_dn, bind_password, base_dn, user_filter, username_attr, email_attr,
			group_filter, group_attr, admin_group, operator_group,
			default_role, is_enabled, created_at, updated_at
		FROM ldap_configs
		ORDER BY name ASC`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list LDAP configs")
	}
	defer rows.Close()

	var configs []*models.LDAPConfig
	for rows.Next() {
		config := &models.LDAPConfig{}

		err := rows.Scan(
			&config.ID, &config.Name, &config.Host, &config.Port, &config.UseTLS, &config.StartTLS, &config.SkipTLSVerify,
			&config.BindDN, &config.BindPassword, &config.BaseDN, &config.UserFilter, &config.UsernameAttr, &config.EmailAttr,
			&config.GroupFilter, &config.GroupAttr, &config.AdminGroup, &config.OperatorGroup,
			&config.DefaultRole, &config.IsEnabled, &config.CreatedAt, &config.UpdatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan LDAP config")
		}

		configs = append(configs, config)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "error iterating LDAP configs")
	}

	return configs, nil
}

// ListEnabled retrieves all enabled LDAP configs
func (r *LDAPConfigRepository) ListEnabled(ctx context.Context) ([]*models.LDAPConfig, error) {
	query := `
		SELECT id, name, host, port, use_tls, start_tls, skip_tls_verify,
			bind_dn, bind_password, base_dn, user_filter, username_attr, email_attr,
			group_filter, group_attr, admin_group, operator_group,
			default_role, is_enabled, created_at, updated_at
		FROM ldap_configs
		WHERE is_enabled = true
		ORDER BY name ASC`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list enabled LDAP configs")
	}
	defer rows.Close()

	var configs []*models.LDAPConfig
	for rows.Next() {
		config := &models.LDAPConfig{}

		err := rows.Scan(
			&config.ID, &config.Name, &config.Host, &config.Port, &config.UseTLS, &config.StartTLS, &config.SkipTLSVerify,
			&config.BindDN, &config.BindPassword, &config.BaseDN, &config.UserFilter, &config.UsernameAttr, &config.EmailAttr,
			&config.GroupFilter, &config.GroupAttr, &config.AdminGroup, &config.OperatorGroup,
			&config.DefaultRole, &config.IsEnabled, &config.CreatedAt, &config.UpdatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan LDAP config")
		}

		configs = append(configs, config)
	}

	return configs, nil
}

// UpdateLDAPConfigInput represents input for updating an LDAP config
type UpdateLDAPConfigInput struct {
	Name          *string
	Host          *string
	Port          *int
	UseTLS        *bool
	StartTLS      *bool
	SkipTLSVerify *bool
	BindDN        *string
	BindPassword  *string
	BaseDN        *string
	UserFilter    *string
	UsernameAttr  *string
	EmailAttr     *string
	GroupFilter   *string
	GroupAttr     *string
	AdminGroup    *string
	OperatorGroup *string
	DefaultRole   *string
	IsEnabled     *bool
}

// Update updates an LDAP config
func (r *LDAPConfigRepository) Update(ctx context.Context, id uuid.UUID, input *UpdateLDAPConfigInput) (*models.LDAPConfig, error) {
	// Build dynamic update query
	setClauses := []string{}
	args := []interface{}{}
	argNum := 1

	addClause := func(col string, val interface{}) {
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", col, argNum))
		args = append(args, val)
		argNum++
	}

	if input.Name != nil {
		addClause("name", *input.Name)
	}
	if input.Host != nil {
		addClause("host", *input.Host)
	}
	if input.Port != nil {
		addClause("port", *input.Port)
	}
	if input.UseTLS != nil {
		addClause("use_tls", *input.UseTLS)
	}
	if input.StartTLS != nil {
		addClause("start_tls", *input.StartTLS)
	}
	if input.SkipTLSVerify != nil {
		addClause("skip_tls_verify", *input.SkipTLSVerify)
	}
	if input.BindDN != nil {
		addClause("bind_dn", *input.BindDN)
	}
	if input.BindPassword != nil {
		addClause("bind_password", *input.BindPassword)
	}
	if input.BaseDN != nil {
		addClause("base_dn", *input.BaseDN)
	}
	if input.UserFilter != nil {
		addClause("user_filter", *input.UserFilter)
	}
	if input.UsernameAttr != nil {
		addClause("username_attr", *input.UsernameAttr)
	}
	if input.EmailAttr != nil {
		addClause("email_attr", *input.EmailAttr)
	}
	if input.GroupFilter != nil {
		addClause("group_filter", *input.GroupFilter)
	}
	if input.GroupAttr != nil {
		addClause("group_attr", *input.GroupAttr)
	}
	if input.AdminGroup != nil {
		addClause("admin_group", *input.AdminGroup)
	}
	if input.OperatorGroup != nil {
		addClause("operator_group", *input.OperatorGroup)
	}
	if input.DefaultRole != nil {
		addClause("default_role", *input.DefaultRole)
	}
	if input.IsEnabled != nil {
		addClause("is_enabled", *input.IsEnabled)
	}

	if len(setClauses) == 0 {
		return r.GetByID(ctx, id)
	}

	// Build query with fmt since we need dynamic placeholders
	query := "UPDATE ldap_configs SET "
	for i, clause := range setClauses {
		if i > 0 {
			query += ", "
		}
		query += clause
	}
	query += fmt.Sprintf(" WHERE id = $%d", argNum)
	args = append(args, id)

	result, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		if IsDuplicateKeyError(err) {
			return nil, errors.New(errors.CodeConflict, "LDAP provider with this name already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to update LDAP config")
	}

	if result.RowsAffected() == 0 {
		return nil, errors.New(errors.CodeNotFound, "LDAP config not found")
	}

	return r.GetByID(ctx, id)
}

// Delete removes an LDAP config
func (r *LDAPConfigRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM ldap_configs WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete LDAP config")
	}

	if result.RowsAffected() == 0 {
		return errors.New(errors.CodeNotFound, "LDAP config not found")
	}

	return nil
}

// Count returns the total number of LDAP configs
func (r *LDAPConfigRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.QueryRow(ctx, "SELECT COUNT(*) FROM ldap_configs").Scan(&count)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count LDAP configs")
	}
	return count, nil
}

// CountEnabled returns the number of enabled LDAP configs
func (r *LDAPConfigRepository) CountEnabled(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.QueryRow(ctx, "SELECT COUNT(*) FROM ldap_configs WHERE is_enabled = true").Scan(&count)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count enabled LDAP configs")
	}
	return count, nil
}
