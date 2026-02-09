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
	"github.com/lib/pq"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// OAuthConfigRepository handles OAuth config database operations
type OAuthConfigRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewOAuthConfigRepository creates a new OAuthConfigRepository
func NewOAuthConfigRepository(db *DB, log *logger.Logger) *OAuthConfigRepository {
	return &OAuthConfigRepository{
		db:     db,
		logger: log.Named("oauth_config_repo"),
	}
}

// CreateOAuthConfigInput represents input for creating an OAuth config
type CreateOAuthConfigInput struct {
	Name          string
	Provider      string
	ClientID      string
	ClientSecret  string // Should be encrypted before storing
	AuthURL       string
	TokenURL      string
	UserInfoURL   string
	Scopes        []string
	RedirectURL   string
	DefaultRole   string
	AutoProvision bool
	AdminGroup    string
	OperatorGroup string
	UserIDClaim   string
	UsernameClaim string
	EmailClaim    string
	GroupsClaim   string
	IsEnabled     bool
}

// Create inserts a new OAuth config
func (r *OAuthConfigRepository) Create(ctx context.Context, input *CreateOAuthConfigInput) (*models.OAuthConfig, error) {
	id := uuid.New()
	now := time.Now()

	query := `
		INSERT INTO oauth_configs (
			id, name, provider, client_id, client_secret,
			auth_url, token_url, user_info_url, scopes, redirect_url,
			default_role, auto_provision, admin_group, operator_group,
			user_id_claim, username_claim, email_claim, groups_claim,
			is_enabled, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
		)
		RETURNING id, created_at, updated_at`

	config := &models.OAuthConfig{
		ID:            id,
		Name:          input.Name,
		Provider:      input.Provider,
		ClientID:      input.ClientID,
		ClientSecret:  input.ClientSecret,
		AuthURL:       input.AuthURL,
		TokenURL:      input.TokenURL,
		UserInfoURL:   input.UserInfoURL,
		Scopes:        input.Scopes,
		RedirectURL:   input.RedirectURL,
		DefaultRole:   models.UserRole(input.DefaultRole),
		AutoProvision: input.AutoProvision,
		AdminGroup:    input.AdminGroup,
		OperatorGroup: input.OperatorGroup,
		UserIDClaim:   input.UserIDClaim,
		UsernameClaim: input.UsernameClaim,
		EmailClaim:    input.EmailClaim,
		GroupsClaim:   input.GroupsClaim,
		IsEnabled:     input.IsEnabled,
	}

	if config.Scopes == nil {
		config.Scopes = []string{}
	}

	err := r.db.QueryRow(ctx, query,
		id, input.Name, input.Provider, input.ClientID, input.ClientSecret,
		input.AuthURL, input.TokenURL, input.UserInfoURL, pq.Array(input.Scopes), input.RedirectURL,
		input.DefaultRole, input.AutoProvision, input.AdminGroup, input.OperatorGroup,
		input.UserIDClaim, input.UsernameClaim, input.EmailClaim, input.GroupsClaim,
		input.IsEnabled, now, now,
	).Scan(&config.ID, &config.CreatedAt, &config.UpdatedAt)

	if err != nil {
		if IsDuplicateKeyError(err) {
			return nil, errors.New(errors.CodeConflict, "OAuth provider with this name already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create OAuth config")
	}

	return config, nil
}

// GetByID retrieves an OAuth config by ID
func (r *OAuthConfigRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.OAuthConfig, error) {
	query := `
		SELECT id, name, provider, client_id, client_secret,
			auth_url, token_url, user_info_url, scopes, redirect_url,
			default_role, auto_provision, admin_group, operator_group,
			user_id_claim, username_claim, email_claim, groups_claim,
			is_enabled, created_at, updated_at
		FROM oauth_configs
		WHERE id = $1`

	config := &models.OAuthConfig{}
	var scopes []string

	err := r.db.QueryRow(ctx, query, id).Scan(
		&config.ID, &config.Name, &config.Provider, &config.ClientID, &config.ClientSecret,
		&config.AuthURL, &config.TokenURL, &config.UserInfoURL, pq.Array(&scopes), &config.RedirectURL,
		&config.DefaultRole, &config.AutoProvision, &config.AdminGroup, &config.OperatorGroup,
		&config.UserIDClaim, &config.UsernameClaim, &config.EmailClaim, &config.GroupsClaim,
		&config.IsEnabled, &config.CreatedAt, &config.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.New(errors.CodeNotFound, "OAuth config not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get OAuth config")
	}

	config.Scopes = scopes
	return config, nil
}

// GetByName retrieves an OAuth config by name
func (r *OAuthConfigRepository) GetByName(ctx context.Context, name string) (*models.OAuthConfig, error) {
	query := `
		SELECT id, name, provider, client_id, client_secret,
			auth_url, token_url, user_info_url, scopes, redirect_url,
			default_role, auto_provision, admin_group, operator_group,
			user_id_claim, username_claim, email_claim, groups_claim,
			is_enabled, created_at, updated_at
		FROM oauth_configs
		WHERE name = $1`

	config := &models.OAuthConfig{}
	var scopes []string

	err := r.db.QueryRow(ctx, query, name).Scan(
		&config.ID, &config.Name, &config.Provider, &config.ClientID, &config.ClientSecret,
		&config.AuthURL, &config.TokenURL, &config.UserInfoURL, pq.Array(&scopes), &config.RedirectURL,
		&config.DefaultRole, &config.AutoProvision, &config.AdminGroup, &config.OperatorGroup,
		&config.UserIDClaim, &config.UsernameClaim, &config.EmailClaim, &config.GroupsClaim,
		&config.IsEnabled, &config.CreatedAt, &config.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.New(errors.CodeNotFound, "OAuth config not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get OAuth config")
	}

	config.Scopes = scopes
	return config, nil
}

// List retrieves all OAuth configs
func (r *OAuthConfigRepository) List(ctx context.Context) ([]*models.OAuthConfig, error) {
	query := `
		SELECT id, name, provider, client_id, client_secret,
			auth_url, token_url, user_info_url, scopes, redirect_url,
			default_role, auto_provision, admin_group, operator_group,
			user_id_claim, username_claim, email_claim, groups_claim,
			is_enabled, created_at, updated_at
		FROM oauth_configs
		ORDER BY name ASC`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list OAuth configs")
	}
	defer rows.Close()

	var configs []*models.OAuthConfig
	for rows.Next() {
		config := &models.OAuthConfig{}
		var scopes []string

		err := rows.Scan(
			&config.ID, &config.Name, &config.Provider, &config.ClientID, &config.ClientSecret,
			&config.AuthURL, &config.TokenURL, &config.UserInfoURL, pq.Array(&scopes), &config.RedirectURL,
			&config.DefaultRole, &config.AutoProvision, &config.AdminGroup, &config.OperatorGroup,
			&config.UserIDClaim, &config.UsernameClaim, &config.EmailClaim, &config.GroupsClaim,
			&config.IsEnabled, &config.CreatedAt, &config.UpdatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan OAuth config")
		}

		config.Scopes = scopes
		configs = append(configs, config)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "error iterating OAuth configs")
	}

	return configs, nil
}

// ListEnabled retrieves all enabled OAuth configs
func (r *OAuthConfigRepository) ListEnabled(ctx context.Context) ([]*models.OAuthConfig, error) {
	query := `
		SELECT id, name, provider, client_id, client_secret,
			auth_url, token_url, user_info_url, scopes, redirect_url,
			default_role, auto_provision, admin_group, operator_group,
			user_id_claim, username_claim, email_claim, groups_claim,
			is_enabled, created_at, updated_at
		FROM oauth_configs
		WHERE is_enabled = true
		ORDER BY name ASC`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list enabled OAuth configs")
	}
	defer rows.Close()

	var configs []*models.OAuthConfig
	for rows.Next() {
		config := &models.OAuthConfig{}
		var scopes []string

		err := rows.Scan(
			&config.ID, &config.Name, &config.Provider, &config.ClientID, &config.ClientSecret,
			&config.AuthURL, &config.TokenURL, &config.UserInfoURL, pq.Array(&scopes), &config.RedirectURL,
			&config.DefaultRole, &config.AutoProvision, &config.AdminGroup, &config.OperatorGroup,
			&config.UserIDClaim, &config.UsernameClaim, &config.EmailClaim, &config.GroupsClaim,
			&config.IsEnabled, &config.CreatedAt, &config.UpdatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan OAuth config")
		}

		config.Scopes = scopes
		configs = append(configs, config)
	}

	return configs, nil
}

// UpdateOAuthConfigInput represents input for updating an OAuth config
type UpdateOAuthConfigInput struct {
	Name          *string
	Provider      *string
	ClientID      *string
	ClientSecret  *string
	AuthURL       *string
	TokenURL      *string
	UserInfoURL   *string
	Scopes        []string
	RedirectURL   *string
	DefaultRole   *string
	AutoProvision *bool
	AdminGroup    *string
	OperatorGroup *string
	UserIDClaim   *string
	UsernameClaim *string
	EmailClaim    *string
	GroupsClaim   *string
	IsEnabled     *bool
}

// Update updates an OAuth config
func (r *OAuthConfigRepository) Update(ctx context.Context, id uuid.UUID, input *UpdateOAuthConfigInput) (*models.OAuthConfig, error) {
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
	if input.Provider != nil {
		addClause("provider", *input.Provider)
	}
	if input.ClientID != nil {
		addClause("client_id", *input.ClientID)
	}
	if input.ClientSecret != nil {
		addClause("client_secret", *input.ClientSecret)
	}
	if input.AuthURL != nil {
		addClause("auth_url", *input.AuthURL)
	}
	if input.TokenURL != nil {
		addClause("token_url", *input.TokenURL)
	}
	if input.UserInfoURL != nil {
		addClause("user_info_url", *input.UserInfoURL)
	}
	if input.Scopes != nil {
		addClause("scopes", pq.Array(input.Scopes))
	}
	if input.RedirectURL != nil {
		addClause("redirect_url", *input.RedirectURL)
	}
	if input.DefaultRole != nil {
		addClause("default_role", *input.DefaultRole)
	}
	if input.AutoProvision != nil {
		addClause("auto_provision", *input.AutoProvision)
	}
	if input.AdminGroup != nil {
		addClause("admin_group", *input.AdminGroup)
	}
	if input.OperatorGroup != nil {
		addClause("operator_group", *input.OperatorGroup)
	}
	if input.UserIDClaim != nil {
		addClause("user_id_claim", *input.UserIDClaim)
	}
	if input.UsernameClaim != nil {
		addClause("username_claim", *input.UsernameClaim)
	}
	if input.EmailClaim != nil {
		addClause("email_claim", *input.EmailClaim)
	}
	if input.GroupsClaim != nil {
		addClause("groups_claim", *input.GroupsClaim)
	}
	if input.IsEnabled != nil {
		addClause("is_enabled", *input.IsEnabled)
	}

	if len(setClauses) == 0 {
		return r.GetByID(ctx, id)
	}

	// Build query with fmt since we need dynamic placeholders
	query := "UPDATE oauth_configs SET "
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
			return nil, errors.New(errors.CodeConflict, "OAuth provider with this name already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to update OAuth config")
	}

	if result.RowsAffected() == 0 {
		return nil, errors.New(errors.CodeNotFound, "OAuth config not found")
	}

	return r.GetByID(ctx, id)
}

// Delete removes an OAuth config
func (r *OAuthConfigRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM oauth_configs WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete OAuth config")
	}

	if result.RowsAffected() == 0 {
		return errors.New(errors.CodeNotFound, "OAuth config not found")
	}

	return nil
}

// Count returns the total number of OAuth configs
func (r *OAuthConfigRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.QueryRow(ctx, "SELECT COUNT(*) FROM oauth_configs").Scan(&count)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count OAuth configs")
	}
	return count, nil
}

// CountEnabled returns the number of enabled OAuth configs
func (r *OAuthConfigRepository) CountEnabled(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.QueryRow(ctx, "SELECT COUNT(*) FROM oauth_configs WHERE is_enabled = true").Scan(&count)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count enabled OAuth configs")
	}
	return count, nil
}
