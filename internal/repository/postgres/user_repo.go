// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package postgres provides PostgreSQL repository implementations.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/models"
)

// UserRepository handles user database operations.
type UserRepository struct {
	db *DB
}

// NewUserRepository creates a new user repository.
func NewUserRepository(db *DB) *UserRepository {
	return &UserRepository{db: db}
}

// ============================================================================
// CRUD Operations
// ============================================================================

// Create inserts a new user into the database.
func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (
			id, username, email, password_hash, role, is_active, 
			is_ldap, ldap_dn, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		)`

	now := time.Now().UTC()
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}
	user.CreatedAt = now
	user.UpdatedAt = now

	_, err := r.db.Exec(ctx, query,
		user.ID,
		user.Username,
		user.Email,
		user.PasswordHash,
		user.Role,
		user.IsActive,
		user.IsLDAP,
		user.LDAPDN,
		user.CreatedAt,
		user.UpdatedAt,
	)

	if err != nil {
		if IsDuplicateKeyError(err) {
			return apperrors.AlreadyExists("user")
		}
		return fmt.Errorf("create user: %w", err)
	}

	return nil
}

// GetByID retrieves a user by ID.
func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	query := `
		SELECT id, username, email, password_hash, role, is_active,
			   is_ldap, ldap_dn, failed_login_attempts, locked_until,
			   last_login_at, totp_secret, totp_enabled, totp_verified_at,
			   created_at, updated_at
		FROM users
		WHERE id = $1`

	user := &models.User{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.IsActive,
		&user.IsLDAP,
		&user.LDAPDN,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.LastLoginAt,
		&user.TOTPSecret,
		&user.TOTPEnabled,
		&user.TOTPVerifiedAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.NotFound("user")
		}
		return nil, fmt.Errorf("get user by id: %w", err)
	}

	return user, nil
}

// GetByUsername retrieves a user by username.
func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	query := `
		SELECT id, username, email, password_hash, role, is_active,
			   is_ldap, ldap_dn, failed_login_attempts, locked_until,
			   last_login_at, totp_secret, totp_enabled, totp_verified_at,
			   created_at, updated_at
		FROM users
		WHERE LOWER(username) = LOWER($1)`

	user := &models.User{}
	err := r.db.QueryRow(ctx, query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.IsActive,
		&user.IsLDAP,
		&user.LDAPDN,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.LastLoginAt,
		&user.TOTPSecret,
		&user.TOTPEnabled,
		&user.TOTPVerifiedAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.NotFound("user")
		}
		return nil, fmt.Errorf("get user by username: %w", err)
	}

	return user, nil
}

// GetByEmail retrieves a user by email.
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `
		SELECT id, username, email, password_hash, role, is_active,
			   is_ldap, ldap_dn, failed_login_attempts, locked_until,
			   last_login_at, totp_secret, totp_enabled, totp_verified_at,
			   created_at, updated_at
		FROM users
		WHERE LOWER(email) = LOWER($1)`

	user := &models.User{}
	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.IsActive,
		&user.IsLDAP,
		&user.LDAPDN,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.LastLoginAt,
		&user.TOTPSecret,
		&user.TOTPEnabled,
		&user.TOTPVerifiedAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.NotFound("user")
		}
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	return user, nil
}

// Update updates an existing user.
func (r *UserRepository) Update(ctx context.Context, user *models.User) error {
	query := `
		UPDATE users SET
			email = $2,
			password_hash = $3,
			role = $4,
			is_active = $5,
			updated_at = $6
		WHERE id = $1`

	user.UpdatedAt = time.Now().UTC()

	result, err := r.db.Exec(ctx, query,
		user.ID,
		user.Email,
		user.PasswordHash,
		user.Role,
		user.IsActive,
		user.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return apperrors.NotFound("user")
	}

	return nil
}

// Delete removes a user from the database.
func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return apperrors.NotFound("user")
	}

	return nil
}

// ============================================================================
// List & Search
// ============================================================================

// ListOptions contains options for listing users.
type UserListOptions struct {
	Page     int
	PerPage  int
	Search   string           // Search in username and email
	Role     *models.UserRole // Filter by role
	IsActive *bool            // Filter by active status
	IsLDAP   *bool            // Filter by LDAP status
	SortBy   string           // Field to sort by
	SortDesc bool             // Sort descending
}

// List retrieves users with pagination and filtering.
func (r *UserRepository) List(ctx context.Context, opts UserListOptions) ([]*models.User, int64, error) {
	// Build WHERE clause
	var conditions []string
	var args []interface{}
	argNum := 1

	if opts.Search != "" {
		conditions = append(conditions, fmt.Sprintf(
			"(LOWER(username) LIKE LOWER($%d) OR LOWER(email) LIKE LOWER($%d))",
			argNum, argNum,
		))
		args = append(args, "%"+opts.Search+"%")
		argNum++
	}

	if opts.Role != nil {
		conditions = append(conditions, fmt.Sprintf("role = $%d", argNum))
		args = append(args, *opts.Role)
		argNum++
	}

	if opts.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argNum))
		args = append(args, *opts.IsActive)
		argNum++
	}

	if opts.IsLDAP != nil {
		conditions = append(conditions, fmt.Sprintf("is_ldap = $%d", argNum))
		args = append(args, *opts.IsLDAP)
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM users %s", whereClause)
	var total int64
	if err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}

	// Build ORDER BY
	sortField := "created_at"
	allowedSortFields := map[string]bool{
		"username": true, "email": true, "role": true,
		"created_at": true, "last_login_at": true,
	}
	if opts.SortBy != "" && allowedSortFields[opts.SortBy] {
		sortField = opts.SortBy
	}

	sortOrder := "ASC"
	if opts.SortDesc {
		sortOrder = "DESC"
	}

	// Pagination
	if opts.Page < 1 {
		opts.Page = 1
	}
	if opts.PerPage < 1 || opts.PerPage > 100 {
		opts.PerPage = 20
	}
	offset := (opts.Page - 1) * opts.PerPage

	// Query users
	query := fmt.Sprintf(`
		SELECT id, username, email, password_hash, role, is_active,
			   is_ldap, ldap_dn, failed_login_attempts, locked_until,
			   last_login_at, totp_secret, totp_enabled, totp_verified_at,
			   created_at, updated_at
		FROM users
		%s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d`,
		whereClause, sortField, sortOrder, argNum, argNum+1,
	)
	args = append(args, opts.PerPage, offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		user := &models.User{}
		if err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.Email,
			&user.PasswordHash,
			&user.Role,
			&user.IsActive,
			&user.IsLDAP,
			&user.LDAPDN,
			&user.FailedLoginAttempts,
			&user.LockedUntil,
			&user.LastLoginAt,
			&user.TOTPSecret,
			&user.TOTPEnabled,
			&user.TOTPVerifiedAt,
			&user.CreatedAt,
			&user.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate users: %w", err)
	}

	return users, total, nil
}

// ============================================================================
// Login & Security
// ============================================================================

// UpdateLastLogin updates the last login timestamp.
func (r *UserRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users SET
			last_login_at = $2,
			failed_login_attempts = 0,
			locked_until = NULL
		WHERE id = $1`

	_, err := r.db.Exec(ctx, query, id, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("update last login: %w", err)
	}

	return nil
}

// IncrementFailedAttempts increments failed login attempts and optionally locks the account.
func (r *UserRepository) IncrementFailedAttempts(ctx context.Context, id uuid.UUID, maxAttempts int, lockDuration time.Duration) error {
	query := `
		UPDATE users SET
			failed_login_attempts = failed_login_attempts + 1,
			locked_until = CASE 
				WHEN failed_login_attempts + 1 >= $2 THEN $3
				ELSE locked_until
			END,
			updated_at = $4
		WHERE id = $1`

	lockedUntil := time.Now().UTC().Add(lockDuration)
	_, err := r.db.Exec(ctx, query, id, maxAttempts, lockedUntil, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("increment failed attempts: %w", err)
	}

	return nil
}

// ResetFailedAttempts resets the failed login attempts counter.
func (r *UserRepository) ResetFailedAttempts(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users SET
			failed_login_attempts = 0,
			locked_until = NULL,
			updated_at = $2
		WHERE id = $1`

	_, err := r.db.Exec(ctx, query, id, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("reset failed attempts: %w", err)
	}

	return nil
}

// Unlock unlocks a user account.
func (r *UserRepository) Unlock(ctx context.Context, id uuid.UUID) error {
	return r.ResetFailedAttempts(ctx, id)
}

// UpdatePassword updates a user's password hash and records the change timestamp.
func (r *UserRepository) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	now := time.Now().UTC()
	query := `
		UPDATE users SET
			password_hash = $2,
			password_changed_at = $3,
			updated_at = $3
		WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id, passwordHash, now)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	if result.RowsAffected() == 0 {
		return apperrors.NotFound("user")
	}

	return nil
}

// GetPasswordHistory returns the N most recent password hashes for a user.
func (r *UserRepository) GetPasswordHistory(ctx context.Context, userID uuid.UUID, limit int) ([]string, error) {
	query := `
		SELECT password_hash FROM password_history
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2`

	rows, err := r.db.Query(ctx, query, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("get password history: %w", err)
	}
	defer rows.Close()

	var hashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, fmt.Errorf("scan password history: %w", err)
		}
		hashes = append(hashes, hash)
	}

	return hashes, rows.Err()
}

// SavePasswordHistory adds a password hash to the user's password history.
func (r *UserRepository) SavePasswordHistory(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	query := `INSERT INTO password_history (user_id, password_hash, created_at) VALUES ($1, $2, $3)`
	_, err := r.db.Exec(ctx, query, userID, passwordHash, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("save password history: %w", err)
	}
	return nil
}

// UpdatePasswordExpiry updates the password expiration date for a user.
func (r *UserRepository) UpdatePasswordExpiry(ctx context.Context, userID uuid.UUID, expiresAt *time.Time) error {
	query := `UPDATE users SET password_expires_at = $2, updated_at = $3 WHERE id = $1`
	_, err := r.db.Exec(ctx, query, userID, expiresAt, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("update password expiry: %w", err)
	}
	return nil
}

// ============================================================================
// Existence checks
// ============================================================================

// ExistsByUsername checks if a user with the given username exists.
func (r *UserRepository) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(username) = LOWER($1))`

	var exists bool
	if err := r.db.QueryRow(ctx, query, username).Scan(&exists); err != nil {
		return false, fmt.Errorf("check username exists: %w", err)
	}

	return exists, nil
}

// ExistsByEmail checks if a user with the given email exists.
func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(email) = LOWER($1))`

	var exists bool
	if err := r.db.QueryRow(ctx, query, email).Scan(&exists); err != nil {
		return false, fmt.Errorf("check email exists: %w", err)
	}

	return exists, nil
}

// ============================================================================
// Statistics
// ============================================================================

// UserStats contains user statistics.
type UserStats struct {
	Total    int64 `json:"total"`
	Active   int64 `json:"active"`
	Inactive int64 `json:"inactive"`
	LDAP     int64 `json:"ldap"`
	Local    int64 `json:"local"`
	Locked   int64 `json:"locked"`
	Admins   int64 `json:"admins"`
}

// GetStats retrieves user statistics.
func (r *UserRepository) GetStats(ctx context.Context) (*UserStats, error) {
	query := `
		SELECT 
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE is_active = true) as active,
			COUNT(*) FILTER (WHERE is_active = false) as inactive,
			COUNT(*) FILTER (WHERE is_ldap = true) as ldap,
			COUNT(*) FILTER (WHERE is_ldap = false) as local,
			COUNT(*) FILTER (WHERE locked_until > NOW()) as locked,
			COUNT(*) FILTER (WHERE role = 'admin') as admins
		FROM users`

	stats := &UserStats{}
	err := r.db.QueryRow(ctx, query).Scan(
		&stats.Total,
		&stats.Active,
		&stats.Inactive,
		&stats.LDAP,
		&stats.Local,
		&stats.Locked,
		&stats.Admins,
	)

	if err != nil {
		return nil, fmt.Errorf("get user stats: %w", err)
	}

	return stats, nil
}

// ============================================================================
// LDAP specific
// ============================================================================

// GetOrCreateLDAPUser gets or creates a user from LDAP authentication.
func (r *UserRepository) GetOrCreateLDAPUser(ctx context.Context, username, email, ldapDN string, role models.UserRole) (*models.User, bool, error) {
	// Try to find existing user
	user, err := r.GetByUsername(ctx, username)
	if err == nil {
		// User exists
		return user, false, nil
	}

	// Check if error is "not found"
	var appErr *apperrors.AppError
	if !errors.As(err, &appErr) {
		return nil, false, err
	}

	// Create new LDAP user
	user = &models.User{
		ID:           uuid.New(),
		Username:     username,
		Email:        &email,
		PasswordHash: "", // LDAP users don't have local password
		Role:         role,
		IsActive:     true,
		IsLDAP:       true,
		LDAPDN:       &ldapDN,
	}

	if err := r.Create(ctx, user); err != nil {
		return nil, false, err
	}

	return user, true, nil
}

// ============================================================================
// Batch operations
// ============================================================================

// DeleteInactive deletes users that haven't logged in for the specified duration.
func (r *UserRepository) DeleteInactive(ctx context.Context, olderThan time.Duration) (int64, error) {
	query := `
		DELETE FROM users 
		WHERE last_login_at < $1 
		AND is_active = false 
		AND role != 'admin'`

	threshold := time.Now().UTC().Add(-olderThan)
	result, err := r.db.Exec(ctx, query, threshold)
	if err != nil {
		return 0, fmt.Errorf("delete inactive users: %w", err)
	}

	return result.RowsAffected(), nil
}

// CountByRole counts users by role.
func (r *UserRepository) CountByRole(ctx context.Context) (map[models.UserRole]int64, error) {
	query := `SELECT role, COUNT(*) FROM users GROUP BY role`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("count by role: %w", err)
	}
	defer rows.Close()

	counts := make(map[models.UserRole]int64)
	for rows.Next() {
		var role models.UserRole
		var count int64
		if err := rows.Scan(&role, &count); err != nil {
			return nil, fmt.Errorf("scan role count: %w", err)
		}
		counts[role] = count
	}

	return counts, nil
}

// ============================================================================
// TOTP Methods
// ============================================================================

// SetTOTPSecret stores an encrypted TOTP secret for a user (not yet enabled).
func (r *UserRepository) SetTOTPSecret(ctx context.Context, userID uuid.UUID, encryptedSecret string) error {
	query := `UPDATE users SET totp_secret = $1, totp_enabled = false, totp_verified_at = NULL WHERE id = $2`
	result, err := r.db.Exec(ctx, query, encryptedSecret, userID)
	if err != nil {
		return fmt.Errorf("set totp secret: %w", err)
	}
	if result.RowsAffected() == 0 {
		return apperrors.NotFound("user")
	}
	return nil
}

// EnableTOTP marks TOTP as enabled and verified for a user.
func (r *UserRepository) EnableTOTP(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE users SET totp_enabled = true, totp_verified_at = $1 WHERE id = $2 AND totp_secret IS NOT NULL`
	now := time.Now().UTC()
	result, err := r.db.Exec(ctx, query, now, userID)
	if err != nil {
		return fmt.Errorf("enable totp: %w", err)
	}
	if result.RowsAffected() == 0 {
		return apperrors.NotFound("user")
	}
	return nil
}

// DisableTOTP removes TOTP secret and disables 2FA for a user.
func (r *UserRepository) DisableTOTP(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE users SET totp_secret = NULL, totp_enabled = false, totp_verified_at = NULL WHERE id = $1`
	result, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("disable totp: %w", err)
	}
	if result.RowsAffected() == 0 {
		return apperrors.NotFound("user")
	}
	return nil
}
