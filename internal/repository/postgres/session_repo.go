// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package postgres provides PostgreSQL repository implementations.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/models"
)

// SessionRepository handles session database operations.
type SessionRepository struct {
	db *DB
}

// NewSessionRepository creates a new session repository.
func NewSessionRepository(db *DB) *SessionRepository {
	return &SessionRepository{db: db}
}

// ============================================================================
// CRUD Operations
// ============================================================================

// Create inserts a new session into the database.
func (r *SessionRepository) Create(ctx context.Context, session *models.Session) error {
	query := `
		INSERT INTO sessions (
			id, user_id, refresh_token_hash, user_agent, ip_address,
			expires_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		)`

	now := time.Now().UTC()
	if session.ID == uuid.Nil {
		session.ID = uuid.New()
	}
	session.CreatedAt = now

	_, err := r.db.Exec(ctx, query,
		session.ID,
		session.UserID,
		session.RefreshTokenHash,
		session.UserAgent,
		session.IPAddress,
		session.ExpiresAt,
		session.CreatedAt,
	)

	if err != nil {
		if IsDuplicateKeyError(err) {
			return apperrors.AlreadyExists("session")
		}
		return fmt.Errorf("create session: %w", err)
	}

	return nil
}

// GetByID retrieves a session by ID.
func (r *SessionRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Session, error) {
	query := `
		SELECT id, user_id, refresh_token_hash, user_agent, ip_address,
			   expires_at, created_at
		FROM sessions
		WHERE id = $1`

	session := &models.Session{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&session.ID,
		&session.UserID,
		&session.RefreshTokenHash,
		&session.UserAgent,
		&session.IPAddress,
		&session.ExpiresAt,
		&session.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.NotFound("session")
		}
		return nil, fmt.Errorf("get session by id: %w", err)
	}

	return session, nil
}

// GetByRefreshTokenHash retrieves a session by refresh token hash.
func (r *SessionRepository) GetByRefreshTokenHash(ctx context.Context, tokenHash string) (*models.Session, error) {
	query := `
		SELECT id, user_id, refresh_token_hash, user_agent, ip_address,
			   expires_at, created_at
		FROM sessions
		WHERE refresh_token_hash = $1`

	session := &models.Session{}
	err := r.db.QueryRow(ctx, query, tokenHash).Scan(
		&session.ID,
		&session.UserID,
		&session.RefreshTokenHash,
		&session.UserAgent,
		&session.IPAddress,
		&session.ExpiresAt,
		&session.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.NotFound("session")
		}
		return nil, fmt.Errorf("get session by token hash: %w", err)
	}

	return session, nil
}

// Delete removes a session from the database.
func (r *SessionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM sessions WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	if result.RowsAffected() == 0 {
		return apperrors.NotFound("session")
	}

	return nil
}

// DeleteByUserID removes all sessions for a user.
func (r *SessionRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
	query := `DELETE FROM sessions WHERE user_id = $1`

	result, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return 0, fmt.Errorf("delete sessions by user: %w", err)
	}

	return result.RowsAffected(), nil
}

// ============================================================================
// List & Query
// ============================================================================

// ListByUserID retrieves all sessions for a user.
func (r *SessionRepository) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*models.Session, error) {
	query := `
		SELECT id, user_id, refresh_token_hash, user_agent, ip_address,
			   expires_at, created_at
		FROM sessions
		WHERE user_id = $1
		ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("list sessions by user: %w", err)
	}
	defer rows.Close()

	var sessions []*models.Session
	for rows.Next() {
		session := &models.Session{}
		if err := rows.Scan(
			&session.ID,
			&session.UserID,
			&session.RefreshTokenHash,
			&session.UserAgent,
			&session.IPAddress,
			&session.ExpiresAt,
			&session.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sessions = append(sessions, session)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}

	return sessions, nil
}

// ListActiveByUserID retrieves all non-expired sessions for a user.
func (r *SessionRepository) ListActiveByUserID(ctx context.Context, userID uuid.UUID) ([]*models.Session, error) {
	query := `
		SELECT id, user_id, refresh_token_hash, user_agent, ip_address,
			   expires_at, created_at
		FROM sessions
		WHERE user_id = $1 AND expires_at > NOW()
		ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("list active sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*models.Session
	for rows.Next() {
		session := &models.Session{}
		if err := rows.Scan(
			&session.ID,
			&session.UserID,
			&session.RefreshTokenHash,
			&session.UserAgent,
			&session.IPAddress,
			&session.ExpiresAt,
			&session.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sessions = append(sessions, session)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}

	return sessions, nil
}

// CountByUserID counts sessions for a user.
func (r *SessionRepository) CountByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
	query := `SELECT COUNT(*) FROM sessions WHERE user_id = $1`

	var count int64
	if err := r.db.QueryRow(ctx, query, userID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count sessions: %w", err)
	}

	return count, nil
}

// CountActiveByUserID counts non-expired sessions for a user.
func (r *SessionRepository) CountActiveByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
	query := `SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND expires_at > NOW()`

	var count int64
	if err := r.db.QueryRow(ctx, query, userID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count active sessions: %w", err)
	}

	return count, nil
}

// ============================================================================
// Session Management
// ============================================================================

// UpdateRefreshToken updates the refresh token hash for a session.
func (r *SessionRepository) UpdateRefreshToken(ctx context.Context, id uuid.UUID, newTokenHash string, newExpiresAt time.Time) error {
	query := `
		UPDATE sessions SET
			refresh_token_hash = $2,
			expires_at = $3
		WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id, newTokenHash, newExpiresAt)
	if err != nil {
		return fmt.Errorf("update refresh token: %w", err)
	}

	if result.RowsAffected() == 0 {
		return apperrors.NotFound("session")
	}

	return nil
}

// Extend extends the session expiration time.
func (r *SessionRepository) Extend(ctx context.Context, id uuid.UUID, newExpiresAt time.Time) error {
	query := `UPDATE sessions SET expires_at = $2 WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id, newExpiresAt)
	if err != nil {
		return fmt.Errorf("extend session: %w", err)
	}

	if result.RowsAffected() == 0 {
		return apperrors.NotFound("session")
	}

	return nil
}

// IsValid checks if a session exists and is not expired.
func (r *SessionRepository) IsValid(ctx context.Context, id uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM sessions WHERE id = $1 AND expires_at > NOW())`

	var exists bool
	if err := r.db.QueryRow(ctx, query, id).Scan(&exists); err != nil {
		return false, fmt.Errorf("check session valid: %w", err)
	}

	return exists, nil
}

// ============================================================================
// Cleanup & Maintenance
// ============================================================================

// DeleteExpired removes all expired sessions.
func (r *SessionRepository) DeleteExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM sessions WHERE expires_at <= NOW()`

	result, err := r.db.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}

	return result.RowsAffected(), nil
}

// DeleteOldest deletes the oldest sessions for a user, keeping only the most recent N.
func (r *SessionRepository) DeleteOldest(ctx context.Context, userID uuid.UUID, keepCount int) (int64, error) {
	query := `
		DELETE FROM sessions 
		WHERE user_id = $1 
		AND id NOT IN (
			SELECT id FROM sessions 
			WHERE user_id = $1 
			ORDER BY created_at DESC 
			LIMIT $2
		)`

	result, err := r.db.Exec(ctx, query, userID, keepCount)
	if err != nil {
		return 0, fmt.Errorf("delete oldest sessions: %w", err)
	}

	return result.RowsAffected(), nil
}

// DeleteAllExcept deletes all sessions for a user except the specified one.
func (r *SessionRepository) DeleteAllExcept(ctx context.Context, userID uuid.UUID, keepSessionID uuid.UUID) (int64, error) {
	query := `DELETE FROM sessions WHERE user_id = $1 AND id != $2`

	result, err := r.db.Exec(ctx, query, userID, keepSessionID)
	if err != nil {
		return 0, fmt.Errorf("delete all except: %w", err)
	}

	return result.RowsAffected(), nil
}

// ============================================================================
// Statistics
// ============================================================================

// SessionStats contains session statistics.
type SessionStats struct {
	Total       int64 `json:"total"`
	Active      int64 `json:"active"`
	Expired     int64 `json:"expired"`
	UniqueUsers int64 `json:"unique_users"`
}

// GetStats retrieves session statistics.
func (r *SessionRepository) GetStats(ctx context.Context) (*SessionStats, error) {
	query := `
		SELECT 
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE expires_at > NOW()) as active,
			COUNT(*) FILTER (WHERE expires_at <= NOW()) as expired,
			COUNT(DISTINCT user_id) as unique_users
		FROM sessions`

	stats := &SessionStats{}
	err := r.db.QueryRow(ctx, query).Scan(
		&stats.Total,
		&stats.Active,
		&stats.Expired,
		&stats.UniqueUsers,
	)

	if err != nil {
		return nil, fmt.Errorf("get session stats: %w", err)
	}

	return stats, nil
}

// ============================================================================
// API Key Repository
// ============================================================================

// APIKeyRepository handles API key database operations.
type APIKeyRepository struct {
	db *DB
}

// NewAPIKeyRepository creates a new API key repository.
func NewAPIKeyRepository(db *DB) *APIKeyRepository {
	return &APIKeyRepository{db: db}
}

// Create inserts a new API key into the database.
func (r *APIKeyRepository) Create(ctx context.Context, key *models.APIKey) error {
	query := `
		INSERT INTO api_keys (
			id, user_id, name, key_hash, prefix, expires_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		)`

	now := time.Now().UTC()
	if key.ID == uuid.Nil {
		key.ID = uuid.New()
	}
	key.CreatedAt = now

	_, err := r.db.Exec(ctx, query,
		key.ID,
		key.UserID,
		key.Name,
		key.KeyHash,
		key.Prefix,
		key.ExpiresAt,
		key.CreatedAt,
	)

	if err != nil {
		if IsDuplicateKeyError(err) {
			return apperrors.AlreadyExists("api_key")
		}
		return fmt.Errorf("create api key: %w", err)
	}

	return nil
}

// GetByID retrieves an API key by ID.
func (r *APIKeyRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.APIKey, error) {
	query := `
		SELECT id, user_id, name, key_hash, prefix, last_used_at, expires_at, created_at
		FROM api_keys
		WHERE id = $1`

	key := &models.APIKey{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&key.ID,
		&key.UserID,
		&key.Name,
		&key.KeyHash,
		&key.Prefix,
		&key.LastUsedAt,
		&key.ExpiresAt,
		&key.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.NotFound("api_key")
		}
		return nil, fmt.Errorf("get api key by id: %w", err)
	}

	return key, nil
}

// GetByKeyHash retrieves an API key by its hash.
func (r *APIKeyRepository) GetByKeyHash(ctx context.Context, keyHash string) (*models.APIKey, error) {
	query := `
		SELECT id, user_id, name, key_hash, prefix, last_used_at, expires_at, created_at
		FROM api_keys
		WHERE key_hash = $1`

	key := &models.APIKey{}
	err := r.db.QueryRow(ctx, query, keyHash).Scan(
		&key.ID,
		&key.UserID,
		&key.Name,
		&key.KeyHash,
		&key.Prefix,
		&key.LastUsedAt,
		&key.ExpiresAt,
		&key.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.NotFound("api_key")
		}
		return nil, fmt.Errorf("get api key by hash: %w", err)
	}

	return key, nil
}

// GetByPrefix retrieves API keys by prefix (for identification in UI).
func (r *APIKeyRepository) GetByPrefix(ctx context.Context, prefix string) ([]*models.APIKey, error) {
	query := `
		SELECT id, user_id, name, key_hash, prefix, last_used_at, expires_at, created_at
		FROM api_keys
		WHERE prefix = $1`

	rows, err := r.db.Query(ctx, query, prefix)
	if err != nil {
		return nil, fmt.Errorf("get api keys by prefix: %w", err)
	}
	defer rows.Close()

	var keys []*models.APIKey
	for rows.Next() {
		key := &models.APIKey{}
		if err := rows.Scan(
			&key.ID,
			&key.UserID,
			&key.Name,
			&key.KeyHash,
			&key.Prefix,
			&key.LastUsedAt,
			&key.ExpiresAt,
			&key.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan api key: %w", err)
		}
		keys = append(keys, key)
	}

	return keys, nil
}

// ListByUserID retrieves all API keys for a user.
func (r *APIKeyRepository) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*models.APIKey, error) {
	query := `
		SELECT id, user_id, name, key_hash, prefix, last_used_at, expires_at, created_at
		FROM api_keys
		WHERE user_id = $1
		ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	var keys []*models.APIKey
	for rows.Next() {
		key := &models.APIKey{}
		if err := rows.Scan(
			&key.ID,
			&key.UserID,
			&key.Name,
			&key.KeyHash,
			&key.Prefix,
			&key.LastUsedAt,
			&key.ExpiresAt,
			&key.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan api key: %w", err)
		}
		keys = append(keys, key)
	}

	return keys, nil
}

// Delete removes an API key from the database.
func (r *APIKeyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM api_keys WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete api key: %w", err)
	}

	if result.RowsAffected() == 0 {
		return apperrors.NotFound("api_key")
	}

	return nil
}

// DeleteByUserID removes all API keys for a user.
func (r *APIKeyRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
	query := `DELETE FROM api_keys WHERE user_id = $1`

	result, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return 0, fmt.Errorf("delete api keys by user: %w", err)
	}

	return result.RowsAffected(), nil
}

// UpdateLastUsed updates the last used timestamp for an API key.
func (r *APIKeyRepository) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE api_keys SET last_used_at = $2 WHERE id = $1`

	_, err := r.db.Exec(ctx, query, id, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("update last used: %w", err)
	}

	return nil
}

// DeleteExpired removes all expired API keys.
func (r *APIKeyRepository) DeleteExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM api_keys WHERE expires_at IS NOT NULL AND expires_at <= NOW()`

	result, err := r.db.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("delete expired api keys: %w", err)
	}

	return result.RowsAffected(), nil
}

// CountByUserID counts API keys for a user.
func (r *APIKeyRepository) CountByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
	query := `SELECT COUNT(*) FROM api_keys WHERE user_id = $1`

	var count int64
	if err := r.db.QueryRow(ctx, query, userID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count api keys: %w", err)
	}

	return count, nil
}

// CountAll counts all API keys across all users (global limit check).
func (r *APIKeyRepository) CountAll(ctx context.Context) (int64, error) {
	query := `SELECT COUNT(*) FROM api_keys`

	var count int64
	if err := r.db.QueryRow(ctx, query).Scan(&count); err != nil {
		return 0, fmt.Errorf("count all api keys: %w", err)
	}

	return count, nil
}

// ExistsByName checks if an API key with the given name exists for a user.
func (r *APIKeyRepository) ExistsByName(ctx context.Context, userID uuid.UUID, name string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM api_keys WHERE user_id = $1 AND LOWER(name) = LOWER($2))`

	var exists bool
	if err := r.db.QueryRow(ctx, query, userID, name).Scan(&exists); err != nil {
		return false, fmt.Errorf("check api key name exists: %w", err)
	}

	return exists, nil
}
