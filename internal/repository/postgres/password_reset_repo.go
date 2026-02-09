// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// PasswordResetToken represents a password reset token
type PasswordResetToken struct {
	ID        uuid.UUID  `db:"id"`
	UserID    uuid.UUID  `db:"user_id"`
	TokenHash string     `db:"token_hash"`
	ExpiresAt time.Time  `db:"expires_at"`
	UsedAt    *time.Time `db:"used_at"`
	CreatedAt time.Time  `db:"created_at"`
}

// PasswordResetRepository handles password reset token database operations
type PasswordResetRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewPasswordResetRepository creates a new PasswordResetRepository
func NewPasswordResetRepository(db *DB, log *logger.Logger) *PasswordResetRepository {
	return &PasswordResetRepository{
		db:     db,
		logger: log.Named("password_reset_repo"),
	}
}

// GenerateToken generates a cryptographically secure token
func GenerateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// Create creates a new password reset token for a user
// Returns the plain token (to send to user) and error
func (r *PasswordResetRepository) Create(ctx context.Context, userID uuid.UUID, expiresIn time.Duration) (string, error) {
	// First, invalidate any existing tokens for this user
	_, err := r.db.Exec(ctx, `
		UPDATE password_reset_tokens
		SET used_at = CURRENT_TIMESTAMP
		WHERE user_id = $1 AND used_at IS NULL`, userID)
	if err != nil {
		r.logger.Warn("failed to invalidate existing tokens", "error", err)
	}

	// Generate a new token
	token, err := GenerateToken()
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "failed to generate token")
	}

	// Hash the token for storage
	tokenHash := crypto.HashToken(token)

	// Calculate expiration
	expiresAt := time.Now().Add(expiresIn)

	// Insert the token
	query := `
		INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
		RETURNING id`

	var id uuid.UUID
	err = r.db.QueryRow(ctx, query, userID, tokenHash, expiresAt).Scan(&id)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeDatabaseError, "failed to create password reset token")
	}

	return token, nil
}

// ValidateToken validates a password reset token and returns the associated user ID
func (r *PasswordResetRepository) ValidateToken(ctx context.Context, token string) (uuid.UUID, error) {
	tokenHash := crypto.HashToken(token)

	query := `
		SELECT id, user_id, expires_at, used_at
		FROM password_reset_tokens
		WHERE token_hash = $1`

	var resetToken PasswordResetToken
	err := r.db.QueryRow(ctx, query, tokenHash).Scan(
		&resetToken.ID,
		&resetToken.UserID,
		&resetToken.ExpiresAt,
		&resetToken.UsedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return uuid.Nil, errors.New(errors.CodeUnauthorized, "invalid or expired reset token")
		}
		return uuid.Nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to validate token")
	}

	// Check if token was already used
	if resetToken.UsedAt != nil {
		return uuid.Nil, errors.New(errors.CodeUnauthorized, "reset token has already been used")
	}

	// Check if token has expired
	if time.Now().After(resetToken.ExpiresAt) {
		return uuid.Nil, errors.New(errors.CodeUnauthorized, "reset token has expired")
	}

	return resetToken.UserID, nil
}

// MarkAsUsed marks a password reset token as used
func (r *PasswordResetRepository) MarkAsUsed(ctx context.Context, token string) error {
	tokenHash := crypto.HashToken(token)

	result, err := r.db.Exec(ctx, `
		UPDATE password_reset_tokens
		SET used_at = CURRENT_TIMESTAMP
		WHERE token_hash = $1 AND used_at IS NULL`,
		tokenHash)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to mark token as used")
	}

	if result.RowsAffected() == 0 {
		return errors.New(errors.CodeNotFound, "token not found or already used")
	}

	return nil
}

// DeleteExpired removes all expired tokens (for cleanup job)
func (r *PasswordResetRepository) DeleteExpired(ctx context.Context) (int64, error) {
	result, err := r.db.Exec(ctx, `
		DELETE FROM password_reset_tokens
		WHERE expires_at < CURRENT_TIMESTAMP OR used_at IS NOT NULL`)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to delete expired tokens")
	}

	return result.RowsAffected(), nil
}

// GetByUserID retrieves all active (non-expired, non-used) tokens for a user
func (r *PasswordResetRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*PasswordResetToken, error) {
	query := `
		SELECT id, user_id, token_hash, expires_at, used_at, created_at
		FROM password_reset_tokens
		WHERE user_id = $1 AND used_at IS NULL AND expires_at > CURRENT_TIMESTAMP
		ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get tokens by user")
	}
	defer rows.Close()

	var tokens []*PasswordResetToken
	for rows.Next() {
		token := &PasswordResetToken{}
		err := rows.Scan(
			&token.ID,
			&token.UserID,
			&token.TokenHash,
			&token.ExpiresAt,
			&token.UsedAt,
			&token.CreatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan token")
		}
		tokens = append(tokens, token)
	}

	return tokens, nil
}

// InvalidateAllForUser invalidates all tokens for a user
func (r *PasswordResetRepository) InvalidateAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE password_reset_tokens
		SET used_at = CURRENT_TIMESTAMP
		WHERE user_id = $1 AND used_at IS NULL`,
		userID)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to invalidate tokens")
	}

	return nil
}
