// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PreferencesRepo implements PreferencesRepository using PostgreSQL.
type PreferencesRepo struct {
	pool *pgxpool.Pool
}

func NewPreferencesRepo(pool *pgxpool.Pool) *PreferencesRepo {
	return &PreferencesRepo{pool: pool}
}

// GetUserPreferences returns the JSON preferences string for a user.
// Returns empty string if no preferences are stored.
func (r *PreferencesRepo) GetUserPreferences(ctx context.Context, userID string) (string, error) {
	var prefs string
	err := r.pool.QueryRow(ctx,
		`SELECT preferences::text FROM user_preferences WHERE user_id = $1`,
		userID,
	).Scan(&prefs)

	if err == pgx.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get user preferences: %w", err)
	}
	return prefs, nil
}

// SaveUserPreferences upserts preferences for a user.
func (r *PreferencesRepo) SaveUserPreferences(userID string, prefsJSON string) error {
	_, err := r.pool.Exec(context.Background(),
		`INSERT INTO user_preferences (user_id, preferences)
		 VALUES ($1, $2::jsonb)
		 ON CONFLICT (user_id) DO UPDATE SET preferences = $2::jsonb`,
		userID, prefsJSON,
	)
	if err != nil {
		return fmt.Errorf("save user preferences: %w", err)
	}
	return nil
}

// DeleteUserPreferences removes all preferences for a user (reset).
func (r *PreferencesRepo) DeleteUserPreferences(userID string) error {
	_, err := r.pool.Exec(context.Background(),
		`DELETE FROM user_preferences WHERE user_id = $1`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("delete user preferences: %w", err)
	}
	return nil
}
