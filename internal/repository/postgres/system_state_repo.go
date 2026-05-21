// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// SystemStateRepository reads and writes the instance-wide key/value
// flags table introduced in migration 057. The first consumer is the
// onboarding wizard; future flags should reuse the same store rather
// than carving out one-row-per-flag domain tables.
type SystemStateRepository struct {
	db *DB
}

// NewSystemStateRepository constructs a SystemStateRepository.
func NewSystemStateRepository(db *DB) *SystemStateRepository {
	return &SystemStateRepository{db: db}
}

// Get returns the raw string value for a key. Missing keys return
// ("", false, nil) so callers can apply a default without a separate
// existence check.
func (r *SystemStateRepository) Get(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := r.db.QueryRow(ctx, `SELECT value FROM system_state WHERE key = $1`, key).Scan(&value)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("system_state.get %q: %w", key, err)
	}
	return value, true, nil
}

// Set writes a key/value pair, upserting on conflict.
func (r *SystemStateRepository) Set(ctx context.Context, key, value string) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO system_state (key, value, updated_at) VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
		key, value,
	)
	if err != nil {
		return fmt.Errorf("system_state.set %q: %w", key, err)
	}
	return nil
}
