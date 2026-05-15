// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// SessionRecordingRepository manages session recording configurations.
type SessionRecordingRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewSessionRecordingRepository creates a new repository.
func NewSessionRecordingRepository(db *DB, log *logger.Logger) *SessionRecordingRepository {
	return &SessionRecordingRepository{
		db:     db,
		logger: log.Named("session_recording_repo"),
	}
}

// IsRecordingEnabled checks if recording is enabled for a user (by user config or role config).
func (r *SessionRecordingRepository) IsRecordingEnabled(ctx context.Context, userID uuid.UUID) (bool, int, error) {
	// Check user-specific config first
	var enabled bool
	var retentionDays int
	err := r.db.QueryRow(ctx,
		`SELECT recording_enabled, retention_days FROM session_recording_configs WHERE user_id = $1`,
		userID,
	).Scan(&enabled, &retentionDays)
	if err == nil {
		return enabled, retentionDays, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, 30, errors.Wrap(err, errors.CodeDatabaseError, "failed to check user recording config")
	}

	// Check role-based config
	err = r.db.QueryRow(ctx,
		`SELECT src.recording_enabled, src.retention_days
		 FROM session_recording_configs src
		 JOIN users u ON u.role = src.role_name
		 WHERE u.id = $1 AND src.user_id IS NULL
		 LIMIT 1`,
		userID,
	).Scan(&enabled, &retentionDays)
	if err == nil {
		return enabled, retentionDays, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, 30, errors.Wrap(err, errors.CodeDatabaseError, "failed to check role recording config")
	}

	// Default: not enabled, 30 day retention
	return false, 30, nil
}

// UpdateRecordingMeta updates the recording path and size for a terminal session.
func (r *SessionRecordingRepository) UpdateRecordingMeta(ctx context.Context, sessionID uuid.UUID, path string, size int64) error {
	_, err := r.db.Exec(ctx,
		`UPDATE terminal_sessions SET recording_path = $1, recording_size = $2 WHERE id = $3`,
		path, size, sessionID,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update recording meta")
	}
	return nil
}

// GetExpiredRecordingPaths returns paths of recordings that have exceeded retention.
func (r *SessionRecordingRepository) GetExpiredRecordingPaths(ctx context.Context, defaultRetentionDays int) ([]string, error) {
	rows, err := r.db.Query(ctx,
		`SELECT ts.recording_path
		 FROM terminal_sessions ts
		 LEFT JOIN session_recording_configs src ON ts.user_id = src.user_id
		 WHERE ts.recording_enabled = TRUE
		   AND ts.recording_path IS NOT NULL
		   AND ts.ended_at IS NOT NULL
		   AND ts.ended_at < NOW() - MAKE_INTERVAL(days => COALESCE(src.retention_days, $1))`,
		defaultRetentionDays,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query expired recordings")
	}
	defer rows.Close()

	var paths []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			continue
		}
		paths = append(paths, p)
	}
	return paths, nil
}

// ClearExpiredRecordingMeta clears recording_path and recording_size for expired sessions.
func (r *SessionRecordingRepository) ClearExpiredRecordingMeta(ctx context.Context, defaultRetentionDays int) (int64, error) {
	result, err := r.db.Exec(ctx,
		`UPDATE terminal_sessions
		 SET recording_path = NULL, recording_size = 0
		 FROM (
		   SELECT ts.id
		   FROM terminal_sessions ts
		   LEFT JOIN session_recording_configs src ON ts.user_id = src.user_id
		   WHERE ts.recording_enabled = TRUE
		     AND ts.recording_path IS NOT NULL
		     AND ts.ended_at IS NOT NULL
		     AND ts.ended_at < NOW() - MAKE_INTERVAL(days => COALESCE(src.retention_days, $1))
		 ) expired
		 WHERE terminal_sessions.id = expired.id`,
		defaultRetentionDays,
	)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to clear expired recording meta")
	}
	return result.RowsAffected(), nil
}
