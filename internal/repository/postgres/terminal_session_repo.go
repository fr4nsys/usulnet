// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// TerminalSessionRepository handles terminal session database operations.
type TerminalSessionRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewTerminalSessionRepository creates a new terminal session repository.
func NewTerminalSessionRepository(db *DB, log *logger.Logger) *TerminalSessionRepository {
	return &TerminalSessionRepository{
		db:     db,
		logger: log.Named("terminal_session_repo"),
	}
}

// TerminalSession represents a terminal session record.
type TerminalSession struct {
	ID           uuid.UUID  `db:"id"`
	UserID       uuid.UUID  `db:"user_id"`
	Username     string     `db:"username"`
	TargetType   string     `db:"target_type"` // "container" or "host"
	TargetID     string     `db:"target_id"`
	TargetName   string     `db:"target_name"`
	HostID       *uuid.UUID `db:"host_id"`
	Shell        string     `db:"shell"`
	TermType     string     `db:"term_type"`
	TermCols     int        `db:"term_cols"`
	TermRows     int        `db:"term_rows"`
	ClientIP     string     `db:"client_ip"`
	UserAgent    string     `db:"user_agent"`
	StartedAt    time.Time  `db:"started_at"`
	EndedAt      *time.Time `db:"ended_at"`
	DurationMs   *int64     `db:"duration_ms"`
	Status       string     `db:"status"` // "active", "completed", "error", "disconnected"
	ErrorMessage string     `db:"error_message"`
}

// CreateInput represents input for creating a terminal session.
type CreateTerminalSessionInput struct {
	UserID     uuid.UUID
	Username   string
	TargetType string
	TargetID   string
	TargetName string
	HostID     *uuid.UUID
	Shell      string
	TermCols   int
	TermRows   int
	ClientIP   string
	UserAgent  string
}

// Create creates a new terminal session and returns its ID.
func (r *TerminalSessionRepository) Create(ctx context.Context, input *CreateTerminalSessionInput) (uuid.UUID, error) {
	id := uuid.New()
	query := `
		INSERT INTO terminal_sessions (
			id, user_id, username, target_type, target_id, target_name,
			host_id, shell, term_cols, term_rows, client_ip, user_agent,
			started_at, status
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), 'active'
		)`

	_, err := r.db.Exec(ctx, query,
		id,
		input.UserID,
		input.Username,
		input.TargetType,
		input.TargetID,
		input.TargetName,
		input.HostID,
		input.Shell,
		input.TermCols,
		input.TermRows,
		input.ClientIP,
		input.UserAgent,
	)
	if err != nil {
		return uuid.Nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create terminal session")
	}

	return id, nil
}

// End marks a terminal session as ended.
func (r *TerminalSessionRepository) End(ctx context.Context, sessionID uuid.UUID, status, errorMsg string) error {
	query := `
		UPDATE terminal_sessions
		SET ended_at = NOW(),
			status = $2,
			error_message = $3
		WHERE id = $1 AND status = 'active'`

	result, err := r.db.Exec(ctx, query, sessionID, status, errorMsg)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to end terminal session")
	}

	if result.RowsAffected() == 0 {
		r.logger.Warn("terminal session not found or already ended", "session_id", sessionID)
	}

	return nil
}

// UpdateResize updates the terminal dimensions.
func (r *TerminalSessionRepository) UpdateResize(ctx context.Context, sessionID uuid.UUID, cols, rows int) error {
	query := `
		UPDATE terminal_sessions
		SET term_cols = $2, term_rows = $3
		WHERE id = $1 AND status = 'active'`

	_, err := r.db.Exec(ctx, query, sessionID, cols, rows)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update terminal size")
	}

	return nil
}

// Get retrieves a terminal session by ID.
func (r *TerminalSessionRepository) Get(ctx context.Context, sessionID uuid.UUID) (*TerminalSession, error) {
	query := `
		SELECT id, user_id, username, target_type, target_id, target_name,
			host_id, shell, term_type, term_cols, term_rows, client_ip, user_agent,
			started_at, ended_at, duration_ms, status, error_message
		FROM terminal_sessions
		WHERE id = $1`

	row := r.db.QueryRow(ctx, query, sessionID)
	session := &TerminalSession{}
	err := row.Scan(
		&session.ID, &session.UserID, &session.Username,
		&session.TargetType, &session.TargetID, &session.TargetName,
		&session.HostID, &session.Shell, &session.TermType,
		&session.TermCols, &session.TermRows, &session.ClientIP, &session.UserAgent,
		&session.StartedAt, &session.EndedAt, &session.DurationMs,
		&session.Status, &session.ErrorMessage,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.Wrap(err, errors.CodeNotFound, "terminal session not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get terminal session")
	}

	return session, nil
}

// ListOptions contains options for listing terminal sessions.
type ListTerminalSessionOptions struct {
	UserID     *uuid.UUID
	TargetType *string
	TargetID   *string
	HostID     *uuid.UUID
	Status     *string
	Since      *time.Time
	Until      *time.Time
	Limit      int
	Offset     int
}

// List retrieves terminal sessions with filtering and pagination.
func (r *TerminalSessionRepository) List(ctx context.Context, opts ListTerminalSessionOptions) ([]*TerminalSession, int, error) {
	// Build WHERE clause
	var conditions []string
	var args []interface{}
	argNum := 1

	if opts.UserID != nil {
		conditions = append(conditions, "user_id = $"+itoa(argNum))
		args = append(args, *opts.UserID)
		argNum++
	}
	if opts.TargetType != nil {
		conditions = append(conditions, "target_type = $"+itoa(argNum))
		args = append(args, *opts.TargetType)
		argNum++
	}
	if opts.TargetID != nil {
		conditions = append(conditions, "target_id = $"+itoa(argNum))
		args = append(args, *opts.TargetID)
		argNum++
	}
	if opts.HostID != nil {
		conditions = append(conditions, "host_id = $"+itoa(argNum))
		args = append(args, *opts.HostID)
		argNum++
	}
	if opts.Status != nil {
		conditions = append(conditions, "status = $"+itoa(argNum))
		args = append(args, *opts.Status)
		argNum++
	}
	if opts.Since != nil {
		conditions = append(conditions, "started_at >= $"+itoa(argNum))
		args = append(args, *opts.Since)
		argNum++
	}
	if opts.Until != nil {
		conditions = append(conditions, "started_at <= $"+itoa(argNum))
		args = append(args, *opts.Until)
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := "SELECT COUNT(*) FROM terminal_sessions" + whereClause
	var total int
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count terminal sessions")
	}

	// Fetch sessions
	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	if opts.Limit > 1000 {
		opts.Limit = 1000
	}

	query := `
		SELECT id, user_id, username, target_type, target_id, target_name,
			host_id, shell, term_type, term_cols, term_rows, client_ip, user_agent,
			started_at, ended_at, duration_ms, status, error_message
		FROM terminal_sessions` + whereClause + `
		ORDER BY started_at DESC
		LIMIT $` + itoa(argNum) + ` OFFSET $` + itoa(argNum+1)

	args = append(args, opts.Limit, opts.Offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to list terminal sessions")
	}
	defer rows.Close()

	var sessions []*TerminalSession
	for rows.Next() {
		session := &TerminalSession{}
		err := rows.Scan(
			&session.ID, &session.UserID, &session.Username,
			&session.TargetType, &session.TargetID, &session.TargetName,
			&session.HostID, &session.Shell, &session.TermType,
			&session.TermCols, &session.TermRows, &session.ClientIP, &session.UserAgent,
			&session.StartedAt, &session.EndedAt, &session.DurationMs,
			&session.Status, &session.ErrorMessage,
		)
		if err != nil {
			return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan terminal session")
		}
		sessions = append(sessions, session)
	}

	return sessions, total, nil
}

// GetActiveSessions returns all currently active sessions.
func (r *TerminalSessionRepository) GetActiveSessions(ctx context.Context) ([]*TerminalSession, error) {
	status := "active"
	sessions, _, err := r.List(ctx, ListTerminalSessionOptions{
		Status: &status,
		Limit:  1000,
	})
	return sessions, err
}

// GetByTarget returns sessions for a specific target.
func (r *TerminalSessionRepository) GetByTarget(ctx context.Context, targetType, targetID string, limit int) ([]*TerminalSession, error) {
	sessions, _, err := r.List(ctx, ListTerminalSessionOptions{
		TargetType: &targetType,
		TargetID:   &targetID,
		Limit:      limit,
	})
	return sessions, err
}

// GetByUser returns sessions for a specific user.
func (r *TerminalSessionRepository) GetByUser(ctx context.Context, userID uuid.UUID, limit int) ([]*TerminalSession, error) {
	sessions, _, err := r.List(ctx, ListTerminalSessionOptions{
		UserID: &userID,
		Limit:  limit,
	})
	return sessions, err
}

// CleanupStaleSessions marks old active sessions as disconnected.
func (r *TerminalSessionRepository) CleanupStaleSessions(ctx context.Context, maxAgeHours int) (int, error) {
	query := `SELECT cleanup_stale_terminal_sessions($1)`
	var affected int
	err := r.db.QueryRow(ctx, query, maxAgeHours).Scan(&affected)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to cleanup stale sessions")
	}
	return affected, nil
}

// Note: itoa is defined in job_repo.go
