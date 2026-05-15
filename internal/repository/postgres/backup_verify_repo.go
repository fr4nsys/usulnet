// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	stderrors "errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// BackupVerificationRepository
// ============================================================================

// BackupVerificationRepository persists backup verification runs.
type BackupVerificationRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewBackupVerificationRepository creates a new repository.
func NewBackupVerificationRepository(db *DB, log *logger.Logger) *BackupVerificationRepository {
	if log == nil {
		log = logger.Nop()
	}
	return &BackupVerificationRepository{
		db:     db,
		logger: log.Named("backup_verify_repo"),
	}
}

// Create inserts a new verification run.
func (r *BackupVerificationRepository) Create(ctx context.Context, v *models.BackupVerification) error {
	if v.ID == uuid.Nil {
		v.ID = uuid.New()
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now()
	}
	if len(v.Details) == 0 {
		v.Details = []byte("{}")
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO backup_verifications (
			id, backup_id, host_id, status, method,
			checksum_valid, files_readable, container_test, data_valid,
			file_count, size_bytes, duration_ms, error_message, details,
			verified_by, started_at, completed_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
		v.ID, v.BackupID, v.HostID, string(v.Status), string(v.Method),
		v.ChecksumValid, v.FilesReadable, v.ContainerTest, v.DataValid,
		v.FileCount, v.SizeBytes, v.DurationMs, v.ErrorMessage, v.Details,
		v.VerifiedBy, v.StartedAt, v.CompletedAt, v.CreatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "create backup verification")
	}
	return nil
}

// GetByID retrieves a verification run by ID.
func (r *BackupVerificationRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.BackupVerification, error) {
	v := &models.BackupVerification{}
	err := r.db.QueryRow(ctx, `
		SELECT id, backup_id, host_id, status, method,
			checksum_valid, files_readable, container_test, data_valid,
			file_count, size_bytes, duration_ms, error_message, details,
			verified_by, started_at, completed_at, created_at
		FROM backup_verifications WHERE id = $1`, id,
	).Scan(
		&v.ID, &v.BackupID, &v.HostID, &v.Status, &v.Method,
		&v.ChecksumValid, &v.FilesReadable, &v.ContainerTest, &v.DataValid,
		&v.FileCount, &v.SizeBytes, &v.DurationMs, &v.ErrorMessage, &v.Details,
		&v.VerifiedBy, &v.StartedAt, &v.CompletedAt, &v.CreatedAt,
	)
	if err != nil {
		if stderrors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("backup_verification").WithDetail("id", id.String())
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get backup verification")
	}
	return v, nil
}

// Update updates a verification run's mutable fields.
func (r *BackupVerificationRepository) Update(ctx context.Context, v *models.BackupVerification) error {
	if len(v.Details) == 0 {
		v.Details = []byte("{}")
	}
	ct, err := r.db.Exec(ctx, `
		UPDATE backup_verifications SET
			status = $2, checksum_valid = $3, files_readable = $4,
			container_test = $5, data_valid = $6, file_count = $7,
			size_bytes = $8, duration_ms = $9, error_message = $10,
			details = $11, started_at = $12, completed_at = $13
		WHERE id = $1`,
		v.ID, string(v.Status), v.ChecksumValid, v.FilesReadable,
		v.ContainerTest, v.DataValid, v.FileCount,
		v.SizeBytes, v.DurationMs, v.ErrorMessage,
		v.Details, v.StartedAt, v.CompletedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "update backup verification")
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("backup_verification").WithDetail("id", v.ID.String())
	}
	return nil
}

// ListByBackup returns every verification run for a backup, newest first.
func (r *BackupVerificationRepository) ListByBackup(ctx context.Context, backupID uuid.UUID) ([]models.BackupVerification, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, backup_id, host_id, status, method,
			checksum_valid, files_readable, container_test, data_valid,
			file_count, size_bytes, duration_ms, error_message, details,
			verified_by, started_at, completed_at, created_at
		FROM backup_verifications WHERE backup_id = $1
		ORDER BY created_at DESC`, backupID,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "list backup verifications by backup")
	}
	defer rows.Close()

	results := make([]models.BackupVerification, 0)
	for rows.Next() {
		var v models.BackupVerification
		if err := rows.Scan(
			&v.ID, &v.BackupID, &v.HostID, &v.Status, &v.Method,
			&v.ChecksumValid, &v.FilesReadable, &v.ContainerTest, &v.DataValid,
			&v.FileCount, &v.SizeBytes, &v.DurationMs, &v.ErrorMessage, &v.Details,
			&v.VerifiedBy, &v.StartedAt, &v.CompletedAt, &v.CreatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "scan backup verification")
		}
		results = append(results, v)
	}
	return results, rows.Err()
}

// ListByHost returns paginated verifications for a host, newest first.
func (r *BackupVerificationRepository) ListByHost(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]models.BackupVerification, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}

	var total int
	if err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM backup_verifications WHERE host_id = $1`, hostID,
	).Scan(&total); err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "count backup verifications")
	}

	rows, err := r.db.Query(ctx, `
		SELECT id, backup_id, host_id, status, method,
			checksum_valid, files_readable, container_test, data_valid,
			file_count, size_bytes, duration_ms, error_message, details,
			verified_by, started_at, completed_at, created_at
		FROM backup_verifications WHERE host_id = $1
		ORDER BY created_at DESC LIMIT $2 OFFSET $3`, hostID, limit, offset,
	)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "list backup verifications by host")
	}
	defer rows.Close()

	results := make([]models.BackupVerification, 0, limit)
	for rows.Next() {
		var v models.BackupVerification
		if err := rows.Scan(
			&v.ID, &v.BackupID, &v.HostID, &v.Status, &v.Method,
			&v.ChecksumValid, &v.FilesReadable, &v.ContainerTest, &v.DataValid,
			&v.FileCount, &v.SizeBytes, &v.DurationMs, &v.ErrorMessage, &v.Details,
			&v.VerifiedBy, &v.StartedAt, &v.CompletedAt, &v.CreatedAt,
		); err != nil {
			return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "scan backup verification")
		}
		results = append(results, v)
	}
	return results, total, rows.Err()
}

// GetLatestByBackup returns the most recent verification for a backup, or nil
// if none has run yet (no error, no rows).
func (r *BackupVerificationRepository) GetLatestByBackup(ctx context.Context, backupID uuid.UUID) (*models.BackupVerification, error) {
	v := &models.BackupVerification{}
	err := r.db.QueryRow(ctx, `
		SELECT id, backup_id, host_id, status, method,
			checksum_valid, files_readable, container_test, data_valid,
			file_count, size_bytes, duration_ms, error_message, details,
			verified_by, started_at, completed_at, created_at
		FROM backup_verifications WHERE backup_id = $1
		ORDER BY created_at DESC LIMIT 1`, backupID,
	).Scan(
		&v.ID, &v.BackupID, &v.HostID, &v.Status, &v.Method,
		&v.ChecksumValid, &v.FilesReadable, &v.ContainerTest, &v.DataValid,
		&v.FileCount, &v.SizeBytes, &v.DurationMs, &v.ErrorMessage, &v.Details,
		&v.VerifiedBy, &v.StartedAt, &v.CompletedAt, &v.CreatedAt,
	)
	if err != nil {
		if stderrors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get latest verification for backup")
	}
	return v, nil
}

// GetStats returns aggregate verification statistics for a host.
func (r *BackupVerificationRepository) GetStats(ctx context.Context, hostID uuid.UUID) (*models.BackupVerificationStats, error) {
	stats := &models.BackupVerificationStats{}

	err := r.db.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status = 'passed'),
			COUNT(*) FILTER (WHERE status = 'failed')
		FROM backup_verifications WHERE host_id = $1`, hostID,
	).Scan(&stats.TotalVerified, &stats.Passed, &stats.Failed)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get verification stats")
	}

	if stats.TotalVerified > 0 {
		stats.PassRate = float64(stats.Passed) / float64(stats.TotalVerified) * 100
	}

	var lastVerified *time.Time
	if err := r.db.QueryRow(ctx, `
		SELECT MAX(completed_at) FROM backup_verifications
		WHERE host_id = $1 AND completed_at IS NOT NULL`, hostID,
	).Scan(&lastVerified); err == nil && lastVerified != nil {
		stats.LastVerified = lastVerified.Format("2006-01-02 15:04")
	}

	return stats, nil
}

// DeleteOlderThan removes verification rows older than the cutoff. Returns
// the number of rows removed.
func (r *BackupVerificationRepository) DeleteOlderThan(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)
	ct, err := r.db.Exec(ctx,
		`DELETE FROM backup_verifications WHERE created_at < $1`, cutoff,
	)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "delete old verifications")
	}
	return ct.RowsAffected(), nil
}

// ============================================================================
// BackupVerificationScheduleRepository
// ============================================================================

// BackupVerificationScheduleRepository persists verification schedules.
type BackupVerificationScheduleRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewBackupVerificationScheduleRepository creates a new schedule repository.
func NewBackupVerificationScheduleRepository(db *DB, log *logger.Logger) *BackupVerificationScheduleRepository {
	if log == nil {
		log = logger.Nop()
	}
	return &BackupVerificationScheduleRepository{
		db:     db,
		logger: log.Named("bv_schedule_repo"),
	}
}

// Create inserts a new schedule.
func (r *BackupVerificationScheduleRepository) Create(ctx context.Context, s *models.BackupVerificationSchedule) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	now := time.Now()
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	s.UpdatedAt = now

	_, err := r.db.Exec(ctx, `
		INSERT INTO backup_verification_schedules (
			id, host_id, schedule, method, max_backups, enabled,
			last_run_at, last_run_status, next_run_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		s.ID, s.HostID, s.Schedule, s.Method, s.MaxBackups, s.Enabled,
		s.LastRunAt, s.LastRunStatus, s.NextRunAt, s.CreatedAt, s.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "create verification schedule")
	}
	return nil
}

// GetByID retrieves a schedule by ID.
func (r *BackupVerificationScheduleRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.BackupVerificationSchedule, error) {
	s := &models.BackupVerificationSchedule{}
	err := r.db.QueryRow(ctx, `
		SELECT id, host_id, schedule, method, max_backups, enabled,
			last_run_at, last_run_status, next_run_at, created_at, updated_at
		FROM backup_verification_schedules WHERE id = $1`, id,
	).Scan(
		&s.ID, &s.HostID, &s.Schedule, &s.Method, &s.MaxBackups, &s.Enabled,
		&s.LastRunAt, &s.LastRunStatus, &s.NextRunAt, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		if stderrors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("verification_schedule").WithDetail("id", id.String())
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get verification schedule")
	}
	return s, nil
}

// List returns every schedule for a host, newest first.
func (r *BackupVerificationScheduleRepository) List(ctx context.Context, hostID uuid.UUID) ([]models.BackupVerificationSchedule, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, host_id, schedule, method, max_backups, enabled,
			last_run_at, last_run_status, next_run_at, created_at, updated_at
		FROM backup_verification_schedules WHERE host_id = $1
		ORDER BY created_at DESC`, hostID,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "list verification schedules")
	}
	defer rows.Close()

	results := make([]models.BackupVerificationSchedule, 0)
	for rows.Next() {
		var s models.BackupVerificationSchedule
		if err := rows.Scan(
			&s.ID, &s.HostID, &s.Schedule, &s.Method, &s.MaxBackups, &s.Enabled,
			&s.LastRunAt, &s.LastRunStatus, &s.NextRunAt, &s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "scan verification schedule")
		}
		results = append(results, s)
	}
	return results, rows.Err()
}

// ListDue returns every enabled schedule whose next_run_at is in the past
// or NULL. The scheduler worker reads this to decide what to run.
func (r *BackupVerificationScheduleRepository) ListDue(ctx context.Context) ([]models.BackupVerificationSchedule, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, host_id, schedule, method, max_backups, enabled,
			last_run_at, last_run_status, next_run_at, created_at, updated_at
		FROM backup_verification_schedules
		WHERE enabled = true AND (next_run_at IS NULL OR next_run_at <= NOW())
		ORDER BY next_run_at ASC NULLS FIRST`,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "list due verification schedules")
	}
	defer rows.Close()

	results := make([]models.BackupVerificationSchedule, 0)
	for rows.Next() {
		var s models.BackupVerificationSchedule
		if err := rows.Scan(
			&s.ID, &s.HostID, &s.Schedule, &s.Method, &s.MaxBackups, &s.Enabled,
			&s.LastRunAt, &s.LastRunStatus, &s.NextRunAt, &s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "scan verification schedule")
		}
		results = append(results, s)
	}
	return results, rows.Err()
}

// Update updates schedule mutable fields.
func (r *BackupVerificationScheduleRepository) Update(ctx context.Context, s *models.BackupVerificationSchedule) error {
	s.UpdatedAt = time.Now()
	ct, err := r.db.Exec(ctx, `
		UPDATE backup_verification_schedules SET
			schedule = $2, method = $3, max_backups = $4, enabled = $5,
			last_run_at = $6, last_run_status = $7, next_run_at = $8, updated_at = $9
		WHERE id = $1`,
		s.ID, s.Schedule, s.Method, s.MaxBackups, s.Enabled,
		s.LastRunAt, s.LastRunStatus, s.NextRunAt, s.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "update verification schedule")
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("verification_schedule").WithDetail("id", s.ID.String())
	}
	return nil
}

// Delete removes a schedule.
func (r *BackupVerificationScheduleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	ct, err := r.db.Exec(ctx, `DELETE FROM backup_verification_schedules WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "delete verification schedule")
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("verification_schedule").WithDetail("id", id.String())
	}
	return nil
}
