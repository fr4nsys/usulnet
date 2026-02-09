// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package postgres provides PostgreSQL repository implementations.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
)

// BackupRepository implements backup.Repository for PostgreSQL.
type BackupRepository struct {
	db *sql.DB
}

// NewBackupRepository creates a new backup repository.
func NewBackupRepository(db *sql.DB) *BackupRepository {
	return &BackupRepository{db: db}
}

// ============================================================================
// Backup CRUD
// ============================================================================

// Create creates a new backup record.
func (r *BackupRepository) Create(ctx context.Context, backup *models.Backup) error {
	metadata, err := json.Marshal(backup.Metadata)
	if err != nil {
		metadata = []byte("{}")
	}
	metadataStr := string(metadata)

	query := `
		INSERT INTO backups (
			id, host_id, type, target_id, target_name, status, trigger,
			path, filename, size_bytes, compression, encrypted, checksum,
			verified, verified_at, metadata, error_message, created_by,
			started_at, completed_at, expires_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
			$17, $18, $19, $20, $21, $22
		)`

	_, err = r.db.ExecContext(ctx, query,
		backup.ID,
		backup.HostID,
		backup.Type,
		backup.TargetID,
		backup.TargetName,
		backup.Status,
		backup.Trigger,
		backup.Path,
		backup.Filename,
		backup.SizeBytes,
		backup.Compression,
		backup.Encrypted,
		backup.Checksum,
		backup.Verified,
		backup.VerifiedAt,
		metadataStr,
		backup.ErrorMessage,
		backup.CreatedBy,
		backup.StartedAt,
		backup.CompletedAt,
		backup.ExpiresAt,
		backup.CreatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create backup")
	}

	return nil
}

// Update updates a backup record.
func (r *BackupRepository) Update(ctx context.Context, backup *models.Backup) error {
	metadata, err := json.Marshal(backup.Metadata)
	if err != nil {
		metadata = []byte("{}")
	}
	metadataStr := string(metadata)

	query := `
		UPDATE backups SET
			status = $2,
			path = $3,
			filename = $4,
			size_bytes = $5,
			checksum = $6,
			verified = $7,
			verified_at = $8,
			metadata = $9,
			error_message = $10,
			started_at = $11,
			completed_at = $12,
			expires_at = $13
		WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query,
		backup.ID,
		backup.Status,
		backup.Path,
		backup.Filename,
		backup.SizeBytes,
		backup.Checksum,
		backup.Verified,
		backup.VerifiedAt,
		metadataStr,
		backup.ErrorMessage,
		backup.StartedAt,
		backup.CompletedAt,
		backup.ExpiresAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update backup")
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.NotFound("backup")
	}

	return nil
}

// Get retrieves a backup by ID.
func (r *BackupRepository) Get(ctx context.Context, id uuid.UUID) (*models.Backup, error) {
	query := `
		SELECT id, host_id, type, target_id, target_name, status, trigger,
			path, filename, size_bytes, compression, encrypted, checksum,
			verified, verified_at, metadata, error_message, created_by,
			started_at, completed_at, expires_at, created_at
		FROM backups WHERE id = $1`

	return r.scanBackup(r.db.QueryRowContext(ctx, query, id))
}

// GetByHostAndTarget retrieves backups for a specific target.
func (r *BackupRepository) GetByHostAndTarget(ctx context.Context, hostID uuid.UUID, targetID string) ([]*models.Backup, error) {
	query := `
		SELECT id, host_id, type, target_id, target_name, status, trigger,
			path, filename, size_bytes, compression, encrypted, checksum,
			verified, verified_at, metadata, error_message, created_by,
			started_at, completed_at, expires_at, created_at
		FROM backups
		WHERE host_id = $1 AND target_id = $2
		ORDER BY created_at DESC`

	return r.queryBackups(ctx, query, hostID, targetID)
}

// List retrieves backups with filters.
func (r *BackupRepository) List(ctx context.Context, opts models.BackupListOptions) ([]*models.Backup, int64, error) {
	// Build query
	query := `
		SELECT id, host_id, type, target_id, target_name, status, trigger,
			path, filename, size_bytes, compression, encrypted, checksum,
			verified, verified_at, metadata, error_message, created_by,
			started_at, completed_at, expires_at, created_at
		FROM backups WHERE 1=1`
	countQuery := `SELECT COUNT(*) FROM backups WHERE 1=1`

	args := []interface{}{}
	argCount := 0

	// Apply filters
	if opts.Type != nil {
		argCount++
		query += ` AND type = $` + strconv.Itoa(argCount)
		countQuery += ` AND type = $` + strconv.Itoa(argCount)
		args = append(args, *opts.Type)
	}

	if opts.Status != nil {
		argCount++
		query += ` AND status = $` + strconv.Itoa(argCount)
		countQuery += ` AND status = $` + strconv.Itoa(argCount)
		args = append(args, *opts.Status)
	}

	if opts.TargetID != nil {
		argCount++
		query += ` AND target_id = $` + strconv.Itoa(argCount)
		countQuery += ` AND target_id = $` + strconv.Itoa(argCount)
		args = append(args, *opts.TargetID)
	}

	if opts.Trigger != nil {
		argCount++
		query += ` AND trigger = $` + strconv.Itoa(argCount)
		countQuery += ` AND trigger = $` + strconv.Itoa(argCount)
		args = append(args, *opts.Trigger)
	}

	if opts.Before != nil {
		argCount++
		query += ` AND created_at < $` + strconv.Itoa(argCount)
		countQuery += ` AND created_at < $` + strconv.Itoa(argCount)
		args = append(args, *opts.Before)
	}

	if opts.After != nil {
		argCount++
		query += ` AND created_at > $` + strconv.Itoa(argCount)
		countQuery += ` AND created_at > $` + strconv.Itoa(argCount)
		args = append(args, *opts.After)
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count backups")
	}

	// Add ordering and pagination
	query += ` ORDER BY created_at DESC`

	if opts.Limit > 0 {
		argCount++
		query += ` LIMIT $` + strconv.Itoa(argCount)
		args = append(args, opts.Limit)
	}

	if opts.Offset > 0 {
		argCount++
		query += ` OFFSET $` + strconv.Itoa(argCount)
		args = append(args, opts.Offset)
	}

	backups, err := r.queryBackups(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}

	return backups, total, nil
}

// Delete deletes a backup record.
func (r *BackupRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM backups WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete backup")
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.NotFound("backup")
	}

	return nil
}

// DeleteExpired deletes expired backups.
func (r *BackupRepository) DeleteExpired(ctx context.Context) ([]uuid.UUID, error) {
	// First get IDs of expired backups
	selectQuery := `
		SELECT id FROM backups 
		WHERE expires_at IS NOT NULL AND expires_at < NOW()`

	rows, err := r.db.QueryContext(ctx, selectQuery)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query expired backups")
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			continue
		}
		ids = append(ids, id)
	}

	if len(ids) == 0 {
		return nil, nil
	}

	// Delete expired backups
	deleteQuery := `
		DELETE FROM backups 
		WHERE expires_at IS NOT NULL AND expires_at < NOW()`

	_, err = r.db.ExecContext(ctx, deleteQuery)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to delete expired backups")
	}

	return ids, nil
}

// GetStats retrieves backup statistics.
func (r *BackupRepository) GetStats(ctx context.Context, hostID *uuid.UUID) (*models.BackupStats, error) {
	stats := &models.BackupStats{
		ByType:    make(map[string]int),
		ByTrigger: make(map[string]int),
	}

	// Base query
	baseWhere := ""
	var args []interface{}
	if hostID != nil {
		baseWhere = " WHERE host_id = $1"
		args = append(args, *hostID)
	}

	// Total counts
	countQuery := `
		SELECT 
			COUNT(*) as total,
			COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0) as completed,
			COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0) as failed,
			COALESCE(SUM(size_bytes), 0) as total_size,
			MAX(created_at) as last_backup,
			MIN(created_at) as oldest_backup
		FROM backups` + baseWhere

	var lastBackup, oldestBackup sql.NullTime
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(
		&stats.TotalBackups,
		&stats.CompletedBackups,
		&stats.FailedBackups,
		&stats.TotalSize,
		&lastBackup,
		&oldestBackup,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get backup stats")
	}

	if lastBackup.Valid {
		stats.LastBackupAt = &lastBackup.Time
	}
	if oldestBackup.Valid {
		stats.OldestBackupAt = &oldestBackup.Time
	}

	// By type
	typeQuery := `SELECT type, COUNT(*) FROM backups` + baseWhere + ` GROUP BY type`
	typeRows, err := r.db.QueryContext(ctx, typeQuery, args...)
	if err == nil {
		defer typeRows.Close()
		for typeRows.Next() {
			var t string
			var count int
			if typeRows.Scan(&t, &count) == nil {
				stats.ByType[t] = count
			}
		}
	}

	// By trigger
	triggerQuery := `SELECT trigger, COUNT(*) FROM backups` + baseWhere + ` GROUP BY trigger`
	triggerRows, err := r.db.QueryContext(ctx, triggerQuery, args...)
	if err == nil {
		defer triggerRows.Close()
		for triggerRows.Next() {
			var t string
			var count int
			if triggerRows.Scan(&t, &count) == nil {
				stats.ByTrigger[t] = count
			}
		}
	}

	return stats, nil
}

// ============================================================================
// Schedule Operations
// ============================================================================

// CreateSchedule creates a backup schedule.
func (r *BackupRepository) CreateSchedule(ctx context.Context, schedule *models.BackupSchedule) error {
	query := `
		INSERT INTO backup_schedules (
			id, host_id, type, target_id, target_name, schedule, compression,
			encrypted, retention_days, max_backups, is_enabled, last_run_at,
			last_run_status, next_run_at, created_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
		)`

	_, err := r.db.ExecContext(ctx, query,
		schedule.ID,
		schedule.HostID,
		schedule.Type,
		schedule.TargetID,
		schedule.TargetName,
		schedule.Schedule,
		schedule.Compression,
		schedule.Encrypted,
		schedule.RetentionDays,
		schedule.MaxBackups,
		schedule.IsEnabled,
		schedule.LastRunAt,
		schedule.LastRunStatus,
		schedule.NextRunAt,
		schedule.CreatedBy,
		schedule.CreatedAt,
		schedule.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create backup schedule")
	}

	return nil
}

// UpdateSchedule updates a backup schedule.
func (r *BackupRepository) UpdateSchedule(ctx context.Context, schedule *models.BackupSchedule) error {
	query := `
		UPDATE backup_schedules SET
			schedule = $2,
			compression = $3,
			encrypted = $4,
			retention_days = $5,
			max_backups = $6,
			is_enabled = $7,
			next_run_at = $8,
			updated_at = $9
		WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query,
		schedule.ID,
		schedule.Schedule,
		schedule.Compression,
		schedule.Encrypted,
		schedule.RetentionDays,
		schedule.MaxBackups,
		schedule.IsEnabled,
		schedule.NextRunAt,
		schedule.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update backup schedule")
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.NotFound("backup schedule")
	}

	return nil
}

// GetSchedule retrieves a schedule by ID.
func (r *BackupRepository) GetSchedule(ctx context.Context, id uuid.UUID) (*models.BackupSchedule, error) {
	query := `
		SELECT id, host_id, type, target_id, target_name, schedule, compression,
			encrypted, retention_days, max_backups, is_enabled, last_run_at,
			last_run_status, next_run_at, created_by, created_at, updated_at
		FROM backup_schedules WHERE id = $1`

	return r.scanSchedule(r.db.QueryRowContext(ctx, query, id))
}

// ListSchedules retrieves all schedules.
func (r *BackupRepository) ListSchedules(ctx context.Context, hostID *uuid.UUID) ([]*models.BackupSchedule, error) {
	query := `
		SELECT id, host_id, type, target_id, target_name, schedule, compression,
			encrypted, retention_days, max_backups, is_enabled, last_run_at,
			last_run_status, next_run_at, created_by, created_at, updated_at
		FROM backup_schedules`

	args := []interface{}{}
	if hostID != nil {
		query += ` WHERE host_id = $1`
		args = append(args, *hostID)
	}
	query += ` ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list schedules")
	}
	defer rows.Close()

	var schedules []*models.BackupSchedule
	for rows.Next() {
		schedule, err := r.scanScheduleRows(rows)
		if err != nil {
			continue
		}
		schedules = append(schedules, schedule)
	}

	return schedules, nil
}

// DeleteSchedule deletes a schedule.
func (r *BackupRepository) DeleteSchedule(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM backup_schedules WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete schedule")
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.NotFound("backup schedule")
	}

	return nil
}

// GetDueSchedules retrieves schedules that are due to run.
func (r *BackupRepository) GetDueSchedules(ctx context.Context) ([]*models.BackupSchedule, error) {
	query := `
		SELECT id, host_id, type, target_id, target_name, schedule, compression,
			encrypted, retention_days, max_backups, is_enabled, last_run_at,
			last_run_status, next_run_at, created_by, created_at, updated_at
		FROM backup_schedules
		WHERE is_enabled = true AND next_run_at <= NOW()`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get due schedules")
	}
	defer rows.Close()

	var schedules []*models.BackupSchedule
	for rows.Next() {
		schedule, err := r.scanScheduleRows(rows)
		if err != nil {
			continue
		}
		schedules = append(schedules, schedule)
	}

	return schedules, nil
}

// UpdateScheduleLastRun updates schedule run status.
func (r *BackupRepository) UpdateScheduleLastRun(ctx context.Context, id uuid.UUID, status models.BackupStatus, nextRun *time.Time) error {
	query := `
		UPDATE backup_schedules SET
			last_run_at = NOW(),
			last_run_status = $2,
			next_run_at = $3,
			updated_at = NOW()
		WHERE id = $1`

	_, err := r.db.ExecContext(ctx, query, id, status, nextRun)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update schedule last run")
	}

	return nil
}

// ============================================================================
// Helpers
// ============================================================================

type scanner interface {
	Scan(dest ...interface{}) error
}

func (r *BackupRepository) scanBackup(row scanner) (*models.Backup, error) {
	var b models.Backup
	var metadata []byte
	var verifiedAt, startedAt, completedAt, expiresAt sql.NullTime
	var createdBy sql.NullString
	var checksum, errorMessage sql.NullString

	err := row.Scan(
		&b.ID,
		&b.HostID,
		&b.Type,
		&b.TargetID,
		&b.TargetName,
		&b.Status,
		&b.Trigger,
		&b.Path,
		&b.Filename,
		&b.SizeBytes,
		&b.Compression,
		&b.Encrypted,
		&checksum,
		&b.Verified,
		&verifiedAt,
		&metadata,
		&errorMessage,
		&createdBy,
		&startedAt,
		&completedAt,
		&expiresAt,
		&b.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NotFound("backup")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan backup")
	}

	if checksum.Valid {
		b.Checksum = &checksum.String
	}
	if errorMessage.Valid {
		b.ErrorMessage = &errorMessage.String
	}
	if createdBy.Valid {
		id, _ := uuid.Parse(createdBy.String)
		b.CreatedBy = &id
	}
	if verifiedAt.Valid {
		b.VerifiedAt = &verifiedAt.Time
	}
	if startedAt.Valid {
		b.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		b.CompletedAt = &completedAt.Time
	}
	if expiresAt.Valid {
		b.ExpiresAt = &expiresAt.Time
	}
	if len(metadata) > 0 {
		var m models.BackupMetadata
		if json.Unmarshal(metadata, &m) == nil {
			b.Metadata = &m
		}
	}

	return &b, nil
}

func (r *BackupRepository) queryBackups(ctx context.Context, query string, args ...interface{}) ([]*models.Backup, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query backups")
	}
	defer rows.Close()

	var backups []*models.Backup
	for rows.Next() {
		backup, err := r.scanBackup(rows)
		if err != nil {
			continue
		}
		backups = append(backups, backup)
	}

	return backups, nil
}

func (r *BackupRepository) scanSchedule(row scanner) (*models.BackupSchedule, error) {
	var s models.BackupSchedule
	var lastRunAt, nextRunAt sql.NullTime
	var lastRunStatus sql.NullString
	var createdBy sql.NullString

	err := row.Scan(
		&s.ID,
		&s.HostID,
		&s.Type,
		&s.TargetID,
		&s.TargetName,
		&s.Schedule,
		&s.Compression,
		&s.Encrypted,
		&s.RetentionDays,
		&s.MaxBackups,
		&s.IsEnabled,
		&lastRunAt,
		&lastRunStatus,
		&nextRunAt,
		&createdBy,
		&s.CreatedAt,
		&s.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NotFound("backup schedule")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan schedule")
	}

	if lastRunAt.Valid {
		s.LastRunAt = &lastRunAt.Time
	}
	if nextRunAt.Valid {
		s.NextRunAt = &nextRunAt.Time
	}
	if lastRunStatus.Valid {
		status := models.BackupStatus(lastRunStatus.String)
		s.LastRunStatus = &status
	}
	if createdBy.Valid {
		id, _ := uuid.Parse(createdBy.String)
		s.CreatedBy = &id
	}

	return &s, nil
}

func (r *BackupRepository) scanScheduleRows(rows *sql.Rows) (*models.BackupSchedule, error) {
	var s models.BackupSchedule
	var lastRunAt, nextRunAt sql.NullTime
	var lastRunStatus sql.NullString
	var createdBy sql.NullString

	err := rows.Scan(
		&s.ID,
		&s.HostID,
		&s.Type,
		&s.TargetID,
		&s.TargetName,
		&s.Schedule,
		&s.Compression,
		&s.Encrypted,
		&s.RetentionDays,
		&s.MaxBackups,
		&s.IsEnabled,
		&lastRunAt,
		&lastRunStatus,
		&nextRunAt,
		&createdBy,
		&s.CreatedAt,
		&s.UpdatedAt,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan schedule row")
	}

	if lastRunAt.Valid {
		s.LastRunAt = &lastRunAt.Time
	}
	if nextRunAt.Valid {
		s.NextRunAt = &nextRunAt.Time
	}
	if lastRunStatus.Valid {
		status := models.BackupStatus(lastRunStatus.String)
		s.LastRunStatus = &status
	}
	if createdBy.Valid {
		id, _ := uuid.Parse(createdBy.String)
		s.CreatedBy = &id
	}

	return &s, nil
}
