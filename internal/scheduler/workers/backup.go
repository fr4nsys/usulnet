// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package workers

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// BackupService interface for backup operations (from Dept H)
type BackupService interface {
	// Create creates a new backup
	Create(ctx context.Context, opts BackupCreateOptions) (*BackupCreateResult, error)

	// Restore restores a backup
	Restore(ctx context.Context, opts BackupRestoreOptions) (*BackupRestoreResult, error)

	// Delete deletes a backup
	Delete(ctx context.Context, id uuid.UUID) error

	// Get retrieves a backup by ID
	Get(ctx context.Context, id uuid.UUID) (*models.Backup, error)

	// PruneTarget removes old backups for a specific target
	PruneTarget(ctx context.Context, hostID uuid.UUID, targetID string, keepCount int) (*BackupCleanupResult, error)
}

// BackupCreateOptions for creating backups
type BackupCreateOptions struct {
	HostID        uuid.UUID
	Type          models.BackupType
	TargetID      string
	TargetName    string
	Trigger       models.BackupTrigger
	Compression   string
	Encrypt       bool
	RetentionDays *int
	CreatedBy     *uuid.UUID
}

// BackupCreateResult from creating a backup
type BackupCreateResult struct {
	Backup *models.Backup
}

// BackupRestoreOptions for restoring backups
type BackupRestoreOptions struct {
	BackupID      uuid.UUID
	TargetID      string
	TargetName    string
	OverwriteMode string
}

// BackupRestoreResult from restoring a backup
type BackupRestoreResult struct {
	Success      bool
	TargetID     string
	RestoredSize int64
	Duration     time.Duration
}

// BackupCleanupResult from cleanup operations
type BackupCleanupResult struct {
	DeletedCount int
	FreedBytes   int64
}

// BackupWorker handles backup creation jobs
type BackupWorker struct {
	BaseWorker
	backupService BackupService
	logger        *logger.Logger
}

// NewBackupWorker creates a new backup worker
func NewBackupWorker(backupService BackupService, log *logger.Logger) *BackupWorker {
	if log == nil {
		log = logger.Nop()
	}

	return &BackupWorker{
		BaseWorker:    NewBaseWorker(models.JobTypeBackupCreate),
		backupService: backupService,
		logger:        log.Named("backup-worker"),
	}
}

// Execute performs the backup job
func (w *BackupWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	log := w.logger.With("job_id", job.ID)

	// Parse payload
	var payload models.BackupPayload
	if err := job.GetPayload(&payload); err != nil {
		return nil, errors.Wrap(err, errors.CodeValidation, "failed to parse payload")
	}

	// Get host ID
	hostID := job.HostID
	if hostID == nil {
		return nil, errors.New(errors.CodeValidation, "host_id is required for backup")
	}

	log.Info("starting backup",
		"host_id", hostID,
		"type", payload.Type,
		"target_id", payload.TargetID,
		"compression", payload.Compression,
		"encrypted", payload.Encrypted,
	)

	// Update progress
	job.Progress = 10
	msg := "Preparing backup..."
	job.ProgressMessage = &msg

	// Parse backup type
	backupType := models.BackupType(payload.Type)
	if backupType == "" {
		backupType = models.BackupTypeVolume
	}

	// Create backup options
	opts := BackupCreateOptions{
		HostID:      *hostID,
		Type:        backupType,
		TargetID:    payload.TargetID,
		Trigger:     models.BackupTriggerScheduled,
		Compression: payload.Compression,
		Encrypt:     payload.Encrypted,
		CreatedBy:   job.CreatedBy,
	}

	if payload.RetentionDays > 0 {
		opts.RetentionDays = &payload.RetentionDays
	}

	// Get target name from job if available
	if job.TargetName != nil {
		opts.TargetName = *job.TargetName
	}

	// Update progress
	job.Progress = 30
	msg = "Creating backup archive..."
	job.ProgressMessage = &msg

	// Create backup
	result, err := w.backupService.Create(ctx, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "backup creation failed")
	}

	// Update progress
	job.Progress = 90
	msg = "Finalizing..."
	job.ProgressMessage = &msg

	// Prune old backups if retention is set
	if payload.RetentionDays > 0 {
		// Calculate keep count based on typical backup frequency
		// Assuming daily backups, keep retention_days worth
		keepCount := payload.RetentionDays
		if keepCount > 30 {
			keepCount = 30 // Cap at 30 backups
		}

		if _, err := w.backupService.PruneTarget(ctx, *hostID, payload.TargetID, keepCount); err != nil {
			log.Warn("failed to prune old backups", "error", err)
			// Don't fail the job for prune failures
		}
	}

	backupResult := &BackupJobResult{
		BackupID:   result.Backup.ID,
		HostID:     *hostID,
		Type:       string(result.Backup.Type),
		TargetID:   result.Backup.TargetID,
		TargetName: result.Backup.TargetName,
		Path:       result.Backup.Path,
		SizeBytes:  result.Backup.SizeBytes,
		Encrypted:  result.Backup.Encrypted,
		CreatedAt:  result.Backup.CreatedAt,
	}

	log.Info("backup completed",
		"backup_id", result.Backup.ID,
		"size", result.Backup.SizeBytes,
		"path", result.Backup.Path,
	)

	return backupResult, nil
}

// BackupJobResult holds the result of a backup job
type BackupJobResult struct {
	BackupID   uuid.UUID `json:"backup_id"`
	HostID     uuid.UUID `json:"host_id"`
	Type       string    `json:"type"`
	TargetID   string    `json:"target_id"`
	TargetName string    `json:"target_name"`
	Path       string    `json:"path"`
	SizeBytes  int64     `json:"size_bytes"`
	Encrypted  bool      `json:"encrypted"`
	CreatedAt  time.Time `json:"created_at"`
}

// ============================================================================
// Backup Restore Worker
// ============================================================================

// BackupRestoreWorker handles backup restoration jobs
type BackupRestoreWorker struct {
	BaseWorker
	backupService BackupService
	logger        *logger.Logger
}

// NewBackupRestoreWorker creates a new backup restore worker
func NewBackupRestoreWorker(backupService BackupService, log *logger.Logger) *BackupRestoreWorker {
	if log == nil {
		log = logger.Nop()
	}

	return &BackupRestoreWorker{
		BaseWorker:    NewBaseWorker(models.JobTypeBackupRestore),
		backupService: backupService,
		logger:        log.Named("backup-restore-worker"),
	}
}

// BackupRestorePayload represents payload for restore job
type BackupRestorePayload struct {
	BackupID      uuid.UUID `json:"backup_id"`
	TargetID      string    `json:"target_id,omitempty"`
	OverwriteMode string    `json:"overwrite_mode,omitempty"` // "replace", "merge", "skip"
}

// Execute performs the backup restore job
func (w *BackupRestoreWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	log := w.logger.With("job_id", job.ID)

	// Parse payload
	var payload BackupRestorePayload
	if err := job.GetPayload(&payload); err != nil {
		return nil, errors.Wrap(err, errors.CodeValidation, "failed to parse payload")
	}

	if payload.BackupID == uuid.Nil {
		return nil, errors.New(errors.CodeValidation, "backup_id is required")
	}

	log.Info("starting backup restore",
		"backup_id", payload.BackupID,
		"target_id", payload.TargetID,
		"overwrite_mode", payload.OverwriteMode,
	)

	// Get backup info
	job.Progress = 10
	msg := "Retrieving backup information..."
	job.ProgressMessage = &msg

	backup, err := w.backupService.Get(ctx, payload.BackupID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "backup not found")
	}

	// Prepare restore options
	opts := BackupRestoreOptions{
		BackupID:      payload.BackupID,
		TargetID:      payload.TargetID,
		OverwriteMode: payload.OverwriteMode,
	}

	if opts.TargetID == "" {
		opts.TargetID = backup.TargetID
	}

	if opts.OverwriteMode == "" {
		opts.OverwriteMode = "replace"
	}

	// Update progress
	job.Progress = 30
	msg = "Extracting backup archive..."
	job.ProgressMessage = &msg

	// Perform restore
	startTime := time.Now()
	result, err := w.backupService.Restore(ctx, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "restore failed")
	}

	duration := time.Since(startTime)

	restoreResult := &BackupRestoreJobResult{
		BackupID:     payload.BackupID,
		TargetID:     result.TargetID,
		Success:      result.Success,
		RestoredSize: result.RestoredSize,
		Duration:     duration,
		RestoredAt:   time.Now(),
	}

	log.Info("backup restore completed",
		"backup_id", payload.BackupID,
		"target_id", result.TargetID,
		"restored_size", result.RestoredSize,
		"duration", duration,
	)

	return restoreResult, nil
}

// BackupRestoreJobResult holds the result of a backup restore job
type BackupRestoreJobResult struct {
	BackupID     uuid.UUID     `json:"backup_id"`
	TargetID     string        `json:"target_id"`
	Success      bool          `json:"success"`
	RestoredSize int64         `json:"restored_size"`
	Duration     time.Duration `json:"duration"`
	RestoredAt   time.Time     `json:"restored_at"`
}
