// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// BackupStatus represents the status of a backup
type BackupStatus string

const (
	BackupStatusPending    BackupStatus = "pending"
	BackupStatusRunning    BackupStatus = "running"
	BackupStatusCompleted  BackupStatus = "completed"
	BackupStatusFailed     BackupStatus = "failed"
	BackupStatusCancelled  BackupStatus = "cancelled"
	BackupStatusVerifying  BackupStatus = "verifying"
	BackupStatusRestoring  BackupStatus = "restoring"
)

// BackupTrigger represents what triggered the backup
type BackupTrigger string

const (
	BackupTriggerManual    BackupTrigger = "manual"
	BackupTriggerScheduled BackupTrigger = "scheduled"
	BackupTriggerPreUpdate BackupTrigger = "pre_update"
	BackupTriggerAutomatic BackupTrigger = "automatic"
)

// BackupType represents the type of backup
type BackupType string

const (
	BackupTypeVolume    BackupType = "volume"
	BackupTypeContainer BackupType = "container"
	BackupTypeStack     BackupType = "stack"
	BackupTypeSystem    BackupType = "system" // Platform config/db backup
)

// BackupCompression represents compression types
type BackupCompression string

const (
	BackupCompressionNone BackupCompression = "none"
	BackupCompressionGzip BackupCompression = "gzip"
	BackupCompressionZstd BackupCompression = "zstd"
)

// Backup represents a backup entry
type Backup struct {
	ID             uuid.UUID         `json:"id" db:"id"`
	HostID         uuid.UUID         `json:"host_id" db:"host_id"`
	Type           BackupType        `json:"type" db:"type"`
	TargetID       string            `json:"target_id" db:"target_id"` // Volume name, Container ID, Stack ID
	TargetName     string            `json:"target_name" db:"target_name"`
	Status         BackupStatus      `json:"status" db:"status"`
	Trigger        BackupTrigger     `json:"trigger" db:"trigger"`
	Path           string            `json:"path" db:"path"`
	Filename       string            `json:"filename" db:"filename"`
	SizeBytes      int64             `json:"size_bytes" db:"size_bytes"`
	Compression    BackupCompression `json:"compression" db:"compression"`
	Encrypted      bool              `json:"encrypted" db:"encrypted"`
	Checksum       *string           `json:"checksum,omitempty" db:"checksum"` // SHA256
	Verified       bool              `json:"verified" db:"verified"`
	VerifiedAt     *time.Time        `json:"verified_at,omitempty" db:"verified_at"`
	Metadata       *BackupMetadata   `json:"metadata,omitempty" db:"metadata"`
	ErrorMessage   *string           `json:"error_message,omitempty" db:"error_message"`
	CreatedBy      *uuid.UUID        `json:"created_by,omitempty" db:"created_by"`
	StartedAt      *time.Time        `json:"started_at,omitempty" db:"started_at"`
	CompletedAt    *time.Time        `json:"completed_at,omitempty" db:"completed_at"`
	ExpiresAt      *time.Time        `json:"expires_at,omitempty" db:"expires_at"`
	CreatedAt      time.Time         `json:"created_at" db:"created_at"`
}

// BackupMetadata contains additional backup information
type BackupMetadata struct {
	ContainerImage   string            `json:"container_image,omitempty"`
	ContainerVersion string            `json:"container_version,omitempty"`
	StackServices    []string          `json:"stack_services,omitempty"`
	VolumeDriver     string            `json:"volume_driver,omitempty"`
	Labels           map[string]string `json:"labels,omitempty"`
	OriginalSize     int64             `json:"original_size,omitempty"`
	FileCount        int               `json:"file_count,omitempty"`
}

// IsCompleted returns true if backup completed successfully
func (b *Backup) IsCompleted() bool {
	return b.Status == BackupStatusCompleted
}

// IsFailed returns true if backup failed
func (b *Backup) IsFailed() bool {
	return b.Status == BackupStatusFailed
}

// IsExpired returns true if backup has expired
func (b *Backup) IsExpired() bool {
	if b.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*b.ExpiresAt)
}

// Duration returns the backup duration
func (b *Backup) Duration() time.Duration {
	if b.StartedAt == nil || b.CompletedAt == nil {
		return 0
	}
	return b.CompletedAt.Sub(*b.StartedAt)
}

// CreateBackupInput represents input for creating a backup
type CreateBackupInput struct {
	Type          BackupType        `json:"type" validate:"required,oneof=volume container stack"`
	TargetID      string            `json:"target_id" validate:"required"`
	Compression   BackupCompression `json:"compression,omitempty" validate:"omitempty,oneof=none gzip zstd"`
	Encrypted     bool              `json:"encrypted,omitempty"`
	RetentionDays *int              `json:"retention_days,omitempty" validate:"omitempty,min=1,max=365"`
}

// RestoreBackupInput represents input for restoring a backup
type RestoreBackupInput struct {
	BackupID          uuid.UUID `json:"backup_id" validate:"required"`
	TargetName        string    `json:"target_name,omitempty"` // New name for restored item
	OverwriteExisting bool      `json:"overwrite_existing,omitempty"`
	StartAfterRestore bool      `json:"start_after_restore,omitempty"`
}

// BackupListOptions represents options for listing backups
type BackupListOptions struct {
	Type      *BackupType   `json:"type,omitempty"`
	TargetID  *string       `json:"target_id,omitempty"`
	Status    *BackupStatus `json:"status,omitempty"`
	Trigger   *BackupTrigger `json:"trigger,omitempty"`
	Before    *time.Time    `json:"before,omitempty"`
	After     *time.Time    `json:"after,omitempty"`
	Limit     int           `json:"limit,omitempty"`
	Offset    int           `json:"offset,omitempty"`
}

// BackupSchedule represents a backup schedule
type BackupSchedule struct {
	ID             uuid.UUID         `json:"id" db:"id"`
	HostID         uuid.UUID         `json:"host_id" db:"host_id"`
	Type           BackupType        `json:"type" db:"type"`
	TargetID       string            `json:"target_id" db:"target_id"`
	TargetName     string            `json:"target_name" db:"target_name"`
	Schedule       string            `json:"schedule" db:"schedule"` // Cron expression
	Compression    BackupCompression `json:"compression" db:"compression"`
	Encrypted      bool              `json:"encrypted" db:"encrypted"`
	RetentionDays  int               `json:"retention_days" db:"retention_days"`
	MaxBackups     int               `json:"max_backups" db:"max_backups"`
	IsEnabled      bool              `json:"is_enabled" db:"is_enabled"`
	LastRunAt      *time.Time        `json:"last_run_at,omitempty" db:"last_run_at"`
	LastRunStatus  *BackupStatus     `json:"last_run_status,omitempty" db:"last_run_status"`
	NextRunAt      *time.Time        `json:"next_run_at,omitempty" db:"next_run_at"`
	CreatedBy      *uuid.UUID        `json:"created_by,omitempty" db:"created_by"`
	CreatedAt      time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at" db:"updated_at"`
}

// CreateBackupScheduleInput represents input for creating a backup schedule
type CreateBackupScheduleInput struct {
	Type          BackupType        `json:"type" validate:"required,oneof=volume container stack"`
	TargetID      string            `json:"target_id" validate:"required"`
	Schedule      string            `json:"schedule" validate:"required,cron"`
	Compression   BackupCompression `json:"compression,omitempty" validate:"omitempty,oneof=none gzip zstd"`
	Encrypted     bool              `json:"encrypted,omitempty"`
	RetentionDays int               `json:"retention_days,omitempty" validate:"omitempty,min=1,max=365"`
	MaxBackups    int               `json:"max_backups,omitempty" validate:"omitempty,min=1,max=100"`
	IsEnabled     bool              `json:"is_enabled,omitempty"`
}

// UpdateBackupScheduleInput represents input for updating a backup schedule
type UpdateBackupScheduleInput struct {
	Schedule      *string            `json:"schedule,omitempty" validate:"omitempty,cron"`
	Compression   *BackupCompression `json:"compression,omitempty" validate:"omitempty,oneof=none gzip zstd"`
	Encrypted     *bool              `json:"encrypted,omitempty"`
	RetentionDays *int               `json:"retention_days,omitempty" validate:"omitempty,min=1,max=365"`
	MaxBackups    *int               `json:"max_backups,omitempty" validate:"omitempty,min=1,max=100"`
	IsEnabled     *bool              `json:"is_enabled,omitempty"`
}

// BackupStorage represents backup storage configuration
type BackupStorage struct {
	Type           string            `json:"type"` // local, s3
	LocalPath      string            `json:"local_path,omitempty"`
	S3Endpoint     string            `json:"s3_endpoint,omitempty"`
	S3Bucket       string            `json:"s3_bucket,omitempty"`
	S3Region       string            `json:"s3_region,omitempty"`
	S3AccessKey    string            `json:"-"`
	S3SecretKey    string            `json:"-"`
	S3UsePathStyle bool              `json:"s3_use_path_style,omitempty"`
	TotalSize      int64             `json:"total_size"`
	UsedSize       int64             `json:"used_size"`
	BackupCount    int               `json:"backup_count"`
}

// BackupStats represents backup statistics
type BackupStats struct {
	TotalBackups     int              `json:"total_backups"`
	CompletedBackups int              `json:"completed_backups"`
	FailedBackups    int              `json:"failed_backups"`
	TotalSize        int64            `json:"total_size"`
	ByType           map[string]int   `json:"by_type"`
	ByTrigger        map[string]int   `json:"by_trigger"`
	LastBackupAt     *time.Time       `json:"last_backup_at,omitempty"`
	OldestBackupAt   *time.Time       `json:"oldest_backup_at,omitempty"`
}

// BackupVerificationResult represents backup verification result
type BackupVerificationResult struct {
	BackupID       uuid.UUID `json:"backup_id"`
	IsValid        bool      `json:"is_valid"`
	ChecksumValid  bool      `json:"checksum_valid"`
	Readable       bool      `json:"readable"`
	FileCount      int       `json:"file_count,omitempty"`
	ErrorMessage   *string   `json:"error_message,omitempty"`
	VerifiedAt     time.Time `json:"verified_at"`
}
