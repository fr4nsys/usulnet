// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package backup provides backup and restore services.
// This file contains core interfaces and types for the backup system.
package backup

import (
	"context"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ============================================================================
// Storage Interface
// ============================================================================

// Storage defines the interface for backup storage backends.
type Storage interface {
	// Type returns the storage type identifier ("local", "s3", etc.)
	Type() string

	// Write writes data from reader to the storage path.
	Write(ctx context.Context, path string, reader io.Reader, size int64) error

	// Read returns a reader for the data at the given path.
	Read(ctx context.Context, path string) (io.ReadCloser, error)

	// Delete removes the file at the given path.
	Delete(ctx context.Context, path string) error

	// Exists checks if a file exists at the given path.
	Exists(ctx context.Context, path string) (bool, error)

	// Size returns the size of the file at the given path.
	Size(ctx context.Context, path string) (int64, error)

	// List returns entries matching the given prefix.
	List(ctx context.Context, prefix string) ([]StorageEntry, error)

	// Stats returns storage statistics.
	Stats(ctx context.Context) (*StorageStats, error)

	// Close closes the storage backend.
	Close() error
}

// StorageEntry represents an entry in storage.
type StorageEntry struct {
	Path         string
	Size         int64
	ModTime      time.Time
	IsDir        bool
	ETag         string
	StorageClass string
}

// StorageStats contains storage statistics.
type StorageStats struct {
	TotalSpace     int64
	UsedSpace      int64
	AvailableSpace int64
	FileCount      int64
}

// ============================================================================
// Repository Interface
// ============================================================================

// Repository defines the interface for backup metadata storage.
type Repository interface {
	// Create creates a new backup record.
	Create(ctx context.Context, backup *models.Backup) error

	// Get retrieves a backup by ID.
	Get(ctx context.Context, id uuid.UUID) (*models.Backup, error)

	// Update updates a backup record.
	Update(ctx context.Context, backup *models.Backup) error

	// Delete deletes a backup record.
	Delete(ctx context.Context, id uuid.UUID) error

	// List retrieves backups with filtering and pagination.
	List(ctx context.Context, opts models.BackupListOptions) ([]*models.Backup, int64, error)

	// GetByHostAndTarget retrieves backups for a specific host and target.
	GetByHostAndTarget(ctx context.Context, hostID uuid.UUID, targetID string) ([]*models.Backup, error)

	// GetStats retrieves backup statistics.
	GetStats(ctx context.Context, hostID *uuid.UUID) (*models.BackupStats, error)

	// Schedule operations
	CreateSchedule(ctx context.Context, schedule *models.BackupSchedule) error
	GetSchedule(ctx context.Context, id uuid.UUID) (*models.BackupSchedule, error)
	ListSchedules(ctx context.Context, hostID *uuid.UUID) ([]*models.BackupSchedule, error)
	UpdateSchedule(ctx context.Context, schedule *models.BackupSchedule) error
	DeleteSchedule(ctx context.Context, id uuid.UUID) error
	GetDueSchedules(ctx context.Context) ([]*models.BackupSchedule, error)
	UpdateScheduleLastRun(ctx context.Context, id uuid.UUID, status models.BackupStatus, nextRun *time.Time) error

	// Cleanup operations
	DeleteExpired(ctx context.Context) ([]uuid.UUID, error)
}

// ============================================================================
// Archiver Interface
// ============================================================================

// Archiver defines the interface for creating and extracting backup archives.
type Archiver interface {
	// Create creates an archive from the source path.
	Create(ctx context.Context, sourcePath string, writer io.Writer, compression models.BackupCompression) (*ArchiveResult, error)

	// Extract extracts an archive to the destination path.
	Extract(ctx context.Context, reader io.Reader, destPath string, compression models.BackupCompression) (*ExtractResult, error)

	// List lists the contents of an archive.
	List(ctx context.Context, reader io.Reader, compression models.BackupCompression) ([]ArchiveEntry, error)
}

// ArchiveResult contains the result of an archive creation.
type ArchiveResult struct {
	OriginalSize int64
	FileCount    int
	Checksum     string
}

// ExtractResult contains the result of an archive extraction.
type ExtractResult struct {
	BytesWritten int64
	FileCount    int
}

// ArchiveEntry represents a file entry in an archive.
type ArchiveEntry struct {
	Name       string
	Size       int64
	Mode       int64
	ModTime    time.Time
	IsDir      bool
	LinkTarget string
}

// ============================================================================
// Stack Provider Interface
// ============================================================================

// StackProvider provides stack information for backups.
type StackProvider interface {
	// GetStack retrieves a stack by ID.
	GetStack(ctx context.Context, id uuid.UUID) (*StackInfo, error)

	// GetStackContainers retrieves containers belonging to a stack.
	GetStackContainers(ctx context.Context, id uuid.UUID) ([]StackContainerInfo, error)
}

// StackInfo contains stack information needed for backup.
type StackInfo struct {
	ID          uuid.UUID
	HostID      uuid.UUID
	Name        string
	ComposeFile string
	EnvFile     *string
	Services    []string
	Labels      map[string]string
}

// StackContainerInfo contains container information within a stack.
type StackContainerInfo struct {
	ID      string
	Name    string
	Image   string
	Volumes []string
	Labels  map[string]string
}

// ============================================================================
// Configuration
// ============================================================================

// Config contains backup service configuration.
type Config struct {
	// Storage settings
	StoragePath string
	StorageType string // "local" or "s3"

	// S3 settings (if StorageType is "s3")
	S3Bucket    string
	S3Region    string
	S3Endpoint  string
	S3AccessKey string
	S3SecretKey string

	// Encryption settings
	EncryptionKey     string
	EncryptionEnabled bool

	// Compression settings
	DefaultCompression models.BackupCompression
	CompressionLevel   int

	// Retention settings
	DefaultRetentionDays int
	MaxBackupsPerTarget  int
	CleanupInterval      time.Duration

	// Concurrency settings
	MaxConcurrentBackups int

	// Verification settings
	VerifyAfterBackup bool
}

// DefaultConfig returns a default configuration.
func DefaultConfig() Config {
	return Config{
		StoragePath:          "/data/backups",
		StorageType:          "local",
		DefaultCompression:   models.BackupCompressionGzip,
		CompressionLevel:     6,
		DefaultRetentionDays: 30,
		MaxBackupsPerTarget:  10,
		CleanupInterval:      24 * time.Hour,
		MaxConcurrentBackups: 3,
		VerifyAfterBackup:    true,
	}
}

// ============================================================================
// Event Types
// ============================================================================

// EventType represents the type of backup event.
type EventType string

const (
	// Backup events
	EventBackupStarted   EventType = "backup.started"
	EventBackupCompleted EventType = "backup.completed"
	EventBackupFailed    EventType = "backup.failed"

	// Restore events
	EventRestoreStarted   EventType = "restore.started"
	EventRestoreCompleted EventType = "restore.completed"
	EventRestoreFailed    EventType = "restore.failed"

	// Cleanup events
	EventCleanupStarted   EventType = "cleanup.started"
	EventCleanupCompleted EventType = "cleanup.completed"
)

// Event represents a backup system event.
type Event struct {
	Type      EventType
	BackupID  *uuid.UUID
	HostID    uuid.UUID
	TargetID  string
	Status    models.BackupStatus
	Message   string
	Timestamp time.Time
}

// EventHandler is a function that handles backup events.
type EventHandler func(Event)

// ============================================================================
// Create/Restore Options and Results
// ============================================================================

// CreateOptions contains options for creating a backup.
type CreateOptions struct {
	HostID           uuid.UUID
	Type             models.BackupType
	TargetID         string
	TargetName       string
	Trigger          models.BackupTrigger
	Compression      models.BackupCompression
	Encrypt          bool
	RetentionDays    *int
	StopContainer    bool
	Metadata         *models.BackupMetadata
	CreatedBy        *uuid.UUID
	ProgressCallback func(Progress)
}

// CreateResult contains the result of a backup creation.
type CreateResult struct {
	Backup       *models.Backup
	Duration     time.Duration
	OriginalSize int64
	FinalSize    int64
	FileCount    int
	Verified     bool
}

// RestoreOptions contains options for restoring a backup.
type RestoreOptions struct {
	BackupID          uuid.UUID
	TargetName        string // Override target name
	OverwriteExisting bool
	StopContainers    bool
	StartAfterRestore bool
	ProgressCallback  func(Progress)
}

// RestoreResult contains the result of a backup restoration.
type RestoreResult struct {
	BackupID     uuid.UUID
	TargetID     string
	TargetName   string
	Duration     time.Duration
	BytesWritten int64
	FileCount    int
}

// VerifyOptions contains options for verifying a backup.
type VerifyOptions struct {
	CheckChecksum   bool
	CheckContents   bool
	CheckDecryption bool
	FullExtract     bool
	ChecksumOnly    bool
}

// Progress represents backup/restore progress.
type Progress struct {
	Phase          string
	Percent        float64
	Message        string
	BytesProcessed int64
	BytesTotal     int64
	CurrentFile    string
}
