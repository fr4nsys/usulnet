// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Restorer handles backup restoration operations.
type Restorer struct {
	storage           Storage
	repo              Repository
	volumeProvider    VolumeProvider
	containerProvider ContainerProvider
	archiver          Archiver
	encryptor         *crypto.AESEncryptor
	config            Config
	logger            *logger.Logger
}

// NewRestorer creates a new backup restorer.
func NewRestorer(
	storage Storage,
	repo Repository,
	volumeProvider VolumeProvider,
	containerProvider ContainerProvider,
	config Config,
	log *logger.Logger,
) (*Restorer, error) {
	restorer := &Restorer{
		storage:           storage,
		repo:              repo,
		volumeProvider:    volumeProvider,
		containerProvider: containerProvider,
		archiver:          NewTarArchiver(),
		config:            config,
		logger:            log.Named("backup.restorer"),
	}

	// Initialize encryptor if key is provided
	if config.EncryptionKey != "" {
		enc, err := crypto.NewAESEncryptor(config.EncryptionKey)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDecryptionFailed, "invalid encryption key")
		}
		restorer.encryptor = enc
	}

	return restorer, nil
}

// Restore restores a backup.
func (r *Restorer) Restore(ctx context.Context, opts RestoreOptions) (*RestoreResult, error) {
	start := time.Now()

	// Get backup record
	backup, err := r.repo.Get(ctx, opts.BackupID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeBackupNotFound, "backup not found")
	}

	// Validate backup status
	if backup.Status != models.BackupStatusCompleted {
		return nil, errors.New(errors.CodeRestoreFailed,
			fmt.Sprintf("cannot restore backup with status %s", backup.Status))
	}

	// Check if backup is expired
	if backup.IsExpired() {
		return nil, errors.New(errors.CodeRestoreFailed, "backup has expired")
	}

	r.logger.Info("starting restore",
		"backup_id", backup.ID,
		"type", backup.Type,
		"target", backup.TargetName,
	)

	// Report progress
	if opts.ProgressCallback != nil {
		opts.ProgressCallback(Progress{
			Phase:   "preparing",
			Percent: 0,
			Message: "Preparing restore...",
		})
	}

	// Update backup status
	backup.Status = models.BackupStatusRestoring
	r.repo.Update(ctx, backup)

	// Restore based on type
	var result *RestoreResult
	switch backup.Type {
	case models.BackupTypeVolume:
		result, err = r.restoreVolume(ctx, backup, opts)
	case models.BackupTypeContainer:
		result, err = r.restoreContainer(ctx, backup, opts)
	case models.BackupTypeStack:
		result, err = r.restoreStack(ctx, backup, opts)
	default:
		err = errors.New(errors.CodeRestoreFailed, "unsupported backup type")
	}

	// Restore backup status
	backup.Status = models.BackupStatusCompleted
	r.repo.Update(ctx, backup)

	if err != nil {
		r.logger.Error("restore failed",
			"backup_id", backup.ID,
			"error", err,
		)
		return nil, err
	}

	result.BackupID = backup.ID
	result.Duration = time.Since(start)

	r.logger.Info("restore completed",
		"backup_id", backup.ID,
		"target", result.TargetName,
		"duration", result.Duration,
	)

	return result, nil
}

// restoreVolume restores a volume backup.
func (r *Restorer) restoreVolume(ctx context.Context, backup *models.Backup, opts RestoreOptions) (*RestoreResult, error) {
	// Determine target name
	targetName := opts.TargetName
	if targetName == "" {
		targetName = backup.TargetName
		if targetName == "" {
			targetName = backup.TargetID
		}
	}

	// Check if volume exists
	exists, err := r.volumeProvider.VolumeExists(ctx, backup.HostID, targetName)
	if err != nil {
		return nil, err
	}

	if exists && !opts.OverwriteExisting {
		return nil, errors.New(errors.CodeConflict,
			fmt.Sprintf("volume %s already exists, use overwrite option to replace", targetName))
	}

	// Create volume if it doesn't exist
	if !exists {
		driver := "local"
		if backup.Metadata != nil && backup.Metadata.VolumeDriver != "" {
			driver = backup.Metadata.VolumeDriver
		}

		// FIX: Use CreateVolumeOptions instead of separate arguments
		createOpts := CreateVolumeOptions{
			Name:   targetName,
			Driver: driver,
		}
		if _, err := r.volumeProvider.CreateVolume(ctx, backup.HostID, createOpts); err != nil {
			return nil, errors.Wrap(err, errors.CodeRestoreFailed, "failed to create volume")
		}
	}

	// FIX: Use GetVolumeMountpoint instead of GetVolumePath
	volumePath, err := r.volumeProvider.GetVolumeMountpoint(ctx, backup.HostID, targetName)
	if err != nil {
		return nil, err
	}

	// Report progress
	if opts.ProgressCallback != nil {
		opts.ProgressCallback(Progress{
			Phase:   "extracting",
			Percent: 20,
			Message: "Downloading and extracting backup...",
		})
	}

	// Extract backup to volume
	result, err := r.extractBackup(ctx, backup, volumePath, opts)
	if err != nil {
		return nil, err
	}

	result.TargetID = targetName
	result.TargetName = targetName

	return result, nil
}

// restoreContainer restores a container backup.
func (r *Restorer) restoreContainer(ctx context.Context, backup *models.Backup, opts RestoreOptions) (*RestoreResult, error) {
	// Create temporary directory for extraction
	tmpDir, err := os.MkdirTemp("", "restore-*")
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeRestoreFailed, "failed to create temp directory")
	}
	defer os.RemoveAll(tmpDir)

	// Report progress
	if opts.ProgressCallback != nil {
		opts.ProgressCallback(Progress{
			Phase:   "extracting",
			Percent: 20,
			Message: "Downloading and extracting backup...",
		})
	}

	// Extract backup
	extractResult, err := r.extractBackup(ctx, backup, tmpDir, opts)
	if err != nil {
		return nil, err
	}

	// Read metadata
	metaPath := filepath.Join(tmpDir, "backup_metadata.json")
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeBackupCorrupted, "backup metadata not found")
	}

	var meta struct {
		ContainerID   string   `json:"container_id"`
		ContainerName string   `json:"container_name"`
		Volumes       []string `json:"volumes"`
	}
	if err := json.Unmarshal(metaData, &meta); err != nil {
		return nil, errors.Wrap(err, errors.CodeBackupCorrupted, "invalid backup metadata")
	}

	// Stop container if running and overwrite is allowed
	targetID := opts.TargetName
	if targetID == "" {
		targetID = meta.ContainerID
	}

	if opts.OverwriteExisting {
		running, _ := r.containerProvider.IsContainerRunning(ctx, backup.HostID, targetID)
		if running {
			if opts.ProgressCallback != nil {
				opts.ProgressCallback(Progress{
					Phase:   "preparing",
					Percent: 50,
					Message: "Stopping container...",
				})
			}

			// FIX: StopContainer expects *int, not time.Duration
			timeout := 30
			if err := r.containerProvider.StopContainer(ctx, backup.HostID, targetID, &timeout); err != nil {
				r.logger.Warn("failed to stop container for restore", "error", err)
			}
		}
	}

	// Restore each volume
	for i, volumeName := range meta.Volumes {
		volumeDataDir := filepath.Join(tmpDir, volumeName)
		if _, err := os.Stat(volumeDataDir); os.IsNotExist(err) {
			continue
		}

		// Get or create volume
		targetVolumeName := volumeName
		exists, _ := r.volumeProvider.VolumeExists(ctx, backup.HostID, targetVolumeName)

		if !exists {
			// FIX: Use CreateVolumeOptions instead of separate arguments
			createOpts := CreateVolumeOptions{
				Name:   targetVolumeName,
				Driver: "local",
			}
			if _, err := r.volumeProvider.CreateVolume(ctx, backup.HostID, createOpts); err != nil {
				r.logger.Warn("failed to create volume",
					"volume", targetVolumeName,
					"error", err,
				)
				continue
			}
		} else if !opts.OverwriteExisting {
			r.logger.Info("skipping existing volume",
				"volume", targetVolumeName,
			)
			continue
		}

		// FIX: Use GetVolumeMountpoint instead of GetVolumePath
		volumePath, err := r.volumeProvider.GetVolumeMountpoint(ctx, backup.HostID, targetVolumeName)
		if err != nil {
			r.logger.Warn("failed to get volume path",
				"volume", targetVolumeName,
				"error", err,
			)
			continue
		}

		// Copy data to volume
		if err := copyDir(volumeDataDir, volumePath); err != nil {
			return nil, errors.Wrap(err, errors.CodeRestoreFailed,
				fmt.Sprintf("failed to restore volume %s", targetVolumeName))
		}

		if opts.ProgressCallback != nil {
			percent := 50 + float64(i+1)/float64(len(meta.Volumes))*40
			opts.ProgressCallback(Progress{
				Phase:   "restoring",
				Percent: percent,
				Message: fmt.Sprintf("Restored volume %s", targetVolumeName),
			})
		}
	}

	// Start container if requested
	if opts.StartAfterRestore {
		if opts.ProgressCallback != nil {
			opts.ProgressCallback(Progress{
				Phase:   "starting",
				Percent: 95,
				Message: "Starting container...",
			})
		}

		if err := r.containerProvider.StartContainer(ctx, backup.HostID, targetID); err != nil {
			r.logger.Warn("failed to start container after restore", "error", err)
		}
	}

	if opts.ProgressCallback != nil {
		opts.ProgressCallback(Progress{
			Phase:   "completed",
			Percent: 100,
			Message: "Restore completed",
		})
	}

	return &RestoreResult{
		TargetID:     targetID,
		TargetName:   meta.ContainerName,
		BytesWritten: extractResult.BytesWritten,
		FileCount:    extractResult.FileCount,
	}, nil
}

// restoreStack restores a stack backup.
func (r *Restorer) restoreStack(ctx context.Context, backup *models.Backup, opts RestoreOptions) (*RestoreResult, error) {
	return nil, errors.New(errors.CodeRestoreFailed, "stack restore not yet implemented")
}

// extractBackup extracts a backup to a destination path.
func (r *Restorer) extractBackup(ctx context.Context, backup *models.Backup, destPath string, opts RestoreOptions) (*RestoreResult, error) {
	// Read backup from storage
	reader, err := r.storage.Read(ctx, backup.Path)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to read backup from storage")
	}
	defer reader.Close()

	var dataReader io.Reader = reader

	// Decrypt if needed
	if backup.Encrypted {
		if r.encryptor == nil {
			return nil, errors.New(errors.CodeDecryptionFailed, "backup is encrypted but no encryption key configured")
		}

		if opts.ProgressCallback != nil {
			opts.ProgressCallback(Progress{
				Phase:   "decrypting",
				Percent: 30,
				Message: "Decrypting backup...",
			})
		}

		decrypted, err := r.decryptStream(reader)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDecryptionFailed, "failed to decrypt backup")
		}
		dataReader = bytes.NewReader(decrypted)
	}

	// Set up progress callback for archiver
	archiver := r.archiver.(*TarArchiver)
	archiver.ProgressCallback = func(current, total int64, currentFile string) {
		if opts.ProgressCallback != nil {
			basePercent := 40.0
			if backup.Encrypted {
				basePercent = 50.0
			}
			opts.ProgressCallback(Progress{
				Phase:          "extracting",
				Percent:        basePercent + float64(current)/float64(total)*40,
				BytesProcessed: current,
				BytesTotal:     total,
				CurrentFile:    currentFile,
			})
		}
	}

	// Extract archive
	result, err := archiver.Extract(ctx, dataReader, destPath, backup.Compression)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeRestoreFailed, "failed to extract backup")
	}

	return &RestoreResult{
		BytesWritten: result.BytesWritten,
		FileCount:    result.FileCount,
	}, nil
}

// decryptStream decrypts an encrypted backup stream.
func (r *Restorer) decryptStream(reader io.Reader) ([]byte, error) {
	// Read all encrypted data
	encrypted, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	// Decrypt
	decrypted, err := r.encryptor.Decrypt(string(encrypted))
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

// Verify verifies backup integrity.
func (r *Restorer) Verify(ctx context.Context, backupID uuid.UUID, opts VerifyOptions) (*models.BackupVerificationResult, error) {
	backup, err := r.repo.Get(ctx, backupID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeBackupNotFound, "backup not found")
	}

	result := &models.BackupVerificationResult{
		BackupID:   backupID,
		VerifiedAt: time.Now(),
	}

	// Check backup exists in storage
	exists, err := r.storage.Exists(ctx, backup.Path)
	if err != nil {
		errMsg := err.Error()
		result.ErrorMessage = &errMsg
		return result, nil
	}
	if !exists {
		errMsg := "backup file not found in storage"
		result.ErrorMessage = &errMsg
		return result, nil
	}

	// Read backup
	reader, err := r.storage.Read(ctx, backup.Path)
	if err != nil {
		errMsg := err.Error()
		result.ErrorMessage = &errMsg
		return result, nil
	}
	defer reader.Close()

	result.Readable = true

	// Verify checksum if available and not encrypted
	if backup.Checksum != nil && !backup.Encrypted {
		checksum, err := CalculateChecksum(reader)
		if err != nil {
			errMsg := err.Error()
			result.ErrorMessage = &errMsg
			return result, nil
		}

		result.ChecksumValid = (checksum == *backup.Checksum)
		if !result.ChecksumValid {
			errMsg := fmt.Sprintf("checksum mismatch: expected %s, got %s", *backup.Checksum, checksum)
			result.ErrorMessage = &errMsg
			return result, nil
		}

		// Need to re-read for content check
		reader.Close()
		reader, _ = r.storage.Read(ctx, backup.Path)
		defer reader.Close()
	} else {
		result.ChecksumValid = true // Skip checksum for encrypted
	}

	// Full extraction test if requested
	if opts.FullExtract && !opts.ChecksumOnly {
		tmpDir, err := os.MkdirTemp("", "verify-*")
		if err != nil {
			errMsg := err.Error()
			result.ErrorMessage = &errMsg
			return result, nil
		}
		defer os.RemoveAll(tmpDir)

		var dataReader io.Reader = reader
		if backup.Encrypted && r.encryptor != nil {
			decrypted, err := r.decryptStream(reader)
			if err != nil {
				errMsg := "decryption failed: " + err.Error()
				result.ErrorMessage = &errMsg
				return result, nil
			}
			dataReader = bytes.NewReader(decrypted)
		}

		extractResult, err := r.archiver.Extract(ctx, dataReader, tmpDir, backup.Compression)
		if err != nil {
			errMsg := "extraction failed: " + err.Error()
			result.ErrorMessage = &errMsg
			return result, nil
		}

		result.FileCount = extractResult.FileCount
	}

	result.IsValid = result.Readable && result.ChecksumValid

	// Update backup record
	backup.Verified = result.IsValid
	backup.VerifiedAt = &result.VerifiedAt
	r.repo.Update(ctx, backup)

	return result, nil
}

// ListContents lists the contents of a backup.
func (r *Restorer) ListContents(ctx context.Context, backupID uuid.UUID) ([]ArchiveEntry, error) {
	backup, err := r.repo.Get(ctx, backupID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeBackupNotFound, "backup not found")
	}

	reader, err := r.storage.Read(ctx, backup.Path)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to read backup")
	}
	defer reader.Close()

	var dataReader io.Reader = reader
	if backup.Encrypted && r.encryptor != nil {
		decrypted, err := r.decryptStream(reader)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDecryptionFailed, "failed to decrypt backup")
		}
		dataReader = bytes.NewReader(decrypted)
	}

	return r.archiver.List(ctx, dataReader, backup.Compression)
}
