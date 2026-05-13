// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// Creator handles backup creation operations.
type Creator struct {
	storage           Storage
	repo              Repository
	volumeProvider    VolumeProvider
	containerProvider ContainerProvider
	stackProvider     StackProvider
	archiver          Archiver
	encryptor         *crypto.AESEncryptor
	config            Config
	logger            *logger.Logger
}

// NewCreator creates a new backup creator.
func NewCreator(
	storage Storage,
	repo Repository,
	volumeProvider VolumeProvider,
	containerProvider ContainerProvider,
	config Config,
	log *logger.Logger,
	opts ...CreatorOption,
) (*Creator, error) {
	creator := &Creator{
		storage:           storage,
		repo:              repo,
		volumeProvider:    volumeProvider,
		containerProvider: containerProvider,
		archiver:          NewTarArchiver(),
		config:            config,
		logger:            log.Named("backup.creator"),
	}

	// Apply options
	for _, opt := range opts {
		opt(creator)
	}

	// Initialize encryptor if key is provided
	if config.EncryptionKey != "" {
		enc, err := crypto.NewAESEncryptor(config.EncryptionKey)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeEncryptionFailed, "invalid encryption key")
		}
		creator.encryptor = enc
	}

	return creator, nil
}

// CreatorOption configures the Creator.
type CreatorOption func(*Creator)

// WithStackProvider sets the stack provider for stack backups.
func WithStackProvider(sp StackProvider) CreatorOption {
	return func(c *Creator) {
		c.stackProvider = sp
	}
}

// Create creates a new backup.
func (c *Creator) Create(ctx context.Context, opts CreateOptions) (*CreateResult, error) {
	start := time.Now()

	// Apply defaults
	if opts.Compression == "" {
		opts.Compression = c.config.DefaultCompression
	}
	if opts.RetentionDays == nil {
		days := c.config.DefaultRetentionDays
		opts.RetentionDays = &days
	}

	// Create backup record
	backup := &models.Backup{
		ID:          uuid.New(),
		HostID:      opts.HostID,
		Type:        opts.Type,
		TargetID:    opts.TargetID,
		TargetName:  opts.TargetName,
		Status:      models.BackupStatusPending,
		Trigger:     opts.Trigger,
		Compression: opts.Compression,
		Encrypted:   opts.Encrypt && c.encryptor != nil,
		Metadata:    opts.Metadata,
		CreatedBy:   opts.CreatedBy,
		CreatedAt:   time.Now(),
	}

	// Calculate expiration
	if opts.RetentionDays != nil && *opts.RetentionDays > 0 {
		expiresAt := time.Now().AddDate(0, 0, *opts.RetentionDays)
		backup.ExpiresAt = &expiresAt
	}

	// Generate filename and path
	backup.Filename = c.generateFilename(backup)
	backup.Path = c.generatePath(backup)

	// Save initial record
	if err := c.repo.Create(ctx, backup); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create backup record")
	}

	// Update status to running
	now := time.Now()
	backup.Status = models.BackupStatusRunning
	backup.StartedAt = &now
	c.repo.Update(ctx, backup)

	// Report progress
	if opts.ProgressCallback != nil {
		opts.ProgressCallback(Progress{
			Phase:   "preparing",
			Percent: 0,
			Message: "Preparing backup...",
		})
	}

	// Create backup based on type
	var result *CreateResult
	var err error

	switch opts.Type {
	case models.BackupTypeVolume:
		result, err = c.createVolumeBackup(ctx, backup, opts)
	case models.BackupTypeContainer:
		result, err = c.createContainerBackup(ctx, backup, opts)
	case models.BackupTypeStack:
		result, err = c.createStackBackup(ctx, backup, opts)
	default:
		err = errors.New(errors.CodeBackupFailed, "unsupported backup type")
	}

	// Handle completion
	completedAt := time.Now()
	backup.CompletedAt = &completedAt

	if err != nil {
		backup.Status = models.BackupStatusFailed
		errMsg := err.Error()
		backup.ErrorMessage = &errMsg
		c.repo.Update(ctx, backup)

		c.logger.Error("backup failed",
			"backup_id", backup.ID,
			"type", opts.Type,
			"target", opts.TargetID,
			"error", err,
		)

		return nil, err
	}

	backup.Status = models.BackupStatusCompleted
	c.repo.Update(ctx, backup)

	result.Backup = backup
	result.Duration = time.Since(start)

	c.logger.Info("backup completed",
		"backup_id", backup.ID,
		"type", opts.Type,
		"target", opts.TargetID,
		"size", backup.SizeBytes,
		"duration", result.Duration,
	)

	return result, nil
}

// createVolumeBackup creates a backup of a Docker volume.
func (c *Creator) createVolumeBackup(ctx context.Context, backup *models.Backup, opts CreateOptions) (*CreateResult, error) {
	// Get volume path
	volumePath, err := c.volumeProvider.GetVolumeMountpoint(ctx, opts.HostID, opts.TargetID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeVolumeNotFound, "failed to get volume path")
	}

	// Get volume info for metadata
	volumeInfo, err := c.volumeProvider.GetVolume(ctx, opts.HostID, opts.TargetID)
	if err == nil && backup.Metadata == nil {
		backup.Metadata = &models.BackupMetadata{
			VolumeDriver: volumeInfo.Driver,
			Labels:       volumeInfo.Labels,
		}
	}

	// Report progress
	if opts.ProgressCallback != nil {
		opts.ProgressCallback(Progress{
			Phase:   "archiving",
			Percent: 10,
			Message: "Creating archive from volume...",
		})
	}

	// Check if the volume path is directly accessible (host install).
	// If not (containerized install), use Docker API to copy volume data.
	if _, statErr := os.Stat(volumePath); statErr != nil && os.IsNotExist(statErr) {
		c.logger.Info("volume path not accessible locally, using Docker API",
			"volume", opts.TargetID,
			"path", volumePath,
		)

		tmpDir, mkErr := os.MkdirTemp("", "usulnet-vol-backup-*")
		if mkErr != nil {
			return nil, errors.Wrap(mkErr, errors.CodeBackupFailed, "failed to create temp directory")
		}
		defer os.RemoveAll(tmpDir)

		if copyErr := c.volumeProvider.CopyVolumeData(ctx, opts.HostID, opts.TargetID, tmpDir); copyErr != nil {
			return nil, errors.Wrap(copyErr, errors.CodeBackupFailed, "failed to copy volume data via Docker API")
		}

		volumePath = tmpDir
	}

	// Create archive
	return c.createArchive(ctx, backup, volumePath, opts)
}

// createContainerBackup creates a backup of a container's volumes.
func (c *Creator) createContainerBackup(ctx context.Context, backup *models.Backup, opts CreateOptions) (*CreateResult, error) {
	// Get container info
	containerInfo, err := c.containerProvider.GetContainer(ctx, opts.HostID, opts.TargetID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeContainerNotFound, "failed to get container info")
	}

	// Store metadata
	if backup.Metadata == nil {
		backup.Metadata = &models.BackupMetadata{}
	}
	backup.Metadata.ContainerImage = containerInfo.Image
	backup.Metadata.Labels = containerInfo.Labels

	// Stop container if requested
	var wasRunning bool
	if opts.StopContainer {
		wasRunning, err = c.containerProvider.IsContainerRunning(ctx, opts.HostID, opts.TargetID)
		if err != nil {
			return nil, err
		}

		if wasRunning {
			if opts.ProgressCallback != nil {
				opts.ProgressCallback(Progress{
					Phase:   "preparing",
					Percent: 5,
					Message: "Stopping container...",
				})
			}

			if err := func() error {
				timeout := 30
				return c.containerProvider.StopContainer(ctx, opts.HostID, opts.TargetID, &timeout)
			}(); err != nil {
				return nil, errors.Wrap(err, errors.CodeBackupFailed, "failed to stop container")
			}

			// Ensure container is restarted on exit
			defer func() {
				if wasRunning {
					c.containerProvider.StartContainer(ctx, opts.HostID, opts.TargetID)
				}
			}()
		}
	}

	// Create temporary directory to collect all volume data
	tmpDir, err := os.MkdirTemp("", "backup-*")
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeBackupFailed, "failed to create temp directory")
	}
	defer os.RemoveAll(tmpDir)

	// Copy volume data
	volumes := containerInfo.Volumes

	for _, volumeName := range volumes {
		// Get volume mountpoint
		mountpoint, err := c.volumeProvider.GetVolumeMountpoint(ctx, opts.HostID, volumeName)
		if err != nil {
			continue // Skip volumes we can't access
		}

		// Create subdirectory for this volume
		volumeDir := filepath.Join(tmpDir, volumeName)
		if err := os.MkdirAll(volumeDir, 0755); err != nil {
			return nil, errors.Wrap(err, errors.CodeBackupFailed, "failed to create volume directory")
		}

		// Copy volume data
		if err := copyDir(mountpoint, volumeDir); err != nil {
			return nil, errors.Wrap(err, errors.CodeBackupFailed,
				fmt.Sprintf("failed to copy volume %s", volumeName))
		}

		if opts.ProgressCallback != nil {
			opts.ProgressCallback(Progress{
				Phase:   "archiving",
				Percent: 20,
				Message: fmt.Sprintf("Copied volume %s", volumeName),
			})
		}
	}

	// Write metadata file
	metaData := map[string]interface{}{
		"container_id":    containerInfo.ID,
		"container_name":  containerInfo.Name,
		"container_image": containerInfo.Image,
		"volumes":         volumes,
		"labels":          containerInfo.Labels,
		"backup_time":     time.Now().UTC(),
	}
	metaJSON, _ := json.MarshalIndent(metaData, "", "  ")
	os.WriteFile(filepath.Join(tmpDir, "backup_metadata.json"), metaJSON, 0644)

	// Create archive
	return c.createArchive(ctx, backup, tmpDir, opts)
}

// createStackBackup creates a backup of a stack's volumes and configuration.
func (c *Creator) createStackBackup(ctx context.Context, backup *models.Backup, opts CreateOptions) (*CreateResult, error) {
	if c.stackProvider == nil {
		return nil, errors.New(errors.CodeBackupFailed, "stack provider not configured")
	}

	// Parse stack ID from TargetID
	stackID, err := uuid.Parse(opts.TargetID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeValidation, "invalid stack ID")
	}

	// Get stack info
	stackInfo, err := c.stackProvider.GetStack(ctx, stackID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "failed to get stack info")
	}

	// Get containers in the stack
	containers, err := c.stackProvider.GetStackContainers(ctx, stackID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeBackupFailed, "failed to get stack containers")
	}

	// Store metadata
	if backup.Metadata == nil {
		backup.Metadata = &models.BackupMetadata{}
	}
	backup.Metadata.StackServices = stackInfo.Services
	backup.Metadata.Labels = stackInfo.Labels

	// Report progress
	if opts.ProgressCallback != nil {
		opts.ProgressCallback(Progress{
			Phase:   "preparing",
			Percent: 5,
			Message: fmt.Sprintf("Preparing backup for stack %s with %d containers...", stackInfo.Name, len(containers)),
		})
	}

	// Stop containers if requested
	var stoppedContainers []string
	if opts.StopContainer {
		if opts.ProgressCallback != nil {
			opts.ProgressCallback(Progress{
				Phase:   "preparing",
				Percent: 10,
				Message: "Stopping stack containers...",
			})
		}

		for _, container := range containers {
			running, err := c.containerProvider.IsContainerRunning(ctx, opts.HostID, container.ID)
			if err != nil {
				continue
			}

			if running {
				timeout := 30
				if err := c.containerProvider.StopContainer(ctx, opts.HostID, container.ID, &timeout); err != nil {
					c.logger.Warn("failed to stop container for stack backup",
						"container_id", container.ID,
						"error", err,
					)
					continue
				}
				stoppedContainers = append(stoppedContainers, container.ID)
			}
		}

		// Ensure containers are restarted on exit
		defer func() {
			for _, containerID := range stoppedContainers {
				c.containerProvider.StartContainer(ctx, opts.HostID, containerID)
			}
		}()
	}

	// Create temporary directory to collect all data
	tmpDir, err := os.MkdirTemp("", "stack-backup-*")
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeBackupFailed, "failed to create temp directory")
	}
	defer os.RemoveAll(tmpDir)

	// 1. Save stack configuration (docker-compose.yml)
	configDir := filepath.Join(tmpDir, "_stack_config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, errors.Wrap(err, errors.CodeBackupFailed, "failed to create config directory")
	}

	// Write compose file
	if stackInfo.ComposeFile != "" {
		composePath := filepath.Join(configDir, "docker-compose.yml")
		if err := os.WriteFile(composePath, []byte(stackInfo.ComposeFile), 0644); err != nil {
			return nil, errors.Wrap(err, errors.CodeBackupFailed, "failed to write compose file")
		}
	}

	// Write env file if present
	if stackInfo.EnvFile != nil && *stackInfo.EnvFile != "" {
		envPath := filepath.Join(configDir, ".env")
		if err := os.WriteFile(envPath, []byte(*stackInfo.EnvFile), 0644); err != nil {
			c.logger.Warn("failed to write env file", "error", err)
		}
	}

	if opts.ProgressCallback != nil {
		opts.ProgressCallback(Progress{
			Phase:   "archiving",
			Percent: 15,
			Message: "Saved stack configuration...",
		})
	}

	// 2. Collect all unique volumes from all containers
	volumeSet := make(map[string]bool)
	for _, container := range containers {
		for _, volumeName := range container.Volumes {
			volumeSet[volumeName] = true
		}
	}

	// 3. Copy volume data
	volumeCount := 0
	totalVolumes := len(volumeSet)
	for volumeName := range volumeSet {
		volumeCount++

		// Get volume mountpoint
		mountpoint, err := c.volumeProvider.GetVolumeMountpoint(ctx, opts.HostID, volumeName)
		if err != nil {
			c.logger.Warn("failed to get volume mountpoint, skipping",
				"volume", volumeName,
				"error", err,
			)
			continue
		}

		// Create subdirectory for this volume
		volumeDir := filepath.Join(tmpDir, "volumes", volumeName)
		if err := os.MkdirAll(volumeDir, 0755); err != nil {
			return nil, errors.Wrap(err, errors.CodeBackupFailed, "failed to create volume directory")
		}

		// Copy volume data
		if err := copyDir(mountpoint, volumeDir); err != nil {
			c.logger.Warn("failed to copy volume data, skipping",
				"volume", volumeName,
				"error", err,
			)
			continue
		}

		if opts.ProgressCallback != nil {
			progress := 15 + float64(volumeCount)/float64(totalVolumes)*35 // 15-50%
			opts.ProgressCallback(Progress{
				Phase:   "archiving",
				Percent: progress,
				Message: fmt.Sprintf("Copied volume %s (%d/%d)", volumeName, volumeCount, totalVolumes),
			})
		}
	}

	// 4. Write metadata file
	containerNames := make([]string, len(containers))
	containerImages := make(map[string]string)
	for i, c := range containers {
		containerNames[i] = c.Name
		containerImages[c.Name] = c.Image
	}

	metaData := map[string]interface{}{
		"stack_id":         stackInfo.ID.String(),
		"stack_name":       stackInfo.Name,
		"host_id":          stackInfo.HostID.String(),
		"services":         stackInfo.Services,
		"containers":       containerNames,
		"container_images": containerImages,
		"volumes":          keysFromSet(volumeSet),
		"labels":           stackInfo.Labels,
		"backup_time":      time.Now().UTC(),
	}
	metaJSON, _ := json.MarshalIndent(metaData, "", "  ")
	if err := os.WriteFile(filepath.Join(tmpDir, "backup_metadata.json"), metaJSON, 0644); err != nil {
		c.logger.Warn("failed to write metadata file", "error", err)
	}

	// Create archive
	return c.createArchive(ctx, backup, tmpDir, opts)
}

// keysFromSet extracts keys from a map[string]bool.
func keysFromSet(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// createArchive creates the backup archive and stores it.
func (c *Creator) createArchive(ctx context.Context, backup *models.Backup, sourcePath string, opts CreateOptions) (*CreateResult, error) {
	result := &CreateResult{}

	// Calculate original size
	var originalSize int64
	var fileCount int
	filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			originalSize += info.Size()
			fileCount++
		}
		return nil
	})
	result.OriginalSize = originalSize
	result.FileCount = fileCount

	// Create pipe for streaming
	pr, pw := io.Pipe()

	// Error channel
	errCh := make(chan error, 1)

	// Create archive in goroutine
	go func() {
		defer pw.Close()

		archiver := c.archiver.(*TarArchiver)
		archiver.ProgressCallback = func(current, total int64, currentFile string) {
			if opts.ProgressCallback != nil {
				percent := float64(current) / float64(total) * 50 // Archive is 50% of work
				opts.ProgressCallback(Progress{
					Phase:          "archiving",
					Percent:        20 + percent,
					BytesProcessed: current,
					BytesTotal:     total,
					CurrentFile:    currentFile,
				})
			}
		}

		archiveResult, err := archiver.Create(ctx, sourcePath, pw, backup.Compression)
		if err != nil {
			errCh <- err
			return
		}

		backup.Checksum = &archiveResult.Checksum
		if backup.Metadata == nil {
			backup.Metadata = &models.BackupMetadata{}
		}
		backup.Metadata.OriginalSize = archiveResult.OriginalSize
		backup.Metadata.FileCount = archiveResult.FileCount

		errCh <- nil
	}()

	// Create storage writer
	var storageReader io.Reader = pr

	// Encrypt if needed
	if backup.Encrypted && c.encryptor != nil {
		if opts.ProgressCallback != nil {
			opts.ProgressCallback(Progress{
				Phase:   "encrypting",
				Percent: 70,
				Message: "Encrypting backup...",
			})
		}

		// Read, encrypt, and create new reader
		encryptedData, err := c.encryptStream(pr)
		if err != nil {
			pr.Close()
			return nil, errors.Wrap(err, errors.CodeEncryptionFailed, "failed to encrypt backup")
		}
		storageReader = bytes.NewReader(encryptedData)
	}

	// Progress for upload
	if opts.ProgressCallback != nil {
		opts.ProgressCallback(Progress{
			Phase:   "uploading",
			Percent: 80,
			Message: "Storing backup...",
		})
	}

	// Write to storage
	if err := c.storage.Write(ctx, backup.Path, storageReader, -1); err != nil {
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to store backup")
	}

	// Wait for archive creation to complete
	if err := <-errCh; err != nil {
		// Clean up partial backup
		c.storage.Delete(ctx, backup.Path)
		return nil, err
	}

	// Get final size from storage
	size, err := c.storage.Size(ctx, backup.Path)
	if err == nil {
		backup.SizeBytes = size
		result.FinalSize = size
	}

	// Verify if configured
	if c.config.VerifyAfterBackup {
		if opts.ProgressCallback != nil {
			opts.ProgressCallback(Progress{
				Phase:   "verifying",
				Percent: 90,
				Message: "Verifying backup...",
			})
		}

		verified, err := c.verifyBackup(ctx, backup)
		if err != nil {
			c.logger.Warn("backup verification failed",
				"backup_id", backup.ID,
				"error", err,
			)
		} else {
			backup.Verified = verified
			now := time.Now()
			backup.VerifiedAt = &now
			result.Verified = verified
		}
	}

	// Update record with final data
	c.repo.Update(ctx, backup)

	if opts.ProgressCallback != nil {
		opts.ProgressCallback(Progress{
			Phase:   "completed",
			Percent: 100,
			Message: "Backup completed",
		})
	}

	return result, nil
}

// encryptStream encrypts a stream and returns the encrypted data.
func (c *Creator) encryptStream(reader io.Reader) ([]byte, error) {
	// Read all data
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	// Encrypt
	encrypted, err := c.encryptor.Encrypt(data)
	if err != nil {
		return nil, err
	}

	return []byte(encrypted), nil
}

// verifyBackup verifies a backup's integrity.
func (c *Creator) verifyBackup(ctx context.Context, backup *models.Backup) (bool, error) {
	// Read backup
	reader, err := c.storage.Read(ctx, backup.Path)
	if err != nil {
		return false, err
	}
	defer reader.Close()

	// Calculate checksum
	hash := sha256.New()
	if _, err := io.Copy(hash, reader); err != nil {
		return false, err
	}

	checksum := hex.EncodeToString(hash.Sum(nil))

	// For encrypted backups, checksum is of encrypted data
	// For unencrypted, it should match the archive checksum
	if backup.Encrypted {
		// Just verify we can read it
		return true, nil
	}

	if backup.Checksum != nil && *backup.Checksum != checksum {
		return false, fmt.Errorf("checksum mismatch: expected %s, got %s", *backup.Checksum, checksum)
	}

	return true, nil
}

// generateFilename generates a backup filename.
func (c *Creator) generateFilename(backup *models.Backup) string {
	timestamp := time.Now().Format("20060102-150405")
	ext := GetCompressionExtension(backup.Compression)
	if backup.Encrypted {
		ext += ".enc"
	}

	name := backup.TargetName
	if name == "" {
		name = backup.TargetID
	}

	// Sanitize name
	name = sanitizeFilename(name)

	return fmt.Sprintf("%s_%s_%s%s", name, string(backup.Type), timestamp, ext)
}

// generatePath generates the storage path for a backup.
func (c *Creator) generatePath(backup *models.Backup) string {
	return fmt.Sprintf("%s/%s/%s",
		backup.HostID.String(),
		string(backup.Type),
		backup.Filename,
	)
}

// sanitizeFilename removes invalid characters from filename.
func sanitizeFilename(name string) string {
	// Remove leading slash and replace invalid chars
	result := make([]byte, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			result = append(result, byte(r))
		case r >= 'A' && r <= 'Z':
			result = append(result, byte(r))
		case r >= '0' && r <= '9':
			result = append(result, byte(r))
		case r == '-' || r == '_' || r == '.':
			result = append(result, byte(r))
		default:
			result = append(result, '_')
		}
	}
	return string(result)
}

// copyDir copies a directory recursively.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get relative path
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		dstPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}

		// Copy file
		return copyFile(path, dstPath, info.Mode())
	})
}

// copyFile copies a single file.
func copyFile(src, dst string, mode os.FileMode) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}
