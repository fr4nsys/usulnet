// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package update

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ContainerVersionUpdater persists version info back to the containers table.
type ContainerVersionUpdater interface {
	UpdateVersionInfo(ctx context.Context, id string, currentVersion, latestVersion string, updateAvailable bool) error
}

// Service handles container update operations
type Service struct {
	repo              UpdateRepository
	checker           *Checker
	changelogFetcher  *ChangelogFetcher
	dockerClient      DockerClient
	backupService     BackupService
	securityService   SecurityService
	versionUpdater    ContainerVersionUpdater
	logger            *logger.Logger
	config            *ServiceConfig

	// Running updates tracking
	runningUpdates map[uuid.UUID]*runningUpdate
	runningMu      sync.RWMutex

	// Semaphore to enforce MaxConcurrentUpdates
	updateSem chan struct{}
}

// ServiceConfig holds configuration for the update service
type ServiceConfig struct {
	// DefaultHealthCheckWait is the default wait time for health checks
	DefaultHealthCheckWait time.Duration

	// DefaultMaxRetries is the default max retries for health checks
	DefaultMaxRetries int

	// DefaultBackupVolumes whether to backup volumes by default
	DefaultBackupVolumes bool

	// DefaultSecurityScan whether to perform security scan by default
	DefaultSecurityScan bool

	// MaxConcurrentUpdates is the max number of concurrent updates
	MaxConcurrentUpdates int
}

// DefaultServiceConfig returns default service configuration
func DefaultServiceConfig() *ServiceConfig {
	return &ServiceConfig{
		DefaultHealthCheckWait: 30 * time.Second,
		DefaultMaxRetries:      3,
		DefaultBackupVolumes:   true,
		DefaultSecurityScan:    true,
		MaxConcurrentUpdates:   3,
	}
}

// UpdateRepository interface for update persistence
type UpdateRepository interface {
	Create(ctx context.Context, update *models.Update) error
	Get(ctx context.Context, id uuid.UUID) (*models.Update, error)
	Update(ctx context.Context, update *models.Update) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.UpdateStatus, errorMsg *string) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, opts models.UpdateListOptions) ([]*models.Update, int64, error)
	GetByTarget(ctx context.Context, hostID uuid.UUID, targetID string, limit int) ([]*models.Update, error)
	GetLatestByTarget(ctx context.Context, hostID uuid.UUID, targetID string) (*models.Update, error)
	GetRollbackCandidate(ctx context.Context, hostID uuid.UUID, targetID string) (*models.Update, error)
	GetStats(ctx context.Context, hostID *uuid.UUID) (*models.UpdateStats, error)

	// Policy operations
	CreatePolicy(ctx context.Context, policy *models.UpdatePolicy) error
	GetPolicy(ctx context.Context, id uuid.UUID) (*models.UpdatePolicy, error)
	GetPolicyByTarget(ctx context.Context, hostID uuid.UUID, targetType models.UpdateType, targetID string) (*models.UpdatePolicy, error)
	UpdatePolicy(ctx context.Context, policy *models.UpdatePolicy) error
	DeletePolicy(ctx context.Context, id uuid.UUID) error
	ListPolicies(ctx context.Context, hostID *uuid.UUID) ([]*models.UpdatePolicy, error)
	GetAutoUpdatePolicies(ctx context.Context) ([]*models.UpdatePolicy, error)

	// Webhook operations
	CreateWebhook(ctx context.Context, webhook *models.UpdateWebhook) error
	GetWebhookByToken(ctx context.Context, token string) (*models.UpdateWebhook, error)
	UpdateWebhookLastUsed(ctx context.Context, id uuid.UUID) error
	DeleteWebhook(ctx context.Context, id uuid.UUID) error
	ListWebhooks(ctx context.Context, hostID uuid.UUID) ([]*models.UpdateWebhook, error)
}

// DockerClient interface for Docker operations
type DockerClient interface {
	// Container operations
	ContainerInspect(ctx context.Context, containerID string) (*dockertypes.ContainerJSON, error)
	ContainerStop(ctx context.Context, containerID string, timeout *int) error
	ContainerStart(ctx context.Context, containerID string) error
	ContainerRemove(ctx context.Context, containerID string, force bool) error
	ContainerCreate(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, name string) (string, error)
	ContainerRename(ctx context.Context, containerID, newName string) error
	ContainerList(ctx context.Context) ([]ContainerInfo, error)

	// Image operations
	ImagePull(ctx context.Context, ref string, onProgress func(status string)) error
	ImageInspect(ctx context.Context, imageID string) (*ImageInfo, error)
}

// ImageInfo holds basic image information
type ImageInfo struct {
	ID          string
	RepoTags    []string
	RepoDigests []string
	Created     time.Time
	Size        int64
	Labels      map[string]string
}

// BackupService interface for backup operations (from Dept H)
type BackupService interface {
	Create(ctx context.Context, opts BackupCreateOptions) (*BackupResult, error)
	Restore(ctx context.Context, opts BackupRestoreOptions) (*BackupRestoreResult, error)
}

// BackupCreateOptions for creating backups
type BackupCreateOptions struct {
	HostID      uuid.UUID
	ContainerID string
	Trigger     string
	CreatedBy   *uuid.UUID
}

// BackupResult from creating a backup
type BackupResult struct {
	BackupID uuid.UUID
	Path     string
	Size     int64
}

// BackupRestoreOptions for restoring backups
type BackupRestoreOptions struct {
	BackupID    uuid.UUID
	ContainerID string
}

// BackupRestoreResult from restoring a backup
type BackupRestoreResult struct {
	Success bool
}

// SecurityService interface for security scanning (from Dept F)
type SecurityService interface {
	ScanContainer(ctx context.Context, hostID uuid.UUID, containerID string) (*SecurityScanResult, error)
	GetLatestScan(ctx context.Context, containerID string) (*SecurityScanResult, error)
}

// SecurityScanResult from security scanning
type SecurityScanResult struct {
	Score int
	Grade string
}

// runningUpdate tracks an in-progress update
type runningUpdate struct {
	UpdateID    uuid.UUID
	ContainerID string
	StartedAt   time.Time
	Status      models.UpdateStatus
	Cancel      context.CancelFunc
}

// NewService creates a new update service
func NewService(
	repo UpdateRepository,
	checker *Checker,
	changelogFetcher *ChangelogFetcher,
	dockerClient DockerClient,
	backupService BackupService,
	securityService SecurityService,
	versionUpdater ContainerVersionUpdater,
	config *ServiceConfig,
	log *logger.Logger,
) *Service {
	if config == nil {
		config = DefaultServiceConfig()
	}

	maxConcurrent := config.MaxConcurrentUpdates
	if maxConcurrent <= 0 {
		maxConcurrent = 3
	}

	return &Service{
		repo:              repo,
		checker:          checker,
		changelogFetcher: changelogFetcher,
		dockerClient:     dockerClient,
		backupService:    backupService,
		securityService:  securityService,
		versionUpdater:   versionUpdater,
		logger:           log.Named("update-service"),
		config:           config,
		runningUpdates:   make(map[uuid.UUID]*runningUpdate),
		updateSem:        make(chan struct{}, maxConcurrent),
	}
}

// ============================================================================
// Update Check Operations
// ============================================================================

// CheckForUpdates checks all containers on a host for available updates
func (s *Service) CheckForUpdates(ctx context.Context, hostID uuid.UUID) (*models.UpdateCheckResult, error) {
	// Get all containers
	containers, err := s.dockerClient.ContainerList(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDocker, "failed to list containers")
	}

	// Convert to ContainerInfo slice
	containerInfos := make([]ContainerInfo, 0, len(containers))
	for _, c := range containers {
		containerInfos = append(containerInfos, ContainerInfo{
			ID:    c.ID,
			Name:  c.Name,
			Image: c.Image,
		})
	}

	// Check for updates
	result, err := s.checker.CheckContainers(ctx, containerInfos)
	if err != nil {
		return nil, err
	}

	// Persist version info to database
	if s.versionUpdater != nil && result != nil {
		for _, update := range result.Updates {
			if err := s.versionUpdater.UpdateVersionInfo(
				ctx,
				update.ContainerID,
				update.CurrentVersion,
				update.LatestVersion,
				update.NeedsUpdate(),
			); err != nil {
				s.logger.Debug("failed to persist version info", "container_id", update.ContainerID, "error", err)
			}
		}
	}

	return result, nil
}

// CheckContainerForUpdate checks a specific container for updates
func (s *Service) CheckContainerForUpdate(ctx context.Context, hostID uuid.UUID, containerID string) (*models.AvailableUpdate, error) {
	// Inspect container
	info, err := s.dockerClient.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDocker, "failed to inspect container")
	}

	// Get current digest
	imageInfo, err := s.dockerClient.ImageInspect(ctx, info.Image)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDocker, "failed to inspect image")
	}

	currentDigest := ""
	if len(imageInfo.RepoDigests) > 0 {
		currentDigest = ExtractDigestFromRepoDigests(imageInfo.RepoDigests, info.Config.Image)
	}

	// Check for update (pass currentDigest for accurate "latest" tag comparison)
	update, err := s.checker.CheckContainer(ctx, containerID, info.Name, info.Config.Image, currentDigest)
	if err != nil {
		return nil, err
	}

	// Fetch changelog if update available
	if update != nil && update.NeedsUpdate() {
		changelog, _ := s.changelogFetcher.FetchChangelog(ctx, info.Config.Image, update.LatestVersion, imageInfo.Labels)
		if changelog != nil {
			update.Changelog = changelog
			update.HasChangelog = true
		}
	}

	// Persist version info to database
	if s.versionUpdater != nil && update != nil {
		if err := s.versionUpdater.UpdateVersionInfo(
			ctx,
			update.ContainerID,
			update.CurrentVersion,
			update.LatestVersion,
			update.NeedsUpdate(),
		); err != nil {
			s.logger.Debug("failed to persist version info", "container_id", update.ContainerID, "error", err)
		}
	}

	return update, nil
}

// ============================================================================
// Update Execution Operations
// ============================================================================

// UpdateContainer performs an update on a container
func (s *Service) UpdateContainer(ctx context.Context, hostID uuid.UUID, opts *models.UpdateOptions) (*models.UpdateResult, error) {
	log := s.logger.With("container_id", opts.ContainerID, "host_id", hostID)
	log.Info("Starting container update")

	// Create update record
	update := &models.Update{
		ID:        uuid.New(),
		HostID:    hostID,
		Type:      models.UpdateTypeContainer,
		TargetID:  opts.ContainerID,
		Status:    models.UpdateStatusPending,
		Trigger:   models.UpdateTriggerManual,
		CreatedBy: opts.CreatedBy,
		CreatedAt: time.Now(),
	}

	// Inspect container
	containerInfo, err := s.dockerClient.ContainerInspect(ctx, opts.ContainerID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDocker, "failed to inspect container")
	}

	update.TargetName = containerInfo.Name
	update.Image = containerInfo.Config.Image

	// Parse current version
	ref, err := ParseImageRef(containerInfo.Config.Image)
	if err != nil {
		return nil, err
	}
	update.FromVersion = ref.Tag

	// Get current digest
	imageInfo, err := s.dockerClient.ImageInspect(ctx, containerInfo.Image)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDocker, "failed to inspect image")
	}
	if len(imageInfo.RepoDigests) > 0 {
		digest := ExtractDigestFromRepoDigests(imageInfo.RepoDigests, containerInfo.Config.Image)
		update.FromDigest = &digest
	}

	// Determine target version
	if opts.TargetVersion != "" {
		update.ToVersion = opts.TargetVersion
	} else {
		// Get latest version
		available, err := s.CheckContainerForUpdate(ctx, hostID, opts.ContainerID)
		if err != nil {
			return nil, err
		}
		if available == nil || !available.NeedsUpdate() {
			return &models.UpdateResult{
				Update:      update,
				Success:     true,
				FromVersion: update.FromVersion,
				ToVersion:   update.FromVersion,
				ErrorMessage: "already up to date",
			}, nil
		}
		update.ToVersion = available.LatestVersion
		if available.Changelog != nil {
			update.ChangelogURL = &available.Changelog.URL
			update.ChangelogBody = &available.Changelog.Body
		}
	}

	// Save initial record
	if err := s.repo.Create(ctx, update); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabase, "failed to create update record")
	}

	// If dry run, stop here
	if opts.DryRun {
		update.Status = models.UpdateStatusSkipped
		if err := s.repo.Update(ctx, update); err != nil {
			s.logger.Warn("failed to persist dry-run update status", "error", err)
		}
		return &models.UpdateResult{
			Update:      update,
			Success:     true,
			FromVersion: update.FromVersion,
			ToVersion:   update.ToVersion,
			DryRun:      true,
		}, nil
	}

	// Acquire semaphore to enforce MaxConcurrentUpdates
	select {
	case s.updateSem <- struct{}{}:
		defer func() { <-s.updateSem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Execute the update
	result := s.executeUpdate(ctx, update, containerInfo, opts)

	return result, nil
}

// executeUpdate performs the actual update workflow
func (s *Service) executeUpdate(ctx context.Context, update *models.Update, containerInfo *dockertypes.ContainerJSON, opts *models.UpdateOptions) *models.UpdateResult {
	log := s.logger.With("update_id", update.ID, "container", update.TargetName)
	startTime := time.Now()
	update.StartedAt = &startTime

	result := &models.UpdateResult{
		Update:      update,
		FromVersion: update.FromVersion,
		ToVersion:   update.ToVersion,
	}

	// Track running update
	s.trackUpdate(update.ID, update.TargetID)
	defer s.untrackUpdate(update.ID)

	// 1. Pre-update security scan
	if (opts.SecurityScan || s.config.DefaultSecurityScan) && s.securityService != nil {
		update.Status = models.UpdateStatusChecking
		s.repo.UpdateStatus(ctx, update.ID, update.Status, nil)

		scan, err := s.securityService.ScanContainer(ctx, update.HostID, update.TargetID)
		if err == nil && scan != nil {
			update.SecurityScoreBefore = &scan.Score
		}
	}

	// 2. Create backup
	if (opts.BackupVolumes || s.config.DefaultBackupVolumes) && s.backupService != nil {
		update.Status = models.UpdateStatusBackingUp
		s.repo.UpdateStatus(ctx, update.ID, update.Status, nil)

		backupResult, err := s.backupService.Create(ctx, BackupCreateOptions{
			HostID:      update.HostID,
			ContainerID: update.TargetID,
			Trigger:     "pre_update",
			CreatedBy:   opts.CreatedBy,
		})
		if err != nil {
			log.Error("Backup failed", "error", err)
			return s.failUpdate(ctx, update, result, "backup failed: "+err.Error())
		}
		update.BackupID = &backupResult.BackupID
		result.BackupID = &backupResult.BackupID
		log.Info("Backup created", "backup_id", backupResult.BackupID)
	}

	// 3. Pull new image
	update.Status = models.UpdateStatusPulling
	s.repo.UpdateStatus(ctx, update.ID, update.Status, nil)

	newImage := buildImageRef(containerInfo.Config.Image, update.ToVersion)
	if err := s.dockerClient.ImagePull(ctx, newImage, nil); err != nil {
		log.Error("Image pull failed", "error", err)
		return s.failUpdate(ctx, update, result, "image pull failed: "+err.Error())
	}
	log.Info("Image pulled", "image", newImage)

	// Get new digest
	newImageInfo, err := s.dockerClient.ImageInspect(ctx, newImage)
	if err == nil && len(newImageInfo.RepoDigests) > 0 {
		digest := ExtractDigestFromRepoDigests(newImageInfo.RepoDigests, newImage)
		update.ToDigest = &digest
	}

	// 4. Stop old container
	update.Status = models.UpdateStatusUpdating
	s.repo.UpdateStatus(ctx, update.ID, update.Status, nil)

	timeout := 30
	if err := s.dockerClient.ContainerStop(ctx, update.TargetID, &timeout); err != nil {
		log.Error("Container stop failed", "error", err)
		return s.failUpdate(ctx, update, result, "container stop failed: "+err.Error())
	}

	// 5. Rename old container
	oldName := containerInfo.Name
	backupName := oldName + "_backup_" + time.Now().Format("20060102150405")
	if err := s.dockerClient.ContainerRename(ctx, update.TargetID, backupName); err != nil {
		log.Error("Container rename failed", "error", err)
		// Try to restart the old container
		if startErr := s.dockerClient.ContainerStart(ctx, update.TargetID); startErr != nil {
			log.Error("rollback: failed to restart container after rename failure", "error", startErr)
		}
		return s.failUpdate(ctx, update, result, "container rename failed: "+err.Error())
	}

	// 6. Create new container with same config
	newConfig := containerInfo.Config
	newConfig.Image = newImage

	newContainerID, err := s.dockerClient.ContainerCreate(ctx, newConfig, containerInfo.HostConfig, oldName)
	if err != nil {
		log.Error("Container create failed", "error", err)
		// Rollback: rename old container back
		if renameErr := s.dockerClient.ContainerRename(ctx, update.TargetID, oldName); renameErr != nil {
			log.Error("rollback: failed to rename container back", "error", renameErr)
		}
		if startErr := s.dockerClient.ContainerStart(ctx, update.TargetID); startErr != nil {
			log.Error("rollback: failed to restart original container", "error", startErr)
		}
		return s.failUpdate(ctx, update, result, "container create failed: "+err.Error())
	}
	result.NewContainerID = newContainerID

	// 7. Start new container
	if err := s.dockerClient.ContainerStart(ctx, newContainerID); err != nil {
		log.Error("Container start failed", "error", err)
		// Rollback
		s.rollbackContainer(ctx, update, containerInfo, newContainerID, oldName)
		return s.failUpdate(ctx, update, result, "container start failed: "+err.Error())
	}

	// 8. Health check
	update.Status = models.UpdateStatusHealthCheck
	s.repo.UpdateStatus(ctx, update.ID, update.Status, nil)

	healthWait := s.config.DefaultHealthCheckWait
	if opts.HealthCheckWait > 0 {
		healthWait = opts.HealthCheckWait
	}

	maxRetries := s.config.DefaultMaxRetries
	if opts.MaxRetries > 0 {
		maxRetries = opts.MaxRetries
	}

	healthy := s.waitForHealthy(ctx, newContainerID, healthWait, maxRetries)
	passed := healthy
	update.HealthCheckPassed = &passed

	if !healthy {
		log.Warn("Health check failed, rolling back")
		s.rollbackContainer(ctx, update, containerInfo, newContainerID, oldName)
		rollbackReason := "health check failed"
		update.RollbackReason = &rollbackReason
		result.WasRolledBack = true
		result.RollbackReason = "health check failed"
		return s.failUpdate(ctx, update, result, "health check failed after update")
	}

	// 9. Post-update security scan
	if (opts.SecurityScan || s.config.DefaultSecurityScan) && s.securityService != nil {
		scan, err := s.securityService.ScanContainer(ctx, update.HostID, newContainerID)
		if err == nil && scan != nil {
			update.SecurityScoreAfter = &scan.Score
			if update.SecurityScoreBefore != nil {
				result.SecurityDelta = scan.Score - *update.SecurityScoreBefore
			}
		}
	}

	// 10. Cleanup old container
	if err := s.dockerClient.ContainerRemove(ctx, update.TargetID, true); err != nil {
		log.Warn("failed to remove old container during cleanup", "error", err)
	}

	// Complete
	completedAt := time.Now()
	update.CompletedAt = &completedAt
	update.Status = models.UpdateStatusCompleted
	durationMs := completedAt.Sub(startTime).Milliseconds()
	update.DurationMs = &durationMs

	if err := s.repo.Update(ctx, update); err != nil {
		log.Error("failed to persist final update status", "error", err)
	}

	result.Success = true
	result.HealthPassed = true
	result.Duration = completedAt.Sub(startTime)

	log.Info("Update completed successfully",
		"duration", result.Duration,
		"from", update.FromVersion,
		"to", update.ToVersion,
	)

	return result
}

// rollbackContainer rolls back to the previous container
func (s *Service) rollbackContainer(ctx context.Context, update *models.Update, originalInfo *dockertypes.ContainerJSON, newContainerID, originalName string) {
	log := s.logger.With("update_id", update.ID)

	// Stop and remove new container
	timeout := 10
	if err := s.dockerClient.ContainerStop(ctx, newContainerID, &timeout); err != nil {
		log.Error("rollback: failed to stop new container", "error", err)
	}
	if err := s.dockerClient.ContainerRemove(ctx, newContainerID, true); err != nil {
		log.Error("rollback: failed to remove new container", "error", err)
	}

	// Rename original back
	if err := s.dockerClient.ContainerRename(ctx, update.TargetID, originalName); err != nil {
		log.Error("rollback: failed to rename original container back", "error", err)
	}

	// Start original
	if err := s.dockerClient.ContainerStart(ctx, update.TargetID); err != nil {
		log.Error("Failed to restart original container", "error", err)
	}
}

// waitForHealthy waits for a container to become healthy
func (s *Service) waitForHealthy(ctx context.Context, containerID string, wait time.Duration, maxRetries int) bool {
	if maxRetries <= 0 {
		maxRetries = 1
	}
	ticker := time.NewTicker(wait / time.Duration(maxRetries))
	defer ticker.Stop()

	for i := 0; i < maxRetries; i++ {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			info, err := s.dockerClient.ContainerInspect(ctx, containerID)
			if err != nil {
				continue
			}

			// If no healthcheck defined, consider it healthy if running
			if info.State.Health == nil {
				if info.State.Running {
					return true
				}
				continue
			}

			// Check health status
			if info.State.Health.Status == "healthy" {
				return true
			}
		}
	}

	return false
}

// failUpdate marks an update as failed
func (s *Service) failUpdate(ctx context.Context, update *models.Update, result *models.UpdateResult, errMsg string) *models.UpdateResult {
	update.Status = models.UpdateStatusFailed
	update.ErrorMessage = &errMsg

	completedAt := time.Now()
	update.CompletedAt = &completedAt
	if update.StartedAt != nil {
		durationMs := completedAt.Sub(*update.StartedAt).Milliseconds()
		update.DurationMs = &durationMs
	}

	s.repo.Update(ctx, update)

	result.Success = false
	result.ErrorMessage = errMsg

	return result
}

// trackUpdate tracks a running update
func (s *Service) trackUpdate(updateID uuid.UUID, containerID string) {
	s.runningMu.Lock()
	defer s.runningMu.Unlock()

	s.runningUpdates[updateID] = &runningUpdate{
		UpdateID:    updateID,
		ContainerID: containerID,
		StartedAt:   time.Now(),
		Status:      models.UpdateStatusPending,
	}
}

// untrackUpdate removes a tracked update
func (s *Service) untrackUpdate(updateID uuid.UUID) {
	s.runningMu.Lock()
	defer s.runningMu.Unlock()

	delete(s.runningUpdates, updateID)
}

// ============================================================================
// Rollback Operations
// ============================================================================

// RollbackUpdate rolls back a completed update
func (s *Service) RollbackUpdate(ctx context.Context, opts *models.RollbackOptions) (*models.RollbackResult, error) {
	log := s.logger.With("update_id", opts.UpdateID)
	log.Info("Starting rollback")

	// Get the update
	update, err := s.repo.Get(ctx, opts.UpdateID)
	if err != nil {
		return nil, err
	}

	if update.Status != models.UpdateStatusCompleted {
		return nil, errors.New(errors.CodeInvalidInput, "can only rollback completed updates")
	}

	result := &models.RollbackResult{
		UpdateID:        opts.UpdateID,
		RestoredVersion: update.FromVersion,
	}

	// Restore backup if requested and available
	if opts.RestoreBackup && update.BackupID != nil && s.backupService != nil {
		_, err := s.backupService.Restore(ctx, BackupRestoreOptions{
			BackupID:    *update.BackupID,
			ContainerID: update.TargetID,
		})
		if err != nil {
			log.Error("Backup restore failed", "error", err)
			result.ErrorMessage = "backup restore failed: " + err.Error()
		} else {
			result.RestoredBackupID = update.BackupID
		}
	}

	// Pull old image
	oldImage := buildImageRef(update.Image, update.FromVersion)
	if err := s.dockerClient.ImagePull(ctx, oldImage, nil); err != nil {
		result.ErrorMessage = "failed to pull original image: " + err.Error()
		return result, nil
	}

	// Get current container info
	containerInfo, err := s.dockerClient.ContainerInspect(ctx, update.TargetID)
	if err != nil {
		result.ErrorMessage = "failed to inspect container: " + err.Error()
		return result, nil
	}

	// Stop current container
	timeout := 30
	s.dockerClient.ContainerStop(ctx, update.TargetID, &timeout)

	// Rename current
	backupName := containerInfo.Name + "_rollback_" + time.Now().Format("20060102150405")
	s.dockerClient.ContainerRename(ctx, update.TargetID, backupName)

	// Create container with old image
	newConfig := containerInfo.Config
	newConfig.Image = oldImage

	newID, err := s.dockerClient.ContainerCreate(ctx, newConfig, containerInfo.HostConfig, containerInfo.Name)
	if err != nil {
		// Revert
		s.dockerClient.ContainerRename(ctx, update.TargetID, containerInfo.Name)
		s.dockerClient.ContainerStart(ctx, update.TargetID)
		result.ErrorMessage = "failed to create rolled back container: " + err.Error()
		return result, nil
	}

	// Start new container
	if err := s.dockerClient.ContainerStart(ctx, newID); err != nil {
		s.dockerClient.ContainerRemove(ctx, newID, true)
		s.dockerClient.ContainerRename(ctx, update.TargetID, containerInfo.Name)
		s.dockerClient.ContainerStart(ctx, update.TargetID)
		result.ErrorMessage = "failed to start rolled back container: " + err.Error()
		return result, nil
	}

	// Cleanup
	s.dockerClient.ContainerRemove(ctx, update.TargetID, true)

	// Update record
	update.Status = models.UpdateStatusRolledBack
	update.RollbackReason = &opts.Reason
	s.repo.Update(ctx, update)

	result.Success = true
	log.Info("Rollback completed", "restored_version", result.RestoredVersion)

	return result, nil
}

// ============================================================================
// Policy Operations
// ============================================================================

// GetPolicy gets an update policy for a target
func (s *Service) GetPolicy(ctx context.Context, hostID uuid.UUID, targetType models.UpdateType, targetID string) (*models.UpdatePolicy, error) {
	return s.repo.GetPolicyByTarget(ctx, hostID, targetType, targetID)
}

// SetPolicy creates or updates an update policy
func (s *Service) SetPolicy(ctx context.Context, policy *models.UpdatePolicy) error {
	existing, _ := s.repo.GetPolicyByTarget(ctx, policy.HostID, policy.TargetType, policy.TargetID)
	if existing != nil {
		policy.ID = existing.ID
		return s.repo.UpdatePolicy(ctx, policy)
	}
	return s.repo.CreatePolicy(ctx, policy)
}

// DeletePolicy deletes an update policy
func (s *Service) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	return s.repo.DeletePolicy(ctx, id)
}

// ============================================================================
// Webhook Operations
// ============================================================================

// CreateWebhook creates a new update webhook
func (s *Service) CreateWebhook(ctx context.Context, hostID uuid.UUID, targetType models.UpdateType, targetID string) (*models.UpdateWebhook, error) {
	token, err := generateWebhookToken()
	if err != nil {
		return nil, err
	}

	webhook := &models.UpdateWebhook{
		ID:         uuid.New(),
		HostID:     hostID,
		TargetType: targetType,
		TargetID:   targetID,
		Token:      token,
		IsEnabled:  true,
		CreatedAt:  time.Now(),
	}

	if err := s.repo.CreateWebhook(ctx, webhook); err != nil {
		return nil, err
	}

	return webhook, nil
}

// TriggerWebhook triggers an update via webhook
func (s *Service) TriggerWebhook(ctx context.Context, token string) (*models.UpdateResult, error) {
	webhook, err := s.repo.GetWebhookByToken(ctx, token)
	if err != nil {
		return nil, errors.New(errors.CodeUnauthorized, "invalid webhook token")
	}

	if !webhook.IsEnabled {
		return nil, errors.New(errors.CodeForbidden, "webhook is disabled")
	}

	// Update last used
	s.repo.UpdateWebhookLastUsed(ctx, webhook.ID)

	// Trigger update
	return s.UpdateContainer(ctx, webhook.HostID, &models.UpdateOptions{
		ContainerID: webhook.TargetID,
	})
}

// ============================================================================
// Stats and History
// ============================================================================

// GetStats returns update statistics
func (s *Service) GetStats(ctx context.Context, hostID *uuid.UUID) (*models.UpdateStats, error) {
	return s.repo.GetStats(ctx, hostID)
}

// GetHistory returns update history for a target
func (s *Service) GetHistory(ctx context.Context, hostID uuid.UUID, targetID string, limit int) ([]*models.Update, error) {
	return s.repo.GetByTarget(ctx, hostID, targetID, limit)
}

// ListUpdates lists updates with filtering
func (s *Service) ListUpdates(ctx context.Context, opts models.UpdateListOptions) ([]*models.Update, int64, error) {
	return s.repo.List(ctx, opts)
}

// ListPolicies lists all update policies
func (s *Service) ListPolicies(ctx context.Context, hostID *uuid.UUID) ([]*models.UpdatePolicy, error) {
	return s.repo.ListPolicies(ctx, hostID)
}

// GetPolicyByID gets an update policy by ID
func (s *Service) GetPolicyByID(ctx context.Context, id uuid.UUID) (*models.UpdatePolicy, error) {
	return s.repo.GetPolicy(ctx, id)
}

// ListWebhooks lists all webhooks for a host
func (s *Service) ListWebhooks(ctx context.Context, hostID uuid.UUID) ([]*models.UpdateWebhook, error) {
	return s.repo.ListWebhooks(ctx, hostID)
}

// DeleteWebhook deletes a webhook
func (s *Service) DeleteWebhook(ctx context.Context, id uuid.UUID) error {
	return s.repo.DeleteWebhook(ctx, id)
}

// ============================================================================
// Helpers
// ============================================================================

// buildImageRef builds a full image reference with a specific tag
func buildImageRef(image, tag string) string {
	// Remove existing tag
	if idx := strings.LastIndex(image, ":"); idx != -1 {
		// Make sure it's not a port
		afterColon := image[idx+1:]
		if !strings.Contains(afterColon, "/") {
			image = image[:idx]
		}
	}

	// Remove existing digest
	if idx := strings.Index(image, "@"); idx != -1 {
		image = image[:idx]
	}

	return image + ":" + tag
}

// generateWebhookToken generates a secure random token
func generateWebhookToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// ExtractDigestFromRepoDigests extracts digest from Docker's RepoDigests
func ExtractDigestFromRepoDigests(repoDigests []string, image string) string {
	if len(repoDigests) == 0 {
		return ""
	}

	// Parse image to match
	ref, _ := ParseImageRef(image)
	if ref == nil {
		// Return first digest
		for _, rd := range repoDigests {
			if idx := strings.Index(rd, "@"); idx != -1 {
				return rd[idx+1:]
			}
		}
		return ""
	}

	// Try to match by repository
	for _, rd := range repoDigests {
		if strings.Contains(rd, ref.Repository) {
			if idx := strings.Index(rd, "@"); idx != -1 {
				return rd[idx+1:]
			}
		}
	}

	// Return first
	for _, rd := range repoDigests {
		if idx := strings.Index(rd, "@"); idx != -1 {
			return rd[idx+1:]
		}
	}

	return ""
}


