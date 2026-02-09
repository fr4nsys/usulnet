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

// ============================================================================
// Update Service Types (defined locally to avoid external dependencies)
// ============================================================================

// UpdateCheckServiceResult result of checking for updates
type UpdateCheckServiceResult struct {
	TotalChecked     int                       `json:"total_checked"`
	AvailableUpdates []*AvailableUpdateService `json:"available_updates"`
}

// AvailableUpdateService represents an available update from the service
type AvailableUpdateService struct {
	ContainerID    string    `json:"container_id"`
	ContainerName  string    `json:"container_name"`
	Image          string    `json:"image"`
	CurrentVersion string    `json:"current_version"`
	LatestVersion  string    `json:"latest_version"`
	UpdateType     string    `json:"update_type"` // major, minor, patch
	Changelog      string    `json:"changelog,omitempty"`
	CheckedAt      time.Time `json:"checked_at"`
}

// UpdateServiceOptions options for performing an update
type UpdateServiceOptions struct {
	ContainerID   string `json:"container_id"`
	TargetVersion string `json:"target_version,omitempty"`
	CreateBackup  bool   `json:"create_backup"`
	AutoRollback  bool   `json:"auto_rollback"`
}

// UpdateServiceResult result of performing an update
type UpdateServiceResult struct {
	UpdateID          uuid.UUID  `json:"update_id"`
	FromVersion       string     `json:"from_version"`
	ToVersion         string     `json:"to_version"`
	BackupID          *uuid.UUID `json:"backup_id,omitempty"`
	HealthCheckPassed bool       `json:"health_check_passed"`
}

// RollbackServiceOptions options for rollback
type RollbackServiceOptions struct {
	ContainerID string    `json:"container_id"`
	BackupID    uuid.UUID `json:"backup_id"`
	RestoreData bool      `json:"restore_data"`
}

// RollbackServiceResult result of a rollback
type RollbackServiceResult struct {
	Success       bool      `json:"success"`
	RestoredImage string    `json:"restored_image"`
	Error         string    `json:"error,omitempty"`
	CompletedAt   time.Time `json:"completed_at"`
}

// UpdateService interface for update operations (from Dept I)
type UpdateService interface {
	// CheckForUpdates checks all containers on a host for available updates
	CheckForUpdates(ctx context.Context, hostID uuid.UUID) (*UpdateCheckServiceResult, error)

	// CheckContainerForUpdate checks a specific container for updates
	CheckContainerForUpdate(ctx context.Context, hostID uuid.UUID, containerID string) (*AvailableUpdateService, error)

	// UpdateContainer performs a container update
	UpdateContainer(ctx context.Context, hostID uuid.UUID, opts *UpdateServiceOptions) (*UpdateServiceResult, error)

	// Rollback rolls back a container to previous version
	Rollback(ctx context.Context, opts *RollbackServiceOptions) (*RollbackServiceResult, error)
}

// ============================================================================
// Update Check Worker
// ============================================================================

// UpdateCheckWorker handles update checking jobs
type UpdateCheckWorker struct {
	BaseWorker
	updateService UpdateService
	logger        *logger.Logger
}

// NewUpdateCheckWorker creates a new update check worker
func NewUpdateCheckWorker(updateService UpdateService, log *logger.Logger) *UpdateCheckWorker {
	if log == nil {
		log = logger.Nop()
	}

	return &UpdateCheckWorker{
		BaseWorker:    NewBaseWorker(models.JobTypeUpdateCheck),
		updateService: updateService,
		logger:        log.Named("update-check-worker"),
	}
}

// Execute performs the update check job
func (w *UpdateCheckWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	log := w.logger.With("job_id", job.ID)

	// Parse payload
	var payload models.UpdateCheckPayload
	if err := job.GetPayload(&payload); err != nil {
		return nil, errors.Wrap(err, errors.CodeValidation, "failed to parse payload")
	}

	// Get host ID
	hostID := job.HostID
	if hostID == nil {
		return nil, errors.New(errors.CodeValidation, "host_id is required for update check")
	}

	log.Info("starting update check",
		"host_id", hostID,
		"container_id", payload.ContainerID,
		"check_all", payload.CheckAll,
	)

	result := &UpdateCheckJobResult{
		HostID:    *hostID,
		StartedAt: time.Now(),
		Updates:   make([]*UpdateInfo, 0),
	}

	if payload.CheckAll {
		// Check all containers
		if err := w.checkAllContainers(ctx, job, *hostID, result); err != nil {
			return result, err
		}
	} else if payload.ContainerID != "" {
		// Check specific container
		if err := w.checkContainer(ctx, job, *hostID, payload.ContainerID, result); err != nil {
			return result, err
		}
	} else {
		return nil, errors.New(errors.CodeValidation, "either container_id or check_all must be specified")
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)

	log.Info("update check completed",
		"checked", result.TotalChecked,
		"updates_available", result.UpdatesAvailable,
		"duration", result.Duration,
	)

	return result, nil
}

func (w *UpdateCheckWorker) checkAllContainers(
	ctx context.Context,
	job *models.Job,
	hostID uuid.UUID,
	result *UpdateCheckJobResult,
) error {
	// Update progress
	job.Progress = 10
	msg := "Checking for updates..."
	job.ProgressMessage = &msg

	// Call update service
	checkResult, err := w.updateService.CheckForUpdates(ctx, hostID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to check for updates")
	}

	result.TotalChecked = checkResult.TotalChecked

	// Convert available updates
	for _, update := range checkResult.AvailableUpdates {
		updateInfo := &UpdateInfo{
			ContainerID:    update.ContainerID,
			ContainerName:  update.ContainerName,
			Image:          update.Image,
			CurrentVersion: update.CurrentVersion,
			LatestVersion:  update.LatestVersion,
			UpdateType:     update.UpdateType,
			HasChangelog:   update.Changelog != "",
			Changelog:      update.Changelog,
			LastCheckedAt:  update.CheckedAt,
		}
		result.Updates = append(result.Updates, updateInfo)
		result.UpdatesAvailable++
	}

	return nil
}

func (w *UpdateCheckWorker) checkContainer(
	ctx context.Context,
	job *models.Job,
	hostID uuid.UUID,
	containerID string,
	result *UpdateCheckJobResult,
) error {
	result.TotalChecked = 1

	// Update progress
	job.Progress = 30
	msg := "Checking container for updates..."
	job.ProgressMessage = &msg

	// Check specific container
	update, err := w.updateService.CheckContainerForUpdate(ctx, hostID, containerID)
	if err != nil {
		// Not finding an update is not an error
		if errors.IsNotFoundError(err) {
			return nil
		}
		return errors.Wrap(err, errors.CodeInternal, "failed to check container for updates")
	}

	if update != nil {
		updateInfo := &UpdateInfo{
			ContainerID:    update.ContainerID,
			ContainerName:  update.ContainerName,
			Image:          update.Image,
			CurrentVersion: update.CurrentVersion,
			LatestVersion:  update.LatestVersion,
			UpdateType:     update.UpdateType,
			HasChangelog:   update.Changelog != "",
			Changelog:      update.Changelog,
			LastCheckedAt:  update.CheckedAt,
		}
		result.Updates = append(result.Updates, updateInfo)
		result.UpdatesAvailable++
	}

	return nil
}

// UpdateCheckJobResult holds the result of an update check job
type UpdateCheckJobResult struct {
	HostID           uuid.UUID     `json:"host_id"`
	StartedAt        time.Time     `json:"started_at"`
	CompletedAt      time.Time     `json:"completed_at"`
	Duration         time.Duration `json:"duration"`
	TotalChecked     int           `json:"total_checked"`
	UpdatesAvailable int           `json:"updates_available"`
	Updates          []*UpdateInfo `json:"updates"`
}

// UpdateInfo holds information about an available update
type UpdateInfo struct {
	ContainerID    string    `json:"container_id"`
	ContainerName  string    `json:"container_name"`
	Image          string    `json:"image"`
	CurrentVersion string    `json:"current_version"`
	LatestVersion  string    `json:"latest_version"`
	UpdateType     string    `json:"update_type"` // major, minor, patch
	HasChangelog   bool      `json:"has_changelog"`
	Changelog      string    `json:"changelog,omitempty"`
	LastCheckedAt  time.Time `json:"last_checked_at"`
}

// ============================================================================
// Container Update Worker
// ============================================================================

// ContainerUpdateWorker handles container update jobs
type ContainerUpdateWorker struct {
	BaseWorker
	updateService UpdateService
	logger        *logger.Logger
}

// NewContainerUpdateWorker creates a new container update worker
func NewContainerUpdateWorker(updateService UpdateService, log *logger.Logger) *ContainerUpdateWorker {
	if log == nil {
		log = logger.Nop()
	}

	return &ContainerUpdateWorker{
		BaseWorker:    NewBaseWorker(models.JobTypeContainerUpdate),
		updateService: updateService,
		logger:        log.Named("container-update-worker"),
	}
}

// Execute performs the container update job
func (w *ContainerUpdateWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	log := w.logger.With("job_id", job.ID)

	// Parse payload
	var payload models.ContainerUpdatePayload
	if err := job.GetPayload(&payload); err != nil {
		return nil, errors.Wrap(err, errors.CodeValidation, "failed to parse payload")
	}

	if payload.ContainerID == "" {
		return nil, errors.New(errors.CodeValidation, "container_id is required")
	}

	// Get host ID
	hostID := job.HostID
	if hostID == nil {
		return nil, errors.New(errors.CodeValidation, "host_id is required for container update")
	}

	log.Info("starting container update",
		"host_id", hostID,
		"container_id", payload.ContainerID,
		"target_version", payload.TargetVersion,
		"create_backup", payload.CreateBackup,
		"auto_rollback", payload.AutoRollback,
	)

	result := &ContainerUpdateJobResult{
		HostID:      *hostID,
		ContainerID: payload.ContainerID,
		StartedAt:   time.Now(),
	}

	// Update progress
	job.Progress = 10
	msg := "Preparing update..."
	job.ProgressMessage = &msg

	// Create update options
	opts := &UpdateServiceOptions{
		ContainerID:   payload.ContainerID,
		TargetVersion: payload.TargetVersion,
		CreateBackup:  payload.CreateBackup,
		AutoRollback:  payload.AutoRollback,
	}

	// Update progress
	job.Progress = 30
	msg = "Pulling new image..."
	job.ProgressMessage = &msg

	// Perform update
	updateResult, err := w.updateService.UpdateContainer(ctx, *hostID, opts)

	// Update progress
	job.Progress = 80
	msg = "Finalizing update..."
	job.ProgressMessage = &msg

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)

		log.Error("container update failed",
			"container_id", payload.ContainerID,
			"error", err,
		)

		// Don't return error - let the result indicate failure
		return result, nil
	}

	result.Success = true
	result.UpdateID = updateResult.UpdateID
	result.FromVersion = updateResult.FromVersion
	result.ToVersion = updateResult.ToVersion
	result.BackupID = updateResult.BackupID
	result.HealthCheckPassed = updateResult.HealthCheckPassed
	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)

	log.Info("container update completed",
		"container_id", payload.ContainerID,
		"from_version", result.FromVersion,
		"to_version", result.ToVersion,
		"duration", result.Duration,
	)

	return result, nil
}

// ContainerUpdateJobResult holds the result of a container update job
type ContainerUpdateJobResult struct {
	HostID            uuid.UUID     `json:"host_id"`
	ContainerID       string        `json:"container_id"`
	StartedAt         time.Time     `json:"started_at"`
	CompletedAt       time.Time     `json:"completed_at"`
	Duration          time.Duration `json:"duration"`
	Success           bool          `json:"success"`
	Error             string        `json:"error,omitempty"`
	UpdateID          uuid.UUID     `json:"update_id,omitempty"`
	FromVersion       string        `json:"from_version,omitempty"`
	ToVersion         string        `json:"to_version,omitempty"`
	BackupID          *uuid.UUID    `json:"backup_id,omitempty"`
	HealthCheckPassed bool          `json:"health_check_passed"`
	RolledBack        bool          `json:"rolled_back"`
}
