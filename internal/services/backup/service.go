// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package backup

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/models"
	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Service provides backup and restore operations.
type Service struct {
	creator   *Creator
	restorer  *Restorer
	retention *RetentionManager
	storage   Storage
	repo      Repository
	config    Config
	logger    *logger.Logger

	// Event handling
	eventHandlers []EventHandler
	eventMu       sync.RWMutex

	// Background workers
	stopCh  chan struct{}
	stopped bool
	wg      sync.WaitGroup

	// Concurrency control
	semaphore chan struct{}

	// License enforcement
	limitProvider license.LimitProvider
}

// SetLimitProvider sets the license limit provider for enforcing MaxBackupDestinations.
func (s *Service) SetLimitProvider(lp license.LimitProvider) {
	s.limitProvider = lp
}

// ServiceOption configures the backup Service.
type ServiceOption func(*serviceOptions)

type serviceOptions struct {
	stackProvider StackProvider
}

// WithStackProviderOption sets the stack provider for the backup service.
func WithStackProviderOption(sp StackProvider) ServiceOption {
	return func(o *serviceOptions) {
		o.stackProvider = sp
	}
}

// NewService creates a new backup service.
func NewService(
	storage Storage,
	repo Repository,
	volumeProvider VolumeProvider,
	containerProvider ContainerProvider,
	config Config,
	log *logger.Logger,
	opts ...ServiceOption,
) (*Service, error) {
	if log == nil {
		log = logger.Nop()
	}

	// Apply options
	options := &serviceOptions{}
	for _, opt := range opts {
		opt(options)
	}

	// Build creator options
	var creatorOpts []CreatorOption
	if options.stackProvider != nil {
		creatorOpts = append(creatorOpts, WithStackProvider(options.stackProvider))
	}

	// Create creator
	creator, err := NewCreator(storage, repo, volumeProvider, containerProvider, config, log, creatorOpts...)
	if err != nil {
		return nil, err
	}

	// Create restorer
	restorer, err := NewRestorer(storage, repo, volumeProvider, containerProvider, config, log)
	if err != nil {
		return nil, err
	}

	// Create retention manager
	retention := NewRetentionManager(storage, repo, config, log)

	// Create semaphore for concurrency control
	maxConcurrent := config.MaxConcurrentBackups
	if maxConcurrent <= 0 {
		maxConcurrent = 3
	}

	return &Service{
		creator:   creator,
		restorer:  restorer,
		retention: retention,
		storage:   storage,
		repo:      repo,
		config:    config,
		logger:    log.Named("backup"),
		stopCh:    make(chan struct{}),
		semaphore: make(chan struct{}, maxConcurrent),
	}, nil
}

// ============================================================================
// Lifecycle
// ============================================================================

// Start starts the backup service and background workers.
func (s *Service) Start(ctx context.Context) error {
	s.logger.Info("starting backup service",
		"storage_type", s.storage.Type(),
		"cleanup_interval", s.config.CleanupInterval,
	)

	// Start cleanup worker
	if s.config.CleanupInterval > 0 {
		s.wg.Add(1)
		go s.cleanupWorker(ctx)
	}

	// Start schedule worker
	s.wg.Add(1)
	go s.scheduleWorker(ctx)

	return nil
}

// Stop stops the backup service.
func (s *Service) Stop() error {
	if s.stopped {
		return nil
	}

	s.stopped = true
	close(s.stopCh)

	// Wait for workers to finish
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		s.logger.Warn("timeout waiting for backup workers to stop")
	}

	s.logger.Info("backup service stopped")
	return nil
}

// ============================================================================
// Backup Operations
// ============================================================================

// Create creates a new backup.
func (s *Service) Create(ctx context.Context, opts CreateOptions) (*CreateResult, error) {
	// Acquire semaphore
	select {
	case s.semaphore <- struct{}{}:
		defer func() { <-s.semaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Emit event
	s.emitEvent(Event{
		Type:      EventBackupStarted,
		HostID:    opts.HostID,
		TargetID:  opts.TargetID,
		Timestamp: time.Now(),
	})

	result, err := s.creator.Create(ctx, opts)

	if err != nil {
		s.emitEvent(Event{
			Type:      EventBackupFailed,
			HostID:    opts.HostID,
			TargetID:  opts.TargetID,
			Status:    models.BackupStatusFailed,
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
		return nil, err
	}

	// FIX: BackupID is *uuid.UUID, need to take address of result.Backup.ID
	backupID := result.Backup.ID
	s.emitEvent(Event{
		Type:      EventBackupCompleted,
		BackupID:  &backupID,
		HostID:    opts.HostID,
		TargetID:  opts.TargetID,
		Status:    models.BackupStatusCompleted,
		Timestamp: time.Now(),
	})

	return result, nil
}

// Restore restores a backup.
func (s *Service) Restore(ctx context.Context, opts RestoreOptions) (*RestoreResult, error) {
	// Acquire semaphore
	select {
	case s.semaphore <- struct{}{}:
		defer func() { <-s.semaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Get backup for event
	backup, _ := s.repo.Get(ctx, opts.BackupID)

	// FIX: BackupID is *uuid.UUID, need to take address
	backupID := opts.BackupID
	s.emitEvent(Event{
		Type:      EventRestoreStarted,
		BackupID:  &backupID,
		HostID:    backup.HostID,
		TargetID:  backup.TargetID,
		Timestamp: time.Now(),
	})

	result, err := s.restorer.Restore(ctx, opts)

	if err != nil {
		s.emitEvent(Event{
			Type:      EventRestoreFailed,
			BackupID:  &backupID,
			HostID:    backup.HostID,
			TargetID:  backup.TargetID,
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
		return nil, err
	}

	s.emitEvent(Event{
		Type:      EventRestoreCompleted,
		BackupID:  &backupID,
		HostID:    backup.HostID,
		TargetID:  result.TargetID,
		Timestamp: time.Now(),
	})

	return result, nil
}

// Verify verifies a backup's integrity.
func (s *Service) Verify(ctx context.Context, backupID uuid.UUID, opts VerifyOptions) (*models.BackupVerificationResult, error) {
	return s.restorer.Verify(ctx, backupID, opts)
}

// ListContents lists the contents of a backup.
func (s *Service) ListContents(ctx context.Context, backupID uuid.UUID) ([]ArchiveEntry, error) {
	return s.restorer.ListContents(ctx, backupID)
}

// ============================================================================
// CRUD Operations
// ============================================================================

// Get retrieves a backup by ID.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*models.Backup, error) {
	return s.repo.Get(ctx, id)
}

// List retrieves backups with filtering.
func (s *Service) List(ctx context.Context, opts models.BackupListOptions) ([]*models.Backup, int64, error) {
	return s.repo.List(ctx, opts)
}

// ListByTarget retrieves backups for a specific target.
func (s *Service) ListByTarget(ctx context.Context, hostID uuid.UUID, targetID string) ([]*models.Backup, error) {
	return s.repo.GetByHostAndTarget(ctx, hostID, targetID)
}

// Delete deletes a backup.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	backup, err := s.repo.Get(ctx, id)
	if err != nil {
		return err
	}

	// Delete from storage
	if err := s.storage.Delete(ctx, backup.Path); err != nil {
		s.logger.Warn("failed to delete backup file",
			"backup_id", id,
			"path", backup.Path,
			"error", err,
		)
	}

	// Delete from database
	return s.repo.Delete(ctx, id)
}

// GetStats retrieves backup statistics.
func (s *Service) GetStats(ctx context.Context, hostID *uuid.UUID) (*models.BackupStats, error) {
	return s.repo.GetStats(ctx, hostID)
}

// GetStorageInfo retrieves storage information.
func (s *Service) GetStorageInfo(ctx context.Context) (*models.BackupStorage, error) {
	return s.retention.GetStorageUsage(ctx)
}

// ============================================================================
// Retention Operations
// ============================================================================

// Cleanup runs backup cleanup based on retention policy.
func (s *Service) Cleanup(ctx context.Context, policy *RetentionPolicy) (*CleanupResult, error) {
	s.emitEvent(Event{
		Type:      EventCleanupStarted,
		Timestamp: time.Now(),
	})

	result, err := s.retention.Cleanup(ctx, policy)

	s.emitEvent(Event{
		Type:      EventCleanupCompleted,
		Timestamp: time.Now(),
	})

	return result, err
}

// CleanupOrphaned removes orphaned backup files.
func (s *Service) CleanupOrphaned(ctx context.Context) (*CleanupResult, error) {
	return s.retention.CleanupOrphaned(ctx)
}

// PruneTarget removes old backups for a specific target.
func (s *Service) PruneTarget(ctx context.Context, hostID uuid.UUID, targetID string, keepCount int) (*CleanupResult, error) {
	return s.retention.PruneTarget(ctx, hostID, targetID, keepCount)
}

// ============================================================================
// Schedule Operations
// ============================================================================

// CreateSchedule creates a new backup schedule.
func (s *Service) CreateSchedule(ctx context.Context, input models.CreateBackupScheduleInput, hostID uuid.UUID, createdBy *uuid.UUID) (*models.BackupSchedule, error) {
	// Enforce MaxBackupDestinations license limit (schedules count as destinations)
	if s.limitProvider != nil {
		limit := s.limitProvider.GetLimits().MaxBackupDestinations
		if limit > 0 {
			existing, err := s.repo.ListSchedules(ctx, nil) // nil = all hosts
			if err == nil && len(existing) >= limit {
				return nil, apperrors.NewWithStatus(apperrors.CodeLimitExceeded,
					fmt.Sprintf("backup schedule limit reached (%d/%d), upgrade your license for more", len(existing), limit), 402)
			}
		}
	}

	schedule := &models.BackupSchedule{
		ID:            uuid.New(),
		HostID:        hostID,
		Type:          input.Type,
		TargetID:      input.TargetID,
		Schedule:      input.Schedule,
		Compression:   input.Compression,
		Encrypted:     input.Encrypted,
		RetentionDays: input.RetentionDays,
		MaxBackups:    input.MaxBackups,
		IsEnabled:     input.IsEnabled,
		CreatedBy:     createdBy,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if schedule.Compression == "" {
		schedule.Compression = s.config.DefaultCompression
	}
	if schedule.RetentionDays == 0 {
		schedule.RetentionDays = s.config.DefaultRetentionDays
	}
	if schedule.MaxBackups == 0 {
		schedule.MaxBackups = 10
	}

	// Calculate next run time
	nextRun := calculateNextRun(schedule.Schedule)
	schedule.NextRunAt = nextRun

	if err := s.repo.CreateSchedule(ctx, schedule); err != nil {
		return nil, err
	}

	s.logger.Info("backup schedule created",
		"schedule_id", schedule.ID,
		"target", schedule.TargetID,
		"cron", schedule.Schedule,
	)

	return schedule, nil
}

// UpdateSchedule updates an existing backup schedule.
func (s *Service) UpdateSchedule(ctx context.Context, id uuid.UUID, input models.UpdateBackupScheduleInput) (*models.BackupSchedule, error) {
	schedule, err := s.repo.GetSchedule(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.Schedule != nil {
		schedule.Schedule = *input.Schedule
		schedule.NextRunAt = calculateNextRun(*input.Schedule)
	}
	if input.Compression != nil {
		schedule.Compression = *input.Compression
	}
	if input.Encrypted != nil {
		schedule.Encrypted = *input.Encrypted
	}
	if input.RetentionDays != nil {
		schedule.RetentionDays = *input.RetentionDays
	}
	if input.MaxBackups != nil {
		schedule.MaxBackups = *input.MaxBackups
	}
	if input.IsEnabled != nil {
		schedule.IsEnabled = *input.IsEnabled
	}

	schedule.UpdatedAt = time.Now()

	if err := s.repo.UpdateSchedule(ctx, schedule); err != nil {
		return nil, err
	}

	return schedule, nil
}

// GetSchedule retrieves a backup schedule.
func (s *Service) GetSchedule(ctx context.Context, id uuid.UUID) (*models.BackupSchedule, error) {
	return s.repo.GetSchedule(ctx, id)
}

// ListSchedules retrieves all backup schedules.
func (s *Service) ListSchedules(ctx context.Context, hostID *uuid.UUID) ([]*models.BackupSchedule, error) {
	return s.repo.ListSchedules(ctx, hostID)
}

// DeleteSchedule deletes a backup schedule.
func (s *Service) DeleteSchedule(ctx context.Context, id uuid.UUID) error {
	return s.repo.DeleteSchedule(ctx, id)
}

// RunSchedule runs a scheduled backup immediately.
func (s *Service) RunSchedule(ctx context.Context, scheduleID uuid.UUID) (*CreateResult, error) {
	schedule, err := s.repo.GetSchedule(ctx, scheduleID)
	if err != nil {
		return nil, err
	}

	// Create backup with schedule options
	opts := CreateOptions{
		HostID:      schedule.HostID,
		Type:        schedule.Type,
		TargetID:    schedule.TargetID,
		TargetName:  schedule.TargetName,
		Trigger:     models.BackupTriggerScheduled,
		Compression: schedule.Compression,
		Encrypt:     schedule.Encrypted,
	}

	if schedule.RetentionDays > 0 {
		opts.RetentionDays = &schedule.RetentionDays
	}

	result, err := s.Create(ctx, opts)

	// Update schedule status
	status := models.BackupStatusCompleted
	if err != nil {
		status = models.BackupStatusFailed
	}
	nextRun := calculateNextRun(schedule.Schedule)
	s.repo.UpdateScheduleLastRun(ctx, scheduleID, status, nextRun)

	// Prune old backups if max is set
	if schedule.MaxBackups > 0 && err == nil {
		s.PruneTarget(ctx, schedule.HostID, schedule.TargetID, schedule.MaxBackups)
	}

	return result, err
}

// ============================================================================
// Event Handling
// ============================================================================

// OnEvent registers an event handler.
func (s *Service) OnEvent(handler EventHandler) {
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	s.eventHandlers = append(s.eventHandlers, handler)
}

// emitEvent emits an event to all handlers.
func (s *Service) emitEvent(event Event) {
	s.eventMu.RLock()
	handlers := s.eventHandlers
	s.eventMu.RUnlock()

	for _, handler := range handlers {
		go handler(event)
	}
}

// ============================================================================
// Background Workers
// ============================================================================

func (s *Service) cleanupWorker(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			if _, err := s.Cleanup(ctx, nil); err != nil {
				s.logger.Error("cleanup failed", "error", err)
			}
		}
	}
}

func (s *Service) scheduleWorker(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.runDueSchedules(ctx)
		}
	}
}

func (s *Service) runDueSchedules(ctx context.Context) {
	schedules, err := s.repo.GetDueSchedules(ctx)
	if err != nil {
		s.logger.Error("failed to get due schedules", "error", err)
		return
	}

	for _, schedule := range schedules {
		if !schedule.IsEnabled {
			continue
		}

		s.logger.Info("running scheduled backup",
			"schedule_id", schedule.ID,
			"target", schedule.TargetID,
		)

		if _, err := s.RunSchedule(ctx, schedule.ID); err != nil {
			s.logger.Error("scheduled backup failed",
				"schedule_id", schedule.ID,
				"error", err,
			)
		}
	}
}

// calculateNextRun calculates the next run time for a cron expression.
func calculateNextRun(cronExpr string) *time.Time {
	// This is a simplified implementation
	// In production, use robfig/cron to parse the expression
	// For now, just return 1 hour from now as a placeholder
	next := time.Now().Add(1 * time.Hour)
	return &next
}

// ============================================================================
// Download Support
// ============================================================================

// Download provides a reader for downloading a backup.
func (s *Service) Download(ctx context.Context, backupID uuid.UUID) (*DownloadInfo, error) {
	backup, err := s.repo.Get(ctx, backupID)
	if err != nil {
		return nil, err
	}

	reader, err := s.storage.Read(ctx, backup.Path)
	if err != nil {
		return nil, err
	}

	return &DownloadInfo{
		Reader:      reader,
		Filename:    backup.Filename,
		Size:        backup.SizeBytes,
		ContentType: "application/octet-stream",
	}, nil
}

// DownloadInfo contains information for downloading a backup.
type DownloadInfo struct {
	Reader      ReadCloserSize
	Filename    string
	Size        int64
	ContentType string
}

// ReadCloserSize combines io.ReadCloser with size information.
type ReadCloserSize interface {
	Read(p []byte) (n int, err error)
	Close() error
}
