// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package backup

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// RetentionManager handles backup retention policies.
type RetentionManager struct {
	storage Storage
	repo    Repository
	config  Config
	logger  *logger.Logger
}

// RetentionPolicy defines backup retention rules.
type RetentionPolicy struct {
	// MaxBackups is the maximum number of backups to keep (0 = unlimited)
	MaxBackups int

	// MaxAgeDays is the maximum age of backups in days (0 = unlimited)
	MaxAgeDays int

	// MinBackups is the minimum number of backups to always keep
	MinBackups int

	// KeepDaily is the number of daily backups to keep
	KeepDaily int

	// KeepWeekly is the number of weekly backups to keep
	KeepWeekly int

	// KeepMonthly is the number of monthly backups to keep
	KeepMonthly int
}

// DefaultRetentionPolicy returns the default retention policy.
func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		MaxBackups:  50,
		MaxAgeDays:  90,
		MinBackups:  3,
		KeepDaily:   7,
		KeepWeekly:  4,
		KeepMonthly: 6,
	}
}

// NewRetentionManager creates a new retention manager.
func NewRetentionManager(
	storage Storage,
	repo Repository,
	config Config,
	log *logger.Logger,
) *RetentionManager {
	return &RetentionManager{
		storage: storage,
		repo:    repo,
		config:  config,
		logger:  log.Named("backup.retention"),
	}
}

// CleanupResult contains the results of a cleanup operation.
type CleanupResult struct {
	DeletedCount    int
	DeletedSize     int64
	FailedCount     int
	SkippedCount    int
	ProcessedCount  int
	Duration        time.Duration
	DeletedBackups  []uuid.UUID
	FailedBackups   []uuid.UUID
	Errors          []error
}

// Cleanup removes expired backups based on retention policy.
func (rm *RetentionManager) Cleanup(ctx context.Context, policy *RetentionPolicy) (*CleanupResult, error) {
	start := time.Now()

	if policy == nil {
		defaultPolicy := DefaultRetentionPolicy()
		policy = &defaultPolicy
	}

	result := &CleanupResult{}

	rm.logger.Info("starting backup cleanup",
		"max_backups", policy.MaxBackups,
		"max_age_days", policy.MaxAgeDays,
	)

	// Get expired backups from database
	expiredIDs, err := rm.repo.DeleteExpired(ctx)
	if err != nil {
		rm.logger.Error("failed to get expired backups", "error", err)
	}

	// Process expired backups
	for _, id := range expiredIDs {
		result.ProcessedCount++

		backup, err := rm.repo.Get(ctx, id)
		if err != nil {
			result.FailedCount++
			result.FailedBackups = append(result.FailedBackups, id)
			continue
		}

		// Delete from storage
		if err := rm.storage.Delete(ctx, backup.Path); err != nil {
			rm.logger.Warn("failed to delete backup file",
				"backup_id", id,
				"path", backup.Path,
				"error", err,
			)
			result.FailedCount++
			result.FailedBackups = append(result.FailedBackups, id)
			result.Errors = append(result.Errors, err)
			continue
		}

		// Delete from database
		if err := rm.repo.Delete(ctx, id); err != nil {
			rm.logger.Warn("failed to delete backup record",
				"backup_id", id,
				"error", err,
			)
			result.FailedCount++
			result.Errors = append(result.Errors, err)
			continue
		}

		result.DeletedCount++
		result.DeletedSize += backup.SizeBytes
		result.DeletedBackups = append(result.DeletedBackups, id)
	}

	// Apply advanced retention policy per target
	if err := rm.applyRetentionPolicy(ctx, policy, result); err != nil {
		rm.logger.Error("failed to apply retention policy", "error", err)
	}

	result.Duration = time.Since(start)

	rm.logger.Info("backup cleanup completed",
		"deleted", result.DeletedCount,
		"failed", result.FailedCount,
		"size_freed", result.DeletedSize,
		"duration", result.Duration,
	)

	return result, nil
}

// applyRetentionPolicy applies advanced retention rules (daily/weekly/monthly).
func (rm *RetentionManager) applyRetentionPolicy(ctx context.Context, policy *RetentionPolicy, result *CleanupResult) error {
	// Get all completed backups grouped by target
	opts := models.BackupListOptions{
		Status: func() *models.BackupStatus { s := models.BackupStatusCompleted; return &s }(),
		Limit:  10000,
	}

	backups, _, err := rm.repo.List(ctx, opts)
	if err != nil {
		return err
	}

	// Group by target
	byTarget := make(map[string][]*models.Backup)
	for _, b := range backups {
		key := b.HostID.String() + "/" + b.TargetID
		byTarget[key] = append(byTarget[key], b)
	}

	// Apply policy to each target
	for target, targetBackups := range byTarget {
		toDelete := rm.selectBackupsToDelete(targetBackups, policy)

		for _, backup := range toDelete {
			result.ProcessedCount++

			// Delete from storage
			if err := rm.storage.Delete(ctx, backup.Path); err != nil {
				rm.logger.Warn("failed to delete backup file",
					"backup_id", backup.ID,
					"target", target,
					"error", err,
				)
				result.FailedCount++
				result.Errors = append(result.Errors, err)
				continue
			}

			// Delete from database
			if err := rm.repo.Delete(ctx, backup.ID); err != nil {
				rm.logger.Warn("failed to delete backup record",
					"backup_id", backup.ID,
					"error", err,
				)
				result.FailedCount++
				result.Errors = append(result.Errors, err)
				continue
			}

			result.DeletedCount++
			result.DeletedSize += backup.SizeBytes
			result.DeletedBackups = append(result.DeletedBackups, backup.ID)
		}
	}

	return nil
}

// selectBackupsToDelete selects which backups to delete based on policy.
func (rm *RetentionManager) selectBackupsToDelete(backups []*models.Backup, policy *RetentionPolicy) []*models.Backup {
	if len(backups) == 0 {
		return nil
	}

	// Sort by creation time (newest first)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].CreatedAt.After(backups[j].CreatedAt)
	})

	// Track which backups to keep
	keep := make(map[uuid.UUID]bool)
	now := time.Now()

	// Always keep minimum backups (newest ones)
	for i := 0; i < min(policy.MinBackups, len(backups)); i++ {
		keep[backups[i].ID] = true
	}

	// Keep daily backups
	if policy.KeepDaily > 0 {
		dailyKept := 0
		lastDay := ""
		for _, b := range backups {
			if dailyKept >= policy.KeepDaily {
				break
			}
			day := b.CreatedAt.Format("2006-01-02")
			if day != lastDay {
				keep[b.ID] = true
				dailyKept++
				lastDay = day
			}
		}
	}

	// Keep weekly backups (Sunday of each week)
	if policy.KeepWeekly > 0 {
		weeklyKept := 0
		lastWeek := ""
		for _, b := range backups {
			if weeklyKept >= policy.KeepWeekly {
				break
			}
			year, week := b.CreatedAt.ISOWeek()
			weekKey := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, (week-1)*7).Format("2006-W02")
			if weekKey != lastWeek {
				keep[b.ID] = true
				weeklyKept++
				lastWeek = weekKey
			}
		}
	}

	// Keep monthly backups (1st of each month)
	if policy.KeepMonthly > 0 {
		monthlyKept := 0
		lastMonth := ""
		for _, b := range backups {
			if monthlyKept >= policy.KeepMonthly {
				break
			}
			month := b.CreatedAt.Format("2006-01")
			if month != lastMonth {
				keep[b.ID] = true
				monthlyKept++
				lastMonth = month
			}
		}
	}

	// Select backups to delete
	var toDelete []*models.Backup
	for _, b := range backups {
		if keep[b.ID] {
			continue
		}

		// Check max age
		if policy.MaxAgeDays > 0 {
			age := now.Sub(b.CreatedAt)
			if age > time.Duration(policy.MaxAgeDays)*24*time.Hour {
				toDelete = append(toDelete, b)
				continue
			}
		}

		// Check max count
		if policy.MaxBackups > 0 && len(backups)-len(toDelete) > policy.MaxBackups {
			toDelete = append(toDelete, b)
		}
	}

	return toDelete
}

// GetStorageUsage returns storage usage statistics.
func (rm *RetentionManager) GetStorageUsage(ctx context.Context) (*models.BackupStorage, error) {
	stats, err := rm.storage.Stats(ctx)
	if err != nil {
		return nil, err
	}

	// Get backup count from repository
	dbStats, err := rm.repo.GetStats(ctx, nil)
	if err != nil {
		return nil, err
	}

	return &models.BackupStorage{
		Type:        rm.storage.Type(),
		TotalSize:   stats.TotalSpace,
		UsedSize:    stats.UsedSpace,
		BackupCount: dbStats.TotalBackups,
	}, nil
}

// CleanupOrphaned removes backup files that exist in storage but not in database.
func (rm *RetentionManager) CleanupOrphaned(ctx context.Context) (*CleanupResult, error) {
	start := time.Now()
	result := &CleanupResult{}

	rm.logger.Info("starting orphaned backup cleanup")

	// Get all files from storage
	entries, err := rm.storage.List(ctx, "")
	if err != nil {
		return nil, err
	}

	// Get all backup paths from database
	opts := models.BackupListOptions{Limit: 100000}
	backups, _, err := rm.repo.List(ctx, opts)
	if err != nil {
		return nil, err
	}

	dbPaths := make(map[string]bool)
	for _, b := range backups {
		dbPaths[b.Path] = true
	}

	// Find orphaned files
	for _, entry := range entries {
		result.ProcessedCount++

		if dbPaths[entry.Path] {
			continue
		}

		// This file exists in storage but not in database - orphaned
		rm.logger.Info("found orphaned backup file",
			"path", entry.Path,
			"size", entry.Size,
		)

		if err := rm.storage.Delete(ctx, entry.Path); err != nil {
			rm.logger.Warn("failed to delete orphaned file",
				"path", entry.Path,
				"error", err,
			)
			result.FailedCount++
			result.Errors = append(result.Errors, err)
			continue
		}

		result.DeletedCount++
		result.DeletedSize += entry.Size
	}

	result.Duration = time.Since(start)

	rm.logger.Info("orphaned backup cleanup completed",
		"deleted", result.DeletedCount,
		"failed", result.FailedCount,
		"size_freed", result.DeletedSize,
		"duration", result.Duration,
	)

	return result, nil
}

// PruneTarget removes old backups for a specific target, keeping only the specified count.
func (rm *RetentionManager) PruneTarget(ctx context.Context, hostID uuid.UUID, targetID string, keepCount int) (*CleanupResult, error) {
	start := time.Now()
	result := &CleanupResult{}

	rm.logger.Info("pruning backups for target",
		"host_id", hostID,
		"target_id", targetID,
		"keep_count", keepCount,
	)

	// Get backups for target
	backups, err := rm.repo.GetByHostAndTarget(ctx, hostID, targetID)
	if err != nil {
		return nil, err
	}

	// Sort by creation time (newest first)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].CreatedAt.After(backups[j].CreatedAt)
	})

	// Delete old ones
	for i := keepCount; i < len(backups); i++ {
		backup := backups[i]
		result.ProcessedCount++

		// Skip incomplete backups
		if backup.Status != models.BackupStatusCompleted {
			result.SkippedCount++
			continue
		}

		// Delete from storage
		if err := rm.storage.Delete(ctx, backup.Path); err != nil {
			rm.logger.Warn("failed to delete backup file",
				"backup_id", backup.ID,
				"error", err,
			)
			result.FailedCount++
			result.Errors = append(result.Errors, err)
			continue
		}

		// Delete from database
		if err := rm.repo.Delete(ctx, backup.ID); err != nil {
			rm.logger.Warn("failed to delete backup record",
				"backup_id", backup.ID,
				"error", err,
			)
			result.FailedCount++
			result.Errors = append(result.Errors, err)
			continue
		}

		result.DeletedCount++
		result.DeletedSize += backup.SizeBytes
		result.DeletedBackups = append(result.DeletedBackups, backup.ID)
	}

	result.Duration = time.Since(start)

	rm.logger.Info("target pruning completed",
		"host_id", hostID,
		"target_id", targetID,
		"deleted", result.DeletedCount,
		"duration", result.Duration,
	)

	return result, nil
}

// min returns the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
