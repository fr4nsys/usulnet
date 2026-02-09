// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package scheduler

import (
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
)

// Dependencies holds all service dependencies for workers
type Dependencies struct {
	SecurityService     workers.SecurityService
	DockerClient        workers.DockerClientForScan
	BackupService       workers.BackupService
	UpdateService       workers.UpdateService
	CleanupService      workers.CleanupService
	JobCleanupService   workers.JobCleanupService
	MetricsService      workers.MetricsService
	InventoryService    workers.InventoryService
	NotificationService workers.NotificationService
	Logger              *logger.Logger
}

// RegisterDefaultWorkers registers all default workers with the registry
func RegisterDefaultWorkers(registry *workers.WorkerRegistry, deps *Dependencies) {
	log := deps.Logger
	if log == nil {
		log = logger.Nop()
	}

	// Security scan worker
	if deps.SecurityService != nil && deps.DockerClient != nil {
		registry.Register(workers.NewSecurityScanWorker(deps.SecurityService, deps.DockerClient, log))
	}

	// Backup workers
	if deps.BackupService != nil {
		registry.Register(workers.NewBackupWorker(deps.BackupService, log))
		registry.Register(workers.NewBackupRestoreWorker(deps.BackupService, log))
	}

	// Update workers
	if deps.UpdateService != nil {
		registry.Register(workers.NewUpdateCheckWorker(deps.UpdateService, log))
		registry.Register(workers.NewContainerUpdateWorker(deps.UpdateService, log))
	}

	// Cleanup workers
	if deps.CleanupService != nil || deps.JobCleanupService != nil {
		registry.Register(workers.NewCleanupWorker(deps.CleanupService, deps.JobCleanupService, log))
	}

	// Prune workers (specialized cleanup)
	if deps.CleanupService != nil {
		registry.Register(workers.NewImagePruneWorker(deps.CleanupService, log))
		registry.Register(workers.NewVolumePruneWorker(deps.CleanupService, log))
		registry.Register(workers.NewNetworkPruneWorker(deps.CleanupService, log))
	}

	// Metrics workers
	if deps.MetricsService != nil {
		registry.Register(workers.NewMetricsCollectionWorker(deps.MetricsService, log))
	}

	// Inventory workers
	if deps.InventoryService != nil {
		registry.Register(workers.NewHostInventoryWorker(deps.InventoryService, log))
	}

	// Notification workers
	if deps.NotificationService != nil {
		registry.Register(workers.NewNotificationWorker(deps.NotificationService, log))
		registry.Register(workers.NewAlertWorker(deps.NotificationService, log))
	}
}
