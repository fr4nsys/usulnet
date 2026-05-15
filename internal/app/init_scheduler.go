// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"

	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/scheduler"
	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
)

// initScheduler initializes the job queue + scheduler with all worker
// adapters and registers the default retention + automatic database backup
// scheduled jobs. The metrics service adapter is wired by initWeb once the
// metrics service is constructed; that field is left nil here.
// Requires ic.securityService, ic.hostService, ic.updateService,
// ic.imageService, ic.volumeService, ic.networkService, ic.containerService,
// ic.notificationService, ic.backupService, ic.defaultHostID.
func (app *Application) initScheduler(ctx context.Context, ic *initContext) error {
	jobRepo := postgres.NewJobRepository(app.DB)

	queueConfig := scheduler.DefaultQueueConfig()
	jobQueue := scheduler.NewQueue(app.Redis, app.Logger, queueConfig)

	schedulerConfig := scheduler.DefaultConfig()
	sched := scheduler.New(jobQueue, jobRepo, schedulerConfig, app.Logger)

	schedulerDeps := &workers.Dependencies{
		SecurityService: &schedulerSecurityAdapter{svc: ic.securityService},
		DockerClient: &schedulerDockerScanAdapter{
			hostService: ic.hostService,
			hostID:      ic.defaultHostID,
		},
		UpdateService: &schedulerUpdateAdapter{
			svc:    ic.updateService,
			hostID: ic.defaultHostID,
		},
		CleanupService: &schedulerCleanupAdapter{
			imageService:     ic.imageService,
			volumeService:    ic.volumeService,
			networkService:   ic.networkService,
			containerService: ic.containerService,
			hostService:      ic.hostService,
			hostID:           ic.defaultHostID,
		},
		JobCleanupService:   &schedulerJobCleanupAdapter{db: app.DB},
		RetentionService:    &schedulerRetentionAdapter{db: app.DB},
		NotificationService: &schedulerNotificationAdapter{svc: ic.notificationService},
		MetricsService:      nil, // Assigned later in initWeb once metrics service exists.
		InventoryService:    &schedulerInventoryAdapter{hostService: ic.hostService},
		Logger:              app.Logger,
	}

	if ic.backupService != nil {
		schedulerDeps.BackupService = &schedulerBackupAdapter{
			svc:    ic.backupService,
			hostID: ic.defaultHostID,
		}
	}

	// Backup verification worker. The sandbox runner is wired post-Register
	// so the worker can use the recon launcher when it lands; until then,
	// container/database verification methods fall back to a recorded
	// "sandbox not wired" failure (see backupverify.Service).
	if ic.backupVerifyService != nil {
		schedulerDeps.BackupVerifyService = ic.backupVerifyService
	}

	// SSL observatory scan worker (v26.5.1). Drains both the daily
	// scheduled sweep and on-demand "Scan Now" jobs enqueued by the
	// web/API. The service enforces its own per-target concurrency cap.
	if ic.sslObsService != nil {
		schedulerDeps.SSLScanService = ic.sslObsService
	}

	workers.RegisterDefaultWorkers(sched.Registry(), schedulerDeps)

	if err := sched.Start(ctx); err != nil {
		app.Logger.Error("Failed to start scheduler", "error", err)
	} else {
		app.schedulerService = sched
		app.Logger.Info("Scheduler service initialized",
			"worker_pool_size", schedulerConfig.WorkerPoolSize,
		)

		app.ensureRetentionScheduledJob(ctx, sched)
		if ic.backupService != nil {
			app.ensureDatabaseBackupScheduledJob(ctx, sched, ic.defaultHostID)
		}
		if ic.sslObsService != nil {
			app.ensureSSLScanScheduledJob(ctx, sched)
		}
	}

	ic.scheduler = sched
	ic.schedulerDeps = schedulerDeps
	return nil
}
