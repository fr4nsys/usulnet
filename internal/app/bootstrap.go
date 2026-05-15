// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	dockerpkg "github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/scheduler"
)

// ensureReconRetentionScheduledJob creates the recon-specific retention
// job if it doesn't already exist. Daily at 03:30 UTC — offset from the
// database-wide retention job at 03:00 so the two runs do not contend
// for I/O.
func (app *Application) ensureReconRetentionScheduledJob(ctx context.Context, sched *scheduler.Scheduler) {
	existing, err := sched.ListScheduledJobs(ctx, false)
	if err != nil {
		app.Logger.Warn("Failed to list scheduled jobs for recon retention check", "error", err)
		return
	}
	for _, job := range existing {
		if job.Type == models.JobTypeReconRetention {
			app.Logger.Debug("Recon retention scheduled job already exists",
				"job_id", job.ID, "schedule", job.Schedule,
			)
			return
		}
	}
	if _, err := sched.CreateScheduledJob(ctx, models.CreateScheduledJobInput{
		Name:        "Recon Retention",
		Type:        models.JobTypeReconRetention,
		Schedule:    "30 3 * * *",
		IsEnabled:   true,
		MaxAttempts: 1,
		Priority:    models.JobPriorityLow,
	}); err != nil {
		app.Logger.Error("Failed to create recon retention scheduled job", "error", err)
		return
	}
	app.Logger.Info("Recon retention scheduled job created (daily at 03:30 UTC)")
}

// ensureSSLScanScheduledJob creates the default daily SSL/TLS scan job
// if it doesn't already exist. Runs daily at 04:00 UTC — offset from the
// 02:00 backup and 03:00 retention windows so heavy I/O does not stack.
// The payload's empty HostID means "scan every enabled target on every
// host"; the service enforces a per-target concurrency cap (default 4).
func (app *Application) ensureSSLScanScheduledJob(ctx context.Context, sched *scheduler.Scheduler) {
	existing, err := sched.ListScheduledJobs(ctx, false)
	if err != nil {
		app.Logger.Warn("Failed to list scheduled jobs for ssl scan check", "error", err)
		return
	}

	for _, job := range existing {
		if job.Type == models.JobTypeSSLScan {
			app.Logger.Debug("ssl scan scheduled job already exists",
				"job_id", job.ID, "schedule", job.Schedule,
			)
			return
		}
	}

	if _, err := sched.CreateScheduledJob(ctx, models.CreateScheduledJobInput{
		Name:        "ssl observatory daily scan",
		Type:        models.JobTypeSSLScan,
		Schedule:    "0 4 * * *",
		IsEnabled:   true,
		MaxAttempts: 1,
		Priority:    models.JobPriorityLow,
	}); err != nil {
		app.Logger.Error("Failed to create ssl scan scheduled job", "error", err)
		return
	}

	app.Logger.Info("ssl observatory scan scheduled job created (daily at 04:00 UTC)")
}

// ensureRetentionScheduledJob creates the default database retention cleanup job
// if it doesn't already exist. Runs daily at 03:00 UTC.
func (app *Application) ensureRetentionScheduledJob(ctx context.Context, sched *scheduler.Scheduler) {
	existing, err := sched.ListScheduledJobs(ctx, false)
	if err != nil {
		app.Logger.Warn("Failed to list scheduled jobs for retention check", "error", err)
		return
	}

	for _, job := range existing {
		if job.Type == models.JobTypeRetention {
			app.Logger.Debug("Retention scheduled job already exists", "job_id", job.ID, "schedule", job.Schedule)
			return
		}
	}

	_, err = sched.CreateScheduledJob(ctx, models.CreateScheduledJobInput{
		Name:        "Database Retention Cleanup",
		Type:        models.JobTypeRetention,
		Schedule:    "0 3 * * *",
		IsEnabled:   true,
		MaxAttempts: 1,
		Priority:    models.JobPriorityLow,
	})
	if err != nil {
		app.Logger.Error("Failed to create retention scheduled job", "error", err)
		return
	}

	app.Logger.Info("Retention scheduled job created (daily at 03:00 UTC)")
}

// ensureDatabaseBackupScheduledJob creates the default automatic database
// backup job if it doesn't already exist. Runs daily at 02:00 UTC with gzip
// compression, encryption enabled, and 7-day retention.
func (app *Application) ensureDatabaseBackupScheduledJob(ctx context.Context, sched *scheduler.Scheduler, hostID uuid.UUID) {
	existing, err := sched.ListScheduledJobs(ctx, false)
	if err != nil {
		app.Logger.Warn("Failed to list scheduled jobs for backup check", "error", err)
		return
	}

	for _, job := range existing {
		if job.Type == models.JobTypeBackupCreate && job.Name == "Automatic Database Backup" {
			app.Logger.Debug("Database backup scheduled job already exists", "job_id", job.ID, "schedule", job.Schedule)
			return
		}
	}

	targetID := "postgresql"
	targetName := "PostgreSQL Database"
	retentionDays := 7
	_, err = sched.CreateScheduledJob(ctx, models.CreateScheduledJobInput{
		Name:        "Automatic Database Backup",
		Type:        models.JobTypeBackupCreate,
		Schedule:    "0 2 * * *",
		HostID:      &hostID,
		TargetID:    &targetID,
		TargetName:  &targetName,
		IsEnabled:   true,
		MaxAttempts: 3,
		Priority:    models.JobPriorityNormal,
		Payload: models.BackupPayload{
			Type:          string(models.BackupTypeSystem),
			TargetID:      targetID,
			Compression:   "gzip",
			Encrypted:     true,
			RetentionDays: retentionDays,
		},
	})
	if err != nil {
		app.Logger.Error("Failed to create database backup scheduled job", "error", err)
		return
	}

	app.Logger.Info("Automatic database backup scheduled job created (daily at 02:00 UTC, 7-day retention)")
}

// bootstrapLocalHost ensures a local Docker host row exists in the hosts table.
// This is required for foreign key constraints when syncing containers.
func (app *Application) bootstrapLocalHost(ctx context.Context, hostID uuid.UUID) error {
	var exists bool
	err := app.DB.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM hosts WHERE id = $1)", hostID).Scan(&exists)
	if err != nil {
		return fmt.Errorf("check host exists: %w", err)
	}
	if exists {
		return nil
	}

	_, err = app.DB.Exec(ctx, `
		INSERT INTO hosts (id, name, display_name, endpoint_type, endpoint_url, tls_enabled, status, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, false, 'online', CURRENT_TIMESTAMP)
		ON CONFLICT (id) DO NOTHING`,
		hostID, "local", "Local Docker", "local", "unix://"+dockerpkg.LocalSocketPath(),
	)
	if err != nil {
		return fmt.Errorf("insert local host: %w", err)
	}

	app.Logger.Info("Local Docker host bootstrapped in DB", "host_id", hostID)
	return nil
}

// bootstrapAdminUser creates a default admin user if no users exist.
func (app *Application) bootstrapAdminUser(ctx context.Context, userRepo *postgres.UserRepository) error {
	users, total, err := userRepo.List(ctx, postgres.UserListOptions{
		Page:    1,
		PerPage: 1,
	})
	if err != nil {
		return fmt.Errorf("check existing users: %w", err)
	}

	_ = users
	if total > 0 {
		app.Logger.Info("Users already exist, skipping admin bootstrap", "count", total)
		return nil
	}

	defaultPassword := "usulnet"
	hash, err := crypto.HashPassword(defaultPassword)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}

	adminUser := &models.User{
		Username:     "admin",
		PasswordHash: hash,
		Role:         models.RoleAdmin,
		IsActive:     true,
	}

	if err := userRepo.Create(ctx, adminUser); err != nil {
		return fmt.Errorf("create admin user: %w", err)
	}

	app.Logger.Warn("Default admin user created — CHANGE PASSWORD IMMEDIATELY after first login",
		"username", "admin",
	)

	return nil
}
