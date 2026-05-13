// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	backupsvc "github.com/fr4nsys/usulnet/internal/services/backup"
	securitysvc "github.com/fr4nsys/usulnet/internal/services/security"
	updatesvc "github.com/fr4nsys/usulnet/internal/services/update"
)

// ============================================================================
// Backup adapter for Update Service
// ============================================================================

// updateBackupAdapter bridges backup.Service → updatesvc.BackupService interface.
type updateBackupAdapter struct {
	svc    *backupsvc.Service
	hostID uuid.UUID
}

func (a *updateBackupAdapter) Create(ctx context.Context, opts updatesvc.BackupCreateOptions) (*updatesvc.BackupResult, error) {
	result, err := a.svc.Create(ctx, backupsvc.CreateOptions{
		HostID:      opts.HostID,
		Type:        models.BackupTypeVolume,
		TargetID:    opts.ContainerID,
		TargetName:  opts.ContainerID, // Will be resolved by backup service
		Trigger:     models.BackupTriggerPreUpdate,
		Compression: models.BackupCompressionGzip,
		CreatedBy:   opts.CreatedBy,
	})
	if err != nil {
		return nil, err
	}

	return &updatesvc.BackupResult{
		BackupID: result.Backup.ID,
		Path:     result.Backup.Path,
		Size:     result.FinalSize,
	}, nil
}

func (a *updateBackupAdapter) Restore(ctx context.Context, opts updatesvc.BackupRestoreOptions) (*updatesvc.BackupRestoreResult, error) {
	_, err := a.svc.Restore(ctx, backupsvc.RestoreOptions{
		BackupID:          opts.BackupID,
		OverwriteExisting: true,
		StopContainers:    true,
		StartAfterRestore: true,
	})
	if err != nil {
		return &updatesvc.BackupRestoreResult{Success: false}, err
	}

	return &updatesvc.BackupRestoreResult{Success: true}, nil
}

// ============================================================================
// Security adapter for Update Service
// ============================================================================

// updateSecurityAdapter bridges security.Service → updatesvc.SecurityService interface.
// Uses GetLatestScan for pre-update checks since full scan requires Docker inspect.
type updateSecurityAdapter struct {
	svc *securitysvc.Service
}

func (a *updateSecurityAdapter) ScanContainer(ctx context.Context, hostID uuid.UUID, containerID string) (*updatesvc.SecurityScanResult, error) {
	// For pre/post update checks, return the latest cached scan rather than
	// triggering a full re-scan (which requires Docker inspect data).
	// The scheduler handles periodic full scans.
	return a.GetLatestScan(ctx, containerID)
}

func (a *updateSecurityAdapter) GetLatestScan(ctx context.Context, containerID string) (*updatesvc.SecurityScanResult, error) {
	scan, err := a.svc.GetLatestScan(ctx, containerID)
	if err != nil {
		return nil, err
	}
	if scan == nil {
		return nil, nil
	}

	return &updatesvc.SecurityScanResult{
		Score: scan.Score,
		Grade: string(scan.Grade),
	}, nil
}
