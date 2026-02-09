// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"time"

	"github.com/google/uuid"

	dockerpkg "github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	backupsvc "github.com/fr4nsys/usulnet/internal/services/backup"
	containersvc "github.com/fr4nsys/usulnet/internal/services/container"
	hostsvc "github.com/fr4nsys/usulnet/internal/services/host"
	imagesvc "github.com/fr4nsys/usulnet/internal/services/image"
	networksvc "github.com/fr4nsys/usulnet/internal/services/network"
	notificationsvc "github.com/fr4nsys/usulnet/internal/services/notification"
	"github.com/fr4nsys/usulnet/internal/services/notification/channels"
	securitysvc "github.com/fr4nsys/usulnet/internal/services/security"
	updatesvc "github.com/fr4nsys/usulnet/internal/services/update"
	volumesvc "github.com/fr4nsys/usulnet/internal/services/volume"
	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
)

// ============================================================================
// Security adapter for Scheduler Workers
// ============================================================================

// schedulerSecurityAdapter bridges securitysvc.Service → workers.SecurityService
type schedulerSecurityAdapter struct {
	svc *securitysvc.Service
}

func (a *schedulerSecurityAdapter) ScanContainer(ctx context.Context, containerInspect interface{}, hostID uuid.UUID) (*models.SecurityScan, error) {
	return a.svc.ScanContainer(ctx, containerInspect, hostID)
}

func (a *schedulerSecurityAdapter) GetLatestScan(ctx context.Context, containerID string) (*models.SecurityScan, error) {
	return a.svc.GetLatestScan(ctx, containerID)
}

func (a *schedulerSecurityAdapter) GetSecuritySummary(ctx context.Context, hostID *uuid.UUID) (*workers.SecuritySummary, error) {
	summary, err := a.svc.GetSecuritySummary(ctx, hostID)
	if err != nil {
		return nil, err
	}

	return &workers.SecuritySummary{
		TotalContainers:   summary.TotalContainers,
		TotalIssues:       summary.TotalIssues,
		AverageScore:      summary.AverageScore,
		GradeDistribution: summary.GradeDistribution,
	}, nil
}

// ============================================================================
// Docker client adapter for Security Scanner Worker
// ============================================================================

// schedulerDockerScanAdapter bridges host/docker services → workers.DockerClientForScan
type schedulerDockerScanAdapter struct {
	hostService *hostsvc.Service
	hostID      uuid.UUID
}

func (a *schedulerDockerScanAdapter) ContainerInspect(ctx context.Context, containerID string) (interface{}, error) {
	client, err := a.hostService.GetClient(ctx, a.hostID)
	if err != nil {
		return nil, err
	}

	// Return raw ContainerJSON for security scanner analysis
	return client.ContainerInspectRaw(ctx, containerID)
}

func (a *schedulerDockerScanAdapter) ContainerList(ctx context.Context, all bool) ([]workers.ContainerBasicInfo, error) {
	client, err := a.hostService.GetClient(ctx, a.hostID)
	if err != nil {
		return nil, err
	}

	containers, err := client.ContainerList(ctx, dockerpkg.ContainerListOptions{All: all})
	if err != nil {
		return nil, err
	}

	result := make([]workers.ContainerBasicInfo, len(containers))
	for i, c := range containers {
		result[i] = workers.ContainerBasicInfo{
			ID:    c.ID,
			Name:  c.Name,
			Image: c.Image,
			State: c.State,
		}
	}
	return result, nil
}

// ============================================================================
// Backup adapter for Scheduler Workers
// ============================================================================

// schedulerBackupAdapter bridges backupsvc.Service → workers.BackupService
type schedulerBackupAdapter struct {
	svc    *backupsvc.Service
	hostID uuid.UUID
}

func (a *schedulerBackupAdapter) Create(ctx context.Context, opts workers.BackupCreateOptions) (*workers.BackupCreateResult, error) {
	result, err := a.svc.Create(ctx, backupsvc.CreateOptions{
		HostID:      opts.HostID,
		Type:        opts.Type,
		TargetID:    opts.TargetID,
		TargetName:  opts.TargetName,
		Trigger:     opts.Trigger,
		Compression: models.BackupCompressionGzip,
		Encrypt:     opts.Encrypt,
	})
	if err != nil {
		return nil, err
	}

	return &workers.BackupCreateResult{
		Backup: result.Backup,
	}, nil
}

func (a *schedulerBackupAdapter) Restore(ctx context.Context, opts workers.BackupRestoreOptions) (*workers.BackupRestoreResult, error) {
	result, err := a.svc.Restore(ctx, backupsvc.RestoreOptions{
		BackupID:          opts.BackupID,
		TargetName:        opts.TargetName,
		OverwriteExisting: true,
		StopContainers:    true,
		StartAfterRestore: true,
	})
	if err != nil {
		return &workers.BackupRestoreResult{Success: false}, err
	}

	return &workers.BackupRestoreResult{
		Success:      true,
		TargetID:     result.TargetID,
		RestoredSize: result.BytesWritten,
		Duration:     result.Duration,
	}, nil
}

func (a *schedulerBackupAdapter) Delete(ctx context.Context, id uuid.UUID) error {
	return a.svc.Delete(ctx, id)
}

func (a *schedulerBackupAdapter) Get(ctx context.Context, id uuid.UUID) (*models.Backup, error) {
	return a.svc.Get(ctx, id)
}

func (a *schedulerBackupAdapter) PruneTarget(ctx context.Context, hostID uuid.UUID, targetID string, keepCount int) (*workers.BackupCleanupResult, error) {
	result, err := a.svc.PruneTarget(ctx, hostID, targetID, keepCount)
	if err != nil {
		return nil, err
	}

	return &workers.BackupCleanupResult{
		DeletedCount: result.DeletedCount,
		FreedBytes:   result.DeletedSize,
	}, nil
}

// ============================================================================
// Update adapter for Scheduler Workers
// ============================================================================

// schedulerUpdateAdapter bridges updatesvc.Service → workers.UpdateService
type schedulerUpdateAdapter struct {
	svc    *updatesvc.Service
	hostID uuid.UUID
}

func (a *schedulerUpdateAdapter) CheckForUpdates(ctx context.Context, hostID uuid.UUID) (*workers.UpdateCheckServiceResult, error) {
	result, err := a.svc.CheckForUpdates(ctx, hostID)
	if err != nil {
		return nil, err
	}

	updates := make([]*workers.AvailableUpdateService, len(result.Updates))
	for i, u := range result.Updates {
		var changelog string
		if u.Changelog != nil {
			changelog = u.Changelog.Body
		}
		updates[i] = &workers.AvailableUpdateService{
			ContainerID:    u.ContainerID,
			ContainerName:  u.ContainerName,
			Image:          u.Image,
			CurrentVersion: u.CurrentVersion,
			LatestVersion:  u.LatestVersion,
			Changelog:      changelog,
			CheckedAt:      u.CheckedAt,
		}
	}

	return &workers.UpdateCheckServiceResult{
		TotalChecked:     result.CheckedCount,
		AvailableUpdates: updates,
	}, nil
}

func (a *schedulerUpdateAdapter) CheckContainerForUpdate(ctx context.Context, hostID uuid.UUID, containerID string) (*workers.AvailableUpdateService, error) {
	result, err := a.svc.CheckContainerForUpdate(ctx, hostID, containerID)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}

	var changelog string
	if result.Changelog != nil {
		changelog = result.Changelog.Body
	}

	return &workers.AvailableUpdateService{
		ContainerID:    result.ContainerID,
		ContainerName:  result.ContainerName,
		Image:          result.Image,
		CurrentVersion: result.CurrentVersion,
		LatestVersion:  result.LatestVersion,
		Changelog:      changelog,
		CheckedAt:      result.CheckedAt,
	}, nil
}

func (a *schedulerUpdateAdapter) UpdateContainer(ctx context.Context, hostID uuid.UUID, opts *workers.UpdateServiceOptions) (*workers.UpdateServiceResult, error) {
	result, err := a.svc.UpdateContainer(ctx, hostID, &models.UpdateOptions{
		ContainerID:   opts.ContainerID,
		TargetVersion: opts.TargetVersion,
		BackupVolumes: opts.CreateBackup,
	})
	if err != nil {
		return nil, err
	}

	return &workers.UpdateServiceResult{
		UpdateID:          result.Update.ID,
		FromVersion:       result.FromVersion,
		ToVersion:         result.ToVersion,
		BackupID:          result.BackupID,
		HealthCheckPassed: result.HealthPassed,
	}, nil
}

func (a *schedulerUpdateAdapter) Rollback(ctx context.Context, opts *workers.RollbackServiceOptions) (*workers.RollbackServiceResult, error) {
	// The workers.RollbackServiceOptions has ContainerID + BackupID,
	// but models.RollbackOptions needs UpdateID. We need to find the update
	// associated with this container. For now, return not supported if no direct mapping.
	// In practice, the update worker tracks the update ID in the job result.

	// Attempt rollback - the RollbackServiceOptions doesn't map cleanly,
	// so we construct what we can.
	result, err := a.svc.RollbackUpdate(ctx, &models.RollbackOptions{
		UpdateID:      opts.BackupID, // Worker passes backup/update ID here
		RestoreBackup: opts.RestoreData,
	})
	if err != nil {
		return &workers.RollbackServiceResult{
			Success:     false,
			Error:       err.Error(),
			CompletedAt: time.Now(),
		}, nil
	}

	return &workers.RollbackServiceResult{
		Success:       result.Success,
		RestoredImage: result.RestoredVersion,
		CompletedAt:   time.Now(),
	}, nil
}

// ============================================================================
// Cleanup adapter for Scheduler Workers
// ============================================================================

// schedulerCleanupAdapter bridges image/volume/network/container services → workers.CleanupService
type schedulerCleanupAdapter struct {
	imageService     *imagesvc.Service
	volumeService    *volumesvc.Service
	networkService   *networksvc.Service
	containerService *containersvc.Service
	hostID           uuid.UUID
}

func (a *schedulerCleanupAdapter) PruneImages(ctx context.Context, hostID uuid.UUID, all bool) (*workers.PruneResult, error) {
	result, err := a.imageService.Prune(ctx, hostID, !all) // dangling = !all
	if err != nil {
		return nil, err
	}
	return &workers.PruneResult{
		ItemsDeleted: int64(len(result.ItemsDeleted)),
		SpaceFreed:   result.SpaceReclaimed,
	}, nil
}

func (a *schedulerCleanupAdapter) PruneVolumes(ctx context.Context, hostID uuid.UUID) (*workers.PruneResult, error) {
	result, err := a.volumeService.Prune(ctx, hostID)
	if err != nil {
		return nil, err
	}
	return &workers.PruneResult{
		ItemsDeleted: int64(len(result.ItemsDeleted)),
		SpaceFreed:   result.SpaceReclaimed,
	}, nil
}

func (a *schedulerCleanupAdapter) PruneNetworks(ctx context.Context, hostID uuid.UUID) (*workers.PruneResult, error) {
	result, err := a.networkService.Prune(ctx, hostID)
	if err != nil {
		return nil, err
	}
	return &workers.PruneResult{
		ItemsDeleted: int64(len(result.ItemsDeleted)),
		SpaceFreed:   result.SpaceReclaimed,
	}, nil
}

func (a *schedulerCleanupAdapter) PruneContainers(ctx context.Context, hostID uuid.UUID) (*workers.PruneResult, error) {
	count, space, err := a.containerService.Prune(ctx, hostID)
	if err != nil {
		return nil, err
	}
	return &workers.PruneResult{
		ItemsDeleted: count,
		SpaceFreed:   int64(space),
	}, nil
}

func (a *schedulerCleanupAdapter) PruneBuildCache(ctx context.Context, hostID uuid.UUID) (*workers.PruneResult, error) {
	// Build cache prune not yet implemented in our docker.Client.
	// Return empty result rather than failing the cleanup worker.
	return &workers.PruneResult{
		ItemsDeleted: 0,
		SpaceFreed:   0,
		Errors:       []string{"build cache prune not implemented"},
	}, nil
}

// ============================================================================
// Job Cleanup adapter for Scheduler Workers
// ============================================================================

// schedulerJobCleanupAdapter implements workers.JobCleanupService using the DB.
type schedulerJobCleanupAdapter struct {
	db *postgres.DB
}

func (a *schedulerJobCleanupAdapter) DeleteOldJobs(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)
	query := `DELETE FROM jobs WHERE status IN ('completed', 'failed', 'cancelled') AND completed_at < $1`
	result, err := a.db.Pool().Exec(ctx, query, cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

func (a *schedulerJobCleanupAdapter) DeleteOldEvents(ctx context.Context, olderThan time.Duration) (int64, error) {
	// Job events table may not exist yet; gracefully return 0
	cutoff := time.Now().Add(-olderThan)
	query := `DELETE FROM job_events WHERE created_at < $1`
	result, err := a.db.Pool().Exec(ctx, query, cutoff)
	if err != nil {
		// Table may not exist, ignore
		return 0, nil
	}
	return result.RowsAffected(), nil
}

// ============================================================================
// Notification adapter for Scheduler Workers
// ============================================================================

// schedulerNotificationAdapter bridges notificationsvc.Service → workers.NotificationService
type schedulerNotificationAdapter struct {
	svc *notificationsvc.Service
}

func (a *schedulerNotificationAdapter) Send(ctx context.Context, notification *workers.Notification) error {
	// The worker's Channel is the delivery mechanism (email, slack, etc.)
	// The service's Type is the notification category (for template selection)
	// Use TemplateID as Type if available, otherwise default to system_info
	notifType := channels.TypeSystemInfo
	if notification.TemplateID != "" {
		notifType = channels.NotificationType(notification.TemplateID)
	}

	msg := notificationsvc.Message{
		Type:     notifType,
		Title:    notification.Subject,
		Body:     notification.Message,
		Priority: channels.PriorityFromString(notification.Priority),
		Data:     notification.Data,
	}

	if notification.Channel != "" {
		msg.Channels = []string{notification.Channel}
	}

	return a.svc.Send(ctx, msg)
}

func (a *schedulerNotificationAdapter) SendBatch(ctx context.Context, notifications []*workers.Notification) (*workers.BatchSendResult, error) {
	result := &workers.BatchSendResult{
		Total: len(notifications),
	}

	for _, n := range notifications {
		if err := a.Send(ctx, n); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, err.Error())
		} else {
			result.Sent++
		}
	}

	return result, nil
}

func (a *schedulerNotificationAdapter) GetChannelConfig(ctx context.Context, channelType string) (*workers.ChannelConfig, error) {
	// Check if the channel is registered in the notification service
	registeredChannels := a.svc.ListChannels()
	for _, ch := range registeredChannels {
		if ch == channelType {
			return &workers.ChannelConfig{
				Type:    channelType,
				Enabled: true,
			}, nil
		}
	}

	return &workers.ChannelConfig{
		Type:    channelType,
		Enabled: false,
	}, nil
}

// ============================================================================
// Retention adapter for Scheduler Workers
// ============================================================================

// schedulerRetentionAdapter calls PostgreSQL retention functions via the DB pool.
type schedulerRetentionAdapter struct {
	db *postgres.DB
}

func (a *schedulerRetentionAdapter) callRetentionFunc(ctx context.Context, funcName string, retentionDays int) (int64, error) {
	var deleted int
	err := a.db.Pool().QueryRow(ctx, "SELECT "+funcName+"($1)", retentionDays).Scan(&deleted)
	if err != nil {
		return 0, err
	}
	return int64(deleted), nil
}

func (a *schedulerRetentionAdapter) callRetentionFuncNoArgs(ctx context.Context, funcName string) (int64, error) {
	var deleted int
	err := a.db.Pool().QueryRow(ctx, "SELECT "+funcName+"()").Scan(&deleted)
	if err != nil {
		return 0, err
	}
	return int64(deleted), nil
}

func (a *schedulerRetentionAdapter) CleanupOldMetrics(ctx context.Context, retentionDays int) (int64, error) {
	return a.callRetentionFunc(ctx, "cleanup_old_metrics", retentionDays)
}

func (a *schedulerRetentionAdapter) CleanupOldContainerStats(ctx context.Context, retentionDays int) (int64, error) {
	return a.callRetentionFunc(ctx, "cleanup_old_container_stats", retentionDays)
}

func (a *schedulerRetentionAdapter) CleanupOldHostMetrics(ctx context.Context, retentionDays int) (int64, error) {
	return a.callRetentionFunc(ctx, "cleanup_old_host_metrics", retentionDays)
}

func (a *schedulerRetentionAdapter) CleanupOldAuditLog(ctx context.Context, retentionDays int) (int64, error) {
	return a.callRetentionFunc(ctx, "cleanup_old_audit_log", retentionDays)
}

func (a *schedulerRetentionAdapter) CleanupOldJobEvents(ctx context.Context, retentionDays int) (int64, error) {
	return a.callRetentionFunc(ctx, "cleanup_old_job_events", retentionDays)
}

func (a *schedulerRetentionAdapter) CleanupOldNotificationLogs(ctx context.Context, retentionDays int) (int64, error) {
	return a.callRetentionFunc(ctx, "cleanup_old_notification_logs", retentionDays)
}

func (a *schedulerRetentionAdapter) CleanupExpiredSessions(ctx context.Context) (int64, error) {
	return a.callRetentionFuncNoArgs(ctx, "cleanup_expired_sessions")
}

func (a *schedulerRetentionAdapter) CleanupExpiredPasswordResetTokens(ctx context.Context) (int64, error) {
	return a.callRetentionFuncNoArgs(ctx, "cleanup_expired_password_reset_tokens")
}


