// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"
	"io"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	backupsvc "github.com/fr4nsys/usulnet/internal/services/backup"
)

type backupAdapter struct {
	svc    *backupsvc.Service
	hostID uuid.UUID
}

func (a *backupAdapter) List(ctx context.Context, containerID string) ([]BackupView, error) {
	if a.svc == nil {
		return nil, nil
	}

	opts := models.BackupListOptions{
		Limit: 100,
	}
	if containerID != "" {
		opts.TargetID = &containerID
	}

	backups, _, err := a.svc.List(ctx, opts)
	if err != nil {
		return nil, err
	}

	views := make([]BackupView, 0, len(backups))
	for _, b := range backups {
		views = append(views, backupToView(b))
	}
	return views, nil
}

func (a *backupAdapter) Get(ctx context.Context, id string) (*BackupView, error) {
	if a.svc == nil {
		return nil, nil
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}

	b, err := a.svc.Get(ctx, uid)
	if err != nil {
		return nil, err
	}

	view := backupToView(b)
	return &view, nil
}

func (a *backupAdapter) Create(ctx context.Context, containerID string) (*BackupView, error) {
	if a.svc == nil {
		return nil, ErrServiceNotConfigured
	}

	result, err := a.svc.Create(ctx, backupsvc.CreateOptions{
		HostID:   resolveHostID(ctx, a.hostID),
		TargetID: containerID,
		Type:     models.BackupTypeContainer,
		Trigger:  models.BackupTriggerManual,
	})
	if err != nil {
		return nil, err
	}

	view := backupToView(result.Backup)
	return &view, nil
}

func (a *backupAdapter) Restore(ctx context.Context, id string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return err
	}

	_, err = a.svc.Restore(ctx, backupsvc.RestoreOptions{
		BackupID: uid,
	})
	return err
}

func (a *backupAdapter) Remove(ctx context.Context, id string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return err
	}

	return a.svc.Delete(ctx, uid)
}

func (a *backupAdapter) Download(ctx context.Context, id string) (string, error) {
	if a.svc == nil {
		return "", ErrServiceNotConfigured
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return "", err
	}

	// Get backup metadata without opening storage reader (avoids unnecessary
	// network I/O for remote storage backends like S3/Azure)
	backup, err := a.svc.Get(ctx, uid)
	if err != nil {
		return "", err
	}

	return backup.Filename, nil
}

func (a *backupAdapter) DownloadStream(ctx context.Context, id string) (io.ReadCloser, string, int64, error) {
	if a.svc == nil {
		return nil, "", 0, fmt.Errorf("backup service not configured")
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, "", 0, err
	}

	info, err := a.svc.Download(ctx, uid)
	if err != nil {
		return nil, "", 0, err
	}

	return info.Reader, info.Filename, info.Size, nil
}

func (a *backupAdapter) CreateWithOptions(ctx context.Context, opts BackupCreateInput) (*BackupView, error) {
	if a.svc == nil {
		return nil, ErrServiceNotConfigured
	}

	backupType := models.BackupTypeContainer
	switch opts.Type {
	case "volume":
		backupType = models.BackupTypeVolume
	case "stack":
		backupType = models.BackupTypeStack
	case "container":
		backupType = models.BackupTypeContainer
	}

	compression := models.BackupCompressionGzip
	switch opts.Compression {
	case "none":
		compression = models.BackupCompressionNone
	case "zstd":
		compression = models.BackupCompressionZstd
	case "gzip":
		compression = models.BackupCompressionGzip
	}

	createOpts := backupsvc.CreateOptions{
		HostID:        resolveHostID(ctx, a.hostID),
		Type:          backupType,
		TargetID:      opts.TargetID,
		TargetName:    opts.TargetName,
		Trigger:       models.BackupTriggerManual,
		Compression:   compression,
		Encrypt:       opts.Encrypt,
		StopContainer: opts.StopContainer,
	}
	if opts.RetentionDays > 0 {
		createOpts.RetentionDays = &opts.RetentionDays
	}

	result, err := a.svc.Create(ctx, createOpts)
	if err != nil {
		return nil, err
	}

	view := backupToView(result.Backup)
	return &view, nil
}

func (a *backupAdapter) GetStats(ctx context.Context) (*BackupStatsView, error) {
	if a.svc == nil {
		return nil, nil
	}

	hostID := resolveHostID(ctx, a.hostID)
	stats, err := a.svc.GetStats(ctx, &hostID)
	if err != nil {
		return nil, err
	}

	view := &BackupStatsView{
		TotalBackups:     stats.TotalBackups,
		CompletedBackups: stats.CompletedBackups,
		FailedBackups:    stats.FailedBackups,
		TotalSize:        stats.TotalSize,
		TotalSizeHuman:   humanSize(stats.TotalSize),
	}
	if stats.LastBackupAt != nil {
		view.LastBackupAt = humanTime(*stats.LastBackupAt)
	}
	return view, nil
}

func (a *backupAdapter) GetStorageInfo(ctx context.Context) (*BackupStorageView, error) {
	if a.svc == nil {
		return nil, nil
	}

	info, err := a.svc.GetStorageInfo(ctx)
	if err != nil {
		return nil, err
	}

	view := &BackupStorageView{
		Type:            info.Type,
		Path:            info.LocalPath,
		TotalSpace:      info.TotalSize,
		TotalSpaceHuman: humanSize(info.TotalSize),
		UsedSpace:       info.UsedSize,
		UsedSpaceHuman:  humanSize(info.UsedSize),
		BackupCount:     int64(info.BackupCount),
	}
	if info.TotalSize > 0 {
		view.UsagePercent = float64(info.UsedSize) / float64(info.TotalSize) * 100
	}
	return view, nil
}

func (a *backupAdapter) ListSchedules(ctx context.Context) ([]BackupScheduleView, error) {
	if a.svc == nil {
		return nil, nil
	}

	hostID := resolveHostID(ctx, a.hostID)
	schedules, err := a.svc.ListSchedules(ctx, &hostID)
	if err != nil {
		return nil, err
	}

	views := make([]BackupScheduleView, 0, len(schedules))
	for _, s := range schedules {
		view := BackupScheduleView{
			ID:            s.ID.String(),
			Type:          string(s.Type),
			TargetID:      s.TargetID,
			TargetName:    s.TargetName,
			Schedule:      s.Schedule,
			Compression:   string(s.Compression),
			Encrypted:     s.Encrypted,
			RetentionDays: s.RetentionDays,
			MaxBackups:    s.MaxBackups,
			IsEnabled:     s.IsEnabled,
			CreatedAt:     humanTime(s.CreatedAt),
		}
		if s.LastRunAt != nil {
			view.LastRunAt = humanTime(*s.LastRunAt)
		}
		if s.LastRunStatus != nil {
			view.LastRunStatus = string(*s.LastRunStatus)
		}
		if s.NextRunAt != nil {
			view.NextRunAt = humanTime(*s.NextRunAt)
		}
		views = append(views, view)
	}
	return views, nil
}

func (a *backupAdapter) CreateSchedule(ctx context.Context, input BackupScheduleInput) (*BackupScheduleView, error) {
	if a.svc == nil {
		return nil, ErrServiceNotConfigured
	}

	backupType := models.BackupTypeContainer
	switch input.Type {
	case "volume":
		backupType = models.BackupTypeVolume
	case "stack":
		backupType = models.BackupTypeStack
	}

	compression := models.BackupCompressionGzip
	switch input.Compression {
	case "none":
		compression = models.BackupCompressionNone
	case "zstd":
		compression = models.BackupCompressionZstd
	}

	hostID := resolveHostID(ctx, a.hostID)
	schedule, err := a.svc.CreateSchedule(ctx, models.CreateBackupScheduleInput{
		Type:          backupType,
		TargetID:      input.TargetID,
		Schedule:      input.Schedule,
		Compression:   compression,
		Encrypted:     input.Encrypted,
		RetentionDays: input.RetentionDays,
		MaxBackups:    input.MaxBackups,
		IsEnabled:     true,
	}, hostID, nil)
	if err != nil {
		return nil, err
	}

	view := &BackupScheduleView{
		ID:            schedule.ID.String(),
		Type:          string(schedule.Type),
		TargetID:      schedule.TargetID,
		TargetName:    schedule.TargetName,
		Schedule:      schedule.Schedule,
		Compression:   string(schedule.Compression),
		Encrypted:     schedule.Encrypted,
		RetentionDays: schedule.RetentionDays,
		MaxBackups:    schedule.MaxBackups,
		IsEnabled:     schedule.IsEnabled,
		CreatedAt:     humanTime(schedule.CreatedAt),
	}
	if schedule.NextRunAt != nil {
		view.NextRunAt = humanTime(*schedule.NextRunAt)
	}
	return view, nil
}

func (a *backupAdapter) DeleteSchedule(ctx context.Context, id string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return err
	}

	return a.svc.DeleteSchedule(ctx, uid)
}

func (a *backupAdapter) RunSchedule(ctx context.Context, id string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return err
	}

	_, err = a.svc.RunSchedule(ctx, uid)
	return err
}
