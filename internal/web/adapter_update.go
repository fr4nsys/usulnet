// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	updatesvc "github.com/fr4nsys/usulnet/internal/services/update"
)

type updateAdapter struct {
	svc    *updatesvc.Service
	hostID uuid.UUID
}

func (a *updateAdapter) ListAvailable(ctx context.Context) ([]UpdateView, error) {
	if a.svc == nil {
		return nil, nil
	}
	result, err := a.svc.CheckForUpdates(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	views := make([]UpdateView, 0, len(result.Updates))
	for _, u := range result.Updates {
		if !u.NeedsUpdate() {
			continue
		}
		v := UpdateView{
			ContainerID:    u.ContainerID,
			ContainerName:  u.ContainerName,
			Image:          u.Image,
			CurrentVersion: u.CurrentVersion,
			LatestVersion:  u.LatestVersion,
			CheckedAt:      u.CheckedAt.Format("2006-01-02 15:04"),
		}
		if u.Changelog != nil {
			v.Changelog = u.Changelog.Body
			v.ChangelogURL = u.Changelog.URL
		}
		views = append(views, v)
	}
	return views, nil
}

func (a *updateAdapter) CheckAll(ctx context.Context) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}
	_, err := a.svc.CheckForUpdates(ctx, resolveHostID(ctx, a.hostID))
	return err
}

func (a *updateAdapter) GetChangelog(ctx context.Context, containerID string) (string, error) {
	if a.svc == nil {
		return "", nil
	}
	update, err := a.svc.CheckContainerForUpdate(ctx, resolveHostID(ctx, a.hostID), containerID)
	if err != nil {
		return "", err
	}
	if update != nil && update.Changelog != nil {
		return update.Changelog.Body, nil
	}
	return "", nil
}

func (a *updateAdapter) Apply(ctx context.Context, containerID string, backup bool, targetVersion string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}
	opts := &models.UpdateOptions{
		ContainerID:   containerID,
		TargetVersion: targetVersion,
		BackupVolumes: backup,
		SecurityScan:  true,
	}
	_, err := a.svc.UpdateContainer(ctx, resolveHostID(ctx, a.hostID), opts)
	return err
}

func (a *updateAdapter) Rollback(ctx context.Context, updateID string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}
	uid, err := uuid.Parse(updateID)
	if err != nil {
		return fmt.Errorf("invalid update ID: %w", err)
	}
	opts := &models.RollbackOptions{
		UpdateID:      uid,
		RestoreBackup: true,
	}
	_, err = a.svc.RollbackUpdate(ctx, opts)
	return err
}

func (a *updateAdapter) GetHistory(ctx context.Context) ([]UpdateHistoryView, error) {
	if a.svc == nil {
		return nil, nil
	}
	updates, err := a.svc.GetHistory(ctx, resolveHostID(ctx, a.hostID), "", 50)
	if err != nil {
		return nil, err
	}
	views := make([]UpdateHistoryView, 0, len(updates))
	for _, u := range updates {
		v := UpdateHistoryView{
			ID:            u.ID.String(),
			ContainerName: u.TargetName,
			FromVersion:   u.FromVersion,
			ToVersion:     u.ToVersion,
			Status:        string(u.Status),
			UpdatedAt:     u.CreatedAt.Format("2006-01-02 15:04"),
			CanRollback:   u.CanRollback(),
		}
		if u.DurationMs != nil {
			dur := time.Duration(*u.DurationMs) * time.Millisecond
			v.Duration = dur.Round(time.Second).String()
		}
		views = append(views, v)
	}
	return views, nil
}

func (a *updateAdapter) ListPolicies(ctx context.Context) ([]UpdatePolicyView, error) {
	if a.svc == nil {
		return nil, nil
	}
	hostID := resolveHostID(ctx, a.hostID)
	policies, err := a.svc.ListPolicies(ctx, &hostID)
	if err != nil {
		return nil, err
	}
	views := make([]UpdatePolicyView, 0, len(policies))
	for _, p := range policies {
		v := UpdatePolicyView{
			ID:                p.ID.String(),
			TargetType:        string(p.TargetType),
			TargetID:          p.TargetID,
			TargetName:        p.TargetName,
			IsEnabled:         p.IsEnabled,
			AutoUpdate:        p.AutoUpdate,
			AutoBackup:        p.AutoBackup,
			IncludePrerelease: p.IncludePrerelease,
			NotifyOnUpdate:    p.NotifyOnUpdate,
			NotifyOnFailure:   p.NotifyOnFailure,
			MaxRetries:        p.MaxRetries,
			HealthCheckWait:   p.HealthCheckWait,
		}
		if p.Schedule != nil {
			v.Schedule = *p.Schedule
		}
		views = append(views, v)
	}
	return views, nil
}

func (a *updateAdapter) SetPolicy(ctx context.Context, pv UpdatePolicyView) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}
	hostID := resolveHostID(ctx, a.hostID)
	policy := &models.UpdatePolicy{
		HostID:            hostID,
		TargetType:        models.UpdateType(pv.TargetType),
		TargetID:          pv.TargetID,
		TargetName:        pv.TargetName,
		IsEnabled:         pv.IsEnabled,
		AutoUpdate:        pv.AutoUpdate,
		AutoBackup:        pv.AutoBackup,
		IncludePrerelease: pv.IncludePrerelease,
		NotifyOnUpdate:    pv.NotifyOnUpdate,
		NotifyOnFailure:   pv.NotifyOnFailure,
		MaxRetries:        pv.MaxRetries,
		HealthCheckWait:   pv.HealthCheckWait,
	}
	if pv.Schedule != "" {
		policy.Schedule = &pv.Schedule
	}
	if pv.ID != "" {
		uid, err := uuid.Parse(pv.ID)
		if err == nil {
			policy.ID = uid
		}
	}
	return a.svc.SetPolicy(ctx, policy)
}

func (a *updateAdapter) DeletePolicy(ctx context.Context, id string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid policy ID: %w", err)
	}
	return a.svc.DeletePolicy(ctx, uid)
}
