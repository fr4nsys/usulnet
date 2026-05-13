// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	containersvc "github.com/fr4nsys/usulnet/internal/services/container"
	volumesvc "github.com/fr4nsys/usulnet/internal/services/volume"
)

type volumeAdapter struct {
	svc          *volumesvc.Service
	containerSvc *containersvc.Service
	hostID       uuid.UUID
}

func (a *volumeAdapter) List(ctx context.Context) ([]VolumeView, error) {
	if a.svc == nil {
		return nil, nil
	}

	volumes, err := a.svc.List(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return nil, err
	}

	// Cross-reference with containers to get InUse and UsedBy
	volumeUsage := make(map[string][]string) // volume name → container names
	if a.containerSvc != nil {
		containers, err := a.containerSvc.ListByHost(ctx, resolveHostID(ctx, a.hostID))
		if err == nil {
			for _, c := range containers {
				for _, m := range c.Mounts {
					if m.Type == "volume" {
						volumeUsage[m.Source] = append(volumeUsage[m.Source], c.Name)
					}
				}
			}
		}
	}

	views := make([]VolumeView, 0, len(volumes))
	for _, v := range volumes {
		view := volumeToView(v)
		if usedBy, ok := volumeUsage[v.Name]; ok {
			view.InUse = true
			view.UsedBy = usedBy
		}
		views = append(views, view)
	}
	return views, nil
}

func (a *volumeAdapter) Get(ctx context.Context, name string) (*VolumeView, error) {
	if a.svc == nil {
		return nil, nil
	}

	v, err := a.svc.Get(ctx, resolveHostID(ctx, a.hostID), name)
	if err != nil {
		return nil, err
	}

	view := volumeToView(v)

	// Cross-reference with containers to get UsedBy
	if a.containerSvc != nil {
		containers, err := a.containerSvc.ListByHost(ctx, resolveHostID(ctx, a.hostID))
		if err == nil {
			for _, c := range containers {
				for _, m := range c.Mounts {
					if m.Type == "volume" && m.Source == name {
						view.InUse = true
						view.UsedBy = append(view.UsedBy, c.Name)
					}
				}
			}
		}
	}

	return &view, nil
}

func (a *volumeAdapter) Create(ctx context.Context, name, driver string, labels map[string]string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}

	input := &models.CreateVolumeInput{
		Name:   name,
		Driver: driver,
		Labels: labels,
	}
	_, err := a.svc.Create(ctx, resolveHostID(ctx, a.hostID), input)
	return err
}

func (a *volumeAdapter) Remove(ctx context.Context, name string, force bool) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}
	return a.svc.Delete(ctx, resolveHostID(ctx, a.hostID), name, force)
}

func (a *volumeAdapter) Prune(ctx context.Context) (int64, error) {
	if a.svc == nil {
		return 0, ErrServiceNotConfigured
	}
	result, err := a.svc.Prune(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return 0, err
	}
	return result.SpaceReclaimed, nil
}

func (a *volumeAdapter) Browse(ctx context.Context, volumeName, path string) ([]VolumeFileEntry, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("volume service not available")
	}
	files, err := a.svc.BrowseVolume(ctx, resolveHostID(ctx, a.hostID), volumeName, path)
	if err != nil {
		return nil, err
	}
	entries := make([]VolumeFileEntry, len(files))
	for i, f := range files {
		entries[i] = VolumeFileEntry{
			Name:       f.Name,
			Path:       f.Path,
			IsDir:      f.IsDir,
			Size:       f.Size,
			SizeHuman:  f.SizeHuman,
			Mode:       f.Mode,
			ModTime:    f.ModTime.Format("2006-01-02 15:04:05"),
			ModTimeAgo: humanTime(f.ModTime),
		}
	}
	return entries, nil
}
