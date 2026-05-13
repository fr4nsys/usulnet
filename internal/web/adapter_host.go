// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	dockerpkg "github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	hostsvc "github.com/fr4nsys/usulnet/internal/services/host"
)

type hostAdapter struct {
	svc    *hostsvc.Service
	hostID uuid.UUID
}

func (a *hostAdapter) GetDockerInfo(ctx context.Context) (*DockerInfoView, error) {
	if a.svc == nil {
		return nil, nil
	}
	info, err := a.svc.GetDockerInfo(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return nil, err
	}
	return &DockerInfoView{
		ID:                info.ID,
		Name:              info.Name,
		ServerVersion:     info.ServerVersion,
		APIVersion:        info.APIVersion,
		OS:                info.OperatingSystem,
		OSType:            info.OSType,
		Architecture:      info.Architecture,
		KernelVersion:     info.KernelVersion,
		Containers:        info.Containers,
		ContainersRunning: info.ContainersRunning,
		ContainersPaused:  info.ContainersPaused,
		ContainersStopped: info.ContainersStopped,
		Images:            info.Images,
		MemTotal:          info.MemTotal,
		NCPU:              info.NCPU,
		DockerRootDir:     info.DockerRootDir,
		StorageDriver:     info.StorageDriver,
		LoggingDriver:     info.LoggingDriver,
		CgroupDriver:      info.CgroupDriver,
		CgroupVersion:     info.CgroupVersion,
		DefaultRuntime:    info.DefaultRuntime,
		SecurityOptions:   info.SecurityOptions,
		Runtimes:          info.RuntimeNames,
		Swarm:             info.SwarmActive,
	}, nil
}

func (a *hostAdapter) List(ctx context.Context) ([]HostView, error) {
	if a.svc == nil {
		return nil, nil
	}

	summaries, err := a.svc.ListSummaries(ctx)
	if err != nil {
		return nil, err
	}

	views := make([]HostView, 0, len(summaries))
	for _, s := range summaries {
		v := HostView{
			ID:                s.ID.String(),
			Name:              s.Name,
			EndpointType:      string(s.EndpointType),
			Status:            string(s.Status),
			TLSEnabled:        s.TLSEnabled,
			Containers:        s.ContainerCount,
			ContainersRunning: s.RunningCount,
		}
		if s.DisplayName != nil {
			v.DisplayName = *s.DisplayName
		}
		if s.EndpointURL != nil {
			v.Endpoint = *s.EndpointURL
		} else if s.EndpointType == models.EndpointLocal {
			v.Endpoint = "unix://" + dockerpkg.LocalSocketPath()
		}
		if s.DockerVersion != nil {
			v.DockerVersion = *s.DockerVersion
		}
		if s.OSType != nil {
			v.OS = *s.OSType
		}
		if s.Architecture != nil {
			v.Arch = *s.Architecture
		}
		if s.TotalCPUs != nil {
			v.CPUs = *s.TotalCPUs
		}
		if s.TotalMemory != nil {
			v.Memory = *s.TotalMemory
			mb := *s.TotalMemory / (1024 * 1024)
			if mb >= 1024 {
				v.MemoryHuman = fmt.Sprintf("%.1f GB", float64(mb)/1024)
			} else {
				v.MemoryHuman = fmt.Sprintf("%d MB", mb)
			}
		}
		if s.LastSeenAt != nil {
			v.LastSeen = *s.LastSeenAt
			dur := time.Since(*s.LastSeenAt)
			switch {
			case dur < time.Minute:
				v.LastSeenHuman = "just now"
			case dur < time.Hour:
				v.LastSeenHuman = fmt.Sprintf("%dm ago", int(dur.Minutes()))
			case dur < 24*time.Hour:
				v.LastSeenHuman = fmt.Sprintf("%dh ago", int(dur.Hours()))
			default:
				v.LastSeenHuman = s.LastSeenAt.Format("2006-01-02 15:04")
			}
		}
		views = append(views, v)
	}

	return views, nil
}

func (a *hostAdapter) Get(ctx context.Context, id string) (*HostView, error) {
	if a.svc == nil {
		return nil, nil
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid host ID: %w", err)
	}
	h, err := a.svc.Get(ctx, uid)
	if err != nil {
		return nil, err
	}
	v := &HostView{
		ID:           h.ID.String(),
		Name:         h.Name,
		EndpointType: string(h.EndpointType),
		Status:       string(h.Status),
		TLSEnabled:   h.TLSEnabled,
	}
	if h.DisplayName != nil {
		v.DisplayName = *h.DisplayName
	}
	if h.EndpointURL != nil {
		v.Endpoint = *h.EndpointURL
	} else if h.EndpointType == models.EndpointLocal {
		v.Endpoint = "unix://" + dockerpkg.LocalSocketPath()
	}
	if h.DockerVersion != nil {
		v.DockerVersion = *h.DockerVersion
	}
	if h.OSType != nil {
		v.OS = *h.OSType
	}
	if h.Architecture != nil {
		v.Arch = *h.Architecture
	}
	if h.TotalCPUs != nil {
		v.CPUs = *h.TotalCPUs
	}
	if h.TotalMemory != nil {
		v.Memory = *h.TotalMemory
		mb := *h.TotalMemory / (1024 * 1024)
		if mb >= 1024 {
			v.MemoryHuman = fmt.Sprintf("%.1f GB", float64(mb)/1024)
		} else {
			v.MemoryHuman = fmt.Sprintf("%d MB", mb)
		}
	}
	if h.LastSeenAt != nil {
		v.LastSeen = *h.LastSeenAt
		dur := time.Since(*h.LastSeenAt)
		switch {
		case dur < time.Minute:
			v.LastSeenHuman = "just now"
		case dur < time.Hour:
			v.LastSeenHuman = fmt.Sprintf("%dm ago", int(dur.Minutes()))
		case dur < 24*time.Hour:
			v.LastSeenHuman = fmt.Sprintf("%dh ago", int(dur.Hours()))
		default:
			v.LastSeenHuman = h.LastSeenAt.Format("2006-01-02 15:04")
		}
	}

	// Enrich with Docker info (images count, kernel version) if host is online
	if h.Status == models.HostStatusOnline {
		info, err := a.svc.GetDockerInfo(ctx, uid)
		if err == nil && info != nil {
			v.Images = info.Images
			v.KernelVersion = info.KernelVersion
			// Fill container counts from live data if not already set
			if v.Containers == 0 {
				v.Containers = info.Containers
				v.ContainersRunning = info.ContainersRunning
			}
		}
	}

	return v, nil
}

func (a *hostAdapter) Create(ctx context.Context, hv *HostView) (string, error) {
	if a.svc == nil {
		return "", fmt.Errorf("host service not initialized")
	}
	input := &models.CreateHostInput{
		Name:         hv.Name,
		EndpointType: models.HostEndpointType(hv.EndpointType),
		TLSEnabled:   hv.TLSEnabled,
	}
	if hv.Endpoint != "" {
		input.EndpointURL = &hv.Endpoint
	}
	if hv.DisplayName != "" {
		input.DisplayName = &hv.DisplayName
	}
	host, err := a.svc.Create(ctx, input)
	if err != nil {
		return "", err
	}
	return host.ID.String(), nil
}

func (a *hostAdapter) Update(ctx context.Context, hv *HostView) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}
	uid, err := uuid.Parse(hv.ID)
	if err != nil {
		return fmt.Errorf("invalid host ID: %w", err)
	}
	input := &models.UpdateHostInput{}
	if hv.DisplayName != "" {
		input.DisplayName = &hv.DisplayName
	}
	if hv.Endpoint != "" {
		input.EndpointURL = &hv.Endpoint
	}
	// Always pass TLS enabled state so it can be toggled off
	input.TLSEnabled = &hv.TLSEnabled
	_, err = a.svc.Update(ctx, uid, input)
	return err
}

func (a *hostAdapter) Remove(ctx context.Context, id string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid host ID: %w", err)
	}
	return a.svc.Delete(ctx, uid)
}

func (a *hostAdapter) Test(ctx context.Context, id string) error {
	// Host service health checks run automatically
	return nil
}

func (a *hostAdapter) GenerateAgentToken(ctx context.Context, id string) (string, error) {
	if a.svc == nil {
		return "", fmt.Errorf("host service not initialized")
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		return "", fmt.Errorf("invalid host ID: %w", err)
	}
	return a.svc.GenerateAgentToken(ctx, uid)
}

func (a *hostAdapter) GetMetrics(ctx context.Context, id string) (*HostMetricsView, error) {
	if a.svc == nil {
		return nil, nil
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid host ID: %w", err)
	}
	m, err := a.svc.GetMetrics(ctx, uid)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, nil
	}
	return &HostMetricsView{
		CPUPercent:    m.CPUPercent,
		MemoryUsed:    m.MemoryUsed,
		MemoryPercent: m.MemoryPercent,
		MemoryUsedStr: humanSize(m.MemoryUsed),
		DiskPercent:   m.DiskPercent,
		DiskUsedStr:   humanSize(m.DiskUsed),
		DiskTotalStr:  humanSize(m.DiskTotal),
		NetworkRxStr:  humanSize(m.NetworkRxBytes),
		NetworkTxStr:  humanSize(m.NetworkTxBytes),
	}, nil
}
