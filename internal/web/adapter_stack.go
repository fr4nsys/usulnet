// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	stacksvc "github.com/fr4nsys/usulnet/internal/services/stack"
)

type stackAdapter struct {
	svc      *stacksvc.Service
	userRepo *postgres.UserRepository
	hostID   uuid.UUID
}

func (a *stackAdapter) List(ctx context.Context) ([]StackView, error) {
	if a.svc == nil {
		return nil, nil
	}

	// Get managed stacks from database
	stacks, _, err := a.svc.List(ctx, postgres.StackListOptions{Page: 1, PerPage: 100})
	if err != nil {
		return nil, err
	}

	// Track managed stack names to avoid duplicates
	managedNames := make(map[string]bool)
	views := make([]StackView, 0, len(stacks))

	for _, s := range stacks {
		managedNames[s.Name] = true
		view := stackToView(s)

		// Enrich with live container data from Docker
		containers, err := a.svc.GetContainers(ctx, s.ID)
		if err == nil && len(containers) > 0 {
			running := 0
			var names []string
			for _, c := range containers {
				names = append(names, c.Name)
				if c.State == models.ContainerStateRunning {
					running++
				}
			}
			view.ContainerNames = names
			view.RunningCount = running
			if view.ServiceCount == 0 {
				view.ServiceCount = len(containers)
			}
			// Update status based on live data
			if running == 0 {
				view.Status = string(models.StackStatusInactive)
			} else if running < view.ServiceCount {
				view.Status = string(models.StackStatusPartial)
			} else {
				view.Status = string(models.StackStatusActive)
			}
		}

		views = append(views, view)
	}

	// Discover external Docker Compose projects (not managed by usulnet)
	discovered, err := a.svc.DiscoverComposeProjects(ctx, resolveHostID(ctx, a.hostID))
	if err == nil && len(discovered) > 0 {
		for _, d := range discovered {
			// Skip if already managed by usulnet
			if managedNames[d.Name] {
				continue
			}

			// Determine status
			status := string(models.StackStatusInactive)
			if d.RunningCount > 0 && d.RunningCount >= d.ServiceCount {
				status = string(models.StackStatusActive)
			} else if d.RunningCount > 0 {
				status = string(models.StackStatusPartial)
			}

			view := StackView{
				Name:         d.Name,
				Status:       status,
				ServiceCount: d.ServiceCount,
				RunningCount: d.RunningCount,
				Path:         d.WorkingDir,
				IsExternal:   true, // Mark as external/discovered
			}

			// Add service/container names
			var containerNames []string
			for _, svc := range d.Services {
				containerNames = append(containerNames, svc.Name)
			}
			view.ContainerNames = containerNames

			views = append(views, view)
		}
	}

	return views, nil
}

func (a *stackAdapter) Get(ctx context.Context, name string) (*StackView, error) {
	if a.svc == nil {
		return nil, nil
	}

	// First try to get from database (managed stacks)
	s, err := a.svc.GetByName(ctx, resolveHostID(ctx, a.hostID), name)
	if err == nil && s != nil {
		view := stackToView(s)
		return &view, nil
	}

	// Not found in database, check for external/discovered stacks
	discovered, discErr := a.svc.DiscoverComposeProjects(ctx, resolveHostID(ctx, a.hostID))
	if discErr == nil {
		for _, d := range discovered {
			if d.Name == name {
				// Found as external stack
				status := string(models.StackStatusInactive)
				if d.RunningCount > 0 && d.RunningCount >= d.ServiceCount {
					status = string(models.StackStatusActive)
				} else if d.RunningCount > 0 {
					status = string(models.StackStatusPartial)
				}

				view := StackView{
					Name:         d.Name,
					Status:       status,
					ServiceCount: d.ServiceCount,
					RunningCount: d.RunningCount,
					Path:         d.WorkingDir,
					IsExternal:   true,
				}

				var containerNames []string
				for _, svc := range d.Services {
					containerNames = append(containerNames, svc.Name)
				}
				view.ContainerNames = containerNames

				return &view, nil
			}
		}
	}

	// Return original error if not found anywhere
	return nil, err
}

func (a *stackAdapter) Deploy(ctx context.Context, name, composeFile string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}

	input := &models.CreateStackInput{
		Name:        name,
		ComposeFile: composeFile,
	}

	slog.Info("stackAdapter.Deploy: creating stack", "name", name)
	stack, err := a.svc.Create(ctx, resolveHostID(ctx, a.hostID), input)
	if err != nil {
		slog.Error("stackAdapter.Deploy: create failed", "name", name, "error", err)
		return err
	}
	slog.Info("stackAdapter.Deploy: stack created, deploying", "name", name, "id", stack.ID)

	result, err := a.svc.Deploy(ctx, stack.ID)
	if err != nil {
		slog.Error("stackAdapter.Deploy: deploy returned error, cleaning up", "name", name, "error", err)
		// Clean up the DB record so the user can retry with the same name
		if delErr := a.svc.Delete(ctx, stack.ID, true); delErr != nil {
			slog.Warn("stackAdapter.Deploy: failed to clean up stack after deploy error", "name", name, "error", delErr)
		}
		return err
	}
	if result != nil && !result.Success {
		slog.Error("stackAdapter.Deploy: deploy failed, cleaning up",
			"name", name,
			"output", result.Output,
			"error", result.Error,
		)
		// Clean up the DB record so the user can retry with the same name
		if delErr := a.svc.Delete(ctx, stack.ID, true); delErr != nil {
			slog.Warn("stackAdapter.Deploy: failed to clean up stack after deploy failure", "name", name, "error", delErr)
		}
		return fmt.Errorf("docker compose failed: %s\nOutput: %s", result.Error, result.Output)
	}
	slog.Info("stackAdapter.Deploy: deploy succeeded", "name", name)
	return nil
}

func (a *stackAdapter) Start(ctx context.Context, name string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}

	s, err := a.svc.GetByName(ctx, resolveHostID(ctx, a.hostID), name)
	if err != nil {
		return err
	}

	return a.svc.Start(ctx, s.ID)
}

func (a *stackAdapter) Stop(ctx context.Context, name string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}

	s, err := a.svc.GetByName(ctx, resolveHostID(ctx, a.hostID), name)
	if err != nil {
		return err
	}

	return a.svc.Stop(ctx, s.ID, false)
}

func (a *stackAdapter) Restart(ctx context.Context, name string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}

	s, err := a.svc.GetByName(ctx, resolveHostID(ctx, a.hostID), name)
	if err != nil {
		return err
	}

	return a.svc.Restart(ctx, s.ID)
}

func (a *stackAdapter) Remove(ctx context.Context, name string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}

	s, err := a.svc.GetByName(ctx, resolveHostID(ctx, a.hostID), name)
	if err != nil {
		return err
	}

	return a.svc.Delete(ctx, s.ID, false)
}

func (a *stackAdapter) GetServices(ctx context.Context, name string) ([]StackServiceView, error) {
	if a.svc == nil {
		return nil, nil
	}

	// First try to get from database (managed stacks)
	s, err := a.svc.GetByName(ctx, resolveHostID(ctx, a.hostID), name)
	var containers []*models.Container

	if err == nil && s != nil {
		// Get live containers for this managed stack
		containers, err = a.svc.GetContainers(ctx, s.ID)
		if err != nil {
			containers = nil // Continue without container data
		}
	} else {
		// External stack: get containers by project label
		discovered, discErr := a.svc.DiscoverComposeProjects(ctx, resolveHostID(ctx, a.hostID))
		if discErr == nil {
			for _, d := range discovered {
				if d.Name == name {
					// Convert discovered services to container views
					for _, svc := range d.Services {
						containers = append(containers, &models.Container{
							ID:     svc.ContainerID,
							Name:   svc.Name,
							Image:  svc.Image,
							Status: svc.Status,
							State:  models.ContainerState(svc.State),
							Labels: map[string]string{
								"com.docker.compose.service": svc.Name,
							},
						})
					}
					break
				}
			}
		}
		// Reset error since we found services
		if len(containers) > 0 {
			err = nil
		}
	}

	// Build views from live containers (keyed by compose service name)
	viewMap := make(map[string]*StackServiceView)
	for _, c := range containers {
		if c.Labels == nil {
			continue
		}
		svcName := c.Labels["com.docker.compose.service"]
		if svcName == "" {
			continue
		}

		view := &StackServiceView{
			Name:          svcName,
			Image:         c.Image,
			ContainerID:   c.ID,
			ContainerName: c.Name,
			Status:        c.Status,
			State:         string(c.State),
			Replicas:      "1/1",
		}
		// Build port strings
		for _, p := range c.Ports {
			if p.PublicPort > 0 {
				view.Ports = append(view.Ports, fmt.Sprintf("%d:%d/%s", p.PublicPort, p.PrivatePort, p.Type))
			} else {
				view.Ports = append(view.Ports, fmt.Sprintf("%d/%s", p.PrivatePort, p.Type))
			}
		}
		viewMap[svcName] = view
	}

	// Enrich with live status from compose ps (only for managed stacks)
	if s != nil {
		status, statusErr := a.svc.GetStatus(ctx, s.ID)
		if statusErr == nil && status != nil {
			for _, ss := range status.Services {
				if v, ok := viewMap[ss.Name]; ok {
					v.Replicas = fmt.Sprintf("%d/%d", ss.Running, ss.Desired)
					if ss.Status != "" {
						v.Status = ss.Status
					}
				} else {
					// Service exists in compose but has no container yet
					state := "stopped"
					if ss.Running > 0 {
						state = "running"
					}
					viewMap[ss.Name] = &StackServiceView{
						Name:     ss.Name,
						Status:   ss.Status,
						State:    state,
						Replicas: fmt.Sprintf("%d/%d", ss.Running, ss.Desired),
					}
				}
			}
		}
	}

	// Convert map to sorted slice
	var views []StackServiceView
	for _, v := range viewMap {
		views = append(views, *v)
	}

	// If no data from containers or status, parse compose file for service names (only for managed stacks)
	if len(views) == 0 && s != nil && s.ComposeFile != "" {
		type composeStruct struct {
			Services map[string]struct {
				Image string `yaml:"image"`
			} `yaml:"services"`
		}
		var cs composeStruct
		if err := yaml.Unmarshal([]byte(s.ComposeFile), &cs); err == nil {
			for svcName, svcDef := range cs.Services {
				views = append(views, StackServiceView{
					Name:     svcName,
					Image:    svcDef.Image,
					Status:   "unknown",
					State:    "unknown",
					Replicas: "0/1",
				})
			}
		}
	}

	return views, nil
}

func (a *stackAdapter) GetComposeConfig(ctx context.Context, name string) (string, error) {
	if a.svc == nil {
		return "", nil
	}

	s, err := a.svc.GetByName(ctx, resolveHostID(ctx, a.hostID), name)
	if err != nil {
		return "", err
	}

	config, err := a.svc.GetComposeConfig(ctx, s.ID)
	if err != nil {
		// Fallback to stored compose file
		return s.ComposeFile, nil
	}
	return config, nil
}

func (a *stackAdapter) ListVersions(ctx context.Context, name string) ([]StackVersionView, error) {
	if a.svc == nil {
		return nil, nil
	}

	s, err := a.svc.GetByName(ctx, resolveHostID(ctx, a.hostID), name)
	if err != nil {
		return nil, err
	}

	versions, err := a.svc.ListVersions(ctx, s.ID)
	if err != nil {
		return nil, err
	}

	views := make([]StackVersionView, 0, len(versions))
	for _, v := range versions {
		createdBy := ""
		if v.CreatedBy != nil && a.userRepo != nil {
			user, err := a.userRepo.GetByID(ctx, *v.CreatedBy)
			if err == nil && user != nil {
				createdBy = user.Username
			}
		}
		views = append(views, StackVersionView{
			Version:    v.Version,
			Comment:    v.Comment,
			CreatedAt:  v.CreatedAt.Format("Jan 2, 2006 15:04"),
			CreatedBy:  createdBy,
			IsDeployed: v.IsDeployed,
		})
	}

	return views, nil
}
