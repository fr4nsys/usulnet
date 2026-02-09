// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package container provides container management services.
// This file adds Config Manager integration for environment variable synchronization.
package container

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	configservice "github.com/fr4nsys/usulnet/internal/services/config"
)

// ============================================================================
// Config Integration Types
// ============================================================================

// RecreateWithEnvOptions extends RecreateOptions with environment configuration.
type RecreateWithEnvOptions struct {
	PullImage        bool
	ImageTag         string
	NewEnv           map[string]string
	RemoveEnv        []string
	TemplateID       *uuid.UUID
	PreserveVolumes  bool
	PreserveNetworks bool
	RemoveOld        bool
}

// ============================================================================
// Recreate with Environment Variables
// ============================================================================

// RecreateWithEnv recreates a container with new environment variables.
func (s *Service) RecreateWithEnv(ctx context.Context, hostID uuid.UUID, containerID string, opts RecreateWithEnvOptions) (*models.Container, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	// Get current container info
	oldInspect, err := client.ContainerGet(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("inspect container: %w", err)
	}

	// Determine new image
	newImage := oldInspect.Image
	if opts.ImageTag != "" {
		newImage = opts.ImageTag
	}

	// Pull image if requested
	if opts.PullImage {
		s.logger.Info("pulling image for recreate", "image", newImage)
		if err := client.ImagePullSync(ctx, newImage, docker.ImagePullOptions{}); err != nil {
			return nil, fmt.Errorf("pull image: %w", err)
		}
	}

	// Store old container name
	oldName := oldInspect.Name
	tempName := fmt.Sprintf("%s_old_%d", oldName, time.Now().Unix())

	// Rename old container to temp name
	if err := client.ContainerRename(ctx, containerID, tempName); err != nil {
		return nil, fmt.Errorf("rename old container: %w", err)
	}

	// Stop old container if running
	wasRunning := oldInspect.State == "running"
	if wasRunning {
		timeout := int(s.config.StopTimeout.Seconds())
		if err := client.ContainerStop(ctx, containerID, &timeout); err != nil {
			client.ContainerRename(ctx, containerID, oldName)
			return nil, fmt.Errorf("stop old container: %w", err)
		}
	}

	// Build new environment from Config.Env
	var oldEnv []string
	if oldInspect.Config != nil {
		oldEnv = oldInspect.Config.Env
	}
	newEnv := mergeEnv(oldEnv, opts.NewEnv, opts.RemoveEnv)

	// Build port bindings from old container Ports
	portBindings := make(map[string][]docker.PortBinding)
	for _, p := range oldInspect.Ports {
		key := fmt.Sprintf("%d/%s", p.PrivatePort, p.Type)
		if p.PublicPort > 0 {
			portBindings[key] = append(portBindings[key], docker.PortBinding{
				HostIP:   p.IP,
				HostPort: fmt.Sprintf("%d", p.PublicPort),
			})
		}
	}

	// Build create options
	createOpts := docker.ContainerCreateOptions{
		Name:         oldName,
		Image:        newImage,
		Env:          newEnv,
		Labels:       oldInspect.Labels,
		PortBindings: portBindings,
	}

	// Preserve volumes if requested - use Binds from HostConfig
	if opts.PreserveVolumes && oldInspect.HostConfig != nil {
		createOpts.Binds = oldInspect.HostConfig.Binds
	}

	// Create new container
	newContainerID, err := client.ContainerCreate(ctx, createOpts)
	if err != nil {
		client.ContainerRename(ctx, containerID, oldName)
		if wasRunning {
			client.ContainerStart(ctx, containerID)
		}
		return nil, fmt.Errorf("create new container: %w", err)
	}

	// Connect to networks if requested
	if opts.PreserveNetworks {
		for _, net := range oldInspect.Networks {
			if net.NetworkName == "bridge" || net.NetworkName == "host" || net.NetworkName == "none" {
				continue
			}
			if err := client.NetworkConnect(ctx, net.NetworkID, docker.NetworkConnectOptions{
				ContainerID: newContainerID,
			}); err != nil {
				s.logger.Warn("failed to connect to network", "network", net.NetworkName, "error", err)
			}
		}
	}

	// Start new container if old was running
	if wasRunning {
		if err := client.ContainerStart(ctx, newContainerID); err != nil {
			client.ContainerRemove(ctx, newContainerID, true, false)
			client.ContainerRename(ctx, containerID, oldName)
			client.ContainerStart(ctx, containerID)
			return nil, fmt.Errorf("start new container: %w", err)
		}
	}

	// Remove old container if requested
	if opts.RemoveOld {
		if err := client.ContainerRemove(ctx, containerID, true, false); err != nil {
			s.logger.Warn("failed to remove old container", "container", containerID, "error", err)
		}
	}

	// Get new container details
	newInspect, err := client.ContainerGet(ctx, newContainerID)
	if err != nil {
		return nil, fmt.Errorf("get new container: %w", err)
	}

	return s.detailsToModel(newInspect, hostID), nil
}

// detailsToModel converts ContainerDetails to models.Container
func (s *Service) detailsToModel(d *docker.ContainerDetails, hostID uuid.UUID) *models.Container {
	imageID := d.ImageID
	created := d.Created
	c := &models.Container{
		ID:              d.ID,
		HostID:          hostID,
		Name:            d.Name,
		Image:           d.Image,
		ImageID:         &imageID,
		State:           models.ContainerState(d.State),
		Status:          d.Status,
		CreatedAtDocker: &created,
	}

	// Copy network attachments
	for _, n := range d.Networks {
		c.Networks = append(c.Networks, models.NetworkAttachment{
			NetworkID:   n.NetworkID,
			NetworkName: n.NetworkName,
			IPAddress:   n.IPAddress,
			Gateway:     n.Gateway,
			MacAddress:  n.MacAddress,
			Aliases:     n.Aliases,
		})
	}

	// Copy port mappings
	for _, p := range d.Ports {
		c.Ports = append(c.Ports, models.PortMapping{
			PrivatePort: p.PrivatePort,
			PublicPort:  p.PublicPort,
			Type:        p.Type,
			IP:          p.IP,
		})
	}

	// Copy mount points
	for _, m := range d.Mounts {
		c.Mounts = append(c.Mounts, models.MountPoint{
			Type:        m.Type,
			Source:      m.Source,
			Destination: m.Destination,
			Mode:        m.Mode,
			RW:          m.RW,
			Propagation: m.Propagation,
		})
	}

	return c
}

// mergeEnv merges environment variables.
func mergeEnv(oldEnv []string, newEnv map[string]string, removeEnv []string) []string {
	envMap := make(map[string]string)
	for _, e := range oldEnv {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}
	for _, key := range removeEnv {
		delete(envMap, key)
	}
	for k, v := range newEnv {
		envMap[k] = v
	}
	result := make([]string, 0, len(envMap))
	for k, v := range envMap {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}
	return result
}

// ============================================================================
// Config Service Integration
// ============================================================================

// SetConfigService sets the config service for variable synchronization.
func (s *Service) SetConfigService(configSvc *configservice.Service) {
	s.configService = configSvc
}

// SyncConfigToContainer applies config variables to a container.
func (s *Service) SyncConfigToContainer(ctx context.Context, hostID uuid.UUID, containerID string, variables []*models.ConfigVariable) error {
	if len(variables) == 0 {
		return nil
	}
	newEnv := make(map[string]string)
	for _, v := range variables {
		if v.Value != "" {
			newEnv[v.Name] = v.Value
		}
	}
	_, err := s.RecreateWithEnv(ctx, hostID, containerID, RecreateWithEnvOptions{
		NewEnv:           newEnv,
		PreserveVolumes:  true,
		PreserveNetworks: true,
		RemoveOld:        true,
	})
	return err
}

// GetContainerEnv retrieves environment variables from a container.
func (s *Service) GetContainerEnv(ctx context.Context, hostID uuid.UUID, containerID string) (map[string]string, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}
	details, err := client.ContainerGet(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("inspect container: %w", err)
	}
	envMap := make(map[string]string)
	if details.Config != nil {
		for _, e := range details.Config.Env {
			parts := strings.SplitN(e, "=", 2)
			if len(parts) == 2 {
				envMap[parts[0]] = parts[1]
			}
		}
	}
	return envMap, nil
}
