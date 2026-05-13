// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package update

import (
	"context"
	"strings"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/google/uuid"

	dockerpkg "github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
)

// HostClientProvider provides Docker clients for a given host.
type HostClientProvider interface {
	GetClient(ctx context.Context, hostID uuid.UUID) (dockerpkg.ClientAPI, error)
}

// DockerClientAdapter adapts a host-based Docker client pool to the DockerClient
// interface required by the update service. It resolves the client lazily on each call.
type DockerClientAdapter struct {
	provider HostClientProvider
	hostID   uuid.UUID
}

// NewDockerClientAdapter wraps a host client provider to implement DockerClient.
func NewDockerClientAdapter(provider HostClientProvider, hostID uuid.UUID) *DockerClientAdapter {
	return &DockerClientAdapter{provider: provider, hostID: hostID}
}

func (a *DockerClientAdapter) getClient(ctx context.Context) (dockerpkg.ClientAPI, error) {
	return a.provider.GetClient(ctx, a.hostID)
}

func (a *DockerClientAdapter) ContainerInspect(ctx context.Context, containerID string) (*dockertypes.ContainerJSON, error) {
	c, err := a.getClient(ctx)
	if err != nil {
		return nil, err
	}
	inspect, err := c.ContainerInspectRaw(ctx, containerID)
	if err != nil {
		return nil, err
	}
	return &inspect, nil
}

func (a *DockerClientAdapter) ContainerStop(ctx context.Context, containerID string, timeout *int) error {
	c, err := a.getClient(ctx)
	if err != nil {
		return err
	}
	return c.ContainerStop(ctx, containerID, timeout)
}

func (a *DockerClientAdapter) ContainerStart(ctx context.Context, containerID string) error {
	c, err := a.getClient(ctx)
	if err != nil {
		return err
	}
	return c.ContainerStart(ctx, containerID)
}

func (a *DockerClientAdapter) ContainerRemove(ctx context.Context, containerID string, force bool) error {
	c, err := a.getClient(ctx)
	if err != nil {
		return err
	}
	return c.ContainerRemove(ctx, containerID, force, false)
}

func (a *DockerClientAdapter) ContainerCreate(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, name string) (string, error) {
	c, err := a.getClient(ctx)
	if err != nil {
		return "", err
	}
	// Raw container creation requires a direct Docker client
	directClient, ok := c.(*dockerpkg.Client)
	if !ok {
		return "", errors.New(errors.CodeDockerConnection, "container creation with raw SDK types not supported for remote hosts")
	}
	cli := directClient.Raw()
	if cli == nil {
		return "", errors.New(errors.CodeDockerConnection, "docker client is closed")
	}
	resp, err := cli.ContainerCreate(ctx, config, hostConfig, nil, nil, name)
	if err != nil {
		return "", err
	}
	return resp.ID, nil
}

func (a *DockerClientAdapter) ContainerRename(ctx context.Context, containerID, newName string) error {
	c, err := a.getClient(ctx)
	if err != nil {
		return err
	}
	return c.ContainerRename(ctx, containerID, newName)
}

func (a *DockerClientAdapter) ContainerList(ctx context.Context) ([]ContainerInfo, error) {
	c, err := a.getClient(ctx)
	if err != nil {
		return nil, err
	}
	containers, err := c.ContainerList(ctx, dockerpkg.ContainerListOptions{All: true})
	if err != nil {
		return nil, err
	}
	result := make([]ContainerInfo, 0, len(containers))
	for _, ct := range containers {
		// ImageID contains the image digest (sha256:...) which enables
		// accurate update detection for "latest" tagged containers.
		digest := ct.ImageID
		if digest != "" && !strings.HasPrefix(digest, "sha256:") {
			digest = ""
		}
		result = append(result, ContainerInfo{
			ID:     ct.ID,
			Name:   ct.Name,
			Image:  ct.Image,
			Digest: digest,
		})
	}
	return result, nil
}

func (a *DockerClientAdapter) ImagePull(ctx context.Context, ref string, onProgress func(status string)) error {
	c, err := a.getClient(ctx)
	if err != nil {
		return err
	}
	progressCh, err := c.ImagePull(ctx, ref, dockerpkg.ImagePullOptions{})
	if err != nil {
		return err
	}
	for p := range progressCh {
		if onProgress != nil {
			onProgress(p.Status)
		}
	}
	return nil
}

func (a *DockerClientAdapter) ImageInspect(ctx context.Context, imageID string) (*ImageInfo, error) {
	c, err := a.getClient(ctx)
	if err != nil {
		return nil, err
	}
	details, err := c.ImageGet(ctx, imageID)
	if err != nil {
		return nil, err
	}
	return &ImageInfo{
		ID:          details.ID,
		RepoTags:    details.RepoTags,
		RepoDigests: details.RepoDigests,
		Created:     details.Created,
		Size:        details.Size,
		Labels:      details.Labels,
	}, nil
}

