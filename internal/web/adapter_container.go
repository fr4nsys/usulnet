// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	containersvc "github.com/fr4nsys/usulnet/internal/services/container"
)

type containerAdapter struct {
	svc    *containersvc.Service
	hostID uuid.UUID
}

func (a *containerAdapter) List(ctx context.Context, filters map[string]string) ([]ContainerView, error) {
	if a.svc == nil {
		return []ContainerView{}, nil
	}

	hostID := resolveHostID(ctx, a.hostID)
	opts := postgres.ContainerListOptions{
		HostID:  &hostID,
		Page:    1,
		PerPage: 500,
	}
	if search := filters["search"]; search != "" {
		opts.Search = search
	}
	if search := filters["name"]; search != "" {
		opts.Search = search
	}
	if stateStr := filters["state"]; stateStr != "" {
		state := models.ContainerState(stateStr)
		opts.State = &state
	}

	containers, _, err := a.svc.List(ctx, opts)
	if err != nil {
		return nil, err
	}

	views := make([]ContainerView, 0, len(containers))
	for _, c := range containers {
		views = append(views, containerToView(c))
	}
	return views, nil
}

func (a *containerAdapter) Get(ctx context.Context, id string) (*ContainerView, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}

	c, err := a.svc.Get(ctx, resolveHostID(ctx, a.hostID), id)
	if err != nil {
		return nil, err
	}

	view := containerToView(c)
	return &view, nil
}

func (a *containerAdapter) Start(ctx context.Context, id string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}
	return a.svc.StartContainer(ctx, resolveHostID(ctx, a.hostID), id)
}

func (a *containerAdapter) Stop(ctx context.Context, id string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}
	return a.svc.StopContainer(ctx, resolveHostID(ctx, a.hostID), id)
}

func (a *containerAdapter) Restart(ctx context.Context, id string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}
	return a.svc.Restart(ctx, resolveHostID(ctx, a.hostID), id)
}

func (a *containerAdapter) Pause(ctx context.Context, id string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}
	return a.svc.Pause(ctx, resolveHostID(ctx, a.hostID), id)
}

func (a *containerAdapter) Unpause(ctx context.Context, id string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}
	return a.svc.Unpause(ctx, resolveHostID(ctx, a.hostID), id)
}

func (a *containerAdapter) Kill(ctx context.Context, id string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}
	return a.svc.Kill(ctx, resolveHostID(ctx, a.hostID), id, "SIGKILL")
}

func (a *containerAdapter) Remove(ctx context.Context, id string, force bool) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}
	return a.svc.Remove(ctx, resolveHostID(ctx, a.hostID), id, force, false)
}

func (a *containerAdapter) Rename(ctx context.Context, id, name string) error {
	if a.svc == nil {
		return fmt.Errorf("container service not available")
	}
	return a.svc.Rename(ctx, resolveHostID(ctx, a.hostID), id, name)
}

// BulkOperationResult represents the result of a single container operation.
type BulkOperationResult struct {
	ContainerID string
	Name        string
	Success     bool
	Error       string
}

// BulkOperationResults represents the results of a bulk operation.
type BulkOperationResults struct {
	Total      int
	Successful int
	Failed     int
	Results    []BulkOperationResult
}

func (a *containerAdapter) BulkStart(ctx context.Context, containerIDs []string) (*BulkOperationResults, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}

	results, err := a.svc.BulkStart(ctx, resolveHostID(ctx, a.hostID), containerIDs)
	if err != nil {
		return nil, err
	}

	return convertBulkResults(results), nil
}

func (a *containerAdapter) BulkStop(ctx context.Context, containerIDs []string) (*BulkOperationResults, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}

	results, err := a.svc.BulkStop(ctx, resolveHostID(ctx, a.hostID), containerIDs)
	if err != nil {
		return nil, err
	}

	return convertBulkResults(results), nil
}

func (a *containerAdapter) BulkRestart(ctx context.Context, containerIDs []string) (*BulkOperationResults, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}

	results, err := a.svc.BulkRestart(ctx, resolveHostID(ctx, a.hostID), containerIDs)
	if err != nil {
		return nil, err
	}

	return convertBulkResults(results), nil
}

func (a *containerAdapter) BulkPause(ctx context.Context, containerIDs []string) (*BulkOperationResults, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}

	results, err := a.svc.BulkPause(ctx, resolveHostID(ctx, a.hostID), containerIDs)
	if err != nil {
		return nil, err
	}

	return convertBulkResults(results), nil
}

func (a *containerAdapter) BulkUnpause(ctx context.Context, containerIDs []string) (*BulkOperationResults, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}

	results, err := a.svc.BulkUnpause(ctx, resolveHostID(ctx, a.hostID), containerIDs)
	if err != nil {
		return nil, err
	}

	return convertBulkResults(results), nil
}

func (a *containerAdapter) BulkKill(ctx context.Context, containerIDs []string) (*BulkOperationResults, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}

	results, err := a.svc.BulkKill(ctx, resolveHostID(ctx, a.hostID), containerIDs, "SIGKILL")
	if err != nil {
		return nil, err
	}

	return convertBulkResults(results), nil
}

func (a *containerAdapter) BulkRemove(ctx context.Context, containerIDs []string, force bool) (*BulkOperationResults, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}

	results, err := a.svc.BulkRemove(ctx, resolveHostID(ctx, a.hostID), containerIDs, force, false)
	if err != nil {
		return nil, err
	}

	return convertBulkResults(results), nil
}

func convertBulkResults(results *containersvc.BulkOperationResults) *BulkOperationResults {
	converted := &BulkOperationResults{
		Total:      results.Total,
		Successful: results.Successful,
		Failed:     results.Failed,
		Results:    make([]BulkOperationResult, len(results.Results)),
	}

	for i, r := range results.Results {
		converted.Results[i] = BulkOperationResult{
			ContainerID: r.ContainerID,
			Name:        r.Name,
			Success:     r.Success,
			Error:       r.Error,
		}
	}

	return converted
}

func (a *containerAdapter) Create(ctx context.Context, input *ContainerCreateInput) (string, error) {
	if a.svc == nil {
		return "", fmt.Errorf("container service not available")
	}

	// Parse ports
	var ports []models.ContainerPort
	for _, p := range input.Ports {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		parts := strings.SplitN(p, ":", 2)
		if len(parts) != 2 {
			continue
		}
		hostPort, err1 := strconv.ParseUint(parts[0], 10, 16)
		containerPort, err2 := strconv.ParseUint(parts[1], 10, 16)
		if err1 != nil || err2 != nil {
			continue
		}
		ports = append(ports, models.ContainerPort{
			HostPort:      uint16(hostPort),
			ContainerPort: uint16(containerPort),
			Protocol:      "tcp",
		})
	}

	// Parse volumes
	var volumes []models.ContainerMount
	for _, v := range input.Volumes {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		parts := strings.SplitN(v, ":", 2)
		if len(parts) != 2 {
			continue
		}
		volumes = append(volumes, models.ContainerMount{
			Source: parts[0],
			Target: parts[1],
			Type:   "bind",
		})
	}

	// Parse environment
	var env []string
	for _, line := range strings.Split(input.Environment, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && strings.Contains(line, "=") {
			env = append(env, line)
		}
	}

	// Parse command
	var cmd []string
	if input.Command != "" {
		cmd = strings.Fields(input.Command)
	}

	// Build networks
	var networks []string
	if input.Network != "" {
		networks = []string{input.Network}
	}

	svcInput := &containersvc.CreateInput{
		Name:          input.Name,
		Image:         input.Image,
		Ports:         ports,
		Volumes:       volumes,
		Env:           env,
		Cmd:           cmd,
		Networks:      networks,
		RestartPolicy: input.RestartPolicy,
		Privileged:    input.Privileged,
	}

	container, err := a.svc.Create(ctx, resolveHostID(ctx, a.hostID), svcInput)
	if err != nil {
		return "", err
	}
	return container.ID, nil
}

func (a *containerAdapter) GetDockerClient(ctx context.Context) (docker.ClientAPI, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}
	return a.svc.GetDockerClient(ctx, resolveHostID(ctx, a.hostID))
}

func (a *containerAdapter) GetHostID() uuid.UUID {
	return a.hostID
}

func (a *containerAdapter) BrowseFiles(ctx context.Context, containerID, path string) ([]ContainerFileView, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}
	files, err := a.svc.BrowseContainer(ctx, resolveHostID(ctx, a.hostID), containerID, path)
	if err != nil {
		return nil, err
	}
	views := make([]ContainerFileView, len(files))
	for i, f := range files {
		views[i] = ContainerFileView{
			Name: f.Name, Path: f.Path, IsDir: f.IsDir, Size: f.Size,
			SizeHuman: f.SizeHuman, Mode: f.Mode, ModTime: f.ModTime.Format(time.RFC3339),
			ModTimeAgo: f.ModTimeAgo, Owner: f.Owner, Group: f.Group,
			LinkTarget: f.LinkTarget, IsSymlink: f.IsSymlink,
		}
	}
	return views, nil
}

func (a *containerAdapter) ReadFile(ctx context.Context, containerID, path string) (*ContainerFileContentView, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("container service not available")
	}
	content, err := a.svc.ReadContainerFile(ctx, resolveHostID(ctx, a.hostID), containerID, path, 10*1024*1024)
	if err != nil {
		return nil, err
	}
	return &ContainerFileContentView{
		Path: content.Path, Content: content.Content, Size: content.Size,
		Truncated: content.Truncated, Binary: content.Binary,
	}, nil
}

func (a *containerAdapter) WriteFile(ctx context.Context, containerID, path, content string) error {
	if a.svc == nil {
		return fmt.Errorf("container service not available")
	}
	return a.svc.WriteContainerFile(ctx, resolveHostID(ctx, a.hostID), containerID, path, content)
}

func (a *containerAdapter) DeleteFile(ctx context.Context, containerID, path string, recursive bool) error {
	if a.svc == nil {
		return fmt.Errorf("container service not available")
	}
	return a.svc.DeleteContainerFile(ctx, resolveHostID(ctx, a.hostID), containerID, path, recursive)
}

func (a *containerAdapter) CreateDirectory(ctx context.Context, containerID, path string) error {
	if a.svc == nil {
		return fmt.Errorf("container service not available")
	}
	return a.svc.CreateContainerDirectory(ctx, resolveHostID(ctx, a.hostID), containerID, path)
}

func (a *containerAdapter) GetLogs(ctx context.Context, id string, tail int) ([]string, error) {
	if a.svc == nil {
		return nil, ErrServiceNotConfigured
	}

	reader, err := a.svc.GetLogs(ctx, resolveHostID(ctx, a.hostID), id, containersvc.LogOptions{
		Tail:       strconv.Itoa(tail),
		Timestamps: true,
		Stdout:     true,
		Stderr:     true,
	})
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	// Split by newlines
	lines := splitLines(string(data))
	return lines, nil
}
