// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package executor provides command execution for the usulnet agent.
package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/docker/docker/api/types/container"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Executor handles command execution on the agent.
type Executor struct {
	docker *docker.Client
	log    *logger.Logger

	// Command handlers
	handlers map[protocol.CommandType]CommandHandler
}

// CommandHandler processes a specific command type.
type CommandHandler func(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult

// New creates a new executor.
func New(dockerClient *docker.Client, log *logger.Logger) *Executor {
	e := &Executor{
		docker:   dockerClient,
		log:      log.Named("executor"),
		handlers: make(map[protocol.CommandType]CommandHandler),
	}

	// Register handlers
	e.registerHandlers()

	return e
}

// registerHandlers registers all command handlers.
func (e *Executor) registerHandlers() {
	// Container commands
	e.handlers[protocol.CmdContainerList] = e.handleContainerList
	e.handlers[protocol.CmdContainerInspect] = e.handleContainerInspect
	e.handlers[protocol.CmdContainerStart] = e.handleContainerStart
	e.handlers[protocol.CmdContainerStop] = e.handleContainerStop
	e.handlers[protocol.CmdContainerRestart] = e.handleContainerRestart
	e.handlers[protocol.CmdContainerKill] = e.handleContainerKill
	e.handlers[protocol.CmdContainerPause] = e.handleContainerPause
	e.handlers[protocol.CmdContainerUnpause] = e.handleContainerUnpause
	e.handlers[protocol.CmdContainerRemove] = e.handleContainerRemove
	e.handlers[protocol.CmdContainerLogs] = e.handleContainerLogs
	e.handlers[protocol.CmdContainerStats] = e.handleContainerStats

	// Image commands
	e.handlers[protocol.CmdImageList] = e.handleImageList
	e.handlers[protocol.CmdImageInspect] = e.handleImageInspect
	e.handlers[protocol.CmdImagePull] = e.handleImagePull
	e.handlers[protocol.CmdImageRemove] = e.handleImageRemove
	e.handlers[protocol.CmdImagePrune] = e.handleImagePrune

	// Volume commands
	e.handlers[protocol.CmdVolumeList] = e.handleVolumeList
	e.handlers[protocol.CmdVolumeInspect] = e.handleVolumeInspect
	e.handlers[protocol.CmdVolumeCreate] = e.handleVolumeCreate
	e.handlers[protocol.CmdVolumeRemove] = e.handleVolumeRemove
	e.handlers[protocol.CmdVolumePrune] = e.handleVolumePrune

	// Network commands
	e.handlers[protocol.CmdNetworkList] = e.handleNetworkList
	e.handlers[protocol.CmdNetworkInspect] = e.handleNetworkInspect
	e.handlers[protocol.CmdNetworkCreate] = e.handleNetworkCreate
	e.handlers[protocol.CmdNetworkRemove] = e.handleNetworkRemove
	e.handlers[protocol.CmdNetworkConnect] = e.handleNetworkConnect
	e.handlers[protocol.CmdNetworkDisconnect] = e.handleNetworkDisconnect

	// System commands
	e.handlers[protocol.CmdSystemInfo] = e.handleSystemInfo
	e.handlers[protocol.CmdSystemVersion] = e.handleSystemVersion
	e.handlers[protocol.CmdSystemDf] = e.handleSystemDf
	e.handlers[protocol.CmdSystemPing] = e.handleSystemPing

	// Security commands
	e.registerSecurityHandlers()
}

// Execute executes a command and returns the result.
func (e *Executor) Execute(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	startedAt := time.Now().UTC()

	e.log.Debug("Executing command",
		"command_id", cmd.ID,
		"type", cmd.Type,
	)

	// Find handler
	handler, exists := e.handlers[cmd.Type]
	if !exists {
		return &protocol.CommandResult{
			CommandID:   cmd.ID,
			Status:      protocol.CommandStatusFailed,
			StartedAt:   startedAt,
			CompletedAt: time.Now().UTC(),
			Duration:    time.Since(startedAt),
			Error: &protocol.CommandError{
				Code:    "UNKNOWN_COMMAND",
				Message: fmt.Sprintf("unknown command type: %s", cmd.Type),
			},
		}
	}

	// Create timeout context
	timeout := cmd.Timeout
	if timeout == 0 {
		timeout = protocol.DefaultTimeout(cmd.Type)
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Execute handler
	result := handler(execCtx, cmd)

	// Fill in timing
	result.CommandID = cmd.ID
	result.StartedAt = startedAt
	result.CompletedAt = time.Now().UTC()
	result.Duration = result.CompletedAt.Sub(startedAt)

	e.log.Debug("Command completed",
		"command_id", cmd.ID,
		"status", result.Status,
		"duration", result.Duration,
	)

	return result
}

// ============================================================================
// Container Handlers
// ============================================================================

func (e *Executor) handleContainerList(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	cli := e.docker.Raw()

	containers, err := cli.ContainerList(ctx, containerListOptionsFromParams(cmd.Params))
	if err != nil {
		return e.errorResult(err)
	}

	// Convert to domain types for consistent serialization over NATS
	result := make([]docker.Container, len(containers))
	for i, c := range containers {
		result[i] = docker.ContainerFromSummary(c)
	}
	return e.successResult(result)
}

func (e *Executor) handleContainerInspect(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.ContainerID == "" {
		return e.invalidParamsResult("container_id is required")
	}

	cli := e.docker.Raw()

	c, err := cli.ContainerInspect(ctx, cmd.Params.ContainerID)
	if err != nil {
		return e.errorResult(err)
	}

	details := docker.ContainerFromInspect(c)
	return e.successResult(details)
}

func (e *Executor) handleContainerStart(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.ContainerID == "" {
		return e.invalidParamsResult("container_id is required")
	}

	cli := e.docker.Raw()

	if err := cli.ContainerStart(ctx, cmd.Params.ContainerID, containerStartOptionsFromParams(cmd.Params)); err != nil {
		return e.errorResult(err)
	}

	return e.successResult(map[string]string{
		"container_id": cmd.Params.ContainerID,
		"action":       "started",
	})
}

func (e *Executor) handleContainerStop(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.ContainerID == "" {
		return e.invalidParamsResult("container_id is required")
	}

	cli := e.docker.Raw()

	if err := cli.ContainerStop(ctx, cmd.Params.ContainerID, containerStopOptionsFromParams(cmd.Params)); err != nil {
		return e.errorResult(err)
	}

	return e.successResult(map[string]string{
		"container_id": cmd.Params.ContainerID,
		"action":       "stopped",
	})
}

func (e *Executor) handleContainerRestart(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.ContainerID == "" {
		return e.invalidParamsResult("container_id is required")
	}

	cli := e.docker.Raw()

	if err := cli.ContainerRestart(ctx, cmd.Params.ContainerID, containerStopOptionsFromParams(cmd.Params)); err != nil {
		return e.errorResult(err)
	}

	return e.successResult(map[string]string{
		"container_id": cmd.Params.ContainerID,
		"action":       "restarted",
	})
}

func (e *Executor) handleContainerKill(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.ContainerID == "" {
		return e.invalidParamsResult("container_id is required")
	}

	signal := cmd.Params.Signal
	if signal == "" {
		signal = "SIGKILL"
	}

	cli := e.docker.Raw()

	if err := cli.ContainerKill(ctx, cmd.Params.ContainerID, signal); err != nil {
		return e.errorResult(err)
	}

	return e.successResult(map[string]string{
		"container_id": cmd.Params.ContainerID,
		"action":       "killed",
		"signal":       signal,
	})
}

func (e *Executor) handleContainerPause(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.ContainerID == "" {
		return e.invalidParamsResult("container_id is required")
	}

	cli := e.docker.Raw()

	if err := cli.ContainerPause(ctx, cmd.Params.ContainerID); err != nil {
		return e.errorResult(err)
	}

	return e.successResult(map[string]string{
		"container_id": cmd.Params.ContainerID,
		"action":       "paused",
	})
}

func (e *Executor) handleContainerUnpause(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.ContainerID == "" {
		return e.invalidParamsResult("container_id is required")
	}

	cli := e.docker.Raw()

	if err := cli.ContainerUnpause(ctx, cmd.Params.ContainerID); err != nil {
		return e.errorResult(err)
	}

	return e.successResult(map[string]string{
		"container_id": cmd.Params.ContainerID,
		"action":       "unpaused",
	})
}

func (e *Executor) handleContainerRemove(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.ContainerID == "" {
		return e.invalidParamsResult("container_id is required")
	}

	cli := e.docker.Raw()

	if err := cli.ContainerRemove(ctx, cmd.Params.ContainerID, containerRemoveOptionsFromParams(cmd.Params)); err != nil {
		return e.errorResult(err)
	}

	return e.successResult(map[string]string{
		"container_id": cmd.Params.ContainerID,
		"action":       "removed",
	})
}

func (e *Executor) handleContainerLogs(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.ContainerID == "" {
		return e.invalidParamsResult("container_id is required")
	}

	cli := e.docker.Raw()

	reader, err := cli.ContainerLogs(ctx, cmd.Params.ContainerID, containerLogsOptionsFromParams(cmd.Params))
	if err != nil {
		return e.errorResult(err)
	}
	defer reader.Close()

	// Stream logs in chunks for large outputs.
	// Each chunk is up to chunkSize bytes. The result includes metadata so the
	// consumer can detect truncation and reassemble if needed.
	const chunkSize = 64 * 1024 // 64KB per chunk
	const maxSize = 10 * 1024 * 1024 // 10MB max total

	var logs []byte
	buf := make([]byte, chunkSize)
	totalRead := 0
	truncated := false

	for totalRead < maxSize {
		n, readErr := reader.Read(buf)
		if n > 0 {
			logs = append(logs, buf[:n]...)
			totalRead += n
		}
		if readErr != nil {
			break
		}
	}

	if totalRead >= maxSize {
		truncated = true
	}

	return e.successResult(map[string]interface{}{
		"container_id": cmd.Params.ContainerID,
		"logs":         string(logs),
		"size":         totalRead,
		"truncated":    truncated,
		"max_size":     maxSize,
	})
}

func (e *Executor) handleContainerStats(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.ContainerID == "" {
		return e.invalidParamsResult("container_id is required")
	}

	cli := e.docker.Raw()

	stats, err := cli.ContainerStatsOneShot(ctx, cmd.Params.ContainerID)
	if err != nil {
		return e.errorResult(err)
	}
	defer stats.Body.Close()

	var statsResp container.StatsResponse
	if err := json.NewDecoder(stats.Body).Decode(&statsResp); err != nil {
		return e.errorResult(fmt.Errorf("parse container stats: %w", err))
	}

	result := docker.StatsFromResponse(cmd.Params.ContainerID, &statsResp)
	return e.successResult(result)
}

// ============================================================================
// Image Handlers
// ============================================================================

func (e *Executor) handleImageList(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	cli := e.docker.Raw()

	images, err := cli.ImageList(ctx, imageListOptionsFromParams(cmd.Params))
	if err != nil {
		return e.errorResult(err)
	}

	result := make([]docker.Image, len(images))
	for i, img := range images {
		result[i] = docker.ImageFromSummary(img)
	}
	return e.successResult(result)
}

func (e *Executor) handleImageInspect(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.ImageRef == "" {
		return e.invalidParamsResult("image_ref is required")
	}

	cli := e.docker.Raw()

	img, _, err := cli.ImageInspectWithRaw(ctx, cmd.Params.ImageRef)
	if err != nil {
		return e.errorResult(err)
	}

	details := docker.ImageFromInspect(img)
	return e.successResult(details)
}

func (e *Executor) handleImagePull(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.ImageRef == "" {
		return e.invalidParamsResult("image_ref is required")
	}

	cli := e.docker.Raw()

	reader, err := cli.ImagePull(ctx, cmd.Params.ImageRef, imagePullOptionsFromParams(cmd.Params))
	if err != nil {
		return e.errorResult(err)
	}
	defer reader.Close()

	// Parse pull progress from the JSON stream.
	// Docker returns one JSON object per line with layer progress info.
	type pullStatus struct {
		ID             string `json:"id"`
		Status         string `json:"status"`
		Progress       string `json:"progress"`
		ProgressDetail struct {
			Current int64 `json:"current"`
			Total   int64 `json:"total"`
		} `json:"progressDetail"`
		Error string `json:"error,omitempty"`
	}

	var lastStatus string
	var pullError string
	layersDone := make(map[string]bool)
	layersTotal := make(map[string]bool)

	decoder := json.NewDecoder(reader)
	for {
		var status pullStatus
		if decodeErr := decoder.Decode(&status); decodeErr != nil {
			break
		}

		if status.Error != "" {
			pullError = status.Error
			break
		}

		// Track layers for progress calculation
		if status.ID != "" {
			layersTotal[status.ID] = true
			if status.Status == "Pull complete" || status.Status == "Already exists" {
				layersDone[status.ID] = true
			}
		}

		lastStatus = status.Status
	}

	if pullError != "" {
		return e.errorResult(fmt.Errorf("image pull failed: %s", pullError))
	}

	return e.successResult(map[string]interface{}{
		"image_ref":    cmd.Params.ImageRef,
		"action":       "pulled",
		"last_status":  lastStatus,
		"layers_total": len(layersTotal),
		"layers_done":  len(layersDone),
	})
}

func (e *Executor) handleImageRemove(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.ImageRef == "" {
		return e.invalidParamsResult("image_ref is required")
	}

	cli := e.docker.Raw()

	removed, err := cli.ImageRemove(ctx, cmd.Params.ImageRef, imageRemoveOptionsFromParams(cmd.Params))
	if err != nil {
		return e.errorResult(err)
	}

	return e.successResult(map[string]interface{}{
		"image_ref": cmd.Params.ImageRef,
		"action":    "removed",
		"deleted":   removed,
	})
}

func (e *Executor) handleImagePrune(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	cli := e.docker.Raw()

	report, err := cli.ImagesPrune(ctx, imagePruneFiltersFromParams(cmd.Params))
	if err != nil {
		return e.errorResult(err)
	}

	return e.successResult(map[string]interface{}{
		"action":         "pruned",
		"images_deleted": report.ImagesDeleted,
		"space_reclaimed": report.SpaceReclaimed,
	})
}

// ============================================================================
// Volume Handlers
// ============================================================================

func (e *Executor) handleVolumeList(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	cli := e.docker.Raw()

	resp, err := cli.VolumeList(ctx, volumeListOptionsFromParams(cmd.Params))
	if err != nil {
		return e.errorResult(err)
	}

	var result []docker.Volume
	if resp.Volumes != nil {
		for _, v := range resp.Volumes {
			if v != nil {
				result = append(result, docker.VolumeFromDocker(*v))
			}
		}
	}
	return e.successResult(result)
}

func (e *Executor) handleVolumeInspect(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.VolumeName == "" {
		return e.invalidParamsResult("volume_name is required")
	}

	cli := e.docker.Raw()

	v, err := cli.VolumeInspect(ctx, cmd.Params.VolumeName)
	if err != nil {
		return e.errorResult(err)
	}

	vol := docker.VolumeFromDocker(v)
	return e.successResult(vol)
}

func (e *Executor) handleVolumeCreate(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.VolumeName == "" {
		return e.invalidParamsResult("volume_name is required")
	}

	cli := e.docker.Raw()

	v, err := cli.VolumeCreate(ctx, volumeCreateOptionsFromParams(cmd.Params))
	if err != nil {
		return e.errorResult(err)
	}

	vol := docker.VolumeFromDocker(v)
	return e.successResult(vol)
}

func (e *Executor) handleVolumeRemove(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.VolumeName == "" {
		return e.invalidParamsResult("volume_name is required")
	}

	cli := e.docker.Raw()

	if err := cli.VolumeRemove(ctx, cmd.Params.VolumeName, cmd.Params.Force); err != nil {
		return e.errorResult(err)
	}

	return e.successResult(map[string]string{
		"volume_name": cmd.Params.VolumeName,
		"action":      "removed",
	})
}

func (e *Executor) handleVolumePrune(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	cli := e.docker.Raw()

	report, err := cli.VolumesPrune(ctx, volumePruneFiltersFromParams(cmd.Params))
	if err != nil {
		return e.errorResult(err)
	}

	return e.successResult(map[string]interface{}{
		"action":          "pruned",
		"volumes_deleted": report.VolumesDeleted,
		"space_reclaimed": report.SpaceReclaimed,
	})
}

// ============================================================================
// Network Handlers
// ============================================================================

func (e *Executor) handleNetworkList(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	cli := e.docker.Raw()

	networks, err := cli.NetworkList(ctx, networkListOptionsFromParams(cmd.Params))
	if err != nil {
		return e.errorResult(err)
	}

	result := make([]docker.Network, len(networks))
	for i, n := range networks {
		result[i] = docker.NetworkFromDocker(n)
	}
	return e.successResult(result)
}

func (e *Executor) handleNetworkInspect(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.NetworkID == "" {
		return e.invalidParamsResult("network_id is required")
	}

	cli := e.docker.Raw()

	n, err := cli.NetworkInspect(ctx, cmd.Params.NetworkID, networkInspectOptionsFromParams(cmd.Params))
	if err != nil {
		return e.errorResult(err)
	}

	net := docker.NetworkFromDocker(n)
	return e.successResult(net)
}

func (e *Executor) handleNetworkCreate(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.NetworkName == "" {
		return e.invalidParamsResult("network_name is required")
	}

	cli := e.docker.Raw()

	resp, err := cli.NetworkCreate(ctx, cmd.Params.NetworkName, networkCreateOptionsFromParams(cmd.Params))
	if err != nil {
		return e.errorResult(err)
	}

	return e.successResult(map[string]interface{}{
		"network_id":   resp.ID,
		"network_name": cmd.Params.NetworkName,
		"action":       "created",
		"warning":      resp.Warning,
	})
}

func (e *Executor) handleNetworkRemove(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.NetworkID == "" {
		return e.invalidParamsResult("network_id is required")
	}

	cli := e.docker.Raw()

	if err := cli.NetworkRemove(ctx, cmd.Params.NetworkID); err != nil {
		return e.errorResult(err)
	}

	return e.successResult(map[string]string{
		"network_id": cmd.Params.NetworkID,
		"action":     "removed",
	})
}

func (e *Executor) handleNetworkConnect(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.NetworkID == "" || cmd.Params.ContainerID == "" {
		return e.invalidParamsResult("network_id and container_id are required")
	}

	cli := e.docker.Raw()

	if err := cli.NetworkConnect(ctx, cmd.Params.NetworkID, cmd.Params.ContainerID, networkConnectOptionsFromParams(cmd.Params)); err != nil {
		return e.errorResult(err)
	}

	return e.successResult(map[string]string{
		"network_id":   cmd.Params.NetworkID,
		"container_id": cmd.Params.ContainerID,
		"action":       "connected",
	})
}

func (e *Executor) handleNetworkDisconnect(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if cmd.Params.NetworkID == "" || cmd.Params.ContainerID == "" {
		return e.invalidParamsResult("network_id and container_id are required")
	}

	cli := e.docker.Raw()

	if err := cli.NetworkDisconnect(ctx, cmd.Params.NetworkID, cmd.Params.ContainerID, cmd.Params.Force); err != nil {
		return e.errorResult(err)
	}

	return e.successResult(map[string]string{
		"network_id":   cmd.Params.NetworkID,
		"container_id": cmd.Params.ContainerID,
		"action":       "disconnected",
	})
}

// ============================================================================
// System Handlers
// ============================================================================

func (e *Executor) handleSystemInfo(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	info, err := e.docker.Info(ctx)
	if err != nil {
		return e.errorResult(err)
	}

	return e.successResult(info)
}

func (e *Executor) handleSystemVersion(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	cli := e.docker.Raw()

	version, err := cli.ServerVersion(ctx)
	if err != nil {
		return e.errorResult(err)
	}

	return e.successResult(map[string]string{
		"version":     version.Version,
		"api_version": version.APIVersion,
		"os":          version.Os,
		"arch":        version.Arch,
	})
}

func (e *Executor) handleSystemDf(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	cli := e.docker.Raw()

	df, err := cli.DiskUsage(ctx, diskUsageOptionsFromParams(cmd.Params))
	if err != nil {
		return e.errorResult(err)
	}

	return e.successResult(df)
}

func (e *Executor) handleSystemPing(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	if err := e.docker.Ping(ctx); err != nil {
		return e.errorResult(err)
	}

	return e.successResult(map[string]string{
		"status": "ok",
	})
}

// ============================================================================
// Helper Methods
// ============================================================================

func (e *Executor) successResult(data interface{}) *protocol.CommandResult {
	return &protocol.CommandResult{
		Status: protocol.CommandStatusCompleted,
		Data:   data,
	}
}

func (e *Executor) errorResult(err error) *protocol.CommandResult {
	return &protocol.CommandResult{
		Status: protocol.CommandStatusFailed,
		Error: &protocol.CommandError{
			Code:        "EXECUTION_ERROR",
			Message:     err.Error(),
			DockerError: err.Error(),
		},
	}
}

func (e *Executor) invalidParamsResult(message string) *protocol.CommandResult {
	return &protocol.CommandResult{
		Status: protocol.CommandStatusFailed,
		Error: &protocol.CommandError{
			Code:    "INVALID_PARAMS",
			Message: message,
		},
	}
}
