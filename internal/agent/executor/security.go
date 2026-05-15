// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package executor

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
)

// SecurityScanRequest represents a request to scan containers on the agent.
type SecurityScanRequest struct {
	ContainerID string `json:"container_id,omitempty"`
	ScanAll     bool   `json:"scan_all,omitempty"`
	IncludeCVE  bool   `json:"include_cve,omitempty"`
}

// SecurityScanResponse represents the response from a security scan.
type SecurityScanResponse struct {
	Scans    []ContainerScanData `json:"scans"`
	Warnings []string            `json:"warnings,omitempty"`
}

// ContainerScanData contains the inspect data needed by the master for scanning.
// This implements Option B from the architecture: agent sends inspect data,
// master runs the actual security analysis (lighter agent footprint).
type ContainerScanData struct {
	ContainerID   string              `json:"container_id"`
	ContainerName string              `json:"container_name"`
	Image         string              `json:"image"`
	InspectData   types.ContainerJSON `json:"inspect_data"`
}

// registerSecurityHandlers registers security-related command handlers.
func (e *Executor) registerSecurityHandlers() {
	e.handlers[protocol.CmdSecurityScan] = e.handleSecurityScan
	e.handlers[protocol.CmdSecurityScanImage] = e.handleSecurityScanImage
}

// handleSecurityScan handles a security scan command.
// Option B: The agent collects container inspect data and sends it to the master.
// The master performs the actual security analysis using its SecurityService.
func (e *Executor) handleSecurityScan(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	var req SecurityScanRequest
	if err := decodeParams(cmd.Params, &req); err != nil {
		return failedResult(fmt.Sprintf("invalid scan request: %v", err))
	}

	cli := e.docker.Raw()
	var scanData []ContainerScanData
	var warnings []string

	if req.ScanAll || req.ContainerID == "" {
		// Scan all running containers
		containers, err := cli.ContainerList(ctx, container.ListOptions{All: false})
		if err != nil {
			return failedResult(fmt.Sprintf("list containers: %v", err))
		}

		for _, c := range containers {
			inspect, err := cli.ContainerInspect(ctx, c.ID)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("inspect %s: %v", c.ID[:12], err))
				continue
			}
			scanData = append(scanData, ContainerScanData{
				ContainerID:   c.ID,
				ContainerName: inspect.Name,
				Image:         inspect.Config.Image,
				InspectData:   inspect,
			})
		}
	} else {
		// Scan a specific container
		inspect, err := cli.ContainerInspect(ctx, req.ContainerID)
		if err != nil {
			return failedResult(fmt.Sprintf("inspect container %s: %v", req.ContainerID, err))
		}
		scanData = append(scanData, ContainerScanData{
			ContainerID:   inspect.ID,
			ContainerName: inspect.Name,
			Image:         inspect.Config.Image,
			InspectData:   inspect,
		})
	}

	resp := SecurityScanResponse{
		Scans:    scanData,
		Warnings: warnings,
	}

	e.log.Info("Security scan data collected",
		"containers", len(scanData),
		"warnings", len(warnings))

	return &protocol.CommandResult{
		Status: protocol.CommandStatusCompleted,
		Data:   resp,
	}
}

// handleSecurityScanImage handles scanning a specific image for vulnerabilities.
// This also follows Option B: agent sends image metadata, master runs Trivy.
func (e *Executor) handleSecurityScanImage(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	imageRef := cmd.Params.ImageRef
	if imageRef == "" {
		return failedResult("image parameter is required")
	}

	cli := e.docker.Raw()

	// Get image inspect data
	imageInspect, _, err := cli.ImageInspectWithRaw(ctx, imageRef)
	if err != nil {
		return failedResult(fmt.Sprintf("inspect image %s: %v", imageRef, err))
	}

	type ImageScanResponse struct {
		ImageID    string   `json:"image_id"`
		ImageRef   string   `json:"image_ref"`
		RepoTags   []string `json:"repo_tags"`
		RepoDigest []string `json:"repo_digests"`
		Size       int64    `json:"size"`
		OS         string   `json:"os"`
		Arch       string   `json:"architecture"`
	}

	resp := ImageScanResponse{
		ImageID:    imageInspect.ID,
		ImageRef:   imageRef,
		RepoTags:   imageInspect.RepoTags,
		RepoDigest: imageInspect.RepoDigests,
		Size:       imageInspect.Size,
		OS:         imageInspect.Os,
		Arch:       imageInspect.Architecture,
	}

	e.log.Info("Image scan data collected",
		"image", imageRef,
		"id", imageInspect.ID[:12])

	return &protocol.CommandResult{
		Status: protocol.CommandStatusCompleted,
		Data:   resp,
	}
}

// decodeParams decodes command params into a struct.
func decodeParams(params protocol.CommandParams, v interface{}) error {
	data, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("marshal params: %w", err)
	}
	return json.Unmarshal(data, v)
}

// failedResult creates a failed command result with an error message.
func failedResult(msg string) *protocol.CommandResult {
	return &protocol.CommandResult{
		Status: protocol.CommandStatusFailed,
		Error: &protocol.CommandError{
			Code:    "SCAN_ERROR",
			Message: msg,
		},
	}
}
