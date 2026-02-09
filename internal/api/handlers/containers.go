// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/services/container"
)

// ContainerHandler handles container-related HTTP requests.
type ContainerHandler struct {
	BaseHandler
	containerService *container.Service
}

// NewContainerHandler creates a new container handler.
func NewContainerHandler(containerService *container.Service, log *logger.Logger) *ContainerHandler {
	return &ContainerHandler{
		BaseHandler:      NewBaseHandler(log),
		containerService: containerService,
	}
}

// Routes returns the router for container endpoints.
func (h *ContainerHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/", h.ListContainers)
	r.Get("/stats", h.GetContainerStats)

	r.Route("/{hostID}", func(r chi.Router) {
		r.Get("/", h.ListByHost)

		// Bulk operations
		r.Post("/bulk/start", h.BulkStart)
		r.Post("/bulk/stop", h.BulkStop)
		r.Post("/bulk/restart", h.BulkRestart)
		r.Post("/bulk/pause", h.BulkPause)
		r.Post("/bulk/unpause", h.BulkUnpause)
		r.Post("/bulk/kill", h.BulkKill)
		r.Delete("/bulk", h.BulkRemove)

		// Import container filesystem as image
		r.Post("/import", h.ImportContainer)

		r.Route("/{containerID}", func(r chi.Router) {
			r.Get("/", h.GetContainer)
			r.Delete("/", h.RemoveContainer)
			r.Post("/start", h.StartContainer)
			r.Post("/stop", h.StopContainer)
			r.Post("/restart", h.RestartContainer)
			r.Post("/pause", h.PauseContainer)
			r.Post("/unpause", h.UnpauseContainer)
			r.Post("/kill", h.KillContainer)
			r.Post("/recreate", h.RecreateContainer)
			r.Get("/logs", h.GetLogs)
			r.Get("/stats", h.GetStats)
			r.Post("/exec", h.ExecCreate)
			// File copy operations
			r.Get("/copy/*", h.CopyFromContainer)
			r.Put("/copy/*", h.CopyToContainer)
			// Resource update operations
			r.Put("/resources", h.UpdateResources)
			r.Post("/commit", h.CommitContainer)
			r.Get("/export", h.ExportContainer)

			// Environment variables
			r.Get("/env", h.GetContainerEnv)
			r.Put("/env", h.UpdateContainerEnv)
			r.Post("/env/sync", h.SyncContainerConfig)

			// File browser operations
			r.Get("/browse", h.BrowseContainer)
			r.Get("/browse/*", h.BrowseContainer)
			r.Get("/file/*", h.ReadContainerFile)
			r.Put("/file/*", h.WriteContainerFile)
			r.Delete("/file/*", h.DeleteContainerFile)
			r.Post("/mkdir/*", h.CreateContainerDirectory)
			r.Get("/download/*", h.DownloadContainerFile)
		})
	})

	// Prune
	r.Post("/{hostID}/prune", h.Prune)

	return r
}

// ============================================================================
// Request/Response types
// ============================================================================

// ContainerResponse represents a container in API responses.
type ContainerResponse struct {
	ID              string                     `json:"id"`
	HostID          string                     `json:"host_id"`
	Name            string                     `json:"name"`
	Image           string                     `json:"image"`
	ImageID         string                     `json:"image_id,omitempty"`
	Status          string                     `json:"status"`
	State           string                     `json:"state"`
	CreatedAt       string                     `json:"created_at,omitempty"`
	StartedAt       string                     `json:"started_at,omitempty"`
	FinishedAt      string                     `json:"finished_at,omitempty"`
	Ports           []PortMappingResponse      `json:"ports,omitempty"`
	Labels          map[string]string          `json:"labels,omitempty"`
	EnvVars         []string                   `json:"env_vars,omitempty"`
	Mounts          []MountResponse            `json:"mounts,omitempty"`
	Networks        []NetworkAttachmentResponse `json:"networks,omitempty"`
	RestartPolicy   string                     `json:"restart_policy,omitempty"`
	SecurityScore   *int                       `json:"security_score,omitempty"`
	SecurityGrade   string                     `json:"security_grade,omitempty"`
	CurrentVersion  string                     `json:"current_version,omitempty"`
	LatestVersion   string                     `json:"latest_version,omitempty"`
	UpdateAvailable bool                       `json:"update_available"`
	LastScannedAt   string                     `json:"last_scanned_at,omitempty"`
	SyncedAt        string                     `json:"synced_at"`
}

// PortMappingResponse represents a port mapping.
type PortMappingResponse struct {
	PrivatePort uint16 `json:"private_port"`
	PublicPort  uint16 `json:"public_port,omitempty"`
	Type        string `json:"type"`
	IP          string `json:"ip,omitempty"`
}

// MountResponse represents a mount point.
type MountResponse struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode,omitempty"`
	RW          bool   `json:"rw"`
}

// NetworkAttachmentResponse represents a network attachment.
type NetworkAttachmentResponse struct {
	NetworkID   string `json:"network_id"`
	NetworkName string `json:"network_name"`
	IPAddress   string `json:"ip_address,omitempty"`
	Gateway     string `json:"gateway,omitempty"`
}

// ContainerStatsResponse represents container statistics.
type ContainerStatsResponse struct {
	CPUPercent     float64 `json:"cpu_percent"`
	MemoryUsage    int64   `json:"memory_usage"`
	MemoryLimit    int64   `json:"memory_limit"`
	MemoryPercent  float64 `json:"memory_percent"`
	NetworkRxBytes int64   `json:"network_rx_bytes"`
	NetworkTxBytes int64   `json:"network_tx_bytes"`
	BlockRead      int64   `json:"block_read"`
	BlockWrite     int64   `json:"block_write"`
	PIDs           int     `json:"pids"`
	CollectedAt    string  `json:"collected_at"`
}

// AggregatedStatsResponse represents aggregated container statistics.
type AggregatedStatsResponse struct {
	Total            int64 `json:"total"`
	Running          int64 `json:"running"`
	Stopped          int64 `json:"stopped"`
	Paused           int64 `json:"paused"`
	Exited           int64 `json:"exited"`
	Dead             int64 `json:"dead"`
	UpdatesAvailable int64 `json:"updates_available"`
	GradeA           int64 `json:"grade_a"`
	GradeB           int64 `json:"grade_b"`
	GradeC           int64 `json:"grade_c"`
	GradeD           int64 `json:"grade_d"`
	GradeF           int64 `json:"grade_f"`
}

// RecreateRequest represents a recreate request.
type RecreateRequest struct {
	PullImage    bool   `json:"pull_image,omitempty"`
	ImageTag     string `json:"image_tag,omitempty"`
	PreserveName bool   `json:"preserve_name,omitempty"`
	CreateBackup bool   `json:"create_backup,omitempty"`
}

// ExecRequest represents an exec request.
type ExecRequest struct {
	Cmd        []string `json:"cmd"`
	Tty        bool     `json:"tty,omitempty"`
	Env        []string `json:"env,omitempty"`
	WorkingDir string   `json:"working_dir,omitempty"`
	User       string   `json:"user,omitempty"`
	Privileged bool     `json:"privileged,omitempty"`
}

// KillRequest represents a kill request.
type KillRequest struct {
	Signal string `json:"signal,omitempty"`
}

// BulkOperationRequest represents a bulk operation request.
type BulkOperationRequest struct {
	ContainerIDs  []string `json:"container_ids" validate:"required,min=1"`
	Force         bool     `json:"force,omitempty"`
	RemoveVolumes bool     `json:"remove_volumes,omitempty"`
	Signal        string   `json:"signal,omitempty"`
}

// BulkOperationResponse represents the response of a bulk operation.
type BulkOperationResponse struct {
	Total      int                       `json:"total"`
	Successful int                       `json:"successful"`
	Failed     int                       `json:"failed"`
	Results    []BulkOperationItemResult `json:"results"`
}

// BulkOperationItemResult represents the result of a single operation in a bulk request.
type BulkOperationItemResult struct {
	ContainerID string `json:"container_id"`
	Name        string `json:"name,omitempty"`
	Success     bool   `json:"success"`
	Error       string `json:"error,omitempty"`
}

// ============================================================================
// Handlers
// ============================================================================

// ListContainers returns all containers with filtering.
// GET /api/v1/containers
func (h *ContainerHandler) ListContainers(w http.ResponseWriter, r *http.Request) {
	pagination := h.GetPagination(r)

	opts := postgres.ContainerListOptions{
		Page:    pagination.Page,
		PerPage: pagination.PerPage,
	}

	// Optional filters
	if hostID := h.QueryParamUUID(r, "host_id"); hostID != nil {
		opts.HostID = hostID
	}
	if state := h.QueryParam(r, "state"); state != "" {
		s := models.ContainerState(state)
		opts.State = &s
	}
	if search := h.QueryParam(r, "search"); search != "" {
		opts.Search = search
	}
	if image := h.QueryParam(r, "image"); image != "" {
		opts.Image = image
	}

	containers, total, err := h.containerService.List(r.Context(), opts)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]ContainerResponse, len(containers))
	for i, c := range containers {
		resp[i] = toContainerResponse(c)
	}

	h.OK(w, NewPaginatedResponse(resp, total, pagination))
}

// ListByHost returns all containers for a specific host.
// GET /api/v1/containers/{hostID}
func (h *ContainerHandler) ListByHost(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	containers, err := h.containerService.ListByHost(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]ContainerResponse, len(containers))
	for i, c := range containers {
		resp[i] = toContainerResponse(c)
	}

	h.OK(w, resp)
}

// GetContainer returns a specific container.
// GET /api/v1/containers/{hostID}/{containerID}
func (h *ContainerHandler) GetContainer(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	containerID := h.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "containerID is required")
		return
	}

	// Check if live data requested
	live := h.QueryParamBool(r, "live", false)

	var c *models.Container
	if live {
		c, err = h.containerService.GetLive(r.Context(), hostID, containerID)
	} else {
		c, err = h.containerService.Get(r.Context(), hostID, containerID)
	}
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toContainerResponse(c))
}

// RemoveContainer removes a container.
// DELETE /api/v1/containers/{hostID}/{containerID}
func (h *ContainerHandler) RemoveContainer(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	containerID := h.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "containerID is required")
		return
	}

	force := h.QueryParamBool(r, "force", false)
	removeVolumes := h.QueryParamBool(r, "volumes", false)

	if err := h.containerService.Remove(r.Context(), hostID, containerID, force, removeVolumes); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// StartContainer starts a container.
// POST /api/v1/containers/{hostID}/{containerID}/start
func (h *ContainerHandler) StartContainer(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	containerID := h.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "containerID is required")
		return
	}

	if err := h.containerService.StartContainer(r.Context(), hostID, containerID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// StopContainer stops a container.
// POST /api/v1/containers/{hostID}/{containerID}/stop
func (h *ContainerHandler) StopContainer(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	containerID := h.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "containerID is required")
		return
	}

	if err := h.containerService.StopContainer(r.Context(), hostID, containerID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// RestartContainer restarts a container.
// POST /api/v1/containers/{hostID}/{containerID}/restart
func (h *ContainerHandler) RestartContainer(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	containerID := h.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "containerID is required")
		return
	}

	if err := h.containerService.Restart(r.Context(), hostID, containerID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// PauseContainer pauses a container.
// POST /api/v1/containers/{hostID}/{containerID}/pause
func (h *ContainerHandler) PauseContainer(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	containerID := h.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "containerID is required")
		return
	}

	if err := h.containerService.Pause(r.Context(), hostID, containerID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// UnpauseContainer unpauses a container.
// POST /api/v1/containers/{hostID}/{containerID}/unpause
func (h *ContainerHandler) UnpauseContainer(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	containerID := h.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "containerID is required")
		return
	}

	if err := h.containerService.Unpause(r.Context(), hostID, containerID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// KillContainer kills a container.
// POST /api/v1/containers/{hostID}/{containerID}/kill
func (h *ContainerHandler) KillContainer(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	containerID := h.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "containerID is required")
		return
	}

	var req KillRequest
	if err := h.ParseJSON(r, &req); err != nil {
		// Default signal
		req.Signal = "SIGKILL"
	}

	if err := h.containerService.Kill(r.Context(), hostID, containerID, req.Signal); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// RecreateContainer recreates a container.
// POST /api/v1/containers/{hostID}/{containerID}/recreate
func (h *ContainerHandler) RecreateContainer(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	containerID := h.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "containerID is required")
		return
	}

	var req RecreateRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	opts := container.RecreateOptions{
		PullImage:    req.PullImage,
		ImageTag:     req.ImageTag,
		PreserveName: req.PreserveName,
		CreateBackup: req.CreateBackup,
	}

	c, err := h.containerService.Recreate(r.Context(), hostID, containerID, opts)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toContainerResponse(c))
}

// GetLogs returns container logs.
// GET /api/v1/containers/{hostID}/{containerID}/logs
func (h *ContainerHandler) GetLogs(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	containerID := h.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "containerID is required")
		return
	}

	tail := h.QueryParam(r, "tail")
	if tail == "" {
		tail = "100"
	}

	opts := container.LogOptions{
		Stdout:     h.QueryParamBool(r, "stdout", true),
		Stderr:     h.QueryParamBool(r, "stderr", true),
		Timestamps: h.QueryParamBool(r, "timestamps", false),
		Follow:     h.QueryParamBool(r, "follow", false),
		Tail:       tail,
		Since:      h.QueryParam(r, "since"),
		Until:      h.QueryParam(r, "until"),
	}

	reader, err := h.containerService.GetLogs(r.Context(), hostID, containerID, opts)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if opts.Follow {
		w.Header().Set("Transfer-Encoding", "chunked")
	}

	io.Copy(w, reader)
}

// GetStats returns container stats.
// GET /api/v1/containers/{hostID}/{containerID}/stats
func (h *ContainerHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	containerID := h.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "containerID is required")
		return
	}

	stats, err := h.containerService.GetStats(r.Context(), hostID, containerID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, ContainerStatsResponse{
		CPUPercent:     stats.CPUPercent,
		MemoryUsage:    stats.MemoryUsage,
		MemoryLimit:    stats.MemoryLimit,
		MemoryPercent:  stats.MemoryPercent,
		NetworkRxBytes: stats.NetworkRxBytes,
		NetworkTxBytes: stats.NetworkTxBytes,
		BlockRead:      stats.BlockRead,
		BlockWrite:     stats.BlockWrite,
		PIDs:           stats.PIDs,
		CollectedAt:    stats.CollectedAt.Format(time.RFC3339),
	})
}

// GetContainerStats returns aggregated container statistics.
// GET /api/v1/containers/stats
func (h *ContainerHandler) GetContainerStats(w http.ResponseWriter, r *http.Request) {
	var hostID *uuid.UUID
	if hid := h.QueryParamUUID(r, "host_id"); hid != nil {
		hostID = hid
	}

	stats, err := h.containerService.GetContainerStats(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, AggregatedStatsResponse{
		Total:            stats.Total,
		Running:          stats.Running,
		Stopped:          stats.Stopped,
		Paused:           stats.Paused,
		Exited:           stats.Exited,
		Dead:             stats.Dead,
		UpdatesAvailable: stats.UpdatesAvailable,
		GradeA:           stats.GradeA,
		GradeB:           stats.GradeB,
		GradeC:           stats.GradeC,
		GradeD:           stats.GradeD,
		GradeF:           stats.GradeF,
	})
}

// ExecCreate creates an exec instance.
// POST /api/v1/containers/{hostID}/{containerID}/exec
func (h *ContainerHandler) ExecCreate(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	containerID := h.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "containerID is required")
		return
	}

	var req ExecRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if len(req.Cmd) == 0 {
		h.BadRequest(w, "cmd is required")
		return
	}

	config := container.ExecConfig{
		Cmd:          req.Cmd,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          req.Tty,
		Env:          req.Env,
		WorkingDir:   req.WorkingDir,
		User:         req.User,
		Privileged:   req.Privileged,
	}

	execID, err := h.containerService.ExecCreate(r.Context(), hostID, containerID, config)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]string{"exec_id": execID})
}

// ============================================================================
// Bulk Operations
// ============================================================================

// BulkStart starts multiple containers.
// POST /api/v1/containers/{hostID}/bulk/start
func (h *ContainerHandler) BulkStart(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req BulkOperationRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if len(req.ContainerIDs) == 0 {
		h.BadRequest(w, "container_ids is required")
		return
	}

	results, err := h.containerService.BulkStart(r.Context(), hostID, req.ContainerIDs)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toBulkOperationResponse(results))
}

// BulkStop stops multiple containers.
// POST /api/v1/containers/{hostID}/bulk/stop
func (h *ContainerHandler) BulkStop(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req BulkOperationRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if len(req.ContainerIDs) == 0 {
		h.BadRequest(w, "container_ids is required")
		return
	}

	results, err := h.containerService.BulkStop(r.Context(), hostID, req.ContainerIDs)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toBulkOperationResponse(results))
}

// BulkRestart restarts multiple containers.
// POST /api/v1/containers/{hostID}/bulk/restart
func (h *ContainerHandler) BulkRestart(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req BulkOperationRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if len(req.ContainerIDs) == 0 {
		h.BadRequest(w, "container_ids is required")
		return
	}

	results, err := h.containerService.BulkRestart(r.Context(), hostID, req.ContainerIDs)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toBulkOperationResponse(results))
}

// BulkPause pauses multiple containers.
// POST /api/v1/containers/{hostID}/bulk/pause
func (h *ContainerHandler) BulkPause(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req BulkOperationRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if len(req.ContainerIDs) == 0 {
		h.BadRequest(w, "container_ids is required")
		return
	}

	results, err := h.containerService.BulkPause(r.Context(), hostID, req.ContainerIDs)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toBulkOperationResponse(results))
}

// BulkUnpause unpauses multiple containers.
// POST /api/v1/containers/{hostID}/bulk/unpause
func (h *ContainerHandler) BulkUnpause(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req BulkOperationRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if len(req.ContainerIDs) == 0 {
		h.BadRequest(w, "container_ids is required")
		return
	}

	results, err := h.containerService.BulkUnpause(r.Context(), hostID, req.ContainerIDs)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toBulkOperationResponse(results))
}

// BulkKill kills multiple containers.
// POST /api/v1/containers/{hostID}/bulk/kill
func (h *ContainerHandler) BulkKill(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req BulkOperationRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if len(req.ContainerIDs) == 0 {
		h.BadRequest(w, "container_ids is required")
		return
	}

	signal := req.Signal
	if signal == "" {
		signal = "SIGKILL"
	}

	results, err := h.containerService.BulkKill(r.Context(), hostID, req.ContainerIDs, signal)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toBulkOperationResponse(results))
}

// BulkRemove removes multiple containers.
// DELETE /api/v1/containers/{hostID}/bulk
func (h *ContainerHandler) BulkRemove(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req BulkOperationRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if len(req.ContainerIDs) == 0 {
		h.BadRequest(w, "container_ids is required")
		return
	}

	results, err := h.containerService.BulkRemove(r.Context(), hostID, req.ContainerIDs, req.Force, req.RemoveVolumes)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toBulkOperationResponse(results))
}

func toBulkOperationResponse(results *container.BulkOperationResults) BulkOperationResponse {
	resp := BulkOperationResponse{
		Total:      results.Total,
		Successful: results.Successful,
		Failed:     results.Failed,
		Results:    make([]BulkOperationItemResult, len(results.Results)),
	}

	for i, r := range results.Results {
		resp.Results[i] = BulkOperationItemResult{
			ContainerID: r.ContainerID,
			Name:        r.Name,
			Success:     r.Success,
			Error:       r.Error,
		}
	}

	return resp
}

// Prune removes stopped containers.
// POST /api/v1/containers/{hostID}/prune
func (h *ContainerHandler) Prune(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	count, size, err := h.containerService.Prune(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]interface{}{
		"containers_deleted": count,
		"space_reclaimed":    size,
	})
}

// ============================================================================
// Helpers
// ============================================================================

func toContainerResponse(c *models.Container) ContainerResponse {
	resp := ContainerResponse{
		ID:              c.ID,
		HostID:          c.HostID.String(),
		Name:            c.Name,
		Image:           c.Image,
		Status:          c.Status,
		State:           string(c.State),
		Labels:          c.Labels,
		EnvVars:         c.EnvVars,
		UpdateAvailable: c.UpdateAvailable,
		SecurityGrade:   c.SecurityGrade,
		SyncedAt:        c.SyncedAt.Format(time.RFC3339),
	}

	if c.ImageID != nil {
		resp.ImageID = *c.ImageID
	}
	if c.CreatedAtDocker != nil {
		resp.CreatedAt = c.CreatedAtDocker.Format(time.RFC3339)
	}
	if c.StartedAt != nil {
		resp.StartedAt = c.StartedAt.Format(time.RFC3339)
	}
	if c.FinishedAt != nil {
		resp.FinishedAt = c.FinishedAt.Format(time.RFC3339)
	}
	if c.RestartPolicy != nil {
		resp.RestartPolicy = *c.RestartPolicy
	}
	if c.CurrentVersion != nil {
		resp.CurrentVersion = *c.CurrentVersion
	}
	if c.LatestVersion != nil {
		resp.LatestVersion = *c.LatestVersion
	}
	if c.LastScannedAt != nil {
		resp.LastScannedAt = c.LastScannedAt.Format(time.RFC3339)
	}

	// Security score
	if c.SecurityScore > 0 {
		score := c.SecurityScore
		resp.SecurityScore = &score
	}

	// Ports
	if len(c.Ports) > 0 {
		resp.Ports = make([]PortMappingResponse, len(c.Ports))
		for i, p := range c.Ports {
			resp.Ports[i] = PortMappingResponse{
				PrivatePort: p.PrivatePort,
				PublicPort:  p.PublicPort,
				Type:        p.Type,
				IP:          p.IP,
			}
		}
	}

	// Mounts
	if len(c.Mounts) > 0 {
		resp.Mounts = make([]MountResponse, len(c.Mounts))
		for i, m := range c.Mounts {
			resp.Mounts[i] = MountResponse{
				Type:        m.Type,
				Source:      m.Source,
				Destination: m.Destination,
				Mode:        m.Mode,
				RW:          m.RW,
			}
		}
	}

	// Networks
	if len(c.Networks) > 0 {
		resp.Networks = make([]NetworkAttachmentResponse, len(c.Networks))
		for i, n := range c.Networks {
			resp.Networks[i] = NetworkAttachmentResponse{
				NetworkID:   n.NetworkID,
				NetworkName: n.NetworkName,
				IPAddress:   n.IPAddress,
				Gateway:     n.Gateway,
			}
		}
	}

	return resp
}

// ============================================================================
// File Copy Operations
// ============================================================================

// CopyFromContainer downloads a file or directory from a container.
// GET /api/containers/{hostID}/{containerID}/copy/*
func (h *ContainerHandler) CopyFromContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hostID, err := uuid.Parse(chi.URLParam(r, "hostID"))
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	containerID := chi.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "container ID required")
		return
	}

	// Get path from URL (everything after /copy/)
	path := chi.URLParam(r, "*")
	if path == "" {
		path = "/"
	}
	// Ensure path starts with /
	if path[0] != '/' {
		path = "/" + path
	}

	h.Logger().Debug("copying from container",
		"host_id", hostID,
		"container_id", containerID,
		"path", path)

	reader, stat, err := h.containerService.CopyFromContainer(ctx, hostID, containerID, path)
	if err != nil {
		h.Logger().Error("failed to copy from container", "error", err)
		h.InternalError(w, err)
		return
	}
	defer reader.Close()

	// Set headers for tar download
	filename := stat.Name
	if filename == "" {
		filename = "download.tar"
	} else if len(filename) > 0 && filename[len(filename)-1] != '/' {
		filename = filename + ".tar"
	}

	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.Header().Set("X-File-Name", stat.Name)
	w.Header().Set("X-File-Size", string(rune(stat.Size)))
	w.Header().Set("X-File-Mode", string(rune(stat.Mode)))

	// Stream the tar archive
	if _, err := io.Copy(w, reader); err != nil {
		h.Logger().Error("failed to stream copy response", "error", err)
		return
	}
}

// CopyToContainer uploads a tar archive to a container.
// PUT /api/containers/{hostID}/{containerID}/copy/*
func (h *ContainerHandler) CopyToContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hostID, err := uuid.Parse(chi.URLParam(r, "hostID"))
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	containerID := chi.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "container ID required")
		return
	}

	// Get destination path from URL (everything after /copy/)
	dstPath := chi.URLParam(r, "*")
	if dstPath == "" {
		dstPath = "/"
	}
	// Ensure path starts with /
	if dstPath[0] != '/' {
		dstPath = "/" + dstPath
	}

	h.Logger().Debug("copying to container",
		"host_id", hostID,
		"container_id", containerID,
		"dst_path", dstPath)

	// The request body should be a tar archive
	if err := h.containerService.CopyToContainer(ctx, hostID, containerID, dstPath, r.Body); err != nil {
		h.Logger().Error("failed to copy to container", "error", err)
		h.HandleError(w, err)
		return
	}

	h.JSON(w, http.StatusOK, map[string]interface{}{
		"message":    "files copied successfully",
		"dst_path":   dstPath,
		"container":  containerID,
	})
}

// ============================================================================
// Resource Update Operations
// ============================================================================

// ResourceUpdateRequest represents a request to update container resources.
type ResourceUpdateRequest struct {
	Memory            int64  `json:"memory,omitempty"`             // Memory limit in bytes
	MemorySwap        int64  `json:"memory_swap,omitempty"`        // Total memory (memory + swap)
	MemoryReservation int64  `json:"memory_reservation,omitempty"` // Soft memory limit
	NanoCPUs          int64  `json:"nano_cpus,omitempty"`          // CPU quota in 10^-9 CPUs
	CPUShares         int64  `json:"cpu_shares,omitempty"`         // CPU shares (relative weight)
	CPUPeriod         int64  `json:"cpu_period,omitempty"`         // CPU CFS period
	CPUQuota          int64  `json:"cpu_quota,omitempty"`          // CPU CFS quota
	CpusetCpus        string `json:"cpuset_cpus,omitempty"`        // CPUs to use
	CpusetMems        string `json:"cpuset_mems,omitempty"`        // MEMs to use
	PidsLimit         *int64 `json:"pids_limit,omitempty"`         // PIDs limit
}

// UpdateResources updates a container's resource limits without restart.
// PUT /api/containers/{hostID}/{containerID}/resources
func (h *ContainerHandler) UpdateResources(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hostID, err := uuid.Parse(chi.URLParam(r, "hostID"))
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	containerID := chi.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "container ID required")
		return
	}

	var req ResourceUpdateRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.BadRequest(w, "invalid request body")
		return
	}

	input := container.ResourceUpdateInput{
		Memory:            req.Memory,
		MemorySwap:        req.MemorySwap,
		MemoryReservation: req.MemoryReservation,
		NanoCPUs:          req.NanoCPUs,
		CPUShares:         req.CPUShares,
		CPUPeriod:         req.CPUPeriod,
		CPUQuota:          req.CPUQuota,
		CpusetCpus:        req.CpusetCpus,
		CpusetMems:        req.CpusetMems,
		PidsLimit:         req.PidsLimit,
	}

	if err := h.containerService.UpdateResources(ctx, hostID, containerID, input); err != nil {
		h.Logger().Error("failed to update container resources", "error", err)
		h.HandleError(w, err)
		return
	}

	h.JSON(w, http.StatusOK, map[string]interface{}{
		"message":   "container resources updated",
		"container": containerID,
	})
}

// ============================================================================
// Container Commit Operations
// ============================================================================

// CommitRequest represents a request to commit a container to an image.
type CommitRequest struct {
	Reference string            `json:"reference"` // image:tag
	Comment   string            `json:"comment,omitempty"`
	Author    string            `json:"author,omitempty"`
	Pause     bool              `json:"pause"`
	Changes   []string          `json:"changes,omitempty"` // Dockerfile instructions
	Labels    map[string]string `json:"labels,omitempty"`
}

// CommitContainer creates a new image from a container's changes.
// POST /api/containers/{hostID}/{containerID}/commit
func (h *ContainerHandler) CommitContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hostID, err := uuid.Parse(chi.URLParam(r, "hostID"))
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	containerID := chi.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "container ID required")
		return
	}

	var req CommitRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.BadRequest(w, "invalid request body")
		return
	}

	if req.Reference == "" {
		h.BadRequest(w, "reference (image:tag) is required")
		return
	}

	input := container.CommitInput{
		Reference: req.Reference,
		Comment:   req.Comment,
		Author:    req.Author,
		Pause:     req.Pause,
		Changes:   req.Changes,
		Labels:    req.Labels,
	}

	result, err := h.containerService.Commit(ctx, hostID, containerID, input)
	if err != nil {
		h.Logger().Error("failed to commit container", "error", err)
		h.HandleError(w, err)
		return
	}

	h.JSON(w, http.StatusOK, map[string]interface{}{
		"message":   "container committed successfully",
		"image_id":  result.ImageID,
		"reference": req.Reference,
	})
}

// ============================================================================
// Container Export Operations
// ============================================================================

// ExportContainer exports a container's filesystem as a tar archive.
// GET /api/containers/{hostID}/{containerID}/export
func (h *ContainerHandler) ExportContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hostID, err := uuid.Parse(chi.URLParam(r, "hostID"))
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	containerID := chi.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "container ID required")
		return
	}

	reader, err := h.containerService.Export(ctx, hostID, containerID)
	if err != nil {
		h.Logger().Error("failed to export container", "error", err)
		h.HandleError(w, err)
		return
	}
	defer reader.Close()

	// Set headers for tar download
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+containerID+".tar\"")

	// Stream the tar archive
	if _, err := io.Copy(w, reader); err != nil {
		h.Logger().Error("failed to stream export response", "error", err)
		return
	}
}

// ImportContainer imports a container filesystem tarball as an image.
// POST /api/v1/hosts/{hostID}/import
func (h *ContainerHandler) ImportContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hostID, err := uuid.Parse(chi.URLParam(r, "hostID"))
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	// Parse multipart form - limit to 2GB
	if err := r.ParseMultipartForm(2 << 30); err != nil {
		h.BadRequest(w, "failed to parse multipart form: "+err.Error())
		return
	}

	// Get the tarball file
	file, _, err := r.FormFile("tarball")
	if err != nil {
		h.BadRequest(w, "tarball file required")
		return
	}
	defer file.Close()

	// Get import options from form
	input := container.ImportInput{
		ImageRef: r.FormValue("image_ref"),
		Message:  r.FormValue("message"),
	}

	if input.ImageRef == "" {
		h.BadRequest(w, "image_ref required")
		return
	}

	// Parse changes if provided (JSON array)
	if changesJSON := r.FormValue("changes"); changesJSON != "" {
		var changes []string
		if err := json.Unmarshal([]byte(changesJSON), &changes); err != nil {
			h.BadRequest(w, "invalid changes format: "+err.Error())
			return
		}
		input.Changes = changes
	}

	result, err := h.containerService.Import(ctx, hostID, file, input)
	if err != nil {
		h.Logger().Error("failed to import container", "error", err)
		h.HandleError(w, err)
		return
	}

	h.JSON(w, http.StatusOK, result)
}

// ============================================================================
// Environment Variable Handlers
// ============================================================================

// EnvVarResponse represents an environment variable.
type EnvVarResponse struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ContainerEnvResponse represents the environment variables of a container.
type ContainerEnvResponse struct {
	ContainerID   string           `json:"container_id"`
	ContainerName string           `json:"container_name"`
	Variables     []EnvVarResponse `json:"variables"`
}

// UpdateEnvRequest represents a request to update environment variables.
type UpdateEnvRequest struct {
	Add    map[string]string `json:"add,omitempty"`
	Remove []string          `json:"remove,omitempty"`
}

// SyncConfigRequest represents a request to sync configuration to a container.
type SyncContainerConfigRequest struct {
	TemplateID   *string           `json:"template_id,omitempty"`
	TemplateName *string           `json:"template_name,omitempty"`
	Overrides    map[string]string `json:"overrides,omitempty"`
	Force        bool              `json:"force,omitempty"`
}

// GetContainerEnv returns the environment variables of a container.
// GET /api/v1/containers/{hostID}/{containerID}/env
func (h *ContainerHandler) GetContainerEnv(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hostID, err := uuid.Parse(chi.URLParam(r, "hostID"))
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	containerID := chi.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "container_id is required")
		return
	}

	envVars, err := h.containerService.GetContainerEnv(ctx, hostID, containerID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	// Get container info for name
	containerInfo, err := h.containerService.Get(ctx, hostID, containerID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := ContainerEnvResponse{
		ContainerID:   containerID,
		ContainerName: containerInfo.Name,
		Variables:     make([]EnvVarResponse, 0, len(envVars)),
	}

	for name, value := range envVars {
		resp.Variables = append(resp.Variables, EnvVarResponse{
			Name:  name,
			Value: value,
		})
	}

	h.OK(w, resp)
}

// UpdateContainerEnv updates the environment variables of a container.
// PUT /api/v1/containers/{hostID}/{containerID}/env
func (h *ContainerHandler) UpdateContainerEnv(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hostID, err := uuid.Parse(chi.URLParam(r, "hostID"))
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	containerID := chi.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "container_id is required")
		return
	}

	var req UpdateEnvRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if len(req.Add) == 0 && len(req.Remove) == 0 {
		h.BadRequest(w, "at least one of 'add' or 'remove' is required")
		return
	}

	// Use RecreateWithEnv to apply the changes
	opts := container.RecreateWithEnvOptions{
		NewEnv:    req.Add,
		RemoveEnv: req.Remove,
	}

	newContainer, err := h.containerService.RecreateWithEnv(ctx, hostID, containerID, opts)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toContainerResponse(newContainer))
}

// SyncContainerConfig syncs configuration variables to a container.
// POST /api/v1/containers/{hostID}/{containerID}/env/sync
func (h *ContainerHandler) SyncContainerConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hostID, err := uuid.Parse(chi.URLParam(r, "hostID"))
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	containerID := chi.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "container_id is required")
		return
	}

	var req SyncContainerConfigRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	// Get container info for name
	containerInfo, err := h.containerService.Get(ctx, hostID, containerID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	// Build variables from template and overrides
	variables := make([]*models.ConfigVariable, 0)
	for name, value := range req.Overrides {
		variables = append(variables, &models.ConfigVariable{
			Name:  name,
			Value: value,
			Type:  models.VariableTypePlain,
			Scope: models.VariableScopeContainer,
		})
	}

	// Sync config to container (this recreates with new env)
	err = h.containerService.SyncConfigToContainer(ctx, hostID, containerID, variables)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]interface{}{
		"success":        true,
		"container_id":   containerID,
		"container_name": containerInfo.Name,
		"message":        "Configuration synced successfully",
	})
}

// ============================================================================
// Container File Browser
// ============================================================================

// ContainerFileResponse represents a file in a container.
type ContainerFileResponse struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	IsDir      bool   `json:"is_dir"`
	Size       int64  `json:"size"`
	SizeHuman  string `json:"size_human"`
	Mode       string `json:"mode"`
	ModTime    string `json:"mod_time"`
	ModTimeAgo string `json:"mod_time_ago"`
	Owner      string `json:"owner"`
	Group      string `json:"group"`
	LinkTarget string `json:"link_target,omitempty"`
	IsSymlink  bool   `json:"is_symlink"`
}

// ContainerFileContentResponse represents file content.
type ContainerFileContentResponse struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	Size      int64  `json:"size"`
	Truncated bool   `json:"truncated"`
	Binary    bool   `json:"binary"`
}

// WriteContainerFileRequest represents a file write request.
type WriteContainerFileRequest struct {
	Content string `json:"content"`
}

// BrowseContainer lists files in a container at the given path.
// GET /api/v1/containers/{hostID}/{containerID}/browse
// GET /api/v1/containers/{hostID}/{containerID}/browse/*
func (h *ContainerHandler) BrowseContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hostID, err := uuid.Parse(chi.URLParam(r, "hostID"))
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	containerID := chi.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "container_id is required")
		return
	}

	path := chi.URLParam(r, "*")
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	files, err := h.containerService.BrowseContainer(ctx, hostID, containerID, path)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]ContainerFileResponse, len(files))
	for i, f := range files {
		resp[i] = ContainerFileResponse{
			Name:       f.Name,
			Path:       f.Path,
			IsDir:      f.IsDir,
			Size:       f.Size,
			SizeHuman:  f.SizeHuman,
			Mode:       f.Mode,
			ModTime:    f.ModTime.Format(time.RFC3339),
			ModTimeAgo: f.ModTimeAgo,
			Owner:      f.Owner,
			Group:      f.Group,
			LinkTarget: f.LinkTarget,
			IsSymlink:  f.IsSymlink,
		}
	}

	h.OK(w, map[string]any{
		"path":  path,
		"files": resp,
	})
}

// ReadContainerFile reads the content of a file in a container.
// GET /api/v1/containers/{hostID}/{containerID}/file/*
func (h *ContainerHandler) ReadContainerFile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hostID, err := uuid.Parse(chi.URLParam(r, "hostID"))
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	containerID := chi.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "container_id is required")
		return
	}

	path := chi.URLParam(r, "*")
	if path == "" {
		h.BadRequest(w, "file path is required")
		return
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	maxSize := h.QueryParamInt(r, "max_size", 1024*1024) // Default 1MB

	content, err := h.containerService.ReadContainerFile(ctx, hostID, containerID, path, int64(maxSize))
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, ContainerFileContentResponse{
		Path:      content.Path,
		Content:   content.Content,
		Size:      content.Size,
		Truncated: content.Truncated,
		Binary:    content.Binary,
	})
}

// WriteContainerFile writes content to a file in a container.
// PUT /api/v1/containers/{hostID}/{containerID}/file/*
func (h *ContainerHandler) WriteContainerFile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hostID, err := uuid.Parse(chi.URLParam(r, "hostID"))
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	containerID := chi.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "container_id is required")
		return
	}

	path := chi.URLParam(r, "*")
	if path == "" {
		h.BadRequest(w, "file path is required")
		return
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	var req WriteContainerFileRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.containerService.WriteContainerFile(ctx, hostID, containerID, path, req.Content); err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]string{"status": "ok", "path": path})
}

// DeleteContainerFile deletes a file or directory in a container.
// DELETE /api/v1/containers/{hostID}/{containerID}/file/*
func (h *ContainerHandler) DeleteContainerFile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hostID, err := uuid.Parse(chi.URLParam(r, "hostID"))
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	containerID := chi.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "container_id is required")
		return
	}

	path := chi.URLParam(r, "*")
	if path == "" {
		h.BadRequest(w, "file path is required")
		return
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	recursive := h.QueryParamBool(r, "recursive", false)

	if err := h.containerService.DeleteContainerFile(ctx, hostID, containerID, path, recursive); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// CreateContainerDirectory creates a directory in a container.
// POST /api/v1/containers/{hostID}/{containerID}/mkdir/*
func (h *ContainerHandler) CreateContainerDirectory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hostID, err := uuid.Parse(chi.URLParam(r, "hostID"))
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	containerID := chi.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "container_id is required")
		return
	}

	path := chi.URLParam(r, "*")
	if path == "" {
		h.BadRequest(w, "directory path is required")
		return
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	if err := h.containerService.CreateContainerDirectory(ctx, hostID, containerID, path); err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, map[string]string{"status": "ok", "path": path})
}

// DownloadContainerFile downloads a file from a container.
// GET /api/v1/containers/{hostID}/{containerID}/download/*
func (h *ContainerHandler) DownloadContainerFile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hostID, err := uuid.Parse(chi.URLParam(r, "hostID"))
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	containerID := chi.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "container_id is required")
		return
	}

	path := chi.URLParam(r, "*")
	if path == "" {
		h.BadRequest(w, "file path is required")
		return
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	reader, size, err := h.containerService.DownloadContainerFile(ctx, hostID, containerID, path)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	defer reader.Close()

	// Extract filename from path
	parts := strings.Split(path, "/")
	filename := parts[len(parts)-1]
	if filename == "" {
		filename = "download"
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	if size > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}

	io.Copy(w, reader)
}
