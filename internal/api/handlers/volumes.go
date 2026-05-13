// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/volume"
)

// VolumeHandler handles volume-related HTTP requests.
type VolumeHandler struct {
	BaseHandler
	volumeService *volume.Service
}

// NewVolumeHandler creates a new volume handler.
func NewVolumeHandler(volumeService *volume.Service, log *logger.Logger) *VolumeHandler {
	return &VolumeHandler{
		BaseHandler:   NewBaseHandler(log),
		volumeService: volumeService,
	}
}

// Routes returns the router for volume endpoints.
func (h *VolumeHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Route("/{hostID}", func(r chi.Router) {
		// Read-only (viewer+)
		r.Get("/", h.ListVolumes)
		r.Get("/stats", h.GetStats)
		r.Get("/orphans", h.DetectOrphanVolumes)

		// Operator+ for mutations
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireOperator)
			r.Post("/", h.CreateVolume)
			r.Post("/prune", h.PruneVolumes)
			r.Post("/orphans/cleanup", h.CleanupOrphanVolumes)
		})

		r.Route("/{volumeName}", func(r chi.Router) {
			// Read-only (viewer+)
			r.Get("/", h.GetVolume)
			r.Get("/used-by", h.GetUsedBy)
			r.Get("/info", h.GetVolumeInfo)
			r.Get("/browse", h.BrowseVolume)
			r.Get("/browse/*", h.BrowseVolume)
			r.Get("/file/*", h.ReadVolumeFile)
			r.Get("/download/*", h.DownloadVolumeFile)

			// Operator+ for mutations
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireOperator)
				r.Delete("/", h.DeleteVolume)
				r.Put("/file/*", h.WriteVolumeFile)
				r.Delete("/file/*", h.DeleteVolumeFile)
				r.Post("/mkdir/*", h.CreateVolumeDirectory)
			})
		})
	})

	return r
}

// ============================================================================
// Request/Response types
// ============================================================================

// CreateVolumeRequest represents a volume creation request.
type CreateVolumeRequest struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver,omitempty"`
	DriverOpts map[string]string `json:"driver_opts,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// VolumeResponse represents a volume in API responses.
type VolumeResponse struct {
	Name       string              `json:"name"`
	HostID     string              `json:"host_id"`
	Driver     string              `json:"driver"`
	Mountpoint string              `json:"mountpoint"`
	Scope      string              `json:"scope"`
	Labels     map[string]string   `json:"labels,omitempty"`
	Options    map[string]string   `json:"options,omitempty"`
	Status     map[string]any      `json:"status,omitempty"`
	UsageData  *VolumeUsageResponse `json:"usage_data,omitempty"`
	CreatedAt  string              `json:"created_at"`
	SyncedAt   string              `json:"synced_at"`
}

// VolumeUsageResponse represents volume usage data.
type VolumeUsageResponse struct {
	Size     int64 `json:"size"`
	RefCount int64 `json:"ref_count"`
}

// VolumeStatsResponse represents volume statistics.
type VolumeStatsResponse struct {
	Total      int   `json:"total"`
	InUse      int   `json:"in_use"`
	Unused     int   `json:"unused"`
	TotalSize  int64 `json:"total_size"`
	UsedSize   int64 `json:"used_size"`
	UnusedSize int64 `json:"unused_size"`
}

// VolumeInfoResponse represents volume backup info.
type VolumeInfoResponse struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Mountpoint string            `json:"mountpoint"`
	Size       int64             `json:"size"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// PruneVolumesResponse represents prune result.
type PruneVolumesResponse struct {
	VolumesDeleted []string `json:"volumes_deleted"`
	SpaceReclaimed int64    `json:"space_reclaimed"`
}

// VolumeFileResponse represents a file in a volume.
type VolumeFileResponse struct {
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

// VolumeFileContentResponse represents file content.
type VolumeFileContentResponse struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	Size      int64  `json:"size"`
	Truncated bool   `json:"truncated"`
	Binary    bool   `json:"binary"`
}

// WriteFileRequest represents a file write request.
type WriteFileRequest struct {
	Content string `json:"content"`
}

// ============================================================================
// Handlers
// ============================================================================

// ListVolumes returns all volumes for a host.
// GET /api/v1/volumes/{hostID}
func (h *VolumeHandler) ListVolumes(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	// Check for driver filter
	driver := h.QueryParam(r, "driver")

	var volumes []*models.Volume
	if driver != "" {
		volumes, err = h.volumeService.ListByDriver(r.Context(), hostID, driver)
	} else {
		volumes, err = h.volumeService.List(r.Context(), hostID)
	}
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]VolumeResponse, len(volumes))
	for i, v := range volumes {
		resp[i] = toVolumeResponse(v)
	}

	h.OK(w, resp)
}

// CreateVolume creates a new volume.
// POST /api/v1/volumes/{hostID}
func (h *VolumeHandler) CreateVolume(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req CreateVolumeRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Name == "" {
		h.BadRequest(w, "name is required")
		return
	}

	input := &models.CreateVolumeInput{
		Name:       req.Name,
		Driver:     req.Driver,
		DriverOpts: req.DriverOpts,
		Labels:     req.Labels,
	}

	vol, err := h.volumeService.Create(r.Context(), hostID, input)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, toVolumeResponse(vol))
}

// GetVolume returns a specific volume.
// GET /api/v1/volumes/{hostID}/{volumeName}
func (h *VolumeHandler) GetVolume(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	volumeName := h.URLParam(r, "volumeName")
	if volumeName == "" {
		h.BadRequest(w, "volumeName is required")
		return
	}

	vol, err := h.volumeService.Get(r.Context(), hostID, volumeName)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toVolumeResponse(vol))
}

// DeleteVolume deletes a volume.
// DELETE /api/v1/volumes/{hostID}/{volumeName}
func (h *VolumeHandler) DeleteVolume(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	volumeName := h.URLParam(r, "volumeName")
	if volumeName == "" {
		h.BadRequest(w, "volumeName is required")
		return
	}

	force := h.QueryParamBool(r, "force", false)

	if err := h.volumeService.Delete(r.Context(), hostID, volumeName, force); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// GetUsedBy returns containers using a volume.
// GET /api/v1/volumes/{hostID}/{volumeName}/used-by
func (h *VolumeHandler) GetUsedBy(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	volumeName := h.URLParam(r, "volumeName")
	if volumeName == "" {
		h.BadRequest(w, "volumeName is required")
		return
	}

	containers, err := h.volumeService.UsedBy(r.Context(), hostID, volumeName)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string][]string{"containers": containers})
}

// GetVolumeInfo returns volume backup info.
// GET /api/v1/volumes/{hostID}/{volumeName}/info
func (h *VolumeHandler) GetVolumeInfo(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	volumeName := h.URLParam(r, "volumeName")
	if volumeName == "" {
		h.BadRequest(w, "volumeName is required")
		return
	}

	info, err := h.volumeService.VolumeInfo(r.Context(), hostID, volumeName)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, VolumeInfoResponse{
		Name:       info.Name,
		Driver:     info.Driver,
		Mountpoint: info.Mountpoint,
		Size:       info.Size,
		Labels:     info.Labels,
	})
}

// GetStats returns volume statistics.
// GET /api/v1/volumes/{hostID}/stats
func (h *VolumeHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	stats, err := h.volumeService.GetStats(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, VolumeStatsResponse{
		Total:      stats.Total,
		InUse:      stats.InUse,
		Unused:     stats.Unused,
		TotalSize:  stats.TotalSize,
		UsedSize:   stats.UsedSize,
		UnusedSize: stats.UnusedSize,
	})
}

// PruneVolumes removes unused volumes.
// POST /api/v1/volumes/{hostID}/prune
func (h *VolumeHandler) PruneVolumes(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	result, err := h.volumeService.Prune(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, PruneVolumesResponse{
		VolumesDeleted: result.ItemsDeleted,
		SpaceReclaimed: result.SpaceReclaimed,
	})
}

// ============================================================================
// Volume File Browser
// ============================================================================

// BrowseVolume lists files in a volume.
// GET /api/v1/volumes/{hostID}/{volumeName}/browse
// GET /api/v1/volumes/{hostID}/{volumeName}/browse/*
func (h *VolumeHandler) BrowseVolume(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	volumeName := h.URLParam(r, "volumeName")
	if volumeName == "" {
		h.BadRequest(w, "volumeName is required")
		return
	}

	path := chi.URLParam(r, "*")
	if path == "" {
		path = "/"
	}

	files, err := h.volumeService.BrowseVolume(r.Context(), hostID, volumeName, path)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]VolumeFileResponse, len(files))
	for i, f := range files {
		resp[i] = VolumeFileResponse{
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

// ReadVolumeFile reads the content of a file in a volume.
// GET /api/v1/volumes/{hostID}/{volumeName}/file/*
func (h *VolumeHandler) ReadVolumeFile(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	volumeName := h.URLParam(r, "volumeName")
	if volumeName == "" {
		h.BadRequest(w, "volumeName is required")
		return
	}

	path := chi.URLParam(r, "*")
	if path == "" {
		h.BadRequest(w, "file path is required")
		return
	}

	maxSize := h.QueryParamInt(r, "max_size", 1024*1024) // Default 1MB

	content, err := h.volumeService.ReadVolumeFile(r.Context(), hostID, volumeName, path, int64(maxSize))
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, VolumeFileContentResponse{
		Path:      content.Path,
		Content:   content.Content,
		Size:      content.Size,
		Truncated: content.Truncated,
		Binary:    content.Binary,
	})
}

// WriteVolumeFile writes content to a file in a volume.
// PUT /api/v1/volumes/{hostID}/{volumeName}/file/*
func (h *VolumeHandler) WriteVolumeFile(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	volumeName := h.URLParam(r, "volumeName")
	if volumeName == "" {
		h.BadRequest(w, "volumeName is required")
		return
	}

	path := chi.URLParam(r, "*")
	if path == "" {
		h.BadRequest(w, "file path is required")
		return
	}

	var req WriteFileRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.volumeService.WriteVolumeFile(r.Context(), hostID, volumeName, path, req.Content); err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]string{"status": "ok", "path": path})
}

// DeleteVolumeFile deletes a file or directory in a volume.
// DELETE /api/v1/volumes/{hostID}/{volumeName}/file/*
func (h *VolumeHandler) DeleteVolumeFile(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	volumeName := h.URLParam(r, "volumeName")
	if volumeName == "" {
		h.BadRequest(w, "volumeName is required")
		return
	}

	path := chi.URLParam(r, "*")
	if path == "" {
		h.BadRequest(w, "file path is required")
		return
	}

	recursive := h.QueryParamBool(r, "recursive", false)

	if err := h.volumeService.DeleteVolumeFile(r.Context(), hostID, volumeName, path, recursive); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// CreateVolumeDirectory creates a directory in a volume.
// POST /api/v1/volumes/{hostID}/{volumeName}/mkdir/*
func (h *VolumeHandler) CreateVolumeDirectory(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	volumeName := h.URLParam(r, "volumeName")
	if volumeName == "" {
		h.BadRequest(w, "volumeName is required")
		return
	}

	path := chi.URLParam(r, "*")
	if path == "" {
		h.BadRequest(w, "directory path is required")
		return
	}

	if err := h.volumeService.CreateVolumeDirectory(r.Context(), hostID, volumeName, path); err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, map[string]string{"status": "ok", "path": path})
}

// DownloadVolumeFile downloads a file from a volume.
// GET /api/v1/volumes/{hostID}/{volumeName}/download/*
func (h *VolumeHandler) DownloadVolumeFile(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	volumeName := h.URLParam(r, "volumeName")
	if volumeName == "" {
		h.BadRequest(w, "volumeName is required")
		return
	}

	path := chi.URLParam(r, "*")
	if path == "" {
		h.BadRequest(w, "file path is required")
		return
	}

	reader, size, err := h.volumeService.DownloadVolumeFile(r.Context(), hostID, volumeName, path)
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

// ============================================================================
// Helpers
// ============================================================================

func toVolumeResponse(v *models.Volume) VolumeResponse {
	resp := VolumeResponse{
		Name:       v.Name,
		HostID:     v.HostID.String(),
		Driver:     v.Driver,
		Mountpoint: v.Mountpoint,
		Scope:      string(v.Scope),
		Labels:     v.Labels,
		Options:    v.Options,
		Status:     v.Status,
		CreatedAt:  v.CreatedAt.Format(time.RFC3339),
		SyncedAt:   v.SyncedAt.Format(time.RFC3339),
	}

	if v.UsageData != nil {
		resp.UsageData = &VolumeUsageResponse{
			Size:     v.UsageData.Size,
			RefCount: v.UsageData.RefCount,
		}
	}

	return resp
}

// ============================================================================
// Orphan Volume Detection
// ============================================================================

// OrphanVolumeResponse represents an orphan volume.
type OrphanVolumeResponse struct {
	VolumeResponse
	CreatedDaysAgo int    `json:"created_days_ago"`
	Reason         string `json:"reason"`
}

// OrphanVolumeResultResponse represents orphan detection results.
type OrphanVolumeResultResponse struct {
	Orphans         []OrphanVolumeResponse `json:"orphans"`
	TotalVolumes    int                    `json:"total_volumes"`
	OrphanCount     int                    `json:"orphan_count"`
	TotalOrphanSize int64                  `json:"total_orphan_size"`
	OrphanSizeHuman string                 `json:"orphan_size_human"`
	ScanTime        string                 `json:"scan_time"`
	ScanDurationMs  int64                  `json:"scan_duration_ms"`
}

// CleanupOrphanRequest represents a cleanup request.
type CleanupOrphanRequest struct {
	VolumeNames []string `json:"volume_names"`
	DryRun      bool     `json:"dry_run"`
}

// DetectOrphanVolumes finds volumes not used by any container.
// GET /api/v1/volumes/{hostID}/orphans
// Query params: min_age_days (int), include_anonymous (bool)
func (h *VolumeHandler) DetectOrphanVolumes(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	minAgeDays := h.QueryParamInt(r, "min_age_days", 0)
	includeAnonymous := h.QueryParamBool(r, "include_anonymous", false)

	result, err := h.volumeService.DetectOrphanVolumes(r.Context(), hostID, minAgeDays, includeAnonymous)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	// Convert to response
	orphans := make([]OrphanVolumeResponse, len(result.Orphans))
	for i, o := range result.Orphans {
		orphans[i] = OrphanVolumeResponse{
			VolumeResponse: toVolumeResponse(o.Volume),
			CreatedDaysAgo: o.CreatedDaysAgo,
			Reason:         o.Reason,
		}
	}

	h.OK(w, OrphanVolumeResultResponse{
		Orphans:         orphans,
		TotalVolumes:    result.TotalVolumes,
		OrphanCount:     result.OrphanCount,
		TotalOrphanSize: result.TotalOrphanSize,
		OrphanSizeHuman: result.OrphanSizeHuman,
		ScanTime:        result.ScanTime.Format(time.RFC3339),
		ScanDurationMs:  result.ScanDurationMs,
	})
}

// CleanupOrphanVolumes removes specified orphan volumes.
// POST /api/v1/volumes/{hostID}/orphans/cleanup
func (h *VolumeHandler) CleanupOrphanVolumes(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req CleanupOrphanRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if len(req.VolumeNames) == 0 {
		h.BadRequest(w, "volume_names is required")
		return
	}

	result, err := h.volumeService.CleanupOrphanVolumes(r.Context(), hostID, req.VolumeNames, req.DryRun)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]any{
		"dry_run":         req.DryRun,
		"volumes_deleted": result.ItemsDeleted,
		"space_reclaimed": result.SpaceReclaimed,
	})
}
