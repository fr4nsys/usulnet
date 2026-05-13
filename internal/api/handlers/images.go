// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/image"
)

// ImageHandler handles image-related HTTP requests.
type ImageHandler struct {
	BaseHandler
	imageService *image.Service
}

// NewImageHandler creates a new image handler.
func NewImageHandler(imageService *image.Service, log *logger.Logger) *ImageHandler {
	return &ImageHandler{
		BaseHandler:  NewBaseHandler(log),
		imageService: imageService,
	}
}

// Routes returns the router for image endpoints.
func (h *ImageHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Route("/{hostID}", func(r chi.Router) {
		// Read-only (viewer+)
		r.Get("/", h.ListImages)
		r.Get("/dangling", h.ListDangling)
		r.Get("/search", h.SearchImages)

		r.Route("/{imageID}", func(r chi.Router) {
			r.Get("/", h.GetImage)
			r.Get("/history", h.GetHistory)
			r.Get("/update-check", h.CheckUpdate)

			// Operator+ for mutations
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireOperator)
				r.Delete("/", h.RemoveImage)
			})
		})

		// Operator+ for mutations
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireOperator)
			r.Post("/pull", h.PullImage)
			r.Post("/push", h.PushImage)
			r.Post("/tag", h.TagImage)
			r.Post("/prune", h.PruneImages)
			r.Post("/build", h.BuildImage)
		})
	})

	return r
}

// ============================================================================
// Request/Response types
// ============================================================================

// ImageResponse represents an image in API responses.
type ImageResponse struct {
	ID          string            `json:"id"`
	HostID      string            `json:"host_id"`
	RepoTags    []string          `json:"repo_tags"`
	RepoDigests []string          `json:"repo_digests,omitempty"`
	ParentID    string            `json:"parent_id,omitempty"`
	Size        int64             `json:"size"`
	VirtualSize int64             `json:"virtual_size"`
	SharedSize  int64             `json:"shared_size"`
	Labels      map[string]string `json:"labels,omitempty"`
	Containers  int64             `json:"containers"`
	CreatedAt   string            `json:"created_at"`
	SyncedAt    string            `json:"synced_at"`
}

// ImageLayerResponse represents an image layer.
type ImageLayerResponse struct {
	ID        string   `json:"id"`
	CreatedAt string   `json:"created_at"`
	CreatedBy string   `json:"created_by"`
	Tags      []string `json:"tags,omitempty"`
	Size      int64    `json:"size"`
	Comment   string   `json:"comment,omitempty"`
}

// PullRequest represents a pull request.
type PullRequest struct {
	Reference string                     `json:"reference"`
	Auth      *models.RegistryAuthConfig `json:"auth,omitempty"`
}

// PushRequest represents a push request.
type PushRequest struct {
	Reference string                     `json:"reference"`
	Auth      *models.RegistryAuthConfig `json:"auth,omitempty"`
}

// TagRequest represents a tag request.
type TagRequest struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// SearchRequest represents a search request.
type SearchRequest struct {
	Term  string                     `json:"term"`
	Limit int                        `json:"limit,omitempty"`
	Auth  *models.RegistryAuthConfig `json:"auth,omitempty"`
}

// SearchResultResponse represents a search result.
type SearchResultResponse struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	StarCount   int    `json:"star_count"`
	IsOfficial  bool   `json:"is_official"`
	IsAutomated bool   `json:"is_automated"`
}

// PullProgressResponse represents pull progress.
type PullProgressResponse struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Progress string `json:"progress,omitempty"`
	Current  int64  `json:"current,omitempty"`
	Total    int64  `json:"total,omitempty"`
	Error    string `json:"error,omitempty"`
}

// ImageUpdateResponse represents update check result.
type ImageUpdateResponse struct {
	UpdateAvailable bool   `json:"update_available"`
	CurrentDigest   string `json:"current_digest"`
	LatestDigest    string `json:"latest_digest"`
	CurrentTag      string `json:"current_tag"`
	LatestTag       string `json:"latest_tag,omitempty"`
	CheckedAt       string `json:"checked_at"`
}

// PruneImagesResponse represents prune result.
type PruneImagesResponse struct {
	ImagesDeleted  []string `json:"images_deleted"`
	SpaceReclaimed int64    `json:"space_reclaimed"`
}

// ============================================================================
// Handlers
// ============================================================================

// ListImages returns all images for a host.
// GET /api/v1/images/{hostID}
func (h *ImageHandler) ListImages(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	images, err := h.imageService.List(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]ImageResponse, len(images))
	for i, img := range images {
		resp[i] = toImageResponse(img)
	}

	h.OK(w, resp)
}

// ListDangling returns dangling images.
// GET /api/v1/images/{hostID}/dangling
func (h *ImageHandler) ListDangling(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	images, err := h.imageService.ListDangling(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]ImageResponse, len(images))
	for i, img := range images {
		resp[i] = toImageResponse(img)
	}

	h.OK(w, resp)
}

// GetImage returns a specific image.
// GET /api/v1/images/{hostID}/{imageID}
func (h *ImageHandler) GetImage(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	imageID := h.URLParam(r, "imageID")
	if imageID == "" {
		h.BadRequest(w, "imageID is required")
		return
	}

	img, err := h.imageService.Get(r.Context(), hostID, imageID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toImageResponse(img))
}

// GetHistory returns image history/layers.
// GET /api/v1/images/{hostID}/{imageID}/history
func (h *ImageHandler) GetHistory(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	imageID := h.URLParam(r, "imageID")
	if imageID == "" {
		h.BadRequest(w, "imageID is required")
		return
	}

	layers, err := h.imageService.GetHistory(r.Context(), hostID, imageID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]ImageLayerResponse, len(layers))
	for i, layer := range layers {
		resp[i] = ImageLayerResponse{
			ID:        layer.ID,
			CreatedAt: layer.Created.Format(time.RFC3339),
			CreatedBy: layer.CreatedBy,
			Tags:      layer.Tags,
			Size:      layer.Size,
			Comment:   layer.Comment,
		}
	}

	h.OK(w, resp)
}

// RemoveImage removes an image.
// DELETE /api/v1/images/{hostID}/{imageID}
func (h *ImageHandler) RemoveImage(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	imageID := h.URLParam(r, "imageID")
	if imageID == "" {
		h.BadRequest(w, "imageID is required")
		return
	}

	force := h.QueryParamBool(r, "force", false)

	if err := h.imageService.Remove(r.Context(), hostID, imageID, force); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// PullImage pulls an image.
// POST /api/v1/images/{hostID}/pull
func (h *ImageHandler) PullImage(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req PullRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Reference == "" {
		h.BadRequest(w, "reference is required")
		return
	}

	// Check if streaming is requested
	stream := h.QueryParamBool(r, "stream", false)

	if stream {
		// Stream progress
		progressCh, err := h.imageService.PullWithProgress(r.Context(), hostID, req.Reference, req.Auth)
		if err != nil {
			h.HandleError(w, err)
			return
		}

		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Transfer-Encoding", "chunked")

		encoder := json.NewEncoder(w)
		flusher, _ := w.(http.Flusher)

		for p := range progressCh {
			resp := PullProgressResponse{
				ID:       p.ID,
				Status:   p.Status,
				Progress: p.Progress,
				Current:  p.ProgressDetail.Current,
				Total:    p.ProgressDetail.Total,
				Error:    p.Error,
			}
			encoder.Encode(resp)
			if flusher != nil {
				flusher.Flush()
			}
		}
	} else {
		// Simple pull
		if err := h.imageService.Pull(r.Context(), hostID, req.Reference, req.Auth); err != nil {
			h.HandleError(w, err)
			return
		}

		h.OK(w, map[string]string{"message": "image pulled successfully"})
	}
}

// PushImage pushes an image.
// POST /api/v1/images/{hostID}/push
func (h *ImageHandler) PushImage(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req PushRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Reference == "" {
		h.BadRequest(w, "reference is required")
		return
	}

	progressCh, err := h.imageService.Push(r.Context(), hostID, req.Reference, req.Auth)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Transfer-Encoding", "chunked")

	encoder := json.NewEncoder(w)
	flusher, _ := w.(http.Flusher)

	for p := range progressCh {
		resp := PullProgressResponse{
			ID:       p.ID,
			Status:   p.Status,
			Progress: p.Progress,
			Current:  p.ProgressDetail.Current,
			Total:    p.ProgressDetail.Total,
			Error:    p.Error,
		}
		encoder.Encode(resp)
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// TagImage tags an image.
// POST /api/v1/images/{hostID}/tag
func (h *ImageHandler) TagImage(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req TagRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Source == "" {
		h.BadRequest(w, "source is required")
		return
	}
	if req.Target == "" {
		h.BadRequest(w, "target is required")
		return
	}

	if err := h.imageService.Tag(r.Context(), hostID, req.Source, req.Target); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// PruneImages removes unused images.
// POST /api/v1/images/{hostID}/prune
func (h *ImageHandler) PruneImages(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	dangling := h.QueryParamBool(r, "dangling", true)

	result, err := h.imageService.Prune(r.Context(), hostID, dangling)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, PruneImagesResponse{
		ImagesDeleted:  result.ItemsDeleted,
		SpaceReclaimed: result.SpaceReclaimed,
	})
}

// SearchImages searches for images.
// GET /api/v1/images/{hostID}/search
func (h *ImageHandler) SearchImages(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	term := h.QueryParam(r, "term")
	if term == "" {
		h.BadRequest(w, "term is required")
		return
	}

	limit := h.QueryParamInt(r, "limit", 25)

	results, err := h.imageService.Search(r.Context(), hostID, term, limit, nil)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]SearchResultResponse, len(results))
	for i, r := range results {
		resp[i] = SearchResultResponse{
			Name:        r.Name,
			Description: r.Description,
			StarCount:   r.StarCount,
			IsOfficial:  r.IsOfficial,
			IsAutomated: r.IsAutomated,
		}
	}

	h.OK(w, resp)
}

// CheckUpdate checks if an image has updates.
// GET /api/v1/images/{hostID}/{imageID}/update-check
func (h *ImageHandler) CheckUpdate(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	imageID := h.URLParam(r, "imageID")
	if imageID == "" {
		h.BadRequest(w, "imageID is required")
		return
	}

	info, err := h.imageService.CheckUpdate(r.Context(), hostID, imageID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, ImageUpdateResponse{
		UpdateAvailable: info.UpdateAvailable,
		CurrentDigest:   info.CurrentDigest,
		LatestDigest:    info.LatestDigest,
		CurrentTag:      info.CurrentTag,
		LatestTag:       info.LatestTag,
		CheckedAt:       info.CheckedAt.Format(time.RFC3339),
	})
}

// ============================================================================
// Helpers
// ============================================================================

func toImageResponse(img *models.Image) ImageResponse {
	return ImageResponse{
		ID:          img.ID,
		HostID:      img.HostID.String(),
		RepoTags:    img.RepoTags,
		RepoDigests: img.RepoDigests,
		ParentID:    img.ParentID,
		Size:        img.Size,
		VirtualSize: img.VirtualSize,
		SharedSize:  img.SharedSize,
		Labels:      img.Labels,
		Containers:  img.Containers,
		CreatedAt:   img.CreatedAt.Format(time.RFC3339),
		SyncedAt:    img.SyncedAt.Format(time.RFC3339),
	}
}

// ============================================================================
// Build Handler
// ============================================================================

// BuildImageRequest represents a build image request.
type BuildImageRequest struct {
	Dockerfile string            `json:"dockerfile"`
	Tags       []string          `json:"tags"`
	BuildArgs  map[string]string `json:"build_args,omitempty"`
	Target     string            `json:"target,omitempty"`
	NoCache    bool              `json:"no_cache,omitempty"`
	Pull       bool              `json:"pull,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Platform   string            `json:"platform,omitempty"`
}

// BuildImageResponse represents a build result.
type BuildImageResponse struct {
	ImageID string   `json:"image_id"`
	Tags    []string `json:"tags"`
	Logs    []string `json:"logs"`
}

// BuildImage builds a Docker image from a Dockerfile.
// POST /api/v1/images/{hostID}/build
func (h *ImageHandler) BuildImage(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req BuildImageRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Dockerfile == "" {
		h.BadRequest(w, "dockerfile is required")
		return
	}

	if len(req.Tags) == 0 {
		h.BadRequest(w, "at least one tag is required")
		return
	}

	// Convert build args to the format expected by the service
	var buildArgs map[string]*string
	if len(req.BuildArgs) > 0 {
		buildArgs = make(map[string]*string)
		for k, v := range req.BuildArgs {
			val := v
			buildArgs[k] = &val
		}
	}

	opts := image.BuildOptions{
		Tags:       req.Tags,
		BuildArgs:  buildArgs,
		Target:     req.Target,
		NoCache:    req.NoCache,
		Pull:       req.Pull,
		Labels:     req.Labels,
		Platform:   req.Platform,
	}

	// Collect logs
	var logs []string
	callback := func(progress image.BuildProgress) {
		if progress.Stream != "" {
			logs = append(logs, progress.Stream)
		}
		if progress.Status != "" {
			logs = append(logs, progress.Status)
		}
		if progress.Error != "" {
			logs = append(logs, "ERROR: "+progress.Error)
		}
	}

	result, err := h.imageService.BuildFromDockerfile(r.Context(), hostID, req.Dockerfile, opts, callback)
	if err != nil {
		h.Logger().Error("failed to build image", "error", err)
		h.HandleError(w, err)
		return
	}

	h.OK(w, BuildImageResponse{
		ImageID: result.ImageID,
		Tags:    result.Tags,
		Logs:    logs,
	})
}
