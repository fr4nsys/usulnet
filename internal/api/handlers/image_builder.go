// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/redis"
	imagebuildersvc "github.com/fr4nsys/usulnet/internal/services/imagebuilder"
)

// ImageBuilderService is the narrow surface this handler depends on.
// Declaring it locally keeps the unit tests free of the concrete docker
// dependency wired into *imagebuilder.Service.
//
// v26.2.7 shipped no REST surface for the image builder — this is a new
// boundary in v26.5.1.
type ImageBuilderService interface {
	StartBuild(ctx context.Context, opts imagebuildersvc.StartBuildOptions) (*models.ImageBuildJob, error)
	GetBuild(ctx context.Context, id uuid.UUID) (*models.ImageBuildJob, error)
	ListBuilds(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]models.ImageBuildJob, int, error)
	GetStats(ctx context.Context, hostID uuid.UUID) (*models.ImageBuildJobStats, error)

	ListTemplates(ctx context.Context, hostID uuid.UUID) ([]models.DockerfileTemplate, error)
	GetTemplate(ctx context.Context, id uuid.UUID) (*models.DockerfileTemplate, error)
	CreateTemplate(ctx context.Context, hostID uuid.UUID, name, description, category, dockerfile string, userID *uuid.UUID) (*models.DockerfileTemplate, error)
	DeleteTemplate(ctx context.Context, id uuid.UUID) error

	LogChannel(buildID uuid.UUID) string
	MaxContextBytes() int64
}

// LogStream is the narrow Redis-pubsub-shaped surface the handler uses
// to bridge build logs into a WebSocket / SSE response. The production
// implementation wraps *redis.PubSub via the
// imagebuilder.RedisLogPublisher adapter; tests can pass a memory
// channel.
type LogStream interface {
	Subscribe(ctx context.Context, channel string, handler redis.MessageHandler) error
	Unsubscribe(ctx context.Context, channel string) error
}

// ImageBuilderHandler handles /api/v1/builds and /api/v1/build-templates.
// The svc field is nil-safe: when nil every handler returns 503 so the
// route tree mounts cleanly during early app boot. The logStream may
// also be nil — log streaming endpoints then return 503 individually.
type ImageBuilderHandler struct {
	BaseHandler
	svc       ImageBuilderService
	logStream LogStream
	hostIDFn  func(*http.Request) uuid.UUID
}

// NewImageBuilderHandler constructs the handler. logStream may be nil
// when the deployment runs without Redis; live log streaming endpoints
// then return 503 instead of mounting a dead WebSocket.
func NewImageBuilderHandler(svc ImageBuilderService, logStream LogStream, hostIDFn func(*http.Request) uuid.UUID, log *logger.Logger) *ImageBuilderHandler {
	return &ImageBuilderHandler{
		BaseHandler: NewBaseHandler(log),
		svc:         svc,
		logStream:   logStream,
		hostIDFn:    hostIDFn,
	}
}

// Routes returns the chi router for the build + template endpoints.
//
//	Builds (mount at /builds):
//	  GET    /api/v1/builds                 (viewer)  — paginated list
//	  POST   /api/v1/builds                 (operator) — start a new build
//	  GET    /api/v1/builds/stats           (viewer)
//	  GET    /api/v1/builds/{id}            (viewer)
//	  GET    /api/v1/builds/{id}/log        (viewer)  — WebSocket OR SSE depending on Accept header
//
//	Templates (mount at /build-templates):
//	  GET    /api/v1/build-templates        (viewer)
//	  POST   /api/v1/build-templates        (operator)
//	  GET    /api/v1/build-templates/{id}   (viewer)
//	  DELETE /api/v1/build-templates/{id}   (operator)
//
// Each registration applies per-method RBAC inline so the deployer can
// shrink permissions without editing the handler code.
func (h *ImageBuilderHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.With(middleware.RequireViewer).Get("/", h.ListBuilds)
	r.With(middleware.RequireOperator).Post("/", h.StartBuild)
	r.With(middleware.RequireViewer).Get("/stats", h.Stats)

	r.Route("/{id}", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.GetBuild)
		r.With(middleware.RequireViewer).Get("/log", h.StreamLog)
	})

	return r
}

// TemplateRoutes returns the chi router for the Dockerfile template
// endpoints. Mounted separately so the API path stays the documented
// `/api/v1/build-templates` rather than nested under /builds.
func (h *ImageBuilderHandler) TemplateRoutes() chi.Router {
	r := chi.NewRouter()

	r.With(middleware.RequireViewer).Get("/", h.ListTemplates)
	r.With(middleware.RequireOperator).Post("/", h.CreateTemplate)

	r.Route("/{id}", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.GetTemplate)
		r.With(middleware.RequireOperator).Delete("/", h.DeleteTemplate)
	})

	return r
}

// ============================================================================
// DTOs
// ============================================================================

// CreateBuildRequest is the body for POST /api/v1/builds. Tags is
// required; everything else is optional. The Dockerfile is paste-only
// for v26.5.1 — multi-file uploads are out of scope.
type CreateBuildRequest struct {
	Name        string            `json:"name,omitempty" validate:"omitempty,max=255"`
	Tags        []string          `json:"tags" validate:"required,min=1,max=10,dive,min=1,max=255"`
	Dockerfile  string            `json:"dockerfile" validate:"required,min=1"`
	ContextPath string            `json:"context_path,omitempty" validate:"omitempty,max=1024"`
	BuildArgs   map[string]string `json:"build_args,omitempty" validate:"omitempty,max=64"`
	Labels      map[string]string `json:"labels,omitempty" validate:"omitempty,max=64"`
	NoCache     bool              `json:"no_cache,omitempty"`
	Pull        bool              `json:"pull,omitempty"`
	Platform    string            `json:"platform,omitempty" validate:"omitempty,max=64"`
	Target      string            `json:"target,omitempty" validate:"omitempty,max=255"`
}

// CreateBuildTemplateRequest is the body for POST /api/v1/build-templates.
// Renamed from `CreateTemplateRequest` because the config handler already
// owns that name in the same package.
type CreateBuildTemplateRequest struct {
	Name        string `json:"name" validate:"required,min=1,max=255"`
	Description string `json:"description,omitempty" validate:"omitempty,max=1024"`
	Category    string `json:"category,omitempty" validate:"omitempty,oneof=web api database worker custom"`
	Dockerfile  string `json:"dockerfile" validate:"required,min=1"`
}

// BuildResponse is the API view of a build job. Output is intentionally
// the trailing-window value; live logs go through the /log endpoint.
type BuildResponse struct {
	ID           string   `json:"id"`
	HostID       string   `json:"host_id"`
	Name         string   `json:"name"`
	Tags         []string `json:"tags"`
	Dockerfile   string   `json:"dockerfile,omitempty"`
	ContextPath  string   `json:"context_path,omitempty"`
	Status       string   `json:"status"`
	Output       string   `json:"output,omitempty"`
	ErrorMessage string   `json:"error_message,omitempty"`
	ImageID      string   `json:"image_id,omitempty"`
	ImageSize    int64    `json:"image_size"`
	DurationMs   int      `json:"duration_ms"`
	Platform     string   `json:"platform,omitempty"`
	Signed       bool     `json:"signed"`
	SignatureRef string   `json:"signature_ref,omitempty"`
	CreatedBy    *string  `json:"created_by,omitempty"`
	StartedAt    *string  `json:"started_at,omitempty"`
	CompletedAt  *string  `json:"completed_at,omitempty"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
}

// BuildListResponse pairs the page rows with pagination metadata.
type BuildListResponse struct {
	Builds   []BuildResponse `json:"builds"`
	Total    int             `json:"total"`
	Page     int             `json:"page"`
	PageSize int             `json:"page_size"`
}

// BuildTemplateResponse is the API view of a Dockerfile template. The
// `BuildTemplate` prefix avoids a collision with the config handler's
// existing `TemplateResponse`.
type BuildTemplateResponse struct {
	ID          string `json:"id"`
	HostID      string `json:"host_id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Category    string `json:"category"`
	Dockerfile  string `json:"dockerfile"`
	IsBuiltin   bool   `json:"is_builtin"`
	CreatedBy   string `json:"created_by,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// BuildStatsResponse is the API view of aggregate stats.
type BuildStatsResponse struct {
	TotalBuilds   int     `json:"total_builds"`
	Successful    int     `json:"successful"`
	Failed        int     `json:"failed"`
	Building      int     `json:"building"`
	AvgDurationMs int     `json:"avg_duration_ms"`
	LastBuildAt   *string `json:"last_build_at,omitempty"`
}

// ============================================================================
// Handlers — Builds
// ============================================================================

// ListBuilds handles GET /api/v1/builds. Paginated by ?page=&page_size=.
func (h *ImageBuilderHandler) ListBuilds(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	page := h.QueryParamInt(r, "page", 1)
	if page < 1 {
		page = 1
	}
	pageSize := h.QueryParamInt(r, "page_size", 50)
	if pageSize < 1 || pageSize > 200 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize

	builds, total, err := h.svc.ListBuilds(r.Context(), hostID, pageSize, offset)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	out := make([]BuildResponse, 0, len(builds))
	for i := range builds {
		out = append(out, toBuildResponse(&builds[i], false))
	}
	h.OK(w, BuildListResponse{
		Builds:   out,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	})
}

// StartBuild handles POST /api/v1/builds. Builds run synchronously
// inside this call so the resulting job row reflects the final outcome
// — clients that want live logs subscribe to /log first, then issue the
// POST. Improvement vs v26.2.7: real Docker invocation, log streaming,
// and the imagesign hook all wire in via the service rather than this
// handler.
func (h *ImageBuilderHandler) StartBuild(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req CreateBuildRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	userID, _ := h.GetUserID(r)
	var userIDPtr *uuid.UUID
	if userID != uuid.Nil {
		userIDPtr = &userID
	}

	job, err := h.svc.StartBuild(r.Context(), imagebuildersvc.StartBuildOptions{
		HostID:      hostID,
		Name:        req.Name,
		Tags:        req.Tags,
		Dockerfile:  req.Dockerfile,
		ContextPath: req.ContextPath,
		BuildArgs:   req.BuildArgs,
		Labels:      req.Labels,
		NoCache:     req.NoCache,
		Pull:        req.Pull,
		Platform:    req.Platform,
		Target:      req.Target,
		UserID:      userIDPtr,
	})
	if err != nil {
		switch {
		case stderrors.Is(err, imagebuildersvc.ErrInvalidInput):
			h.Error(w, apierrors.InvalidInput(err.Error()))
		case stderrors.Is(err, imagebuildersvc.ErrContextTooLarge):
			h.Error(w, apierrors.ArtifactTooLarge(h.svc.MaxContextBytes()))
		case stderrors.Is(err, imagebuildersvc.ErrBuilderUnavailable):
			h.Error(w, apierrors.ServiceUnavailable("docker daemon is not available to the image builder"))
		default:
			h.HandleError(w, err)
		}
		return
	}

	h.JSON(w, http.StatusAccepted, toBuildResponse(job, true))
}

// GetBuild handles GET /api/v1/builds/{id}.
func (h *ImageBuilderHandler) GetBuild(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	job, err := h.svc.GetBuild(r.Context(), id)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	h.OK(w, toBuildResponse(job, true))
}

// Stats handles GET /api/v1/builds/stats.
func (h *ImageBuilderHandler) Stats(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	stats, err := h.svc.GetStats(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	resp := BuildStatsResponse{
		TotalBuilds:   stats.TotalBuilds,
		Successful:    stats.Successful,
		Failed:        stats.Failed,
		Building:      stats.Building,
		AvgDurationMs: stats.AvgDurationMs,
	}
	if stats.LastBuildAt != nil {
		s := stats.LastBuildAt.Format(time.RFC3339)
		resp.LastBuildAt = &s
	}
	h.OK(w, resp)
}

// StreamLog handles GET /api/v1/builds/{id}/log. The transport is
// negotiated from the Accept header: text/event-stream → SSE,
// otherwise → WebSocket. Both paths subscribe to the same Redis
// channel so the wire content is identical.
//
// Improvement vs v26.2.7: log streaming did not exist; the v26.2.7 web
// page rendered a static synthetic "build completed" string after the
// fact. v26.5.1 streams the daemon's own NDJSON output via Redis.
func (h *ImageBuilderHandler) StreamLog(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	if h.logStream == nil {
		h.Error(w, apierrors.ServiceUnavailable("log streaming is disabled (Redis not configured)"))
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	// Confirm the job exists so we don't silently subscribe to a dead channel.
	if _, err := h.svc.GetBuild(r.Context(), id); err != nil {
		h.HandleError(w, err)
		return
	}

	channel := h.svc.LogChannel(id)
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/event-stream") {
		h.streamLogSSE(w, r, channel)
		return
	}
	h.streamLogWS(w, r, channel)
}

// streamLogSSE bridges the Redis channel into an SSE response.
func (h *ImageBuilderHandler) streamLogSSE(w http.ResponseWriter, r *http.Request, channel string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		h.Error(w, apierrors.Internal("streaming not supported by underlying http connection"))
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	var (
		mu      sync.Mutex
		closeCh = make(chan struct{}, 1)
	)

	handler := func(_ context.Context, msg *redis.Message) {
		mu.Lock()
		defer mu.Unlock()
		if _, err := fmt.Fprintf(w, "data: %s\n\n", string(msg.Payload)); err != nil {
			select {
			case closeCh <- struct{}{}:
			default:
			}
			return
		}
		flusher.Flush()
	}

	if err := h.logStream.Subscribe(ctx, channel, handler); err != nil {
		h.Logger().Error("imagebuilder: SSE subscribe failed", "channel", channel, "error", err)
		return
	}
	defer func() {
		_ = h.logStream.Unsubscribe(context.Background(), channel)
	}()

	mu.Lock()
	_, _ = io.WriteString(w, ": connected\n\n")
	flusher.Flush()
	mu.Unlock()

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-closeCh:
			return
		case <-keepalive.C:
			mu.Lock()
			_, err := io.WriteString(w, ": ping\n\n")
			if err != nil {
				mu.Unlock()
				return
			}
			flusher.Flush()
			mu.Unlock()
		}
	}
}

// streamLogWS bridges the Redis channel into a WebSocket response.
func (h *ImageBuilderHandler) streamLogWS(w http.ResponseWriter, r *http.Request, channel string) {
	conn, err := WebSocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		h.Logger().Error("imagebuilder: websocket upgrade failed", "channel", channel, "error", err)
		return
	}
	defer conn.Close()

	conn.SetReadLimit(MaxMessageSize)
	_ = conn.SetReadDeadline(time.Now().Add(PongWait))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(PongWait))
		return nil
	})

	var (
		mu      sync.Mutex
		closeCh = make(chan struct{}, 1)
	)

	handler := func(_ context.Context, msg *redis.Message) {
		mu.Lock()
		defer mu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(WriteWait))
		if err := conn.WriteMessage(websocket.TextMessage, msg.Payload); err != nil {
			select {
			case closeCh <- struct{}{}:
			default:
			}
		}
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	if err := h.logStream.Subscribe(ctx, channel, handler); err != nil {
		h.Logger().Error("imagebuilder: ws subscribe failed", "channel", channel, "error", err)
		return
	}
	defer func() {
		_ = h.logStream.Unsubscribe(context.Background(), channel)
	}()

	// Send a hello so the client can confirm the subscription is live
	// before the first daemon log line lands.
	mu.Lock()
	_ = conn.SetWriteDeadline(time.Now().Add(WriteWait))
	if err := conn.WriteJSON(WSMessage{Type: "connected"}); err != nil {
		mu.Unlock()
		return
	}
	mu.Unlock()

	pingTicker := time.NewTicker(PingPeriod)
	defer pingTicker.Stop()

	readErrCh := make(chan struct{})
	go func() {
		defer close(readErrCh)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-closeCh:
			return
		case <-readErrCh:
			return
		case <-pingTicker.C:
			mu.Lock()
			_ = conn.SetWriteDeadline(time.Now().Add(WriteWait))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				mu.Unlock()
				return
			}
			mu.Unlock()
		}
	}
}

// ============================================================================
// Handlers — Templates
// ============================================================================

// ListTemplates handles GET /api/v1/build-templates.
func (h *ImageBuilderHandler) ListTemplates(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	templates, err := h.svc.ListTemplates(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	out := make([]BuildTemplateResponse, 0, len(templates))
	for i := range templates {
		out = append(out, toBuildTemplateResponse(&templates[i]))
	}
	h.OK(w, out)
}

// GetTemplate handles GET /api/v1/build-templates/{id}.
func (h *ImageBuilderHandler) GetTemplate(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	t, err := h.svc.GetTemplate(r.Context(), id)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	h.OK(w, toBuildTemplateResponse(t))
}

// CreateTemplate handles POST /api/v1/build-templates.
func (h *ImageBuilderHandler) CreateTemplate(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	var req CreateBuildTemplateRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	userID, _ := h.GetUserID(r)
	var userIDPtr *uuid.UUID
	if userID != uuid.Nil {
		userIDPtr = &userID
	}
	t, err := h.svc.CreateTemplate(r.Context(), hostID, req.Name, req.Description, req.Category, req.Dockerfile, userIDPtr)
	if err != nil {
		if stderrors.Is(err, imagebuildersvc.ErrInvalidInput) {
			h.Error(w, apierrors.InvalidInput(err.Error()))
			return
		}
		h.HandleError(w, err)
		return
	}
	h.Created(w, toBuildTemplateResponse(t))
}

// DeleteTemplate handles DELETE /api/v1/build-templates/{id}.
func (h *ImageBuilderHandler) DeleteTemplate(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	if err := h.svc.DeleteTemplate(r.Context(), id); err != nil {
		switch {
		case stderrors.Is(err, imagebuildersvc.ErrBuiltinDelete):
			h.Error(w, apierrors.Forbidden("built-in templates cannot be deleted"))
		default:
			h.HandleError(w, err)
		}
		return
	}
	h.NoContent(w)
}

// ============================================================================
// Helpers
// ============================================================================

func (h *ImageBuilderHandler) serviceUnavailable(w http.ResponseWriter) {
	apierrors.WriteError(w, apierrors.ServiceUnavailable("image builder is not configured"))
}

// resolveHostID resolves the host UUID from the closure first, then from
// the standard X-Host-ID header / ?host_id= query string. Returns the
// MissingField error so the API contract is consistent with the other
// per-host handlers.
func (h *ImageBuilderHandler) resolveHostID(r *http.Request) (uuid.UUID, error) {
	if h.hostIDFn != nil {
		if id := h.hostIDFn(r); id != uuid.Nil {
			return id, nil
		}
	}
	if q := h.QueryParam(r, "host_id"); q != "" {
		id, err := uuid.Parse(q)
		if err != nil {
			return uuid.Nil, apierrors.InvalidInput("invalid host_id format")
		}
		return id, nil
	}
	if hdr := r.Header.Get("X-Host-ID"); hdr != "" {
		id, err := uuid.Parse(hdr)
		if err != nil {
			return uuid.Nil, apierrors.InvalidInput("invalid X-Host-ID format")
		}
		return id, nil
	}
	return uuid.Nil, apierrors.MissingField("host_id")
}

// toBuildResponse converts the model into the wire shape. The
// includeDockerfile flag stays false in list views so the full payload
// is not shipped on every page render.
func toBuildResponse(b *models.ImageBuildJob, includeDockerfile bool) BuildResponse {
	if b == nil {
		return BuildResponse{}
	}
	resp := BuildResponse{
		ID:           b.ID.String(),
		HostID:       b.HostID.String(),
		Name:         b.Name,
		Tags:         b.Tags,
		ContextPath:  b.ContextPath,
		Status:       string(b.Status),
		Output:       b.Output,
		ErrorMessage: b.ErrorMessage,
		ImageID:      b.ImageID,
		ImageSize:    b.ImageSize,
		DurationMs:   b.DurationMs,
		Platform:     b.Platform,
		Signed:       b.Signed,
		SignatureRef: b.SignatureRef,
		CreatedAt:    b.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    b.UpdatedAt.Format(time.RFC3339),
	}
	if includeDockerfile {
		resp.Dockerfile = b.Dockerfile
	}
	if b.CreatedBy != nil {
		s := b.CreatedBy.String()
		resp.CreatedBy = &s
	}
	if b.StartedAt != nil {
		s := b.StartedAt.Format(time.RFC3339)
		resp.StartedAt = &s
	}
	if b.CompletedAt != nil {
		s := b.CompletedAt.Format(time.RFC3339)
		resp.CompletedAt = &s
	}
	return resp
}

func toBuildTemplateResponse(t *models.DockerfileTemplate) BuildTemplateResponse {
	if t == nil {
		return BuildTemplateResponse{}
	}
	resp := BuildTemplateResponse{
		ID:          t.ID.String(),
		HostID:      t.HostID.String(),
		Name:        t.Name,
		Description: t.Description,
		Category:    t.Category,
		Dockerfile:  t.Dockerfile,
		IsBuiltin:   t.IsBuiltin,
		CreatedAt:   t.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   t.UpdatedAt.Format(time.RFC3339),
	}
	if t.CreatedBy != nil {
		resp.CreatedBy = t.CreatedBy.String()
	}
	return resp
}
