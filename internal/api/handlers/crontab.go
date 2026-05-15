// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"context"
	"encoding/json"
	stderrors "errors"
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
	crontabsvc "github.com/fr4nsys/usulnet/internal/services/crontab"
)

// CrontabService is the narrow interface this handler depends on,
// satisfied by *crontab.Service. Declaring it here lets the handler
// be unit-tested with a mock without importing the concrete service.
// v26.2.7 had no API handler at all — this is a new boundary.
type CrontabService interface {
	List(ctx context.Context, hostID uuid.UUID) ([]*models.CrontabEntry, error)
	Get(ctx context.Context, id uuid.UUID) (*models.CrontabEntry, error)
	Create(ctx context.Context, hostID uuid.UUID, input models.CreateCrontabInput, userID *uuid.UUID) (*models.CrontabEntry, error)
	Update(ctx context.Context, id uuid.UUID, input models.UpdateCrontabInput) (*models.CrontabEntry, error)
	Delete(ctx context.Context, id uuid.UUID) error
	ToggleEnabled(ctx context.Context, id uuid.UUID, enabled bool) error
	RunNow(ctx context.Context, id uuid.UUID) error
	ListExecutions(ctx context.Context, entryID uuid.UUID, limit, offset int) ([]*models.CrontabExecution, error)
	CountExecutions(ctx context.Context, entryID uuid.UUID) (int, error)
	GetStats(ctx context.Context, hostID uuid.UUID) (*models.CrontabStats, error)
	AddExecutionListener(l crontabsvc.ExecutionListener) func()
}

// CrontabHandler handles /api/v1/crontab/* requests. The svc field is
// nil-safe: when it is nil every handler returns 503 service_unavailable
// so the routes still mount cleanly during early app boot.
type CrontabHandler struct {
	BaseHandler
	svc      CrontabService
	hostIDFn func(*http.Request) uuid.UUID
}

// NewCrontabHandler creates a new crontab handler. hostIDFn resolves
// the active host ID for a given request; the standalone-mode app
// passes a closure returning the default host UUID.
func NewCrontabHandler(svc CrontabService, hostIDFn func(*http.Request) uuid.UUID, log *logger.Logger) *CrontabHandler {
	return &CrontabHandler{
		BaseHandler: NewBaseHandler(log),
		svc:         svc,
		hostIDFn:    hostIDFn,
	}
}

// Routes returns the chi router for /api/v1/crontab.
// Read endpoints are viewer+, mutations are operator+, run-now and
// toggle are operator+. The caller is responsible for placing the
// subtree behind the JWT/API-key auth middleware.
func (h *CrontabHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Route("/entries", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.ListEntries)
		r.With(middleware.RequireOperator).Post("/", h.CreateEntry)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.RequireViewer).Get("/", h.GetEntry)
			r.With(middleware.RequireOperator).Put("/", h.UpdateEntry)
			r.With(middleware.RequireOperator).Delete("/", h.DeleteEntry)
			r.With(middleware.RequireOperator).Post("/run", h.RunNow)
			r.With(middleware.RequireOperator).Post("/toggle", h.Toggle)
		})
	})

	r.With(middleware.RequireViewer).Get("/executions", h.ListExecutions)
	r.With(middleware.RequireViewer).Get("/stats", h.GetStats)

	// WebSocket live tail of executions. Subscribers receive every
	// completed execution from the moment they connect.
	r.With(middleware.RequireViewer).Get("/executions/tail", h.TailExecutions)

	return r
}

// ============================================================================
// DTOs
// ============================================================================

// CreateCrontabRequest is the body for POST /api/v1/crontab/entries.
type CreateCrontabRequest struct {
	HostID      string  `json:"host_id,omitempty" validate:"omitempty,uuid"`
	Name        string  `json:"name" validate:"required,min=1,max=255"`
	Description string  `json:"description,omitempty" validate:"omitempty,max=1024"`
	Schedule    string  `json:"schedule" validate:"required,min=1,max=100"`
	CommandType string  `json:"command_type,omitempty" validate:"omitempty,oneof=shell docker http"`
	Command     string  `json:"command" validate:"required"`
	ContainerID *string `json:"container_id,omitempty"`
	WorkingDir  *string `json:"working_dir,omitempty"`
	HTTPMethod  *string `json:"http_method,omitempty" validate:"omitempty,oneof=GET POST PUT DELETE PATCH HEAD"`
	HTTPURL     *string `json:"http_url,omitempty"`
	Enabled     bool    `json:"enabled"`
}

// UpdateCrontabRequest is the body for PUT /api/v1/crontab/entries/{id}.
// All fields are optional — only the supplied ones are patched.
type UpdateCrontabRequest struct {
	Name        *string `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	Description *string `json:"description,omitempty" validate:"omitempty,max=1024"`
	Schedule    *string `json:"schedule,omitempty" validate:"omitempty,min=1,max=100"`
	CommandType *string `json:"command_type,omitempty" validate:"omitempty,oneof=shell docker http"`
	Command     *string `json:"command,omitempty"`
	ContainerID *string `json:"container_id,omitempty"`
	WorkingDir  *string `json:"working_dir,omitempty"`
	HTTPMethod  *string `json:"http_method,omitempty" validate:"omitempty,oneof=GET POST PUT DELETE PATCH HEAD"`
	HTTPURL     *string `json:"http_url,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
}

// ToggleCrontabRequest is the body for POST /api/v1/crontab/entries/{id}/toggle.
type ToggleCrontabRequest struct {
	Enabled bool `json:"enabled"`
}

// CrontabEntryResponse is the API view of a crontab entry.
type CrontabEntryResponse struct {
	ID            string  `json:"id"`
	HostID        string  `json:"host_id"`
	Name          string  `json:"name"`
	Description   string  `json:"description,omitempty"`
	Schedule      string  `json:"schedule"`
	CommandType   string  `json:"command_type"`
	Command       string  `json:"command"`
	ContainerID   *string `json:"container_id,omitempty"`
	WorkingDir    *string `json:"working_dir,omitempty"`
	HTTPMethod    *string `json:"http_method,omitempty"`
	HTTPURL       *string `json:"http_url,omitempty"`
	Enabled       bool    `json:"enabled"`
	RunCount      int64   `json:"run_count"`
	FailCount     int64   `json:"fail_count"`
	LastRunAt     *string `json:"last_run_at,omitempty"`
	LastRunStatus *string `json:"last_run_status,omitempty"`
	NextRunAt     *string `json:"next_run_at,omitempty"`
	CreatedBy     *string `json:"created_by,omitempty"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

// CrontabExecutionResponse is the API view of one execution record.
type CrontabExecutionResponse struct {
	ID         string  `json:"id"`
	EntryID    string  `json:"entry_id"`
	HostID     string  `json:"host_id"`
	Status     string  `json:"status"`
	Output     string  `json:"output,omitempty"`
	Error      string  `json:"error,omitempty"`
	ExitCode   *int    `json:"exit_code,omitempty"`
	DurationMs int64   `json:"duration_ms"`
	StartedAt  string  `json:"started_at"`
	FinishedAt string  `json:"finished_at"`
	EntryName  *string `json:"entry_name,omitempty"`
}

// CrontabExecutionPage is the paginated executions response. v26.2.7
// loaded every row; v26.5.1 caps the page size to 100 by default and
// surfaces the total count for the client to drive pagination.
type CrontabExecutionPage struct {
	Entries []CrontabExecutionResponse `json:"entries"`
	Total   int                        `json:"total"`
	Limit   int                        `json:"limit"`
	Offset  int                        `json:"offset"`
}

// CrontabStatsResponse is the API view of CrontabStats.
type CrontabStatsResponse struct {
	Total    int `json:"total"`
	Enabled  int `json:"enabled"`
	Disabled int `json:"disabled"`
	Running  int `json:"running"`
}

// ============================================================================
// Entry handlers
// ============================================================================

// ListEntries handles GET /api/v1/crontab/entries.
func (h *CrontabHandler) ListEntries(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	entries, err := h.svc.List(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	resp := make([]CrontabEntryResponse, len(entries))
	for i, e := range entries {
		resp[i] = toCrontabEntryResponse(e)
	}
	h.OK(w, resp)
}

// GetEntry handles GET /api/v1/crontab/entries/{id}.
func (h *CrontabHandler) GetEntry(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	entry, err := h.svc.Get(r.Context(), id)
	if err != nil {
		h.HandleError(w, mapCrontabError(err))
		return
	}
	h.OK(w, toCrontabEntryResponse(entry))
}

// CreateEntry handles POST /api/v1/crontab/entries.
func (h *CrontabHandler) CreateEntry(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	var req CreateCrontabRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	hostID, err := h.resolveHostIDFromBody(r, req.HostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	actor, _ := h.GetUserID(r)
	cmdType := models.CrontabCommandShell
	if req.CommandType != "" {
		cmdType = models.CrontabCommandType(req.CommandType)
	}

	in := models.CreateCrontabInput{
		Name:        req.Name,
		Description: req.Description,
		Schedule:    req.Schedule,
		CommandType: cmdType,
		Command:     req.Command,
		ContainerID: req.ContainerID,
		WorkingDir:  req.WorkingDir,
		HTTPMethod:  req.HTTPMethod,
		HTTPURL:     req.HTTPURL,
		Enabled:     req.Enabled,
	}

	entry, err := h.svc.Create(r.Context(), hostID, in, nilableUUID(actor))
	if err != nil {
		h.HandleError(w, mapCrontabError(err))
		return
	}
	h.Created(w, toCrontabEntryResponse(entry))
}

// UpdateEntry handles PUT /api/v1/crontab/entries/{id}.
func (h *CrontabHandler) UpdateEntry(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	var req UpdateCrontabRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	in := models.UpdateCrontabInput{
		Name:        req.Name,
		Description: req.Description,
		Schedule:    req.Schedule,
		Command:     req.Command,
		ContainerID: req.ContainerID,
		WorkingDir:  req.WorkingDir,
		HTTPMethod:  req.HTTPMethod,
		HTTPURL:     req.HTTPURL,
		Enabled:     req.Enabled,
	}
	if req.CommandType != nil {
		t := models.CrontabCommandType(*req.CommandType)
		in.CommandType = &t
	}

	entry, err := h.svc.Update(r.Context(), id, in)
	if err != nil {
		h.HandleError(w, mapCrontabError(err))
		return
	}
	h.OK(w, toCrontabEntryResponse(entry))
}

// DeleteEntry handles DELETE /api/v1/crontab/entries/{id}.
func (h *CrontabHandler) DeleteEntry(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	if err := h.svc.Delete(r.Context(), id); err != nil {
		h.HandleError(w, mapCrontabError(err))
		return
	}
	h.NoContent(w)
}

// RunNow handles POST /api/v1/crontab/entries/{id}/run. Returns 202
// because the execution is started asynchronously and the row appears
// in /executions when it finishes.
func (h *CrontabHandler) RunNow(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	if err := h.svc.RunNow(r.Context(), id); err != nil {
		h.HandleError(w, mapCrontabError(err))
		return
	}
	h.JSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

// Toggle handles POST /api/v1/crontab/entries/{id}/toggle.
func (h *CrontabHandler) Toggle(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	var req ToggleCrontabRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	if err := h.svc.ToggleEnabled(r.Context(), id, req.Enabled); err != nil {
		h.HandleError(w, mapCrontabError(err))
		return
	}
	h.NoContent(w)
}

// ============================================================================
// Executions
// ============================================================================

// ListExecutions handles GET /api/v1/crontab/executions?entry_id=…&limit=…&offset=….
// limit defaults to 100 and is capped at 100.
func (h *CrontabHandler) ListExecutions(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	entryIDStr := h.QueryParam(r, "entry_id")
	if entryIDStr == "" {
		h.HandleError(w, apierrors.MissingField("entry_id"))
		return
	}
	entryID, err := uuid.Parse(entryIDStr)
	if err != nil {
		h.HandleError(w, apierrors.InvalidInput("invalid entry_id format"))
		return
	}

	limit := h.QueryParamInt(r, "limit", crontabsvc.MaxExecutionsPerPage)
	offset := h.QueryParamInt(r, "offset", 0)
	if offset < 0 {
		offset = 0
	}

	executions, err := h.svc.ListExecutions(r.Context(), entryID, limit, offset)
	if err != nil {
		h.HandleError(w, mapCrontabError(err))
		return
	}
	total, err := h.svc.CountExecutions(r.Context(), entryID)
	if err != nil {
		h.HandleError(w, mapCrontabError(err))
		return
	}

	resp := make([]CrontabExecutionResponse, len(executions))
	for i, e := range executions {
		resp[i] = toCrontabExecutionResponse(e, "")
	}
	h.OK(w, CrontabExecutionPage{
		Entries: resp,
		Total:   total,
		Limit:   clampLimitForAPI(limit),
		Offset:  offset,
	})
}

// GetStats handles GET /api/v1/crontab/stats.
func (h *CrontabHandler) GetStats(w http.ResponseWriter, r *http.Request) {
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
	resp := CrontabStatsResponse{}
	if stats != nil {
		resp = CrontabStatsResponse(*stats)
	}
	h.OK(w, resp)
}

// ============================================================================
// WebSocket execution tail
// ============================================================================

// crontabWSListener bridges the service's ExecutionListener interface to a
// WebSocket connection. Writes are mutex-guarded because gorilla/websocket
// is not safe for concurrent writes.
type crontabWSListener struct {
	conn    *websocket.Conn
	mu      *sync.Mutex
	filter  *uuid.UUID
	closeCh chan struct{}
}

// OnExecution implements crontabsvc.ExecutionListener. Filtering by entry
// happens before the lock so an unfocused tail does not stall when the
// listener is suspended.
func (l *crontabWSListener) OnExecution(ex *models.CrontabExecution, entryName string) {
	if l.filter != nil && ex.EntryID != *l.filter {
		return
	}
	msg := WSMessage{
		Type:    "execution",
		Payload: toCrontabExecutionResponse(ex, entryName),
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.conn.SetWriteDeadline(time.Now().Add(WriteWait))
	if err := l.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		select {
		case <-l.closeCh:
		default:
			close(l.closeCh)
		}
	}
}

// TailExecutions handles GET /api/v1/crontab/executions/tail (WebSocket).
// Optional ?entry_id=<uuid> filters the stream to one entry. The handler
// keeps the connection open until the client closes or the service stops.
func (h *CrontabHandler) TailExecutions(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}

	var filter *uuid.UUID
	if q := h.QueryParam(r, "entry_id"); q != "" {
		id, err := uuid.Parse(q)
		if err != nil {
			h.HandleError(w, apierrors.InvalidInput("invalid entry_id format"))
			return
		}
		filter = &id
	}

	conn, err := WebSocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		h.Logger().Error("crontab tail: websocket upgrade failed", "error", err)
		return
	}
	defer conn.Close()

	conn.SetReadLimit(MaxMessageSize)
	_ = conn.SetReadDeadline(time.Now().Add(PongWait))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(PongWait))
		return nil
	})

	listener := &crontabWSListener{
		conn:    conn,
		mu:      &sync.Mutex{},
		filter:  filter,
		closeCh: make(chan struct{}),
	}
	deregister := h.svc.AddExecutionListener(listener)
	defer deregister()

	listener.mu.Lock()
	_ = conn.SetWriteDeadline(time.Now().Add(WriteWait))
	if err := conn.WriteJSON(WSMessage{Type: "connected"}); err != nil {
		listener.mu.Unlock()
		return
	}
	listener.mu.Unlock()

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
		case <-listener.closeCh:
			return
		case <-readErrCh:
			return
		case <-pingTicker.C:
			listener.mu.Lock()
			_ = conn.SetWriteDeadline(time.Now().Add(WriteWait))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				listener.mu.Unlock()
				return
			}
			listener.mu.Unlock()
		}
	}
}

// ============================================================================
// Helpers
// ============================================================================

func (h *CrontabHandler) serviceUnavailable(w http.ResponseWriter) {
	apierrors.WriteError(w, apierrors.ServiceUnavailable("crontab service is not configured"))
}

func (h *CrontabHandler) resolveHostID(r *http.Request) (uuid.UUID, error) {
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

func (h *CrontabHandler) resolveHostIDFromBody(r *http.Request, bodyHostID string) (uuid.UUID, error) {
	if bodyHostID != "" {
		id, err := uuid.Parse(bodyHostID)
		if err != nil {
			return uuid.Nil, apierrors.InvalidInput("invalid host_id format")
		}
		return id, nil
	}
	return h.resolveHostID(r)
}

// mapCrontabError translates package-level crontab errors to API errors.
func mapCrontabError(err error) error {
	switch {
	case stderrors.Is(err, crontabsvc.ErrInvalidSchedule):
		return apierrors.InvalidInput(err.Error())
	case stderrors.Is(err, crontabsvc.ErrInvalidInput):
		return apierrors.InvalidInput(err.Error())
	}
	return err
}

func clampLimitForAPI(limit int) int {
	if limit <= 0 {
		return crontabsvc.MaxExecutionsPerPage
	}
	if limit > crontabsvc.MaxExecutionsPerPage {
		return crontabsvc.MaxExecutionsPerPage
	}
	return limit
}

func toCrontabEntryResponse(e *models.CrontabEntry) CrontabEntryResponse {
	resp := CrontabEntryResponse{
		ID:          e.ID.String(),
		HostID:      e.HostID.String(),
		Name:        e.Name,
		Description: e.Description,
		Schedule:    e.Schedule,
		CommandType: string(e.CommandType),
		Command:     e.Command,
		ContainerID: e.ContainerID,
		WorkingDir:  e.WorkingDir,
		HTTPMethod:  e.HTTPMethod,
		HTTPURL:     e.HTTPURL,
		Enabled:     e.Enabled,
		RunCount:    e.RunCount,
		FailCount:   e.FailCount,
		CreatedAt:   e.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   e.UpdatedAt.Format(time.RFC3339),
	}
	if e.LastRunAt != nil {
		s := e.LastRunAt.Format(time.RFC3339)
		resp.LastRunAt = &s
	}
	if e.LastRunStatus != nil {
		resp.LastRunStatus = e.LastRunStatus
	}
	if e.NextRunAt != nil {
		s := e.NextRunAt.Format(time.RFC3339)
		resp.NextRunAt = &s
	}
	if e.CreatedBy != nil {
		s := e.CreatedBy.String()
		resp.CreatedBy = &s
	}
	return resp
}

func toCrontabExecutionResponse(e *models.CrontabExecution, entryName string) CrontabExecutionResponse {
	resp := CrontabExecutionResponse{
		ID:         e.ID.String(),
		EntryID:    e.EntryID.String(),
		HostID:     e.HostID.String(),
		Status:     e.Status,
		Output:     e.Output,
		Error:      e.Error,
		ExitCode:   e.ExitCode,
		DurationMs: e.DurationMs,
		StartedAt:  e.StartedAt.Format(time.RFC3339),
		FinishedAt: e.FinishedAt.Format(time.RFC3339),
	}
	if entryName != "" {
		n := strings.Clone(entryName)
		resp.EntryName = &n
	}
	return resp
}
