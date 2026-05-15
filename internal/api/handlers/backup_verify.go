// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"context"
	stderrors "errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	backupverifysvc "github.com/fr4nsys/usulnet/internal/services/backupverify"
)

// BackupVerifyService is the narrow interface this handler depends on,
// satisfied by *backupverify.Service. Declaring it locally keeps the
// handler unit-testable without dragging the concrete service into tests.
// v26.2.7 shipped no REST API for verification — this is a new surface
// on the v26.5.1 merge.
type BackupVerifyService interface {
	RunVerification(ctx context.Context, backupID uuid.UUID, method models.VerificationMethod, userID *uuid.UUID) (*models.BackupVerification, error)
	ListVerifications(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]models.BackupVerification, int, error)
	ListByBackup(ctx context.Context, backupID uuid.UUID) ([]models.BackupVerification, error)
	GetVerification(ctx context.Context, id uuid.UUID) (*models.BackupVerification, error)
	GetStats(ctx context.Context, hostID uuid.UUID) (*models.BackupVerificationStats, error)

	ListSchedules(ctx context.Context, hostID uuid.UUID) ([]models.BackupVerificationSchedule, error)
	GetSchedule(ctx context.Context, id uuid.UUID) (*models.BackupVerificationSchedule, error)
	CreateSchedule(ctx context.Context, hostID uuid.UUID, schedule, method string, maxBackups int) (*models.BackupVerificationSchedule, error)
	UpdateSchedule(ctx context.Context, id uuid.UUID, schedule, method *string, maxBackups *int, enabled *bool) (*models.BackupVerificationSchedule, error)
	DeleteSchedule(ctx context.Context, id uuid.UUID) error
}

// BackupVerifyHandler handles /api/v1/backup-verify/* requests. svc is
// nil-safe: when nil, every endpoint returns 503 so routes still mount
// during early app boot.
type BackupVerifyHandler struct {
	BaseHandler
	svc      BackupVerifyService
	hostIDFn func(*http.Request) uuid.UUID
}

// NewBackupVerifyHandler creates a backup verify API handler. hostIDFn
// resolves the active host ID for a request; the standalone-mode app
// passes a closure returning the default host UUID.
func NewBackupVerifyHandler(svc BackupVerifyService, hostIDFn func(*http.Request) uuid.UUID, log *logger.Logger) *BackupVerifyHandler {
	return &BackupVerifyHandler{
		BaseHandler: NewBaseHandler(log),
		svc:         svc,
		hostIDFn:    hostIDFn,
	}
}

// Routes returns the chi router for /api/v1/backup-verify.
// Reads are viewer+, runs and schedule mutations are operator+.
func (h *BackupVerifyHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Route("/runs", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.ListRuns)
		r.With(middleware.RequireViewer).Get("/{id}", h.GetRun)
	})

	r.With(middleware.RequireOperator).Post("/run/{backup_id}", h.RunVerify)
	r.With(middleware.RequireViewer).Get("/backups/{backup_id}/runs", h.ListRunsByBackup)
	r.With(middleware.RequireViewer).Get("/stats", h.GetStats)

	r.Route("/schedules", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.ListSchedules)
		r.With(middleware.RequireOperator).Post("/", h.CreateSchedule)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.RequireViewer).Get("/", h.GetSchedule)
			r.With(middleware.RequireOperator).Put("/", h.UpdateSchedule)
			r.With(middleware.RequireOperator).Delete("/", h.DeleteSchedule)
		})
	})

	return r
}

// ============================================================================
// DTOs
// ============================================================================

// RunVerifyRequest is the body for POST /api/v1/backup-verify/run/{backup_id}.
type RunVerifyRequest struct {
	Method string `json:"method,omitempty" validate:"omitempty,oneof=extract container database"`
}

// VerificationResponse is the API view of a BackupVerification row.
type VerificationResponse struct {
	ID            string  `json:"id"`
	BackupID      string  `json:"backup_id"`
	HostID        string  `json:"host_id"`
	Status        string  `json:"status"`
	Method        string  `json:"method"`
	ChecksumValid *bool   `json:"checksum_valid,omitempty"`
	FilesReadable *bool   `json:"files_readable,omitempty"`
	ContainerTest *bool   `json:"container_test,omitempty"`
	DataValid     *bool   `json:"data_valid,omitempty"`
	FileCount     int     `json:"file_count"`
	SizeBytes     int64   `json:"size_bytes"`
	DurationMs    int     `json:"duration_ms"`
	ErrorMessage  string  `json:"error_message,omitempty"`
	VerifiedBy    *string `json:"verified_by,omitempty"`
	StartedAt     *string `json:"started_at,omitempty"`
	CompletedAt   *string `json:"completed_at,omitempty"`
	CreatedAt     string  `json:"created_at"`
}

// VerificationPage is the paginated response for ListRuns.
type VerificationPage struct {
	Entries []VerificationResponse `json:"entries"`
	Total   int                    `json:"total"`
	Limit   int                    `json:"limit"`
	Offset  int                    `json:"offset"`
}

// VerificationStatsResponse mirrors models.BackupVerificationStats with
// stable JSON tags.
type VerificationStatsResponse struct {
	TotalVerified int     `json:"total_verified"`
	Passed        int     `json:"passed"`
	Failed        int     `json:"failed"`
	PassRate      float64 `json:"pass_rate"`
	LastVerified  string  `json:"last_verified,omitempty"`
}

// CreateVerifyScheduleRequest is the body for POST /api/v1/backup-verify/schedules.
type CreateVerifyScheduleRequest struct {
	HostID     string `json:"host_id,omitempty" validate:"omitempty,uuid"`
	Schedule   string `json:"schedule" validate:"required,min=1,max=100"`
	Method     string `json:"method" validate:"required,oneof=extract container database"`
	MaxBackups int    `json:"max_backups,omitempty" validate:"omitempty,gte=1,lte=50"`
}

// UpdateVerifyScheduleRequest is the body for PUT /api/v1/backup-verify/schedules/{id}.
// All fields are optional — only the supplied ones are applied.
type UpdateVerifyScheduleRequest struct {
	Schedule   *string `json:"schedule,omitempty" validate:"omitempty,min=1,max=100"`
	Method     *string `json:"method,omitempty" validate:"omitempty,oneof=extract container database"`
	MaxBackups *int    `json:"max_backups,omitempty" validate:"omitempty,gte=1,lte=50"`
	Enabled    *bool   `json:"enabled,omitempty"`
}

// VerifyScheduleResponse is the API view of a BackupVerificationSchedule.
type VerifyScheduleResponse struct {
	ID            string  `json:"id"`
	HostID        string  `json:"host_id"`
	Schedule      string  `json:"schedule"`
	Method        string  `json:"method"`
	MaxBackups    int     `json:"max_backups"`
	Enabled       bool    `json:"enabled"`
	LastRunAt     *string `json:"last_run_at,omitempty"`
	LastRunStatus string  `json:"last_run_status,omitempty"`
	NextRunAt     *string `json:"next_run_at,omitempty"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

// ============================================================================
// Verification handlers
// ============================================================================

// ListRuns handles GET /api/v1/backup-verify/runs?limit=&offset=.
func (h *BackupVerifyHandler) ListRuns(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	limit := h.QueryParamInt(r, "limit", 50)
	offset := h.QueryParamInt(r, "offset", 0)
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}

	verifs, total, err := h.svc.ListVerifications(r.Context(), hostID, limit, offset)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	entries := make([]VerificationResponse, len(verifs))
	for i, v := range verifs {
		entries[i] = toVerificationResponse(&v)
	}
	h.OK(w, VerificationPage{
		Entries: entries,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
	})
}

// GetRun handles GET /api/v1/backup-verify/runs/{id}.
func (h *BackupVerifyHandler) GetRun(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	v, err := h.svc.GetVerification(r.Context(), id)
	if err != nil {
		h.HandleError(w, mapBackupVerifyError(err))
		return
	}
	h.OK(w, toVerificationResponse(v))
}

// ListRunsByBackup handles GET /api/v1/backup-verify/backups/{backup_id}/runs.
func (h *BackupVerifyHandler) ListRunsByBackup(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	backupID, err := h.URLParamUUID(r, "backup_id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	rows, err := h.svc.ListByBackup(r.Context(), backupID)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	out := make([]VerificationResponse, len(rows))
	for i, v := range rows {
		out[i] = toVerificationResponse(&v)
	}
	h.OK(w, out)
}

// RunVerify handles POST /api/v1/backup-verify/run/{backup_id}.
func (h *BackupVerifyHandler) RunVerify(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	backupID, err := h.URLParamUUID(r, "backup_id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	method := models.VerificationMethodExtract
	if r.Body != nil && r.ContentLength > 0 {
		var req RunVerifyRequest
		if err := h.ParseJSON(r, &req); err != nil {
			h.HandleError(w, err)
			return
		}
		if req.Method != "" {
			method = models.VerificationMethod(req.Method)
		}
	}

	actor, _ := h.GetUserID(r)
	v, err := h.svc.RunVerification(r.Context(), backupID, method, nilableUUID(actor))
	if err != nil {
		h.HandleError(w, mapBackupVerifyError(err))
		return
	}
	h.Created(w, toVerificationResponse(v))
}

// GetStats handles GET /api/v1/backup-verify/stats.
func (h *BackupVerifyHandler) GetStats(w http.ResponseWriter, r *http.Request) {
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
	resp := VerificationStatsResponse{}
	if stats != nil {
		resp.TotalVerified = stats.TotalVerified
		resp.Passed = stats.Passed
		resp.Failed = stats.Failed
		resp.PassRate = stats.PassRate
		resp.LastVerified = stats.LastVerified
	}
	h.OK(w, resp)
}

// ============================================================================
// Schedule handlers
// ============================================================================

// ListSchedules handles GET /api/v1/backup-verify/schedules.
func (h *BackupVerifyHandler) ListSchedules(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	scheds, err := h.svc.ListSchedules(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	out := make([]VerifyScheduleResponse, len(scheds))
	for i, s := range scheds {
		out[i] = toVerifyScheduleResponse(&s)
	}
	h.OK(w, out)
}

// GetSchedule handles GET /api/v1/backup-verify/schedules/{id}.
func (h *BackupVerifyHandler) GetSchedule(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	s, err := h.svc.GetSchedule(r.Context(), id)
	if err != nil {
		h.HandleError(w, mapBackupVerifyError(err))
		return
	}
	h.OK(w, toVerifyScheduleResponse(s))
}

// CreateSchedule handles POST /api/v1/backup-verify/schedules.
func (h *BackupVerifyHandler) CreateSchedule(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	var req CreateVerifyScheduleRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	hostID, err := h.resolveHostIDFromBody(r, req.HostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	maxBackups := req.MaxBackups
	if maxBackups == 0 {
		maxBackups = 5
	}
	s, err := h.svc.CreateSchedule(r.Context(), hostID, req.Schedule, req.Method, maxBackups)
	if err != nil {
		h.HandleError(w, mapBackupVerifyError(err))
		return
	}
	h.Created(w, toVerifyScheduleResponse(s))
}

// UpdateSchedule handles PUT /api/v1/backup-verify/schedules/{id}.
func (h *BackupVerifyHandler) UpdateSchedule(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	var req UpdateVerifyScheduleRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	s, err := h.svc.UpdateSchedule(r.Context(), id, req.Schedule, req.Method, req.MaxBackups, req.Enabled)
	if err != nil {
		h.HandleError(w, mapBackupVerifyError(err))
		return
	}
	h.OK(w, toVerifyScheduleResponse(s))
}

// DeleteSchedule handles DELETE /api/v1/backup-verify/schedules/{id}.
func (h *BackupVerifyHandler) DeleteSchedule(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	if err := h.svc.DeleteSchedule(r.Context(), id); err != nil {
		h.HandleError(w, mapBackupVerifyError(err))
		return
	}
	h.NoContent(w)
}

// ============================================================================
// Helpers
// ============================================================================

func (h *BackupVerifyHandler) serviceUnavailable(w http.ResponseWriter) {
	apierrors.WriteError(w, apierrors.ServiceUnavailable("backup verification service is not configured"))
}

func (h *BackupVerifyHandler) resolveHostID(r *http.Request) (uuid.UUID, error) {
	if h.hostIDFn != nil {
		if id := h.hostIDFn(r); id != uuid.Nil {
			return id, nil
		}
	}
	if q := strings.TrimSpace(h.QueryParam(r, "host_id")); q != "" {
		id, err := uuid.Parse(q)
		if err != nil {
			return uuid.Nil, apierrors.InvalidInput("invalid host_id format")
		}
		return id, nil
	}
	if hdr := strings.TrimSpace(r.Header.Get("X-Host-ID")); hdr != "" {
		id, err := uuid.Parse(hdr)
		if err != nil {
			return uuid.Nil, apierrors.InvalidInput("invalid X-Host-ID format")
		}
		return id, nil
	}
	return uuid.Nil, apierrors.MissingField("host_id")
}

func (h *BackupVerifyHandler) resolveHostIDFromBody(r *http.Request, bodyHostID string) (uuid.UUID, error) {
	if bodyHostID != "" {
		id, err := uuid.Parse(bodyHostID)
		if err != nil {
			return uuid.Nil, apierrors.InvalidInput("invalid host_id format")
		}
		return id, nil
	}
	return h.resolveHostID(r)
}

// Compile-time check: chi URL param helpers are imported.
var _ = chi.URLParam

// mapBackupVerifyError translates service-package errors to API errors.
func mapBackupVerifyError(err error) error {
	switch {
	case stderrors.Is(err, backupverifysvc.ErrInvalidMethod):
		return apierrors.InvalidInput(err.Error())
	case stderrors.Is(err, backupverifysvc.ErrInvalidSchedule):
		return apierrors.InvalidInput(err.Error())
	case stderrors.Is(err, backupverifysvc.ErrInvalidInput):
		return apierrors.InvalidInput(err.Error())
	case stderrors.Is(err, backupverifysvc.ErrBackupGetterMissing):
		return apierrors.ServiceUnavailable(err.Error())
	}
	return err
}

func toVerificationResponse(v *models.BackupVerification) VerificationResponse {
	resp := VerificationResponse{
		ID:            v.ID.String(),
		BackupID:      v.BackupID.String(),
		HostID:        v.HostID.String(),
		Status:        string(v.Status),
		Method:        string(v.Method),
		ChecksumValid: v.ChecksumValid,
		FilesReadable: v.FilesReadable,
		ContainerTest: v.ContainerTest,
		DataValid:     v.DataValid,
		FileCount:     v.FileCount,
		SizeBytes:     v.SizeBytes,
		DurationMs:    v.DurationMs,
		ErrorMessage:  v.ErrorMessage,
		CreatedAt:     v.CreatedAt.Format(time.RFC3339),
	}
	if v.VerifiedBy != nil {
		s := v.VerifiedBy.String()
		resp.VerifiedBy = &s
	}
	if v.StartedAt != nil {
		s := v.StartedAt.Format(time.RFC3339)
		resp.StartedAt = &s
	}
	if v.CompletedAt != nil {
		s := v.CompletedAt.Format(time.RFC3339)
		resp.CompletedAt = &s
	}
	return resp
}

func toVerifyScheduleResponse(s *models.BackupVerificationSchedule) VerifyScheduleResponse {
	resp := VerifyScheduleResponse{
		ID:            s.ID.String(),
		HostID:        s.HostID.String(),
		Schedule:      s.Schedule,
		Method:        s.Method,
		MaxBackups:    s.MaxBackups,
		Enabled:       s.Enabled,
		LastRunStatus: s.LastRunStatus,
		CreatedAt:     s.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     s.UpdatedAt.Format(time.RFC3339),
	}
	if s.LastRunAt != nil {
		v := s.LastRunAt.Format(time.RFC3339)
		resp.LastRunAt = &v
	}
	if s.NextRunAt != nil {
		v := s.NextRunAt.Format(time.RFC3339)
		resp.NextRunAt = &v
	}
	return resp
}
