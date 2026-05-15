// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"context"
	stderrors "errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	sslobssvc "github.com/fr4nsys/usulnet/internal/services/sslobservatory"
)

// SSLObservatoryService is the narrow interface the API handler needs
// from *sslobservatory.Service. Declared here so unit tests can stub
// the service without standing up real persistence.
type SSLObservatoryService interface {
	ListTargets(ctx context.Context, hostID uuid.UUID) ([]models.SSLTarget, error)
	GetTarget(ctx context.Context, id uuid.UUID) (*models.SSLTarget, error)
	CreateTarget(ctx context.Context, hostID uuid.UUID, input models.CreateSSLTargetInput) (*models.SSLTarget, error)
	UpdateTarget(ctx context.Context, id uuid.UUID, input models.UpdateSSLTargetInput) (*models.SSLTarget, error)
	DeleteTarget(ctx context.Context, id uuid.UUID) error
	ScanTarget(ctx context.Context, id uuid.UUID) ([]models.SSLScanResult, error)
	ListScans(ctx context.Context, targetID uuid.UUID, limit, offset int) ([]models.SSLScanResult, int, error)
	GetLatestScan(ctx context.Context, targetID uuid.UUID) (*models.SSLScanResult, error)
	GetExpiringCerts(ctx context.Context, hostID uuid.UUID, days int) ([]models.SSLScanResult, error)
	GetDashboardStats(ctx context.Context, hostID uuid.UUID) (*models.SSLDashboardStats, error)
}

// SSLObservatoryHandler handles /api/v1/ssl/* requests. The svc field
// is nil-safe: when nil every handler returns 503 service_unavailable
// so routes mount cleanly during early app boot. v26.2.7 shipped no
// REST surface for SSL observatory — this is a new boundary.
type SSLObservatoryHandler struct {
	BaseHandler
	svc      SSLObservatoryService
	hostIDFn func(*http.Request) uuid.UUID
}

// NewSSLObservatoryHandler creates a new SSL observatory handler.
// hostIDFn resolves the active host UUID for a request. The
// standalone-mode app passes a closure that returns the default host
// UUID; multi-host installs can resolve from query/header.
func NewSSLObservatoryHandler(svc SSLObservatoryService, hostIDFn func(*http.Request) uuid.UUID, log *logger.Logger) *SSLObservatoryHandler {
	return &SSLObservatoryHandler{
		BaseHandler: NewBaseHandler(log),
		svc:         svc,
		hostIDFn:    hostIDFn,
	}
}

// Routes returns the chi router for /api/v1/ssl.
//
//	GET    /api/v1/ssl/targets               (viewer)
//	POST   /api/v1/ssl/targets               (operator)
//	GET    /api/v1/ssl/targets/{id}          (viewer)
//	PUT    /api/v1/ssl/targets/{id}          (operator)
//	DELETE /api/v1/ssl/targets/{id}          (operator)
//	GET    /api/v1/ssl/targets/{id}/scans    (viewer)
//	POST   /api/v1/ssl/targets/{id}/scan     (operator)
//	GET    /api/v1/ssl/stats                 (viewer)
//	GET    /api/v1/ssl/expiring              (viewer)
func (h *SSLObservatoryHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Route("/targets", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.ListTargets)
		r.With(middleware.RequireOperator).Post("/", h.CreateTarget)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.RequireViewer).Get("/", h.GetTarget)
			r.With(middleware.RequireOperator).Put("/", h.UpdateTarget)
			r.With(middleware.RequireOperator).Delete("/", h.DeleteTarget)

			r.With(middleware.RequireViewer).Get("/scans", h.ListScans)
			r.With(middleware.RequireOperator).Post("/scan", h.ScanTarget)
		})
	})

	r.With(middleware.RequireViewer).Get("/stats", h.Stats)
	r.With(middleware.RequireViewer).Get("/expiring", h.Expiring)

	return r
}

// ============================================================================
// DTOs
// ============================================================================

// CreateSSLTargetRequest is the body for POST /api/v1/ssl/targets.
type CreateSSLTargetRequest struct {
	HostID          string   `json:"host_id,omitempty" validate:"omitempty,uuid"`
	Name            string   `json:"name" validate:"required,min=1,max=255"`
	Hostname        string   `json:"hostname" validate:"required,min=1,max=512"`
	Port            int      `json:"port,omitempty" validate:"omitempty,min=1,max=65535"`
	ExtraHostnames  []string `json:"extra_hostnames,omitempty" validate:"omitempty,dive,max=512"`
	AlertThresholds []int    `json:"alert_thresholds,omitempty" validate:"omitempty,dive,gt=0,lt=3650"`
}

// UpdateSSLTargetRequest is the body for PUT /api/v1/ssl/targets/{id}.
// All fields are optional.
type UpdateSSLTargetRequest struct {
	Name            *string  `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	Hostname        *string  `json:"hostname,omitempty" validate:"omitempty,min=1,max=512"`
	Port            *int     `json:"port,omitempty" validate:"omitempty,min=1,max=65535"`
	ExtraHostnames  []string `json:"extra_hostnames,omitempty" validate:"omitempty,dive,max=512"`
	AlertThresholds []int    `json:"alert_thresholds,omitempty" validate:"omitempty,dive,gt=0,lt=3650"`
	Enabled         *bool    `json:"enabled,omitempty"`
}

// SSLTargetResponse is the API view of an SSL target.
type SSLTargetResponse struct {
	ID              string   `json:"id"`
	HostID          string   `json:"host_id"`
	Name            string   `json:"name"`
	Hostname        string   `json:"hostname"`
	Port            int      `json:"port"`
	ExtraHostnames  []string `json:"extra_hostnames"`
	AlertThresholds []int    `json:"alert_thresholds"`
	AutoDiscovered  bool     `json:"auto_discovered"`
	Enabled         bool     `json:"enabled"`
	CreatedAt       string   `json:"created_at"`
	UpdatedAt       string   `json:"updated_at"`
}

// SSLScanResultResponse is the API view of one scan result row.
type SSLScanResultResponse struct {
	ID                string     `json:"id"`
	TargetID          string     `json:"target_id"`
	ScanHostname      string     `json:"scan_hostname"`
	Grade             string     `json:"grade"`
	Score             int        `json:"score"`
	ProtocolVersions  []string   `json:"protocol_versions"`
	CipherSuites      string     `json:"cipher_suites,omitempty"`
	CertificateCN     string     `json:"certificate_cn"`
	CertificateIssuer string     `json:"certificate_issuer"`
	CertificateSANs   []string   `json:"certificate_sans"`
	CertNotBefore     *time.Time `json:"cert_not_before,omitempty"`
	CertNotAfter      *time.Time `json:"cert_not_after,omitempty"`
	CertKeyType       string     `json:"cert_key_type"`
	CertKeyBits       int        `json:"cert_key_bits"`
	CertChainValid    bool       `json:"cert_chain_valid"`
	CertChainLength   int        `json:"cert_chain_length"`
	HasHSTS           bool       `json:"has_hsts"`
	HasOCSPStapling   bool       `json:"has_ocsp_stapling"`
	HasSCT            bool       `json:"has_sct"`
	ErrorMessage      string     `json:"error_message,omitempty"`
	ScanDurationMs    int        `json:"scan_duration_ms"`
	ScannedAt         string     `json:"scanned_at"`
}

// SSLScanListResponse is the paginated /scans body.
type SSLScanListResponse struct {
	Results []SSLScanResultResponse `json:"results"`
	Total   int                     `json:"total"`
	Limit   int                     `json:"limit"`
	Offset  int                     `json:"offset"`
}

// SSLDashboardStatsResponse is the API view of dashboard stats.
type SSLDashboardStatsResponse struct {
	TotalTargets      int            `json:"total_targets"`
	GradeDistribution map[string]int `json:"grade_distribution"`
	ExpiringSoon      int            `json:"expiring_soon"`
	LastScanTime      *string        `json:"last_scan_time,omitempty"`
}

// ============================================================================
// Handlers
// ============================================================================

// ListTargets handles GET /api/v1/ssl/targets.
func (h *SSLObservatoryHandler) ListTargets(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	targets, err := h.svc.ListTargets(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	resp := make([]SSLTargetResponse, len(targets))
	for i := range targets {
		resp[i] = toSSLTargetResponse(&targets[i])
	}
	h.OK(w, resp)
}

// GetTarget handles GET /api/v1/ssl/targets/{id}.
func (h *SSLObservatoryHandler) GetTarget(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	t, err := h.svc.GetTarget(r.Context(), id)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	h.OK(w, toSSLTargetResponse(t))
}

// CreateTarget handles POST /api/v1/ssl/targets.
func (h *SSLObservatoryHandler) CreateTarget(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	var req CreateSSLTargetRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	hostID, err := h.resolveHostIDFromBody(r, req.HostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	port := req.Port
	if port == 0 {
		port = 443
	}
	t, err := h.svc.CreateTarget(r.Context(), hostID, models.CreateSSLTargetInput{
		Name:            req.Name,
		Hostname:        req.Hostname,
		Port:            port,
		ExtraHostnames:  req.ExtraHostnames,
		AlertThresholds: req.AlertThresholds,
	})
	if err != nil {
		h.HandleError(w, mapSSLError(err))
		return
	}
	h.Created(w, toSSLTargetResponse(t))
}

// UpdateTarget handles PUT /api/v1/ssl/targets/{id}.
func (h *SSLObservatoryHandler) UpdateTarget(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	var req UpdateSSLTargetRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	in := models.UpdateSSLTargetInput{
		Name:            req.Name,
		Hostname:        req.Hostname,
		Port:            req.Port,
		ExtraHostnames:  req.ExtraHostnames,
		AlertThresholds: req.AlertThresholds,
		Enabled:         req.Enabled,
	}
	t, err := h.svc.UpdateTarget(r.Context(), id, in)
	if err != nil {
		h.HandleError(w, mapSSLError(err))
		return
	}
	h.OK(w, toSSLTargetResponse(t))
}

// DeleteTarget handles DELETE /api/v1/ssl/targets/{id}.
func (h *SSLObservatoryHandler) DeleteTarget(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	if err := h.svc.DeleteTarget(r.Context(), id); err != nil {
		h.HandleError(w, mapSSLError(err))
		return
	}
	h.NoContent(w)
}

// ScanTarget handles POST /api/v1/ssl/targets/{id}/scan.
func (h *SSLObservatoryHandler) ScanTarget(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	results, err := h.svc.ScanTarget(r.Context(), id)
	if err != nil {
		h.HandleError(w, mapSSLError(err))
		return
	}
	resp := make([]SSLScanResultResponse, len(results))
	for i := range results {
		resp[i] = toSSLScanResultResponse(&results[i])
	}
	h.OK(w, resp)
}

// ListScans handles GET /api/v1/ssl/targets/{id}/scans.
func (h *SSLObservatoryHandler) ListScans(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	page := h.GetPagination(r)
	results, total, err := h.svc.ListScans(r.Context(), id, page.PerPage, page.Offset)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	resp := make([]SSLScanResultResponse, len(results))
	for i := range results {
		resp[i] = toSSLScanResultResponse(&results[i])
	}
	h.OK(w, SSLScanListResponse{
		Results: resp,
		Total:   total,
		Limit:   page.PerPage,
		Offset:  page.Offset,
	})
}

// Stats handles GET /api/v1/ssl/stats.
func (h *SSLObservatoryHandler) Stats(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	stats, err := h.svc.GetDashboardStats(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	resp := SSLDashboardStatsResponse{
		TotalTargets:      stats.TotalTargets,
		GradeDistribution: stats.GradeDistribution,
		ExpiringSoon:      stats.ExpiringSoon,
	}
	if stats.LastScanTime != nil {
		s := stats.LastScanTime.Format(time.RFC3339)
		resp.LastScanTime = &s
	}
	h.OK(w, resp)
}

// Expiring handles GET /api/v1/ssl/expiring?days=30.
func (h *SSLObservatoryHandler) Expiring(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	days := 30
	if q := r.URL.Query().Get("days"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 365 {
			days = v
		}
	}
	results, err := h.svc.GetExpiringCerts(r.Context(), hostID, days)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	resp := make([]SSLScanResultResponse, len(results))
	for i := range results {
		resp[i] = toSSLScanResultResponse(&results[i])
	}
	h.OK(w, resp)
}

// ============================================================================
// Helpers
// ============================================================================

func (h *SSLObservatoryHandler) resolveHostID(r *http.Request) (uuid.UUID, error) {
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

func (h *SSLObservatoryHandler) resolveHostIDFromBody(r *http.Request, bodyHostID string) (uuid.UUID, error) {
	if bodyHostID != "" {
		id, err := uuid.Parse(bodyHostID)
		if err != nil {
			return uuid.Nil, apierrors.InvalidInput("invalid host_id format")
		}
		return id, nil
	}
	return h.resolveHostID(r)
}

func (h *SSLObservatoryHandler) serviceUnavailable(w http.ResponseWriter) {
	apierrors.WriteError(w, apierrors.ServiceUnavailable("ssl observatory service is not configured"))
}

// mapSSLError translates package-level service errors to typed API
// errors. The catch-all goes through BaseHandler.HandleError which
// already understands errors.NotFound.
func mapSSLError(err error) error {
	if stderrors.Is(err, sslobssvc.ErrInvalidInput) {
		return apierrors.InvalidInput(err.Error())
	}
	return err
}

func toSSLTargetResponse(t *models.SSLTarget) SSLTargetResponse {
	resp := SSLTargetResponse{
		ID:              t.ID.String(),
		HostID:          t.HostID.String(),
		Name:            t.Name,
		Hostname:        t.Hostname,
		Port:            t.Port,
		ExtraHostnames:  []string{},
		AlertThresholds: t.EffectiveThresholds(),
		AutoDiscovered:  t.AutoDiscovered,
		Enabled:         t.Enabled,
		CreatedAt:       t.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       t.UpdatedAt.Format(time.RFC3339),
	}
	for _, h := range t.ExtraHostnames {
		resp.ExtraHostnames = append(resp.ExtraHostnames, h)
	}
	return resp
}

func toSSLScanResultResponse(s *models.SSLScanResult) SSLScanResultResponse {
	resp := SSLScanResultResponse{
		ID:                s.ID.String(),
		TargetID:          s.TargetID.String(),
		ScanHostname:      s.ScanHostname,
		Grade:             s.Grade,
		Score:             s.Score,
		ProtocolVersions:  []string{},
		CertificateCN:     s.CertificateCN,
		CertificateIssuer: s.CertificateIssuer,
		CertificateSANs:   []string{},
		CertNotBefore:     s.CertNotBefore,
		CertNotAfter:      s.CertNotAfter,
		CertKeyType:       s.CertKeyType,
		CertKeyBits:       s.CertKeyBits,
		CertChainValid:    s.CertChainValid,
		CertChainLength:   s.CertChainLength,
		HasHSTS:           s.HasHSTS,
		HasOCSPStapling:   s.HasOCSPStapling,
		HasSCT:            s.HasSCT,
		ErrorMessage:      s.ErrorMessage,
		ScanDurationMs:    s.ScanDurationMs,
		ScannedAt:         s.ScannedAt.Format(time.RFC3339),
	}
	for _, p := range s.ProtocolVersions {
		resp.ProtocolVersions = append(resp.ProtocolVersions, p)
	}
	for _, h := range s.CertificateSANs {
		resp.CertificateSANs = append(resp.CertificateSANs, h)
	}
	if len(s.CipherSuites) > 0 {
		resp.CipherSuites = string(s.CipherSuites)
	}
	return resp
}

// Verify chi var compiles (avoid the unused import warning when
// reformatting). chi is used in Routes() above; nothing else here
// needs it.
var _ = chi.NewRouter
