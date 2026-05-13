// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/recon"
	"github.com/fr4nsys/usulnet/internal/services/recon/report"
)

// ReconConnectorService is the narrow interface the connectors
// endpoint requires. Implementations live alongside the recon Service
// once the S02 follow-up lands; until then the handler tolerates a
// nil connector service (GET returns empty, PUT/DELETE return 501).
type ReconConnectorService interface {
	ListConnectors(ctx context.Context) ([]ReconConnectorInfo, error)
	SetConnector(ctx context.Context, kind string, creds map[string]string, enabled bool) error
	DeleteConnector(ctx context.Context, kind string) error
}

// ReconConnectorInfo is the API view of one connector configuration
// row. Credentials are NEVER returned — only kind / enabled / health.
type ReconConnectorInfo struct {
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`
	Healthy bool   `json:"healthy"`
}

// ReconAckRecorder persists the "module.enabled" acknowledgement and
// reports the current state. Implementations should cache so the
// middleware does not roundtrip on every request.
type ReconAckRecorder interface {
	middleware.ReconAckChecker
	Acknowledge(ctx context.Context, actorID *uuid.UUID, ip string) error
}

// ReconHandler handles /api/v1/recon/* requests.
type ReconHandler struct {
	BaseHandler
	svc        recon.Service
	connectors ReconConnectorService
	ack        ReconAckRecorder
}

// NewReconHandler creates a new recon handler. The svc parameter may
// be nil during early app boot — every handler method returns 503
// engine_unavailable in that case so the routes still register. The
// service can be wired afterwards with SetService.
func NewReconHandler(svc recon.Service, connectors ReconConnectorService, ack ReconAckRecorder, log *logger.Logger) *ReconHandler {
	return &ReconHandler{
		BaseHandler: NewBaseHandler(log),
		svc:         svc,
		connectors:  connectors,
		ack:         ack,
	}
}

// SetService installs the recon Service after construction. The router
// captures methods by closure so wiring the service later still lets
// every route resolve. Callers wire the service exactly once, before
// the first request hits the API.
func (h *ReconHandler) SetService(svc recon.Service) {
	h.svc = svc
}

// Routes returns the chi router for /api/v1/recon. The caller is
// responsible for placing this subtree behind the feature-flag and
// acknowledgement middleware (see internal/api/router.go).
//
// The acknowledgement endpoint must be mounted on a sibling subtree
// that skips the acknowledgement middleware — exposing it via
// (h *ReconHandler).AckRoutes().
func (h *ReconHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Targets ------------------------------------------------------------
	r.Route("/targets", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.ListTargets)
		r.With(middleware.RequireOperator).Post("/", h.CreateTarget)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.RequireViewer).Get("/", h.GetTarget)
			r.With(middleware.RequireOperator).Delete("/", h.DeleteTarget)
			r.With(middleware.RequireOperator).Post("/ownership/verify", h.VerifyOwnership)
		})
	})

	// Profiles -----------------------------------------------------------
	r.Route("/profiles", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.ListProfiles)
		r.With(middleware.RequireOperator).Post("/", h.CreateProfile)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.RequireOperator).Put("/", h.UpdateProfile)
			r.With(middleware.RequireAdmin).Delete("/", h.DeleteProfile)
		})
	})

	// Scans --------------------------------------------------------------
	r.Route("/scans", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.ListScans)
		r.With(middleware.RequireOperator).Post("/", h.StartScan)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.RequireViewer).Get("/", h.GetScan)
			r.With(middleware.RequireOperator).Delete("/", h.CancelScan)
			r.With(middleware.RequireViewer).Get("/findings", h.ListFindings)
			r.With(middleware.RequireViewer).Get("/report.json", h.ReportJSON)
			r.With(middleware.RequireViewer).Get("/report.csv", h.ReportCSV)
			r.With(middleware.RequireViewer).Get("/report.pdf", h.ReportPDF)
		})
	})

	// Connectors ---------------------------------------------------------
	r.Route("/connectors", func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		r.Get("/", h.ListConnectors)
		r.Put("/{kind}", h.UpdateConnector)
		r.Delete("/{kind}", h.DeleteConnector)
	})

	return r
}

// AckRoutes returns the subtree containing the acknowledgement
// endpoint. The router mounts this branch outside the acknowledgement
// middleware so an admin can record consent.
func (h *ReconHandler) AckRoutes() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequireAdmin)
	r.Post("/_ack", h.Acknowledge)
	return r
}

// ============================================================================
// DTOs
// ============================================================================

// CreateTargetRequest is the body for POST /api/v1/recon/targets.
type CreateTargetRequest struct {
	Type  string `json:"type" validate:"required,oneof=email phone username domain ip ip_range"`
	Value string `json:"value" validate:"required,min=1,max=255"`
	Label string `json:"label" validate:"omitempty,max=128"`
}

// VerifyOwnershipRequest is the body for POST
// /api/v1/recon/targets/{id}/ownership/verify.
type VerifyOwnershipRequest struct {
	Method string         `json:"method" validate:"required,oneof=dns_txt email_link rdap_match admin_attest self_assert"`
	Input  map[string]any `json:"input,omitempty"`
}

// StartScanRequest is the body for POST /api/v1/recon/scans.
type StartScanRequest struct {
	TargetID  string `json:"target_id" validate:"required,uuid"`
	ProfileID string `json:"profile_id" validate:"required,uuid"`
}

// ReconCreateProfileRequest is the body for POST /api/v1/recon/profiles.
// Kind is fixed to "custom" by the service; it is not accepted as
// input. The validator only checks shape — the service rejects target
// types outside the closed enum and modules outside the known catalog
// with ErrProfileInvalid.
type ReconCreateProfileRequest struct {
	Name        string         `json:"name" validate:"required,min=1,max=128"`
	Description string         `json:"description,omitempty" validate:"omitempty,max=512"`
	TargetTypes []string       `json:"target_types" validate:"required,min=1,dive,oneof=email phone username domain ip ip_range"`
	Modules     []string       `json:"modules" validate:"required,min=1,dive,min=1"`
	Options     map[string]any `json:"options,omitempty"`
}

// ReconUpdateProfileRequest is the body for PUT /api/v1/recon/profiles/{id}.
// Same shape as ReconCreateProfileRequest minus the CreatedBy lineage.
type ReconUpdateProfileRequest struct {
	Name        string         `json:"name" validate:"required,min=1,max=128"`
	Description string         `json:"description,omitempty" validate:"omitempty,max=512"`
	TargetTypes []string       `json:"target_types" validate:"required,min=1,dive,oneof=email phone username domain ip ip_range"`
	Modules     []string       `json:"modules" validate:"required,min=1,dive,min=1"`
	Options     map[string]any `json:"options,omitempty"`
}

// UpdateConnectorRequest is the body for PUT
// /api/v1/recon/connectors/{kind}.
type UpdateConnectorRequest struct {
	Enabled bool              `json:"enabled"`
	Creds   map[string]string `json:"credentials,omitempty"`
}

// TargetResponse is the API view of a Target.
type TargetResponse struct {
	ID        string  `json:"id"`
	Type      string  `json:"type"`
	Value     string  `json:"value"`
	Label     string  `json:"label,omitempty"`
	CreatedBy *string `json:"created_by,omitempty"`
	CreatedAt string  `json:"created_at"`
	UpdatedAt string  `json:"updated_at"`
}

// OwnershipProofResponse is the API view of an OwnershipProof. The
// challenge is returned verbatim so the caller can complete a
// DNS-TXT verification; the evidence map is filtered to non-secret
// fields.
type OwnershipProofResponse struct {
	ID         string         `json:"id"`
	TargetID   string         `json:"target_id"`
	Method     string         `json:"method"`
	Status     string         `json:"status"`
	Challenge  string         `json:"challenge,omitempty"`
	Evidence   map[string]any `json:"evidence,omitempty"`
	VerifiedAt *string        `json:"verified_at,omitempty"`
	CreatedAt  string         `json:"created_at"`
}

// ProfileResponse is the API view of a Profile.
type ProfileResponse struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Kind        string         `json:"kind"`
	TargetTypes []string       `json:"target_types"`
	Modules     []string       `json:"modules,omitempty"`
	Options     map[string]any `json:"options,omitempty"`
	CreatedAt   string         `json:"created_at"`
}

// ScanResponse is the API view of a Scan.
type ScanResponse struct {
	ID          string  `json:"id"`
	TargetID    string  `json:"target_id"`
	ProfileID   string  `json:"profile_id"`
	Status      string  `json:"status"`
	Engine      string  `json:"engine,omitempty"`
	EngineRunID string  `json:"engine_run_id,omitempty"`
	Error       string  `json:"error,omitempty"`
	StartedAt   *string `json:"started_at,omitempty"`
	FinishedAt  *string `json:"finished_at,omitempty"`
	CreatedBy   *string `json:"created_by,omitempty"`
	CreatedAt   string  `json:"created_at"`
}

// FindingResponse is the API view of a Finding.
type FindingResponse struct {
	ID         string `json:"id"`
	ScanID     string `json:"scan_id"`
	TargetID   string `json:"target_id"`
	Module     string `json:"module"`
	Category   string `json:"category"`
	Severity   string `json:"severity"`
	Value      string `json:"value"`
	Source     string `json:"source,omitempty"`
	Confidence int    `json:"confidence"`
	FirstSeen  string `json:"first_seen"`
	LastSeen   string `json:"last_seen"`
}

// ============================================================================
// Targets
// ============================================================================

// CreateTarget handles POST /api/v1/recon/targets.
func (h *ReconHandler) CreateTarget(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}

	var req CreateTargetRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	actor, _ := h.GetUserID(r)
	in := recon.CreateTargetInput{
		Type:      recon.TargetType(req.Type),
		Value:     strings.TrimSpace(req.Value),
		Label:     req.Label,
		CreatedBy: nilableUUID(actor),
	}

	t, err := h.svc.CreateTarget(r.Context(), in)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, toTargetResponse(t))
}

// ListTargets handles GET /api/v1/recon/targets.
func (h *ReconHandler) ListTargets(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}

	pagination := h.GetPagination(r)
	filter := recon.ListTargetsFilter{
		Limit:  pagination.PerPage,
		Offset: pagination.Offset,
	}
	if t := h.QueryParam(r, "type"); t != "" {
		tt := recon.TargetType(t)
		filter.Type = &tt
	}
	if c := h.QueryParamUUID(r, "created_by"); c != nil {
		filter.CreatedBy = c
	}

	targets, err := h.svc.ListTargets(r.Context(), filter)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]TargetResponse, len(targets))
	for i := range targets {
		resp[i] = toTargetResponse(&targets[i])
	}
	h.OK(w, resp)
}

// GetTarget handles GET /api/v1/recon/targets/{id}.
func (h *ReconHandler) GetTarget(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
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

	h.OK(w, toTargetResponse(t))
}

// DeleteTarget handles DELETE /api/v1/recon/targets/{id}.
func (h *ReconHandler) DeleteTarget(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}

	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.svc.DeleteTarget(r.Context(), id); err != nil {
		h.HandleError(w, err)
		return
	}
	h.NoContent(w)
}

// VerifyOwnership handles POST
// /api/v1/recon/targets/{id}/ownership/verify. It starts a proof for
// the requested method, immediately runs verification, and returns the
// resulting proof so the caller can inspect status and challenge data.
func (h *ReconHandler) VerifyOwnership(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}

	targetID, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req VerifyOwnershipRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	proof, err := h.svc.StartOwnershipProof(r.Context(), targetID, recon.OwnershipMethod(req.Method))
	if err != nil {
		h.HandleError(w, mapOwnershipError(err))
		return
	}

	verified, err := h.svc.VerifyOwnershipProof(r.Context(), proof.ID)
	if err != nil {
		// Surface the started proof so the caller can finish the
		// DNS / email flow asynchronously, then translate the error.
		if verified == nil {
			verified = proof
		}
		resp := toOwnershipProofResponse(verified)
		details := map[string]any{"proof": resp, "error": err.Error()}
		h.Error(w, apierrors.NewErrorWithDetails(http.StatusConflict,
			apierrors.ErrCodeOwnershipPending,
			"Ownership verification did not complete", details))
		return
	}

	h.OK(w, toOwnershipProofResponse(verified))
}

// ============================================================================
// Profiles
// ============================================================================

// CreateProfile handles POST /api/v1/recon/profiles.
func (h *ReconHandler) CreateProfile(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}
	var req ReconCreateProfileRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	actor, _ := h.GetUserID(r)
	in := recon.CreateProfileInput{
		Name:        strings.TrimSpace(req.Name),
		Description: req.Description,
		TargetTypes: toReconTargetTypes(req.TargetTypes),
		Modules:     req.Modules,
		Options:     req.Options,
		CreatedBy:   nilableUUID(actor),
	}
	p, err := h.svc.CreateProfile(r.Context(), in)
	if err != nil {
		h.HandleError(w, mapProfileError(err))
		return
	}
	h.Created(w, toProfileResponse(p))
}

// UpdateProfile handles PUT /api/v1/recon/profiles/{id}.
func (h *ReconHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	var req ReconUpdateProfileRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	in := recon.UpdateProfileInput{
		Name:        strings.TrimSpace(req.Name),
		Description: req.Description,
		TargetTypes: toReconTargetTypes(req.TargetTypes),
		Modules:     req.Modules,
		Options:     req.Options,
	}
	p, err := h.svc.UpdateProfile(r.Context(), id, in)
	if err != nil {
		h.HandleError(w, mapProfileError(err))
		return
	}
	h.OK(w, toProfileResponse(p))
}

// DeleteProfile handles DELETE /api/v1/recon/profiles/{id}.
func (h *ReconHandler) DeleteProfile(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	if err := h.svc.DeleteProfile(r.Context(), id); err != nil {
		h.HandleError(w, mapProfileError(err))
		return
	}
	h.NoContent(w)
}

// ListProfiles handles GET /api/v1/recon/profiles.
func (h *ReconHandler) ListProfiles(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}

	profiles, err := h.svc.ListProfiles(r.Context())
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]ProfileResponse, len(profiles))
	for i := range profiles {
		resp[i] = toProfileResponse(&profiles[i])
	}
	h.OK(w, resp)
}

// ============================================================================
// Scans
// ============================================================================

// StartScan handles POST /api/v1/recon/scans.
func (h *ReconHandler) StartScan(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}

	var req StartScanRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	targetID, err := uuid.Parse(req.TargetID)
	if err != nil {
		h.BadRequest(w, "invalid target_id")
		return
	}
	profileID, err := uuid.Parse(req.ProfileID)
	if err != nil {
		h.BadRequest(w, "invalid profile_id")
		return
	}

	actor, _ := h.GetUserID(r)
	in := recon.StartScanInput{
		TargetID:  targetID,
		ProfileID: profileID,
		CreatedBy: nilableUUID(actor),
	}

	scan, err := h.svc.StartScan(r.Context(), in)
	if err != nil {
		h.HandleError(w, mapScanError(err, req.TargetID))
		return
	}

	h.Created(w, toScanResponse(scan))
}

// ListScans handles GET /api/v1/recon/scans.
func (h *ReconHandler) ListScans(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}

	pagination := h.GetPagination(r)
	filter := recon.ListScansFilter{
		Limit:  pagination.PerPage,
		Offset: pagination.Offset,
	}
	if t := h.QueryParamUUID(r, "target_id"); t != nil {
		filter.TargetID = t
	}
	if s := h.QueryParam(r, "status"); s != "" {
		st := recon.ScanStatus(s)
		filter.Status = &st
	}

	scans, err := h.svc.ListScans(r.Context(), filter)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]ScanResponse, len(scans))
	for i := range scans {
		resp[i] = toScanResponse(&scans[i])
	}
	h.OK(w, resp)
}

// GetScan handles GET /api/v1/recon/scans/{id}.
func (h *ReconHandler) GetScan(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}

	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	scan, err := h.svc.GetScan(r.Context(), id)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	h.OK(w, toScanResponse(scan))
}

// CancelScan handles DELETE /api/v1/recon/scans/{id}.
func (h *ReconHandler) CancelScan(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}

	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	if err := h.svc.CancelScan(r.Context(), id); err != nil {
		h.HandleError(w, err)
		return
	}
	h.NoContent(w)
}

// ListFindings handles GET /api/v1/recon/scans/{id}/findings.
func (h *ReconHandler) ListFindings(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}

	scanID, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	pagination := h.GetPagination(r)
	filter := recon.ListFindingsFilter{
		ScanID: &scanID,
		Limit:  pagination.PerPage,
		Offset: pagination.Offset,
	}
	if sev := h.QueryParam(r, "severity"); sev != "" {
		s := recon.Severity(sev)
		filter.Severity = &s
	}
	if m := h.QueryParam(r, "module"); m != "" {
		filter.Module = m
	}
	if c := h.QueryParam(r, "category"); c != "" {
		filter.Category = c
	}

	findings, err := h.svc.ListFindings(r.Context(), filter)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]FindingResponse, len(findings))
	for i := range findings {
		resp[i] = toFindingResponse(&findings[i])
	}
	h.OK(w, resp)
}

// buildReport collects the inputs report.Build needs and returns the
// assembled *report.Report. The handler factors this out so all three
// report endpoints share the same load+assemble path.
func (h *ReconHandler) buildReport(ctx context.Context, scanID uuid.UUID) (*report.Report, error) {
	scan, err := h.svc.GetScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	target, err := h.svc.GetTarget(ctx, scan.TargetID)
	if err != nil {
		return nil, err
	}
	profile, err := h.svc.GetProfile(ctx, scan.ProfileID)
	if err != nil {
		return nil, err
	}
	summary, err := h.svc.GetScanSummary(ctx, scanID)
	if err != nil {
		return nil, err
	}
	findings, err := h.svc.ListFindings(ctx, recon.ListFindingsFilter{
		ScanID: &scanID,
		Limit:  10_000,
	})
	if err != nil {
		return nil, err
	}
	return report.Build(scan, target, profile, summary, findings, time.Now()), nil
}

// ReportJSON handles GET /api/v1/recon/scans/{id}/report.json. The
// payload is the structured Report assembled by report.Build:
// target + profile + summary + findings grouped by category.
func (h *ReconHandler) ReportJSON(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}
	scanID, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	rep, err := h.buildReport(r.Context(), scanID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var buf bytes.Buffer
	if err := report.GenerateJSON(rep, &buf); err != nil {
		h.InternalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// ReportCSV handles GET /api/v1/recon/scans/{id}/report.csv. The
// download is a flat findings table — see report.CSVHeader for the
// column order.
func (h *ReconHandler) ReportCSV(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}
	scanID, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	rep, err := h.buildReport(r.Context(), scanID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var buf bytes.Buffer
	if err := report.GenerateCSV(rep, &buf); err != nil {
		h.InternalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"scan-"+scanID.String()+".csv\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// ReportPDF handles GET /api/v1/recon/scans/{id}/report.pdf. The
// body is a paginated A4 document with a header, profile/summary
// block, and one section per category.
func (h *ReconHandler) ReportPDF(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}
	scanID, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	rep, err := h.buildReport(r.Context(), scanID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var buf bytes.Buffer
	if err := report.GeneratePDF(rep, &buf); err != nil {
		h.InternalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "attachment; filename=\"scan-"+scanID.String()+".pdf\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// ============================================================================
// Connectors
// ============================================================================

// ListConnectors handles GET /api/v1/recon/connectors.
func (h *ReconHandler) ListConnectors(w http.ResponseWriter, r *http.Request) {
	if h.connectors == nil {
		h.OK(w, []ReconConnectorInfo{})
		return
	}
	infos, err := h.connectors.ListConnectors(r.Context())
	if err != nil {
		h.HandleError(w, err)
		return
	}
	h.OK(w, infos)
}

// UpdateConnector handles PUT /api/v1/recon/connectors/{kind}.
func (h *ReconHandler) UpdateConnector(w http.ResponseWriter, r *http.Request) {
	kind := strings.ToLower(strings.TrimSpace(h.URLParam(r, "kind")))
	if kind == "" {
		h.BadRequest(w, "connector kind is required")
		return
	}

	var req UpdateConnectorRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if h.connectors == nil {
		apierrors.WriteError(w, apierrors.NotImplemented("connector backend is not wired in this build"))
		return
	}

	if err := h.connectors.SetConnector(r.Context(), kind, req.Creds, req.Enabled); err != nil {
		h.HandleError(w, err)
		return
	}
	h.NoContent(w)
}

// DeleteConnector handles DELETE /api/v1/recon/connectors/{kind}. It
// wipes the persisted credentials + enabled flag from
// recon_connectors. The in-memory connector keeps its current state
// until the next process start — same hot-reload posture as
// UpdateConnector.
func (h *ReconHandler) DeleteConnector(w http.ResponseWriter, r *http.Request) {
	kind := strings.ToLower(strings.TrimSpace(h.URLParam(r, "kind")))
	if kind == "" {
		h.BadRequest(w, "connector kind is required")
		return
	}
	if h.connectors == nil {
		apierrors.WriteError(w, apierrors.NotImplemented("connector backend is not wired in this build"))
		return
	}
	if err := h.connectors.DeleteConnector(r.Context(), kind); err != nil {
		h.HandleError(w, err)
		return
	}
	h.NoContent(w)
}

// ============================================================================
// Acknowledgement
// ============================================================================

// Acknowledge handles POST /api/v1/recon/_ack. The caller must be an
// admin (enforced by the AckRoutes middleware stack). The endpoint is
// idempotent: calling it twice yields the same 204 response.
func (h *ReconHandler) Acknowledge(w http.ResponseWriter, r *http.Request) {
	if h.ack == nil {
		h.InternalError(w, errors.New("recon acknowledgement store not configured"))
		return
	}
	actor, _ := h.GetUserID(r)
	if err := h.ack.Acknowledge(r.Context(), nilableUUID(actor), middleware.ClientIP(r)); err != nil {
		h.HandleError(w, err)
		return
	}
	h.NoContent(w)
}

// ============================================================================
// Helpers
// ============================================================================

// engineUnavailable returns the 503 used when the recon Service is not
// wired yet (early boot, missing dependencies). The error code is the
// one called out by docs/v26.5/technical-notes.md.
func (h *ReconHandler) engineUnavailable(w http.ResponseWriter) {
	apierrors.WriteError(w, apierrors.NewError(
		http.StatusServiceUnavailable,
		apierrors.ErrCodeEngineUnavailable,
		"Recon engine is not available",
	))
}

// nilableUUID returns nil for the zero UUID and a pointer otherwise.
func nilableUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

// mapOwnershipError converts package-level recon errors into typed
// APIErrors. Anything not recognised is passed through unchanged so
// BaseHandler.HandleError takes over.
func mapOwnershipError(err error) error {
	switch {
	case errors.Is(err, recon.ErrOwnershipUnsupported):
		return apierrors.UnsupportedTargetType("")
	case errors.Is(err, recon.ErrOwnershipForbidden):
		return apierrors.Forbidden("ownership method requires elevated privileges")
	case errors.Is(err, recon.ErrOwnershipInputMissing):
		return apierrors.InvalidInput("ownership verification input is required")
	}
	return err
}

// mapProfileError translates the user-defined profile CRUD sentinels
// into APIErrors with stable status codes. ErrProfileNotFound → 404;
// ErrProfileExists → 409 with code ALREADY_EXISTS; ErrProfileBuiltin
// → 403 (the row exists but the caller is not authorised to mutate
// it); ErrProfileInUse → 409 Conflict; ErrProfileInvalid → 400.
// Anything else flows through to BaseHandler.HandleError.
func mapProfileError(err error) error {
	switch {
	case errors.Is(err, recon.ErrProfileNotFound):
		return apierrors.NotFound("profile")
	case errors.Is(err, recon.ErrProfileExists):
		return apierrors.AlreadyExists("profile")
	case errors.Is(err, recon.ErrProfileBuiltin):
		return apierrors.Forbidden("built-in profiles cannot be modified")
	case errors.Is(err, recon.ErrProfileInUse):
		return apierrors.Conflict("profile is referenced by existing scans")
	case errors.Is(err, recon.ErrProfileInvalid):
		return apierrors.InvalidInput(err.Error())
	}
	return err
}

// toReconTargetTypes converts an API []string into recon.TargetType
// slice without applying any validation — the service rejects values
// outside the closed enum.
func toReconTargetTypes(in []string) []recon.TargetType {
	out := make([]recon.TargetType, len(in))
	for i, t := range in {
		out[i] = recon.TargetType(t)
	}
	return out
}

// mapScanError translates the well-known recon error codes the scan
// path can surface (ownership_required and friends).
func mapScanError(err error, targetID string) error {
	switch {
	case errors.Is(err, recon.ErrOwnershipMismatch),
		errors.Is(err, recon.ErrOwnershipExpired):
		return apierrors.OwnershipRequired(targetID)
	case errors.Is(err, recon.ErrOwnershipUnsupported):
		return apierrors.UnsupportedTargetType("")
	}
	return err
}

func toTargetResponse(t *recon.Target) TargetResponse {
	resp := TargetResponse{
		ID:        t.ID.String(),
		Type:      string(t.Type),
		Value:     t.Value,
		Label:     t.Label,
		CreatedAt: t.CreatedAt.Format(time.RFC3339),
		UpdatedAt: t.UpdatedAt.Format(time.RFC3339),
	}
	if t.CreatedBy != nil {
		s := t.CreatedBy.String()
		resp.CreatedBy = &s
	}
	return resp
}

func toOwnershipProofResponse(p *recon.OwnershipProof) OwnershipProofResponse {
	resp := OwnershipProofResponse{
		ID:        p.ID.String(),
		TargetID:  p.TargetID.String(),
		Method:    string(p.Method),
		Status:    string(p.Status),
		Challenge: p.Challenge,
		Evidence:  filterEvidence(p.Evidence),
		CreatedAt: p.CreatedAt.Format(time.RFC3339),
	}
	if p.VerifiedAt != nil {
		s := p.VerifiedAt.Format(time.RFC3339)
		resp.VerifiedAt = &s
	}
	return resp
}

// filterEvidence drops any field whose key starts with "token_hash" or
// is named "token" so secret material never leaves the API. The map
// returned is a fresh copy; the caller may mutate it.
func filterEvidence(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		lk := strings.ToLower(k)
		if lk == "token" || strings.HasPrefix(lk, "token_hash") || strings.Contains(lk, "secret") {
			continue
		}
		out[k] = v
	}
	return out
}

func toProfileResponse(p *recon.Profile) ProfileResponse {
	types := make([]string, len(p.TargetTypes))
	for i, t := range p.TargetTypes {
		types[i] = string(t)
	}
	return ProfileResponse{
		ID:          p.ID.String(),
		Name:        p.Name,
		Description: p.Description,
		Kind:        p.Kind,
		TargetTypes: types,
		Modules:     p.Modules,
		Options:     p.Options,
		CreatedAt:   p.CreatedAt.Format(time.RFC3339),
	}
}

func toScanResponse(s *recon.Scan) ScanResponse {
	resp := ScanResponse{
		ID:          s.ID.String(),
		TargetID:    s.TargetID.String(),
		ProfileID:   s.ProfileID.String(),
		Status:      string(s.Status),
		Engine:      s.Engine,
		EngineRunID: s.EngineRunID,
		Error:       s.Error,
		CreatedAt:   s.CreatedAt.Format(time.RFC3339),
	}
	if s.StartedAt != nil {
		v := s.StartedAt.Format(time.RFC3339)
		resp.StartedAt = &v
	}
	if s.FinishedAt != nil {
		v := s.FinishedAt.Format(time.RFC3339)
		resp.FinishedAt = &v
	}
	if s.CreatedBy != nil {
		v := s.CreatedBy.String()
		resp.CreatedBy = &v
	}
	return resp
}

func toFindingResponse(f *recon.Finding) FindingResponse {
	return FindingResponse{
		ID:         f.ID.String(),
		ScanID:     f.ScanID.String(),
		TargetID:   f.TargetID.String(),
		Module:     f.Module,
		Category:   f.Category,
		Severity:   string(f.Severity),
		Value:      f.Value,
		Source:     f.Source,
		Confidence: f.Confidence,
		FirstSeen:  f.FirstSeen.Format(time.RFC3339),
		LastSeen:   f.LastSeen.Format(time.RFC3339),
	}
}

// ============================================================================
// In-memory acknowledgement store
// ============================================================================

// MemoryAckStore is an in-process ReconAckRecorder used by tests and
// the default app wiring before a Postgres-backed implementation
// lands. It is safe for concurrent use.
type MemoryAckStore struct {
	mu           sync.RWMutex
	acknowledged bool
}

// NewMemoryAckStore returns a new in-memory acknowledgement store.
func NewMemoryAckStore() *MemoryAckStore { return &MemoryAckStore{} }

// IsAcknowledged reports the current state.
func (s *MemoryAckStore) IsAcknowledged(_ context.Context) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.acknowledged, nil
}

// Acknowledge marks the module as acknowledged. The actorID and ip
// parameters are accepted for interface compatibility — the
// in-memory store does not persist them.
func (s *MemoryAckStore) Acknowledge(_ context.Context, _ *uuid.UUID, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acknowledged = true
	return nil
}

// Ensure interface compliance at compile time.
var _ ReconAckRecorder = (*MemoryAckStore)(nil)
var _ middleware.ReconAckChecker = (*MemoryAckStore)(nil)
