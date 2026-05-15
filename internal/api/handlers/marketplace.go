// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	marketplacesvc "github.com/fr4nsys/usulnet/internal/services/marketplace"
)

// MarketplaceService is the narrow interface this handler depends on.
// It is implemented by *marketplacesvc.Service. v26.2.7 had no API
// handler at all — this is the v26.5.1 surface, built from scratch
// against the same service contract.
type MarketplaceService interface {
	SearchApps(ctx context.Context, query, category string, limit, offset int) ([]*models.MarketplaceApp, int, error)
	GetApp(ctx context.Context, id uuid.UUID) (*models.MarketplaceApp, error)
	GetAppBySlug(ctx context.Context, slug string) (*models.MarketplaceApp, error)
	ListFeatured(ctx context.Context, limit int) ([]*models.MarketplaceApp, error)
	InstallApp(ctx context.Context, appID, hostID uuid.UUID, opts marketplacesvc.InstallOptions) (*models.MarketplaceInstallation, error)
	ListInstallations(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.MarketplaceInstallation, int, error)
	GetInstallation(ctx context.Context, id uuid.UUID) (*models.MarketplaceInstallation, error)
	UninstallApp(ctx context.Context, id uuid.UUID) error
	AddReview(ctx context.Context, review *models.MarketplaceReview) error
	ListReviews(ctx context.Context, appID uuid.UUID) ([]*models.MarketplaceReview, error)
}

// MarketplaceHandler serves /api/v1/marketplace/*.
//
// The handler is nil-safe: every endpoint replies 503
// service_unavailable when svc is nil, so the router mounting code
// can stay simple.
type MarketplaceHandler struct {
	BaseHandler
	svc      MarketplaceService
	hostIDFn func(*http.Request) uuid.UUID
}

// NewMarketplaceHandler builds a marketplace API handler.
func NewMarketplaceHandler(svc MarketplaceService, hostIDFn func(*http.Request) uuid.UUID, log *logger.Logger) *MarketplaceHandler {
	return &MarketplaceHandler{
		BaseHandler: NewBaseHandler(log),
		svc:         svc,
		hostIDFn:    hostIDFn,
	}
}

// Routes mounts /api/v1/marketplace/*. Read endpoints are viewer+,
// installs and reviews are operator+, app submissions are operator+.
func (h *MarketplaceHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.With(middleware.RequireViewer).Get("/apps", h.ListApps)
	r.With(middleware.RequireViewer).Get("/featured", h.ListFeatured)
	r.Route("/apps/{slug}", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.GetApp)
		r.With(middleware.RequireOperator).Post("/install", h.InstallApp)
		r.With(middleware.RequireViewer).Get("/reviews", h.ListReviews)
	})

	r.With(middleware.RequireViewer).Get("/installations", h.ListInstallations)
	r.Route("/installations/{id}", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.GetInstallation)
		r.With(middleware.RequireOperator).Post("/uninstall", h.Uninstall)
	})

	r.With(middleware.RequireOperator).Post("/reviews", h.AddReview)

	return r
}

// ============================================================================
// DTOs
// ============================================================================

// MarketplaceAppResponse is the API view of a marketplace app.
type MarketplaceAppResponse struct {
	ID              string          `json:"id"`
	Slug            string          `json:"slug"`
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	LongDescription string          `json:"long_description,omitempty"`
	Icon            string          `json:"icon"`
	IconColor       string          `json:"icon_color"`
	IconSVG         string          `json:"icon_svg,omitempty"`
	Category        string          `json:"category"`
	Version         string          `json:"version,omitempty"`
	ManifestVersion int             `json:"manifest_version"`
	Website         string          `json:"website,omitempty"`
	Source          string          `json:"source,omitempty"`
	Author          string          `json:"author,omitempty"`
	License         string          `json:"license,omitempty"`
	ComposeTemplate string          `json:"compose_template,omitempty"`
	Fields          json.RawMessage `json:"fields"`
	Tags            []string        `json:"tags"`
	MinMemoryMB     int             `json:"min_memory_mb"`
	MinCPUCores     float64         `json:"min_cpu_cores"`
	IsOfficial      bool            `json:"is_official"`
	IsVerified      bool            `json:"is_verified"`
	Featured        bool            `json:"featured"`
	BuiltIn         bool            `json:"built_in"`
	InstallCount    int             `json:"install_count"`
	AvgRating       float64         `json:"avg_rating"`
	RatingCount     int             `json:"rating_count"`
	CreatedAt       string          `json:"created_at,omitempty"`
	UpdatedAt       string          `json:"updated_at,omitempty"`
}

// MarketplaceInstallationResponse is the API view of an installation.
type MarketplaceInstallationResponse struct {
	ID           string          `json:"id"`
	AppID        string          `json:"app_id"`
	HostID       string          `json:"host_id"`
	StackID      string          `json:"stack_id,omitempty"`
	Name         string          `json:"name"`
	Status       string          `json:"status"`
	Version      string          `json:"version,omitempty"`
	ConfigValues json.RawMessage `json:"config_values"`
	InstalledBy  string          `json:"installed_by,omitempty"`
	InstalledAt  string          `json:"installed_at"`
	UpdatedAt    string          `json:"updated_at,omitempty"`
}

// MarketplaceReviewResponse is the API view of a review.
type MarketplaceReviewResponse struct {
	ID        string `json:"id"`
	AppID     string `json:"app_id"`
	UserID    string `json:"user_id"`
	Rating    int    `json:"rating"`
	Title     string `json:"title,omitempty"`
	Comment   string `json:"comment,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// MarketplaceAppListResponse pages search results.
type MarketplaceAppListResponse struct {
	Apps  []MarketplaceAppResponse `json:"apps"`
	Total int                      `json:"total"`
}

// MarketplaceInstallationListResponse pages installation results.
type MarketplaceInstallationListResponse struct {
	Installations []MarketplaceInstallationResponse `json:"installations"`
	Total         int                               `json:"total"`
}

// InstallAppRequest is the body for POST /apps/{slug}/install.
type InstallAppRequest struct {
	HostID       string            `json:"host_id,omitempty" validate:"omitempty,uuid"`
	Name         string            `json:"name,omitempty" validate:"omitempty,max=255"`
	ConfigValues map[string]string `json:"config_values,omitempty"`
}

// InstallAppResponse is returned from POST /apps/{slug}/install. The
// API contract calls out the stack_id explicitly so REST consumers can
// look up the resulting stack without an extra fetch.
type InstallAppResponse struct {
	InstallationID string `json:"installation_id"`
	StackID        string `json:"stack_id"`
	Status         string `json:"status"`
}

// AddReviewRequest is the body for POST /reviews. UserID is taken from
// the JWT claims — clients cannot impersonate another reviewer.
type AddReviewRequest struct {
	AppID   string `json:"app_id" validate:"required,uuid"`
	Rating  int    `json:"rating" validate:"required,min=1,max=5"`
	Title   string `json:"title,omitempty" validate:"omitempty,max=255"`
	Comment string `json:"comment,omitempty" validate:"omitempty,max=4096"`
}

// ============================================================================
// Handlers — apps
// ============================================================================

// ListApps handles GET /apps.
func (h *MarketplaceHandler) ListApps(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	query := h.QueryParam(r, "q")
	category := h.QueryParam(r, "category")
	page := h.GetPagination(r)

	apps, total, err := h.svc.SearchApps(r.Context(), query, category, page.PerPage, page.Offset)
	if err != nil {
		h.HandleError(w, mapMarketplaceError(err))
		return
	}
	resp := MarketplaceAppListResponse{
		Apps:  make([]MarketplaceAppResponse, 0, len(apps)),
		Total: total,
	}
	for _, a := range apps {
		resp.Apps = append(resp.Apps, toMarketplaceAppResponse(a, false))
	}
	h.OK(w, resp)
}

// ListFeatured handles GET /featured.
func (h *MarketplaceHandler) ListFeatured(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	limit := h.QueryParamInt(r, "limit", 6)
	apps, err := h.svc.ListFeatured(r.Context(), limit)
	if err != nil {
		h.HandleError(w, mapMarketplaceError(err))
		return
	}
	out := make([]MarketplaceAppResponse, 0, len(apps))
	for _, a := range apps {
		out = append(out, toMarketplaceAppResponse(a, false))
	}
	h.OK(w, out)
}

// GetApp handles GET /apps/{slug}.
func (h *MarketplaceHandler) GetApp(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	slug := chi.URLParam(r, "slug")
	app, err := h.svc.GetAppBySlug(r.Context(), slug)
	if err != nil {
		h.HandleError(w, mapMarketplaceError(err))
		return
	}
	h.OK(w, toMarketplaceAppResponse(app, true))
}

// InstallApp handles POST /apps/{slug}/install.
func (h *MarketplaceHandler) InstallApp(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	slug := chi.URLParam(r, "slug")

	var req InstallAppRequest
	// Body is optional — defaults are fine.
	if r.ContentLength > 0 {
		if err := h.ParseJSON(r, &req); err != nil {
			h.HandleError(w, err)
			return
		}
	}

	app, err := h.svc.GetAppBySlug(r.Context(), slug)
	if err != nil {
		h.HandleError(w, mapMarketplaceError(err))
		return
	}

	hostID, err := h.resolveMarketplaceHostID(r, req.HostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	userID, _ := h.GetUserID(r)
	opts := marketplacesvc.InstallOptions{
		Name:         req.Name,
		ConfigValues: req.ConfigValues,
		UserID:       nilableUUID(userID),
	}
	inst, err := h.svc.InstallApp(r.Context(), app.ID, hostID, opts)
	if err != nil {
		h.HandleError(w, mapMarketplaceError(err))
		return
	}
	stackID := ""
	if inst.StackID != nil {
		stackID = inst.StackID.String()
	}
	h.Created(w, InstallAppResponse{
		InstallationID: inst.ID.String(),
		StackID:        stackID,
		Status:         string(inst.Status),
	})
}

// ListReviews handles GET /apps/{slug}/reviews.
func (h *MarketplaceHandler) ListReviews(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	slug := chi.URLParam(r, "slug")
	app, err := h.svc.GetAppBySlug(r.Context(), slug)
	if err != nil {
		h.HandleError(w, mapMarketplaceError(err))
		return
	}
	reviews, err := h.svc.ListReviews(r.Context(), app.ID)
	if err != nil {
		h.HandleError(w, mapMarketplaceError(err))
		return
	}
	out := make([]MarketplaceReviewResponse, 0, len(reviews))
	for _, rv := range reviews {
		out = append(out, toMarketplaceReviewResponse(rv))
	}
	h.OK(w, out)
}

// ============================================================================
// Handlers — installations
// ============================================================================

// ListInstallations handles GET /installations.
func (h *MarketplaceHandler) ListInstallations(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveMarketplaceHostID(r, "")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	page := h.GetPagination(r)
	insts, total, err := h.svc.ListInstallations(r.Context(), hostID, page.PerPage, page.Offset)
	if err != nil {
		h.HandleError(w, mapMarketplaceError(err))
		return
	}
	out := MarketplaceInstallationListResponse{
		Installations: make([]MarketplaceInstallationResponse, 0, len(insts)),
		Total:         total,
	}
	for _, inst := range insts {
		out.Installations = append(out.Installations, toMarketplaceInstallationResponse(inst))
	}
	h.OK(w, out)
}

// GetInstallation handles GET /installations/{id}.
func (h *MarketplaceHandler) GetInstallation(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	inst, err := h.svc.GetInstallation(r.Context(), id)
	if err != nil {
		h.HandleError(w, mapMarketplaceError(err))
		return
	}
	h.OK(w, toMarketplaceInstallationResponse(inst))
}

// Uninstall handles POST /installations/{id}/uninstall.
func (h *MarketplaceHandler) Uninstall(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	if err := h.svc.UninstallApp(r.Context(), id); err != nil {
		h.HandleError(w, mapMarketplaceError(err))
		return
	}
	h.NoContent(w)
}

// ============================================================================
// Handlers — reviews
// ============================================================================

// AddReview handles POST /reviews.
func (h *MarketplaceHandler) AddReview(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	var req AddReviewRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	appID, err := uuid.Parse(req.AppID)
	if err != nil {
		h.HandleError(w, apierrors.InvalidInput("invalid app_id"))
		return
	}
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	review := &models.MarketplaceReview{
		AppID:   appID,
		UserID:  userID,
		Rating:  req.Rating,
		Title:   req.Title,
		Comment: req.Comment,
	}
	if err := h.svc.AddReview(r.Context(), review); err != nil {
		h.HandleError(w, mapMarketplaceError(err))
		return
	}
	h.Created(w, toMarketplaceReviewResponse(review))
}

// ============================================================================
// Helpers
// ============================================================================

func (h *MarketplaceHandler) serviceUnavailable(w http.ResponseWriter) {
	apierrors.WriteError(w, apierrors.ServiceUnavailable("marketplace service is not configured"))
}

// resolveMarketplaceHostID consolidates host ID resolution:
//
//  1. Body's host_id field (if non-empty and a valid UUID)
//  2. Query parameter "host_id"
//  3. X-Host-ID header
//  4. The router-level resolver (defaults to the standalone host)
func (h *MarketplaceHandler) resolveMarketplaceHostID(r *http.Request, bodyHostID string) (uuid.UUID, error) {
	if bodyHostID != "" {
		id, err := uuid.Parse(bodyHostID)
		if err != nil {
			return uuid.Nil, apierrors.InvalidInput("invalid host_id format")
		}
		return id, nil
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
	if h.hostIDFn != nil {
		if id := h.hostIDFn(r); id != uuid.Nil {
			return id, nil
		}
	}
	return uuid.Nil, apierrors.MissingField("host_id")
}

func mapMarketplaceError(err error) error {
	switch {
	case stderrors.Is(err, marketplacesvc.ErrAppNotFound):
		return apierrors.NotFound("marketplace_app")
	case stderrors.Is(err, marketplacesvc.ErrInvalidInput):
		return apierrors.InvalidInput(err.Error())
	case stderrors.Is(err, marketplacesvc.ErrStackRequired):
		return apierrors.ServiceUnavailable(err.Error())
	}
	return err
}

func toMarketplaceAppResponse(a *models.MarketplaceApp, includeCompose bool) MarketplaceAppResponse {
	resp := MarketplaceAppResponse{
		ID:              a.ID.String(),
		Slug:            a.Slug,
		Name:            a.Name,
		Description:     a.Description,
		LongDescription: a.LongDescription,
		Icon:            a.Icon,
		IconColor:       a.IconColor,
		IconSVG:         a.IconSVG,
		Category:        string(a.Category),
		Version:         a.Version,
		ManifestVersion: a.ManifestVersion,
		Website:         a.Website,
		Source:          a.Source,
		Author:          a.Author,
		License:         a.License,
		Fields:          a.Fields,
		Tags:            a.Tags,
		MinMemoryMB:     a.MinMemoryMB,
		MinCPUCores:     a.MinCPUCores,
		IsOfficial:      a.IsOfficial,
		IsVerified:      a.IsVerified,
		Featured:        a.Featured,
		BuiltIn:         a.BuiltIn,
		InstallCount:    a.InstallCount,
		AvgRating:       a.AvgRating,
		RatingCount:     a.RatingCount,
	}
	if includeCompose {
		resp.ComposeTemplate = a.ComposeTemplate
	}
	if resp.Fields == nil {
		resp.Fields = json.RawMessage("[]")
	}
	if !a.CreatedAt.IsZero() {
		resp.CreatedAt = a.CreatedAt.Format(time.RFC3339)
	}
	if !a.UpdatedAt.IsZero() {
		resp.UpdatedAt = a.UpdatedAt.Format(time.RFC3339)
	}
	return resp
}

func toMarketplaceInstallationResponse(inst *models.MarketplaceInstallation) MarketplaceInstallationResponse {
	resp := MarketplaceInstallationResponse{
		ID:           inst.ID.String(),
		AppID:        inst.AppID.String(),
		HostID:       inst.HostID.String(),
		Name:         inst.Name,
		Status:       string(inst.Status),
		Version:      inst.Version,
		ConfigValues: inst.ConfigValues,
		InstalledAt:  inst.InstalledAt.Format(time.RFC3339),
	}
	if inst.StackID != nil {
		resp.StackID = inst.StackID.String()
	}
	if inst.InstalledBy != nil {
		resp.InstalledBy = inst.InstalledBy.String()
	}
	if !inst.UpdatedAt.IsZero() {
		resp.UpdatedAt = inst.UpdatedAt.Format(time.RFC3339)
	}
	if resp.ConfigValues == nil {
		resp.ConfigValues = json.RawMessage("{}")
	}
	return resp
}

func toMarketplaceReviewResponse(rv *models.MarketplaceReview) MarketplaceReviewResponse {
	resp := MarketplaceReviewResponse{
		ID:      rv.ID.String(),
		AppID:   rv.AppID.String(),
		UserID:  rv.UserID.String(),
		Rating:  rv.Rating,
		Title:   rv.Title,
		Comment: rv.Comment,
	}
	if !rv.CreatedAt.IsZero() {
		resp.CreatedAt = rv.CreatedAt.Format(time.RFC3339)
	}
	if !rv.UpdatedAt.IsZero() {
		resp.UpdatedAt = rv.UpdatedAt.Format(time.RFC3339)
	}
	return resp
}
