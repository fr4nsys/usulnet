// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	egresssvc "github.com/fr4nsys/usulnet/internal/services/egress"
)

// EgressService is the narrow interface this handler depends on,
// satisfied by *egress.Service. Declared here so the handler can be
// unit-tested with a mock without importing the concrete service.
type EgressService interface {
	ListPolicies(ctx context.Context, hostID uuid.UUID) ([]models.EgressPolicy, error)
	CreatePolicy(ctx context.Context, hostID uuid.UUID, in models.CreateEgressPolicyInput) (*models.EgressPolicy, error)
	DeletePolicy(ctx context.Context, id uuid.UUID) error
	RecentDenies(ctx context.Context, hostID uuid.UUID, limit int) ([]models.EgressAuditLog, error)
}

// EgressHandler serves /api/v1/egress/*. svc is nil-safe: when it is nil
// every endpoint returns 503 service_unavailable so the route registration
// still succeeds during early app boot.
type EgressHandler struct {
	BaseHandler
	svc EgressService
}

// NewEgressHandler creates a new egress API handler.
func NewEgressHandler(svc EgressService, log *logger.Logger) *EgressHandler {
	return &EgressHandler{
		BaseHandler: NewBaseHandler(log),
		svc:         svc,
	}
}

// Routes returns the chi router for /api/v1/egress. Per the brief:
//
//   - GET    /{hostID}/policies      → list (operator+)
//   - POST   /{hostID}/policies      → create (operator+)
//   - DELETE /policies/{id}          → delete (operator+)
//   - GET    /{hostID}/denies        → recent denies (operator+) — small
//     read-only addition so the UI's "why was my call blocked" panel
//     does not need a separate audit-log handler.
//
// RequireOperator on every endpoint — egress filtering is an operational
// security knob, not a viewer concern.
func (h *EgressHandler) Routes() chi.Router {
	r := chi.NewRouter()
	r.With(middleware.RequireOperator).Get("/{hostID}/policies", h.List)
	r.With(middleware.RequireOperator).Post("/{hostID}/policies", h.Create)
	r.With(middleware.RequireOperator).Get("/{hostID}/denies", h.Denies)
	r.With(middleware.RequireOperator).Delete("/policies/{id}", h.Delete)
	return r
}

// ----------------------------------------------------------------------------
// DTOs
// ----------------------------------------------------------------------------

// CreateEgressPolicyRequest is the body for POST /{hostID}/policies.
type CreateEgressPolicyRequest struct {
	TargetGlob string `json:"target_glob" validate:"required,min=1,max=255"`
	Allow      bool   `json:"allow"`
}

// EgressPolicyResponse is the API view of a policy row.
type EgressPolicyResponse struct {
	ID         string `json:"id"`
	HostID     string `json:"host_id"`
	TargetGlob string `json:"target_glob"`
	Allow      bool   `json:"allow"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// EgressDenyResponse is the API view of one deny audit row.
type EgressDenyResponse struct {
	ID        string `json:"id"`
	HostID    string `json:"host_id"`
	Target    string `json:"target"`
	Method    string `json:"method,omitempty"`
	Decision  string `json:"decision"`
	CreatedAt string `json:"created_at"`
}

// ----------------------------------------------------------------------------
// Handlers
// ----------------------------------------------------------------------------

// List handles GET /api/v1/egress/{hostID}/policies.
func (h *EgressHandler) List(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.parseHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	policies, err := h.svc.ListPolicies(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, mapEgressError(err))
		return
	}
	resp := make([]EgressPolicyResponse, len(policies))
	for i := range policies {
		resp[i] = toEgressPolicyResponse(&policies[i])
	}
	h.OK(w, resp)
}

// Create handles POST /api/v1/egress/{hostID}/policies.
func (h *EgressHandler) Create(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.parseHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	var req CreateEgressPolicyRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	policy, err := h.svc.CreatePolicy(r.Context(), hostID, models.CreateEgressPolicyInput{
		TargetGlob: req.TargetGlob,
		Allow:      req.Allow,
	})
	if err != nil {
		h.HandleError(w, mapEgressError(err))
		return
	}
	h.Created(w, toEgressPolicyResponse(policy))
}

// Delete handles DELETE /api/v1/egress/policies/{id}.
func (h *EgressHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	if err := h.svc.DeletePolicy(r.Context(), id); err != nil {
		h.HandleError(w, mapEgressError(err))
		return
	}
	h.NoContent(w)
}

// Denies handles GET /api/v1/egress/{hostID}/denies — the most-recent
// denied requests, newest first. Accepts ?limit= (default 100, max 1000).
func (h *EgressHandler) Denies(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.parseHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	limit := h.QueryParamInt(r, "limit", 100)
	if limit < 1 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	entries, err := h.svc.RecentDenies(r.Context(), hostID, limit)
	if err != nil {
		h.HandleError(w, mapEgressError(err))
		return
	}
	resp := make([]EgressDenyResponse, len(entries))
	for i := range entries {
		resp[i] = toEgressDenyResponse(&entries[i])
	}
	h.OK(w, resp)
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

func (h *EgressHandler) parseHostID(r *http.Request) (uuid.UUID, error) {
	raw := chi.URLParam(r, "hostID")
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, apierrors.InvalidInput("invalid hostID")
	}
	return id, nil
}

func (h *EgressHandler) serviceUnavailable(w http.ResponseWriter) {
	apierrors.WriteError(w, apierrors.ServiceUnavailable("egress service is not configured"))
}

func mapEgressError(err error) error {
	if errors.Is(err, egresssvc.ErrInvalidInput) {
		return apierrors.InvalidInput(err.Error())
	}
	return err
}

func toEgressPolicyResponse(p *models.EgressPolicy) EgressPolicyResponse {
	return EgressPolicyResponse{
		ID:         p.ID.String(),
		HostID:     p.HostID.String(),
		TargetGlob: p.TargetGlob,
		Allow:      p.Allow,
		CreatedAt:  p.CreatedAt.Format(time.RFC3339),
		UpdatedAt:  p.UpdatedAt.Format(time.RFC3339),
	}
}

func toEgressDenyResponse(e *models.EgressAuditLog) EgressDenyResponse {
	return EgressDenyResponse{
		ID:        e.ID.String(),
		HostID:    e.HostID.String(),
		Target:    e.Target,
		Method:    e.Method,
		Decision:  e.Decision,
		CreatedAt: e.CreatedAt.Format(time.RFC3339),
	}
}
