// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	firewallsvc "github.com/fr4nsys/usulnet/internal/services/firewall"
)

// FirewallService is the narrow interface this handler depends on,
// satisfied by *firewall.Service. Declaring it here lets the handler
// be unit-tested with a mock without importing the concrete service.
// v26.2.7 had no API handler at all — the web handler called the
// concrete service directly — so this is a new boundary.
type FirewallService interface {
	ListRules(ctx context.Context, hostID uuid.UUID) ([]models.FirewallRule, error)
	GetRule(ctx context.Context, id uuid.UUID) (*models.FirewallRule, error)
	CreateRule(ctx context.Context, hostID uuid.UUID, input models.CreateFirewallRuleInput, userID *uuid.UUID) (*models.FirewallRule, error)
	UpdateRule(ctx context.Context, id uuid.UUID, input models.UpdateFirewallRuleInput, userID *uuid.UUID) (*models.FirewallRule, error)
	DeleteRule(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error
	DetectBackend(ctx context.Context, hostID uuid.UUID) (*models.FirewallHostStatus, error)
	ApplyRules(ctx context.Context, hostID uuid.UUID, userID *uuid.UUID) error
	SyncFromHost(ctx context.Context, hostID uuid.UUID, userID *uuid.UUID) (string, error)
	ListAuditLogs(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]models.FirewallAuditLog, int, error)
}

// FirewallHandler handles /api/v1/firewall/* requests. The svc field is
// nil-safe: when it is nil every handler returns 503 service_unavailable
// so the routes still mount cleanly during early app boot.
type FirewallHandler struct {
	BaseHandler
	svc      FirewallService
	hostIDFn func(*http.Request) uuid.UUID
}

// NewFirewallHandler creates a new firewall handler. hostIDFn resolves
// the active host ID for a given request. The standalone-mode app passes
// a closure that returns the default host UUID; multi-host installs can
// resolve from the URL or query string. If hostIDFn is nil, the handler
// falls back to reading ?host_id=<uuid> from the query string.
func NewFirewallHandler(svc FirewallService, hostIDFn func(*http.Request) uuid.UUID, log *logger.Logger) *FirewallHandler {
	return &FirewallHandler{
		BaseHandler: NewBaseHandler(log),
		svc:         svc,
		hostIDFn:    hostIDFn,
	}
}

// Routes returns the chi router for /api/v1/firewall.
// Read endpoints are viewer+, mutations are operator+, sync/apply are
// admin (they touch the host). The caller is responsible for placing
// the subtree behind the JWT/API-key auth middleware (see internal/api/router.go).
func (h *FirewallHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Route("/rules", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.ListRules)
		r.With(middleware.RequireOperator).Post("/", h.CreateRule)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.RequireViewer).Get("/", h.GetRule)
			r.With(middleware.RequireOperator).Put("/", h.UpdateRule)
			r.With(middleware.RequireOperator).Delete("/", h.DeleteRule)
		})
	})

	r.With(middleware.RequireViewer).Get("/status", h.Status)
	r.With(middleware.RequireAdmin).Post("/apply", h.Apply)
	r.With(middleware.RequireAdmin).Post("/sync", h.Sync)
	r.With(middleware.RequireViewer).Get("/audit", h.ListAudit)

	return r
}

// ============================================================================
// DTOs
// ============================================================================

// CreateFirewallRuleRequest is the body for POST /api/v1/firewall/rules.
type CreateFirewallRuleRequest struct {
	HostID        string `json:"host_id,omitempty" validate:"omitempty,uuid"`
	Name          string `json:"name" validate:"required,min=1,max=255"`
	Description   string `json:"description,omitempty" validate:"omitempty,max=1024"`
	Chain         string `json:"chain" validate:"required,oneof=INPUT OUTPUT FORWARD DOCKER-USER"`
	Protocol      string `json:"protocol,omitempty" validate:"omitempty,oneof=tcp udp icmp all"`
	Source        string `json:"source,omitempty" validate:"omitempty,max=255"`
	Destination   string `json:"destination,omitempty" validate:"omitempty,max=255"`
	SrcPort       string `json:"src_port,omitempty" validate:"omitempty,max=50"`
	DstPort       string `json:"dst_port,omitempty" validate:"omitempty,max=50"`
	Action        string `json:"action" validate:"required,oneof=ACCEPT DROP REJECT LOG"`
	Direction     string `json:"direction,omitempty" validate:"omitempty,oneof=inbound outbound"`
	InterfaceName string `json:"interface_name,omitempty" validate:"omitempty,max=50"`
	ContainerID   string `json:"container_id,omitempty" validate:"omitempty,max=128"`
	NetworkName   string `json:"network_name,omitempty" validate:"omitempty,max=255"`
	Comment       string `json:"comment,omitempty" validate:"omitempty,max=255"`
	Enabled       bool   `json:"enabled"`
}

// UpdateFirewallRuleRequest is the body for PUT /api/v1/firewall/rules/{id}.
// All fields are optional — only the supplied ones are patched.
type UpdateFirewallRuleRequest struct {
	Name          *string `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	Description   *string `json:"description,omitempty" validate:"omitempty,max=1024"`
	Chain         *string `json:"chain,omitempty" validate:"omitempty,oneof=INPUT OUTPUT FORWARD DOCKER-USER"`
	Protocol      *string `json:"protocol,omitempty" validate:"omitempty,oneof=tcp udp icmp all"`
	Source        *string `json:"source,omitempty" validate:"omitempty,max=255"`
	Destination   *string `json:"destination,omitempty" validate:"omitempty,max=255"`
	SrcPort       *string `json:"src_port,omitempty" validate:"omitempty,max=50"`
	DstPort       *string `json:"dst_port,omitempty" validate:"omitempty,max=50"`
	Action        *string `json:"action,omitempty" validate:"omitempty,oneof=ACCEPT DROP REJECT LOG"`
	Direction     *string `json:"direction,omitempty" validate:"omitempty,oneof=inbound outbound"`
	InterfaceName *string `json:"interface_name,omitempty" validate:"omitempty,max=50"`
	ContainerID   *string `json:"container_id,omitempty" validate:"omitempty,max=128"`
	NetworkName   *string `json:"network_name,omitempty" validate:"omitempty,max=255"`
	Comment       *string `json:"comment,omitempty" validate:"omitempty,max=255"`
	Enabled       *bool   `json:"enabled,omitempty"`
}

// FirewallRuleResponse is the API view of a firewall rule.
type FirewallRuleResponse struct {
	ID            string  `json:"id"`
	HostID        string  `json:"host_id"`
	Name          string  `json:"name"`
	Description   string  `json:"description,omitempty"`
	Chain         string  `json:"chain"`
	Protocol      string  `json:"protocol"`
	Source        string  `json:"source,omitempty"`
	Destination   string  `json:"destination,omitempty"`
	SrcPort       string  `json:"src_port,omitempty"`
	DstPort       string  `json:"dst_port,omitempty"`
	Action        string  `json:"action"`
	Direction     string  `json:"direction"`
	InterfaceName string  `json:"interface_name,omitempty"`
	Position      int     `json:"position"`
	Enabled       bool    `json:"enabled"`
	Applied       bool    `json:"applied"`
	ContainerID   string  `json:"container_id,omitempty"`
	NetworkName   string  `json:"network_name,omitempty"`
	Comment       string  `json:"comment,omitempty"`
	CreatedBy     *string `json:"created_by,omitempty"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

// FirewallStatusResponse is the API view of FirewallHostStatus.
type FirewallStatusResponse struct {
	Backend      string  `json:"backend"`
	Version      string  `json:"version"`
	ActiveRules  int     `json:"active_rules"`
	ManagedRules int     `json:"managed_rules"`
	LastApplied  *string `json:"last_applied,omitempty"`
	LastSynced   *string `json:"last_synced,omitempty"`
}

// FirewallAuditResponse is the API view of a firewall audit log entry.
type FirewallAuditResponse struct {
	ID          string  `json:"id"`
	HostID      string  `json:"host_id"`
	UserID      *string `json:"user_id,omitempty"`
	Action      string  `json:"action"`
	RuleID      *string `json:"rule_id,omitempty"`
	RuleSummary string  `json:"rule_summary"`
	Details     string  `json:"details,omitempty"`
	CreatedAt   string  `json:"created_at"`
}

// FirewallAuditPage is the paginated audit-log response.
type FirewallAuditPage struct {
	Entries []FirewallAuditResponse `json:"entries"`
	Total   int                     `json:"total"`
	Limit   int                     `json:"limit"`
	Offset  int                     `json:"offset"`
}

// ============================================================================
// Handlers
// ============================================================================

// ListRules handles GET /api/v1/firewall/rules.
func (h *FirewallHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	rules, err := h.svc.ListRules(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	resp := make([]FirewallRuleResponse, len(rules))
	for i := range rules {
		resp[i] = toFirewallRuleResponse(&rules[i])
	}
	h.OK(w, resp)
}

// GetRule handles GET /api/v1/firewall/rules/{id}.
func (h *FirewallHandler) GetRule(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	rule, err := h.svc.GetRule(r.Context(), id)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	h.OK(w, toFirewallRuleResponse(rule))
}

// CreateRule handles POST /api/v1/firewall/rules.
func (h *FirewallHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	var req CreateFirewallRuleRequest
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
	in := models.CreateFirewallRuleInput{
		Name:          req.Name,
		Description:   req.Description,
		Chain:         models.FirewallChain(req.Chain),
		Protocol:      strings.ToLower(req.Protocol),
		Source:        req.Source,
		Destination:   req.Destination,
		SrcPort:       req.SrcPort,
		DstPort:       req.DstPort,
		Action:        models.FirewallAction(req.Action),
		Direction:     req.Direction,
		InterfaceName: req.InterfaceName,
		ContainerID:   req.ContainerID,
		NetworkName:   req.NetworkName,
		Comment:       req.Comment,
		Enabled:       req.Enabled,
	}

	rule, err := h.svc.CreateRule(r.Context(), hostID, in, nilableUUID(actor))
	if err != nil {
		h.HandleError(w, mapFirewallError(err))
		return
	}
	h.Created(w, toFirewallRuleResponse(rule))
}

// UpdateRule handles PUT /api/v1/firewall/rules/{id}.
func (h *FirewallHandler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	var req UpdateFirewallRuleRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	in := models.UpdateFirewallRuleInput{
		Name:          req.Name,
		Description:   req.Description,
		Source:        req.Source,
		Destination:   req.Destination,
		SrcPort:       req.SrcPort,
		DstPort:       req.DstPort,
		Direction:     req.Direction,
		InterfaceName: req.InterfaceName,
		ContainerID:   req.ContainerID,
		NetworkName:   req.NetworkName,
		Comment:       req.Comment,
		Enabled:       req.Enabled,
	}
	if req.Chain != nil {
		c := models.FirewallChain(*req.Chain)
		in.Chain = &c
	}
	if req.Action != nil {
		a := models.FirewallAction(*req.Action)
		in.Action = &a
	}
	if req.Protocol != nil {
		p := strings.ToLower(*req.Protocol)
		in.Protocol = &p
	}

	actor, _ := h.GetUserID(r)
	rule, err := h.svc.UpdateRule(r.Context(), id, in, nilableUUID(actor))
	if err != nil {
		h.HandleError(w, mapFirewallError(err))
		return
	}
	h.OK(w, toFirewallRuleResponse(rule))
}

// DeleteRule handles DELETE /api/v1/firewall/rules/{id}.
func (h *FirewallHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	actor, _ := h.GetUserID(r)
	if err := h.svc.DeleteRule(r.Context(), id, nilableUUID(actor)); err != nil {
		h.HandleError(w, mapFirewallError(err))
		return
	}
	h.NoContent(w)
}

// Status handles GET /api/v1/firewall/status. Returns the detected
// backend + counts. Falls back to an "unknown" backend when no agent is
// reachable — never an error from this endpoint.
func (h *FirewallHandler) Status(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	status, err := h.svc.DetectBackend(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, mapFirewallError(err))
		return
	}
	h.OK(w, toFirewallStatusResponse(status))
}

// Apply handles POST /api/v1/firewall/apply. Pushes enabled rules to
// the agent. Admin-only.
func (h *FirewallHandler) Apply(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	actor, _ := h.GetUserID(r)
	if err := h.svc.ApplyRules(r.Context(), hostID, nilableUUID(actor)); err != nil {
		h.HandleError(w, mapFirewallError(err))
		return
	}
	h.NoContent(w)
}

// FirewallSyncResponse is the body of POST /api/v1/firewall/sync. The
// output is the raw textual dump returned by the host's firewall tool
// (e.g. `ufw status verbose`).
type FirewallSyncResponse struct {
	Output string `json:"output"`
}

// Sync handles POST /api/v1/firewall/sync. Reads firewall state from
// the host. Admin-only.
func (h *FirewallHandler) Sync(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	actor, _ := h.GetUserID(r)
	out, err := h.svc.SyncFromHost(r.Context(), hostID, nilableUUID(actor))
	if err != nil {
		h.HandleError(w, mapFirewallError(err))
		return
	}
	h.OK(w, FirewallSyncResponse{Output: out})
}

// ListAudit handles GET /api/v1/firewall/audit.
func (h *FirewallHandler) ListAudit(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	pagination := h.GetPagination(r)
	entries, total, err := h.svc.ListAuditLogs(r.Context(), hostID, pagination.PerPage, pagination.Offset)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	resp := make([]FirewallAuditResponse, len(entries))
	for i := range entries {
		resp[i] = toFirewallAuditResponse(&entries[i])
	}
	h.OK(w, FirewallAuditPage{
		Entries: resp,
		Total:   total,
		Limit:   pagination.PerPage,
		Offset:  pagination.Offset,
	})
}

// ============================================================================
// Helpers
// ============================================================================

// resolveHostID returns the active host UUID for the request. It tries,
// in order: the hostIDFn injected at construction, the ?host_id= query
// string, and finally the X-Host-ID header. Returns an error only if
// none of those resolve.
func (h *FirewallHandler) resolveHostID(r *http.Request) (uuid.UUID, error) {
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

// resolveHostIDFromBody is the create-path variant — the host can be
// supplied in the request body.
func (h *FirewallHandler) resolveHostIDFromBody(r *http.Request, bodyHostID string) (uuid.UUID, error) {
	if bodyHostID != "" {
		id, err := uuid.Parse(bodyHostID)
		if err != nil {
			return uuid.Nil, apierrors.InvalidInput("invalid host_id format")
		}
		return id, nil
	}
	return h.resolveHostID(r)
}

// serviceUnavailable writes a 503 with code SERVICE_UNAVAILABLE — the
// firewall service is not wired in this build.
func (h *FirewallHandler) serviceUnavailable(w http.ResponseWriter) {
	apierrors.WriteError(w, apierrors.ServiceUnavailable("firewall service is not configured"))
}

// mapFirewallError translates package-level firewall errors into typed
// APIErrors. ErrInvalidInput → 400; ErrSenderNotConfigured → 503;
// everything else flows to BaseHandler.HandleError.
func mapFirewallError(err error) error {
	switch {
	case errors.Is(err, firewallsvc.ErrInvalidInput):
		return apierrors.InvalidInput(err.Error())
	case errors.Is(err, firewallsvc.ErrSenderNotConfigured):
		return apierrors.ServiceUnavailable("firewall agent transport is not configured")
	}
	return err
}

func toFirewallRuleResponse(r *models.FirewallRule) FirewallRuleResponse {
	resp := FirewallRuleResponse{
		ID:            r.ID.String(),
		HostID:        r.HostID.String(),
		Name:          r.Name,
		Description:   r.Description,
		Chain:         string(r.Chain),
		Protocol:      r.Protocol,
		Source:        r.Source,
		Destination:   r.Destination,
		SrcPort:       r.SrcPort,
		DstPort:       r.DstPort,
		Action:        string(r.Action),
		Direction:     r.Direction,
		InterfaceName: r.InterfaceName,
		Position:      r.Position,
		Enabled:       r.Enabled,
		Applied:       r.Applied,
		ContainerID:   r.ContainerID,
		NetworkName:   r.NetworkName,
		Comment:       r.Comment,
		CreatedAt:     r.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     r.UpdatedAt.Format(time.RFC3339),
	}
	if r.CreatedBy != nil {
		s := r.CreatedBy.String()
		resp.CreatedBy = &s
	}
	return resp
}

func toFirewallStatusResponse(s *models.FirewallHostStatus) FirewallStatusResponse {
	resp := FirewallStatusResponse{
		Backend:      string(s.Backend),
		Version:      s.Version,
		ActiveRules:  s.ActiveRules,
		ManagedRules: s.ManagedRules,
	}
	if s.LastApplied != nil {
		v := s.LastApplied.Format(time.RFC3339)
		resp.LastApplied = &v
	}
	if s.LastSynced != nil {
		v := s.LastSynced.Format(time.RFC3339)
		resp.LastSynced = &v
	}
	return resp
}

func toFirewallAuditResponse(e *models.FirewallAuditLog) FirewallAuditResponse {
	resp := FirewallAuditResponse{
		ID:          e.ID.String(),
		HostID:      e.HostID.String(),
		Action:      e.Action,
		RuleSummary: e.RuleSummary,
		Details:     e.Details,
		CreatedAt:   e.CreatedAt.Format(time.RFC3339),
	}
	if e.UserID != nil {
		v := e.UserID.String()
		resp.UserID = &v
	}
	if e.RuleID != nil {
		v := e.RuleID.String()
		resp.RuleID = &v
	}
	return resp
}
