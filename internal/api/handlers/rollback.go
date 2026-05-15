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
	rollbacksvc "github.com/fr4nsys/usulnet/internal/services/rollback"
)

// RollbackService is the narrow interface the handler depends on. The
// real *rollback.Service satisfies it implicitly; declaring it here
// keeps tests free of the concrete service.
type RollbackService interface {
	CreatePolicy(ctx context.Context, in models.CreateRollbackPolicyInput, actor *uuid.UUID) (*models.RollbackPolicy, error)
	UpdatePolicy(ctx context.Context, id uuid.UUID, in models.UpdateRollbackPolicyInput, actor *uuid.UUID) (*models.RollbackPolicy, error)
	DeletePolicy(ctx context.Context, id uuid.UUID, actor *uuid.UUID) error
	GetPolicy(ctx context.Context, id uuid.UUID) (*models.RollbackPolicy, error)
	ListPolicies(ctx context.Context) ([]models.RollbackPolicy, error)
	ListExecutions(ctx context.Context, opts models.RollbackExecutionListOptions) ([]models.RollbackExecution, int, error)
	GetExecution(ctx context.Context, id uuid.UUID) (*models.RollbackExecution, error)
	ListAudit(ctx context.Context, policyID, stackID uuid.UUID, limit, offset int) ([]models.RollbackAuditEntry, int, error)
	DryRun(ctx context.Context, policyID, stackID uuid.UUID, actor *uuid.UUID) (*models.RollbackDryRunResult, error)
}

// RollbackHandler serves /api/v1/rollback/*. svc is nil-safe — every
// route returns 503 service_unavailable when the wiring is absent.
type RollbackHandler struct {
	BaseHandler
	svc RollbackService
}

// NewRollbackHandler constructs a new handler.
func NewRollbackHandler(svc RollbackService, log *logger.Logger) *RollbackHandler {
	return &RollbackHandler{
		BaseHandler: NewBaseHandler(log),
		svc:         svc,
	}
}

// Routes returns the chi subrouter mounted under /api/v1/rollback.
//   - List/Get policies + executions + audit are viewer+.
//   - Create/Update/Delete policies and Dry-run are operator+. Dry-run
//     does not modify the live stack, but it does append an audit row,
//     so operator-only is the right level.
func (h *RollbackHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Route("/policies", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.ListPolicies)
		r.With(middleware.RequireOperator).Post("/", h.CreatePolicy)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.RequireViewer).Get("/", h.GetPolicy)
			r.With(middleware.RequireOperator).Put("/", h.UpdatePolicy)
			r.With(middleware.RequireOperator).Delete("/", h.DeletePolicy)
			r.With(middleware.RequireOperator).Post("/dry-run", h.DryRun)
		})
	})

	r.With(middleware.RequireViewer).Get("/executions", h.ListExecutions)
	r.With(middleware.RequireViewer).Get("/executions/{id}", h.GetExecution)
	r.With(middleware.RequireViewer).Get("/audit", h.ListAudit)

	return r
}

// ============================================================================
// DTOs
// ============================================================================

// CreateRollbackPolicyRequest is the body of POST /api/v1/rollback/policies.
type CreateRollbackPolicyRequest struct {
	Name             string `json:"name" validate:"required,min=1,max=255"`
	Description      string `json:"description,omitempty" validate:"omitempty,max=4096"`
	Enabled          bool   `json:"enabled"`
	Scope            string `json:"scope" validate:"required,oneof=all stack tag"`
	ScopeStackID     string `json:"scope_stack_id,omitempty" validate:"omitempty,uuid"`
	ScopeValue       string `json:"scope_value,omitempty" validate:"omitempty,max=255"`
	TriggerKind      string `json:"trigger_kind" validate:"required,oneof=deploy_failed healthcheck_failed container_crash"`
	FailureThreshold *int   `json:"failure_threshold,omitempty" validate:"omitempty,gt=0"`
	WindowSeconds    *int   `json:"window_seconds,omitempty" validate:"omitempty,gt=0"`
	LastGoodStrategy string `json:"last_good_strategy" validate:"required,oneof=previous last_healthy"`
	CooldownSeconds  int    `json:"cooldown_seconds" validate:"gte=0"`
	DryRun           bool   `json:"dry_run"`
}

// UpdateRollbackPolicyRequest is the body of PUT /api/v1/rollback/policies/{id}.
// All fields are optional.
type UpdateRollbackPolicyRequest struct {
	Name             *string `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	Description      *string `json:"description,omitempty" validate:"omitempty,max=4096"`
	Enabled          *bool   `json:"enabled,omitempty"`
	Scope            *string `json:"scope,omitempty" validate:"omitempty,oneof=all stack tag"`
	ScopeStackID     *string `json:"scope_stack_id,omitempty" validate:"omitempty,uuid"`
	ScopeValue       *string `json:"scope_value,omitempty" validate:"omitempty,max=255"`
	TriggerKind      *string `json:"trigger_kind,omitempty" validate:"omitempty,oneof=deploy_failed healthcheck_failed container_crash"`
	FailureThreshold *int    `json:"failure_threshold,omitempty" validate:"omitempty,gt=0"`
	WindowSeconds    *int    `json:"window_seconds,omitempty" validate:"omitempty,gt=0"`
	LastGoodStrategy *string `json:"last_good_strategy,omitempty" validate:"omitempty,oneof=previous last_healthy"`
	CooldownSeconds  *int    `json:"cooldown_seconds,omitempty" validate:"omitempty,gte=0"`
	DryRun           *bool   `json:"dry_run,omitempty"`
}

// DryRunRequest is the body of POST /api/v1/rollback/policies/{id}/dry-run.
type DryRunRequest struct {
	StackID string `json:"stack_id" validate:"required,uuid"`
}

// RollbackPolicyResponse is the API view of a policy.
type RollbackPolicyResponse struct {
	ID               string  `json:"id"`
	Name             string  `json:"name"`
	Description      string  `json:"description,omitempty"`
	Enabled          bool    `json:"enabled"`
	Scope            string  `json:"scope"`
	ScopeStackID     *string `json:"scope_stack_id,omitempty"`
	ScopeValue       string  `json:"scope_value,omitempty"`
	TriggerKind      string  `json:"trigger_kind"`
	FailureThreshold *int    `json:"failure_threshold,omitempty"`
	WindowSeconds    *int    `json:"window_seconds,omitempty"`
	LastGoodStrategy string  `json:"last_good_strategy"`
	CooldownSeconds  int     `json:"cooldown_seconds"`
	DryRun           bool    `json:"dry_run"`
	CreatedBy        *string `json:"created_by,omitempty"`
	CreatedAt        string  `json:"created_at"`
	UpdatedAt        string  `json:"updated_at"`
}

// RollbackExecutionResponse is the API view of an execution.
type RollbackExecutionResponse struct {
	ID            string  `json:"id"`
	PolicyID      string  `json:"policy_id"`
	StackID       string  `json:"stack_id"`
	ChangeEventID *string `json:"change_event_id,omitempty"`
	TriggerKind   string  `json:"trigger_kind"`
	FromVersion   *int    `json:"from_version,omitempty"`
	ToVersion     *int    `json:"to_version,omitempty"`
	Status        string  `json:"status"`
	Reason        string  `json:"reason,omitempty"`
	Error         string  `json:"error,omitempty"`
	StartedAt     *string `json:"started_at,omitempty"`
	FinishedAt    *string `json:"finished_at,omitempty"`
	CreatedAt     string  `json:"created_at"`
}

// RollbackExecutionPage is the paginated /executions response.
type RollbackExecutionPage struct {
	Entries []RollbackExecutionResponse `json:"entries"`
	Total   int                         `json:"total"`
	Limit   int                         `json:"limit"`
	Offset  int                         `json:"offset"`
}

// RollbackAuditResponse is the API view of an audit row.
type RollbackAuditResponse struct {
	ID          string  `json:"id"`
	PolicyID    *string `json:"policy_id,omitempty"`
	ExecutionID *string `json:"execution_id,omitempty"`
	StackID     *string `json:"stack_id,omitempty"`
	ActorID     *string `json:"actor_id,omitempty"`
	Action      string  `json:"action"`
	Details     string  `json:"details,omitempty"`
	CreatedAt   string  `json:"created_at"`
}

// RollbackAuditPage is the paginated /audit response.
type RollbackAuditPage struct {
	Entries []RollbackAuditResponse `json:"entries"`
	Total   int                     `json:"total"`
	Limit   int                     `json:"limit"`
	Offset  int                     `json:"offset"`
}

// RollbackDryRunResponse is the API view of a dry-run preview.
type RollbackDryRunResponse struct {
	Matched       bool    `json:"matched"`
	PolicyID      string  `json:"policy_id"`
	StackID       *string `json:"stack_id,omitempty"`
	StackName     string  `json:"stack_name,omitempty"`
	FromVersion   *int    `json:"from_version,omitempty"`
	ToVersion     *int    `json:"to_version,omitempty"`
	Strategy      string  `json:"strategy"`
	WouldExecute  bool    `json:"would_execute"`
	SkipReason    string  `json:"skip_reason,omitempty"`
	PolicyEnabled bool    `json:"policy_enabled"`
	PolicyDryRun  bool    `json:"policy_dry_run"`
	Reason        string  `json:"reason,omitempty"`
	NextStatus    string  `json:"next_status"`
}

// ============================================================================
// Handlers
// ============================================================================

// ListPolicies handles GET /api/v1/rollback/policies.
func (h *RollbackHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	policies, err := h.svc.ListPolicies(r.Context())
	if err != nil {
		h.HandleError(w, mapRollbackError(err))
		return
	}
	resp := make([]RollbackPolicyResponse, len(policies))
	for i := range policies {
		resp[i] = toRollbackPolicyResponse(&policies[i])
	}
	h.OK(w, resp)
}

// GetPolicy handles GET /api/v1/rollback/policies/{id}.
func (h *RollbackHandler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	p, err := h.svc.GetPolicy(r.Context(), id)
	if err != nil {
		h.HandleError(w, mapRollbackError(err))
		return
	}
	h.OK(w, toRollbackPolicyResponse(p))
}

// CreatePolicy handles POST /api/v1/rollback/policies.
func (h *RollbackHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	var req CreateRollbackPolicyRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	in, err := req.toModelCreateInput()
	if err != nil {
		h.HandleError(w, err)
		return
	}
	actor, _ := h.GetUserID(r)
	p, err := h.svc.CreatePolicy(r.Context(), in, nilableUUID(actor))
	if err != nil {
		h.HandleError(w, mapRollbackError(err))
		return
	}
	h.Created(w, toRollbackPolicyResponse(p))
}

// UpdatePolicy handles PUT /api/v1/rollback/policies/{id}.
func (h *RollbackHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	var req UpdateRollbackPolicyRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	in, err := req.toModelUpdateInput()
	if err != nil {
		h.HandleError(w, err)
		return
	}
	actor, _ := h.GetUserID(r)
	p, err := h.svc.UpdatePolicy(r.Context(), id, in, nilableUUID(actor))
	if err != nil {
		h.HandleError(w, mapRollbackError(err))
		return
	}
	h.OK(w, toRollbackPolicyResponse(p))
}

// DeletePolicy handles DELETE /api/v1/rollback/policies/{id}.
func (h *RollbackHandler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
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
	if err := h.svc.DeletePolicy(r.Context(), id, nilableUUID(actor)); err != nil {
		h.HandleError(w, mapRollbackError(err))
		return
	}
	h.NoContent(w)
}

// DryRun handles POST /api/v1/rollback/policies/{id}/dry-run.
func (h *RollbackHandler) DryRun(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	var req DryRunRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	stackID, err := uuid.Parse(req.StackID)
	if err != nil {
		h.HandleError(w, apierrors.InvalidInput("invalid stack_id"))
		return
	}
	actor, _ := h.GetUserID(r)
	result, err := h.svc.DryRun(r.Context(), id, stackID, nilableUUID(actor))
	if err != nil {
		h.HandleError(w, mapRollbackError(err))
		return
	}
	h.OK(w, toRollbackDryRunResponse(result))
}

// ListExecutions handles GET /api/v1/rollback/executions.
func (h *RollbackHandler) ListExecutions(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	pagination := h.GetPagination(r)
	opts := models.RollbackExecutionListOptions{
		Limit:  pagination.PerPage,
		Offset: pagination.Offset,
	}
	if q := h.QueryParam(r, "policy_id"); q != "" {
		id, err := uuid.Parse(q)
		if err != nil {
			h.HandleError(w, apierrors.InvalidInput("invalid policy_id"))
			return
		}
		opts.PolicyID = &id
	}
	if q := h.QueryParam(r, "stack_id"); q != "" {
		id, err := uuid.Parse(q)
		if err != nil {
			h.HandleError(w, apierrors.InvalidInput("invalid stack_id"))
			return
		}
		opts.StackID = &id
	}
	if q := h.QueryParam(r, "status"); q != "" {
		opts.Status = models.RollbackExecutionStatus(q)
	}

	executions, total, err := h.svc.ListExecutions(r.Context(), opts)
	if err != nil {
		h.HandleError(w, mapRollbackError(err))
		return
	}
	resp := make([]RollbackExecutionResponse, len(executions))
	for i := range executions {
		resp[i] = toRollbackExecutionResponse(&executions[i])
	}
	h.OK(w, RollbackExecutionPage{
		Entries: resp,
		Total:   total,
		Limit:   pagination.PerPage,
		Offset:  pagination.Offset,
	})
}

// GetExecution handles GET /api/v1/rollback/executions/{id}.
func (h *RollbackHandler) GetExecution(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	e, err := h.svc.GetExecution(r.Context(), id)
	if err != nil {
		h.HandleError(w, mapRollbackError(err))
		return
	}
	h.OK(w, toRollbackExecutionResponse(e))
}

// ListAudit handles GET /api/v1/rollback/audit.
func (h *RollbackHandler) ListAudit(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	pagination := h.GetPagination(r)
	var policyID, stackID uuid.UUID
	if q := h.QueryParam(r, "policy_id"); q != "" {
		id, err := uuid.Parse(q)
		if err != nil {
			h.HandleError(w, apierrors.InvalidInput("invalid policy_id"))
			return
		}
		policyID = id
	}
	if q := h.QueryParam(r, "stack_id"); q != "" {
		id, err := uuid.Parse(q)
		if err != nil {
			h.HandleError(w, apierrors.InvalidInput("invalid stack_id"))
			return
		}
		stackID = id
	}
	entries, total, err := h.svc.ListAudit(r.Context(), policyID, stackID, pagination.PerPage, pagination.Offset)
	if err != nil {
		h.HandleError(w, mapRollbackError(err))
		return
	}
	resp := make([]RollbackAuditResponse, len(entries))
	for i := range entries {
		resp[i] = toRollbackAuditResponse(&entries[i])
	}
	h.OK(w, RollbackAuditPage{
		Entries: resp,
		Total:   total,
		Limit:   pagination.PerPage,
		Offset:  pagination.Offset,
	})
}

// ============================================================================
// Helpers
// ============================================================================

func (h *RollbackHandler) serviceUnavailable(w http.ResponseWriter) {
	apierrors.WriteError(w, apierrors.ServiceUnavailable("rollback service is not configured"))
}

// mapRollbackError converts package-level rollback errors to typed
// APIErrors. Anything not recognized is passed through to BaseHandler.
func mapRollbackError(err error) error {
	switch {
	case errors.Is(err, rollbacksvc.ErrInvalidInput):
		return apierrors.InvalidInput(err.Error())
	case errors.Is(err, rollbacksvc.ErrStackBusy):
		return apierrors.Conflict("stack is already being rolled back")
	case errors.Is(err, rollbacksvc.ErrNoLastKnownGood):
		return apierrors.InvalidInput(err.Error())
	case errors.Is(err, rollbacksvc.ErrStackNotFound):
		return apierrors.NotFound("stack")
	}
	return err
}

func (req CreateRollbackPolicyRequest) toModelCreateInput() (models.CreateRollbackPolicyInput, error) {
	in := models.CreateRollbackPolicyInput{
		Name:             req.Name,
		Description:      req.Description,
		Enabled:          req.Enabled,
		Scope:            models.RollbackScope(req.Scope),
		ScopeValue:       req.ScopeValue,
		TriggerKind:      models.RollbackTriggerKind(req.TriggerKind),
		FailureThreshold: req.FailureThreshold,
		WindowSeconds:    req.WindowSeconds,
		LastGoodStrategy: models.RollbackStrategy(req.LastGoodStrategy),
		CooldownSeconds:  req.CooldownSeconds,
		DryRun:           req.DryRun,
	}
	if req.ScopeStackID != "" {
		id, err := uuid.Parse(req.ScopeStackID)
		if err != nil {
			return in, apierrors.InvalidInput("invalid scope_stack_id")
		}
		in.ScopeStackID = &id
	}
	return in, nil
}

func (req UpdateRollbackPolicyRequest) toModelUpdateInput() (models.UpdateRollbackPolicyInput, error) {
	in := models.UpdateRollbackPolicyInput{
		Name:             req.Name,
		Description:      req.Description,
		Enabled:          req.Enabled,
		ScopeValue:       req.ScopeValue,
		FailureThreshold: req.FailureThreshold,
		WindowSeconds:    req.WindowSeconds,
		CooldownSeconds:  req.CooldownSeconds,
		DryRun:           req.DryRun,
	}
	if req.Scope != nil {
		s := models.RollbackScope(*req.Scope)
		in.Scope = &s
	}
	if req.TriggerKind != nil {
		t := models.RollbackTriggerKind(*req.TriggerKind)
		in.TriggerKind = &t
	}
	if req.LastGoodStrategy != nil {
		st := models.RollbackStrategy(*req.LastGoodStrategy)
		in.LastGoodStrategy = &st
	}
	if req.ScopeStackID != nil && *req.ScopeStackID != "" {
		id, err := uuid.Parse(*req.ScopeStackID)
		if err != nil {
			return in, apierrors.InvalidInput("invalid scope_stack_id")
		}
		in.ScopeStackID = &id
	}
	return in, nil
}

func toRollbackPolicyResponse(p *models.RollbackPolicy) RollbackPolicyResponse {
	resp := RollbackPolicyResponse{
		ID:               p.ID.String(),
		Name:             p.Name,
		Description:      p.Description,
		Enabled:          p.Enabled,
		Scope:            string(p.Scope),
		ScopeValue:       p.ScopeValue,
		TriggerKind:      string(p.TriggerKind),
		FailureThreshold: p.FailureThreshold,
		WindowSeconds:    p.WindowSeconds,
		LastGoodStrategy: string(p.LastGoodStrategy),
		CooldownSeconds:  p.CooldownSeconds,
		DryRun:           p.DryRun,
		CreatedAt:        p.CreatedAt.Format(time.RFC3339),
		UpdatedAt:        p.UpdatedAt.Format(time.RFC3339),
	}
	if p.ScopeStackID != nil {
		s := p.ScopeStackID.String()
		resp.ScopeStackID = &s
	}
	if p.CreatedBy != nil {
		s := p.CreatedBy.String()
		resp.CreatedBy = &s
	}
	return resp
}

func toRollbackExecutionResponse(e *models.RollbackExecution) RollbackExecutionResponse {
	resp := RollbackExecutionResponse{
		ID:          e.ID.String(),
		PolicyID:    e.PolicyID.String(),
		StackID:     e.StackID.String(),
		TriggerKind: string(e.TriggerKind),
		FromVersion: e.FromVersion,
		ToVersion:   e.ToVersion,
		Status:      string(e.Status),
		Reason:      e.Reason,
		Error:       e.Error,
		CreatedAt:   e.CreatedAt.Format(time.RFC3339),
	}
	if e.ChangeEventID != nil {
		s := e.ChangeEventID.String()
		resp.ChangeEventID = &s
	}
	if e.StartedAt != nil {
		s := e.StartedAt.Format(time.RFC3339)
		resp.StartedAt = &s
	}
	if e.FinishedAt != nil {
		s := e.FinishedAt.Format(time.RFC3339)
		resp.FinishedAt = &s
	}
	return resp
}

func toRollbackAuditResponse(e *models.RollbackAuditEntry) RollbackAuditResponse {
	resp := RollbackAuditResponse{
		ID:        e.ID.String(),
		Action:    e.Action,
		Details:   e.Details,
		CreatedAt: e.CreatedAt.Format(time.RFC3339),
	}
	if e.PolicyID != nil {
		s := e.PolicyID.String()
		resp.PolicyID = &s
	}
	if e.ExecutionID != nil {
		s := e.ExecutionID.String()
		resp.ExecutionID = &s
	}
	if e.StackID != nil {
		s := e.StackID.String()
		resp.StackID = &s
	}
	if e.ActorID != nil {
		s := e.ActorID.String()
		resp.ActorID = &s
	}
	return resp
}

func toRollbackDryRunResponse(r *models.RollbackDryRunResult) RollbackDryRunResponse {
	resp := RollbackDryRunResponse{
		Matched:       r.Matched,
		PolicyID:      r.PolicyID.String(),
		StackName:     r.StackName,
		FromVersion:   r.FromVersion,
		ToVersion:     r.ToVersion,
		Strategy:      string(r.Strategy),
		WouldExecute:  r.WouldExecute,
		SkipReason:    r.SkipReason,
		PolicyEnabled: r.PolicyEnabled,
		PolicyDryRun:  r.PolicyDryRun,
		Reason:        r.Reason,
		NextStatus:    string(r.NextStatus),
	}
	if r.StackID != nil {
		s := r.StackID.String()
		resp.StackID = &s
	}
	return resp
}
