// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	rollbacksvc "github.com/fr4nsys/usulnet/internal/services/rollback"
	rollbacktpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/rollback"
)

// requireRollbackSvc returns the rollback service or renders a
// "not configured" error.
func (h *Handler) requireRollbackSvc(w http.ResponseWriter, r *http.Request) *rollbacksvc.Service {
	if reg, ok := h.services.(*ServiceRegistry); ok && reg.rollbackSvc != nil {
		return reg.rollbackSvc
	}
	h.RenderErrorTempl(w, r, http.StatusServiceUnavailable,
		"Rollback Not Configured",
		"The automated rollback module is not enabled in this build.")
	return nil
}

func (h *Handler) rollbackUserUUID(r *http.Request) *uuid.UUID {
	user := h.getUserData(r)
	if user == nil || user.ID == "" {
		return nil
	}
	id, err := uuid.Parse(user.ID)
	if err != nil {
		return nil
	}
	return &id
}

// rollbackStackOptions reads available stacks so the policy editor can
// offer a dropdown. The list is limited; we accept the standalone-mode
// default-host behavior and let the handler keep working in master mode
// (the form is a substring filter anyway).
func (h *Handler) rollbackStackOptions(ctx context.Context, r *http.Request) []rollbacktpl.StackOption {
	if h.services == nil {
		return nil
	}
	reg, ok := h.services.(*ServiceRegistry)
	if !ok || reg.stackSvc == nil {
		return nil
	}
	stacks, _, err := reg.stackSvc.List(ctx, postgres.StackListOptions{PerPage: 200, Page: 1})
	if err != nil {
		h.logger.Warn("rollback: list stacks failed", "error", err)
		return nil
	}
	opts := make([]rollbacktpl.StackOption, 0, len(stacks))
	for _, s := range stacks {
		opts = append(opts, rollbacktpl.StackOption{
			ID:   s.ID.String(),
			Name: s.Name,
		})
	}
	return opts
}

// rollbackPolicyView projects models.RollbackPolicy onto the templ-side
// PolicyView. The (optional) stack name is resolved through the stack
// service when scope is "stack".
func (h *Handler) rollbackPolicyView(ctx context.Context, p *models.RollbackPolicy) rollbacktpl.PolicyView {
	v := rollbacktpl.PolicyView{
		ID:               p.ID.String(),
		Name:             p.Name,
		Description:      p.Description,
		Enabled:          p.Enabled,
		Scope:            string(p.Scope),
		ScopeValue:       p.ScopeValue,
		TriggerKind:      string(p.TriggerKind),
		LastGoodStrategy: string(p.LastGoodStrategy),
		CooldownSeconds:  p.CooldownSeconds,
		DryRun:           p.DryRun,
		CreatedAt:        p.CreatedAt.Format("2006-01-02 15:04"),
	}
	if p.ScopeStackID != nil {
		v.ScopeStackID = p.ScopeStackID.String()
		if reg, ok := h.services.(*ServiceRegistry); ok && reg.stackSvc != nil {
			if stack, err := reg.stackSvc.Get(ctx, *p.ScopeStackID); err == nil && stack != nil {
				v.ScopeStackName = stack.Name
			}
		}
	}
	return v
}

// rollbackExecutionView projects an execution row with policy and stack
// names filled in. Service look-ups are best-effort; a missing stack
// (e.g. deleted after the execution) falls back to the ID string.
func (h *Handler) rollbackExecutionView(ctx context.Context, e *models.RollbackExecution) rollbacktpl.ExecutionView {
	v := rollbacktpl.ExecutionView{
		ID:          e.ID.String(),
		PolicyID:    e.PolicyID.String(),
		StackID:     e.StackID.String(),
		TriggerKind: string(e.TriggerKind),
		Status:      string(e.Status),
		Reason:      e.Reason,
		Error:       e.Error,
		CreatedAt:   e.CreatedAt.Format("2006-01-02 15:04:05"),
	}
	if e.FromVersion != nil {
		v.FromVersion = strconv.Itoa(*e.FromVersion)
	}
	if e.ToVersion != nil {
		v.ToVersion = strconv.Itoa(*e.ToVersion)
	}
	if e.StartedAt != nil {
		v.StartedAt = e.StartedAt.Format("2006-01-02 15:04:05")
	}
	if e.FinishedAt != nil {
		v.FinishedAt = e.FinishedAt.Format("2006-01-02 15:04:05")
	}
	if reg, ok := h.services.(*ServiceRegistry); ok {
		if reg.rollbackSvc != nil {
			if p, err := reg.rollbackSvc.GetPolicy(ctx, e.PolicyID); err == nil {
				v.PolicyName = p.Name
			}
		}
		if reg.stackSvc != nil {
			if stack, err := reg.stackSvc.Get(ctx, e.StackID); err == nil {
				v.StackName = stack.Name
			}
		}
	}
	return v
}

// ============================================================================
// List
// ============================================================================

// RollbackListTempl renders the policy list page.
func (h *Handler) RollbackListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireRollbackSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Automated Rollback", "rollback")

	policies, err := svc.ListPolicies(ctx)
	if err != nil {
		h.renderTempl(w, r, rollbacktpl.List(rollbacktpl.ListData{
			PageData:   pageData,
			Error:      "Failed to load policies: " + err.Error(),
			EmptyState: EmptyStateCatalogRollback(),
		}))
		return
	}

	views := make([]rollbacktpl.PolicyView, 0, len(policies))
	var stats rollbacktpl.StatsView
	for i := range policies {
		views = append(views, h.rollbackPolicyView(ctx, &policies[i]))
		stats.Total++
		if policies[i].Enabled {
			stats.Enabled++
		}
		if policies[i].DryRun {
			stats.DryRun++
		}
	}

	h.renderTempl(w, r, rollbacktpl.List(rollbacktpl.ListData{
		PageData:   pageData,
		Policies:   views,
		Stats:      stats,
		EmptyState: EmptyStateCatalogRollback(),
	}))
}

// ============================================================================
// New / Create
// ============================================================================

// RollbackNewTempl renders the new-policy form.
func (h *Handler) RollbackNewTempl(w http.ResponseWriter, r *http.Request) {
	if svc := h.requireRollbackSvc(w, r); svc == nil {
		return
	}
	pageData := h.prepareTemplPageData(r, "New Rollback Policy", "rollback")
	h.renderTempl(w, r, rollbacktpl.New(rollbacktpl.NewData{
		PageData: pageData,
		Form: rollbacktpl.FormData{
			Action:    "/rollback",
			Method:    "POST",
			CSRFToken: pageData.CSRFToken,
			IsEdit:    false,
			Policy: rollbacktpl.PolicyView{
				Scope:            "all",
				TriggerKind:      "deploy_failed",
				LastGoodStrategy: "last_healthy",
				CooldownSeconds:  300,
				Enabled:          true,
			},
			Stacks: h.rollbackStackOptions(r.Context(), r),
		},
	}))
}

// RollbackCreateTempl handles POST /rollback.
func (h *Handler) RollbackCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireRollbackSvc(w, r)
	if svc == nil {
		return
	}
	in, parseErr := h.parseRollbackPolicyForm(r)
	if parseErr != nil {
		h.renderPolicyFormWithError(w, r, "New Rollback Policy", in, parseErr.Error(), false, "")
		return
	}
	actor := h.rollbackUserUUID(r)
	if _, err := svc.CreatePolicy(r.Context(), in, actor); err != nil {
		h.renderPolicyFormWithError(w, r, "New Rollback Policy", in, err.Error(), false, "")
		return
	}
	http.Redirect(w, r, "/rollback", http.StatusSeeOther)
}

// ============================================================================
// Detail
// ============================================================================

// RollbackDetailTempl renders a single policy view.
func (h *Handler) RollbackDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireRollbackSvc(w, r)
	if svc == nil {
		return
	}
	policyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The policy ID is not valid.")
		return
	}
	p, err := svc.GetPolicy(r.Context(), policyID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "The requested rollback policy was not found.")
		return
	}

	executions, _, _ := svc.ListExecutions(r.Context(), models.RollbackExecutionListOptions{
		PolicyID: &policyID,
		Limit:    10,
	})
	views := make([]rollbacktpl.ExecutionView, 0, len(executions))
	for i := range executions {
		views = append(views, h.rollbackExecutionView(r.Context(), &executions[i]))
	}

	pageData := h.prepareTemplPageData(r, p.Name, "rollback")
	h.renderTempl(w, r, rollbacktpl.Detail(rollbacktpl.DetailData{
		PageData:         pageData,
		Policy:           h.rollbackPolicyView(r.Context(), p),
		RecentExecutions: views,
		CSRFToken:        pageData.CSRFToken,
	}))
}

// ============================================================================
// Edit / Update
// ============================================================================

// RollbackEditTempl renders the edit form.
func (h *Handler) RollbackEditTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireRollbackSvc(w, r)
	if svc == nil {
		return
	}
	policyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The policy ID is not valid.")
		return
	}
	p, err := svc.GetPolicy(r.Context(), policyID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "The requested rollback policy was not found.")
		return
	}
	pageData := h.prepareTemplPageData(r, "Edit "+p.Name, "rollback")
	h.renderTempl(w, r, rollbacktpl.Edit(rollbacktpl.EditData{
		PageData: pageData,
		Form: rollbacktpl.FormData{
			Action:    "/rollback/" + p.ID.String() + "/update",
			Method:    "POST",
			CSRFToken: pageData.CSRFToken,
			IsEdit:    true,
			Policy:    h.rollbackPolicyView(r.Context(), p),
			Stacks:    h.rollbackStackOptions(r.Context(), r),
		},
	}))
}

// RollbackUpdateTempl handles POST /rollback/{id}/update.
func (h *Handler) RollbackUpdateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireRollbackSvc(w, r)
	if svc == nil {
		return
	}
	policyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The policy ID is not valid.")
		return
	}
	in, parseErr := h.parseRollbackPolicyForm(r)
	if parseErr != nil {
		h.renderPolicyFormWithError(w, r, "Edit policy", in, parseErr.Error(), true, policyID.String())
		return
	}

	// Convert create-input to update-input — every field is supplied.
	upd := models.UpdateRollbackPolicyInput{
		Name:             strPtr(in.Name),
		Description:      strPtr(in.Description),
		Enabled:          boolPtr(in.Enabled),
		Scope:            scopePtr(in.Scope),
		ScopeStackID:     in.ScopeStackID,
		ScopeValue:       strPtr(in.ScopeValue),
		TriggerKind:      triggerPtr(in.TriggerKind),
		FailureThreshold: in.FailureThreshold,
		WindowSeconds:    in.WindowSeconds,
		LastGoodStrategy: strategyPtr(in.LastGoodStrategy),
		CooldownSeconds:  intPtr(in.CooldownSeconds),
		DryRun:           boolPtr(in.DryRun),
	}
	actor := h.rollbackUserUUID(r)
	if _, err := svc.UpdatePolicy(r.Context(), policyID, upd, actor); err != nil {
		h.renderPolicyFormWithError(w, r, "Edit policy", in, err.Error(), true, policyID.String())
		return
	}
	http.Redirect(w, r, "/rollback/"+policyID.String(), http.StatusSeeOther)
}

// ============================================================================
// Delete
// ============================================================================

// RollbackDeleteTempl handles POST /rollback/{id}/delete.
func (h *Handler) RollbackDeleteTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireRollbackSvc(w, r)
	if svc == nil {
		return
	}
	policyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}
	actor := h.rollbackUserUUID(r)
	if err := svc.DeletePolicy(r.Context(), policyID, actor); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Delete failed", err.Error())
		return
	}
	http.Redirect(w, r, "/rollback", http.StatusSeeOther)
}

// ============================================================================
// Dry-run
// ============================================================================

// RollbackDryRunGetTempl renders the dry-run form.
func (h *Handler) RollbackDryRunGetTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireRollbackSvc(w, r)
	if svc == nil {
		return
	}
	policyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The policy ID is not valid.")
		return
	}
	p, err := svc.GetPolicy(r.Context(), policyID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "The requested rollback policy was not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Dry-run: "+p.Name, "rollback")
	h.renderTempl(w, r, rollbacktpl.DryRun(rollbacktpl.DryRunData{
		PageData:  pageData,
		Policy:    h.rollbackPolicyView(r.Context(), p),
		Stacks:    h.rollbackStackOptions(r.Context(), r),
		CSRFToken: pageData.CSRFToken,
	}))
}

// RollbackDryRunPostTempl handles POST /rollback/{id}/dry-run — runs
// the preview and renders the result inline.
func (h *Handler) RollbackDryRunPostTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireRollbackSvc(w, r)
	if svc == nil {
		return
	}
	policyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The policy ID is not valid.")
		return
	}
	var dryRunForm struct {
		StackID string `form:"stack_id" validate:"required,uuid"`
	}
	bindMsg := BindForm(r, &dryRunForm)
	p, err := svc.GetPolicy(r.Context(), policyID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "The requested rollback policy was not found.")
		return
	}
	pageData := h.prepareTemplPageData(r, "Dry-run: "+p.Name, "rollback")
	data := rollbacktpl.DryRunData{
		PageData:  pageData,
		Policy:    h.rollbackPolicyView(r.Context(), p),
		Stacks:    h.rollbackStackOptions(r.Context(), r),
		CSRFToken: pageData.CSRFToken,
	}
	if bindMsg != "" {
		data.Error = bindMsg
		h.renderTempl(w, r, rollbacktpl.DryRun(data))
		return
	}
	// Validator already confirmed the UUID shape; parse cannot fail.
	stackID, _ := uuid.Parse(dryRunForm.StackID)
	data.StackID = dryRunForm.StackID

	result, err := svc.DryRun(r.Context(), policyID, stackID, h.rollbackUserUUID(r))
	if err != nil {
		data.Error = err.Error()
		h.renderTempl(w, r, rollbacktpl.DryRun(data))
		return
	}
	view := &rollbacktpl.DryRunResultView{
		Matched:       result.Matched,
		StackName:     result.StackName,
		Strategy:      string(result.Strategy),
		WouldExecute:  result.WouldExecute,
		SkipReason:    result.SkipReason,
		PolicyEnabled: result.PolicyEnabled,
		PolicyDryRun:  result.PolicyDryRun,
		Reason:        result.Reason,
		NextStatus:    string(result.NextStatus),
	}
	if result.StackID != nil {
		view.StackID = result.StackID.String()
	}
	if result.FromVersion != nil {
		view.FromVersion = strconv.Itoa(*result.FromVersion)
	}
	if result.ToVersion != nil {
		view.ToVersion = strconv.Itoa(*result.ToVersion)
	}
	data.Result = view
	h.renderTempl(w, r, rollbacktpl.DryRun(data))
}

// ============================================================================
// Executions list + detail
// ============================================================================

// RollbackExecutionsTempl renders the execution log.
func (h *Handler) RollbackExecutionsTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireRollbackSvc(w, r)
	if svc == nil {
		return
	}
	const pageSize = 50
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	offset := (page - 1) * pageSize
	executions, total, err := svc.ListExecutions(r.Context(), models.RollbackExecutionListOptions{
		Limit:  pageSize,
		Offset: offset,
	})
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load executions: "+err.Error())
		return
	}
	views := make([]rollbacktpl.ExecutionView, 0, len(executions))
	for i := range executions {
		views = append(views, h.rollbackExecutionView(r.Context(), &executions[i]))
	}
	pageData := h.prepareTemplPageData(r, "Rollback executions", "rollback")
	h.renderTempl(w, r, rollbacktpl.ExecutionsList(rollbacktpl.ExecutionsListData{
		PageData:   pageData,
		Executions: views,
		Total:      total,
		Limit:      pageSize,
		Offset:     offset,
	}))
}

// RollbackExecutionDetailTempl renders a single execution row.
func (h *Handler) RollbackExecutionDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireRollbackSvc(w, r)
	if svc == nil {
		return
	}
	execID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The execution ID is not valid.")
		return
	}
	e, err := svc.GetExecution(r.Context(), execID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "The execution was not found.")
		return
	}
	pageData := h.prepareTemplPageData(r, "Execution "+execID.String()[:8], "rollback")
	h.renderTempl(w, r, rollbacktpl.ExecutionDetail(rollbacktpl.ExecutionDetailData{
		PageData:  pageData,
		Execution: h.rollbackExecutionView(r.Context(), e),
	}))
}

// ============================================================================
// Audit log
// ============================================================================

// RollbackAuditTempl renders the audit log.
func (h *Handler) RollbackAuditTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireRollbackSvc(w, r)
	if svc == nil {
		return
	}
	const pageSize = 100
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	offset := (page - 1) * pageSize
	entries, total, err := svc.ListAudit(r.Context(), uuid.Nil, uuid.Nil, pageSize, offset)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load audit log: "+err.Error())
		return
	}
	views := make([]rollbacktpl.AuditView, 0, len(entries))
	for i := range entries {
		views = append(views, h.rollbackAuditView(r.Context(), &entries[i]))
	}
	pageData := h.prepareTemplPageData(r, "Rollback audit log", "rollback")
	h.renderTempl(w, r, rollbacktpl.Audit(rollbacktpl.AuditData{
		PageData: pageData,
		Entries:  views,
		Total:    total,
		Limit:    pageSize,
		Offset:   offset,
	}))
}

// rollbackAuditView projects an audit row with policy / stack names
// resolved where possible.
func (h *Handler) rollbackAuditView(ctx context.Context, e *models.RollbackAuditEntry) rollbacktpl.AuditView {
	v := rollbacktpl.AuditView{
		ID:        e.ID.String(),
		Action:    e.Action,
		Details:   e.Details,
		CreatedAt: e.CreatedAt.Format("2006-01-02 15:04:05"),
	}
	if e.ActorID != nil {
		v.Actor = e.ActorID.String()
	}
	reg, ok := h.services.(*ServiceRegistry)
	if !ok {
		return v
	}
	if e.PolicyID != nil && reg.rollbackSvc != nil {
		if p, err := reg.rollbackSvc.GetPolicy(ctx, *e.PolicyID); err == nil {
			v.Policy = p.Name
		}
	}
	if e.StackID != nil && reg.stackSvc != nil {
		if stack, err := reg.stackSvc.Get(ctx, *e.StackID); err == nil {
			v.Stack = stack.Name
		}
	}
	return v
}

// ============================================================================
// Form parsing
// ============================================================================

// rollbackPolicyForm captures the rollback policy inputs. The
// three threshold-style numerics are plain ints — 0 is treated as
// "absent" because the underlying CreateInput uses *int to express
// optionality and 0 is never a valid sentinel (failure_threshold /
// window_seconds must be >0; cooldown_seconds is always-present
// with a 0-default).
type rollbackPolicyForm struct {
	Name             string `form:"name" validate:"required"`
	Description      string `form:"description"`
	Enabled          bool   `form:"enabled"`
	Scope            string `form:"scope"`
	ScopeStackID     string `form:"scope_stack_id" validate:"omitempty,uuid"`
	ScopeValue       string `form:"scope_value"`
	TriggerKind      string `form:"trigger_kind"`
	FailureThreshold int    `form:"failure_threshold" validate:"gte=0"`
	WindowSeconds    int    `form:"window_seconds" validate:"gte=0"`
	LastGoodStrategy string `form:"last_good_strategy"`
	CooldownSeconds  int    `form:"cooldown_seconds" validate:"gte=0"`
	DryRun           bool   `form:"dry_run"`
}

func (h *Handler) parseRollbackPolicyForm(r *http.Request) (models.CreateRollbackPolicyInput, error) {
	var form rollbackPolicyForm
	if msg := BindForm(r, &form); msg != "" {
		return models.CreateRollbackPolicyInput{}, errInvalidField(msg)
	}
	in := models.CreateRollbackPolicyInput{
		Name:             form.Name,
		Description:      form.Description,
		Enabled:          form.Enabled,
		Scope:            models.RollbackScope(form.Scope),
		ScopeValue:       form.ScopeValue,
		TriggerKind:      models.RollbackTriggerKind(form.TriggerKind),
		LastGoodStrategy: models.RollbackStrategy(form.LastGoodStrategy),
		DryRun:           form.DryRun,
		CooldownSeconds:  form.CooldownSeconds,
	}
	if form.ScopeStackID != "" {
		// Validator already confirmed the UUID shape; parse cannot fail.
		id, _ := uuid.Parse(form.ScopeStackID)
		in.ScopeStackID = &id
	}
	if form.FailureThreshold > 0 {
		v := form.FailureThreshold
		in.FailureThreshold = &v
	}
	if form.WindowSeconds > 0 {
		v := form.WindowSeconds
		in.WindowSeconds = &v
	}
	return in, nil
}

type rollbackFormError string

func (e rollbackFormError) Error() string { return string(e) }

func errInvalidField(msg string) error { return rollbackFormError(msg) }

func (h *Handler) renderPolicyFormWithError(w http.ResponseWriter, r *http.Request, title string, in models.CreateRollbackPolicyInput, errMsg string, isEdit bool, policyID string) {
	pageData := h.prepareTemplPageData(r, title, "rollback")
	view := rollbacktpl.PolicyView{
		ID:               policyID,
		Name:             in.Name,
		Description:      in.Description,
		Enabled:          in.Enabled,
		Scope:            string(in.Scope),
		ScopeValue:       in.ScopeValue,
		TriggerKind:      string(in.TriggerKind),
		LastGoodStrategy: string(in.LastGoodStrategy),
		CooldownSeconds:  in.CooldownSeconds,
		DryRun:           in.DryRun,
	}
	if in.ScopeStackID != nil {
		view.ScopeStackID = in.ScopeStackID.String()
	}
	form := rollbacktpl.FormData{
		Action:     "/rollback",
		Method:     "POST",
		CSRFToken:  pageData.CSRFToken,
		IsEdit:     isEdit,
		Policy:     view,
		Stacks:     h.rollbackStackOptions(r.Context(), r),
		FieldError: errMsg,
	}
	if isEdit && policyID != "" {
		form.Action = "/rollback/" + policyID + "/update"
		h.renderTempl(w, r, rollbacktpl.Edit(rollbacktpl.EditData{PageData: pageData, Form: form}))
		return
	}
	h.renderTempl(w, r, rollbacktpl.New(rollbacktpl.NewData{PageData: pageData, Form: form}))
}

// ============================================================================
// Tiny pointer helpers used by the update path. strPtr and boolPtr live
// in handler_connections_ext.go — we reuse them here.
// ============================================================================

func intPtr(n int) *int { v := n; return &v }
func scopePtr(s models.RollbackScope) *models.RollbackScope {
	v := s
	return &v
}
func triggerPtr(t models.RollbackTriggerKind) *models.RollbackTriggerKind {
	v := t
	return &v
}
func strategyPtr(s models.RollbackStrategy) *models.RollbackStrategy {
	v := s
	return &v
}
