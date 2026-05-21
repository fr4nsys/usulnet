// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	egresssvc "github.com/fr4nsys/usulnet/internal/services/egress"
	egresstpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/egress"
)

// requireEgressSvc returns the egress service or renders a "not
// configured" error. Same nil-safe pattern as requireFirewallSvc.
func (h *Handler) requireEgressSvc(w http.ResponseWriter, r *http.Request) *egresssvc.Service {
	if reg, ok := h.services.(*ServiceRegistry); ok && reg.egressSvc != nil {
		return reg.egressSvc
	}
	h.RenderErrorTempl(w, r, http.StatusServiceUnavailable,
		"Egress Filter Not Configured",
		"The L7 egress filtering service is not enabled in this build.")
	return nil
}

// getEgressHostID resolves the active host UUID for egress operations.
// Standalone mode has exactly one host — the default — so resolveHostID
// is the right call; the proxy listener also enforces that same host id.
func (h *Handler) getEgressHostID(r *http.Request) uuid.UUID {
	if reg, ok := h.services.(*ServiceRegistry); ok {
		return resolveHostID(r.Context(), reg.defaultHostID)
	}
	return uuid.Nil
}

// egressListenAddr returns the configured proxy listener address for
// the info panel. Returns a friendly "(disabled)" marker when the
// listener didn't start — operators can still manage policies via the
// UI; the listener flag is just for enforcement.
func (h *Handler) egressListenAddr() string {
	if reg, ok := h.services.(*ServiceRegistry); ok && reg.egressListenAddr != "" {
		return reg.egressListenAddr
	}
	return "(disabled — set egress_proxy.enabled=true to enforce)"
}

// EgressListTempl renders /egress: policies for the active host plus
// the most-recent denies.
func (h *Handler) EgressListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireEgressSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getEgressHostID(r)
	pageData := h.prepareTemplPageData(r, "L7 Egress Filter", "egress")

	policies, err := svc.ListPolicies(ctx, hostID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError,
			"Error", "Failed to load egress policies: "+err.Error())
		return
	}
	denies, err := svc.RecentDenies(ctx, hostID, 50)
	if err != nil {
		// A failure to read the audit log is non-fatal — render the
		// policies and an empty denies list. The operator can still
		// add and remove rules.
		denies = nil
	}

	policyViews := make([]egresstpl.PolicyView, 0, len(policies))
	for i := range policies {
		policyViews = append(policyViews, egresstpl.PolicyView{
			ID:         policies[i].ID.String(),
			TargetGlob: policies[i].TargetGlob,
			Allow:      policies[i].Allow,
			CreatedAt:  policies[i].CreatedAt.Format("2006-01-02 15:04"),
		})
	}
	denyViews := make([]egresstpl.DenyView, 0, len(denies))
	for i := range denies {
		denyViews = append(denyViews, egresstpl.DenyView{
			Target:    denies[i].Target,
			Method:    methodOrDash(denies[i].Method),
			CreatedAt: denies[i].CreatedAt.Format(time.RFC3339),
		})
	}

	h.renderTempl(w, r, egresstpl.List(egresstpl.ListData{
		PageData:   pageData,
		Policies:   policyViews,
		Denies:     denyViews,
		ListenAddr: h.egressListenAddr(),
		HostID:     hostID.String(),
	}))
}

// EgressCreateTempl handles POST /egress: form submission to add a
// new policy. allow="true" / "false" comes from the <select>.
func (h *Handler) EgressCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireEgressSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	hostID := h.getEgressHostID(r)
	in := models.CreateEgressPolicyInput{
		TargetGlob: r.FormValue("target_glob"),
		Allow:      r.FormValue("allow") == "true",
	}
	if _, err := svc.CreatePolicy(r.Context(), hostID, in); err != nil {
		// Re-render the page with the validation error inline rather
		// than punting to the generic 500 page — operators expect
		// add-policy failures to show up in context.
		h.renderEgressListWithError(w, r, "Failed to create policy: "+err.Error())
		return
	}
	http.Redirect(w, r, "/egress", http.StatusSeeOther)
}

// EgressDeleteTempl handles POST /egress/{id}/delete.
func (h *Handler) EgressDeleteTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireEgressSvc(w, r)
	if svc == nil {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid policy ID", http.StatusBadRequest)
		return
	}
	if err := svc.DeletePolicy(r.Context(), id); err != nil {
		h.renderEgressListWithError(w, r, "Failed to delete policy: "+err.Error())
		return
	}
	http.Redirect(w, r, "/egress", http.StatusSeeOther)
}

// renderEgressListWithError re-renders the list page with an inline
// error banner. Used by the create and delete handlers when the
// underlying service returns an error.
func (h *Handler) renderEgressListWithError(w http.ResponseWriter, r *http.Request, msg string) {
	svc := h.requireEgressSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getEgressHostID(r)
	policies, _ := svc.ListPolicies(ctx, hostID)
	denies, _ := svc.RecentDenies(ctx, hostID, 50)

	policyViews := make([]egresstpl.PolicyView, 0, len(policies))
	for i := range policies {
		policyViews = append(policyViews, egresstpl.PolicyView{
			ID:         policies[i].ID.String(),
			TargetGlob: policies[i].TargetGlob,
			Allow:      policies[i].Allow,
			CreatedAt:  policies[i].CreatedAt.Format("2006-01-02 15:04"),
		})
	}
	denyViews := make([]egresstpl.DenyView, 0, len(denies))
	for i := range denies {
		denyViews = append(denyViews, egresstpl.DenyView{
			Target:    denies[i].Target,
			Method:    methodOrDash(denies[i].Method),
			CreatedAt: denies[i].CreatedAt.Format(time.RFC3339),
		})
	}
	pageData := h.prepareTemplPageData(r, "L7 Egress Filter", "egress")
	h.renderTempl(w, r, egresstpl.List(egresstpl.ListData{
		PageData:   pageData,
		Policies:   policyViews,
		Denies:     denyViews,
		ListenAddr: h.egressListenAddr(),
		HostID:     hostID.String(),
		Error:      msg,
	}))
}

func methodOrDash(m string) string {
	if m == "" {
		return "-"
	}
	return m
}
