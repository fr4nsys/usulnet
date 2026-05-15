// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	firewallsvc "github.com/fr4nsys/usulnet/internal/services/firewall"
	firewalltpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/firewall"
)

// requireFirewallSvc returns the firewall service or renders a
// "not configured" error. Centralized so every handler has the
// identical degradation path when firewall service wiring is missing.
func (h *Handler) requireFirewallSvc(w http.ResponseWriter, r *http.Request) *firewallsvc.Service {
	if reg, ok := h.services.(*ServiceRegistry); ok && reg.firewallSvc != nil {
		return reg.firewallSvc
	}
	h.RenderErrorTempl(w, r, http.StatusServiceUnavailable,
		"Firewall Not Configured",
		"The firewall manager is not enabled in this build.")
	return nil
}

// getFirewallHostID resolves the active host ID for firewall operations.
// Falls back to the default host when no active host is set in context.
func (h *Handler) getFirewallHostID(r *http.Request) uuid.UUID {
	if reg, ok := h.services.(*ServiceRegistry); ok {
		return resolveHostID(r.Context(), reg.defaultHostID)
	}
	return uuid.Nil
}

// firewallUserUUID returns a *uuid.UUID for the requesting user, or nil
// if the session has no authenticated user. Matches the pattern in
// handler_log_management.go so the createdBy column gets populated
// consistently across modules.
func (h *Handler) firewallUserUUID(r *http.Request) *uuid.UUID {
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

func ruleToView(r models.FirewallRule) firewalltpl.RuleView {
	return firewalltpl.RuleView{
		ID:            r.ID.String(),
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
		CreatedAt:     r.CreatedAt.Format("2006-01-02 15:04"),
	}
}

// buildIptablesCmdPreview renders a human-readable iptables command for
// the rule. Purely informational — the agent translates the stored rule
// to its own backend syntax. The comment is shell-escaped to neutralize
// any user-supplied content; this string is rendered into HTML, never
// passed to os/exec.
func buildIptablesCmdPreview(r models.FirewallRule) string {
	cmd := "iptables -A " + string(r.Chain)
	if r.Protocol != "" && r.Protocol != "all" {
		cmd += " -p " + r.Protocol
	}
	if r.Source != "" {
		cmd += " -s " + r.Source
	}
	if r.Destination != "" {
		cmd += " -d " + r.Destination
	}
	if r.InterfaceName != "" {
		cmd += " -i " + r.InterfaceName
	}
	if r.SrcPort != "" && r.Protocol != "icmp" && r.Protocol != "all" {
		cmd += " --sport " + r.SrcPort
	}
	if r.DstPort != "" && r.Protocol != "icmp" && r.Protocol != "all" {
		cmd += " --dport " + r.DstPort
	}
	if r.Comment != "" {
		cmd += " -m comment --comment " + strconv.Quote(r.Comment)
	}
	cmd += " -j " + string(r.Action)
	return cmd
}

// ============================================================================
// List
// ============================================================================

// FirewallListTempl renders the firewall rules list page.
func (h *Handler) FirewallListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireFirewallSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getFirewallHostID(r)
	pageData := h.prepareTemplPageData(r, "Firewall Manager", "firewall")

	rules, err := svc.ListRules(ctx, hostID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError,
			"Error", "Failed to load firewall rules: "+err.Error())
		return
	}

	ruleViews := make([]firewalltpl.RuleView, 0, len(rules))
	var stats firewalltpl.StatsView
	for _, rule := range rules {
		ruleViews = append(ruleViews, ruleToView(rule))
		stats.Total++
		if rule.Enabled {
			stats.Enabled++
		}
		if rule.Applied {
			stats.Applied++
		}
	}

	h.renderTempl(w, r, firewalltpl.List(firewalltpl.ListData{
		PageData: pageData,
		Rules:    ruleViews,
		Stats:    stats,
	}))
}

// ============================================================================
// Create
// ============================================================================

// FirewallNewTempl renders the new firewall rule form.
func (h *Handler) FirewallNewTempl(w http.ResponseWriter, r *http.Request) {
	if svc := h.requireFirewallSvc(w, r); svc == nil {
		return
	}
	pageData := h.prepareTemplPageData(r, "New Firewall Rule", "firewall")
	h.renderTempl(w, r, firewalltpl.New(firewalltpl.NewData{PageData: pageData}))
}

// FirewallCreateTempl handles POST /firewall — creates a new firewall rule.
func (h *Handler) FirewallCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireFirewallSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	hostID := h.getFirewallHostID(r)
	userID := h.firewallUserUUID(r)

	input := models.CreateFirewallRuleInput{
		Name:          r.FormValue("name"),
		Description:   r.FormValue("description"),
		Chain:         models.FirewallChain(r.FormValue("chain")),
		Protocol:      r.FormValue("protocol"),
		Source:        r.FormValue("source"),
		Destination:   r.FormValue("destination"),
		SrcPort:       r.FormValue("src_port"),
		DstPort:       r.FormValue("dst_port"),
		Action:        models.FirewallAction(r.FormValue("action")),
		Direction:     r.FormValue("direction"),
		InterfaceName: r.FormValue("interface_name"),
		ContainerID:   r.FormValue("container_id"),
		NetworkName:   r.FormValue("network_name"),
		Comment:       r.FormValue("comment"),
		Enabled:       r.FormValue("enabled") == "on" || r.FormValue("enabled") == "true",
	}

	if _, err := svc.CreateRule(r.Context(), hostID, input, userID); err != nil {
		pageData := h.prepareTemplPageData(r, "New Firewall Rule", "firewall")
		h.renderTempl(w, r, firewalltpl.New(firewalltpl.NewData{
			PageData: pageData,
			Error:    "Failed to create rule: " + err.Error(),
		}))
		return
	}

	http.Redirect(w, r, "/firewall", http.StatusSeeOther)
}

// ============================================================================
// Detail
// ============================================================================

// FirewallDetailTempl renders the firewall rule detail page.
func (h *Handler) FirewallDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireFirewallSvc(w, r)
	if svc == nil {
		return
	}

	ruleID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The rule ID is not valid.")
		return
	}

	rule, err := svc.GetRule(r.Context(), ruleID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "The requested firewall rule was not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Rule: "+rule.Name, "firewall")
	h.renderTempl(w, r, firewalltpl.Detail(firewalltpl.DetailData{
		PageData:    pageData,
		Rule:        ruleToView(*rule),
		IptablesCmd: buildIptablesCmdPreview(*rule),
	}))
}

// ============================================================================
// Edit / Update
// ============================================================================

// FirewallEditTempl renders the firewall rule edit form.
func (h *Handler) FirewallEditTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireFirewallSvc(w, r)
	if svc == nil {
		return
	}

	ruleID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The rule ID is not valid.")
		return
	}

	rule, err := svc.GetRule(r.Context(), ruleID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "The requested firewall rule was not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Edit: "+rule.Name, "firewall")
	h.renderTempl(w, r, firewalltpl.Edit(firewalltpl.EditData{
		PageData: pageData,
		Rule:     ruleToView(*rule),
	}))
}

// FirewallUpdateTempl handles POST /firewall/{id} — updates a rule.
func (h *Handler) FirewallUpdateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireFirewallSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	ruleID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The rule ID is not valid.")
		return
	}

	userID := h.firewallUserUUID(r)

	name := r.FormValue("name")
	desc := r.FormValue("description")
	chain := models.FirewallChain(r.FormValue("chain"))
	proto := r.FormValue("protocol")
	src := r.FormValue("source")
	dst := r.FormValue("destination")
	srcPort := r.FormValue("src_port")
	dstPort := r.FormValue("dst_port")
	action := models.FirewallAction(r.FormValue("action"))
	dir := r.FormValue("direction")
	iface := r.FormValue("interface_name")
	ctrID := r.FormValue("container_id")
	netName := r.FormValue("network_name")
	comment := r.FormValue("comment")
	enabled := r.FormValue("enabled") == "on" || r.FormValue("enabled") == "true"

	input := models.UpdateFirewallRuleInput{
		Name:          &name,
		Description:   &desc,
		Chain:         &chain,
		Protocol:      &proto,
		Source:        &src,
		Destination:   &dst,
		SrcPort:       &srcPort,
		DstPort:       &dstPort,
		Action:        &action,
		Direction:     &dir,
		InterfaceName: &iface,
		ContainerID:   &ctrID,
		NetworkName:   &netName,
		Comment:       &comment,
		Enabled:       &enabled,
	}

	if _, err := svc.UpdateRule(r.Context(), ruleID, input, userID); err != nil {
		pageData := h.prepareTemplPageData(r, "Edit Firewall Rule", "firewall")
		h.renderTempl(w, r, firewalltpl.Edit(firewalltpl.EditData{
			PageData: pageData,
			Rule: firewalltpl.RuleView{
				ID:   ruleID.String(),
				Name: name,
			},
			Error: "Failed to update rule: " + err.Error(),
		}))
		return
	}

	http.Redirect(w, r, "/firewall/"+ruleID.String(), http.StatusSeeOther)
}

// ============================================================================
// Delete
// ============================================================================

// FirewallDeleteTempl handles DELETE /firewall/{id}.
func (h *Handler) FirewallDeleteTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireFirewallSvc(w, r)
	if svc == nil {
		return
	}

	ruleID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	userID := h.firewallUserUUID(r)

	if err := svc.DeleteRule(r.Context(), ruleID, userID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError,
			"Error", "Failed to delete rule: "+err.Error())
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/firewall")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/firewall", http.StatusSeeOther)
}

// ============================================================================
// Apply + Sync
// ============================================================================

// FirewallApplyTempl handles POST /firewall/apply — pushes rules to host.
func (h *Handler) FirewallApplyTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireFirewallSvc(w, r)
	if svc == nil {
		return
	}

	hostID := h.getFirewallHostID(r)
	userID := h.firewallUserUUID(r)

	if err := svc.ApplyRules(r.Context(), hostID, userID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError,
			"Apply Failed", "Failed to apply rules: "+err.Error())
		return
	}

	http.Redirect(w, r, "/firewall", http.StatusSeeOther)
}

// FirewallSyncTempl handles POST /firewall/sync — reads rules from host.
func (h *Handler) FirewallSyncTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireFirewallSvc(w, r)
	if svc == nil {
		return
	}

	hostID := h.getFirewallHostID(r)
	userID := h.firewallUserUUID(r)

	if _, err := svc.SyncFromHost(r.Context(), hostID, userID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError,
			"Sync Failed", "Failed to sync from host: "+err.Error())
		return
	}

	http.Redirect(w, r, "/firewall", http.StatusSeeOther)
}

// ============================================================================
// Audit Log
// ============================================================================

// FirewallAuditTempl renders the firewall audit log page.
func (h *Handler) FirewallAuditTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireFirewallSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getFirewallHostID(r)
	pageData := h.prepareTemplPageData(r, "Firewall Audit Log", "firewall")

	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	const pageSize = 50
	offset := (page - 1) * pageSize

	entries, total, err := svc.ListAuditLogs(ctx, hostID, pageSize, offset)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError,
			"Error", "Failed to load audit logs: "+err.Error())
		return
	}

	entryViews := make([]firewalltpl.AuditEntryView, 0, len(entries))
	for _, e := range entries {
		entryViews = append(entryViews, firewalltpl.AuditEntryView{
			ID:          e.ID.String(),
			Action:      e.Action,
			RuleSummary: e.RuleSummary,
			Details:     e.Details,
			CreatedAt:   e.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}

	h.renderTempl(w, r, firewalltpl.Audit(firewalltpl.AuditData{
		PageData: pageData,
		Entries:  entryViews,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}))
}
