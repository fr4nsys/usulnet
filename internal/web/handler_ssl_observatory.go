// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	sslobssvc "github.com/fr4nsys/usulnet/internal/services/sslobservatory"
	ssltpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/sslobservatory"
)

// requireSSLObsSvc returns the SSL observatory service or renders a
// "not configured" error. Centralized so every handler has the
// identical degradation path when the service is not wired.
func (h *Handler) requireSSLObsSvc(w http.ResponseWriter, r *http.Request) *sslobssvc.Service {
	if reg, ok := h.services.(*ServiceRegistry); ok && reg.sslObsSvc != nil {
		return reg.sslObsSvc
	}
	h.RenderErrorTempl(w, r, http.StatusServiceUnavailable,
		"SSL Observatory Not Configured",
		"The SSL observatory service is not enabled in this build.")
	return nil
}

// getSSLHostID resolves the active host ID for SSL operations.
// Falls back to the default host when no active host is set in context.
func (h *Handler) getSSLHostID(r *http.Request) uuid.UUID {
	if reg, ok := h.services.(*ServiceRegistry); ok {
		return resolveHostID(r.Context(), reg.defaultHostID)
	}
	return uuid.Nil
}

// parseHostList splits user-supplied SNI text on commas / newlines /
// whitespace. The service performs the canonical normalization; this
// is purely a "permissive form input" helper.
func parseHostList(raw string) []string {
	if raw == "" {
		return nil
	}
	out := make([]string, 0)
	for _, tok := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ';'
	}) {
		if tok = strings.TrimSpace(tok); tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

// parseIntList parses comma/space separated positive ints. Invalid
// tokens are skipped silently — the service drops the rest.
func parseIntList(raw string) []int {
	if raw == "" {
		return nil
	}
	out := make([]int, 0)
	for _, tok := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ';'
	}) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if v, err := strconv.Atoi(tok); err == nil && v > 0 {
			out = append(out, v)
		}
	}
	return out
}

func scanResultToView(result models.SSLScanResult) ssltpl.ScanView {
	view := ssltpl.ScanView{
		ID:           result.ID.String(),
		ScanHostname: result.ScanHostname,
		Grade:        result.Grade,
		Score:        result.Score,
		CertCN:       result.CertificateCN,
		CertIssuer:   result.CertificateIssuer,
		CertKeyType:  result.CertKeyType,
		CertKeyBits:  result.CertKeyBits,
		ChainValid:   result.CertChainValid,
		ChainLength:  result.CertChainLength,
		HasHSTS:      result.HasHSTS,
		HasOCSP:      result.HasOCSPStapling,
		HasSCT:       result.HasSCT,
		ErrorMessage: result.ErrorMessage,
		ScanDuration: fmt.Sprintf("%dms", result.ScanDurationMs),
		ScannedAt:    result.ScannedAt.Format("2006-01-02 15:04"),
	}

	if len(result.ProtocolVersions) > 0 {
		view.ProtocolVersions = strings.Join(result.ProtocolVersions, ", ")
	}

	if len(result.CipherSuites) > 0 {
		var ciphers []struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(result.CipherSuites, &ciphers) == nil && len(ciphers) > 0 {
			view.CipherSuite = ciphers[0].Name
		}
	}

	if len(result.CertificateSANs) > 0 {
		view.CertSANs = strings.Join(result.CertificateSANs, ", ")
	}

	if result.CertNotBefore != nil {
		view.CertNotBefore = result.CertNotBefore.Format("2006-01-02 15:04")
	}
	if result.CertNotAfter != nil {
		view.CertNotAfter = result.CertNotAfter.Format("2006-01-02 15:04")
	}

	return view
}

func targetToView(target models.SSLTarget, latestScan *models.SSLScanResult) ssltpl.TargetView {
	view := ssltpl.TargetView{
		ID:       target.ID.String(),
		Name:     target.Name,
		Hostname: target.Hostname,
		Port:     target.Port,
		Enabled:  target.Enabled,
	}
	view.ExtraHostnames = append(view.ExtraHostnames, target.ExtraHostnames...)

	if latestScan != nil {
		view.LatestGrade = latestScan.Grade
		view.LatestScore = fmt.Sprintf("%d", latestScan.Score)
		view.LastScan = latestScan.ScannedAt.Format("2006-01-02 15:04")
		if latestScan.CertNotAfter != nil {
			view.CertExpires = latestScan.CertNotAfter.Format("2006-01-02")
		}
	}

	return view
}

// ============================================================================
// Dashboard
// ============================================================================

// SSLDashboardTempl renders the SSL observatory dashboard.
func (h *Handler) SSLDashboardTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireSSLObsSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getSSLHostID(r)
	pageData := h.prepareTemplPageData(r, "SSL Observatory", "ssl")

	stats, err := svc.GetDashboardStats(ctx, hostID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load dashboard stats: "+err.Error())
		return
	}

	expiring, err := svc.GetExpiringCerts(ctx, hostID, 30)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load expiring certs: "+err.Error())
		return
	}

	expiringViews := make([]ssltpl.ExpiringCertView, 0, len(expiring))
	for _, scan := range expiring {
		target, tErr := svc.GetTarget(ctx, scan.TargetID)
		targetID := scan.TargetID.String()
		targetName := ""
		hostname := scan.ScanHostname
		if tErr == nil && target != nil {
			targetName = target.Name
			if hostname == "" {
				hostname = target.Hostname
			}
		}

		daysLeft := 0
		expiresAt := ""
		if scan.CertNotAfter != nil {
			daysLeft = int(time.Until(*scan.CertNotAfter).Hours() / 24)
			expiresAt = scan.CertNotAfter.Format("2006-01-02")
		}

		expiringViews = append(expiringViews, ssltpl.ExpiringCertView{
			TargetID:   targetID,
			TargetName: targetName,
			Hostname:   hostname,
			Grade:      scan.Grade,
			CertCN:     scan.CertificateCN,
			ExpiresAt:  expiresAt,
			DaysLeft:   daysLeft,
		})
	}

	lastScanTime := ""
	if stats.LastScanTime != nil {
		lastScanTime = stats.LastScanTime.Format("2006-01-02 15:04")
	}

	data := ssltpl.DashboardData{
		PageData:          pageData,
		TotalTargets:      stats.TotalTargets,
		GradeDistribution: stats.GradeDistribution,
		ExpiringSoon:      expiringViews,
		LastScanTime:      lastScanTime,
	}

	h.renderTempl(w, r, ssltpl.Dashboard(data))
}

// ============================================================================
// Target List
// ============================================================================

// SSLTargetListTempl renders the SSL targets list page.
func (h *Handler) SSLTargetListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireSSLObsSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getSSLHostID(r)
	pageData := h.prepareTemplPageData(r, "SSL Targets", "ssl")

	targets, err := svc.ListTargets(ctx, hostID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load SSL targets: "+err.Error())
		return
	}

	targetViews := make([]ssltpl.TargetView, 0, len(targets))
	for _, t := range targets {
		latest, _ := svc.GetLatestScan(ctx, t.ID)
		targetViews = append(targetViews, targetToView(t, latest))
	}

	data := ssltpl.TargetListData{
		PageData:   pageData,
		Targets:    targetViews,
		EmptyState: EmptyStateCatalogSSLObservatory(),
	}

	h.renderTempl(w, r, ssltpl.TargetList(data))
}

// ============================================================================
// Create
// ============================================================================

// SSLTargetNewTempl renders the new SSL target form.
func (h *Handler) SSLTargetNewTempl(w http.ResponseWriter, r *http.Request) {
	if svc := h.requireSSLObsSvc(w, r); svc == nil {
		return
	}
	pageData := h.prepareTemplPageData(r, "New SSL Target", "ssl")
	h.renderTempl(w, r, ssltpl.NewTarget(ssltpl.NewTargetData{PageData: pageData}))
}

// SSLTargetCreateTempl handles POST /ssl/targets — creates a new SSL target.
// sslTargetForm captures the SSL target inputs for Create.
// Port defaults to 443 after binding when 0.
type sslTargetForm struct {
	Name            string `form:"name" validate:"required"`
	Hostname        string `form:"hostname" validate:"required"`
	Port            int    `form:"port" validate:"gte=0,lte=65535"`
	ExtraHostnames  string `form:"extra_hostnames"`
	AlertThresholds string `form:"alert_thresholds"`
}

// sslTargetUpdateForm extends sslTargetForm with the Enabled
// toggle that the Update endpoint accepts (Create always sets
// Enabled=true on the underlying repo).
type sslTargetUpdateForm struct {
	sslTargetForm
	Enabled bool `form:"enabled"`
}

func (h *Handler) SSLTargetCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireSSLObsSvc(w, r)
	if svc == nil {
		return
	}
	var form sslTargetForm
	if msg := BindForm(r, &form); msg != "" {
		pageData := h.prepareTemplPageData(r, "New SSL Target", "ssl")
		h.renderTempl(w, r, ssltpl.NewTarget(ssltpl.NewTargetData{
			PageData: pageData,
			Error:    msg,
		}))
		return
	}

	hostID := h.getSSLHostID(r)

	port := form.Port
	if port == 0 {
		port = 443
	}

	input := models.CreateSSLTargetInput{
		Name:            form.Name,
		Hostname:        form.Hostname,
		Port:            port,
		ExtraHostnames:  parseHostList(form.ExtraHostnames),
		AlertThresholds: parseIntList(form.AlertThresholds),
	}

	if _, err := svc.CreateTarget(r.Context(), hostID, input); err != nil {
		pageData := h.prepareTemplPageData(r, "New SSL Target", "ssl")
		h.renderTempl(w, r, ssltpl.NewTarget(ssltpl.NewTargetData{
			PageData: pageData,
			Error:    "Failed to create target: " + err.Error(),
		}))
		return
	}

	http.Redirect(w, r, "/ssl/targets", http.StatusSeeOther)
}

// ============================================================================
// Detail
// ============================================================================

// SSLTargetDetailTempl renders the SSL target detail page.
func (h *Handler) SSLTargetDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireSSLObsSvc(w, r)
	if svc == nil {
		return
	}

	targetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The target ID is not valid.")
		return
	}

	target, err := svc.GetTarget(r.Context(), targetID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "The requested SSL target was not found.")
		return
	}

	// Latest scan per hostname.
	hostnames := target.ScanHostnames()
	latestViews := make([]ssltpl.ScanView, 0, len(hostnames))
	var primaryLatest *models.SSLScanResult
	for _, hn := range hostnames {
		scan, lerr := svc.GetLatestScanByHostname(r.Context(), targetID, hn)
		if lerr != nil || scan == nil {
			continue
		}
		latestViews = append(latestViews, scanResultToView(*scan))
		if hn == target.Hostname && primaryLatest == nil {
			s := *scan
			primaryLatest = &s
		}
	}

	scans, _, _ := svc.ListScans(r.Context(), targetID, 50, 0)
	historyViews := make([]ssltpl.ScanView, 0, len(scans))
	for _, s := range scans {
		historyViews = append(historyViews, scanResultToView(s))
	}

	pageData := h.prepareTemplPageData(r, "SSL: "+target.Name, "ssl")

	extras := make([]string, 0, len(target.ExtraHostnames))
	extras = append(extras, target.ExtraHostnames...)

	data := ssltpl.TargetDetailData{
		PageData:    pageData,
		Target:      targetToView(*target, primaryLatest),
		Thresholds:  target.EffectiveThresholds(),
		ExtraSNI:    extras,
		LatestScans: latestViews,
		ScanHistory: historyViews,
	}

	h.renderTempl(w, r, ssltpl.TargetDetail(data))
}

// ============================================================================
// Edit / Update
// ============================================================================

// SSLTargetEditTempl renders the edit form.
func (h *Handler) SSLTargetEditTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireSSLObsSvc(w, r)
	if svc == nil {
		return
	}
	targetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The target ID is not valid.")
		return
	}
	target, err := svc.GetTarget(r.Context(), targetID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "The requested SSL target was not found.")
		return
	}
	extras := make([]string, 0, len(target.ExtraHostnames))
	extras = append(extras, target.ExtraHostnames...)
	pageData := h.prepareTemplPageData(r, "Edit: "+target.Name, "ssl")
	h.renderTempl(w, r, ssltpl.EditTarget(ssltpl.EditTargetData{
		PageData:       pageData,
		ID:             target.ID.String(),
		Name:           target.Name,
		Hostname:       target.Hostname,
		Port:           target.Port,
		ExtraHostnames: extras,
		Thresholds:     target.EffectiveThresholds(),
		Enabled:        target.Enabled,
	}))
}

// SSLTargetUpdateTempl handles POST /ssl/targets/{id}/edit.
func (h *Handler) SSLTargetUpdateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireSSLObsSvc(w, r)
	if svc == nil {
		return
	}
	targetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The target ID is not valid.")
		return
	}
	var form sslTargetUpdateForm
	if msg := BindForm(r, &form); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	port := form.Port
	if port == 0 {
		port = 443
	}
	enabled := form.Enabled
	input := models.UpdateSSLTargetInput{
		Name:            &form.Name,
		Hostname:        &form.Hostname,
		Port:            &port,
		ExtraHostnames:  parseHostList(form.ExtraHostnames),
		AlertThresholds: parseIntList(form.AlertThresholds),
		Enabled:         &enabled,
	}
	if input.ExtraHostnames == nil {
		input.ExtraHostnames = []string{}
	}
	if input.AlertThresholds == nil {
		input.AlertThresholds = []int{}
	}
	if _, err := svc.UpdateTarget(r.Context(), targetID, input); err != nil {
		pageData := h.prepareTemplPageData(r, "Edit SSL Target", "ssl")
		h.renderTempl(w, r, ssltpl.EditTarget(ssltpl.EditTargetData{
			PageData:       pageData,
			ID:             targetID.String(),
			Name:           form.Name,
			Hostname:       form.Hostname,
			Port:           port,
			ExtraHostnames: input.ExtraHostnames,
			Thresholds:     input.AlertThresholds,
			Enabled:        enabled,
			Error:          "Failed to update target: " + err.Error(),
		}))
		return
	}

	http.Redirect(w, r, "/ssl/targets/"+targetID.String(), http.StatusSeeOther)
}

// ============================================================================
// Delete
// ============================================================================

// SSLTargetDeleteTempl handles DELETE /ssl/targets/{id}.
func (h *Handler) SSLTargetDeleteTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireSSLObsSvc(w, r)
	if svc == nil {
		return
	}

	targetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if err := svc.DeleteTarget(r.Context(), targetID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to delete target: "+err.Error())
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/ssl/targets")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/ssl/targets", http.StatusSeeOther)
}

// ============================================================================
// Scanning
// ============================================================================

// SSLScanTargetTempl handles POST /ssl/targets/{id}/scan.
func (h *Handler) SSLScanTargetTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireSSLObsSvc(w, r)
	if svc == nil {
		return
	}

	targetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The target ID is not valid.")
		return
	}

	if _, err := svc.ScanTarget(r.Context(), targetID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Scan Failed", "Failed to scan target: "+err.Error())
		return
	}

	http.Redirect(w, r, "/ssl/targets/"+targetID.String(), http.StatusSeeOther)
}

// SSLScanAllTempl handles POST /ssl/scan-all.
func (h *Handler) SSLScanAllTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireSSLObsSvc(w, r)
	if svc == nil {
		return
	}

	hostID := h.getSSLHostID(r)

	if _, err := svc.ScanAll(r.Context(), hostID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Scan Failed", "Failed to scan all targets: "+err.Error())
		return
	}

	http.Redirect(w, r, "/ssl", http.StatusSeeOther)
}
