// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	metadatatmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/metadata"
	recontmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/recon"
	reconpart "github.com/fr4nsys/usulnet/internal/web/templates/partials/recon"
)

// ReconDashboardTempl renders /recon/dashboard.
func (h *Handler) ReconDashboardTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.reconService()
	if svc == nil || !svc.IsEnabled() {
		http.NotFound(w, r)
		return
	}
	pageData := h.prepareTemplPageData(r, "Privacy & Recon", "recon-dashboard")
	data := recontmpl.DashboardData{
		PageData:       pageData,
		Acknowledged:   h.reconAcknowledged(r),
		LegalNotice:    ReconLegalNotice,
		IsAdmin:        h.isAdmin(r),
		IsAcknowledged: h.reconAcknowledged(r),
	}
	if dash, err := svc.GetDashboard(r.Context()); err == nil && dash != nil {
		data.Stats = recontmpl.DashboardStats{
			Targets:        dash.TotalTargets,
			Scans:          dash.TotalScans,
			Running:        dash.RunningScans,
			Completed:      dash.CompletedScans,
			Failed:         dash.FailedScans,
			FindingsBySev:  dash.FindingsBySev,
			Critical:       dash.FindingsBySev["critical"],
			High:           dash.FindingsBySev["high"],
			Medium:         dash.FindingsBySev["medium"],
			Low:            dash.FindingsBySev["low"],
		}
		for _, s := range dash.RecentScans {
			data.RecentScans = append(data.RecentScans, reconScanViewToTmpl(s))
		}
		for _, f := range dash.TopFindings {
			data.TopFindings = append(data.TopFindings, reconFindingViewToTmpl(f))
		}
	} else if err != nil {
		h.logger.Error("recon dashboard failed", "error", err)
	}
	h.renderTempl(w, r, recontmpl.Dashboard(data))
}

// ReconTargetsListTempl renders /recon/targets.
func (h *Handler) ReconTargetsListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.reconService()
	if svc == nil || !svc.IsEnabled() {
		http.NotFound(w, r)
		return
	}
	pageData := h.prepareTemplPageData(r, "Recon Targets", "recon-targets")
	data := recontmpl.TargetsListData{
		PageData: pageData,
		IsAdmin:  h.isAdmin(r),
	}
	if targets, err := svc.ListTargets(r.Context()); err == nil {
		for _, t := range targets {
			data.Targets = append(data.Targets, reconTargetViewToTmpl(t))
		}
	} else {
		h.logger.Error("recon list targets failed", "error", err)
	}
	if profiles, err := svc.ListProfiles(r.Context()); err == nil {
		for _, p := range profiles {
			data.Profiles = append(data.Profiles, reconProfileViewToTmpl(p))
		}
	}
	h.renderTempl(w, r, recontmpl.TargetsList(data))
}

// ReconTargetDetailTempl renders /recon/targets/{id}.
func (h *Handler) ReconTargetDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.reconService()
	if svc == nil || !svc.IsEnabled() {
		http.NotFound(w, r)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid target id", http.StatusBadRequest)
		return
	}
	detail, err := svc.GetTarget(r.Context(), id)
	if err != nil || detail == nil {
		http.NotFound(w, r)
		return
	}
	pageData := h.prepareTemplPageData(r, "Recon Target", "recon-targets")
	data := recontmpl.TargetDetailData{
		PageData: pageData,
		Target:   reconTargetViewToTmpl(detail.Target),
	}
	for _, s := range detail.Scans {
		data.Scans = append(data.Scans, reconScanViewToTmpl(s))
	}
	for _, f := range detail.Findings {
		data.Findings = append(data.Findings, reconFindingViewToTmpl(f))
	}
	for _, p := range detail.OwnershipProofs {
		data.OwnershipProofs = append(data.OwnershipProofs, recontmpl.OwnershipProofView{
			ID:         p.ID,
			Method:     p.Method,
			Status:     p.Status,
			Challenge:  p.Challenge,
			VerifiedAt: p.VerifiedAt,
			CreatedAt:  p.CreatedAt,
		})
	}
	h.renderTempl(w, r, recontmpl.TargetDetail(data))
}

// ReconScansListTempl renders /recon/scans.
func (h *Handler) ReconScansListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.reconService()
	if svc == nil || !svc.IsEnabled() {
		http.NotFound(w, r)
		return
	}
	pageData := h.prepareTemplPageData(r, "Recon Scans", "recon-scans")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	filter := ReconScanFilter{
		Status: r.URL.Query().Get("status"),
		Limit:  limit,
	}
	data := recontmpl.ScansListData{
		PageData:     pageData,
		FilterStatus: filter.Status,
	}
	if scans, err := svc.ListScans(r.Context(), filter); err == nil {
		for _, s := range scans {
			data.Scans = append(data.Scans, reconScanViewToTmpl(s))
		}
	} else {
		h.logger.Error("recon list scans failed", "error", err)
	}
	h.renderTempl(w, r, recontmpl.ScansList(data))
}

// ReconScanDetailTempl renders /recon/scans/{id}.
func (h *Handler) ReconScanDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.reconService()
	if svc == nil || !svc.IsEnabled() {
		http.NotFound(w, r)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid scan id", http.StatusBadRequest)
		return
	}
	detail, err := svc.GetScan(r.Context(), id)
	if err != nil || detail == nil {
		http.NotFound(w, r)
		return
	}
	pageData := h.prepareTemplPageData(r, "Recon Scan", "recon-scans")
	data := recontmpl.ScanDetailData{
		PageData: pageData,
		Scan:     reconScanViewToTmpl(detail.Scan),
		Modules:  detail.Modules,
	}
	if detail.Summary != nil {
		data.Summary = &recontmpl.ScanSummaryView{
			Grade:       detail.Summary.Grade,
			Counts:      detail.Summary.Counts,
			GeneratedAt: detail.Summary.GeneratedAt,
		}
	}
	for _, f := range detail.Findings {
		data.Findings = append(data.Findings, reconFindingViewToTmpl(f))
	}
	h.renderTempl(w, r, recontmpl.ScanDetail(data))
}

// ReconScanFindingsPartial renders the findings table as an HTMX partial.
// Supports ?severity= and ?module= filters; reuses the same target id used
// by the full page so swap targets stay stable.
func (h *Handler) ReconScanFindingsPartial(w http.ResponseWriter, r *http.Request) {
	svc := h.reconService()
	if svc == nil || !svc.IsEnabled() {
		http.NotFound(w, r)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid scan id", http.StatusBadRequest)
		return
	}
	filter := ReconFindingFilter{
		Severity: r.URL.Query().Get("severity"),
		Module:   r.URL.Query().Get("module"),
		Limit:    500,
	}
	findings, err := svc.ListFindings(r.Context(), id, filter)
	if err != nil {
		h.logger.Error("recon findings partial failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	rows := make([]reconpart.FindingRow, 0, len(findings))
	for _, f := range findings {
		rows = append(rows, reconpart.FindingRow{
			ID:         f.ID,
			Module:     f.Module,
			Category:   f.Category,
			Severity:   f.Severity,
			Value:      f.Value,
			Source:     f.Source,
			Confidence: f.Confidence,
			FirstSeen:  f.FirstSeen,
			LastSeen:   f.LastSeen,
		})
	}
	h.renderTempl(w, r, reconpart.FindingsTable(rows))
}

// ReconScanProgressPartial renders the live progress bar for a scan.
// The partial subscribes to /api/v1/events for SSE updates.
func (h *Handler) ReconScanProgressPartial(w http.ResponseWriter, r *http.Request) {
	svc := h.reconService()
	if svc == nil || !svc.IsEnabled() {
		http.NotFound(w, r)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid scan id", http.StatusBadRequest)
		return
	}
	detail, err := svc.GetScan(r.Context(), id)
	if err != nil || detail == nil {
		http.NotFound(w, r)
		return
	}
	h.renderTempl(w, r, reconpart.ScanProgress(reconpart.ScanProgressData{
		ScanID:   detail.Scan.ID,
		Status:   detail.Scan.Status,
		Progress: detail.Scan.Progress,
		Engine:   detail.Scan.Engine,
		Error:    detail.Scan.Error,
	}))
}

// ReconConnectorsTempl renders /recon/connectors.
func (h *Handler) ReconConnectorsTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.reconService()
	if svc == nil || !svc.IsEnabled() {
		http.NotFound(w, r)
		return
	}
	pageData := h.prepareTemplPageData(r, "Recon Connectors", "recon-connectors")
	data := recontmpl.ConnectorsData{PageData: pageData}
	if conns, err := svc.ListConnectors(r.Context()); err == nil {
		for _, c := range conns {
			data.Connectors = append(data.Connectors, recontmpl.ConnectorView{
				Kind:        c.Kind,
				Name:        c.Name,
				Enabled:     c.Enabled,
				Configured:  c.Configured,
				Description: c.Description,
				DocsURL:     c.DocsURL,
			})
		}
	}
	h.renderTempl(w, r, recontmpl.Connectors(data))
}

// ReconReportsTempl renders /recon/reports.
func (h *Handler) ReconReportsTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.reconService()
	if svc == nil || !svc.IsEnabled() {
		http.NotFound(w, r)
		return
	}
	pageData := h.prepareTemplPageData(r, "Recon Reports", "recon-reports")
	data := recontmpl.ReportsData{PageData: pageData}
	if reports, err := svc.ListReports(r.Context()); err == nil {
		for _, rp := range reports {
			data.Reports = append(data.Reports, recontmpl.ReportView{
				ID:          rp.ID,
				ScanID:      rp.ScanID,
				TargetValue: rp.TargetValue,
				Format:      rp.Format,
				SizeBytes:   rp.SizeBytes,
				CreatedAt:   rp.CreatedAt,
				DownloadURL: rp.DownloadURL,
			})
		}
	}
	h.renderTempl(w, r, recontmpl.Reports(data))
}

// ReconAck handles the POST /recon/ack form (mirrors POST /api/v1/recon/_ack
// for the in-page modal). Returns the dashboard fragment for HTMX or
// redirects on a normal form submit.
func (h *Handler) ReconAck(w http.ResponseWriter, r *http.Request) {
	svc := h.reconService()
	if svc == nil || !svc.IsEnabled() {
		http.NotFound(w, r)
		return
	}
	if !h.isAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var actorID *uuid.UUID
	if u := GetUserFromContext(r.Context()); u != nil {
		if parsed, err := uuid.Parse(u.ID); err == nil {
			actorID = &parsed
		}
	}
	if err := svc.Acknowledge(r.Context(), actorID, clientIP(r)); err != nil {
		h.logger.Error("recon acknowledgement failed", "error", err)
		h.setFlash(w, r, "error", "Failed to record acknowledgement: "+err.Error())
		h.redirect(w, r, "/recon/dashboard")
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/recon/dashboard")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/recon/dashboard", http.StatusSeeOther)
}

// ----------------------------------------------------------------------------
// Internal helpers
// ----------------------------------------------------------------------------

// reconService returns the registered ReconService or nil when the host
// services registry is not a *ServiceRegistry (test scenarios).
func (h *Handler) reconService() ReconService {
	if h == nil || h.services == nil {
		return nil
	}
	if reg, ok := h.services.(reconAware); ok {
		return reg.Recon()
	}
	return nil
}

// metadataService is the metadata counterpart.
func (h *Handler) metadataService() MetadataService {
	if h == nil || h.services == nil {
		return nil
	}
	if reg, ok := h.services.(metadataAware); ok {
		return reg.Metadata()
	}
	return nil
}

// reconAware and metadataAware narrow the Services interface so that the
// new accessors can be added on the concrete *ServiceRegistry without
// forcing every test mock to implement them.
type reconAware interface {
	Recon() ReconService
}

type metadataAware interface {
	Metadata() MetadataService
}

func (h *Handler) reconAcknowledged(r *http.Request) bool {
	svc := h.reconService()
	if svc == nil {
		return false
	}
	ok, err := svc.IsAcknowledged(r.Context())
	if err != nil {
		h.logger.Error("recon ack check failed", "error", err)
		return false
	}
	return ok
}

func (h *Handler) isAdmin(r *http.Request) bool {
	u := GetUserFromContext(r.Context())
	if u == nil {
		return false
	}
	return u.Role == "admin"
}

func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}

// ----------------------------------------------------------------------------
// View → template type bridges. Templates live in their own packages and
// declare their own structs; these helpers translate the adapter views
// (which the handler tests can verify) to the template-layer DTOs.
// ----------------------------------------------------------------------------

func reconTargetViewToTmpl(t ReconTargetView) recontmpl.TargetView {
	return recontmpl.TargetView{
		ID:              t.ID,
		Type:            t.Type,
		Value:           t.Value,
		ValueHashPrefix: t.ValueHashPrefix,
		Label:           t.Label,
		OwnershipStatus: t.OwnershipStatus,
		OwnershipMethod: t.OwnershipMethod,
		OwnershipOK:     t.OwnershipVerified,
		LastScanAt:      t.LastScanAt,
		ScanCount:       t.ScanCount,
		CreatedAt:       t.CreatedAt,
	}
}

func reconScanViewToTmpl(s ReconScanView) recontmpl.ScanView {
	return recontmpl.ScanView{
		ID:          s.ID,
		TargetID:    s.TargetID,
		TargetValue: s.TargetValue,
		TargetType:  s.TargetType,
		ProfileID:   s.ProfileID,
		ProfileName: s.ProfileName,
		Status:      s.Status,
		Engine:      s.Engine,
		Error:       s.Error,
		StartedAt:   s.StartedAt,
		FinishedAt:  s.FinishedAt,
		Duration:    s.Duration,
		Progress:    s.Progress,
		CreatedAt:   s.CreatedAt,
	}
}

func reconFindingViewToTmpl(f ReconFindingView) recontmpl.FindingView {
	return recontmpl.FindingView{
		ID:         f.ID,
		ScanID:     f.ScanID,
		TargetID:   f.TargetID,
		Module:     f.Module,
		Category:   f.Category,
		Severity:   f.Severity,
		Value:      f.Value,
		Source:     f.Source,
		Confidence: f.Confidence,
		FirstSeen:  f.FirstSeen,
		LastSeen:   f.LastSeen,
	}
}

func reconProfileViewToTmpl(p ReconProfileView) recontmpl.ProfileView {
	return recontmpl.ProfileView{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		Kind:        p.Kind,
		TargetTypes: p.TargetTypes,
		Modules:     p.Modules,
	}
}

// Unused import placeholder removed by go compiler; left here only to
// silence the linter if the metadata templates package is ever
// referenced through this handler in future sessions.
var _ = metadatatmpl.UploadData{}
