// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	vulntmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/vulnmgmt"
)

// VulnMgmtTempl renders the vulnerability management page.
func (h *Handler) VulnMgmtTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Vulnerability Management", "vulnerabilities")

	secSvc := h.services.Security()
	trivyAvailable := secSvc != nil && secSvc.IsTrivyAvailable()

	// Build container risk and per-container CVE counts from security scan data.
	var containerRisk []vulntmpl.VulnContainerView
	containerCVECounts := make(map[string]map[string]int) // containerID → severity → count
	if secSvc != nil {
		if containers, err := secSvc.ListContainersWithSecurity(ctx); err == nil {
			for _, c := range containers {
				if !c.HasScan {
					continue
				}
				risk := "low"
				if c.Score < 30 {
					risk = "critical"
				} else if c.Score < 50 {
					risk = "high"
				} else if c.Score < 70 {
					risk = "medium"
				}
				cv := vulntmpl.VulnContainerView{
					ContainerID:   c.ID,
					ContainerName: c.Name,
					Image:         c.Image,
					RiskScore:     risk,
					LastScanAt:    c.LastScanned,
				}
				containerRisk = append(containerRisk, cv)
			}
		}
		if issues, err := secSvc.ListIssues(ctx); err == nil {
			for _, issue := range issues {
				if issue.CVEID == "" || issue.ContainerID == "" {
					continue
				}
				if containerCVECounts[issue.ContainerID] == nil {
					containerCVECounts[issue.ContainerID] = make(map[string]int)
				}
				containerCVECounts[issue.ContainerID][issue.Severity]++
			}
		}
	}
	for i := range containerRisk {
		if counts, ok := containerCVECounts[containerRisk[i].ContainerID]; ok {
			containerRisk[i].CriticalCount = counts["critical"]
			containerRisk[i].HighCount = counts["high"]
			containerRisk[i].MediumCount = counts["medium"]
			containerRisk[i].LowCount = counts["low"]
			containerRisk[i].TotalCount = counts["critical"] + counts["high"] + counts["medium"] + counts["low"]
		}
	}

	// Build vulnerability views and stats.
	var vulns []vulntmpl.VulnerabilityView
	stats := vulntmpl.VulnStats{}
	now := time.Now()
	var totalFixTime time.Duration
	var resolvedCount int
	hasTrackedData := false

	if h.trackedVulnRepo != nil {
		dbVulns, err := h.trackedVulnRepo.List(ctx)
		if err == nil && len(dbVulns) > 0 {
			hasTrackedData = true
			for _, v := range dbVulns {
				vv := vulntmpl.VulnerabilityView{
					ID:              v.ID.String(),
					CVEID:           v.CVEID,
					Title:           v.Title,
					Description:     v.Description,
					Severity:        v.Severity,
					CVSSScore:       v.CVSSScore,
					Package:         v.Package,
					InstalledVer:    v.InstalledVer,
					FixedVer:        v.FixedVer,
					AffectedImages:  v.AffectedImages,
					ContainerCount:  v.ContainerCount,
					Status:          v.Status,
					Priority:        v.Priority,
					Assignee:        v.Assignee,
					Notes:           v.Notes,
					ResolutionNotes: v.ResolutionNotes,
					DetectedAt:      v.DetectedAt.Format("Jan 02 15:04"),
				}
				if v.AssigneeID != nil {
					vv.AssigneeID = v.AssigneeID.String()
				}
				if v.SLADeadline != nil {
					vv.SLADeadline = v.SLADeadline.Format("Jan 02 2006")
					if now.After(*v.SLADeadline) && v.Status != "resolved" && v.Status != "accepted_risk" {
						vv.SLABreached = true
						stats.SLABreached++
					}
				}
				if v.ResolvedAt != nil {
					vv.ResolvedAt = v.ResolvedAt.Format("Jan 02 15:04")
					if now.Sub(*v.ResolvedAt) < 7*24*time.Hour {
						stats.ResolvedThisWeek++
					}
					if v.Status == "resolved" {
						fixTime := v.ResolvedAt.Sub(v.DetectedAt)
						if fixTime > 0 {
							totalFixTime += fixTime
							resolvedCount++
						}
					}
				}
				vulns = append(vulns, vv)
				stats.TotalVulns++
				switch v.Severity {
				case "critical":
					stats.CriticalVulns++
				case "high":
					stats.HighVulns++
				case "medium":
					stats.MediumVulns++
				case "low":
					stats.LowVulns++
				}
			}
		}
	}

	// Fallback: if no tracked vulnerabilities exist, populate from security issues.
	if !hasTrackedData && secSvc != nil {
		if issues, err := secSvc.ListIssues(ctx); err == nil {
			vulns, stats = buildVulnViewsFromIssues(issues)
		}
	}

	// Calculate Mean Time To Fix
	stats.MeanTimeToFix = "N/A"
	if resolvedCount > 0 {
		avgFix := totalFixTime / time.Duration(resolvedCount)
		days := int(avgFix.Hours() / 24)
		if days > 0 {
			stats.MeanTimeToFix = fmt.Sprintf("%dd", days)
		} else {
			hours := int(avgFix.Hours())
			if hours > 0 {
				stats.MeanTimeToFix = fmt.Sprintf("%dh", hours)
			} else {
				stats.MeanTimeToFix = fmt.Sprintf("%dm", int(avgFix.Minutes()))
			}
		}
	}

	// Dashboard KPIs (Phase 2)
	var slaCompliancePct float64 = 100
	var mttrBySev map[string]float64
	var weeklyTrend []models.VulnWeeklyTrend
	var topImages []models.ImageVulnCount

	if h.trackedVulnRepo != nil && hasTrackedData {
		if pct, err := h.trackedVulnRepo.SLACompliancePercent(ctx); err == nil {
			slaCompliancePct = pct
		}
		if m, err := h.trackedVulnRepo.MTTRBySeverity(ctx); err == nil {
			mttrBySev = m
		}
		if t, err := h.trackedVulnRepo.WeeklyTrend(ctx); err == nil {
			weeklyTrend = t
		}
		if imgs, err := h.trackedVulnRepo.TopAffectedImages(ctx, 10); err == nil {
			topImages = imgs
		}
	}

	// Build user list for assignment dropdown
	var users []vulntmpl.VulnUserView
	if userSvc := h.services.Users(); userSvc != nil {
		if userList, _, err := userSvc.List(ctx, "", ""); err == nil {
			for _, u := range userList {
				users = append(users, vulntmpl.VulnUserView{
					ID:       u.ID,
					Username: u.Username,
				})
			}
		}
	}

	data := vulntmpl.VulnMgmtData{
		PageData:         pageData,
		Vulnerabilities:  vulns,
		Containers:       containerRisk,
		Stats:            stats,
		ActiveTab:        r.URL.Query().Get("tab"),
		TrivyAvailable:   trivyAvailable,
		HasTrackedData:   hasTrackedData,
		Users:            users,
		SLACompliancePct: slaCompliancePct,
		MTTRBySeverity:   vulnMTTRStrings(mttrBySev),
		WeeklyTrend:      weeklyTrend,
		TopImages:        topImages,
	}

	h.renderTempl(w, r, vulntmpl.VulnManagement(data))
}

// vulnMTTRStrings converts MTTR hours map to human-readable strings.
func vulnMTTRStrings(m map[string]float64) map[string]string {
	out := make(map[string]string, len(m))
	for sev, hours := range m {
		days := int(hours / 24)
		if days > 0 {
			out[sev] = fmt.Sprintf("%dd", days)
		} else if hours >= 1 {
			out[sev] = fmt.Sprintf("%dh", int(hours))
		} else {
			out[sev] = fmt.Sprintf("%dm", int(hours*60))
		}
	}
	return out
}

// buildVulnViewsFromIssues builds vulnerability views from security issues (CVE-only).
func buildVulnViewsFromIssues(issues []IssueView) ([]vulntmpl.VulnerabilityView, vulntmpl.VulnStats) {
	type cveAgg struct {
		issue        IssueView
		containerIDs map[string]struct{}
	}
	cveMap := make(map[string]*cveAgg)
	for _, issue := range issues {
		if issue.CVEID == "" {
			continue
		}
		if agg, ok := cveMap[issue.CVEID]; ok {
			if issue.ContainerID != "" {
				agg.containerIDs[issue.ContainerID] = struct{}{}
			}
		} else {
			cids := make(map[string]struct{})
			if issue.ContainerID != "" {
				cids[issue.ContainerID] = struct{}{}
			}
			cveMap[issue.CVEID] = &cveAgg{issue: issue, containerIDs: cids}
		}
	}

	var vulns []vulntmpl.VulnerabilityView
	var stats vulntmpl.VulnStats
	for cveID, agg := range cveMap {
		pkg := extractPackageFromTitle(agg.issue.Title)
		cvssStr := ""
		if agg.issue.CVSSScore > 0 {
			cvssStr = fmt.Sprintf("%.1f", agg.issue.CVSSScore)
		}
		vv := vulntmpl.VulnerabilityView{
			ID:             cveID,
			CVEID:          cveID,
			Title:          agg.issue.Title,
			Description:    agg.issue.Message,
			Severity:       agg.issue.Severity,
			CVSSScore:      cvssStr,
			Package:        pkg,
			ContainerCount: len(agg.containerIDs),
			Status:         "open",
			Priority:       vulnPriorityFromSeverity(agg.issue.Severity),
		}
		vulns = append(vulns, vv)
		stats.TotalVulns++
		switch agg.issue.Severity {
		case "critical":
			stats.CriticalVulns++
		case "high":
			stats.HighVulns++
		case "medium":
			stats.MediumVulns++
		case "low":
			stats.LowVulns++
		}
	}
	return vulns, stats
}

// VulnScan triggers a vulnerability scan using the existing security service.
func (h *Handler) VulnScan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	secSvc := h.services.Security()
	if secSvc == nil {
		h.setFlash(w, r, "error", "Security service unavailable")
		http.Redirect(w, r, "/vulnerabilities", http.StatusSeeOther)
		return
	}

	if err := secSvc.ScanAll(ctx); err != nil {
		h.setFlash(w, r, "error", "Scan failed: "+err.Error())
		http.Redirect(w, r, "/vulnerabilities", http.StatusSeeOther)
		return
	}

	issues, err := secSvc.ListIssues(ctx)
	if err == nil && h.trackedVulnRepo != nil {
		containerImages := make(map[string]string)
		if containerSvc := h.services.Containers(); containerSvc != nil {
			if containers, cerr := containerSvc.List(ctx, nil); cerr == nil {
				for _, c := range containers {
					containerImages[c.ID] = c.Image
				}
			}
		}

		type cveInfo struct {
			issue        IssueView
			containerIDs map[string]struct{}
		}
		cveMap := make(map[string]*cveInfo)
		for _, issue := range issues {
			if issue.CVEID == "" {
				continue
			}
			if ci, ok := cveMap[issue.CVEID]; ok {
				if issue.ContainerID != "" {
					ci.containerIDs[issue.ContainerID] = struct{}{}
				}
			} else {
				cids := make(map[string]struct{})
				if issue.ContainerID != "" {
					cids[issue.ContainerID] = struct{}{}
				}
				cveMap[issue.CVEID] = &cveInfo{issue: issue, containerIDs: cids}
			}
		}

		imported := 0
		updated := 0
		for _, ci := range cveMap {
			imageSet := make(map[string]struct{})
			for cid := range ci.containerIDs {
				if img, ok := containerImages[cid]; ok {
					imageSet[img] = struct{}{}
				}
			}
			var affectedImages []string
			for img := range imageSet {
				affectedImages = append(affectedImages, img)
			}

			pkg := extractPackageFromTitle(ci.issue.Title)
			cvssStr := ""
			if ci.issue.CVSSScore > 0 {
				cvssStr = fmt.Sprintf("%.1f", ci.issue.CVSSScore)
			}

			sla := vulnSLADays(ci.issue.Severity)
			deadline := time.Now().Add(time.Duration(sla) * 24 * time.Hour)
			priority := vulnPriorityFromSeverity(ci.issue.Severity)
			v := &TrackedVulnRecord{
				ID:             uuid.New(),
				CVEID:          ci.issue.CVEID,
				Title:          ci.issue.Title,
				Description:    ci.issue.Message,
				Severity:       ci.issue.Severity,
				CVSSScore:      cvssStr,
				Package:        pkg,
				AffectedImages: affectedImages,
				ContainerCount: len(ci.containerIDs),
				Status:         "open",
				Priority:       priority,
				SLADeadline:    &deadline,
				DetectedAt:     time.Now(),
			}

			existed, _ := h.trackedVulnRepo.ExistsByCVE(ctx, ci.issue.CVEID)
			if err := h.trackedVulnRepo.Upsert(ctx, v); err == nil {
				if existed {
					updated++
				} else {
					imported++
				}
			}
		}

		msg := fmt.Sprintf("Vulnerability scan complete: %d new CVEs imported", imported)
		if updated > 0 {
			msg += fmt.Sprintf(", %d updated", updated)
		}
		h.setFlash(w, r, "success", msg)
	} else if err != nil {
		h.setFlash(w, r, "warning", "Scan triggered but failed to import results: "+err.Error())
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/vulnerabilities")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/vulnerabilities", http.StatusSeeOther)
}

// VulnAcknowledge starts working on a vulnerability.
func (h *Handler) VulnAcknowledge(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.updateTrackedVulnStatus(r, id, "in_progress"); err != nil {
		h.setFlash(w, r, "error", "Failed to update vulnerability: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Vulnerability marked as in progress")
	}
	redirectVulns(w, r)
}

// VulnResolve marks a vulnerability as resolved. Accepts optional resolution_notes.
func (h *Handler) VulnResolve(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	uid, err := uuid.Parse(id)
	if err != nil {
		h.setFlash(w, r, "error", "Invalid vulnerability ID")
		redirectVulns(w, r)
		return
	}
	if h.trackedVulnRepo == nil {
		h.setFlash(w, r, "error", "Vulnerability tracking not configured")
		redirectVulns(w, r)
		return
	}

	notes := r.FormValue("resolution_notes")
	if notes == "" {
		notes = "Resolved without additional notes"
	}

	if err := h.trackedVulnRepo.Resolve(r.Context(), uid, notes, nil); err != nil {
		h.setFlash(w, r, "error", "Failed to resolve vulnerability: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Vulnerability resolved with evidence recorded")
	}
	redirectVulns(w, r)
}

// VulnAcceptRisk marks a vulnerability as accepted risk.
func (h *Handler) VulnAcceptRisk(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.updateTrackedVulnStatus(r, id, "accepted_risk"); err != nil {
		h.setFlash(w, r, "error", "Failed to accept risk: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Risk accepted for vulnerability")
	}
	redirectVulns(w, r)
}

// VulnAssign assigns a vulnerability to a user.
func (h *Handler) VulnAssign(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	uid, err := uuid.Parse(id)
	if err != nil {
		h.setFlash(w, r, "error", "Invalid vulnerability ID")
		redirectVulns(w, r)
		return
	}
	if h.trackedVulnRepo == nil {
		h.setFlash(w, r, "error", "Vulnerability tracking not configured")
		redirectVulns(w, r)
		return
	}

	assigneeIDStr := r.FormValue("assignee_id")
	assigneeName := r.FormValue("assignee_name")

	var assigneeID *uuid.UUID
	if assigneeIDStr != "" {
		parsed, err := uuid.Parse(assigneeIDStr)
		if err != nil {
			h.setFlash(w, r, "error", "Invalid assignee ID")
			redirectVulns(w, r)
			return
		}
		assigneeID = &parsed

		// Resolve username if not provided
		if assigneeName == "" && h.userRepo != nil {
			if u, err := h.userRepo.GetUserByID(assigneeIDStr); err == nil && u != nil {
				assigneeName = u.Username
			}
		}
	}

	if err := h.trackedVulnRepo.Assign(r.Context(), uid, assigneeID, assigneeName); err != nil {
		h.setFlash(w, r, "error", "Failed to assign vulnerability: "+err.Error())
	} else {
		msg := "Vulnerability unassigned"
		if assigneeName != "" {
			msg = fmt.Sprintf("Vulnerability assigned to %s", assigneeName)
		}
		h.setFlash(w, r, "success", msg)
	}
	redirectVulns(w, r)
}

// VulnAssignAPI handles JSON-based assignment for AJAX calls.
func (h *Handler) VulnAssignAPI(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	uid, err := uuid.Parse(id)
	if err != nil {
		h.jsonError(w, "invalid vulnerability ID", http.StatusBadRequest)
		return
	}
	if h.trackedVulnRepo == nil {
		h.jsonError(w, "vulnerability tracking not configured", http.StatusServiceUnavailable)
		return
	}

	var body struct {
		AssigneeID string `json:"assignee_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	var assigneeID *uuid.UUID
	var assigneeName string

	if body.AssigneeID != "" {
		parsed, err := uuid.Parse(body.AssigneeID)
		if err != nil {
			h.jsonError(w, "invalid assignee ID", http.StatusBadRequest)
			return
		}
		assigneeID = &parsed
		if h.userRepo != nil {
			if u, err := h.userRepo.GetUserByID(body.AssigneeID); err == nil && u != nil {
				assigneeName = u.Username
			}
		}
	}

	if err := h.trackedVulnRepo.Assign(r.Context(), uid, assigneeID, assigneeName); err != nil {
		h.jsonError(w, "failed to assign: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":       true,
		"assignee": assigneeName,
	})
}

// VulnResolveAPI handles JSON-based resolution with evidence for AJAX calls.
func (h *Handler) VulnResolveAPI(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	uid, err := uuid.Parse(id)
	if err != nil {
		h.jsonError(w, "invalid vulnerability ID", http.StatusBadRequest)
		return
	}
	if h.trackedVulnRepo == nil {
		h.jsonError(w, "vulnerability tracking not configured", http.StatusServiceUnavailable)
		return
	}

	var body struct {
		ResolutionNotes string `json:"resolution_notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(body.ResolutionNotes) == "" {
		h.jsonError(w, "resolution_notes is required", http.StatusBadRequest)
		return
	}

	if err := h.trackedVulnRepo.Resolve(r.Context(), uid, body.ResolutionNotes, nil); err != nil {
		h.jsonError(w, "failed to resolve: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

// VulnDashboardAPI returns JSON dashboard KPIs for AJAX polling.
func (h *Handler) VulnDashboardAPI(w http.ResponseWriter, r *http.Request) {
	if h.trackedVulnRepo == nil {
		h.jsonError(w, "vulnerability tracking not configured", http.StatusServiceUnavailable)
		return
	}
	ctx := r.Context()

	result := make(map[string]interface{})

	if bySev, err := h.trackedVulnRepo.CountBySeverity(ctx); err == nil {
		result["by_severity"] = bySev
	}
	if byStat, err := h.trackedVulnRepo.CountByStatus(ctx); err == nil {
		result["by_status"] = byStat
	}
	if pct, err := h.trackedVulnRepo.SLACompliancePercent(ctx); err == nil {
		result["sla_compliance_pct"] = pct
	}
	if mttr, err := h.trackedVulnRepo.MTTRBySeverity(ctx); err == nil {
		result["mttr_by_severity"] = vulnMTTRStrings(mttr)
	}
	if trend, err := h.trackedVulnRepo.WeeklyTrend(ctx); err == nil {
		result["weekly_trend"] = trend
	}
	if imgs, err := h.trackedVulnRepo.TopAffectedImages(ctx, 10); err == nil {
		result["top_images"] = imgs
	}
	if breached, err := h.trackedVulnRepo.CountSLABreached(ctx); err == nil {
		result["sla_breached"] = breached
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) updateTrackedVulnStatus(r *http.Request, id, status string) error {
	if h.trackedVulnRepo == nil {
		return fmt.Errorf("vulnerability tracking not configured")
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid vulnerability ID")
	}
	return h.trackedVulnRepo.UpdateStatus(r.Context(), uid, status)
}

func redirectVulns(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/vulnerabilities")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/vulnerabilities", http.StatusSeeOther)
}

func extractPackageFromTitle(title string) string {
	if idx := strings.Index(title, " in "); idx >= 0 {
		return strings.TrimSpace(title[idx+4:])
	}
	return ""
}

func vulnSLADays(severity string) int {
	switch severity {
	case "critical":
		return 7
	case "high":
		return 30
	case "medium":
		return 90
	case "low":
		return 180
	default:
		return 90
	}
}

func vulnPriorityFromSeverity(severity string) string {
	switch severity {
	case "critical":
		return "p0"
	case "high":
		return "p1"
	case "medium":
		return "p2"
	default:
		return "p3"
	}
}
