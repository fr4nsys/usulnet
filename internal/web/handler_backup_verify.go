// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	backupverifysvc "github.com/fr4nsys/usulnet/internal/services/backupverify"
	bvtpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/backupverify"
)

// requireBackupVerifySvc returns the backup verify service or renders a
// "not configured" error. Centralized so every handler degrades the same
// way when the wiring is missing.
func (h *Handler) requireBackupVerifySvc(w http.ResponseWriter, r *http.Request) *backupverifysvc.Service {
	if reg, ok := h.services.(*ServiceRegistry); ok && reg.backupVerifySvc != nil {
		return reg.backupVerifySvc
	}
	h.RenderErrorTempl(w, r, http.StatusServiceUnavailable,
		"Backup Verification Not Configured",
		"The backup verification service is not enabled in this build.")
	return nil
}

// getBVHostID resolves the active host ID for backup verification operations.
func (h *Handler) getBVHostID(r *http.Request) uuid.UUID {
	if reg, ok := h.services.(*ServiceRegistry); ok {
		return resolveHostID(r.Context(), reg.defaultHostID)
	}
	return uuid.Nil
}

// backupVerifyUserUUID returns the request user's UUID, or nil if absent.
func (h *Handler) backupVerifyUserUUID(r *http.Request) *uuid.UUID {
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

// ============================================================================
// List
// ============================================================================

// BackupVerifyListTempl renders the verification list page.
func (h *Handler) BackupVerifyListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireBackupVerifySvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getBVHostID(r)
	pageData := h.prepareTemplPageData(r, "Backup Verification", "backup-verify")

	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	pageSize := 50
	offset := (page - 1) * pageSize

	verifications, total, err := svc.ListVerifications(ctx, hostID, pageSize, offset)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError,
			"Error", "Failed to load verifications: "+err.Error())
		return
	}

	stats, _ := svc.GetStats(ctx, hostID)

	views := make([]bvtpl.VerificationView, 0, len(verifications))
	for _, v := range verifications {
		views = append(views, verificationToView(v))
	}

	statsView := bvtpl.StatsView{}
	if stats != nil {
		statsView.TotalVerified = stats.TotalVerified
		statsView.Passed = stats.Passed
		statsView.Failed = stats.Failed
		statsView.LastVerified = stats.LastVerified
		if stats.TotalVerified > 0 {
			statsView.PassRate = fmt.Sprintf("%.0f%%", stats.PassRate)
		} else {
			statsView.PassRate = "-"
		}
	}

	h.renderTempl(w, r, bvtpl.List(bvtpl.ListData{
		PageData:      pageData,
		Verifications: views,
		Stats:         statsView,
		Total:         total,
		Page:          page,
		PageSize:      pageSize,
	}))
}

// ============================================================================
// Detail
// ============================================================================

// BackupVerifyDetailTempl renders a single verification's detail page.
func (h *Handler) BackupVerifyDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireBackupVerifySvc(w, r)
	if svc == nil {
		return
	}

	verifyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest,
			"Invalid ID", "The verification ID is not valid.")
		return
	}

	v, err := svc.GetVerification(r.Context(), verifyID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound,
			"Not Found", "The requested verification was not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Verification Detail", "backup-verify")
	h.renderTempl(w, r, bvtpl.Detail(bvtpl.DetailData{
		PageData:     pageData,
		Verification: verificationToView(*v),
	}))
}

// ============================================================================
// Run Verification
// ============================================================================

// BackupVerifyRunTempl handles POST /backup-verify/{backupID}/verify.
func (h *Handler) BackupVerifyRunTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireBackupVerifySvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	backupID, err := uuid.Parse(chi.URLParam(r, "backupID"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest,
			"Invalid ID", "The backup ID is not valid.")
		return
	}

	method := models.VerificationMethod(r.FormValue("method"))
	if method == "" {
		method = models.VerificationMethodExtract
	}
	if !method.IsValid() {
		h.RenderErrorTempl(w, r, http.StatusBadRequest,
			"Invalid Method", "Unknown verification method.")
		return
	}

	userID := h.backupVerifyUserUUID(r)

	if _, err := svc.RunVerification(r.Context(), backupID, method, userID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError,
			"Verification Failed", "Failed to run verification: "+err.Error())
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/backup-verify")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/backup-verify", http.StatusSeeOther)
}

// ============================================================================
// Schedules
// ============================================================================

// BackupVerifyScheduleListTempl renders the verification schedules page.
func (h *Handler) BackupVerifyScheduleListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireBackupVerifySvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getBVHostID(r)
	pageData := h.prepareTemplPageData(r, "Verification Schedules", "backup-verify")

	schedules, err := svc.ListSchedules(ctx, hostID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError,
			"Error", "Failed to load schedules: "+err.Error())
		return
	}

	views := make([]bvtpl.ScheduleView, 0, len(schedules))
	for _, s := range schedules {
		v := bvtpl.ScheduleView{
			ID:            s.ID.String(),
			Schedule:      s.Schedule,
			Method:        s.Method,
			MaxBackups:    s.MaxBackups,
			Enabled:       s.Enabled,
			LastRunStatus: s.LastRunStatus,
		}
		if s.LastRunAt != nil {
			v.LastRunAt = s.LastRunAt.Format("2006-01-02 15:04")
		}
		if s.NextRunAt != nil {
			v.NextRunAt = s.NextRunAt.Format("2006-01-02 15:04")
		}
		views = append(views, v)
	}

	h.renderTempl(w, r, bvtpl.ScheduleList(bvtpl.ScheduleListData{
		PageData:  pageData,
		Schedules: views,
	}))
}

// BackupVerifyScheduleNewTempl renders the new schedule form.
func (h *Handler) BackupVerifyScheduleNewTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireBackupVerifySvc(w, r)
	if svc == nil {
		return
	}
	pageData := h.prepareTemplPageData(r, "New Verification Schedule", "backup-verify")
	h.renderTempl(w, r, bvtpl.ScheduleNew(bvtpl.ScheduleNewData{PageData: pageData}))
}

// BackupVerifyScheduleCreateTempl handles POST /backup-verify/schedules.
func (h *Handler) BackupVerifyScheduleCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireBackupVerifySvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	hostID := h.getBVHostID(r)

	schedule := r.FormValue("schedule")
	method := r.FormValue("method")
	if method == "" {
		method = "extract"
	}
	maxBackups := 5
	if mb := r.FormValue("max_backups"); mb != "" {
		if v, err := strconv.Atoi(mb); err == nil && v > 0 {
			maxBackups = v
		}
	}

	if schedule == "" {
		pageData := h.prepareTemplPageData(r, "New Verification Schedule", "backup-verify")
		h.renderTempl(w, r, bvtpl.ScheduleNew(bvtpl.ScheduleNewData{
			PageData: pageData,
			Error:    "Schedule is required.",
		}))
		return
	}

	if _, err := svc.CreateSchedule(r.Context(), hostID, schedule, method, maxBackups); err != nil {
		pageData := h.prepareTemplPageData(r, "New Verification Schedule", "backup-verify")
		h.renderTempl(w, r, bvtpl.ScheduleNew(bvtpl.ScheduleNewData{
			PageData: pageData,
			Error:    "Failed to create schedule: " + err.Error(),
		}))
		return
	}

	http.Redirect(w, r, "/backup-verify/schedules", http.StatusSeeOther)
}

// BackupVerifyScheduleDeleteTempl handles DELETE /backup-verify/schedules/{id}.
func (h *Handler) BackupVerifyScheduleDeleteTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireBackupVerifySvc(w, r)
	if svc == nil {
		return
	}

	schedID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if err := svc.DeleteSchedule(r.Context(), schedID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError,
			"Error", "Failed to delete schedule: "+err.Error())
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/backup-verify/schedules")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/backup-verify/schedules", http.StatusSeeOther)
}

// ============================================================================
// Helpers
// ============================================================================

// verificationToView maps a model row to the template view. v26.2.7 used
// the BackupID prefix as a fallback name; we keep that behavior since the
// backup name lives on a different table that the list query does not join.
func verificationToView(v models.BackupVerification) bvtpl.VerificationView {
	view := bvtpl.VerificationView{
		ID:            v.ID.String(),
		BackupID:      v.BackupID.String(),
		BackupName:    v.BackupID.String()[:8],
		Status:        string(v.Status),
		Method:        string(v.Method),
		ChecksumValid: v.ChecksumValid,
		FilesReadable: v.FilesReadable,
		ContainerTest: v.ContainerTest,
		DataValid:     v.DataValid,
		FileCount:     v.FileCount,
		SizeBytes:     formatBytes(v.SizeBytes),
		DurationMs:    v.DurationMs,
		ErrorMessage:  v.ErrorMessage,
		CreatedAt:     v.CreatedAt.Format("2006-01-02 15:04"),
	}
	if v.VerifiedBy != nil {
		view.VerifiedBy = v.VerifiedBy.String()
	}
	if v.CompletedAt != nil {
		view.CompletedAt = v.CompletedAt.Format("2006-01-02 15:04")
	}
	return view
}
