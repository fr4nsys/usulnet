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
	crontabsvc "github.com/fr4nsys/usulnet/internal/services/crontab"
	crontabtpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/crontab"
)

// requireCrontabSvc returns the crontab service or renders a
// "not configured" error. Centralized so every handler degrades the
// same way when the service wiring is missing.
func (h *Handler) requireCrontabSvc(w http.ResponseWriter, r *http.Request) *crontabsvc.Service {
	if reg, ok := h.services.(*ServiceRegistry); ok && reg.crontabSvc != nil {
		return reg.crontabSvc
	}
	h.RenderErrorTempl(w, r, http.StatusServiceUnavailable,
		"Crontab Not Configured",
		"The crontab manager is not enabled in this build.")
	return nil
}

// getCrontabHostID resolves the active host ID for crontab operations.
func (h *Handler) getCrontabHostID(r *http.Request) uuid.UUID {
	if reg, ok := h.services.(*ServiceRegistry); ok {
		return resolveHostID(r.Context(), reg.defaultHostID)
	}
	return uuid.Nil
}

// crontabUserUUID returns the request user's UUID, or nil when the
// session has no authenticated user.
func (h *Handler) crontabUserUUID(r *http.Request) *uuid.UUID {
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

func entryToView(e *models.CrontabEntry) crontabtpl.EntryView {
	v := crontabtpl.EntryView{
		ID:          e.ID.String(),
		Name:        e.Name,
		Description: e.Description,
		Schedule:    e.Schedule,
		CommandType: string(e.CommandType),
		Command:     e.Command,
		Enabled:     e.Enabled,
		RunCount:    e.RunCount,
		FailCount:   e.FailCount,
		CreatedAt:   e.CreatedAt.Format("2006-01-02 15:04"),
		ContainerID: e.ContainerID,
		WorkingDir:  e.WorkingDir,
		HTTPMethod:  e.HTTPMethod,
		HTTPURL:     e.HTTPURL,
	}
	if e.LastRunAt != nil {
		s := e.LastRunAt.Format("2006-01-02 15:04:05")
		v.LastRunAt = &s
	}
	if e.LastRunStatus != nil {
		v.LastRunStatus = e.LastRunStatus
	}
	if e.LastRunOutput != nil {
		v.LastRunOutput = e.LastRunOutput
	}
	if e.NextRunAt != nil {
		s := e.NextRunAt.Format("2006-01-02 15:04:05")
		v.NextRunAt = &s
	}
	return v
}

// ============================================================================
// List
// ============================================================================

// CrontabListTempl renders the crontab entries list page.
func (h *Handler) CrontabListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCrontabSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getCrontabHostID(r)
	pageData := h.prepareTemplPageData(r, "Crontab Manager", "crontab")

	entries, err := svc.List(ctx, hostID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError,
			"Error", "Failed to load crontab entries: "+err.Error())
		return
	}

	stats, _ := svc.GetStats(ctx, hostID)

	entryViews := make([]crontabtpl.EntryView, 0, len(entries))
	for _, e := range entries {
		entryViews = append(entryViews, entryToView(e))
	}

	statsView := crontabtpl.StatsView{}
	if stats != nil {
		statsView = crontabtpl.StatsView{
			Total:    stats.Total,
			Enabled:  stats.Enabled,
			Disabled: stats.Disabled,
			Running:  stats.Running,
		}
	}

	h.renderTempl(w, r, crontabtpl.List(crontabtpl.ListData{
		PageData:   pageData,
		Entries:    entryViews,
		Stats:      statsView,
		EmptyState: EmptyStateCatalogCrontab(),
	}))
}

// ============================================================================
// Create
// ============================================================================

// CrontabNewTempl renders the new crontab entry form.
func (h *Handler) CrontabNewTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCrontabSvc(w, r)
	if svc == nil {
		return
	}
	pageData := h.prepareTemplPageData(r, "New Cron Job", "crontab")
	h.renderTempl(w, r, crontabtpl.New(crontabtpl.NewData{PageData: pageData}))
}

// CrontabCreateTempl handles POST /crontab.
// crontabWriteForm captures the inputs shared between cron-job
// create and update. Pointer fields preserve the "absent vs
// present-but-empty" distinction the underlying service uses to
// avoid overwriting an existing value.
type crontabWriteForm struct {
	Name        string  `form:"name" validate:"required"`
	Description string  `form:"description"`
	Schedule    string  `form:"schedule" validate:"required"`
	CommandType string  `form:"command_type"`
	Command     string  `form:"command"`
	Enabled     bool    `form:"enabled"`
	ContainerID *string `form:"container_id"`
	WorkingDir  *string `form:"working_dir"`
	HTTPMethod  *string `form:"http_method"`
	HTTPURL     *string `form:"http_url"`
}

func (h *Handler) CrontabCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCrontabSvc(w, r)
	if svc == nil {
		return
	}
	var form crontabWriteForm
	if msg := BindForm(r, &form); msg != "" {
		pageData := h.prepareTemplPageData(r, "New Cron Job", "crontab")
		h.renderTempl(w, r, crontabtpl.New(crontabtpl.NewData{
			PageData: pageData,
			Error:    msg,
		}))
		return
	}

	hostID := h.getCrontabHostID(r)
	userID := h.crontabUserUUID(r)

	cmdType := models.CrontabCommandType(form.CommandType)
	if cmdType == "" {
		cmdType = models.CrontabCommandShell
	}

	input := models.CreateCrontabInput{
		Name:        form.Name,
		Description: form.Description,
		Schedule:    form.Schedule,
		CommandType: cmdType,
		Command:     form.Command,
		Enabled:     form.Enabled,
		ContainerID: nilIfEmpty(form.ContainerID),
		WorkingDir:  nilIfEmpty(form.WorkingDir),
		HTTPMethod:  nilIfEmpty(form.HTTPMethod),
		HTTPURL:     nilIfEmpty(form.HTTPURL),
	}

	if _, err := svc.Create(r.Context(), hostID, input, userID); err != nil {
		pageData := h.prepareTemplPageData(r, "New Cron Job", "crontab")
		h.renderTempl(w, r, crontabtpl.New(crontabtpl.NewData{
			PageData: pageData,
			Error:    "Failed to create cron job: " + err.Error(),
		}))
		return
	}

	http.Redirect(w, r, "/crontab", http.StatusSeeOther)
}

// ============================================================================
// Detail
// ============================================================================

// CrontabDetailTempl renders the entry detail page with paginated executions.
func (h *Handler) CrontabDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCrontabSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()

	entryID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The cron job ID is not valid.")
		return
	}

	entry, err := svc.Get(ctx, entryID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "The requested cron job was not found.")
		return
	}

	page := 0
	if p := r.URL.Query().Get("page"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			page = n
		}
	}
	limit := crontabsvc.MaxExecutionsPerPage
	offset := page * limit

	executions, _ := svc.ListExecutions(ctx, entryID, limit, offset)
	total, _ := svc.CountExecutions(ctx, entryID)

	execViews := make([]crontabtpl.ExecutionView, 0, len(executions))
	for _, ex := range executions {
		ev := crontabtpl.ExecutionView{
			ID:         ex.ID.String(),
			Status:     ex.Status,
			Output:     ex.Output,
			Error:      ex.Error,
			DurationMs: ex.DurationMs,
			StartedAt:  ex.StartedAt.Format("2006-01-02 15:04:05"),
			FinishedAt: ex.FinishedAt.Format("2006-01-02 15:04:05"),
		}
		if ex.ExitCode != nil {
			ev.ExitCode = ex.ExitCode
		}
		execViews = append(execViews, ev)
	}

	pageData := h.prepareTemplPageData(r, "Cron Job: "+entry.Name, "crontab")
	h.renderTempl(w, r, crontabtpl.Detail(crontabtpl.DetailData{
		PageData:        pageData,
		Entry:           entryToView(entry),
		Executions:      execViews,
		ExecutionsPage:  page,
		ExecutionsTotal: total,
		ExecutionsLimit: limit,
	}))
}

// ============================================================================
// Edit / Update
// ============================================================================

// CrontabEditTempl renders the entry edit form.
func (h *Handler) CrontabEditTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCrontabSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()

	entryID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The cron job ID is not valid.")
		return
	}

	entry, err := svc.Get(ctx, entryID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "The requested cron job was not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Edit: "+entry.Name, "crontab")
	h.renderTempl(w, r, crontabtpl.Edit(crontabtpl.EditData{
		PageData: pageData,
		Entry:    entryToView(entry),
	}))
}

// CrontabUpdateTempl handles POST /crontab/{id}.
func (h *Handler) CrontabUpdateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCrontabSvc(w, r)
	if svc == nil {
		return
	}
	entryID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The cron job ID is not valid.")
		return
	}

	var form crontabWriteForm
	if msg := BindForm(r, &form); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	cmdType := models.CrontabCommandType(form.CommandType)

	input := models.UpdateCrontabInput{
		Name:        &form.Name,
		Description: &form.Description,
		Schedule:    &form.Schedule,
		Command:     &form.Command,
		CommandType: &cmdType,
		Enabled:     &form.Enabled,
		ContainerID: nilIfEmpty(form.ContainerID),
		WorkingDir:  nilIfEmpty(form.WorkingDir),
		HTTPMethod:  nilIfEmpty(form.HTTPMethod),
		HTTPURL:     nilIfEmpty(form.HTTPURL),
	}

	if _, err := svc.Update(r.Context(), entryID, input); err != nil {
		pageData := h.prepareTemplPageData(r, "Edit Cron Job", "crontab")
		ev := crontabtpl.EntryView{
			ID:          entryID.String(),
			Name:        form.Name,
			Description: form.Description,
			Schedule:    form.Schedule,
			CommandType: form.CommandType,
			Command:     form.Command,
			Enabled:     form.Enabled,
		}
		h.renderTempl(w, r, crontabtpl.Edit(crontabtpl.EditData{
			PageData: pageData,
			Entry:    ev,
			Error:    "Failed to update cron job: " + err.Error(),
		}))
		return
	}

	http.Redirect(w, r, "/crontab/"+entryID.String(), http.StatusSeeOther)
}

// ============================================================================
// Delete
// ============================================================================

// CrontabDeleteTempl handles DELETE /crontab/{id}.
func (h *Handler) CrontabDeleteTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCrontabSvc(w, r)
	if svc == nil {
		return
	}

	entryID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if err := svc.Delete(r.Context(), entryID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to delete cron job: "+err.Error())
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/crontab")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/crontab", http.StatusSeeOther)
}

// ============================================================================
// Toggle + Run Now
// ============================================================================

// CrontabToggleTempl handles POST /crontab/{id}/toggle.
func (h *Handler) CrontabToggleTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCrontabSvc(w, r)
	if svc == nil {
		return
	}
	entryID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	var toggleForm struct {
		Enabled bool `form:"enabled"`
	}
	if msg := BindForm(r, &toggleForm); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	enabled := toggleForm.Enabled
	if err := svc.ToggleEnabled(r.Context(), entryID, enabled); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to toggle cron job: "+err.Error())
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/crontab/"+entryID.String())
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/crontab/"+entryID.String(), http.StatusSeeOther)
}

// CrontabRunNowTempl handles POST /crontab/{id}/run.
func (h *Handler) CrontabRunNowTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCrontabSvc(w, r)
	if svc == nil {
		return
	}

	entryID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if err := svc.RunNow(r.Context(), entryID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to run cron job: "+err.Error())
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/crontab/"+entryID.String())
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/crontab/"+entryID.String(), http.StatusSeeOther)
}
