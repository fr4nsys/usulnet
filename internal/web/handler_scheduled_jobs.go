// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/jobs"
)

// ScheduledJobsTempl renders the scheduled jobs management page.
func (h *Handler) ScheduledJobsTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Scheduled Jobs", "jobs")

	var items []jobs.ScheduledJobView
	sched := h.services.Scheduler()
	if sched != nil {
		sjobs, err := sched.ListScheduledJobs(r.Context(), false)
		if err != nil {
			slog.Error("Failed to list scheduled jobs", "error", err)
		} else {
			for _, sj := range sjobs {
				item := jobs.ScheduledJobView{
					ID:       sj.ID.String(),
					Name:     sj.Name,
					Type:     string(sj.Type),
					Schedule: sj.Schedule,
					Enabled:  sj.IsEnabled,
					RunCount: sj.RunCount,
				}
				if sj.LastRunAt != nil {
					item.LastRun = sj.LastRunAt.Format("2006-01-02 15:04")
				}
				if sj.LastRunStatus != nil {
					item.LastStatus = string(*sj.LastRunStatus)
				}
				if sj.NextRunAt != nil {
					item.NextRun = sj.NextRunAt.Format("2006-01-02 15:04")
				}
				items = append(items, item)
			}
		}
	}

	data := jobs.ScheduledJobListData{
		PageData:      pageData,
		ScheduledJobs: items,
	}
	h.renderTempl(w, r, jobs.ScheduledJobList(data))
}

// ScheduledJobCreate handles creation of a new scheduled job.
func (h *Handler) ScheduledJobCreate(w http.ResponseWriter, r *http.Request) {
	sched := h.services.Scheduler()
	if sched == nil {
		h.setFlash(w, r, "error", "Scheduler not configured")
		h.redirect(w, r, "/jobs/scheduled")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		h.redirect(w, r, "/jobs/scheduled")
		return
	}

	name := r.FormValue("name")
	jobType := r.FormValue("type")
	schedule := r.FormValue("schedule")
	if name == "" || jobType == "" || schedule == "" {
		h.setFlash(w, r, "error", "Name, type, and schedule are required")
		h.redirect(w, r, "/jobs/scheduled")
		return
	}

	maxAttempts := 3
	if ma := r.FormValue("max_attempts"); ma != "" {
		if v, err := strconv.Atoi(ma); err == nil && v >= 1 && v <= 10 {
			maxAttempts = v
		}
	}

	input := models.CreateScheduledJobInput{
		Name:        name,
		Type:        models.JobType(jobType),
		Schedule:    schedule,
		IsEnabled:   r.FormValue("is_enabled") == "on",
		Priority:    models.JobPriorityNormal,
		MaxAttempts: maxAttempts,
	}

	if targetName := r.FormValue("target_name"); targetName != "" {
		input.TargetName = &targetName
	}

	// CreatedBy is not part of the public input struct: the scheduler
	// stamps it from the authenticated session before persisting.
	_ = GetUserFromContext(r.Context())

	if _, err := sched.CreateScheduledJob(r.Context(), input); err != nil {
		slog.Error("Failed to create scheduled job", "name", name, "error", err)
		h.setFlash(w, r, "error", "Failed to create scheduled job: "+err.Error())
		h.redirect(w, r, "/jobs/scheduled")
		return
	}

	h.setFlash(w, r, "success", "Scheduled job '"+name+"' created")
	h.redirect(w, r, "/jobs/scheduled")
}

// ScheduledJobDelete handles deletion of a scheduled job.
func (h *Handler) ScheduledJobDelete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/jobs/scheduled")
		return
	}

	sched := h.services.Scheduler()
	if sched != nil {
		if err := sched.DeleteScheduledJob(r.Context(), id); err != nil {
			slog.Error("Failed to delete scheduled job", "id", id, "error", err)
			h.setFlash(w, r, "error", "Failed to delete scheduled job: "+err.Error())
			h.redirect(w, r, "/jobs/scheduled")
			return
		}
	}

	h.setFlash(w, r, "success", "Scheduled job deleted")
	h.redirect(w, r, "/jobs/scheduled")
}

// ScheduledJobRunNow triggers immediate execution of a scheduled job.
func (h *Handler) ScheduledJobRunNow(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/jobs/scheduled")
		return
	}

	sched := h.services.Scheduler()
	if sched == nil {
		h.setFlash(w, r, "error", "Scheduler not configured")
		h.redirect(w, r, "/jobs/scheduled")
		return
	}

	job, err := sched.RunScheduledJobNow(r.Context(), id)
	if err != nil {
		slog.Error("Failed to run scheduled job", "id", id, "error", err)
		h.setFlash(w, r, "error", "Failed to run job: "+err.Error())
		h.redirect(w, r, "/jobs/scheduled")
		return
	}

	h.setFlash(w, r, "success", "Job enqueued: "+job.ID.String()[:8])
	h.redirect(w, r, "/jobs/scheduled")
}
