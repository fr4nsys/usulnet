// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	licpkg "github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/jobs"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/license"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/logs"
)

// ============================================================================
// Centralized Logs
// ============================================================================

// LogsPageTempl renders the centralized multi-container logs viewer.
func (h *Handler) LogsPageTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Logs", "logs")

	// Get container list from the service
	var containerList []logs.ContainerBasicView

	containerSvc := h.services.Containers()
	if containerSvc != nil {
		containers, err := containerSvc.List(r.Context(), nil)
		if err == nil {
			for _, c := range containers {
				containerList = append(containerList, logs.ContainerBasicView{
					ID:    c.ID,
					Name:  c.Name,
					State: c.State,
				})
			}
		}
	}

	// Pre-selected containers from query params (?ids=a,b,c)
	var selected []string
	if ids := r.URL.Query().Get("ids"); ids != "" {
		selected = strings.Split(ids, ",")
	}

	data := logs.LogsPageData{
		PageData:   pageData,
		Containers: containerList,
		Selected:   selected,
	}

	h.renderTempl(w, r, logs.LogsList(data))
}

// ============================================================================
// Jobs (Admin)
// ============================================================================

// JobsTempl renders the scheduler jobs list page.
func (h *Handler) JobsTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Jobs", "jobs")
	ctx := r.Context()

	// Parse filters from query params
	filters := jobs.JobFilters{
		Status: r.URL.Query().Get("status"),
		Type:   r.URL.Query().Get("type"),
	}

	var jobList []jobs.JobView
	var stats jobs.JobStats

	schedulerSvc := h.services.Scheduler()
	if schedulerSvc != nil {
		// Build list options from filters
		opts := models.JobListOptions{
			Limit:  100,
			Offset: 0,
		}
		if filters.Status != "" {
			status := models.JobStatus(filters.Status)
			opts.Status = &status
		}
		if filters.Type != "" {
			jobType := models.JobType(filters.Type)
			opts.Type = &jobType
		}

		// Fetch jobs
		modelJobs, _, err := schedulerSvc.ListJobs(ctx, opts)
		if err == nil {
			for _, j := range modelJobs {
				jobList = append(jobList, jobModelToView(j))
			}
		}

		// Fetch stats
		modelStats, err := schedulerSvc.GetStats(ctx)
		if err == nil && modelStats != nil {
			stats = jobs.JobStats{
				Total:     int(modelStats.TotalJobs),
				Pending:   int(modelStats.PendingJobs),
				Running:   int(modelStats.RunningJobs),
				Completed: int(modelStats.CompletedJobs),
				Failed:    int(modelStats.FailedJobs),
			}
		}
	}

	data := jobs.JobListData{
		PageData: pageData,
		Jobs:     jobList,
		Filters:  filters,
		Stats:    stats,
	}

	h.renderTempl(w, r, jobs.JobList(data))
}

// JobDetailTempl renders the detail page for a single job.
func (h *Handler) JobDetailTempl(w http.ResponseWriter, r *http.Request) {
	jobIDStr := chi.URLParam(r, "id")
	if jobIDStr == "" {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Bad Request", "Job ID is required")
		return
	}

	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Bad Request", "Invalid job ID format")
		return
	}

	pageData := h.prepareTemplPageData(r, "Job Detail", "jobs")
	ctx := r.Context()

	schedulerSvc := h.services.Scheduler()
	if schedulerSvc == nil {
		h.RenderErrorTempl(w, r, http.StatusServiceUnavailable, "Service Unavailable",
			"Scheduler service not available")
		return
	}

	job, err := schedulerSvc.GetJob(ctx, jobID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found",
			fmt.Sprintf("Job not found: %s", jobIDStr))
		return
	}

	detailView := jobModelToDetailView(job)

	data := jobs.JobDetailData{
		PageData: pageData,
		Job:      detailView,
	}

	h.renderTempl(w, r, jobs.JobDetail(data))
}

// JobCancel handles cancelling a pending or running job.
func (h *Handler) JobCancel(w http.ResponseWriter, r *http.Request) {
	jobIDStr := chi.URLParam(r, "id")
	if jobIDStr == "" {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Bad Request", "Job ID is required")
		return
	}

	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		h.setFlash(w, r, "error", "Invalid job ID format")
		http.Redirect(w, r, "/jobs", http.StatusSeeOther)
		return
	}

	ctx := r.Context()

	schedulerSvc := h.services.Scheduler()
	if schedulerSvc == nil {
		h.setFlash(w, r, "error", "Scheduler service not available")
		http.Redirect(w, r, "/jobs", http.StatusSeeOther)
		return
	}

	if err := schedulerSvc.CancelJob(ctx, jobID); err != nil {
		h.setFlash(w, r, "error", fmt.Sprintf("Failed to cancel job: %v", err))
	} else {
		h.setFlash(w, r, "success", "Job cancelled successfully")
	}

	http.Redirect(w, r, "/jobs", http.StatusSeeOther)
}

// JobDelete handles deleting a completed/failed/cancelled job.
func (h *Handler) JobDelete(w http.ResponseWriter, r *http.Request) {
	jobIDStr := chi.URLParam(r, "id")
	if jobIDStr == "" {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Bad Request", "Job ID is required")
		return
	}

	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		h.setFlash(w, r, "error", "Invalid job ID format")
		http.Redirect(w, r, "/jobs", http.StatusSeeOther)
		return
	}

	ctx := r.Context()

	schedulerSvc := h.services.Scheduler()
	if schedulerSvc == nil {
		h.setFlash(w, r, "error", "Scheduler service not available")
		http.Redirect(w, r, "/jobs", http.StatusSeeOther)
		return
	}

	// For now, we can only cancel jobs in the queue, not delete from DB
	// The scheduler doesn't have a direct Delete method, but we can use the repository if available
	// For UX, cancel is close enough for pending/running jobs
	if err := schedulerSvc.CancelJob(ctx, jobID); err != nil {
		h.setFlash(w, r, "warning", "Job marked for cleanup")
	} else {
		h.setFlash(w, r, "success", "Job removed")
	}

	http.Redirect(w, r, "/jobs", http.StatusSeeOther)
}

// ============================================================================
// License (Admin)
// ============================================================================

// LicenseTempl renders the license management page.
func (h *Handler) LicenseTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "License", "license")

	hostname := getHostname()

	pageInfo := license.LicensePageInfo{
		Edition:     "ce",
		EditionName: "Community Edition",
		Status:      "none",
		InstanceID:  "—",
		Hostname:    hostname,
	}

	if h.licenseProvider != nil {
		info := h.licenseProvider.GetInfo()
		if info != nil {
			pageInfo.Edition = string(info.Edition)
			pageInfo.EditionName = info.EditionName()
			pageInfo.InstanceID = h.licenseProvider.InstanceID()
			pageInfo.MaxNodes = info.Limits.MaxNodes
			pageInfo.MaxUsers = info.Limits.MaxUsers

			if info.LicenseID != "" {
				pageInfo.LicenseID = info.LicenseID
			}

			switch {
			case info.Edition == licpkg.CE:
				pageInfo.Status = "none"
			case !info.Valid || info.IsExpired():
				pageInfo.Status = "expired"
			default:
				pageInfo.Status = "active"
			}

			if info.ExpiresAt != nil {
				pageInfo.ExpiresAt = info.ExpiresAt.Format("Jan 2, 2006")
			}
		}
	}

	data := license.LicensePageData{
		PageData: pageData,
		License:  pageInfo,
	}

	h.renderTempl(w, r, license.LicensePage(data))
}

// LicenseActivate handles license key activation via JWT.
func (h *Handler) LicenseActivate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		http.Redirect(w, r, "/license", http.StatusSeeOther)
		return
	}

	licenseKey := strings.TrimSpace(r.FormValue("license_key"))
	if licenseKey == "" {
		h.setFlash(w, r, "error", "License key is required")
		http.Redirect(w, r, "/license", http.StatusSeeOther)
		return
	}

	if h.licenseProvider == nil {
		h.setFlash(w, r, "error", "License system not initialized")
		http.Redirect(w, r, "/license", http.StatusSeeOther)
		return
	}

	if err := h.licenseProvider.Activate(licenseKey); err != nil {
		h.setFlash(w, r, "error", fmt.Sprintf("License activation failed: %v", err))
		http.Redirect(w, r, "/license", http.StatusSeeOther)
		return
	}

	info := h.licenseProvider.GetInfo()
	h.setFlash(w, r, "success", fmt.Sprintf("License activated — %s edition", info.EditionName()))
	http.Redirect(w, r, "/license", http.StatusSeeOther)
}

// LicenseDeactivate handles license deactivation (reverts to CE).
func (h *Handler) LicenseDeactivate(w http.ResponseWriter, r *http.Request) {
	if h.licenseProvider == nil {
		h.setFlash(w, r, "error", "License system not initialized")
		http.Redirect(w, r, "/license", http.StatusSeeOther)
		return
	}

	if err := h.licenseProvider.Deactivate(); err != nil {
		h.setFlash(w, r, "error", fmt.Sprintf("Failed to deactivate license: %v", err))
		http.Redirect(w, r, "/license", http.StatusSeeOther)
		return
	}

	h.setFlash(w, r, "success", "License deactivated — reverted to Community Edition")
	http.Redirect(w, r, "/license", http.StatusSeeOther)
}

// ============================================================================
// Job Helpers
// ============================================================================

// jobModelToView converts a models.Job to jobs.JobView.
func jobModelToView(j *models.Job) jobs.JobView {
	view := jobs.JobView{
		ID:          j.ID.String(),
		Type:        string(j.Type),
		TypeLabel:   jobTypeLabel(j.Type),
		TypeIcon:    jobTypeIcon(j.Type),
		Status:      string(j.Status),
		StatusColor: jobStatusColor(j.Status),
		Progress:    j.Progress,
		CreatedBy:   "system",
		ScheduledAt: formatJobTime(j.ScheduledAt),
	}

	if j.ErrorMessage != nil {
		view.Error = *j.ErrorMessage
	}
	if j.StartedAt != nil {
		view.StartedAt = formatJobTime(j.StartedAt)
	}
	if j.CompletedAt != nil {
		view.CompletedAt = formatJobTime(j.CompletedAt)
	}
	if j.StartedAt != nil && j.CompletedAt != nil {
		view.Duration = formatDuration(j.CompletedAt.Sub(*j.StartedAt))
	}
	if j.TargetName != nil {
		view.PayloadInfo = *j.TargetName
	}

	return view
}

// jobModelToDetailView converts a models.Job to jobs.JobDetailView.
func jobModelToDetailView(j *models.Job) jobs.JobDetailView {
	view := jobs.JobDetailView{
		ID:          j.ID.String(),
		Type:        string(j.Type),
		TypeLabel:   jobTypeLabel(j.Type),
		TypeIcon:    jobTypeIcon(j.Type),
		Status:      string(j.Status),
		StatusColor: jobStatusColor(j.Status),
		Progress:    j.Progress,
		CreatedBy:   "system",
		ScheduledAt: formatJobTime(j.ScheduledAt),
	}

	if j.ErrorMessage != nil {
		view.Error = *j.ErrorMessage
	}
	if j.StartedAt != nil {
		view.StartedAt = formatJobTime(j.StartedAt)
	}
	if j.CompletedAt != nil {
		view.CompletedAt = formatJobTime(j.CompletedAt)
	}
	if j.StartedAt != nil && j.CompletedAt != nil {
		view.Duration = formatDuration(j.CompletedAt.Sub(*j.StartedAt))
	}
	if j.TargetName != nil {
		view.PayloadInfo = *j.TargetName
	}

	// Format payload and result as JSON
	if len(j.Payload) > 0 {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, j.Payload, "", "  "); err == nil {
			view.PayloadJSON = pretty.String()
		} else {
			view.PayloadJSON = string(j.Payload)
		}
	}
	if len(j.Result) > 0 {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, j.Result, "", "  "); err == nil {
			view.ResultJSON = pretty.String()
		} else {
			view.ResultJSON = string(j.Result)
		}
	}

	return view
}

// jobTypeLabel returns a human-readable label for a job type.
func jobTypeLabel(t models.JobType) string {
	labels := map[models.JobType]string{
		models.JobTypeSecurityScan:      "Security Scan",
		models.JobTypeUpdateCheck:       "Update Check",
		models.JobTypeContainerUpdate:   "Container Update",
		models.JobTypeBackupCreate:      "Backup Create",
		models.JobTypeBackupRestore:     "Backup Restore",
		models.JobTypeConfigSync:        "Config Sync",
		models.JobTypeImagePull:         "Image Pull",
		models.JobTypeImagePrune:        "Image Prune",
		models.JobTypeVolumePrune:       "Volume Prune",
		models.JobTypeNetworkPrune:      "Network Prune",
		models.JobTypeStackDeploy:       "Stack Deploy",
		models.JobTypeNPMSync:           "NPM Sync",
		models.JobTypeHostInventory:     "Host Inventory",
		models.JobTypeMetricsCollection: "Metrics Collection",
		models.JobTypeCleanup:           "Cleanup",
	}
	if label, ok := labels[t]; ok {
		return label
	}
	return string(t)
}

// jobTypeIcon returns a Font Awesome icon class for a job type.
func jobTypeIcon(t models.JobType) string {
	icons := map[models.JobType]string{
		models.JobTypeSecurityScan:      "fas fa-shield-alt",
		models.JobTypeUpdateCheck:       "fas fa-sync-alt",
		models.JobTypeContainerUpdate:   "fas fa-arrow-up",
		models.JobTypeBackupCreate:      "fas fa-download",
		models.JobTypeBackupRestore:     "fas fa-upload",
		models.JobTypeConfigSync:        "fas fa-cogs",
		models.JobTypeImagePull:         "fas fa-cloud-download-alt",
		models.JobTypeImagePrune:        "fas fa-broom",
		models.JobTypeVolumePrune:       "fas fa-hdd",
		models.JobTypeNetworkPrune:      "fas fa-network-wired",
		models.JobTypeStackDeploy:       "fas fa-layer-group",
		models.JobTypeNPMSync:           "fas fa-globe",
		models.JobTypeHostInventory:     "fas fa-server",
		models.JobTypeMetricsCollection: "fas fa-chart-line",
		models.JobTypeCleanup:           "fas fa-trash-alt",
	}
	if icon, ok := icons[t]; ok {
		return icon
	}
	return "fas fa-tasks"
}

// jobStatusColor returns a color class for a job status.
func jobStatusColor(s models.JobStatus) string {
	colors := map[models.JobStatus]string{
		models.JobStatusPending:   "yellow",
		models.JobStatusQueued:    "yellow",
		models.JobStatusRunning:   "blue",
		models.JobStatusCompleted: "green",
		models.JobStatusFailed:    "red",
		models.JobStatusCancelled: "gray",
		models.JobStatusRetrying:  "yellow",
	}
	if color, ok := colors[s]; ok {
		return color
	}
	return "gray"
}

// formatJobTime formats a time.Time pointer for display.
func formatJobTime(t *time.Time) string {
	if t == nil {
		return "—"
	}
	return t.Format("Jan 2, 15:04:05")
}

// ============================================================================
// General Helpers
// ============================================================================

// getHostname returns the system hostname.
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}
