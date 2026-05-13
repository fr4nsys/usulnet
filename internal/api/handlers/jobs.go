// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/scheduler"
)

// JobsHandler handles job-related HTTP requests.
type JobsHandler struct {
	BaseHandler
	scheduler *scheduler.Scheduler
}

// NewJobsHandler creates a new jobs handler.
func NewJobsHandler(sched *scheduler.Scheduler, log *logger.Logger) *JobsHandler {
	return &JobsHandler{
		BaseHandler: NewBaseHandler(log),
		scheduler:   sched,
	}
}

// Routes returns the router for job endpoints.
func (h *JobsHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Read-only routes (viewer+)
	r.Get("/", h.ListJobs)
	r.Get("/stats", h.GetStats)
	r.Get("/queue-stats", h.GetQueueStats)
	r.Get("/pool-stats", h.GetPoolStats)

	r.Route("/{jobID}", func(r chi.Router) {
		r.Get("/", h.GetJob)

		// Operator+ for mutations
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireOperator)
			r.Delete("/", h.CancelJob)
		})
	})

	// Operator+ for enqueue
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireOperator)
		r.Post("/", h.EnqueueJob)
	})

	// Scheduled job operations
	r.Route("/scheduled", func(r chi.Router) {
		// Read-only (viewer+)
		r.Get("/", h.ListScheduledJobs)

		r.Route("/{scheduledJobID}", func(r chi.Router) {
			r.Get("/", h.GetScheduledJob)

			// Operator+ for mutations
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireOperator)
				r.Put("/", h.UpdateScheduledJob)
				r.Delete("/", h.DeleteScheduledJob)
				r.Post("/run", h.RunScheduledJobNow)
			})
		})

		// Operator+ for creation
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireOperator)
			r.Post("/", h.CreateScheduledJob)
		})
	})

	return r
}

// ============================================================================
// Request/Response types
// ============================================================================

// EnqueueJobRequest represents a job enqueue request.
type EnqueueJobRequest struct {
	Type        string      `json:"type"`
	HostID      *string     `json:"host_id,omitempty"`
	TargetID    *string     `json:"target_id,omitempty"`
	TargetName  *string     `json:"target_name,omitempty"`
	Payload     interface{} `json:"payload,omitempty"`
	Priority    string      `json:"priority,omitempty"`
	MaxAttempts int         `json:"max_attempts,omitempty"`
	ScheduledAt *string     `json:"scheduled_at,omitempty"`
}

// CreateScheduledJobRequest represents a scheduled job creation request.
type CreateScheduledJobRequest struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"`
	Schedule    string      `json:"schedule"`
	HostID      *string     `json:"host_id,omitempty"`
	TargetID    *string     `json:"target_id,omitempty"`
	TargetName  *string     `json:"target_name,omitempty"`
	Payload     interface{} `json:"payload,omitempty"`
	Priority    string      `json:"priority,omitempty"`
	MaxAttempts int         `json:"max_attempts,omitempty"`
	IsEnabled   bool        `json:"is_enabled,omitempty"`
}

// UpdateScheduledJobRequest represents a scheduled job update request.
type UpdateScheduledJobRequest struct {
	Name        *string     `json:"name,omitempty"`
	Schedule    *string     `json:"schedule,omitempty"`
	Payload     interface{} `json:"payload,omitempty"`
	Priority    *string     `json:"priority,omitempty"`
	MaxAttempts *int        `json:"max_attempts,omitempty"`
	IsEnabled   *bool       `json:"is_enabled,omitempty"`
}

// JobResponse represents a job in API responses.
type JobResponse struct {
	ID              string  `json:"id"`
	Type            string  `json:"type"`
	Status          string  `json:"status"`
	Priority        string  `json:"priority"`
	HostID          *string `json:"host_id,omitempty"`
	TargetID        *string `json:"target_id,omitempty"`
	TargetName      *string `json:"target_name,omitempty"`
	Payload         interface{} `json:"payload,omitempty"`
	Result          interface{} `json:"result,omitempty"`
	ErrorMessage    *string `json:"error_message,omitempty"`
	Progress        int     `json:"progress"`
	ProgressMessage *string `json:"progress_message,omitempty"`
	Attempts        int     `json:"attempts"`
	MaxAttempts     int     `json:"max_attempts"`
	ScheduledAt     *string `json:"scheduled_at,omitempty"`
	StartedAt       *string `json:"started_at,omitempty"`
	CompletedAt     *string `json:"completed_at,omitempty"`
	CreatedBy       *string `json:"created_by,omitempty"`
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`
}

// ScheduledJobResponse represents a scheduled job in API responses.
type ScheduledJobResponse struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Type          string  `json:"type"`
	Schedule      string  `json:"schedule"`
	HostID        *string `json:"host_id,omitempty"`
	TargetID      *string `json:"target_id,omitempty"`
	TargetName    *string `json:"target_name,omitempty"`
	Payload       interface{} `json:"payload,omitempty"`
	Priority      string  `json:"priority"`
	MaxAttempts   int     `json:"max_attempts"`
	IsEnabled     bool    `json:"is_enabled"`
	LastRunAt     *string `json:"last_run_at,omitempty"`
	LastRunStatus *string `json:"last_run_status,omitempty"`
	NextRunAt     *string `json:"next_run_at,omitempty"`
	RunCount      int64   `json:"run_count"`
	FailCount     int64   `json:"fail_count"`
	CreatedBy     *string `json:"created_by,omitempty"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

// JobStatsResponse represents job statistics.
type JobStatsResponse struct {
	TotalJobs     int64            `json:"total_jobs"`
	PendingJobs   int64            `json:"pending_jobs"`
	RunningJobs   int64            `json:"running_jobs"`
	CompletedJobs int64            `json:"completed_jobs"`
	FailedJobs    int64            `json:"failed_jobs"`
	ByType        map[string]int64 `json:"by_type"`
	AvgDuration   string           `json:"avg_duration"`
	SuccessRate   float64          `json:"success_rate"`
}

// QueueStatsResponse represents queue statistics.
type QueueStatsResponse struct {
	TotalPending int64            `json:"total_pending"`
	Running      int64            `json:"running"`
	DeadLetter   int64            `json:"dead_letter"`
	QueueLengths map[string]int64 `json:"queue_lengths"`
}

// PoolStatsResponse represents worker pool statistics.
type PoolStatsResponse struct {
	Size           int   `json:"size"`
	QueueLength    int   `json:"queue_length"`
	QueueCapacity  int   `json:"queue_capacity"`
	TotalProcessed int64 `json:"total_processed"`
	TotalSucceeded int64 `json:"total_succeeded"`
	TotalFailed    int64 `json:"total_failed"`
	Running        bool  `json:"running"`
}

// ============================================================================
// Job handlers
// ============================================================================

// ListJobs returns all jobs.
// GET /api/v1/jobs
func (h *JobsHandler) ListJobs(w http.ResponseWriter, r *http.Request) {
	pagination := h.GetPagination(r)

	opts := models.JobListOptions{
		Limit:  pagination.PerPage,
		Offset: pagination.Offset,
	}

	// Optional filters
	if jobType := h.QueryParam(r, "type"); jobType != "" {
		t := models.JobType(jobType)
		opts.Type = &t
	}
	if status := h.QueryParam(r, "status"); status != "" {
		s := models.JobStatus(status)
		opts.Status = &s
	}
	if hostID := h.QueryParamUUID(r, "host_id"); hostID != nil {
		opts.HostID = hostID
	}
	if targetID := h.QueryParam(r, "target_id"); targetID != "" {
		opts.TargetID = &targetID
	}

	jobs, total, err := h.scheduler.ListJobs(r.Context(), opts)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]JobResponse, len(jobs))
	for i, j := range jobs {
		resp[i] = toJobResponse(j)
	}

	h.OK(w, NewPaginatedResponse(resp, int64(total), pagination))
}

// EnqueueJob enqueues a new job.
// POST /api/v1/jobs
func (h *JobsHandler) EnqueueJob(w http.ResponseWriter, r *http.Request) {
	var req EnqueueJobRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Type == "" {
		h.BadRequest(w, "type is required")
		return
	}

	input := models.CreateJobInput{
		Type:    models.JobType(req.Type),
		Payload: req.Payload,
	}

	if req.HostID != nil {
		id, err := uuid.Parse(*req.HostID)
		if err == nil {
			input.HostID = &id
		}
	}
	if req.TargetID != nil {
		input.TargetID = req.TargetID
	}
	if req.TargetName != nil {
		input.TargetName = req.TargetName
	}
	if req.Priority != "" {
		input.Priority = parseJobPriority(req.Priority)
	}
	if req.MaxAttempts > 0 {
		input.MaxAttempts = req.MaxAttempts
	}
	if req.ScheduledAt != nil {
		t, err := time.Parse(time.RFC3339, *req.ScheduledAt)
		if err == nil {
			input.ScheduledAt = &t
		}
	}

	job, err := h.scheduler.EnqueueJob(r.Context(), input)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, toJobResponse(job))
}

// GetJob returns a specific job.
// GET /api/v1/jobs/{jobID}
func (h *JobsHandler) GetJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := h.URLParamUUID(r, "jobID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	job, err := h.scheduler.GetJob(r.Context(), jobID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toJobResponse(job))
}

// CancelJob cancels a job.
// DELETE /api/v1/jobs/{jobID}
func (h *JobsHandler) CancelJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := h.URLParamUUID(r, "jobID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.scheduler.CancelJob(r.Context(), jobID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// GetStats returns job statistics.
// GET /api/v1/jobs/stats
func (h *JobsHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.scheduler.GetStats(r.Context())
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, JobStatsResponse{
		TotalJobs:     stats.TotalJobs,
		PendingJobs:   stats.PendingJobs,
		RunningJobs:   stats.RunningJobs,
		CompletedJobs: stats.CompletedJobs,
		FailedJobs:    stats.FailedJobs,
		ByType:        stats.ByType,
		AvgDuration:   stats.AvgDuration.String(),
		SuccessRate:   stats.SuccessRate,
	})
}

// GetQueueStats returns queue statistics.
// GET /api/v1/jobs/queue-stats
func (h *JobsHandler) GetQueueStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.scheduler.GetQueueStats(r.Context())
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, QueueStatsResponse{
		TotalPending: stats.TotalPending,
		Running:      stats.Running,
		DeadLetter:   stats.DeadLetter,
		QueueLengths: stats.QueueLengths,
	})
}

// GetPoolStats returns worker pool statistics.
// GET /api/v1/jobs/pool-stats
func (h *JobsHandler) GetPoolStats(w http.ResponseWriter, r *http.Request) {
	stats := h.scheduler.GetPoolStats()

	h.OK(w, PoolStatsResponse{
		Size:           stats.Size,
		QueueLength:    stats.QueueLength,
		QueueCapacity:  stats.QueueCapacity,
		TotalProcessed: stats.TotalProcessed,
		TotalSucceeded: stats.TotalSucceeded,
		TotalFailed:    stats.TotalFailed,
		Running:        stats.Running,
	})
}

// ============================================================================
// Scheduled job handlers
// ============================================================================

// ListScheduledJobs returns all scheduled jobs.
// GET /api/v1/jobs/scheduled
func (h *JobsHandler) ListScheduledJobs(w http.ResponseWriter, r *http.Request) {
	enabledOnly := h.QueryParamBool(r, "enabled_only", false)

	jobs, err := h.scheduler.ListScheduledJobs(r.Context(), enabledOnly)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]ScheduledJobResponse, len(jobs))
	for i, j := range jobs {
		resp[i] = toScheduledJobResponse(j)
	}

	h.OK(w, resp)
}

// CreateScheduledJob creates a new scheduled job.
// POST /api/v1/jobs/scheduled
func (h *JobsHandler) CreateScheduledJob(w http.ResponseWriter, r *http.Request) {
	var req CreateScheduledJobRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Name == "" {
		h.BadRequest(w, "name is required")
		return
	}
	if req.Type == "" {
		h.BadRequest(w, "type is required")
		return
	}
	if req.Schedule == "" {
		h.BadRequest(w, "schedule is required")
		return
	}

	input := models.CreateScheduledJobInput{
		Name:      req.Name,
		Type:      models.JobType(req.Type),
		Schedule:  req.Schedule,
		Payload:   req.Payload,
		IsEnabled: req.IsEnabled,
	}

	if req.HostID != nil {
		id, err := uuid.Parse(*req.HostID)
		if err == nil {
			input.HostID = &id
		}
	}
	if req.TargetID != nil {
		input.TargetID = req.TargetID
	}
	if req.TargetName != nil {
		input.TargetName = req.TargetName
	}
	if req.Priority != "" {
		input.Priority = parseJobPriority(req.Priority)
	}
	if req.MaxAttempts > 0 {
		input.MaxAttempts = req.MaxAttempts
	}

	job, err := h.scheduler.CreateScheduledJob(r.Context(), input)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, toScheduledJobResponse(job))
}

// GetScheduledJob returns a specific scheduled job.
// GET /api/v1/jobs/scheduled/{scheduledJobID}
func (h *JobsHandler) GetScheduledJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := h.URLParamUUID(r, "scheduledJobID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	job, err := h.scheduler.GetScheduledJob(r.Context(), jobID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toScheduledJobResponse(job))
}

// UpdateScheduledJob updates a scheduled job.
// PUT /api/v1/jobs/scheduled/{scheduledJobID}
func (h *JobsHandler) UpdateScheduledJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := h.URLParamUUID(r, "scheduledJobID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req UpdateScheduledJobRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	input := models.UpdateScheduledJobInput{
		Name:        req.Name,
		Schedule:    req.Schedule,
		Payload:     req.Payload,
		MaxAttempts: req.MaxAttempts,
		IsEnabled:   req.IsEnabled,
	}

	if req.Priority != nil {
		p := parseJobPriority(*req.Priority)
		input.Priority = &p
	}

	job, err := h.scheduler.UpdateScheduledJob(r.Context(), jobID, input)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toScheduledJobResponse(job))
}

// DeleteScheduledJob deletes a scheduled job.
// DELETE /api/v1/jobs/scheduled/{scheduledJobID}
func (h *JobsHandler) DeleteScheduledJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := h.URLParamUUID(r, "scheduledJobID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.scheduler.DeleteScheduledJob(r.Context(), jobID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// RunScheduledJobNow runs a scheduled job immediately.
// POST /api/v1/jobs/scheduled/{scheduledJobID}/run
func (h *JobsHandler) RunScheduledJobNow(w http.ResponseWriter, r *http.Request) {
	jobID, err := h.URLParamUUID(r, "scheduledJobID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	job, err := h.scheduler.RunScheduledJobNow(r.Context(), jobID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toJobResponse(job))
}

// ============================================================================
// Helpers
// ============================================================================

func toJobResponse(j *models.Job) JobResponse {
	resp := JobResponse{
		ID:              j.ID.String(),
		Type:            string(j.Type),
		Status:          string(j.Status),
		Priority:        formatJobPriority(j.Priority),
		Progress:        j.Progress,
		ProgressMessage: j.ProgressMessage,
		Attempts:        j.Attempts,
		MaxAttempts:     j.MaxAttempts,
		ErrorMessage:    j.ErrorMessage,
		CreatedAt:       j.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       j.UpdatedAt.Format(time.RFC3339),
	}

	if j.HostID != nil {
		s := j.HostID.String()
		resp.HostID = &s
	}
	if j.TargetID != nil {
		resp.TargetID = j.TargetID
	}
	if j.TargetName != nil {
		resp.TargetName = j.TargetName
	}
	if len(j.Payload) > 0 {
		resp.Payload = j.Payload
	}
	if len(j.Result) > 0 {
		resp.Result = j.Result
	}
	if j.ScheduledAt != nil {
		s := j.ScheduledAt.Format(time.RFC3339)
		resp.ScheduledAt = &s
	}
	if j.StartedAt != nil {
		s := j.StartedAt.Format(time.RFC3339)
		resp.StartedAt = &s
	}
	if j.CompletedAt != nil {
		s := j.CompletedAt.Format(time.RFC3339)
		resp.CompletedAt = &s
	}
	if j.CreatedBy != nil {
		s := j.CreatedBy.String()
		resp.CreatedBy = &s
	}

	return resp
}

func toScheduledJobResponse(j *models.ScheduledJob) ScheduledJobResponse {
	resp := ScheduledJobResponse{
		ID:          j.ID.String(),
		Name:        j.Name,
		Type:        string(j.Type),
		Schedule:    j.Schedule,
		Priority:    formatJobPriority(j.Priority),
		MaxAttempts: j.MaxAttempts,
		IsEnabled:   j.IsEnabled,
		RunCount:    j.RunCount,
		FailCount:   j.FailCount,
		CreatedAt:   j.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   j.UpdatedAt.Format(time.RFC3339),
	}

	if j.HostID != nil {
		s := j.HostID.String()
		resp.HostID = &s
	}
	if j.TargetID != nil {
		resp.TargetID = j.TargetID
	}
	if j.TargetName != nil {
		resp.TargetName = j.TargetName
	}
	if len(j.Payload) > 0 {
		resp.Payload = j.Payload
	}
	if j.LastRunAt != nil {
		s := j.LastRunAt.Format(time.RFC3339)
		resp.LastRunAt = &s
	}
	if j.LastRunStatus != nil {
		s := string(*j.LastRunStatus)
		resp.LastRunStatus = &s
	}
	if j.NextRunAt != nil {
		s := j.NextRunAt.Format(time.RFC3339)
		resp.NextRunAt = &s
	}
	if j.CreatedBy != nil {
		s := j.CreatedBy.String()
		resp.CreatedBy = &s
	}

	return resp
}

// parseJobPriority converts a string to JobPriority.
func parseJobPriority(s string) models.JobPriority {
	switch s {
	case "low":
		return models.JobPriorityLow
	case "high":
		return models.JobPriorityHigh
	case "critical":
		return models.JobPriorityCritical
	default:
		return models.JobPriorityNormal
	}
}

// formatJobPriority converts JobPriority to string.
func formatJobPriority(p models.JobPriority) string {
	switch p {
	case models.JobPriorityLow:
		return "low"
	case models.JobPriorityHigh:
		return "high"
	case models.JobPriorityCritical:
		return "critical"
	default:
		return "normal"
	}
}
