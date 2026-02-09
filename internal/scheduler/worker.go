// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package scheduler

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// Worker defines the interface for job workers
type Worker interface {
	// Type returns the job type this worker handles
	Type() models.JobType

	// Execute processes a job and returns the result
	Execute(ctx context.Context, job *models.Job) (interface{}, error)

	// CanHandle returns true if this worker can handle the given job type
	CanHandle(jobType models.JobType) bool
}

// WorkerFunc is a function type that implements Worker for simple cases
type WorkerFunc struct {
	jobType   models.JobType
	executeFn func(ctx context.Context, job *models.Job) (interface{}, error)
}

// NewWorkerFunc creates a worker from a function
func NewWorkerFunc(jobType models.JobType, fn func(ctx context.Context, job *models.Job) (interface{}, error)) *WorkerFunc {
	return &WorkerFunc{
		jobType:   jobType,
		executeFn: fn,
	}
}

// Type returns the job type
func (w *WorkerFunc) Type() models.JobType {
	return w.jobType
}

// Execute runs the worker function
func (w *WorkerFunc) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	return w.executeFn(ctx, job)
}

// CanHandle returns true if this worker handles the job type
func (w *WorkerFunc) CanHandle(jobType models.JobType) bool {
	return w.jobType == jobType
}

// BaseWorker provides common functionality for workers
type BaseWorker struct {
	jobType models.JobType
}

// NewBaseWorker creates a new base worker
func NewBaseWorker(jobType models.JobType) BaseWorker {
	return BaseWorker{jobType: jobType}
}

// Type returns the job type
func (w *BaseWorker) Type() models.JobType {
	return w.jobType
}

// CanHandle returns true if this worker handles the job type
func (w *BaseWorker) CanHandle(jobType models.JobType) bool {
	return w.jobType == jobType
}

// WorkerResult represents the result of a worker execution
type WorkerResult struct {
	JobID       uuid.UUID     `json:"job_id"`
	Success     bool          `json:"success"`
	Result      interface{}   `json:"result,omitempty"`
	Error       error         `json:"-"`
	ErrorMsg    string        `json:"error,omitempty"`
	Duration    time.Duration `json:"duration"`
	CompletedAt time.Time     `json:"completed_at"`
}

// WorkerContext provides context helpers for workers
type WorkerContext struct {
	ctx       context.Context
	job       *models.Job
	onProgress func(progress int, message string)
}

// NewWorkerContext creates a new worker context
func NewWorkerContext(ctx context.Context, job *models.Job, onProgress func(int, string)) *WorkerContext {
	return &WorkerContext{
		ctx:        ctx,
		job:        job,
		onProgress: onProgress,
	}
}

// Context returns the underlying context
func (wc *WorkerContext) Context() context.Context {
	return wc.ctx
}

// Job returns the job being processed
func (wc *WorkerContext) Job() *models.Job {
	return wc.job
}

// ReportProgress reports job progress
func (wc *WorkerContext) ReportProgress(progress int, message string) {
	if wc.onProgress != nil {
		wc.onProgress(progress, message)
	}
}

// IsCancelled checks if the context is cancelled
func (wc *WorkerContext) IsCancelled() bool {
	select {
	case <-wc.ctx.Done():
		return true
	default:
		return false
	}
}

// GetPayload unmarshals the job payload into the provided struct
func (wc *WorkerContext) GetPayload(v interface{}) error {
	return wc.job.GetPayload(v)
}

// HostID returns the host ID from the job, if set
func (wc *WorkerContext) HostID() *uuid.UUID {
	return wc.job.HostID
}

// TargetID returns the target ID from the job, if set
func (wc *WorkerContext) TargetID() string {
	if wc.job.TargetID != nil {
		return *wc.job.TargetID
	}
	return ""
}

// WorkerRegistry maintains a registry of workers by job type
type WorkerRegistry struct {
	workers map[models.JobType]Worker
}

// NewWorkerRegistry creates a new worker registry
func NewWorkerRegistry() *WorkerRegistry {
	return &WorkerRegistry{
		workers: make(map[models.JobType]Worker),
	}
}

// Register registers a worker for a job type
func (r *WorkerRegistry) Register(worker Worker) {
	r.workers[worker.Type()] = worker
}

// Get returns the worker for a job type
func (r *WorkerRegistry) Get(jobType models.JobType) (Worker, bool) {
	w, ok := r.workers[jobType]
	return w, ok
}

// Types returns all registered job types
func (r *WorkerRegistry) Types() []models.JobType {
	types := make([]models.JobType, 0, len(r.workers))
	for t := range r.workers {
		types = append(types, t)
	}
	return types
}

// Has returns true if a worker is registered for the job type
func (r *WorkerRegistry) Has(jobType models.JobType) bool {
	_, ok := r.workers[jobType]
	return ok
}

// Count returns the number of registered workers
func (r *WorkerRegistry) Count() int {
	return len(r.workers)
}
