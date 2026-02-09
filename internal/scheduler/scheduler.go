// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package scheduler

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/robfig/cron/v3"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
)

// Config holds scheduler configuration
type Config struct {
	// WorkerPoolSize is the number of worker goroutines
	WorkerPoolSize int

	// MaxJobDuration is the maximum time a job can run
	MaxJobDuration time.Duration

	// QueueVisibilityTimeout is how long a job is invisible after dequeue
	QueueVisibilityTimeout time.Duration

	// PollInterval is how often to poll the queue
	PollInterval time.Duration

	// RecoveryInterval is how often to recover stale jobs
	RecoveryInterval time.Duration

	// CleanupInterval is how often to cleanup dead letter queue
	CleanupInterval time.Duration

	// DeadLetterMaxAge is how long to keep failed jobs
	DeadLetterMaxAge time.Duration
}

// DefaultConfig returns default scheduler configuration
func DefaultConfig() *Config {
	return &Config{
		WorkerPoolSize:         5,
		MaxJobDuration:         30 * time.Minute,
		QueueVisibilityTimeout: 5 * time.Minute,
		PollInterval:           1 * time.Second,
		RecoveryInterval:       1 * time.Minute,
		CleanupInterval:        1 * time.Hour,
		DeadLetterMaxAge:       7 * 24 * time.Hour,
	}
}

// Scheduler coordinates job scheduling, queuing, and execution
type Scheduler struct {
	config   *Config
	queue    *Queue
	pool     *workers.Pool
	registry *workers.WorkerRegistry
	cron     *cron.Cron
	repo     Repository
	logger   *logger.Logger

	// Event handlers
	eventHandlers []EventHandler
	eventMu       sync.RWMutex

	// State
	running      bool
	mu           sync.RWMutex
	stopCh       chan struct{}
	wg           sync.WaitGroup
	cronEntries  map[string]cron.EntryID
	cronMu       sync.RWMutex
}

// Repository interface for job persistence
type Repository interface {
	// Job operations
	Create(ctx context.Context, job *models.Job) error
	Get(ctx context.Context, id uuid.UUID) (*models.Job, error)
	Update(ctx context.Context, job *models.Job) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, opts models.JobListOptions) ([]*models.Job, int, error)
	GetStats(ctx context.Context) (*models.JobStats, error)

	// Scheduled job operations
	CreateScheduledJob(ctx context.Context, job *models.ScheduledJob) error
	GetScheduledJob(ctx context.Context, id uuid.UUID) (*models.ScheduledJob, error)
	UpdateScheduledJob(ctx context.Context, job *models.ScheduledJob) error
	DeleteScheduledJob(ctx context.Context, id uuid.UUID) error
	ListScheduledJobs(ctx context.Context, enabled *bool) ([]*models.ScheduledJob, error)
	UpdateScheduledJobLastRun(ctx context.Context, id uuid.UUID, status models.JobStatus, nextRun *time.Time) error
}

// EventHandler handles scheduler events
type EventHandler func(event Event)

// Event represents a scheduler event
type Event struct {
	Type      EventType
	JobID     uuid.UUID
	JobType   models.JobType
	Status    models.JobStatus
	Progress  int
	Message   string
	Error     error
	Timestamp time.Time
}

// EventType represents the type of scheduler event
type EventType string

const (
	EventJobCreated   EventType = "job_created"
	EventJobStarted   EventType = "job_started"
	EventJobProgress  EventType = "job_progress"
	EventJobCompleted EventType = "job_completed"
	EventJobFailed    EventType = "job_failed"
	EventJobCancelled EventType = "job_cancelled"
	EventJobRetrying  EventType = "job_retrying"
)

// New creates a new scheduler
func New(queue *Queue, repo Repository, config *Config, log *logger.Logger) *Scheduler {
	if config == nil {
		config = DefaultConfig()
	}

	if log == nil {
		log = logger.Nop()
	}

	registry := workers.NewWorkerRegistry()

	poolConfig := &workers.PoolConfig{
		Size:           config.WorkerPoolSize,
		MaxJobDuration: config.MaxJobDuration,
	}
	pool := workers.NewPool(poolConfig, registry, log)

	// Create cron with seconds support and panic recovery
	cronInstance := cron.New(
		cron.WithSeconds(),
		cron.WithChain(
			cron.Recover(cron.DefaultLogger),
		),
	)

	s := &Scheduler{
		config:      config,
		queue:       queue,
		pool:        pool,
		registry:    registry,
		cron:        cronInstance,
		repo:        repo,
		logger:      log.Named("scheduler"),
		stopCh:      make(chan struct{}),
		cronEntries: make(map[string]cron.EntryID),
	}

	// Set pool callbacks
	pool.SetProgressCallback(s.handleProgress)
	pool.SetCompleteCallback(s.handleComplete)

	return s
}

// ============================================================================
// Lifecycle
// ============================================================================

// Start starts the scheduler
func (s *Scheduler) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New(errors.CodeValidation, "scheduler already running")
	}
	s.running = true
	s.mu.Unlock()

	s.logger.Info("starting scheduler",
		"worker_pool_size", s.config.WorkerPoolSize,
		"poll_interval", s.config.PollInterval,
	)

	// Start cron
	s.cron.Start()

	// Start worker pool
	if err := s.pool.Start(ctx); err != nil {
		return err
	}

	// Load scheduled jobs from database
	if err := s.loadScheduledJobs(ctx); err != nil {
		s.logger.Warn("failed to load scheduled jobs", "error", err)
	}

	// Start queue processor
	s.wg.Add(1)
	go s.queueProcessor(ctx)

	// Start recovery processor
	s.wg.Add(1)
	go s.recoveryProcessor(ctx)

	// Start cleanup processor
	s.wg.Add(1)
	go s.cleanupProcessor(ctx)

	return nil
}

// Stop stops the scheduler gracefully
func (s *Scheduler) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	s.mu.Unlock()

	s.logger.Info("stopping scheduler")

	// Signal stop
	close(s.stopCh)

	// Stop cron
	cronCtx := s.cron.Stop()
	<-cronCtx.Done()

	// Stop pool
	s.pool.Stop()

	// Wait for processors
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		s.logger.Warn("scheduler shutdown timeout")
	}

	s.logger.Info("scheduler stopped")
	return nil
}

// IsRunning returns true if the scheduler is running
func (s *Scheduler) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// ============================================================================
// Worker Registration
// ============================================================================

// RegisterWorker registers a worker for a job type
func (s *Scheduler) RegisterWorker(worker workers.Worker) {
	s.registry.Register(worker)
	s.logger.Debug("worker registered", "job_type", worker.Type())
}

// RegisterWorkerFunc registers a function as a worker
func (s *Scheduler) RegisterWorkerFunc(jobType models.JobType, fn func(context.Context, *models.Job) (interface{}, error)) {
	worker := workers.NewWorkerFunc(jobType, fn)
	s.registry.Register(worker)
	s.logger.Debug("worker function registered", "job_type", jobType)
}

// Registry returns the worker registry for external registration
func (s *Scheduler) Registry() *workers.WorkerRegistry {
	return s.registry
}

// ============================================================================
// Job Operations
// ============================================================================

// EnqueueJob creates and enqueues a job for execution
func (s *Scheduler) EnqueueJob(ctx context.Context, input models.CreateJobInput) (*models.Job, error) {
	// Check if we have a worker for this job type
	if !s.registry.Has(input.Type) {
		return nil, errors.Newf(errors.CodeValidation, "no worker registered for job type: %s", input.Type)
	}

	job := &models.Job{
		ID:          uuid.New(),
		Type:        input.Type,
		Status:      models.JobStatusPending,
		Priority:    input.Priority,
		HostID:      input.HostID,
		TargetID:    input.TargetID,
		TargetName:  input.TargetName,
		MaxAttempts: input.MaxAttempts,
		ScheduledAt: input.ScheduledAt,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if job.Priority == 0 {
		job.Priority = models.JobPriorityNormal
	}

	if job.MaxAttempts == 0 {
		job.MaxAttempts = 3
	}

	// Set payload
	if input.Payload != nil {
		if err := job.SetPayload(input.Payload); err != nil {
			return nil, errors.Wrap(err, errors.CodeValidation, "failed to set payload")
		}
	}

	// Save to database
	if s.repo != nil {
		if err := s.repo.Create(ctx, job); err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to save job")
		}
	}

	// Enqueue
	if err := s.queue.Enqueue(ctx, job); err != nil {
		return nil, err
	}

	s.emitEvent(Event{
		Type:      EventJobCreated,
		JobID:     job.ID,
		JobType:   job.Type,
		Status:    job.Status,
		Timestamp: time.Now(),
	})

	return job, nil
}

// CancelJob cancels a pending or running job
func (s *Scheduler) CancelJob(ctx context.Context, jobID uuid.UUID) error {
	// Try to cancel in pool first (for running jobs)
	if s.pool.CancelJob(jobID) {
		s.logger.Debug("cancelled running job", "job_id", jobID)
	}

	// Cancel in queue
	if err := s.queue.Cancel(ctx, jobID); err != nil {
		return err
	}

	// Update in database
	if s.repo != nil {
		job, err := s.repo.Get(ctx, jobID)
		if err == nil && job != nil {
			job.Status = models.JobStatusCancelled
			now := time.Now()
			job.CompletedAt = &now
			job.UpdatedAt = now
			s.repo.Update(ctx, job)
		}
	}

	s.emitEvent(Event{
		Type:      EventJobCancelled,
		JobID:     jobID,
		Timestamp: time.Now(),
	})

	return nil
}

// GetJob retrieves a job by ID
func (s *Scheduler) GetJob(ctx context.Context, jobID uuid.UUID) (*models.Job, error) {
	// Try queue first (for recent jobs)
	job, err := s.queue.GetJob(ctx, jobID)
	if err == nil {
		return job, nil
	}

	// Fall back to database
	if s.repo != nil {
		return s.repo.Get(ctx, jobID)
	}

	return nil, errors.New(errors.CodeNotFound, "job not found")
}

// ListJobs lists jobs with filtering
func (s *Scheduler) ListJobs(ctx context.Context, opts models.JobListOptions) ([]*models.Job, int, error) {
	if s.repo == nil {
		return nil, 0, errors.New(errors.CodeInternal, "no repository configured")
	}
	return s.repo.List(ctx, opts)
}

// GetStats returns job statistics
func (s *Scheduler) GetStats(ctx context.Context) (*models.JobStats, error) {
	if s.repo == nil {
		return nil, errors.New(errors.CodeInternal, "no repository configured")
	}
	return s.repo.GetStats(ctx)
}

// ============================================================================
// Scheduled Jobs (Cron)
// ============================================================================

// CreateScheduledJob creates a new scheduled job
func (s *Scheduler) CreateScheduledJob(ctx context.Context, input models.CreateScheduledJobInput) (*models.ScheduledJob, error) {
	// Validate cron expression
	if _, err := cron.ParseStandard(input.Schedule); err != nil {
		return nil, errors.Wrap(err, errors.CodeValidation, "invalid cron expression")
	}

	// Check worker exists
	if !s.registry.Has(input.Type) {
		return nil, errors.Newf(errors.CodeValidation, "no worker registered for job type: %s", input.Type)
	}

	job := &models.ScheduledJob{
		ID:          uuid.New(),
		Name:        input.Name,
		Type:        input.Type,
		Schedule:    input.Schedule,
		HostID:      input.HostID,
		TargetID:    input.TargetID,
		TargetName:  input.TargetName,
		Priority:    input.Priority,
		MaxAttempts: input.MaxAttempts,
		IsEnabled:   input.IsEnabled,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if job.Priority == 0 {
		job.Priority = models.JobPriorityNormal
	}

	if job.MaxAttempts == 0 {
		job.MaxAttempts = 3
	}

	// Set payload
	if input.Payload != nil {
		data, err := json.Marshal(input.Payload)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeValidation, "failed to marshal payload")
		}
		job.Payload = data
	}

	// Calculate next run
	nextRun := s.calculateNextRun(job.Schedule)
	job.NextRunAt = nextRun

	// Save to database
	if s.repo != nil {
		if err := s.repo.CreateScheduledJob(ctx, job); err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to save scheduled job")
		}
	}

	// Register with cron if enabled
	if job.IsEnabled {
		if err := s.registerCronJob(job); err != nil {
			s.logger.Error("failed to register cron job", "job_id", job.ID, "error", err)
		}
	}

	return job, nil
}

// UpdateScheduledJob updates a scheduled job
func (s *Scheduler) UpdateScheduledJob(ctx context.Context, id uuid.UUID, input models.UpdateScheduledJobInput) (*models.ScheduledJob, error) {
	job, err := s.repo.GetScheduledJob(ctx, id)
	if err != nil {
		return nil, err
	}

	// Update fields
	if input.Name != nil {
		job.Name = *input.Name
	}
	if input.Schedule != nil {
		// Validate new schedule
		if _, err := cron.ParseStandard(*input.Schedule); err != nil {
			return nil, errors.Wrap(err, errors.CodeValidation, "invalid cron expression")
		}
		job.Schedule = *input.Schedule
		job.NextRunAt = s.calculateNextRun(*input.Schedule)
	}
	if input.Priority != nil {
		job.Priority = *input.Priority
	}
	if input.MaxAttempts != nil {
		job.MaxAttempts = *input.MaxAttempts
	}
	if input.IsEnabled != nil {
		job.IsEnabled = *input.IsEnabled
	}
	if input.Payload != nil {
		data, err := json.Marshal(input.Payload)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeValidation, "failed to marshal payload")
		}
		job.Payload = data
	}

	job.UpdatedAt = time.Now()

	// Save
	if err := s.repo.UpdateScheduledJob(ctx, job); err != nil {
		return nil, err
	}

	// Update cron registration
	s.unregisterCronJob(id)
	if job.IsEnabled {
		if err := s.registerCronJob(job); err != nil {
			s.logger.Error("failed to re-register cron job", "job_id", id, "error", err)
		}
	}

	return job, nil
}

// DeleteScheduledJob deletes a scheduled job
func (s *Scheduler) DeleteScheduledJob(ctx context.Context, id uuid.UUID) error {
	s.unregisterCronJob(id)
	if s.repo != nil {
		return s.repo.DeleteScheduledJob(ctx, id)
	}
	return nil
}

// GetScheduledJob retrieves a scheduled job
func (s *Scheduler) GetScheduledJob(ctx context.Context, id uuid.UUID) (*models.ScheduledJob, error) {
	if s.repo == nil {
		return nil, errors.New(errors.CodeInternal, "no repository configured")
	}
	return s.repo.GetScheduledJob(ctx, id)
}

// ListScheduledJobs lists scheduled jobs
func (s *Scheduler) ListScheduledJobs(ctx context.Context, enabledOnly bool) ([]*models.ScheduledJob, error) {
	if s.repo == nil {
		return nil, errors.New(errors.CodeInternal, "no repository configured")
	}
	var enabled *bool
	if enabledOnly {
		enabled = &enabledOnly
	}
	return s.repo.ListScheduledJobs(ctx, enabled)
}

// RunScheduledJobNow triggers a scheduled job to run immediately
func (s *Scheduler) RunScheduledJobNow(ctx context.Context, id uuid.UUID) (*models.Job, error) {
	schedJob, err := s.repo.GetScheduledJob(ctx, id)
	if err != nil {
		return nil, err
	}

	return s.createJobFromScheduled(ctx, schedJob)
}

// ============================================================================
// Event Handling
// ============================================================================

// OnEvent registers an event handler
func (s *Scheduler) OnEvent(handler EventHandler) {
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	s.eventHandlers = append(s.eventHandlers, handler)
}

func (s *Scheduler) emitEvent(event Event) {
	s.eventMu.RLock()
	handlers := s.eventHandlers
	s.eventMu.RUnlock()

	for _, handler := range handlers {
		go handler(event)
	}
}

// ============================================================================
// Queue Statistics
// ============================================================================

// GetQueueStats returns queue statistics
func (s *Scheduler) GetQueueStats(ctx context.Context) (*QueueStats, error) {
	return s.queue.GetQueueStats(ctx)
}

// GetPoolStats returns worker pool statistics
func (s *Scheduler) GetPoolStats() *workers.PoolStats {
	return s.pool.Stats()
}

// ============================================================================
// Internal methods
// ============================================================================

func (s *Scheduler) queueProcessor(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.processQueue(ctx)
		}
	}
}

func (s *Scheduler) processQueue(ctx context.Context) {
	// Dequeue and process jobs
	for {
		job, err := s.queue.Dequeue(ctx)
		if err != nil {
			s.logger.Error("failed to dequeue job", "error", err)
			return
		}

		if job == nil {
			// No jobs available
			return
		}

		s.emitEvent(Event{
			Type:      EventJobStarted,
			JobID:     job.ID,
			JobType:   job.Type,
			Status:    job.Status,
			Timestamp: time.Now(),
		})

		// Submit to pool with callbacks
		err = s.pool.SubmitWithCallbacks(job,
			func(progress int, message string) {
				s.handleProgress(job.ID, progress, message)
			},
			func(result interface{}, err error) {
				s.handleComplete(job.ID, result, err)
			},
		)

		if err != nil {
			s.logger.Error("failed to submit job to pool", "job_id", job.ID, "error", err)
			// Re-queue the job
			s.queue.Fail(ctx, job.ID, err)
		}
	}
}

func (s *Scheduler) handleProgress(jobID uuid.UUID, progress int, message string) {
	ctx := context.Background()

	// Update queue
	if err := s.queue.UpdateProgress(ctx, jobID, progress, message); err != nil {
		s.logger.Error("failed to update job progress", "job_id", jobID, "error", err)
	}

	// Update database
	if s.repo != nil {
		job, err := s.repo.Get(ctx, jobID)
		if err == nil && job != nil {
			job.Progress = progress
			if message != "" {
				job.ProgressMessage = &message
			}
			job.UpdatedAt = time.Now()
			s.repo.Update(ctx, job)
		}
	}

	s.emitEvent(Event{
		Type:      EventJobProgress,
		JobID:     jobID,
		Progress:  progress,
		Message:   message,
		Timestamp: time.Now(),
	})
}

func (s *Scheduler) handleComplete(jobID uuid.UUID, result interface{}, jobErr error) {
	ctx := context.Background()

	if jobErr != nil {
		// Mark as failed in queue (handles retry logic)
		if err := s.queue.Fail(ctx, jobID, jobErr); err != nil {
			s.logger.Error("failed to mark job as failed", "job_id", jobID, "error", err)
		}

		// Update database
		if s.repo != nil {
			job, err := s.repo.Get(ctx, jobID)
			if err == nil && job != nil {
				errMsg := jobErr.Error()
				job.ErrorMessage = &errMsg
				job.UpdatedAt = time.Now()
				if job.CanRetry() {
					job.Status = models.JobStatusRetrying
				} else {
					job.Status = models.JobStatusFailed
					now := time.Now()
					job.CompletedAt = &now
				}
				s.repo.Update(ctx, job)
			}
		}

		eventType := EventJobFailed
		job, _ := s.queue.GetJob(ctx, jobID)
		if job != nil && job.Status == models.JobStatusRetrying {
			eventType = EventJobRetrying
		}

		s.emitEvent(Event{
			Type:      eventType,
			JobID:     jobID,
			Error:     jobErr,
			Timestamp: time.Now(),
		})
	} else {
		// Mark as completed
		if err := s.queue.Complete(ctx, jobID, result); err != nil {
			s.logger.Error("failed to mark job as completed", "job_id", jobID, "error", err)
		}

		// Update database
		if s.repo != nil {
			job, err := s.repo.Get(ctx, jobID)
			if err == nil && job != nil {
				job.Status = models.JobStatusCompleted
				job.Progress = 100
				now := time.Now()
				job.CompletedAt = &now
				job.UpdatedAt = now
				if result != nil {
					job.SetResult(result)
				}
				s.repo.Update(ctx, job)
			}
		}

		s.emitEvent(Event{
			Type:      EventJobCompleted,
			JobID:     jobID,
			Timestamp: time.Now(),
		})
	}
}

func (s *Scheduler) recoveryProcessor(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.RecoveryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			recovered, err := s.queue.RecoverStaleJobs(ctx)
			if err != nil {
				s.logger.Error("failed to recover stale jobs", "error", err)
			} else if recovered > 0 {
				s.logger.Info("recovered stale jobs", "count", recovered)
			}
		}
	}
}

func (s *Scheduler) cleanupProcessor(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			removed, err := s.queue.CleanupDeadLetterQueue(ctx, s.config.DeadLetterMaxAge)
			if err != nil {
				s.logger.Error("failed to cleanup dead letter queue", "error", err)
			} else if removed > 0 {
				s.logger.Info("cleaned up dead letter queue", "removed", removed)
			}
		}
	}
}

func (s *Scheduler) loadScheduledJobs(ctx context.Context) error {
	if s.repo == nil {
		return nil
	}

	enabled := true
	jobs, err := s.repo.ListScheduledJobs(ctx, &enabled)
	if err != nil {
		return err
	}

	for _, job := range jobs {
		if err := s.registerCronJob(job); err != nil {
			s.logger.Error("failed to register scheduled job", "job_id", job.ID, "error", err)
		}
	}

	s.logger.Info("loaded scheduled jobs", "count", len(jobs))
	return nil
}

func (s *Scheduler) registerCronJob(job *models.ScheduledJob) error {
	s.cronMu.Lock()
	defer s.cronMu.Unlock()

	// Remove existing if any
	if entryID, exists := s.cronEntries[job.ID.String()]; exists {
		s.cron.Remove(entryID)
	}

	entryID, err := s.cron.AddFunc(job.Schedule, func() {
		ctx := context.Background()
		if _, err := s.createJobFromScheduled(ctx, job); err != nil {
			s.logger.Error("failed to create job from schedule",
				"scheduled_job_id", job.ID,
				"error", err,
			)
		}
	})

	if err != nil {
		return err
	}

	s.cronEntries[job.ID.String()] = entryID
	s.logger.Debug("registered cron job",
		"scheduled_job_id", job.ID,
		"name", job.Name,
		"schedule", job.Schedule,
	)

	return nil
}

func (s *Scheduler) unregisterCronJob(id uuid.UUID) {
	s.cronMu.Lock()
	defer s.cronMu.Unlock()

	if entryID, exists := s.cronEntries[id.String()]; exists {
		s.cron.Remove(entryID)
		delete(s.cronEntries, id.String())
		s.logger.Debug("unregistered cron job", "scheduled_job_id", id)
	}
}

func (s *Scheduler) createJobFromScheduled(ctx context.Context, schedJob *models.ScheduledJob) (*models.Job, error) {
	// Parse payload
	var payload interface{}
	if schedJob.Payload != nil {
		payload = schedJob.Payload
	}

	input := models.CreateJobInput{
		Type:        schedJob.Type,
		HostID:      schedJob.HostID,
		TargetID:    schedJob.TargetID,
		TargetName:  schedJob.TargetName,
		Payload:     payload,
		Priority:    schedJob.Priority,
		MaxAttempts: schedJob.MaxAttempts,
	}

	job, err := s.EnqueueJob(ctx, input)
	if err != nil {
		return nil, err
	}

	// Update scheduled job last run
	if s.repo != nil {
		nextRun := s.calculateNextRun(schedJob.Schedule)
		s.repo.UpdateScheduledJobLastRun(ctx, schedJob.ID, models.JobStatusRunning, nextRun)
	}

	return job, nil
}

func (s *Scheduler) calculateNextRun(schedule string) *time.Time {
	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	sched, err := parser.Parse(schedule)
	if err != nil {
		// Try standard format without seconds
		sched, err = cron.ParseStandard(schedule)
		if err != nil {
			return nil
		}
	}

	next := sched.Next(time.Now())
	return &next
}


