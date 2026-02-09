// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package workers

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// PoolConfig holds worker pool configuration
type PoolConfig struct {
	// Size is the number of worker goroutines
	Size int

	// MaxJobDuration is the maximum time a job can run
	MaxJobDuration time.Duration

	// ShutdownTimeout is the timeout for graceful shutdown
	ShutdownTimeout time.Duration
}

// DefaultPoolConfig returns default pool configuration
func DefaultPoolConfig() *PoolConfig {
	return &PoolConfig{
		Size:            5,
		MaxJobDuration:  30 * time.Minute,
		ShutdownTimeout: 60 * time.Second,
	}
}

// Pool manages a pool of worker goroutines
type Pool struct {
	config   *PoolConfig
	registry *WorkerRegistry
	logger   *logger.Logger

	// Job channel
	jobChan chan *PoolJob

	// Progress callback
	onProgress func(jobID uuid.UUID, progress int, message string)

	// Completion callback
	onComplete func(jobID uuid.UUID, result interface{}, err error)

	// State
	running   atomic.Bool
	wg        sync.WaitGroup
	stopCh    chan struct{}
	cancelFns map[uuid.UUID]context.CancelFunc
	cancelMu  sync.RWMutex

	// Metrics
	processed atomic.Int64
	succeeded atomic.Int64
	failed    atomic.Int64
}

// PoolJob wraps a job for pool processing
type PoolJob struct {
	Job        *models.Job
	OnProgress func(progress int, message string)
	OnComplete func(result interface{}, err error)
}

// NewPool creates a new worker pool
func NewPool(config *PoolConfig, registry *WorkerRegistry, log *logger.Logger) *Pool {
	if config == nil {
		config = DefaultPoolConfig()
	}

	if log == nil {
		log = logger.Nop()
	}

	return &Pool{
		config:    config,
		registry:  registry,
		logger:    log.Named("worker-pool"),
		jobChan:   make(chan *PoolJob, config.Size*10),
		stopCh:    make(chan struct{}),
		cancelFns: make(map[uuid.UUID]context.CancelFunc),
	}
}

// SetProgressCallback sets the progress callback
func (p *Pool) SetProgressCallback(fn func(jobID uuid.UUID, progress int, message string)) {
	p.onProgress = fn
}

// SetCompleteCallback sets the completion callback
func (p *Pool) SetCompleteCallback(fn func(jobID uuid.UUID, result interface{}, err error)) {
	p.onComplete = fn
}

// Start starts the worker pool
func (p *Pool) Start(ctx context.Context) error {
	if p.running.Load() {
		return errors.New(errors.CodeInvalidInput, "pool already running")
	}

	p.running.Store(true)
	p.logger.Info("starting worker pool", "size", p.config.Size)

	// Start workers
	for i := 0; i < p.config.Size; i++ {
		p.wg.Add(1)
		go p.worker(ctx, i)
	}

	return nil
}

// Stop stops the worker pool gracefully
func (p *Pool) Stop() error {
	if !p.running.Load() {
		return nil
	}

	p.logger.Info("stopping worker pool")
	p.running.Store(false)

	// Signal stop
	close(p.stopCh)

	// Wait for workers with timeout
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		p.logger.Info("worker pool stopped gracefully",
			"processed", p.processed.Load(),
			"succeeded", p.succeeded.Load(),
			"failed", p.failed.Load(),
		)
	case <-time.After(p.config.ShutdownTimeout):
		p.logger.Warn("worker pool shutdown timeout, cancelling remaining jobs")
		p.cancelAllJobs()
	}

	return nil
}

// Submit submits a job to the pool
func (p *Pool) Submit(job *models.Job) error {
	if !p.running.Load() {
		return errors.New(errors.CodeInternal, "pool not running")
	}

	// Check if we have a worker for this job type
	if !p.registry.Has(job.Type) {
		return errors.Newf(errors.CodeInvalidInput, "no worker registered for job type: %s", job.Type)
	}

	poolJob := &PoolJob{
		Job: job,
	}

	select {
	case p.jobChan <- poolJob:
		return nil
	default:
		return errors.New(errors.CodeResourceExhausted, "job queue full")
	}
}

// SubmitWithCallbacks submits a job with callbacks
func (p *Pool) SubmitWithCallbacks(job *models.Job, onProgress func(int, string), onComplete func(interface{}, error)) error {
	if !p.running.Load() {
		return errors.New(errors.CodeInternal, "pool not running")
	}

	if !p.registry.Has(job.Type) {
		return errors.Newf(errors.CodeInvalidInput, "no worker registered for job type: %s", job.Type)
	}

	poolJob := &PoolJob{
		Job:        job,
		OnProgress: onProgress,
		OnComplete: onComplete,
	}

	select {
	case p.jobChan <- poolJob:
		return nil
	default:
		return errors.New(errors.CodeResourceExhausted, "job queue full")
	}
}

// CancelJob cancels a running job
func (p *Pool) CancelJob(jobID uuid.UUID) bool {
	p.cancelMu.RLock()
	cancel, ok := p.cancelFns[jobID]
	p.cancelMu.RUnlock()

	if ok {
		cancel()
		return true
	}
	return false
}

// Stats returns pool statistics
func (p *Pool) Stats() *PoolStats {
	return &PoolStats{
		Size:           p.config.Size,
		QueueLength:    len(p.jobChan),
		QueueCapacity:  cap(p.jobChan),
		TotalProcessed: p.processed.Load(),
		TotalSucceeded: p.succeeded.Load(),
		TotalFailed:    p.failed.Load(),
		Running:        p.running.Load(),
	}
}

// PoolStats holds pool statistics
type PoolStats struct {
	Size           int   `json:"size"`
	QueueLength    int   `json:"queue_length"`
	QueueCapacity  int   `json:"queue_capacity"`
	TotalProcessed int64 `json:"total_processed"`
	TotalSucceeded int64 `json:"total_succeeded"`
	TotalFailed    int64 `json:"total_failed"`
	Running        bool  `json:"running"`
}

// worker is the main worker goroutine
func (p *Pool) worker(ctx context.Context, id int) {
	defer p.wg.Done()

	log := p.logger.With("worker_id", id)
	log.Debug("worker started")

	for {
		select {
		case <-ctx.Done():
			log.Debug("worker stopped (context cancelled)")
			return

		case <-p.stopCh:
			log.Debug("worker stopped (pool stopped)")
			return

		case poolJob, ok := <-p.jobChan:
			if !ok {
				log.Debug("worker stopped (channel closed)")
				return
			}

			p.processJob(ctx, log, poolJob)
		}
	}
}

func (p *Pool) processJob(ctx context.Context, log *logger.Logger, poolJob *PoolJob) {
	job := poolJob.Job
	jobLog := log.With("job_id", job.ID, "job_type", job.Type)

	// Get worker
	worker, ok := p.registry.Get(job.Type)
	if !ok {
		jobLog.Error("no worker for job type")
		p.handleCompletion(poolJob, nil, errors.Newf(errors.CodeInternal, "no worker for job type: %s", job.Type))
		return
	}

	// Create cancellable context with timeout
	jobCtx, cancel := context.WithTimeout(ctx, p.config.MaxJobDuration)
	defer cancel()

	// Register cancel function
	p.cancelMu.Lock()
	p.cancelFns[job.ID] = cancel
	p.cancelMu.Unlock()

	defer func() {
		p.cancelMu.Lock()
		delete(p.cancelFns, job.ID)
		p.cancelMu.Unlock()
	}()

	// Create progress callback
	progressFn := func(progress int, message string) {
		if poolJob.OnProgress != nil {
			poolJob.OnProgress(progress, message)
		}
		if p.onProgress != nil {
			p.onProgress(job.ID, progress, message)
		}
	}

	// Execute with panic recovery
	start := time.Now()
	var result interface{}
	var execErr error

	func() {
		defer func() {
			if r := recover(); r != nil {
				execErr = errors.Newf(errors.CodeInternal, "worker panic: %v", r)
				jobLog.Error("worker panic", "panic", r)
			}
		}()

		// Create worker context
		workerCtx := NewWorkerContext(jobCtx, job, progressFn)
		_ = workerCtx // Available for workers that need it

		result, execErr = worker.Execute(jobCtx, job)
	}()

	duration := time.Since(start)
	p.processed.Add(1)

	if execErr != nil {
		p.failed.Add(1)
		jobLog.Error("job failed",
			"error", execErr,
			"duration", duration,
		)
	} else {
		p.succeeded.Add(1)
		jobLog.Info("job completed",
			"duration", duration,
		)
	}

	p.handleCompletion(poolJob, result, execErr)
}

func (p *Pool) handleCompletion(poolJob *PoolJob, result interface{}, err error) {
	// Call job-specific callback
	if poolJob.OnComplete != nil {
		poolJob.OnComplete(result, err)
	}

	// Call global callback
	if p.onComplete != nil {
		p.onComplete(poolJob.Job.ID, result, err)
	}
}

func (p *Pool) cancelAllJobs() {
	p.cancelMu.Lock()
	defer p.cancelMu.Unlock()

	for jobID, cancel := range p.cancelFns {
		p.logger.Debug("cancelling job", "job_id", jobID)
		cancel()
	}
}
