// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	redisclient "github.com/fr4nsys/usulnet/internal/repository/redis"
)

const (
	// Redis key prefixes
	keyPrefixJobQueue    = "usulnet:jobs:queue"
	keyPrefixJobData     = "usulnet:jobs:data"
	keyPrefixJobRunning  = "usulnet:jobs:running"
	keyPrefixJobDead     = "usulnet:jobs:dead"
	keyPrefixJobSchedule = "usulnet:jobs:schedule"

	// Queue names by priority
	queueCritical = "critical"
	queueHigh     = "high"
	queueNormal   = "normal"
	queueLow      = "low"

	// Default timeouts
	defaultVisibilityTimeout = 5 * time.Minute
	defaultJobTTL            = 24 * time.Hour
	deadLetterTTL            = 7 * 24 * time.Hour
)

// Queue manages job queuing with Redis backing
type Queue struct {
	client            *redisclient.Client
	logger            *logger.Logger
	visibilityTimeout time.Duration
}

// QueueConfig holds queue configuration
type QueueConfig struct {
	VisibilityTimeout time.Duration
}

// DefaultQueueConfig returns default queue configuration
func DefaultQueueConfig() *QueueConfig {
	return &QueueConfig{
		VisibilityTimeout: defaultVisibilityTimeout,
	}
}

// NewQueue creates a new Redis-backed job queue
func NewQueue(client *redisclient.Client, log *logger.Logger, config *QueueConfig) *Queue {
	if config == nil {
		config = DefaultQueueConfig()
	}

	if log == nil {
		log = logger.Nop()
	}

	return &Queue{
		client:            client,
		logger:            log.Named("queue"),
		visibilityTimeout: config.VisibilityTimeout,
	}
}

// Enqueue adds a job to the queue
func (q *Queue) Enqueue(ctx context.Context, job *models.Job) error {
	if job.ID == uuid.Nil {
		job.ID = uuid.New()
	}

	if job.Status == "" {
		job.Status = models.JobStatusPending
	}

	if job.Priority == 0 {
		job.Priority = models.JobPriorityNormal
	}

	if job.MaxAttempts == 0 {
		job.MaxAttempts = 3
	}

	job.CreatedAt = time.Now()
	job.UpdatedAt = time.Now()

	// Serialize job data
	data, err := json.Marshal(job)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to marshal job")
	}

	// Store job data
	dataKey := q.jobDataKey(job.ID)
	if err := q.client.Redis().Set(ctx, dataKey, data, defaultJobTTL).Err(); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to store job data")
	}

	// Determine queue based on priority
	queueKey := q.queueKey(job.Priority)

	// Calculate score (for scheduled jobs or immediate)
	var score float64
	if job.ScheduledAt != nil && job.ScheduledAt.After(time.Now()) {
		score = float64(job.ScheduledAt.UnixNano())
	} else {
		score = float64(time.Now().UnixNano())
	}

	// Add to sorted set queue
	if err := q.client.Redis().ZAdd(ctx, queueKey, redis.Z{
		Score:  score,
		Member: job.ID.String(),
	}).Err(); err != nil {
		// Cleanup data key on failure
		q.client.Redis().Del(ctx, dataKey)
		return errors.Wrap(err, errors.CodeInternal, "failed to enqueue job")
	}

	q.logger.Debug("job enqueued",
		"job_id", job.ID,
		"type", job.Type,
		"priority", job.Priority,
	)

	return nil
}

// Dequeue retrieves the next job from the queue
// Returns nil if no jobs are available
func (q *Queue) Dequeue(ctx context.Context) (*models.Job, error) {
	// Check queues in priority order
	queues := []string{
		q.queueKey(models.JobPriorityCritical),
		q.queueKey(models.JobPriorityHigh),
		q.queueKey(models.JobPriorityNormal),
		q.queueKey(models.JobPriorityLow),
	}

	now := float64(time.Now().UnixNano())

	for _, queueKey := range queues {
		// Get jobs that are ready (score <= now)
		results, err := q.client.Redis().ZRangeByScoreWithScores(ctx, queueKey, &redis.ZRangeBy{
			Min:    "-inf",
			Max:    fmt.Sprintf("%f", now),
			Offset: 0,
			Count:  1,
		}).Result()

		if err != nil {
			q.logger.Error("failed to check queue", "queue", queueKey, "error", err)
			continue
		}

		if len(results) == 0 {
			continue
		}

		jobIDStr := results[0].Member.(string)
		jobID, err := uuid.Parse(jobIDStr)
		if err != nil {
			q.logger.Error("invalid job ID in queue", "job_id", jobIDStr, "error", err)
			// Remove invalid entry
			q.client.Redis().ZRem(ctx, queueKey, jobIDStr)
			continue
		}

		// Atomic move to running set with visibility timeout
		moved, err := q.atomicMoveToRunning(ctx, queueKey, jobID)
		if err != nil {
			q.logger.Error("failed to move job to running", "job_id", jobID, "error", err)
			continue
		}

		if !moved {
			// Another worker got it, try next
			continue
		}

		// Get job data
		job, err := q.GetJob(ctx, jobID)
		if err != nil {
			q.logger.Error("failed to get job data", "job_id", jobID, "error", err)
			// Move back to queue
			q.requeueJob(ctx, jobID)
			continue
		}

		// Update status
		job.Status = models.JobStatusRunning
		job.Attempts++
		now := time.Now()
		job.StartedAt = &now
		job.UpdatedAt = now

		if err := q.updateJobData(ctx, job); err != nil {
			q.logger.Error("failed to update job status", "job_id", jobID, "error", err)
		}

		q.logger.Debug("job dequeued",
			"job_id", job.ID,
			"type", job.Type,
			"attempt", job.Attempts,
		)

		return job, nil
	}

	return nil, nil
}

// Complete marks a job as completed
func (q *Queue) Complete(ctx context.Context, jobID uuid.UUID, result interface{}) error {
	job, err := q.GetJob(ctx, jobID)
	if err != nil {
		return err
	}

	job.Status = models.JobStatusCompleted
	now := time.Now()
	job.CompletedAt = &now
	job.UpdatedAt = now
	job.Progress = 100

	if result != nil {
		if err := job.SetResult(result); err != nil {
			q.logger.Warn("failed to set job result", "job_id", jobID, "error", err)
		}
	}

	// Update job data
	if err := q.updateJobData(ctx, job); err != nil {
		return err
	}

	// Remove from running set
	runningKey := q.runningKey()
	q.client.Redis().ZRem(ctx, runningKey, jobID.String())

	q.logger.Debug("job completed",
		"job_id", jobID,
		"type", job.Type,
		"duration", job.Duration(),
	)

	return nil
}

// Fail marks a job as failed
func (q *Queue) Fail(ctx context.Context, jobID uuid.UUID, jobErr error) error {
	job, err := q.GetJob(ctx, jobID)
	if err != nil {
		return err
	}

	errMsg := jobErr.Error()
	job.ErrorMessage = &errMsg
	job.UpdatedAt = time.Now()

	// Check if can retry
	if job.CanRetry() {
		job.Status = models.JobStatusRetrying

		// Calculate backoff delay
		backoff := q.calculateBackoff(job.Attempts)

		// Re-enqueue with delay
		scheduledAt := time.Now().Add(backoff)
		job.ScheduledAt = &scheduledAt

		if err := q.updateJobData(ctx, job); err != nil {
			return err
		}

		// Remove from running
		runningKey := q.runningKey()
		q.client.Redis().ZRem(ctx, runningKey, jobID.String())

		// Add back to queue
		queueKey := q.queueKey(job.Priority)
		q.client.Redis().ZAdd(ctx, queueKey, redis.Z{
			Score:  float64(scheduledAt.UnixNano()),
			Member: jobID.String(),
		})

		q.logger.Debug("job scheduled for retry",
			"job_id", jobID,
			"attempt", job.Attempts,
			"max_attempts", job.MaxAttempts,
			"retry_at", scheduledAt,
		)
	} else {
		// Move to dead letter queue
		job.Status = models.JobStatusFailed
		now := time.Now()
		job.CompletedAt = &now

		if err := q.updateJobData(ctx, job); err != nil {
			return err
		}

		// Remove from running
		runningKey := q.runningKey()
		q.client.Redis().ZRem(ctx, runningKey, jobID.String())

		// Add to dead letter queue
		deadKey := q.deadLetterKey()
		q.client.Redis().ZAdd(ctx, deadKey, redis.Z{
			Score:  float64(time.Now().UnixNano()),
			Member: jobID.String(),
		})

		// Set TTL on job data
		dataKey := q.jobDataKey(jobID)
		q.client.Redis().Expire(ctx, dataKey, deadLetterTTL)

		q.logger.Warn("job moved to dead letter queue",
			"job_id", jobID,
			"type", job.Type,
			"attempts", job.Attempts,
			"error", errMsg,
		)
	}

	return nil
}

// Cancel cancels a pending or running job
func (q *Queue) Cancel(ctx context.Context, jobID uuid.UUID) error {
	job, err := q.GetJob(ctx, jobID)
	if err != nil {
		return err
	}

	if job.IsFinished() {
		return errors.New(errors.CodeValidation, "cannot cancel finished job")
	}

	job.Status = models.JobStatusCancelled
	now := time.Now()
	job.CompletedAt = &now
	job.UpdatedAt = now

	if err := q.updateJobData(ctx, job); err != nil {
		return err
	}

	// Remove from all queues
	q.removeFromAllQueues(ctx, jobID)

	q.logger.Debug("job cancelled", "job_id", jobID)

	return nil
}

// UpdateProgress updates job progress
func (q *Queue) UpdateProgress(ctx context.Context, jobID uuid.UUID, progress int, message string) error {
	job, err := q.GetJob(ctx, jobID)
	if err != nil {
		return err
	}

	job.Progress = progress
	if message != "" {
		job.ProgressMessage = &message
	}
	job.UpdatedAt = time.Now()

	// Extend visibility timeout while making progress
	runningKey := q.runningKey()
	newTimeout := float64(time.Now().Add(q.visibilityTimeout).UnixNano())
	q.client.Redis().ZAdd(ctx, runningKey, redis.Z{
		Score:  newTimeout,
		Member: jobID.String(),
	})

	return q.updateJobData(ctx, job)
}

// GetJob retrieves a job by ID
func (q *Queue) GetJob(ctx context.Context, jobID uuid.UUID) (*models.Job, error) {
	dataKey := q.jobDataKey(jobID)

	data, err := q.client.Redis().Get(ctx, dataKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, errors.New(errors.CodeNotFound, "job not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get job data")
	}

	var job models.Job
	if err := json.Unmarshal(data, &job); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to unmarshal job")
	}

	return &job, nil
}

// GetQueueStats returns queue statistics
func (q *Queue) GetQueueStats(ctx context.Context) (*QueueStats, error) {
	stats := &QueueStats{
		QueueLengths: make(map[string]int64),
	}

	// Count jobs in each priority queue
	for _, priority := range []models.JobPriority{
		models.JobPriorityCritical,
		models.JobPriorityHigh,
		models.JobPriorityNormal,
		models.JobPriorityLow,
	} {
		queueKey := q.queueKey(priority)
		count, err := q.client.Redis().ZCard(ctx, queueKey).Result()
		if err != nil {
			q.logger.Error("failed to get queue length", "queue", queueKey, "error", err)
			continue
		}
		stats.QueueLengths[priorityName(priority)] = count
		stats.TotalPending += count
	}

	// Count running jobs
	runningKey := q.runningKey()
	running, err := q.client.Redis().ZCard(ctx, runningKey).Result()
	if err == nil {
		stats.Running = running
	}

	// Count dead letter jobs
	deadKey := q.deadLetterKey()
	dead, err := q.client.Redis().ZCard(ctx, deadKey).Result()
	if err == nil {
		stats.DeadLetter = dead
	}

	return stats, nil
}

// RecoverStaleJobs recovers jobs that have exceeded visibility timeout
func (q *Queue) RecoverStaleJobs(ctx context.Context) (int, error) {
	runningKey := q.runningKey()
	now := float64(time.Now().UnixNano())

	// Find jobs past visibility timeout
	stale, err := q.client.Redis().ZRangeByScore(ctx, runningKey, &redis.ZRangeBy{
		Min: "-inf",
		Max: fmt.Sprintf("%f", now),
	}).Result()

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternal, "failed to get stale jobs")
	}

	recovered := 0
	for _, jobIDStr := range stale {
		jobID, err := uuid.Parse(jobIDStr)
		if err != nil {
			continue
		}

		q.logger.Warn("recovering stale job", "job_id", jobID)

		// Re-queue the job
		if err := q.requeueJob(ctx, jobID); err != nil {
			q.logger.Error("failed to requeue stale job", "job_id", jobID, "error", err)
			continue
		}

		recovered++
	}

	return recovered, nil
}

// CleanupDeadLetterQueue removes old jobs from dead letter queue
func (q *Queue) CleanupDeadLetterQueue(ctx context.Context, maxAge time.Duration) (int64, error) {
	deadKey := q.deadLetterKey()
	cutoff := float64(time.Now().Add(-maxAge).UnixNano())

	// Get jobs to remove
	toRemove, err := q.client.Redis().ZRangeByScore(ctx, deadKey, &redis.ZRangeBy{
		Min: "-inf",
		Max: fmt.Sprintf("%f", cutoff),
	}).Result()

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternal, "failed to get old dead letter jobs")
	}

	if len(toRemove) == 0 {
		return 0, nil
	}

	// Remove job data
	for _, jobIDStr := range toRemove {
		jobID, err := uuid.Parse(jobIDStr)
		if err != nil {
			continue
		}
		dataKey := q.jobDataKey(jobID)
		q.client.Redis().Del(ctx, dataKey)
	}

	// Remove from dead letter queue
	removed, err := q.client.Redis().ZRemRangeByScore(ctx, deadKey, "-inf", fmt.Sprintf("%f", cutoff)).Result()
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternal, "failed to remove old dead letter jobs")
	}

	return removed, nil
}

// ============================================================================
// Internal helpers
// ============================================================================

func (q *Queue) queueKey(priority models.JobPriority) string {
	return fmt.Sprintf("%s:%s", keyPrefixJobQueue, priorityName(priority))
}

func (q *Queue) jobDataKey(jobID uuid.UUID) string {
	return fmt.Sprintf("%s:%s", keyPrefixJobData, jobID.String())
}

func (q *Queue) runningKey() string {
	return keyPrefixJobRunning
}

func (q *Queue) deadLetterKey() string {
	return keyPrefixJobDead
}

func priorityName(p models.JobPriority) string {
	switch p {
	case models.JobPriorityCritical:
		return queueCritical
	case models.JobPriorityHigh:
		return queueHigh
	case models.JobPriorityNormal:
		return queueNormal
	case models.JobPriorityLow:
		return queueLow
	default:
		return queueNormal
	}
}

func (q *Queue) atomicMoveToRunning(ctx context.Context, queueKey string, jobID uuid.UUID) (bool, error) {
	script := redis.NewScript(`
		local removed = redis.call('ZREM', KEYS[1], ARGV[1])
		if removed == 1 then
			redis.call('ZADD', KEYS[2], ARGV[2], ARGV[1])
			return 1
		end
		return 0
	`)

	runningKey := q.runningKey()
	visibilityScore := float64(time.Now().Add(q.visibilityTimeout).UnixNano())

	result, err := script.Run(ctx, q.client.Redis(), []string{queueKey, runningKey},
		jobID.String(), visibilityScore).Int()

	if err != nil {
		return false, err
	}

	return result == 1, nil
}

func (q *Queue) updateJobData(ctx context.Context, job *models.Job) error {
	data, err := json.Marshal(job)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to marshal job")
	}

	dataKey := q.jobDataKey(job.ID)
	return q.client.Redis().Set(ctx, dataKey, data, defaultJobTTL).Err()
}

func (q *Queue) requeueJob(ctx context.Context, jobID uuid.UUID) error {
	job, err := q.GetJob(ctx, jobID)
	if err != nil {
		return err
	}

	// Remove from running
	runningKey := q.runningKey()
	q.client.Redis().ZRem(ctx, runningKey, jobID.String())

	// Reset status
	job.Status = models.JobStatusPending
	job.StartedAt = nil

	// Add back to appropriate queue
	queueKey := q.queueKey(job.Priority)
	score := float64(time.Now().UnixNano())

	if err := q.updateJobData(ctx, job); err != nil {
		return err
	}

	return q.client.Redis().ZAdd(ctx, queueKey, redis.Z{
		Score:  score,
		Member: jobID.String(),
	}).Err()
}

func (q *Queue) removeFromAllQueues(ctx context.Context, jobID uuid.UUID) {
	jobIDStr := jobID.String()

	// Remove from all priority queues
	for _, priority := range []models.JobPriority{
		models.JobPriorityCritical,
		models.JobPriorityHigh,
		models.JobPriorityNormal,
		models.JobPriorityLow,
	} {
		q.client.Redis().ZRem(ctx, q.queueKey(priority), jobIDStr)
	}

	// Remove from running
	q.client.Redis().ZRem(ctx, q.runningKey(), jobIDStr)
}

func (q *Queue) calculateBackoff(attempt int) time.Duration {
	// Exponential backoff: 10s, 30s, 90s, 270s, ...
	base := 10 * time.Second
	for i := 1; i < attempt; i++ {
		base *= 3
	}

	// Cap at 1 hour
	if base > time.Hour {
		base = time.Hour
	}

	return base
}

// QueueStats holds queue statistics
type QueueStats struct {
	TotalPending int64            `json:"total_pending"`
	Running      int64            `json:"running"`
	DeadLetter   int64            `json:"dead_letter"`
	QueueLengths map[string]int64 `json:"queue_lengths"`
}
