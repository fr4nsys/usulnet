// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package workers

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// MetadataJobService is the narrow contract MetadataJobWorker
// consumes. The real *metadata.Implementation satisfies it via its
// RunJob method, which drives the artifact-by-artifact extraction and
// strip and commits the terminal status row.
type MetadataJobService interface {
	RunJob(ctx context.Context, jobID uuid.UUID) error
}

// MetadataJobNotifier is an optional notification hook called by the
// worker when a job terminates. Identical responsibilities to
// ReconScanNotifier (kept separate so future per-domain routing rules
// are straightforward to express).
type MetadataJobNotifier interface {
	NotifyMetadataJobCompleted(ctx context.Context, jobID uuid.UUID, success bool, message string)
}

// MetadataJobPayload is the scheduler payload for a metadata job.
type MetadataJobPayload struct {
	JobID uuid.UUID `json:"job_id"`
}

// MetadataJobWorker processes recon_metadata_jobs.
type MetadataJobWorker struct {
	BaseWorker
	service  MetadataJobService
	notifier MetadataJobNotifier
	logger   *logger.Logger
}

// NewMetadataJobWorker constructs a worker. A nil notifier is
// permitted.
func NewMetadataJobWorker(service MetadataJobService, notifier MetadataJobNotifier, log *logger.Logger) *MetadataJobWorker {
	if log == nil {
		log = logger.Nop()
	}
	return &MetadataJobWorker{
		BaseWorker: NewBaseWorker(models.JobTypeMetadataJob),
		service:    service,
		notifier:   notifier,
		logger:     log.Named("metadata-job-worker"),
	}
}

// Execute delegates to MetadataJobService.RunJob. The service drives
// the on-disk artifact pipeline and persists every transition; the
// worker is a thin envelope that surfaces the outcome to the scheduler
// and emits a notification event.
func (w *MetadataJobWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	if w.service == nil {
		return nil, errors.New(errors.CodeInternal, "metadata job worker: no service wired")
	}

	var payload MetadataJobPayload
	if err := job.GetPayload(&payload); err != nil {
		return nil, errors.Wrap(err, errors.CodeValidation, "metadata job worker: parse payload")
	}
	if payload.JobID == uuid.Nil {
		return nil, errors.New(errors.CodeValidation, "metadata job worker: job_id is required")
	}

	log := w.logger.With(
		"job_id", job.ID,
		"metadata_job_id", payload.JobID,
	)
	log.Info("metadata job starting")
	started := time.Now()

	runErr := w.service.RunJob(ctx, payload.JobID)
	duration := time.Since(started)

	result := &MetadataJobResult{
		MetadataJobID: payload.JobID,
		StartedAt:     started,
		Duration:      duration,
		Success:       runErr == nil,
	}
	if runErr != nil {
		result.Error = runErr.Error()
	}

	if w.notifier != nil {
		msg := "Metadata job completed"
		if runErr != nil {
			msg = "Metadata job failed: " + runErr.Error()
		}
		w.notifier.NotifyMetadataJobCompleted(ctx, payload.JobID, runErr == nil, msg)
	}

	if runErr != nil {
		log.Warn("metadata job failed",
			"error", runErr,
			"duration", duration,
		)
		return result, errors.Wrap(runErr, errors.CodeInternal, "metadata job worker: run")
	}

	log.Info("metadata job completed",
		"duration", duration,
	)
	return result, nil
}

// MetadataJobResult is the value persisted to jobs.result on success.
// The actual artifacts and extracted metadata live in
// recon_metadata_artifacts.
type MetadataJobResult struct {
	MetadataJobID uuid.UUID     `json:"metadata_job_id"`
	StartedAt     time.Time     `json:"started_at"`
	Duration      time.Duration `json:"duration"`
	Success       bool          `json:"success"`
	Error         string        `json:"error,omitempty"`
}
