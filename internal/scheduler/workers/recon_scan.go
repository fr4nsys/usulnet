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

// ReconScanService is the narrow contract the ReconScanWorker requires.
// It mirrors the security_scan.go pattern: define the dependency next to
// the consumer, let the real recon.Service satisfy it implicitly.
//
// RunScan must drive the scan to its terminal state (completed/failed)
// and update the recon_scans row itself. The worker treats RunScan as
// authoritative and does not modify the row.
type ReconScanService interface {
	RunScan(ctx context.Context, scanID uuid.UUID) error
}

// ReconScanNotifier is an optional notification hook called by the
// worker when a scan terminates. Implementations should never block the
// worker for long; the production wiring delegates to the scheduler's
// notification worker via an internal queue.
type ReconScanNotifier interface {
	NotifyScanCompleted(ctx context.Context, scanID uuid.UUID, success bool, message string)
}

// ReconScanPayload is the job payload accepted by ReconScanWorker. The
// API/Service that enqueues the job populates it; nothing else writes
// to it.
type ReconScanPayload struct {
	ScanID uuid.UUID `json:"scan_id"`
}

// ReconScanWorker processes recon_scan jobs by delegating to a
// ReconScanService and emitting a single notification event on
// terminal transition.
type ReconScanWorker struct {
	BaseWorker
	service  ReconScanService
	notifier ReconScanNotifier
	logger   *logger.Logger
}

// NewReconScanWorker constructs a worker. A nil notifier is permitted
// — the worker simply skips the notification step.
func NewReconScanWorker(service ReconScanService, notifier ReconScanNotifier, log *logger.Logger) *ReconScanWorker {
	if log == nil {
		log = logger.Nop()
	}
	return &ReconScanWorker{
		BaseWorker: NewBaseWorker(models.JobTypeReconScan),
		service:    service,
		notifier:   notifier,
		logger:     log.Named("recon-scan-worker"),
	}
}

// Execute runs the scan. Per the session-08 contract, the Service has
// already updated the recon_scans row on success and failure, so the
// worker only needs to:
//
//  1. parse the job payload,
//  2. delegate to ReconScanService.RunScan,
//  3. emit a notification event on terminal transition,
//  4. surface a non-nil error so the scheduler records the job
//     outcome correctly.
func (w *ReconScanWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	if w.service == nil {
		return nil, errors.New(errors.CodeInternal, "recon scan worker: no service wired")
	}

	var payload ReconScanPayload
	if err := job.GetPayload(&payload); err != nil {
		return nil, errors.Wrap(err, errors.CodeValidation, "recon scan worker: parse payload")
	}
	if payload.ScanID == uuid.Nil {
		return nil, errors.New(errors.CodeValidation, "recon scan worker: scan_id is required")
	}

	log := w.logger.With(
		"job_id", job.ID,
		"scan_id", payload.ScanID,
	)
	log.Info("recon scan job starting")
	started := time.Now()

	runErr := w.service.RunScan(ctx, payload.ScanID)
	duration := time.Since(started)

	result := &ReconScanResult{
		ScanID:    payload.ScanID,
		StartedAt: started,
		Duration:  duration,
		Success:   runErr == nil,
	}
	if runErr != nil {
		result.Error = runErr.Error()
	}

	if w.notifier != nil {
		msg := "Recon scan completed"
		if runErr != nil {
			msg = "Recon scan failed: " + runErr.Error()
		}
		w.notifier.NotifyScanCompleted(ctx, payload.ScanID, runErr == nil, msg)
	}

	if runErr != nil {
		log.Warn("recon scan job failed",
			"error", runErr,
			"duration", duration,
		)
		return result, errors.Wrap(runErr, errors.CodeInternal, "recon scan worker: run")
	}

	log.Info("recon scan job completed",
		"duration", duration,
	)
	return result, nil
}

// ReconScanResult is the value returned to the scheduler for storage in
// the jobs.result column. Findings live in recon_findings — this
// struct is intentionally a thin summary.
type ReconScanResult struct {
	ScanID    uuid.UUID     `json:"scan_id"`
	StartedAt time.Time     `json:"started_at"`
	Duration  time.Duration `json:"duration"`
	Success   bool          `json:"success"`
	Error     string        `json:"error,omitempty"`
}
