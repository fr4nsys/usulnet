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

// SSLScanService is the narrow contract the SSL scan worker needs.
// Satisfied by *sslobservatory.Service. ScanAll fans out across
// every enabled target, respecting the service's per-target
// concurrency cap; ScanTarget runs one target on demand.
type SSLScanService interface {
	ScanAll(ctx context.Context, hostID uuid.UUID) (int, error)
	ScanTarget(ctx context.Context, targetID uuid.UUID) ([]models.SSLScanResult, error)
}

// SSLScanPayload is the job payload accepted by SSLScanWorker.
//
//   - TargetID set: scan exactly that target (manual trigger from the
//     web UI / API).
//   - HostID set, TargetID zero: sweep all enabled targets for the host.
//   - Both zero: sweep every enabled target on every host (the daily
//     scheduled cadence).
type SSLScanPayload struct {
	HostID   uuid.UUID `json:"host_id,omitempty"`
	TargetID uuid.UUID `json:"target_id,omitempty"`
}

// SSLScanResult is the worker's terminal outcome. Returned so the
// scheduler stores a human-readable summary on the jobs row.
type SSLScanResult struct {
	Scope    string        `json:"scope"` // "target" | "host" | "all"
	Scanned  int           `json:"scanned"`
	Duration time.Duration `json:"duration"`
}

// SSLScanWorker drains the ssl_scan job queue. The actual TLS
// handshakes run inside SSLScanService.ScanAll / ScanTarget — this
// worker is purely the scheduling glue.
type SSLScanWorker struct {
	BaseWorker
	service SSLScanService
	logger  *logger.Logger
}

// NewSSLScanWorker constructs a worker.
func NewSSLScanWorker(svc SSLScanService, log *logger.Logger) *SSLScanWorker {
	if log == nil {
		log = logger.Nop()
	}
	return &SSLScanWorker{
		BaseWorker: NewBaseWorker(models.JobTypeSSLScan),
		service:    svc,
		logger:     log.Named("ssl-scan-worker"),
	}
}

// Execute processes one ssl_scan job.
func (w *SSLScanWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	if w.service == nil {
		return nil, errors.New(errors.CodeInternal, "ssl scan worker: no service wired")
	}

	var payload SSLScanPayload
	if err := job.GetPayload(&payload); err != nil {
		return nil, errors.Wrap(err, errors.CodeValidation, "ssl scan worker: parse payload")
	}

	log := w.logger.With("job_id", job.ID)
	started := time.Now()

	// Per-target manual scan.
	if payload.TargetID != uuid.Nil {
		results, err := w.service.ScanTarget(ctx, payload.TargetID)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "ssl scan worker: scan target")
		}
		log.Info("ssl target scan complete",
			"target_id", payload.TargetID,
			"results", len(results),
		)
		return &SSLScanResult{
			Scope:    "target",
			Scanned:  len(results),
			Duration: time.Since(started),
		}, nil
	}

	// Host-scoped or all-hosts sweep — uuid.Nil hostID means "all".
	scanned, err := w.service.ScanAll(ctx, payload.HostID)
	if err != nil {
		// ScanAll is partial-success: scanned may be > 0 even on error.
		// Surface the error so the job row records it, but include
		// the result so the UI shows progress.
		log.Warn("ssl scan worker: scan all returned error",
			"host_id", payload.HostID,
			"scanned", scanned,
			"error", err,
		)
		return &SSLScanResult{
			Scope:    scopeFor(payload.HostID),
			Scanned:  scanned,
			Duration: time.Since(started),
		}, errors.Wrap(err, errors.CodeInternal, "ssl scan worker: scan all")
	}

	log.Info("ssl scan sweep complete",
		"scope", scopeFor(payload.HostID),
		"host_id", payload.HostID,
		"scanned", scanned,
	)
	return &SSLScanResult{
		Scope:    scopeFor(payload.HostID),
		Scanned:  scanned,
		Duration: time.Since(started),
	}, nil
}

func scopeFor(hostID uuid.UUID) string {
	if hostID == uuid.Nil {
		return "all"
	}
	return "host"
}
