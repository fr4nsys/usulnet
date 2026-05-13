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

// ReconRetentionService is the narrow contract ReconRetentionWorker
// consumes. The implementation lives in
// internal/repository/postgres.ReconRetentionRepository; defining the
// interface next to the worker keeps the worker package self-contained
// and lets the unit tests drop in a counting double instead of a real
// PostgreSQL repo.
//
// The contract is intentionally split into three phases so the
// security review can assert "the worker only deletes what it should":
//
//  1. DeleteFindingsOlderThan / DeleteScansOlderThan / DeleteAuditOlderThan
//     remove rows older than the configured retention window.
//  2. MarkArtifactsForDeletion flags metadata artifacts whose owning
//     job finished before the cutoff. The on-disk file stays put so a
//     mistake is recoverable.
//  3. SweepMarkedArtifacts deletes rows + on-disk files for artifacts
//     marked at least GracePeriodDays ago.
//
// Every deletion appends to recon_audit_log via AppendAudit. The
// retention.delete action is the only DELETE-adjacent write the
// repository ever performs — every other entry is an INSERT.
type ReconRetentionService interface {
	DeleteFindingsOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
	DeleteScansOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
	DeleteAuditOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
	MarkArtifactsForDeletion(ctx context.Context, cutoff time.Time, now time.Time) (int64, error)
	SweepMarkedArtifacts(ctx context.Context, before time.Time) (int64, error)
	AppendRetentionAudit(ctx context.Context, summary ReconRetentionSummary) error
}

// ReconRetentionConfig is the per-run configuration of the worker. All
// fields have defaults the worker applies when zero so a freshly
// inserted recon retention scheduled-job needs no payload.
type ReconRetentionConfig struct {
	// RetentionDays bounds findings + scans + audit rows. Default: 90.
	RetentionDays int `json:"retention_days,omitempty"`

	// GracePeriodDays is the delay between MarkArtifactsForDeletion
	// (phase 1) and SweepMarkedArtifacts (phase 2). Default: 7.
	GracePeriodDays int `json:"grace_period_days,omitempty"`
}

// DefaultRetentionDays matches cfg.Recon.RetentionDays' documented
// default (90 days). Kept as a package constant so unit tests can
// assert the worker's chosen cutoff.
const DefaultRetentionDays = 90

// DefaultGracePeriodDays is the canonical 7-day grace window for the
// two-phase metadata-artifact delete.
const DefaultGracePeriodDays = 7

// ReconRetentionSummary is both the worker's return value and the
// payload appended to recon_audit_log on every run. Fields are flat
// so a downstream operator can grep `details->>'findings_deleted'`
// for trending without parsing nested JSON.
type ReconRetentionSummary struct {
	StartedAt          time.Time     `json:"started_at"`
	CompletedAt        time.Time     `json:"completed_at"`
	Duration           time.Duration `json:"duration"`
	RetentionDays      int           `json:"retention_days"`
	GracePeriodDays    int           `json:"grace_period_days"`
	FindingsDeleted    int64         `json:"findings_deleted"`
	ScansDeleted       int64         `json:"scans_deleted"`
	AuditDeleted       int64         `json:"audit_deleted"`
	ArtifactsMarked    int64         `json:"artifacts_marked"`
	ArtifactsSwept     int64         `json:"artifacts_swept"`
	Errors             []string      `json:"errors,omitempty"`
}

// ReconRetentionWorker prunes recon data according to the configured
// retention policy. Runs daily via the existing cron-backed
// scheduled-jobs pipeline (see ensureReconRetentionScheduledJob in
// internal/app/app.go).
type ReconRetentionWorker struct {
	BaseWorker
	svc           ReconRetentionService
	defaultCfg    ReconRetentionConfig
	clock         func() time.Time
	logger        *logger.Logger
}

// NewReconRetentionWorker constructs a worker. Pass defaultCfg with
// the configured cfg.Recon.RetentionDays so a scheduled job without a
// payload still inherits the operator-configured window. A nil service
// is rejected at Execute (not in the constructor) so the worker can
// register with a half-wired app and surface the misconfiguration
// loudly on the next tick.
func NewReconRetentionWorker(svc ReconRetentionService, defaultCfg ReconRetentionConfig, log *logger.Logger) *ReconRetentionWorker {
	if log == nil {
		log = logger.Nop()
	}
	return &ReconRetentionWorker{
		BaseWorker: NewBaseWorker(models.JobTypeReconRetention),
		svc:        svc,
		defaultCfg: defaultCfg,
		clock:      time.Now,
		logger:     log.Named("recon-retention-worker"),
	}
}

// withDefaults fills zero fields in c from the worker's defaults and
// the package-level constants. Callable on a value receiver because
// the result is returned, not mutated.
func (w *ReconRetentionWorker) withDefaults(c ReconRetentionConfig) ReconRetentionConfig {
	if c.RetentionDays <= 0 {
		c.RetentionDays = w.defaultCfg.RetentionDays
	}
	if c.RetentionDays <= 0 {
		c.RetentionDays = DefaultRetentionDays
	}
	if c.GracePeriodDays <= 0 {
		c.GracePeriodDays = w.defaultCfg.GracePeriodDays
	}
	if c.GracePeriodDays <= 0 {
		c.GracePeriodDays = DefaultGracePeriodDays
	}
	return c
}

// Execute is the scheduler-facing entry point. It parses the optional
// payload, runs the three phases sequentially, and writes one audit
// row summarising the outcome. The audit write is best-effort: if the
// audit insert fails the worker logs the error but still reports
// success on its actual deletions, which is what got persisted.
func (w *ReconRetentionWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	if w.svc == nil {
		return nil, errors.New(errors.CodeInternal, "recon retention worker: no service wired")
	}

	var payload ReconRetentionConfig
	if err := job.GetPayload(&payload); err != nil {
		w.logger.Debug("no payload, using defaults")
	}
	cfg := w.withDefaults(payload)

	now := w.clock().UTC()
	cutoff := now.AddDate(0, 0, -cfg.RetentionDays)
	sweepBefore := now.AddDate(0, 0, -cfg.GracePeriodDays)

	log := w.logger.With(
		"job_id", job.ID,
		"retention_days", cfg.RetentionDays,
		"grace_period_days", cfg.GracePeriodDays,
		"cutoff", cutoff.Format(time.RFC3339),
		"sweep_before", sweepBefore.Format(time.RFC3339),
	)
	log.Info("recon retention starting")

	summary := ReconRetentionSummary{
		StartedAt:       now,
		RetentionDays:   cfg.RetentionDays,
		GracePeriodDays: cfg.GracePeriodDays,
	}

	// Phase 0: row-level deletes on findings and scans. Order matters
	// because findings reference scans, but recon_scans has ON DELETE
	// CASCADE on findings (migration 044); the order below is the
	// least-surprise one for an operator reading the audit log.

	if n, err := w.svc.DeleteFindingsOlderThan(ctx, cutoff); err != nil {
		summary.Errors = append(summary.Errors, "findings: "+err.Error())
		log.Warn("delete findings failed", "error", err)
	} else {
		summary.FindingsDeleted = n
		log.Info("findings deleted", "rows", n)
	}

	if n, err := w.svc.DeleteScansOlderThan(ctx, cutoff); err != nil {
		summary.Errors = append(summary.Errors, "scans: "+err.Error())
		log.Warn("delete scans failed", "error", err)
	} else {
		summary.ScansDeleted = n
		log.Info("scans deleted", "rows", n)
	}

	// Phase 1: mark old metadata artifacts. Phase 2: sweep marks that
	// have exceeded the grace period. The two phases are intentionally
	// done in the same run — the grace window is measured in days,
	// far longer than a single retention run.

	if n, err := w.svc.MarkArtifactsForDeletion(ctx, cutoff, now); err != nil {
		summary.Errors = append(summary.Errors, "mark_artifacts: "+err.Error())
		log.Warn("mark artifacts failed", "error", err)
	} else {
		summary.ArtifactsMarked = n
		log.Info("artifacts marked for deletion", "rows", n)
	}

	if n, err := w.svc.SweepMarkedArtifacts(ctx, sweepBefore); err != nil {
		summary.Errors = append(summary.Errors, "sweep_artifacts: "+err.Error())
		log.Warn("sweep artifacts failed", "error", err)
	} else {
		summary.ArtifactsSwept = n
		log.Info("artifacts swept", "rows", n)
	}

	// Phase 3: audit log rows. Done last so an audit-table failure in
	// the row-delete step still leaves enough evidence behind. The
	// retention window for the audit log matches the rest.
	if n, err := w.svc.DeleteAuditOlderThan(ctx, cutoff); err != nil {
		summary.Errors = append(summary.Errors, "audit: "+err.Error())
		log.Warn("delete audit failed", "error", err)
	} else {
		summary.AuditDeleted = n
		log.Info("audit rows deleted", "rows", n)
	}

	summary.CompletedAt = w.clock().UTC()
	summary.Duration = summary.CompletedAt.Sub(summary.StartedAt)

	// Append a single audit row summarising the run. Failures here
	// are non-fatal; the deletions already happened.
	if err := w.svc.AppendRetentionAudit(ctx, summary); err != nil {
		log.Warn("audit append failed", "error", err)
	}

	if len(summary.Errors) > 0 {
		log.Warn("recon retention completed with errors",
			"errors", summary.Errors,
		)
		return summary, errors.New(errors.CodeInternal, "recon retention had errors: "+summary.Errors[0])
	}

	log.Info("recon retention completed",
		"duration", summary.Duration,
		"findings_deleted", summary.FindingsDeleted,
		"scans_deleted", summary.ScansDeleted,
		"audit_deleted", summary.AuditDeleted,
		"artifacts_marked", summary.ArtifactsMarked,
		"artifacts_swept", summary.ArtifactsSwept,
	)
	return summary, nil
}

// SetClock overrides time.Now for tests so the worker's cutoff
// boundaries are deterministic.
func (w *ReconRetentionWorker) SetClock(clock func() time.Time) {
	if clock != nil {
		w.clock = clock
	}
}

// Compile-time guarantee: the worker satisfies Worker.
var _ Worker = (*ReconRetentionWorker)(nil)

// jobIDOrNew returns job.ID or a fresh uuid; only used by the audit
// summary stamp when the scheduler passes a nil-id job.
func jobIDOrNew(id uuid.UUID) uuid.UUID {
	if id == uuid.Nil {
		return uuid.New()
	}
	return id
}
