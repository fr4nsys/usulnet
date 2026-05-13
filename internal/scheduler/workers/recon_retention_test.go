// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package workers

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// stubRetentionSvc records every call so the worker's contract can be
// asserted (correct cutoff, correct order, correct audit summary).
type stubRetentionSvc struct {
	mu sync.Mutex

	findingsDeleted int64
	scansDeleted    int64
	auditDeleted    int64
	marked          int64
	swept           int64

	findingsErr error
	scansErr    error
	auditErr    error
	markErr     error
	sweepErr    error
	appendErr   error

	calls         []string
	cutoffSeen    time.Time
	sweepBefore   time.Time
	markNow       time.Time
	auditSummary  ReconRetentionSummary
	auditAppended bool
}

func (s *stubRetentionSvc) DeleteFindingsOlderThan(_ context.Context, cutoff time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "findings")
	s.cutoffSeen = cutoff
	return s.findingsDeleted, s.findingsErr
}
func (s *stubRetentionSvc) DeleteScansOlderThan(_ context.Context, _ time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "scans")
	return s.scansDeleted, s.scansErr
}
func (s *stubRetentionSvc) DeleteAuditOlderThan(_ context.Context, _ time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "audit")
	return s.auditDeleted, s.auditErr
}
func (s *stubRetentionSvc) MarkArtifactsForDeletion(_ context.Context, _ time.Time, now time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "mark")
	s.markNow = now
	return s.marked, s.markErr
}
func (s *stubRetentionSvc) SweepMarkedArtifacts(_ context.Context, before time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "sweep")
	s.sweepBefore = before
	return s.swept, s.sweepErr
}
func (s *stubRetentionSvc) AppendRetentionAudit(_ context.Context, summary ReconRetentionSummary) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "audit_append")
	s.auditSummary = summary
	s.auditAppended = true
	return s.appendErr
}

func mustJob(t *testing.T) *models.Job {
	t.Helper()
	return &models.Job{ID: uuid.New(), Type: models.JobTypeReconRetention}
}

func fixedClock(ts time.Time) func() time.Time {
	return func() time.Time { return ts }
}

// ============================================================================
// Happy path
// ============================================================================

func TestReconRetention_HappyPath_RunsAllPhases(t *testing.T) {
	svc := &stubRetentionSvc{
		findingsDeleted: 7,
		scansDeleted:    3,
		auditDeleted:    99,
		marked:          5,
		swept:           4,
	}
	w := NewReconRetentionWorker(svc, ReconRetentionConfig{RetentionDays: 30, GracePeriodDays: 7}, logger.Nop())
	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	w.SetClock(fixedClock(now))

	res, err := w.Execute(context.Background(), mustJob(t))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	summary, ok := res.(ReconRetentionSummary)
	if !ok {
		t.Fatalf("result type = %T, want ReconRetentionSummary", res)
	}
	if summary.FindingsDeleted != 7 || summary.ScansDeleted != 3 || summary.AuditDeleted != 99 ||
		summary.ArtifactsMarked != 5 || summary.ArtifactsSwept != 4 {
		t.Errorf("summary mismatch: %+v", summary)
	}
	if summary.RetentionDays != 30 || summary.GracePeriodDays != 7 {
		t.Errorf("config not echoed: %+v", summary)
	}
	if !svc.auditAppended {
		t.Error("audit summary not appended")
	}

	wantOrder := []string{"findings", "scans", "mark", "sweep", "audit", "audit_append"}
	if len(svc.calls) != len(wantOrder) {
		t.Fatalf("calls = %v, want %v", svc.calls, wantOrder)
	}
	for i, want := range wantOrder {
		if svc.calls[i] != want {
			t.Errorf("call[%d] = %q, want %q", i, svc.calls[i], want)
		}
	}

	wantCutoff := now.AddDate(0, 0, -30)
	if !svc.cutoffSeen.Equal(wantCutoff) {
		t.Errorf("cutoff = %v, want %v", svc.cutoffSeen, wantCutoff)
	}
	wantSweep := now.AddDate(0, 0, -7)
	if !svc.sweepBefore.Equal(wantSweep) {
		t.Errorf("sweep_before = %v, want %v", svc.sweepBefore, wantSweep)
	}
}

// ============================================================================
// Defaults
// ============================================================================

func TestReconRetention_AppliesPackageDefaults(t *testing.T) {
	svc := &stubRetentionSvc{}
	w := NewReconRetentionWorker(svc, ReconRetentionConfig{}, nil)
	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	w.SetClock(fixedClock(now))

	res, err := w.Execute(context.Background(), mustJob(t))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	summary := res.(ReconRetentionSummary)
	if summary.RetentionDays != DefaultRetentionDays {
		t.Errorf("RetentionDays = %d, want %d", summary.RetentionDays, DefaultRetentionDays)
	}
	if summary.GracePeriodDays != DefaultGracePeriodDays {
		t.Errorf("GracePeriodDays = %d, want %d", summary.GracePeriodDays, DefaultGracePeriodDays)
	}
}

func TestReconRetention_PayloadOverridesDefaults(t *testing.T) {
	svc := &stubRetentionSvc{}
	w := NewReconRetentionWorker(svc, ReconRetentionConfig{RetentionDays: 90, GracePeriodDays: 7}, nil)
	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	w.SetClock(fixedClock(now))

	job := mustJob(t)
	if err := job.SetPayload(ReconRetentionConfig{RetentionDays: 14}); err != nil {
		t.Fatalf("SetPayload: %v", err)
	}
	res, err := w.Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	summary := res.(ReconRetentionSummary)
	if summary.RetentionDays != 14 {
		t.Errorf("RetentionDays = %d, want 14", summary.RetentionDays)
	}
	// Grace fell back to the constructor default.
	if summary.GracePeriodDays != 7 {
		t.Errorf("GracePeriodDays = %d, want 7", summary.GracePeriodDays)
	}
}

// ============================================================================
// Error propagation
// ============================================================================

func TestReconRetention_PartialErrorDoesNotShortCircuit(t *testing.T) {
	svc := &stubRetentionSvc{
		findingsErr: errors.New("boom"),
		scansDeleted: 5,
	}
	w := NewReconRetentionWorker(svc, ReconRetentionConfig{RetentionDays: 30}, logger.Nop())
	w.SetClock(fixedClock(time.Now().UTC()))

	res, err := w.Execute(context.Background(), mustJob(t))
	if err == nil {
		t.Fatal("expected non-nil err when a phase failed")
	}
	summary := res.(ReconRetentionSummary)
	if len(summary.Errors) == 0 {
		t.Error("expected errors slice to be populated")
	}
	// Even though findings failed, scans and downstream phases still ran.
	if summary.ScansDeleted != 5 {
		t.Errorf("ScansDeleted = %d, want 5 — worker should not short-circuit", summary.ScansDeleted)
	}
}

func TestReconRetention_NilService(t *testing.T) {
	w := NewReconRetentionWorker(nil, ReconRetentionConfig{}, nil)
	_, err := w.Execute(context.Background(), mustJob(t))
	if err == nil {
		t.Fatal("expected err with nil service")
	}
}

// ============================================================================
// Type registration
// ============================================================================

func TestReconRetention_RegistersExpectedJobType(t *testing.T) {
	w := NewReconRetentionWorker(&stubRetentionSvc{}, ReconRetentionConfig{}, nil)
	if w.Type() != models.JobTypeReconRetention {
		t.Errorf("Type = %q, want %q", w.Type(), models.JobTypeReconRetention)
	}
}
