// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package calendar

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ============================================================================
// Mocks for BackupLister and ScheduledJobLister
// ============================================================================

type mockBackupLister struct {
	runs      []*models.Backup
	total     int64
	schedules []*models.BackupSchedule
	err       error
	lastOpts  models.BackupListOptions
}

func (m *mockBackupLister) List(ctx context.Context, opts models.BackupListOptions) ([]*models.Backup, int64, error) {
	m.lastOpts = opts
	if m.err != nil {
		return nil, 0, m.err
	}
	return m.runs, m.total, nil
}

func (m *mockBackupLister) ListSchedules(ctx context.Context, hostID *uuid.UUID) ([]*models.BackupSchedule, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.schedules, nil
}

type mockJobLister struct {
	jobs []*models.ScheduledJob
	err  error
}

func (m *mockJobLister) ListScheduledJobs(ctx context.Context, enabled *bool) ([]*models.ScheduledJob, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.jobs, nil
}

// ============================================================================
// BackupSource tests
// ============================================================================

func TestBackupSourceName(t *testing.T) {
	src := NewBackupSource(nil)
	if src.Name() != "backup" {
		t.Fatalf("expected name 'backup', got %q", src.Name())
	}
}

func TestBackupSourceNilLister(t *testing.T) {
	src := NewBackupSource(nil)
	got, err := src.ListEvents(context.Background(), uuid.New(), models.CalendarRange{From: time.Now(), To: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("expected nil error for nil lister, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil events, got %d", len(got))
	}
}

func TestBackupSourceTranslatesRuns(t *testing.T) {
	hostID := uuid.New()
	now := time.Now().UTC()
	start := now.Add(-time.Hour)
	end := now.Add(-30 * time.Minute)

	failed := models.BackupStatusFailed
	b1 := &models.Backup{
		ID:          uuid.New(),
		HostID:      hostID,
		TargetName:  "vol1",
		Status:      models.BackupStatusCompleted,
		StartedAt:   &start,
		CompletedAt: &end,
	}
	b2 := &models.Backup{
		ID:         uuid.New(),
		HostID:     hostID,
		TargetName: "vol2",
		Status:     failed,
		StartedAt:  &start,
	}
	// Backup without StartedAt should be filtered out.
	b3 := &models.Backup{
		ID:         uuid.New(),
		HostID:     hostID,
		TargetName: "vol3",
		Status:     models.BackupStatusPending,
	}

	m := &mockBackupLister{runs: []*models.Backup{b1, b2, b3}}
	src := NewBackupSource(m)

	got, err := src.ListEvents(context.Background(), hostID, models.CalendarRange{
		From: now.Add(-2 * time.Hour),
		To:   now,
	})
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 translated runs, got %d", len(got))
	}
	for _, e := range got {
		if e.Source != models.CalendarSourceBackup {
			t.Errorf("expected Source=backup, got %q", e.Source)
		}
		if e.Kind != models.CalendarKindBackup {
			t.Errorf("expected Kind=backup, got %q", e.Kind)
		}
	}
}

func TestBackupSourceScheduledWindows(t *testing.T) {
	hostID := uuid.New()
	now := time.Now().UTC()
	future := now.Add(time.Hour)

	m := &mockBackupLister{
		schedules: []*models.BackupSchedule{
			{
				ID:         uuid.New(),
				HostID:     hostID,
				TargetName: "vol1",
				IsEnabled:  true,
				NextRunAt:  &future,
			},
			// Disabled — should be skipped.
			{
				ID:         uuid.New(),
				HostID:     hostID,
				TargetName: "vol2",
				IsEnabled:  false,
				NextRunAt:  &future,
			},
			// No NextRunAt — should be skipped.
			{
				ID:         uuid.New(),
				HostID:     hostID,
				TargetName: "vol3",
				IsEnabled:  true,
			},
		},
	}
	src := NewBackupSource(m)
	got, err := src.ListEvents(context.Background(), hostID, models.CalendarRange{
		From: now,
		To:   now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 scheduled-backup event, got %d", len(got))
	}
	if got[0].Title != "Scheduled backup: vol1" {
		t.Errorf("expected 'Scheduled backup: vol1', got %q", got[0].Title)
	}
}

func TestBackupSourcePropagatesError(t *testing.T) {
	src := NewBackupSource(&mockBackupLister{err: stderrors.New("db down")})
	if _, err := src.ListEvents(context.Background(), uuid.New(), models.CalendarRange{
		From: time.Now(), To: time.Now().Add(time.Hour),
	}); err == nil {
		t.Fatal("expected error to propagate")
	}
}

// ============================================================================
// ScheduledJobSource tests
// ============================================================================

func TestScheduledJobSourceName(t *testing.T) {
	src := NewScheduledJobSource(nil)
	if src.Name() != "scheduled_job" {
		t.Fatalf("expected name 'scheduled_job', got %q", src.Name())
	}
}

func TestScheduledJobSourceFiltersByHost(t *testing.T) {
	hostA := uuid.New()
	hostB := uuid.New()
	future := time.Now().UTC().Add(time.Hour)

	m := &mockJobLister{
		jobs: []*models.ScheduledJob{
			// Match host.
			{ID: uuid.New(), Name: "job-a", HostID: &hostA, NextRunAt: &future, IsEnabled: true},
			// Different host.
			{ID: uuid.New(), Name: "job-b", HostID: &hostB, NextRunAt: &future, IsEnabled: true},
			// No host (global) — should match any host.
			{ID: uuid.New(), Name: "job-c", NextRunAt: &future, IsEnabled: true},
			// No NextRunAt — should be skipped.
			{ID: uuid.New(), Name: "job-d", HostID: &hostA, IsEnabled: true},
		},
	}
	src := NewScheduledJobSource(m)
	got, err := src.ListEvents(context.Background(), hostA, models.CalendarRange{
		From: time.Now().UTC(),
		To:   time.Now().UTC().Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 events (hostA + global), got %d", len(got))
	}
}

func TestScheduledJobSourceNilLister(t *testing.T) {
	src := NewScheduledJobSource(nil)
	got, err := src.ListEvents(context.Background(), uuid.New(), models.CalendarRange{
		From: time.Now(), To: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("expected nil error for nil lister, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil events, got %d", len(got))
	}
}

func TestScheduledJobSourcePropagatesError(t *testing.T) {
	src := NewScheduledJobSource(&mockJobLister{err: stderrors.New("boom")})
	if _, err := src.ListEvents(context.Background(), uuid.New(), models.CalendarRange{
		From: time.Now(), To: time.Now().Add(time.Hour),
	}); err == nil {
		t.Fatal("expected error to propagate")
	}
}
