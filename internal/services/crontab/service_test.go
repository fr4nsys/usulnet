// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package crontab

import (
	"context"
	stderrors "errors"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ----------------------------------------------------------------------------
// In-memory mock repositories
// ----------------------------------------------------------------------------

type mockEntryRepo struct {
	mu      sync.Mutex
	entries map[uuid.UUID]*models.CrontabEntry
}

func newMockEntryRepo() *mockEntryRepo {
	return &mockEntryRepo{entries: map[uuid.UUID]*models.CrontabEntry{}}
}

func (r *mockEntryRepo) Create(_ context.Context, e *models.CrontabEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *e
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	cp.UpdatedAt = cp.CreatedAt
	r.entries[cp.ID] = &cp
	return nil
}

func (r *mockEntryRepo) GetByID(_ context.Context, id uuid.UUID) (*models.CrontabEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[id]
	if !ok {
		return nil, stderrors.New("not found")
	}
	cp := *e
	return &cp, nil
}

func (r *mockEntryRepo) List(_ context.Context, hostID uuid.UUID) ([]*models.CrontabEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*models.CrontabEntry, 0)
	for _, e := range r.entries {
		if e.HostID == hostID {
			cp := *e
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r *mockEntryRepo) Update(_ context.Context, e *models.CrontabEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.entries[e.ID]; !ok {
		return stderrors.New("not found")
	}
	cp := *e
	cp.UpdatedAt = time.Now()
	r.entries[cp.ID] = &cp
	return nil
}

func (r *mockEntryRepo) Delete(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.entries[id]; !ok {
		return stderrors.New("not found")
	}
	delete(r.entries, id)
	return nil
}

func (r *mockEntryRepo) UpdateLastRun(_ context.Context, id uuid.UUID, status, output string, runAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[id]
	if !ok {
		return stderrors.New("not found")
	}
	e.LastRunAt = &runAt
	s := status
	o := output
	e.LastRunStatus = &s
	e.LastRunOutput = &o
	e.RunCount++
	if status == "failed" {
		e.FailCount++
	}
	return nil
}

func (r *mockEntryRepo) UpdateNextRun(_ context.Context, id uuid.UUID, nextRun *time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[id]
	if !ok {
		return stderrors.New("not found")
	}
	e.NextRunAt = nextRun
	return nil
}

func (r *mockEntryRepo) GetStats(_ context.Context, hostID uuid.UUID) (*models.CrontabStats, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	stats := &models.CrontabStats{}
	for _, e := range r.entries {
		if e.HostID != hostID {
			continue
		}
		stats.Total++
		if e.Enabled {
			stats.Enabled++
		} else {
			stats.Disabled++
		}
	}
	return stats, nil
}

type mockExecutionRepo struct {
	mu      sync.Mutex
	rows    map[uuid.UUID]*models.CrontabExecution
	deleted int64
}

func newMockExecutionRepo() *mockExecutionRepo {
	return &mockExecutionRepo{rows: map[uuid.UUID]*models.CrontabExecution{}}
}

func (r *mockExecutionRepo) Create(_ context.Context, e *models.CrontabExecution) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *e
	r.rows[cp.ID] = &cp
	return nil
}

func (r *mockExecutionRepo) ListByEntry(_ context.Context, entryID uuid.UUID, limit, offset int) ([]*models.CrontabExecution, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var all []*models.CrontabExecution
	for _, e := range r.rows {
		if e.EntryID == entryID {
			cp := *e
			all = append(all, &cp)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].StartedAt.After(all[j].StartedAt) })
	if offset >= len(all) {
		return nil, nil
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	return all[offset:end], nil
}

func (r *mockExecutionRepo) CountByEntry(_ context.Context, entryID uuid.UUID) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.rows {
		if e.EntryID == entryID {
			n++
		}
	}
	return n, nil
}

func (r *mockExecutionRepo) DeleteOlderThan(_ context.Context, _ time.Duration) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.deleted, nil
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

func newTestService(t *testing.T) (*Service, *mockEntryRepo, *mockExecutionRepo) {
	t.Helper()
	entries := newMockEntryRepo()
	executions := newMockExecutionRepo()
	svc := NewService(entries, executions, logger.Nop())
	if err := svc.Start(context.Background(), uuid.New()); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop() })
	return svc, entries, executions
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

func TestNewService_NilLoggerIsSafe(t *testing.T) {
	svc := NewService(newMockEntryRepo(), newMockExecutionRepo(), nil)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestCreate_InvalidScheduleRejected(t *testing.T) {
	svc, _, _ := newTestService(t)
	_, err := svc.Create(context.Background(), svc.HostID(), models.CreateCrontabInput{
		Name:     "bad",
		Schedule: "not a cron expression",
		Command:  "true",
	}, nil)
	if !stderrors.Is(err, ErrInvalidSchedule) {
		t.Fatalf("expected ErrInvalidSchedule, got %v", err)
	}
}

func TestCreate_EmptyNameRejected(t *testing.T) {
	svc, _, _ := newTestService(t)
	_, err := svc.Create(context.Background(), svc.HostID(), models.CreateCrontabInput{
		Name:     "   ",
		Schedule: "*/5 * * * *",
		Command:  "true",
	}, nil)
	if !stderrors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreate_DockerRequiresContainerID(t *testing.T) {
	svc, _, _ := newTestService(t)
	_, err := svc.Create(context.Background(), svc.HostID(), models.CreateCrontabInput{
		Name:        "bad-docker",
		Schedule:    "*/5 * * * *",
		CommandType: models.CrontabCommandDocker,
		Command:     "ls",
	}, nil)
	if !stderrors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreate_HTTPRequiresURL(t *testing.T) {
	svc, _, _ := newTestService(t)
	_, err := svc.Create(context.Background(), svc.HostID(), models.CreateCrontabInput{
		Name:        "bad-http",
		Schedule:    "*/5 * * * *",
		CommandType: models.CrontabCommandHTTP,
		Command:     "",
	}, nil)
	if !stderrors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreate_DefaultsShellCommandType(t *testing.T) {
	svc, _, _ := newTestService(t)
	entry, err := svc.Create(context.Background(), svc.HostID(), models.CreateCrontabInput{
		Name:     "default-type",
		Schedule: "*/5 * * * *",
		Command:  "echo hi",
		Enabled:  false,
	}, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if entry.CommandType != models.CrontabCommandShell {
		t.Fatalf("expected shell default, got %q", entry.CommandType)
	}
}

func TestCreate_AndGet_RoundTrip(t *testing.T) {
	svc, _, _ := newTestService(t)
	userID := uuid.New()
	entry, err := svc.Create(context.Background(), svc.HostID(), models.CreateCrontabInput{
		Name:        "round-trip",
		Description: "desc",
		Schedule:    "0 * * * *",
		Command:     "uptime",
		Enabled:     true,
	}, &userID)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := svc.Get(context.Background(), entry.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "round-trip" || got.Schedule != "0 * * * *" || !got.Enabled {
		t.Fatalf("entry not round-tripped: %+v", got)
	}
	if got.CreatedBy == nil || *got.CreatedBy != userID {
		t.Fatalf("created_by not preserved")
	}
}

func TestList_FiltersByHost(t *testing.T) {
	svc, _, _ := newTestService(t)
	otherHost := uuid.New()
	if _, err := svc.Create(context.Background(), svc.HostID(), models.CreateCrontabInput{
		Name:     "mine",
		Schedule: "*/1 * * * *",
		Command:  "true",
	}, nil); err != nil {
		t.Fatalf("create mine: %v", err)
	}
	if _, err := svc.Create(context.Background(), otherHost, models.CreateCrontabInput{
		Name:     "theirs",
		Schedule: "*/1 * * * *",
		Command:  "true",
	}, nil); err != nil {
		t.Fatalf("create theirs: %v", err)
	}
	got, err := svc.List(context.Background(), svc.HostID())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Name != "mine" {
		t.Fatalf("expected only \"mine\", got %+v", got)
	}
}

func TestUpdate_InvalidScheduleRejected(t *testing.T) {
	svc, _, _ := newTestService(t)
	entry, err := svc.Create(context.Background(), svc.HostID(), models.CreateCrontabInput{
		Name:     "u",
		Schedule: "*/5 * * * *",
		Command:  "true",
	}, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	bad := "not a schedule"
	if _, err := svc.Update(context.Background(), entry.ID, models.UpdateCrontabInput{Schedule: &bad}); !stderrors.Is(err, ErrInvalidSchedule) {
		t.Fatalf("expected ErrInvalidSchedule, got %v", err)
	}
}

func TestUpdate_EmptyNameRejected(t *testing.T) {
	svc, _, _ := newTestService(t)
	entry, _ := svc.Create(context.Background(), svc.HostID(), models.CreateCrontabInput{
		Name: "ok", Schedule: "*/5 * * * *", Command: "true",
	}, nil)
	empty := "   "
	if _, err := svc.Update(context.Background(), entry.ID, models.UpdateCrontabInput{Name: &empty}); !stderrors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestToggleEnabled(t *testing.T) {
	svc, _, _ := newTestService(t)
	entry, _ := svc.Create(context.Background(), svc.HostID(), models.CreateCrontabInput{
		Name: "toggle", Schedule: "*/5 * * * *", Command: "true", Enabled: true,
	}, nil)
	if err := svc.ToggleEnabled(context.Background(), entry.ID, false); err != nil {
		t.Fatalf("toggle off: %v", err)
	}
	got, _ := svc.Get(context.Background(), entry.ID)
	if got.Enabled {
		t.Fatalf("expected disabled")
	}
	if err := svc.ToggleEnabled(context.Background(), entry.ID, true); err != nil {
		t.Fatalf("toggle on: %v", err)
	}
	got, _ = svc.Get(context.Background(), entry.ID)
	if !got.Enabled {
		t.Fatalf("expected enabled")
	}
}

func TestDelete(t *testing.T) {
	svc, _, _ := newTestService(t)
	entry, _ := svc.Create(context.Background(), svc.HostID(), models.CreateCrontabInput{
		Name: "to-delete", Schedule: "*/5 * * * *", Command: "true",
	}, nil)
	if err := svc.Delete(context.Background(), entry.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := svc.Get(context.Background(), entry.ID); err == nil {
		t.Fatalf("expected not-found error after delete")
	}
}

func TestRunNow_RecordsExecution(t *testing.T) {
	svc, _, executions := newTestService(t)
	entry, _ := svc.Create(context.Background(), svc.HostID(), models.CreateCrontabInput{
		Name:        "run-now",
		Schedule:    "*/5 * * * *",
		CommandType: models.CrontabCommandShell,
		Command:     "echo hello",
	}, nil)
	if err := svc.RunNow(context.Background(), entry.ID); err != nil {
		t.Fatalf("run now: %v", err)
	}
	// Wait briefly for the background goroutine to record the row.
	waitFor(t, 2*time.Second, func() bool {
		n, _ := executions.CountByEntry(context.Background(), entry.ID)
		return n >= 1
	})
	rows, err := executions.ListByEntry(context.Background(), entry.ID, 100, 0)
	if err != nil {
		t.Fatalf("list executions: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 execution row, got %d", len(rows))
	}
	if rows[0].Status != "success" {
		t.Fatalf("expected status=success, got %q (output=%q error=%q)", rows[0].Status, rows[0].Output, rows[0].Error)
	}
}

func TestRunNow_UnknownCommandTypeFails(t *testing.T) {
	svc, _, executions := newTestService(t)
	// Validation rejects unknown types on create; inject directly to test
	// the runtime dispatch path.
	hostID := svc.HostID()
	bad := &models.CrontabEntry{
		ID:          uuid.New(),
		HostID:      hostID,
		Name:        "unknown",
		Schedule:    "*/5 * * * *",
		CommandType: models.CrontabCommandType("bogus"),
		Command:     "x",
	}
	_ = svc.entries.Create(context.Background(), bad)
	if err := svc.RunNow(context.Background(), bad.ID); err != nil {
		t.Fatalf("run now: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool {
		n, _ := executions.CountByEntry(context.Background(), bad.ID)
		return n >= 1
	})
	rows, _ := executions.ListByEntry(context.Background(), bad.ID, 10, 0)
	if len(rows) == 0 || rows[0].Status != "failed" {
		t.Fatalf("expected failed status for unknown command type, got %+v", rows)
	}
}

func TestListExecutions_LimitClampedTo100(t *testing.T) {
	svc, _, _ := newTestService(t)
	if limit := clampLimit(0); limit != MaxExecutionsPerPage {
		t.Fatalf("clamp(0) = %d, want %d", limit, MaxExecutionsPerPage)
	}
	if limit := clampLimit(500); limit != MaxExecutionsPerPage {
		t.Fatalf("clamp(500) = %d, want %d", limit, MaxExecutionsPerPage)
	}
	if limit := clampLimit(25); limit != 25 {
		t.Fatalf("clamp(25) = %d, want 25", limit)
	}
	// integration: 200 rows but limit clamped to 100.
	entry, _ := svc.Create(context.Background(), svc.HostID(), models.CreateCrontabInput{
		Name: "page", Schedule: "*/5 * * * *", Command: "true",
	}, nil)
	for i := 0; i < 150; i++ {
		_ = svc.executions.Create(context.Background(), &models.CrontabExecution{
			ID:        uuid.New(),
			EntryID:   entry.ID,
			HostID:    svc.HostID(),
			Status:    "success",
			StartedAt: time.Now().Add(time.Duration(-i) * time.Second),
		})
	}
	rows, err := svc.ListExecutions(context.Background(), entry.ID, 9999, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != MaxExecutionsPerPage {
		t.Fatalf("expected %d rows (clamped), got %d", MaxExecutionsPerPage, len(rows))
	}
}

func TestExecutionListener_Notified(t *testing.T) {
	svc, _, _ := newTestService(t)
	var got atomic.Int32
	deregister := svc.AddExecutionListener(&testListener{onExec: func(_ *models.CrontabExecution, _ string) {
		got.Add(1)
	}})
	defer deregister()
	entry, _ := svc.Create(context.Background(), svc.HostID(), models.CreateCrontabInput{
		Name: "listener", Schedule: "*/5 * * * *", Command: "echo x",
	}, nil)
	_ = svc.RunNow(context.Background(), entry.ID)
	waitFor(t, 2*time.Second, func() bool { return got.Load() >= 1 })
	if got.Load() < 1 {
		t.Fatalf("listener never called")
	}
}

func TestExecutionListener_DeregisterStopsNotifications(t *testing.T) {
	svc, _, _ := newTestService(t)
	var got atomic.Int32
	deregister := svc.AddExecutionListener(&testListener{onExec: func(_ *models.CrontabExecution, _ string) {
		got.Add(1)
	}})
	deregister()
	entry, _ := svc.Create(context.Background(), svc.HostID(), models.CreateCrontabInput{
		Name: "dereg", Schedule: "*/5 * * * *", Command: "echo y",
	}, nil)
	_ = svc.RunNow(context.Background(), entry.ID)
	time.Sleep(500 * time.Millisecond)
	if got.Load() != 0 {
		t.Fatalf("listener fired after deregister: %d", got.Load())
	}
}

func TestGetStats(t *testing.T) {
	svc, _, _ := newTestService(t)
	_, _ = svc.Create(context.Background(), svc.HostID(), models.CreateCrontabInput{
		Name: "on1", Schedule: "*/5 * * * *", Command: "true", Enabled: true,
	}, nil)
	_, _ = svc.Create(context.Background(), svc.HostID(), models.CreateCrontabInput{
		Name: "off1", Schedule: "*/5 * * * *", Command: "true", Enabled: false,
	}, nil)
	stats, err := svc.GetStats(context.Background(), svc.HostID())
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Total != 2 || stats.Enabled != 1 || stats.Disabled != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestExecuteShell_CapturesStderr(t *testing.T) {
	svc := NewService(newMockEntryRepo(), newMockExecutionRepo(), logger.Nop())
	out, code, err := svc.executeShell(context.Background(), ">&2 echo stderr-msg; exit 3", "")
	if err == nil {
		t.Fatalf("expected error for non-zero exit")
	}
	if code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
	if !contains(out, "stderr-msg") {
		t.Fatalf("expected stderr in output, got %q", out)
	}
}

func TestValidateCreateInput_ShellRequiresCommand(t *testing.T) {
	if err := validateCreateInput(models.CreateCrontabInput{
		Name: "x", Schedule: "*/5 * * * *", Command: "",
	}); !stderrors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestValidateCreateInput_UnknownTypeRejected(t *testing.T) {
	if err := validateCreateInput(models.CreateCrontabInput{
		Name: "x", Schedule: "*/5 * * * *", CommandType: models.CrontabCommandType("nope"), Command: "x",
	}); !stderrors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

// ----------------------------------------------------------------------------
// Test helpers
// ----------------------------------------------------------------------------

type testListener struct {
	onExec func(*models.CrontabExecution, string)
}

func (l *testListener) OnExecution(ex *models.CrontabExecution, name string) {
	if l.onExec != nil {
		l.onExec(ex, name)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}
