// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package calendar

import (
	"context"
	stderrors "errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ============================================================================
// In-memory test double for Repository
// ============================================================================

type memRepo struct {
	mu     sync.Mutex
	events map[uuid.UUID]*models.CalendarEvent
}

func newMemRepo() *memRepo {
	return &memRepo{events: make(map[uuid.UUID]*models.CalendarEvent)}
}

func (m *memRepo) Create(ctx context.Context, e *models.CalendarEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	e.UpdatedAt = time.Now()
	clone := *e
	m.events[e.ID] = &clone
	return nil
}

func (m *memRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.CalendarEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.events[id]
	if !ok {
		return nil, stderrors.New("not found")
	}
	clone := *e
	return &clone, nil
}

func (m *memRepo) ListInRange(ctx context.Context, hostID uuid.UUID, from, to time.Time) ([]*models.CalendarEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*models.CalendarEvent, 0)
	for _, e := range m.events {
		if e.HostID != hostID {
			continue
		}
		if e.StartsAt.Before(to) && e.EndsAt.After(from) {
			clone := *e
			out = append(out, &clone)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartsAt.Before(out[j].StartsAt) })
	return out, nil
}

func (m *memRepo) ListAll(ctx context.Context, hostID uuid.UUID) ([]*models.CalendarEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*models.CalendarEvent, 0)
	for _, e := range m.events {
		if e.HostID != hostID {
			continue
		}
		clone := *e
		out = append(out, &clone)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartsAt.Before(out[j].StartsAt) })
	return out, nil
}

func (m *memRepo) Update(ctx context.Context, e *models.CalendarEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.events[e.ID]; !ok {
		return stderrors.New("not found")
	}
	e.UpdatedAt = time.Now()
	clone := *e
	m.events[e.ID] = &clone
	return nil
}

func (m *memRepo) Delete(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.events[id]; !ok {
		return stderrors.New("not found")
	}
	delete(m.events, id)
	return nil
}

func (m *memRepo) GetStats(ctx context.Context, hostID uuid.UUID) (*models.CalendarStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := &models.CalendarStats{}
	for _, e := range m.events {
		if e.HostID != hostID {
			continue
		}
		s.Total++
		switch e.Kind {
		case models.CalendarKindMaintenance:
			s.Maintenance++
		case models.CalendarKindBackup:
			s.Backup++
		case models.CalendarKindDeploy:
			s.Deploy++
		case models.CalendarKindJob:
			s.Job++
		case models.CalendarKindAlert:
			s.Alert++
		case models.CalendarKindNote:
			s.Note++
		}
	}
	return s, nil
}

// ============================================================================
// Mock EventSource
// ============================================================================

type mockSource struct {
	name   string
	events []*models.CalendarEvent
	err    error
}

func (m *mockSource) Name() string { return m.name }
func (m *mockSource) ListEvents(ctx context.Context, hostID uuid.UUID, r models.CalendarRange) ([]*models.CalendarEvent, error) {
	if m.err != nil {
		return nil, m.err
	}
	out := make([]*models.CalendarEvent, 0)
	for _, e := range m.events {
		if e.StartsAt.Before(r.To) && e.EndsAt.After(r.From) {
			out = append(out, e)
		}
	}
	return out, nil
}

// ============================================================================
// Tests
// ============================================================================

func newTestService(t *testing.T) (*Service, *memRepo, uuid.UUID) {
	t.Helper()
	repo := newMemRepo()
	svc := NewService(repo, nil)
	return svc, repo, uuid.New()
}

func TestCreateAndGet(t *testing.T) {
	svc, _, hostID := newTestService(t)
	ctx := context.Background()

	now := time.Now().UTC().Round(time.Second)
	in := models.CreateCalendarEventInput{
		Kind:     models.CalendarKindMaintenance,
		Title:    "Q4 patching window",
		StartsAt: now,
		EndsAt:   now.Add(2 * time.Hour),
	}
	ev, err := svc.Create(ctx, hostID, in, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if ev.Source != models.CalendarSourceManual {
		t.Fatalf("expected Source=manual, got %q", ev.Source)
	}
	if ev.HostID != hostID {
		t.Fatalf("expected HostID %s, got %s", hostID, ev.HostID)
	}

	got, err := svc.Get(ctx, ev.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Title != "Q4 patching window" {
		t.Fatalf("expected stored title, got %q", got.Title)
	}
}

func TestCreateValidation(t *testing.T) {
	svc, _, hostID := newTestService(t)
	ctx := context.Background()
	base := time.Now().UTC()

	cases := []struct {
		name string
		in   models.CreateCalendarEventInput
	}{
		{
			name: "empty title",
			in: models.CreateCalendarEventInput{
				Kind:     models.CalendarKindNote,
				Title:    "  ",
				StartsAt: base, EndsAt: base.Add(time.Hour),
			},
		},
		{
			name: "unknown kind",
			in: models.CreateCalendarEventInput{
				Kind:     "ghost",
				Title:    "x",
				StartsAt: base, EndsAt: base.Add(time.Hour),
			},
		},
		{
			name: "ends before starts",
			in: models.CreateCalendarEventInput{
				Kind:     models.CalendarKindNote,
				Title:    "x",
				StartsAt: base.Add(time.Hour), EndsAt: base,
			},
		},
		{
			name: "zero starts",
			in: models.CreateCalendarEventInput{
				Kind:  models.CalendarKindNote,
				Title: "x", EndsAt: base.Add(time.Hour),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.Create(ctx, hostID, tc.in, nil); !stderrors.Is(err, ErrInvalidInput) {
				t.Fatalf("expected ErrInvalidInput, got %v", err)
			}
		})
	}
}

func TestUpdateAndDelete(t *testing.T) {
	svc, _, hostID := newTestService(t)
	ctx := context.Background()
	base := time.Now().UTC()

	ev, err := svc.Create(ctx, hostID, models.CreateCalendarEventInput{
		Kind:     models.CalendarKindDeploy,
		Title:    "Initial",
		StartsAt: base, EndsAt: base.Add(time.Hour),
	}, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Patch title only.
	newTitle := "Updated"
	if _, err := svc.Update(ctx, ev.ID, models.UpdateCalendarEventInput{Title: &newTitle}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := svc.Get(ctx, ev.ID)
	if got.Title != "Updated" {
		t.Fatalf("expected title 'Updated', got %q", got.Title)
	}

	// Reject ends < starts on update.
	bad := base.Add(-time.Hour)
	if _, err := svc.Update(ctx, ev.ID, models.UpdateCalendarEventInput{EndsAt: &bad}); !stderrors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}

	// Reject unknown kind.
	bk := models.CalendarEventKind("ghost")
	if _, err := svc.Update(ctx, ev.ID, models.UpdateCalendarEventInput{Kind: &bk}); !stderrors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}

	// Reject empty title.
	empty := "  "
	if _, err := svc.Update(ctx, ev.ID, models.UpdateCalendarEventInput{Title: &empty}); !stderrors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}

	if err := svc.Delete(ctx, ev.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := svc.Get(ctx, ev.ID); err == nil {
		t.Fatalf("expected error after delete")
	}
}

func TestListEventsMergesAndSorts(t *testing.T) {
	svc, repo, hostID := newTestService(t)
	ctx := context.Background()

	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	// Manual at base+30min.
	manualID := uuid.New()
	_ = repo.Create(ctx, &models.CalendarEvent{
		ID:       manualID,
		HostID:   hostID,
		Source:   models.CalendarSourceManual,
		Kind:     models.CalendarKindMaintenance,
		Title:    "Manual",
		StartsAt: base.Add(30 * time.Minute),
		EndsAt:   base.Add(time.Hour),
	})

	// Aggregator event at base.
	src := &mockSource{
		name: "test",
		events: []*models.CalendarEvent{
			{
				ID:       uuid.New(),
				HostID:   hostID,
				Source:   models.CalendarSourceBackup,
				Kind:     models.CalendarKindBackup,
				Title:    "Backup",
				StartsAt: base,
				EndsAt:   base.Add(10 * time.Minute),
			},
		},
	}
	svc.RegisterSource(src)

	events, err := svc.ListEvents(ctx, hostID, base.Add(-time.Hour), base.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Title != "Backup" || events[1].Title != "Manual" {
		t.Fatalf("expected sorted by StartsAt: [Backup, Manual], got %v / %v", events[0].Title, events[1].Title)
	}
}

func TestListEventsHandlesFailingSource(t *testing.T) {
	svc, _, hostID := newTestService(t)
	ctx := context.Background()

	svc.RegisterSource(&mockSource{name: "broken", err: stderrors.New("boom")})
	// One good source still gets through.
	svc.RegisterSource(&mockSource{
		name: "ok",
		events: []*models.CalendarEvent{
			{
				ID:       uuid.New(),
				HostID:   hostID,
				Source:   models.CalendarSourceBackup,
				Kind:     models.CalendarKindBackup,
				Title:    "Survivor",
				StartsAt: time.Now().UTC(),
				EndsAt:   time.Now().UTC().Add(time.Hour),
			},
		},
	})

	events, err := svc.ListEvents(ctx, hostID, time.Now().UTC().Add(-time.Hour), time.Now().UTC().Add(2*time.Hour))
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 1 || events[0].Title != "Survivor" {
		t.Fatalf("expected single 'Survivor' event, got %+v", events)
	}
}

func TestListEventsRangeValidation(t *testing.T) {
	svc, _, hostID := newTestService(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if _, err := svc.ListEvents(ctx, hostID, now, now); !stderrors.Is(err, ErrInvalidRange) {
		t.Fatalf("expected ErrInvalidRange for zero window, got %v", err)
	}
	if _, err := svc.ListEvents(ctx, hostID, now, now.Add(-time.Hour)); !stderrors.Is(err, ErrInvalidRange) {
		t.Fatalf("expected ErrInvalidRange for reversed window, got %v", err)
	}
	// Window > MaxRangeDays.
	from := now
	to := now.AddDate(0, 0, MaxRangeDays+1)
	if _, err := svc.ListEvents(ctx, hostID, from, to); !stderrors.Is(err, ErrInvalidRange) {
		t.Fatalf("expected ErrInvalidRange for oversized window, got %v", err)
	}
}

func TestSources(t *testing.T) {
	svc, _, _ := newTestService(t)

	if got := svc.Sources(); len(got) != 1 || got[0] != "manual" {
		t.Fatalf("expected [manual], got %v", got)
	}
	svc.RegisterSource(&mockSource{name: "backup"})
	svc.RegisterSource(&mockSource{name: "scheduled_job"})
	svc.RegisterSource(nil) // no-op
	got := svc.Sources()
	want := []string{"manual", "backup", "scheduled_job"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i, s := range want {
		if got[i] != s {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}
}

func TestGetStats(t *testing.T) {
	svc, _, hostID := newTestService(t)
	ctx := context.Background()
	base := time.Now().UTC()

	for _, kind := range []models.CalendarEventKind{
		models.CalendarKindMaintenance,
		models.CalendarKindBackup,
		models.CalendarKindBackup,
		models.CalendarKindDeploy,
		models.CalendarKindJob,
		models.CalendarKindAlert,
		models.CalendarKindNote,
	} {
		_, err := svc.Create(ctx, hostID, models.CreateCalendarEventInput{
			Kind:     kind,
			Title:    "x",
			StartsAt: base, EndsAt: base.Add(time.Hour),
		}, nil)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
	}
	s, err := svc.GetStats(ctx, hostID)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if s.Total != 7 || s.Backup != 2 || s.Maintenance != 1 {
		t.Fatalf("unexpected stats: %+v", s)
	}
}

func TestExportICSEmpty(t *testing.T) {
	svc, _, hostID := newTestService(t)
	ctx := context.Background()

	body, err := svc.ExportICS(ctx, hostID)
	if err != nil {
		t.Fatalf("ExportICS: %v", err)
	}
	// Empty calendar still contains the header/footer.
	if len(body) == 0 {
		t.Fatal("expected non-empty .ics body")
	}
}
