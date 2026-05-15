// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package changes

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// fakeRepo is a minimal in-memory Repository used to exercise the
// service's Record/Subscribe paths without a real Postgres.
type fakeRepo struct {
	mu     sync.Mutex
	events []*models.ChangeEvent
}

func (f *fakeRepo) Create(_ context.Context, e *models.ChangeEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	f.events = append(f.events, e)
	return nil
}

func (f *fakeRepo) GetByID(_ context.Context, _ uuid.UUID) (*models.ChangeEvent, error) {
	return nil, nil
}
func (f *fakeRepo) List(_ context.Context, _ models.ChangeEventListOptions) ([]*models.ChangeEvent, int, error) {
	return nil, 0, nil
}
func (f *fakeRepo) GetByResource(_ context.Context, _, _ string, _ int) ([]*models.ChangeEvent, error) {
	return nil, nil
}
func (f *fakeRepo) GetByUser(_ context.Context, _ uuid.UUID, _ int) ([]*models.ChangeEvent, error) {
	return nil, nil
}
func (f *fakeRepo) GetStats(_ context.Context, _ time.Time) (*models.ChangeEventStats, error) {
	return nil, nil
}
func (f *fakeRepo) DeleteOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}
func (f *fakeRepo) ExportCSV(_ context.Context, _ models.ChangeEventListOptions) ([][]string, error) {
	return nil, nil
}

func TestSubscribeReceivesMatchingEvents(t *testing.T) {
	svc := NewService(&fakeRepo{}, nil)
	sub := svc.Subscribe(SubscriptionFilter{
		ResourceType: models.ChangeResourceStack,
		Actions:      []string{models.ChangeActionDeploy},
	}, 4)
	defer sub.Close()

	ctx := context.Background()

	// Matching event should be delivered.
	if err := svc.Record(ctx, RecordInput{
		ResourceType: models.ChangeResourceStack,
		ResourceID:   "stack-1",
		Action:       models.ChangeActionDeploy,
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	select {
	case e := <-sub.Events():
		if e.Action != models.ChangeActionDeploy {
			t.Fatalf("unexpected action: %q", e.Action)
		}
		if e.ResourceType != models.ChangeResourceStack {
			t.Fatalf("unexpected resource type: %q", e.ResourceType)
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive matching event within deadline")
	}
}

func TestSubscribeFiltersByResourceType(t *testing.T) {
	svc := NewService(&fakeRepo{}, nil)
	sub := svc.Subscribe(SubscriptionFilter{ResourceType: models.ChangeResourceStack}, 4)
	defer sub.Close()

	ctx := context.Background()

	// Non-matching event must NOT be delivered.
	if err := svc.Record(ctx, RecordInput{
		ResourceType: models.ChangeResourceContainer,
		ResourceID:   "container-1",
		Action:       models.ChangeActionStart,
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	select {
	case e := <-sub.Events():
		t.Fatalf("unexpected event delivered: %+v", e)
	case <-time.After(50 * time.Millisecond):
		// good — no event
	}
}

func TestSubscribeFiltersByAction(t *testing.T) {
	svc := NewService(&fakeRepo{}, nil)
	sub := svc.Subscribe(SubscriptionFilter{
		Actions: []string{models.ChangeActionDeploy, models.ChangeActionRollback},
	}, 4)
	defer sub.Close()

	ctx := context.Background()

	if err := svc.Record(ctx, RecordInput{
		ResourceType: models.ChangeResourceStack,
		Action:       models.ChangeActionCreate, // not in filter
	}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := svc.Record(ctx, RecordInput{
		ResourceType: models.ChangeResourceStack,
		Action:       models.ChangeActionDeploy, // in filter
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	select {
	case e := <-sub.Events():
		if e.Action != models.ChangeActionDeploy {
			t.Fatalf("expected deploy event, got %q", e.Action)
		}
	case <-time.After(time.Second):
		t.Fatal("deploy event not received")
	}

	// Nothing else queued.
	select {
	case e := <-sub.Events():
		t.Fatalf("unexpected second event: %+v", e)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestSubscribeCloseStopsDelivery(t *testing.T) {
	svc := NewService(&fakeRepo{}, nil)
	sub := svc.Subscribe(SubscriptionFilter{}, 4)
	sub.Close()
	// Double close must not panic.
	sub.Close()

	ctx := context.Background()
	if err := svc.Record(ctx, RecordInput{
		ResourceType: models.ChangeResourceStack,
		Action:       models.ChangeActionDeploy,
	}); err != nil {
		t.Fatalf("record after close: %v", err)
	}
	// No assertion on sub.ch — Close closed it; we just need Record to
	// not block or panic.
}

func TestSubscribeDoesNotBlockOnSlowConsumer(t *testing.T) {
	svc := NewService(&fakeRepo{}, nil)
	sub := svc.Subscribe(SubscriptionFilter{}, 1) // tiny buffer
	defer sub.Close()

	ctx := context.Background()
	for i := 0; i < 10; i++ {
		// Multiple records; only the first fills the buffer. Rest are
		// dropped without blocking.
		if err := svc.Record(ctx, RecordInput{
			ResourceType: models.ChangeResourceStack,
			Action:       models.ChangeActionDeploy,
		}); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	// Drain whatever ended up in the buffer.
	timer := time.NewTimer(50 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-sub.Events():
		case <-timer.C:
			return
		}
	}
}
