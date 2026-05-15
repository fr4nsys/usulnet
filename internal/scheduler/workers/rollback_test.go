// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package workers

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	changessvc "github.com/fr4nsys/usulnet/internal/services/changes"
)

// fakeChangesRepo is the minimal Repository the changes service needs.
type fakeChangesRepoForWorker struct{}

func (f *fakeChangesRepoForWorker) Create(_ context.Context, e *models.ChangeEvent) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	return nil
}
func (f *fakeChangesRepoForWorker) GetByID(_ context.Context, _ uuid.UUID) (*models.ChangeEvent, error) {
	return nil, nil
}
func (f *fakeChangesRepoForWorker) List(_ context.Context, _ models.ChangeEventListOptions) ([]*models.ChangeEvent, int, error) {
	return nil, 0, nil
}
func (f *fakeChangesRepoForWorker) GetByResource(_ context.Context, _, _ string, _ int) ([]*models.ChangeEvent, error) {
	return nil, nil
}
func (f *fakeChangesRepoForWorker) GetByUser(_ context.Context, _ uuid.UUID, _ int) ([]*models.ChangeEvent, error) {
	return nil, nil
}
func (f *fakeChangesRepoForWorker) GetStats(_ context.Context, _ time.Time) (*models.ChangeEventStats, error) {
	return nil, nil
}
func (f *fakeChangesRepoForWorker) DeleteOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}
func (f *fakeChangesRepoForWorker) ExportCSV(_ context.Context, _ models.ChangeEventListOptions) ([][]string, error) {
	return nil, nil
}

// fakeConsumer records every event dispatched to it.
type fakeConsumer struct {
	mu     sync.Mutex
	events []*models.ChangeEvent
}

func (c *fakeConsumer) ExecuteOnEvent(_ context.Context, e *models.ChangeEvent) (*models.RollbackExecution, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
	return nil, nil
}

func TestRollbackEventWorkerDispatches(t *testing.T) {
	repo := &fakeChangesRepoForWorker{}
	changeSvc := changessvc.NewService(repo, nil)

	consumer := &fakeConsumer{}
	worker := NewRollbackEventWorker(changeSvc, consumer, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := worker.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer worker.Stop()

	// Record one matching event.
	if err := changeSvc.Record(ctx, changessvc.RecordInput{
		ResourceType: models.ChangeResourceStack,
		ResourceID:   uuid.New().String(),
		Action:       models.ChangeActionDeploy,
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	// Poll briefly for the worker to consume.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		consumer.mu.Lock()
		n := len(consumer.events)
		consumer.mu.Unlock()
		if n == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("worker did not dispatch within deadline")
}

func TestRollbackEventWorkerStartIdempotent(t *testing.T) {
	repo := &fakeChangesRepoForWorker{}
	changeSvc := changessvc.NewService(repo, nil)
	consumer := &fakeConsumer{}
	worker := NewRollbackEventWorker(changeSvc, consumer, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := worker.Start(ctx); err != nil {
		t.Fatalf("first start: %v", err)
	}
	if err := worker.Start(ctx); err != nil {
		t.Fatalf("second start: %v", err)
	}
	worker.Stop()
	worker.Stop() // double Stop must not panic.
}

func TestRollbackEventWorkerStartWithoutDepsNoop(t *testing.T) {
	w := NewRollbackEventWorker(nil, nil, nil)
	if err := w.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	w.Stop()
}
