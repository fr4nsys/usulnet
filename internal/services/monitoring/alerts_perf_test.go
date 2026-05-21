// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package monitoring

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// countingAlertRepo is a stub AlertRepository that records how often
// each event-mutating call hits the repo. Only the methods exercised by
// the resolveActiveEvents path are real; the rest are no-ops so the
// service compiles against the full interface.
type countingAlertRepo struct {
	updateEventCount         int
	resolveActiveEventsCount int
	resolveActiveEventsArg   uuid.UUID
	firingEvents             []*models.AlertEvent
}

func (r *countingAlertRepo) CreateRule(ctx context.Context, rule *models.AlertRule) error {
	return nil
}
func (r *countingAlertRepo) GetRule(ctx context.Context, id uuid.UUID) (*models.AlertRule, error) {
	return nil, nil
}
func (r *countingAlertRepo) UpdateRule(ctx context.Context, rule *models.AlertRule) error {
	return nil
}
func (r *countingAlertRepo) DeleteRule(ctx context.Context, id uuid.UUID) error { return nil }
func (r *countingAlertRepo) ListRules(ctx context.Context, opts models.AlertListOptions) ([]*models.AlertRule, int64, error) {
	return nil, 0, nil
}
func (r *countingAlertRepo) ListEnabledRules(ctx context.Context) ([]*models.AlertRule, error) {
	return nil, nil
}
func (r *countingAlertRepo) CreateEvent(ctx context.Context, event *models.AlertEvent) error {
	return nil
}
func (r *countingAlertRepo) GetEvent(ctx context.Context, id uuid.UUID) (*models.AlertEvent, error) {
	return nil, nil
}
func (r *countingAlertRepo) UpdateEvent(ctx context.Context, event *models.AlertEvent) error {
	r.updateEventCount++
	return nil
}
func (r *countingAlertRepo) ListEvents(ctx context.Context, opts models.AlertEventListOptions) ([]*models.AlertEvent, int64, error) {
	return r.firingEvents, int64(len(r.firingEvents)), nil
}
func (r *countingAlertRepo) GetActiveEvents(ctx context.Context) ([]*models.AlertEvent, error) {
	return r.firingEvents, nil
}
func (r *countingAlertRepo) ResolveActiveEvents(ctx context.Context, ruleID uuid.UUID, resolvedAt time.Time) error {
	r.resolveActiveEventsCount++
	r.resolveActiveEventsArg = ruleID
	return nil
}
func (r *countingAlertRepo) CreateSilence(ctx context.Context, silence *models.AlertSilence) error {
	return nil
}
func (r *countingAlertRepo) GetSilence(ctx context.Context, id uuid.UUID) (*models.AlertSilence, error) {
	return nil, nil
}
func (r *countingAlertRepo) DeleteSilence(ctx context.Context, id uuid.UUID) error { return nil }
func (r *countingAlertRepo) ListSilences(ctx context.Context) ([]*models.AlertSilence, error) {
	return nil, nil
}
func (r *countingAlertRepo) GetActiveSilences(ctx context.Context) ([]*models.AlertSilence, error) {
	return nil, nil
}
func (r *countingAlertRepo) GetStats(ctx context.Context) (*models.AlertStats, error) {
	return nil, nil
}

// TestResolveActiveEvents_SingleRoundTrip pins that recovering a rule
// issues exactly one DB call regardless of how many events are firing.
// Before v26.5.2-perf this path round-tripped N times — once per event
// — through UpdateEvent.
func TestResolveActiveEvents_SingleRoundTrip(t *testing.T) {
	const firingCount = 50

	repo := &countingAlertRepo{
		firingEvents: make([]*models.AlertEvent, firingCount),
	}
	for i := range repo.firingEvents {
		repo.firingEvents[i] = &models.AlertEvent{
			ID:    uuid.New(),
			State: models.AlertStateFiring,
		}
	}

	svc := NewAlertService(repo, nil, nil, AlertServiceConfig{}, nil)

	ruleID := uuid.New()
	svc.resolveActiveEvents(context.Background(), ruleID, time.Now())

	if repo.resolveActiveEventsCount != 1 {
		t.Fatalf("ResolveActiveEvents call count = %d, want 1", repo.resolveActiveEventsCount)
	}
	if repo.updateEventCount != 0 {
		t.Fatalf("per-event UpdateEvent call count = %d, want 0 (regressed back to N+1)", repo.updateEventCount)
	}
	if repo.resolveActiveEventsArg != ruleID {
		t.Fatalf("ResolveActiveEvents rule arg = %v, want %v", repo.resolveActiveEventsArg, ruleID)
	}
}
