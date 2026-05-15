// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package changes

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Repository defines the persistence interface for change events.
type Repository interface {
	Create(ctx context.Context, e *models.ChangeEvent) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.ChangeEvent, error)
	List(ctx context.Context, opts models.ChangeEventListOptions) ([]*models.ChangeEvent, int, error)
	GetByResource(ctx context.Context, resourceType, resourceID string, limit int) ([]*models.ChangeEvent, error)
	GetByUser(ctx context.Context, userID uuid.UUID, limit int) ([]*models.ChangeEvent, error)
	GetStats(ctx context.Context, since time.Time) (*models.ChangeEventStats, error)
	DeleteOlderThan(ctx context.Context, before time.Time) (int64, error)
	ExportCSV(ctx context.Context, opts models.ChangeEventListOptions) ([][]string, error)
}

// Service handles change event recording and retrieval.
type Service struct {
	repo   Repository
	logger *logger.Logger

	// In-process pub-sub for downstream consumers (rollback worker, the
	// future drift correlator, etc.). The slice is guarded by subMu;
	// fan-out is non-blocking — a slow subscriber whose channel is full
	// drops the event and logs a warning.
	subMu       sync.RWMutex
	subscribers []*Subscription
}

// NewService creates a new change tracking service.
func NewService(repo Repository, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		repo:   repo,
		logger: log.Named("changes"),
	}
}

// SubscriptionFilter narrows the events delivered to a subscriber. Empty
// fields match everything.
type SubscriptionFilter struct {
	// ResourceType — e.g. "stack", "container".
	ResourceType string
	// Actions — if non-empty, only events whose Action is in the set
	// are delivered.
	Actions []string
}

// Subscription is a live pull-side handle returned by Subscribe.
// Consume Events; call Close when done. Close is idempotent.
type Subscription struct {
	ch     chan *models.ChangeEvent
	filter SubscriptionFilter
	svc    *Service

	closeOnce sync.Once
	closed    chan struct{}
}

// Events is the channel of incoming change events. Closed when the
// subscription is Close()d.
func (s *Subscription) Events() <-chan *models.ChangeEvent {
	return s.ch
}

// Close unregisters the subscription. Safe to call from any goroutine;
// idempotent.
func (s *Subscription) Close() {
	s.closeOnce.Do(func() {
		s.svc.unsubscribe(s)
		close(s.closed)
		close(s.ch)
	})
}

// Subscribe registers a new subscriber to live change events. The
// returned Subscription's Events channel buffers up to bufSize events
// (bufSize<=0 becomes 32). Records arriving while the buffer is full
// are dropped; a slow consumer cannot block the Record path.
//
// Callers MUST eventually invoke Subscription.Close() to release
// resources — typically with a `defer sub.Close()` in the consuming
// goroutine.
func (s *Service) Subscribe(filter SubscriptionFilter, bufSize int) *Subscription {
	if bufSize <= 0 {
		bufSize = 32
	}
	sub := &Subscription{
		ch:     make(chan *models.ChangeEvent, bufSize),
		filter: filter,
		svc:    s,
		closed: make(chan struct{}),
	}
	s.subMu.Lock()
	s.subscribers = append(s.subscribers, sub)
	s.subMu.Unlock()
	return sub
}

// unsubscribe removes the given subscription. Called from
// Subscription.Close — do not call directly.
func (s *Service) unsubscribe(target *Subscription) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for i, sub := range s.subscribers {
		if sub == target {
			s.subscribers = append(s.subscribers[:i], s.subscribers[i+1:]...)
			return
		}
	}
}

// fanOut delivers e to every matching subscriber. Non-blocking — drops
// when a subscriber's buffer is full.
func (s *Service) fanOut(e *models.ChangeEvent) {
	s.subMu.RLock()
	defer s.subMu.RUnlock()
	for _, sub := range s.subscribers {
		if !subscriptionMatches(sub.filter, e) {
			continue
		}
		select {
		case sub.ch <- e:
		default:
			s.logger.Warn("change event dropped: subscriber buffer full",
				"resource_type", e.ResourceType,
				"action", e.Action,
			)
		}
	}
}

func subscriptionMatches(f SubscriptionFilter, e *models.ChangeEvent) bool {
	if f.ResourceType != "" && f.ResourceType != e.ResourceType {
		return false
	}
	if len(f.Actions) == 0 {
		return true
	}
	for _, a := range f.Actions {
		if a == e.Action {
			return true
		}
	}
	return false
}

// RecordInput is the input for recording a new change event.
type RecordInput struct {
	UserID        *uuid.UUID
	UserName      string
	ClientIP      string
	ResourceType  string
	ResourceID    string
	ResourceName  string
	Action        string
	OldState      any // will be JSON-marshaled
	NewState      any // will be JSON-marshaled
	DiffSummary   string
	RelatedTicket string
	Metadata      map[string]any
}

// Record creates an immutable change event from the given input.
func (s *Service) Record(ctx context.Context, input RecordInput) error {
	e := &models.ChangeEvent{
		UserID:        input.UserID,
		UserName:      input.UserName,
		ClientIP:      input.ClientIP,
		ResourceType:  input.ResourceType,
		ResourceID:    input.ResourceID,
		ResourceName:  input.ResourceName,
		Action:        input.Action,
		DiffSummary:   input.DiffSummary,
		RelatedTicket: input.RelatedTicket,
	}

	if input.OldState != nil {
		raw, err := json.Marshal(input.OldState)
		if err == nil {
			msg := json.RawMessage(raw)
			e.OldState = &msg
		}
	}
	if input.NewState != nil {
		raw, err := json.Marshal(input.NewState)
		if err == nil {
			msg := json.RawMessage(raw)
			e.NewState = &msg
		}
	}
	if len(input.Metadata) > 0 {
		raw, err := json.Marshal(input.Metadata)
		if err == nil {
			msg := json.RawMessage(raw)
			e.Metadata = &msg
		}
	}

	// Auto-generate diff summary if not provided
	if e.DiffSummary == "" && e.OldState != nil && e.NewState != nil {
		e.DiffSummary = generateDiffSummary(e.OldState, e.NewState)
	}

	if err := s.repo.Create(ctx, e); err != nil {
		s.logger.Error("failed to record change event",
			"resource_type", input.ResourceType,
			"resource_id", input.ResourceID,
			"action", input.Action,
			"error", err,
		)
		return fmt.Errorf("recording change event: %w", err)
	}

	s.logger.Debug("change event recorded",
		"id", e.ID,
		"resource_type", input.ResourceType,
		"resource_id", input.ResourceID,
		"action", input.Action,
		"user", input.UserName,
	)

	s.fanOut(e)

	return nil
}

// RecordAsync records a change event asynchronously (fire-and-forget).
func (s *Service) RecordAsync(ctx context.Context, input RecordInput) {
	go func() {
		bgCtx := context.WithoutCancel(ctx)
		if err := s.Record(bgCtx, input); err != nil {
			s.logger.Error("async change event recording failed", "error", err)
		}
	}()
}

// GetByID retrieves a single change event by its ID.
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (*models.ChangeEvent, error) {
	return s.repo.GetByID(ctx, id)
}

// List retrieves change events with filtering and pagination.
func (s *Service) List(ctx context.Context, opts models.ChangeEventListOptions) ([]*models.ChangeEvent, int, error) {
	return s.repo.List(ctx, opts)
}

// GetByResource retrieves change events for a specific resource.
func (s *Service) GetByResource(ctx context.Context, resourceType, resourceID string, limit int) ([]*models.ChangeEvent, error) {
	return s.repo.GetByResource(ctx, resourceType, resourceID, limit)
}

// GetByUser retrieves change events for a specific user.
func (s *Service) GetByUser(ctx context.Context, userID uuid.UUID, limit int) ([]*models.ChangeEvent, error) {
	return s.repo.GetByUser(ctx, userID, limit)
}

// GetStats returns aggregated statistics for change events.
func (s *Service) GetStats(ctx context.Context, since time.Time) (*models.ChangeEventStats, error) {
	return s.repo.GetStats(ctx, since)
}

// ExportCSV returns change events as CSV rows.
func (s *Service) ExportCSV(ctx context.Context, opts models.ChangeEventListOptions) ([][]string, error) {
	return s.repo.ExportCSV(ctx, opts)
}

// generateDiffSummary creates a human-readable summary comparing two JSON states.
func generateDiffSummary(oldRaw, newRaw *json.RawMessage) string {
	if oldRaw == nil || newRaw == nil {
		return ""
	}

	var oldMap, newMap map[string]any
	if err := json.Unmarshal(*oldRaw, &oldMap); err != nil {
		return ""
	}
	if err := json.Unmarshal(*newRaw, &newMap); err != nil {
		return ""
	}

	var changes []string

	// Find modified and deleted keys
	for k, oldVal := range oldMap {
		newVal, exists := newMap[k]
		if !exists {
			changes = append(changes, fmt.Sprintf("-%s", k))
			continue
		}
		oldStr := fmt.Sprintf("%v", oldVal)
		newStr := fmt.Sprintf("%v", newVal)
		if oldStr != newStr {
			changes = append(changes, fmt.Sprintf("~%s", k))
		}
	}

	// Find added keys
	for k := range newMap {
		if _, exists := oldMap[k]; !exists {
			changes = append(changes, fmt.Sprintf("+%s", k))
		}
	}

	if len(changes) == 0 {
		return "no changes detected"
	}

	summary := strings.Join(changes, ", ")
	if len(summary) > 500 {
		summary = summary[:497] + "..."
	}
	return summary
}
