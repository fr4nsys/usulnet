// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package calendar provides an operations calendar for usulnet.
//
// The calendar surfaces three classes of events:
//
//  1. Manually-entered events (maintenance windows, deploys, notes)
//     persisted in the calendar_events table.
//  2. Backup runs and scheduled backup windows pulled from the backup
//     service via an EventSource implementation.
//  3. Scheduled jobs and crontab entries pulled from the scheduler and
//     crontab services via EventSource implementations.
//
// Aggregator events are never persisted: the EventSource interface
// returns them at read time so the calendar always reflects the truth
// in the originating service.
//
// The service is a free AGPL feature — no biz gating, no edition checks,
// no call-home.
package calendar

import (
	"context"
	stderrors "errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Sentinel errors returned by the service.
var (
	// ErrInvalidInput is returned when an event payload fails validation
	// (empty title, invalid kind, ends_at before starts_at).
	ErrInvalidInput = stderrors.New("calendar: invalid input")

	// ErrInvalidRange is returned when a range query has To <= From.
	ErrInvalidRange = stderrors.New("calendar: invalid range")
)

const (
	// MaxRangeDays caps a single range query to one year. Larger windows
	// fan out across every event source and risk OOM on a busy host.
	MaxRangeDays = 366

	// DefaultRangeDays is the default range when callers do not specify
	// from/to. Mirrors the v26.2.7 default of one month.
	DefaultRangeDays = 31
)

// Repository defines persistence for manual calendar events.
type Repository interface {
	Create(ctx context.Context, e *models.CalendarEvent) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.CalendarEvent, error)
	ListInRange(ctx context.Context, hostID uuid.UUID, from, to time.Time) ([]*models.CalendarEvent, error)
	ListAll(ctx context.Context, hostID uuid.UUID) ([]*models.CalendarEvent, error)
	Update(ctx context.Context, e *models.CalendarEvent) error
	Delete(ctx context.Context, id uuid.UUID) error
	GetStats(ctx context.Context, hostID uuid.UUID) (*models.CalendarStats, error)
}

// Service is the calendar service. Aggregator EventSource instances are
// registered via RegisterSource at boot; the order of registration is
// not significant because results are merged and re-sorted by StartsAt.
type Service struct {
	repo    Repository
	sources []EventSource
	logger  *logger.Logger
	prodID  string
}

// NewService constructs a calendar service with the given repository.
// Event sources are added afterwards via RegisterSource. The logger may
// be nil — a no-op logger is substituted to keep the constructor
// signature uniform across modules.
func NewService(repo Repository, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		repo:   repo,
		logger: log.Named("calendar"),
		prodID: "-//usulnet//calendar//EN",
	}
}

// RegisterSource adds an aggregator event source. Calling with nil is a
// no-op so callers can pass optional services without nil-checking.
func (s *Service) RegisterSource(src EventSource) {
	if src == nil {
		return
	}
	s.sources = append(s.sources, src)
	s.logger.Info("calendar event source registered", "name", src.Name())
}

// Sources returns the registered source names (read-only, used by the
// API handler to advertise capabilities).
func (s *Service) Sources() []string {
	out := make([]string, 0, len(s.sources)+1)
	out = append(out, "manual")
	for _, src := range s.sources {
		out = append(out, src.Name())
	}
	return out
}

// ============================================================================
// CRUD (manual events)
// ============================================================================

// Create persists a manual calendar event.
func (s *Service) Create(ctx context.Context, hostID uuid.UUID, input models.CreateCalendarEventInput, userID *uuid.UUID) (*models.CalendarEvent, error) {
	if err := validateCreate(input); err != nil {
		return nil, err
	}
	event := &models.CalendarEvent{
		ID:          uuid.New(),
		HostID:      hostID,
		Source:      models.CalendarSourceManual,
		Kind:        input.Kind,
		Title:       strings.TrimSpace(input.Title),
		Description: input.Description,
		Location:    input.Location,
		URL:         input.URL,
		StartsAt:    input.StartsAt,
		EndsAt:      input.EndsAt,
		AllDay:      input.AllDay,
		CreatedBy:   userID,
	}
	if err := s.repo.Create(ctx, event); err != nil {
		return nil, err
	}
	s.logger.Info("calendar event created",
		"id", event.ID, "kind", event.Kind, "title", event.Title,
		"starts_at", event.StartsAt, "ends_at", event.EndsAt)
	return event, nil
}

// Get retrieves a single manual event.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*models.CalendarEvent, error) {
	return s.repo.GetByID(ctx, id)
}

// Update modifies a manual event. Only the supplied fields are patched.
func (s *Service) Update(ctx context.Context, id uuid.UUID, input models.UpdateCalendarEventInput) (*models.CalendarEvent, error) {
	event, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.Kind != nil {
		if !models.IsValidCalendarKind(*input.Kind) {
			return nil, fmt.Errorf("%w: unknown kind %q", ErrInvalidInput, *input.Kind)
		}
		event.Kind = *input.Kind
	}
	if input.Title != nil {
		trimmed := strings.TrimSpace(*input.Title)
		if trimmed == "" {
			return nil, fmt.Errorf("%w: title must not be empty", ErrInvalidInput)
		}
		event.Title = trimmed
	}
	if input.Description != nil {
		event.Description = *input.Description
	}
	if input.Location != nil {
		event.Location = *input.Location
	}
	if input.URL != nil {
		event.URL = *input.URL
	}
	if input.StartsAt != nil {
		event.StartsAt = *input.StartsAt
	}
	if input.EndsAt != nil {
		event.EndsAt = *input.EndsAt
	}
	if event.EndsAt.Before(event.StartsAt) {
		return nil, fmt.Errorf("%w: ends_at must not be before starts_at", ErrInvalidInput)
	}
	if input.AllDay != nil {
		event.AllDay = *input.AllDay
	}

	if err := s.repo.Update(ctx, event); err != nil {
		return nil, err
	}
	s.logger.Info("calendar event updated", "id", id, "title", event.Title)
	return event, nil
}

// Delete removes a manual event.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}
	s.logger.Info("calendar event deleted", "id", id)
	return nil
}

// ============================================================================
// Aggregated queries
// ============================================================================

// ListEvents returns every event — manual + aggregator — whose window
// overlaps [from, to). Results are sorted ascending by StartsAt.
//
// Aggregator failures are logged and skipped: a backup service that
// errors must not blank the entire calendar. This mirrors the
// "non-fatal failures are logged but do not block startup" convention
// in CLAUDE.md.
func (s *Service) ListEvents(ctx context.Context, hostID uuid.UUID, from, to time.Time) ([]*models.CalendarEvent, error) {
	if !to.After(from) {
		return nil, fmt.Errorf("%w: to must be after from", ErrInvalidRange)
	}
	if to.Sub(from) > time.Duration(MaxRangeDays)*24*time.Hour {
		return nil, fmt.Errorf("%w: window exceeds %d days", ErrInvalidRange, MaxRangeDays)
	}

	manual, err := s.repo.ListInRange(ctx, hostID, from, to)
	if err != nil {
		return nil, err
	}
	out := make([]*models.CalendarEvent, 0, len(manual))
	out = append(out, manual...)

	r := models.CalendarRange{From: from, To: to}
	for _, src := range s.sources {
		events, err := src.ListEvents(ctx, hostID, r)
		if err != nil {
			s.logger.Warn("calendar event source failed",
				"name", src.Name(), "error", err,
				"from", from, "to", to)
			continue
		}
		out = append(out, events...)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].StartsAt.Equal(out[j].StartsAt) {
			return out[i].Title < out[j].Title
		}
		return out[i].StartsAt.Before(out[j].StartsAt)
	})
	return out, nil
}

// GetStats returns aggregate counts for manual events on a host.
func (s *Service) GetStats(ctx context.Context, hostID uuid.UUID) (*models.CalendarStats, error) {
	return s.repo.GetStats(ctx, hostID)
}

// ============================================================================
// iCalendar export
// ============================================================================

// ExportICS renders every manual event for a host as an RFC 5545 .ics
// document. Aggregator events are not included because clients
// subscribing to the URL would replay them every refresh; the iCalendar
// surface is the canonical record of operator-entered windows.
//
// The output is normalised:
//   - line endings: CRLF (\r\n) per RFC 5545 §3.1
//   - line folding: long lines split at 75 octets with CRLF + single space
//   - text escaping: backslash + comma + semicolon + newline escaping
//     per RFC 5545 §3.3.11
//   - timestamps: UTC with "Z" suffix
//   - PRODID + VERSION + CALSCALE: required calendar properties
func (s *Service) ExportICS(ctx context.Context, hostID uuid.UUID) ([]byte, error) {
	events, err := s.repo.ListAll(ctx, hostID)
	if err != nil {
		return nil, err
	}
	return RenderICS(s.prodID, events), nil
}

// ============================================================================
// Validation helpers
// ============================================================================

func validateCreate(in models.CreateCalendarEventInput) error {
	if strings.TrimSpace(in.Title) == "" {
		return fmt.Errorf("%w: title must not be empty", ErrInvalidInput)
	}
	if !models.IsValidCalendarKind(in.Kind) {
		return fmt.Errorf("%w: unknown kind %q", ErrInvalidInput, in.Kind)
	}
	if in.StartsAt.IsZero() {
		return fmt.Errorf("%w: starts_at must be set", ErrInvalidInput)
	}
	if in.EndsAt.IsZero() {
		return fmt.Errorf("%w: ends_at must be set", ErrInvalidInput)
	}
	if in.EndsAt.Before(in.StartsAt) {
		return fmt.Errorf("%w: ends_at must not be before starts_at", ErrInvalidInput)
	}
	return nil
}
