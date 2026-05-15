// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// CalendarEventSource identifies where a calendar event originated. The
// "manual" source is the only one persisted in the calendar_events table;
// every other source is fanned in at read time from another service so
// the calendar never duplicates the truth.
type CalendarEventSource string

const (
	// CalendarSourceManual is an event hand-entered via the web UI or API.
	CalendarSourceManual CalendarEventSource = "manual"
	// CalendarSourceBackup surfaces backup runs (started/completed timestamps).
	CalendarSourceBackup CalendarEventSource = "backup"
	// CalendarSourceScheduledJob surfaces scheduled job next-run windows.
	CalendarSourceScheduledJob CalendarEventSource = "scheduled_job"
)

// CalendarEventKind classifies an event for filtering and styling. The
// list is a strict allow-list; aggregating sources must pick one of
// these values rather than inventing new ones.
type CalendarEventKind string

const (
	// CalendarKindMaintenance is a planned maintenance window.
	CalendarKindMaintenance CalendarEventKind = "maintenance"
	// CalendarKindBackup is a backup run or scheduled backup window.
	CalendarKindBackup CalendarEventKind = "backup"
	// CalendarKindDeploy is a deploy or release event.
	CalendarKindDeploy CalendarEventKind = "deploy"
	// CalendarKindJob is a scheduled job execution.
	CalendarKindJob CalendarEventKind = "job"
	// CalendarKindAlert is a service alert window.
	CalendarKindAlert CalendarEventKind = "alert"
	// CalendarKindNote is a free-form annotation.
	CalendarKindNote CalendarEventKind = "note"
)

// ValidCalendarKinds returns the allow-list of event kinds. The
// repository and service reject anything outside this set so the table
// stays a usable calendar instead of a junk drawer.
func ValidCalendarKinds() []CalendarEventKind {
	return []CalendarEventKind{
		CalendarKindMaintenance,
		CalendarKindBackup,
		CalendarKindDeploy,
		CalendarKindJob,
		CalendarKindAlert,
		CalendarKindNote,
	}
}

// IsValidCalendarKind reports whether k is in the allow-list.
func IsValidCalendarKind(k CalendarEventKind) bool {
	for _, v := range ValidCalendarKinds() {
		if k == v {
			return true
		}
	}
	return false
}

// CalendarEvent is one event displayed on the operations calendar. Only
// manually-entered events live in the calendar_events table; events from
// other services are materialized on demand by the aggregator.
type CalendarEvent struct {
	ID          uuid.UUID           `json:"id" db:"id"`
	HostID      uuid.UUID           `json:"host_id" db:"host_id"`
	Source      CalendarEventSource `json:"source" db:"source"`
	Kind        CalendarEventKind   `json:"kind" db:"kind"`
	Title       string              `json:"title" db:"title"`
	Description string              `json:"description,omitempty" db:"description"`
	Location    string              `json:"location,omitempty" db:"location"`
	URL         string              `json:"url,omitempty" db:"url"`
	StartsAt    time.Time           `json:"starts_at" db:"starts_at"`
	EndsAt      time.Time           `json:"ends_at" db:"ends_at"`
	AllDay      bool                `json:"all_day" db:"all_day"`
	// ExternalID lets aggregators key derived events back to the underlying
	// row (e.g. a backup's UUID) without writing into calendar_events.
	ExternalID string     `json:"external_id,omitempty" db:"-"`
	CreatedBy  *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at" db:"updated_at"`
}

// CreateCalendarEventInput is the input for creating a manual event.
// Source is always "manual" — aggregator events are never persisted.
type CreateCalendarEventInput struct {
	Kind        CalendarEventKind
	Title       string
	Description string
	Location    string
	URL         string
	StartsAt    time.Time
	EndsAt      time.Time
	AllDay      bool
}

// UpdateCalendarEventInput is the input for updating a manual event.
type UpdateCalendarEventInput struct {
	Kind        *CalendarEventKind
	Title       *string
	Description *string
	Location    *string
	URL         *string
	StartsAt    *time.Time
	EndsAt      *time.Time
	AllDay      *bool
}

// CalendarRange is the half-open time window queried against the
// aggregator. Events with StartsAt < To AND EndsAt > From overlap the
// window and are returned.
type CalendarRange struct {
	From time.Time
	To   time.Time
}

// CalendarStats holds aggregate counts for the calendar dashboard.
type CalendarStats struct {
	Total       int `json:"total"`
	Maintenance int `json:"maintenance"`
	Backup      int `json:"backup"`
	Deploy      int `json:"deploy"`
	Job         int `json:"job"`
	Alert       int `json:"alert"`
	Note        int `json:"note"`
}
