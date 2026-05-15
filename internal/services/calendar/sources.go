// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package calendar

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// EventSource is the read-only fan-in interface every aggregator
// implements. Sources never write into calendar_events; they translate
// rows from their own tables into transient CalendarEvent values that
// the service merges and sorts.
//
// Implementations MUST honor the supplied range — events outside it
// are useless to the caller and waste bandwidth.
//
// Errors are non-fatal: the service logs them and continues with the
// other sources so one broken source does not blank the whole calendar.
type EventSource interface {
	// Name returns a short identifier used in logs and the
	// /api/v1/calendar/sources response. Must be stable.
	Name() string

	// ListEvents returns CalendarEvents whose [StartsAt, EndsAt) window
	// overlaps the supplied range. hostID scopes the query in multi-host
	// installs; aggregators that have no host concept may ignore it.
	ListEvents(ctx context.Context, hostID uuid.UUID, r models.CalendarRange) ([]*models.CalendarEvent, error)
}

// ============================================================================
// BackupSource
// ============================================================================

// BackupLister is the narrow read surface the calendar needs from the
// backup repository. It is satisfied by *postgres.BackupRepository.
//
// Declared here rather than imported so the calendar service depends on
// behavior rather than the concrete repo, which keeps the unit tests
// hermetic.
type BackupLister interface {
	List(ctx context.Context, opts models.BackupListOptions) ([]*models.Backup, int64, error)
	ListSchedules(ctx context.Context, hostID *uuid.UUID) ([]*models.BackupSchedule, error)
}

// BackupSource is the EventSource that surfaces backup runs (started /
// completed timestamps) and scheduled backup windows (next run).
type BackupSource struct {
	backups BackupLister
}

// NewBackupSource wires a BackupLister into an EventSource.
func NewBackupSource(b BackupLister) *BackupSource {
	return &BackupSource{backups: b}
}

// Name implements EventSource.
func (s *BackupSource) Name() string { return "backup" }

// ListEvents implements EventSource by translating recent + in-range
// Backup rows and the next-run timestamps of every enabled schedule
// into CalendarEvents.
func (s *BackupSource) ListEvents(ctx context.Context, hostID uuid.UUID, r models.CalendarRange) ([]*models.CalendarEvent, error) {
	if s.backups == nil {
		return nil, nil
	}

	out := make([]*models.CalendarEvent, 0)

	// Backup runs: any backup that started within the window. The
	// Backup model uses StartedAt / CompletedAt; a still-running
	// backup gets EndsAt = StartsAt + 5 min so it has a non-zero
	// span on the calendar without claiming a fake completion.
	hostFilter := hostID
	opts := models.BackupListOptions{
		HostID: &hostFilter,
		After:  &r.From,
		Before: &r.To,
		Limit:  500,
	}
	runs, _, err := s.backups.List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("backup source: list runs: %w", err)
	}
	for _, b := range runs {
		ev := backupRunToEvent(b)
		if ev == nil {
			continue
		}
		out = append(out, ev)
	}

	// Scheduled backups: the NextRunAt of every enabled schedule that
	// lands inside the window. Past last-runs are already covered by
	// the backups query above so we only project the future.
	schedules, err := s.backups.ListSchedules(ctx, &hostFilter)
	if err != nil {
		return nil, fmt.Errorf("backup source: list schedules: %w", err)
	}
	for _, sched := range schedules {
		if !sched.IsEnabled || sched.NextRunAt == nil {
			continue
		}
		nr := *sched.NextRunAt
		// 5-minute synthetic span — the schedule has no duration.
		end := nr.Add(5 * time.Minute)
		if !nr.Before(r.To) || !end.After(r.From) {
			continue
		}
		out = append(out, &models.CalendarEvent{
			ID:         sched.ID,
			HostID:     sched.HostID,
			Source:     models.CalendarSourceBackup,
			Kind:       models.CalendarKindBackup,
			Title:      fmt.Sprintf("Scheduled backup: %s", sched.TargetName),
			StartsAt:   nr,
			EndsAt:     end,
			ExternalID: sched.ID.String(),
		})
	}

	return out, nil
}

// backupRunToEvent translates a single Backup into a CalendarEvent
// suitable for the calendar grid. Returns nil for runs without a
// StartedAt timestamp because they have not actually run yet.
func backupRunToEvent(b *models.Backup) *models.CalendarEvent {
	if b.StartedAt == nil {
		return nil
	}
	start := *b.StartedAt
	end := start.Add(5 * time.Minute)
	if b.CompletedAt != nil && b.CompletedAt.After(start) {
		end = *b.CompletedAt
	}

	title := fmt.Sprintf("Backup: %s", b.TargetName)
	if b.IsFailed() {
		title = "Backup failed: " + b.TargetName
	}
	return &models.CalendarEvent{
		ID:         b.ID,
		HostID:     b.HostID,
		Source:     models.CalendarSourceBackup,
		Kind:       models.CalendarKindBackup,
		Title:      title,
		StartsAt:   start,
		EndsAt:     end,
		ExternalID: b.ID.String(),
	}
}

// ============================================================================
// ScheduledJobSource
// ============================================================================

// ScheduledJobLister is the narrow surface the calendar needs from the
// job repository. Satisfied by *postgres.JobRepository.
type ScheduledJobLister interface {
	ListScheduledJobs(ctx context.Context, enabled *bool) ([]*models.ScheduledJob, error)
}

// ScheduledJobSource is the EventSource that surfaces scheduled job
// next-run timestamps. Past runs from the regular jobs table are not
// included here — they belong to the jobs page; the calendar shows
// upcoming work.
type ScheduledJobSource struct {
	jobs ScheduledJobLister
}

// NewScheduledJobSource wires a ScheduledJobLister into an EventSource.
func NewScheduledJobSource(j ScheduledJobLister) *ScheduledJobSource {
	return &ScheduledJobSource{jobs: j}
}

// Name implements EventSource.
func (s *ScheduledJobSource) Name() string { return "scheduled_job" }

// ListEvents implements EventSource.
func (s *ScheduledJobSource) ListEvents(ctx context.Context, hostID uuid.UUID, r models.CalendarRange) ([]*models.CalendarEvent, error) {
	if s.jobs == nil {
		return nil, nil
	}
	enabled := true
	jobs, err := s.jobs.ListScheduledJobs(ctx, &enabled)
	if err != nil {
		return nil, fmt.Errorf("scheduled_job source: list: %w", err)
	}
	out := make([]*models.CalendarEvent, 0, len(jobs))
	for _, j := range jobs {
		if j.NextRunAt == nil {
			continue
		}
		// Optional per-host filter. ScheduledJobs may be host-scoped
		// (e.g. backup workers) or global (e.g. cleanup). Both are
		// shown when hostID matches OR the job has no HostID set.
		if j.HostID != nil && *j.HostID != hostID {
			continue
		}
		start := *j.NextRunAt
		end := start.Add(5 * time.Minute)
		if !start.Before(r.To) || !end.After(r.From) {
			continue
		}
		title := fmt.Sprintf("Scheduled job: %s", j.Name)
		hid := uuid.Nil
		if j.HostID != nil {
			hid = *j.HostID
		}
		out = append(out, &models.CalendarEvent{
			ID:         j.ID,
			HostID:     hid,
			Source:     models.CalendarSourceScheduledJob,
			Kind:       models.CalendarKindJob,
			Title:      title,
			StartsAt:   start,
			EndsAt:     end,
			ExternalID: j.ID.String(),
		})
	}
	return out, nil
}
