// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	stderrors "errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// CalendarRepository implements persistence for manually-entered
// calendar events. Aggregator-sourced events (backups, jobs, …) are
// not persisted; they are merged in at read time by the service.
type CalendarRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewCalendarRepository creates a new calendar repository.
func NewCalendarRepository(db *DB, log *logger.Logger) *CalendarRepository {
	if log == nil {
		log = logger.Nop()
	}
	return &CalendarRepository{
		db:     db,
		logger: log.Named("calendar_repo"),
	}
}

// Create inserts a new manual calendar event.
func (r *CalendarRepository) Create(ctx context.Context, e *models.CalendarEvent) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.Source == "" {
		e.Source = models.CalendarSourceManual
	}
	now := time.Now()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	e.UpdatedAt = now

	_, err := r.db.Exec(ctx, `
		INSERT INTO calendar_events (
			id, host_id, source, kind, title, description, location, url,
			starts_at, ends_at, all_day, created_by, created_at, updated_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14
		)`,
		e.ID, e.HostID, string(e.Source), string(e.Kind), e.Title, e.Description,
		e.Location, e.URL, e.StartsAt, e.EndsAt, e.AllDay,
		e.CreatedBy, e.CreatedAt, e.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "calendar: create event")
	}
	return nil
}

// GetByID retrieves a single event by ID.
func (r *CalendarRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.CalendarEvent, error) {
	rows, err := r.db.Query(ctx, `SELECT * FROM calendar_events WHERE id = $1`, id)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "calendar: query event")
	}
	defer rows.Close()

	e, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.CalendarEvent])
	if err != nil {
		if stderrors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("calendar event").WithDetail("id", id.String())
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "calendar: scan event")
	}
	return e, nil
}

// ListInRange returns manual events whose window overlaps [from, to).
// Overlap is "starts before window end AND ends after window start" —
// the inclusive forms are not used because half-open intervals match
// iCalendar's DTSTART/DTEND semantics.
func (r *CalendarRepository) ListInRange(ctx context.Context, hostID uuid.UUID, from, to time.Time) ([]*models.CalendarEvent, error) {
	rows, err := r.db.Query(ctx, `
		SELECT * FROM calendar_events
		WHERE host_id = $1
		  AND starts_at < $3
		  AND ends_at   > $2
		ORDER BY starts_at ASC`,
		hostID, from, to,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "calendar: list events in range")
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.CalendarEvent])
}

// ListAll returns every manual event for a host. Used by the iCalendar
// export when the caller does not constrain a window.
func (r *CalendarRepository) ListAll(ctx context.Context, hostID uuid.UUID) ([]*models.CalendarEvent, error) {
	rows, err := r.db.Query(ctx,
		`SELECT * FROM calendar_events WHERE host_id = $1 ORDER BY starts_at ASC`,
		hostID,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "calendar: list all events")
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.CalendarEvent])
}

// Update modifies an existing manual event.
func (r *CalendarRepository) Update(ctx context.Context, e *models.CalendarEvent) error {
	e.UpdatedAt = time.Now()

	ct, err := r.db.Exec(ctx, `
		UPDATE calendar_events SET
			kind=$2, title=$3, description=$4, location=$5, url=$6,
			starts_at=$7, ends_at=$8, all_day=$9, updated_at=$10
		WHERE id=$1`,
		e.ID, string(e.Kind), e.Title, e.Description, e.Location, e.URL,
		e.StartsAt, e.EndsAt, e.AllDay, e.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "calendar: update event")
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("calendar event").WithDetail("id", e.ID.String())
	}
	return nil
}

// Delete removes a manual event.
func (r *CalendarRepository) Delete(ctx context.Context, id uuid.UUID) error {
	ct, err := r.db.Exec(ctx, `DELETE FROM calendar_events WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "calendar: delete event")
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("calendar event").WithDetail("id", id.String())
	}
	return nil
}

// GetStats returns aggregate counts grouped by kind for a host's manual
// events. Aggregator events are not counted — those are surfaced by the
// service from each source's own statistics.
func (r *CalendarRepository) GetStats(ctx context.Context, hostID uuid.UUID) (*models.CalendarStats, error) {
	var s models.CalendarStats
	err := r.db.QueryRow(ctx, `
		SELECT
			COUNT(*)                                                AS total,
			COUNT(*) FILTER (WHERE kind = 'maintenance')            AS maintenance,
			COUNT(*) FILTER (WHERE kind = 'backup')                 AS backup,
			COUNT(*) FILTER (WHERE kind = 'deploy')                 AS deploy,
			COUNT(*) FILTER (WHERE kind = 'job')                    AS job,
			COUNT(*) FILTER (WHERE kind = 'alert')                  AS alert,
			COUNT(*) FILTER (WHERE kind = 'note')                   AS note
		FROM calendar_events
		WHERE host_id = $1`, hostID,
	).Scan(&s.Total, &s.Maintenance, &s.Backup, &s.Deploy, &s.Job, &s.Alert, &s.Note)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "calendar: get stats")
	}
	return &s, nil
}
