// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ChangeEventRepository handles change event database operations.
type ChangeEventRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewChangeEventRepository creates a new ChangeEventRepository.
func NewChangeEventRepository(db *DB, log *logger.Logger) *ChangeEventRepository {
	return &ChangeEventRepository{
		db:     db,
		logger: log.Named("change_event_repo"),
	}
}

// changeCols is the shared column list for SELECT queries.
const changeCols = `id, timestamp, user_id, user_name, client_ip,
	resource_type, resource_id, resource_name, action,
	old_state, new_state, diff_summary, related_ticket, metadata`

// scanChangeEvent scans a row into a ChangeEvent.
func scanChangeEvent(row pgx.Row) (*models.ChangeEvent, error) {
	var e models.ChangeEvent
	var clientIP *net.IP
	err := row.Scan(
		&e.ID, &e.Timestamp, &e.UserID, &e.UserName, &clientIP,
		&e.ResourceType, &e.ResourceID, &e.ResourceName, &e.Action,
		&e.OldState, &e.NewState, &e.DiffSummary, &e.RelatedTicket, &e.Metadata,
	)
	if err != nil {
		return nil, err
	}
	if clientIP != nil {
		e.ClientIP = clientIP.String()
	}
	return &e, nil
}

// scanChangeEvents scans multiple rows into a slice of ChangeEvent.
func scanChangeEvents(rows pgx.Rows) ([]*models.ChangeEvent, error) {
	var events []*models.ChangeEvent
	for rows.Next() {
		var e models.ChangeEvent
		var clientIP *net.IP
		err := rows.Scan(
			&e.ID, &e.Timestamp, &e.UserID, &e.UserName, &clientIP,
			&e.ResourceType, &e.ResourceID, &e.ResourceName, &e.Action,
			&e.OldState, &e.NewState, &e.DiffSummary, &e.RelatedTicket, &e.Metadata,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning change event row: %w", err)
		}
		if clientIP != nil {
			e.ClientIP = clientIP.String()
		}
		events = append(events, &e)
	}
	return events, rows.Err()
}

// Create inserts a new change event.
func (r *ChangeEventRepository) Create(ctx context.Context, e *models.ChangeEvent) error {
	query := `
		INSERT INTO change_events (
			user_id, user_name, client_ip, resource_type, resource_id,
			resource_name, action, old_state, new_state, diff_summary,
			related_ticket, metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		) RETURNING id, timestamp`

	var clientIP *net.IP
	if e.ClientIP != "" {
		parsed := net.ParseIP(e.ClientIP)
		clientIP = &parsed
	}

	oldJSON, _ := nullableJSON(e.OldState)
	newJSON, _ := nullableJSON(e.NewState)
	metaJSON, _ := nullableJSON(e.Metadata)

	err := r.db.QueryRow(ctx, query,
		e.UserID, e.UserName, clientIP,
		e.ResourceType, e.ResourceID, e.ResourceName,
		e.Action, oldJSON, newJSON, e.DiffSummary,
		e.RelatedTicket, metaJSON,
	).Scan(&e.ID, &e.Timestamp)
	if err != nil {
		return fmt.Errorf("creating change event: %w", err)
	}
	return nil
}

// GetByID retrieves a single change event by ID.
func (r *ChangeEventRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ChangeEvent, error) {
	query := fmt.Sprintf(`SELECT %s FROM change_events WHERE id = $1`, changeCols)
	e, err := scanChangeEvent(r.db.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("getting change event %s: %w", id, err)
	}
	return e, nil
}

// List retrieves change events with filtering and pagination.
func (r *ChangeEventRepository) List(ctx context.Context, opts models.ChangeEventListOptions) ([]*models.ChangeEvent, int, error) {
	var conditions []string
	var args []any
	argIdx := 1

	if opts.UserID != nil {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argIdx))
		args = append(args, *opts.UserID)
		argIdx++
	}
	if opts.ResourceType != "" {
		conditions = append(conditions, fmt.Sprintf("resource_type = $%d", argIdx))
		args = append(args, opts.ResourceType)
		argIdx++
	}
	if opts.ResourceID != "" {
		conditions = append(conditions, fmt.Sprintf("resource_id = $%d", argIdx))
		args = append(args, opts.ResourceID)
		argIdx++
	}
	if opts.Action != "" {
		conditions = append(conditions, fmt.Sprintf("action = $%d", argIdx))
		args = append(args, opts.Action)
		argIdx++
	}
	if opts.Since != nil {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argIdx))
		args = append(args, *opts.Since)
		argIdx++
	}
	if opts.Until != nil {
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argIdx))
		args = append(args, *opts.Until)
		argIdx++
	}
	if opts.Search != "" {
		conditions = append(conditions, fmt.Sprintf("search_text @@ plainto_tsquery('english', $%d)", argIdx))
		args = append(args, opts.Search)
		argIdx++
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total matching
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM change_events %s", where)
	var total int
	if err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting change events: %w", err)
	}

	// Fetch page
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}

	dataQuery := fmt.Sprintf(
		"SELECT %s FROM change_events %s ORDER BY timestamp DESC LIMIT $%d OFFSET $%d",
		changeCols, where, argIdx, argIdx+1,
	)
	args = append(args, limit, offset)

	rows, err := r.db.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing change events: %w", err)
	}
	defer rows.Close()

	events, err := scanChangeEvents(rows)
	if err != nil {
		return nil, 0, err
	}
	return events, total, nil
}

// GetByResource retrieves change events for a specific resource.
func (r *ChangeEventRepository) GetByResource(ctx context.Context, resourceType, resourceID string, limit int) ([]*models.ChangeEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	query := fmt.Sprintf(
		"SELECT %s FROM change_events WHERE resource_type = $1 AND resource_id = $2 ORDER BY timestamp DESC LIMIT $3",
		changeCols,
	)
	rows, err := r.db.Query(ctx, query, resourceType, resourceID, limit)
	if err != nil {
		return nil, fmt.Errorf("getting change events by resource: %w", err)
	}
	defer rows.Close()
	return scanChangeEvents(rows)
}

// GetByUser retrieves change events for a specific user.
func (r *ChangeEventRepository) GetByUser(ctx context.Context, userID uuid.UUID, limit int) ([]*models.ChangeEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	query := fmt.Sprintf(
		"SELECT %s FROM change_events WHERE user_id = $1 ORDER BY timestamp DESC LIMIT $2",
		changeCols,
	)
	rows, err := r.db.Query(ctx, query, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("getting change events by user: %w", err)
	}
	defer rows.Close()
	return scanChangeEvents(rows)
}

// GetStats returns aggregated statistics for change events.
func (r *ChangeEventRepository) GetStats(ctx context.Context, since time.Time) (*models.ChangeEventStats, error) {
	stats := &models.ChangeEventStats{
		ByAction:   make(map[string]int),
		ByResource: make(map[string]int),
	}

	// Total count
	err := r.db.QueryRow(ctx,
		"SELECT COUNT(*) FROM change_events WHERE timestamp >= $1", since,
	).Scan(&stats.TotalEvents)
	if err != nil {
		return nil, fmt.Errorf("counting change events: %w", err)
	}

	// Today count
	today := time.Now().Truncate(24 * time.Hour)
	err = r.db.QueryRow(ctx,
		"SELECT COUNT(*) FROM change_events WHERE timestamp >= $1", today,
	).Scan(&stats.TodayEvents)
	if err != nil {
		return nil, fmt.Errorf("counting today's events: %w", err)
	}

	// By action
	rows, err := r.db.Query(ctx,
		"SELECT action, COUNT(*) FROM change_events WHERE timestamp >= $1 GROUP BY action ORDER BY COUNT(*) DESC",
		since,
	)
	if err != nil {
		return nil, fmt.Errorf("getting action stats: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var action string
		var count int
		if err := rows.Scan(&action, &count); err != nil {
			return nil, err
		}
		stats.ByAction[action] = count
	}

	// By resource type
	rows2, err := r.db.Query(ctx,
		"SELECT resource_type, COUNT(*) FROM change_events WHERE timestamp >= $1 GROUP BY resource_type ORDER BY COUNT(*) DESC",
		since,
	)
	if err != nil {
		return nil, fmt.Errorf("getting resource stats: %w", err)
	}
	defer rows2.Close()
	for rows2.Next() {
		var rt string
		var count int
		if err := rows2.Scan(&rt, &count); err != nil {
			return nil, err
		}
		stats.ByResource[rt] = count
	}

	// Top 10 users
	rows3, err := r.db.Query(ctx,
		"SELECT user_name, COUNT(*) AS cnt FROM change_events WHERE timestamp >= $1 AND user_name != '' GROUP BY user_name ORDER BY cnt DESC LIMIT 10",
		since,
	)
	if err != nil {
		return nil, fmt.Errorf("getting user stats: %w", err)
	}
	defer rows3.Close()
	for rows3.Next() {
		var s models.ChangeUserStat
		if err := rows3.Scan(&s.UserName, &s.Count); err != nil {
			return nil, err
		}
		stats.TopUsers = append(stats.TopUsers, s)
	}

	return stats, nil
}

// DeleteOlderThan removes change events older than the given time.
func (r *ChangeEventRepository) DeleteOlderThan(ctx context.Context, before time.Time) (int64, error) {
	tag, err := r.db.Exec(ctx,
		"DELETE FROM change_events WHERE timestamp < $1", before,
	)
	if err != nil {
		return 0, fmt.Errorf("deleting old change events: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ExportCSV returns change events formatted as CSV rows.
func (r *ChangeEventRepository) ExportCSV(ctx context.Context, opts models.ChangeEventListOptions) ([][]string, error) {
	events, _, err := r.List(ctx, opts)
	if err != nil {
		return nil, err
	}

	rows := [][]string{
		{"ID", "Timestamp", "User", "IP", "Resource Type", "Resource ID", "Resource Name", "Action", "Diff Summary", "Ticket"},
	}
	for _, e := range events {
		rows = append(rows, []string{
			e.ID.String(),
			e.Timestamp.Format(time.RFC3339),
			e.UserName,
			e.ClientIP,
			e.ResourceType,
			e.ResourceID,
			e.ResourceName,
			e.Action,
			e.DiffSummary,
			e.RelatedTicket,
		})
	}
	return rows, nil
}

// nullableJSON converts a *json.RawMessage to a []byte suitable for pgx, or nil.
func nullableJSON(raw *json.RawMessage) ([]byte, error) {
	if raw == nil || len(*raw) == 0 {
		return nil, nil
	}
	return []byte(*raw), nil
}
