// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
)

// AgentEventRepository implements protocol.EventStore for PostgreSQL.
type AgentEventRepository struct {
	db *DB
}

// NewAgentEventRepository creates a new agent event repository.
func NewAgentEventRepository(db *DB) *AgentEventRepository {
	return &AgentEventRepository{db: db}
}

// Save persists an agent event.
func (r *AgentEventRepository) Save(ctx context.Context, event *protocol.Event) error {
	var actorJSON, attrsJSON, dataJSON []byte
	var err error

	if event.Actor != nil {
		actorJSON, err = json.Marshal(event.Actor)
		if err != nil {
			return errors.Wrap(err, errors.CodeInternal, "failed to marshal actor")
		}
	}

	if event.Attributes != nil {
		attrsJSON, err = json.Marshal(event.Attributes)
		if err != nil {
			return errors.Wrap(err, errors.CodeInternal, "failed to marshal attributes")
		}
	}

	if event.Data != nil {
		dataJSON, err = json.Marshal(event.Data)
		if err != nil {
			return errors.Wrap(err, errors.CodeInternal, "failed to marshal data")
		}
	}

	var hostID *uuid.UUID
	if event.HostID != "" {
		if id, parseErr := uuid.Parse(event.HostID); parseErr == nil {
			hostID = &id
		}
	}

	ts := event.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	query := `
		INSERT INTO agent_events (
			id, event_type, agent_id, host_id, severity,
			message, actor_json, attributes, data, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		)
		ON CONFLICT (id) DO NOTHING`

	// JSONB columns are passed as string (not []byte) because the
	// connection pool runs in pgx.QueryExecModeSimpleProtocol; see
	// encodeJSONObject in recon_repo.go for the full rationale.
	// nullableJSONBytes preserves a SQL NULL for fields the caller
	// never set, instead of converting them to the empty string the
	// JSONB column would reject.
	_, err = r.db.Exec(ctx, query,
		event.ID,
		string(event.Type),
		event.AgentID,
		hostID,
		string(event.Severity),
		event.Message,
		nullableJSONBytes(actorJSON),
		nullableJSONBytes(attrsJSON),
		nullableJSONBytes(dataJSON),
		ts,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to save agent event")
	}

	return nil
}

// GetByID retrieves an event by ID.
func (r *AgentEventRepository) GetByID(ctx context.Context, id string) (*protocol.Event, error) {
	query := `
		SELECT id, event_type, agent_id, host_id, severity,
			message, actor_json, attributes, data, created_at
		FROM agent_events
		WHERE id = $1`

	return r.scanEvent(r.db.QueryRow(ctx, query, id))
}

// List retrieves events with filters.
func (r *AgentEventRepository) List(ctx context.Context, opts protocol.EventListOptions) ([]*protocol.Event, int64, error) {
	var conditions []string
	var args []interface{}
	argNum := 1

	if opts.HostID != nil {
		conditions = append(conditions, fmt.Sprintf("host_id = $%d", argNum))
		args = append(args, *opts.HostID)
		argNum++
	}

	if opts.AgentID != "" {
		conditions = append(conditions, fmt.Sprintf("agent_id = $%d", argNum))
		args = append(args, opts.AgentID)
		argNum++
	}

	if opts.Type != nil {
		conditions = append(conditions, fmt.Sprintf("event_type = $%d", argNum))
		args = append(args, string(*opts.Type))
		argNum++
	}

	if opts.Severity != nil {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argNum))
		args = append(args, string(*opts.Severity))
		argNum++
	}

	if opts.Since != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argNum))
		args = append(args, *opts.Since)
		argNum++
	}

	if opts.Until != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argNum))
		args = append(args, *opts.Until)
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM agent_events %s", whereClause)
	var total int64
	if err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count agent events")
	}

	// Pagination defaults
	perPage := opts.PerPage
	if perPage <= 0 {
		perPage = 50
	}
	if perPage > 500 {
		perPage = 500
	}
	page := opts.Page
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * perPage

	// Sort order
	sortDir := "DESC"
	if !opts.SortDesc {
		sortDir = "ASC"
	}

	query := fmt.Sprintf(`
		SELECT id, event_type, agent_id, host_id, severity,
			message, actor_json, attributes, data, created_at
		FROM agent_events
		%s
		ORDER BY created_at %s
		LIMIT $%d OFFSET $%d`,
		whereClause, sortDir, argNum, argNum+1)

	args = append(args, perPage, offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to list agent events")
	}
	defer rows.Close()

	var events []*protocol.Event
	for rows.Next() {
		evt, err := r.scanEventRow(rows)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, evt)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "error iterating agent events")
	}

	return events, total, nil
}

// DeleteOlderThan removes events older than the specified duration.
func (r *AgentEventRepository) DeleteOlderThan(ctx context.Context, duration time.Duration) (int64, error) {
	cutoff := time.Now().Add(-duration)
	result, err := r.db.Exec(ctx,
		`DELETE FROM agent_events WHERE created_at < $1`,
		cutoff,
	)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to delete old agent events")
	}
	return result.RowsAffected(), nil
}

// scanEvent scans a single row into a protocol.Event.
func (r *AgentEventRepository) scanEvent(row pgx.Row) (*protocol.Event, error) {
	evt := &protocol.Event{}
	var hostID *uuid.UUID
	var actorJSON, attrsJSON, dataJSON []byte
	var eventType, severity string

	err := row.Scan(
		&evt.ID,
		&eventType,
		&evt.AgentID,
		&hostID,
		&severity,
		&evt.Message,
		&actorJSON,
		&attrsJSON,
		&dataJSON,
		&evt.Timestamp,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.NotFound("agent event")
	}
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan agent event")
	}

	evt.Type = protocol.EventType(eventType)
	evt.Severity = protocol.EventSeverity(severity)
	if hostID != nil {
		evt.HostID = hostID.String()
	}

	if len(actorJSON) > 0 {
		var actor protocol.EventActor
		if err := json.Unmarshal(actorJSON, &actor); err == nil {
			evt.Actor = &actor
		}
	}

	if len(attrsJSON) > 0 {
		var attrs map[string]string
		if err := json.Unmarshal(attrsJSON, &attrs); err == nil {
			evt.Attributes = attrs
		}
	}

	if len(dataJSON) > 0 {
		var data interface{}
		if err := json.Unmarshal(dataJSON, &data); err == nil {
			evt.Data = data
		}
	}

	return evt, nil
}

// scanEventRow scans a pgx.Rows row into a protocol.Event.
func (r *AgentEventRepository) scanEventRow(rows pgx.Rows) (*protocol.Event, error) {
	evt := &protocol.Event{}
	var hostID *uuid.UUID
	var actorJSON, attrsJSON, dataJSON []byte
	var eventType, severity string

	err := rows.Scan(
		&evt.ID,
		&eventType,
		&evt.AgentID,
		&hostID,
		&severity,
		&evt.Message,
		&actorJSON,
		&attrsJSON,
		&dataJSON,
		&evt.Timestamp,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan agent event row")
	}

	evt.Type = protocol.EventType(eventType)
	evt.Severity = protocol.EventSeverity(severity)
	if hostID != nil {
		evt.HostID = hostID.String()
	}

	if len(actorJSON) > 0 {
		var actor protocol.EventActor
		if err := json.Unmarshal(actorJSON, &actor); err == nil {
			evt.Actor = &actor
		}
	}

	if len(attrsJSON) > 0 {
		var attrs map[string]string
		if err := json.Unmarshal(attrsJSON, &attrs); err == nil {
			evt.Attributes = attrs
		}
	}

	if len(dataJSON) > 0 {
		var data interface{}
		if err := json.Unmarshal(dataJSON, &data); err == nil {
			evt.Data = data
		}
	}

	return evt, nil
}

// Verify interface compliance.
var _ protocol.EventStore = (*AgentEventRepository)(nil)
