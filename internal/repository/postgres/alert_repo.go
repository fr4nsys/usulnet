// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// AlertRepository implements alert persistence.
type AlertRepository struct {
	db *DB
}

// NewAlertRepository creates a new alert repository.
func NewAlertRepository(db *DB) *AlertRepository {
	return &AlertRepository{db: db}
}

// CreateRule creates a new alert rule.
func (r *AlertRepository) CreateRule(ctx context.Context, rule *models.AlertRule) error {
	if rule.ID == uuid.Nil {
		rule.ID = uuid.New()
	}

	labelsJSON, _ := json.Marshal(rule.Labels)
	autoActionsJSON := rule.AutoActions
	if autoActionsJSON == nil {
		autoActionsJSON = json.RawMessage("null")
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO alert_rules (
			id, host_id, container_id, name, description, metric, operator, threshold,
			severity, duration_seconds, cooldown_seconds, eval_interval_seconds,
			state, notify_channels, auto_actions, is_enabled, labels, created_by
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		rule.ID, rule.HostID, rule.ContainerID, rule.Name, rule.Description,
		rule.Metric, rule.Operator, rule.Threshold, rule.Severity,
		rule.Duration, rule.Cooldown, rule.EvalInterval,
		rule.State, pq.Array(rule.NotifyChannels), autoActionsJSON,
		rule.IsEnabled, labelsJSON, rule.CreatedBy,
	)
	return err
}

// GetRule retrieves an alert rule by ID.
func (r *AlertRepository) GetRule(ctx context.Context, id uuid.UUID) (*models.AlertRule, error) {
	rule := &models.AlertRule{}
	var labelsJSON, autoActionsJSON []byte

	err := r.db.QueryRow(ctx, `
		SELECT id, host_id, container_id, name, description, metric, operator, threshold,
			severity, duration_seconds, cooldown_seconds, eval_interval_seconds,
			state, state_changed_at, last_evaluated, last_fired_at, firing_value,
			notify_channels, auto_actions, is_enabled, labels, created_by, created_at, updated_at
		FROM alert_rules WHERE id = $1`, id).Scan(
		&rule.ID, &rule.HostID, &rule.ContainerID, &rule.Name, &rule.Description,
		&rule.Metric, &rule.Operator, &rule.Threshold, &rule.Severity,
		&rule.Duration, &rule.Cooldown, &rule.EvalInterval,
		&rule.State, &rule.StateChangedAt, &rule.LastEvaluated, &rule.LastFiredAt, &rule.FiringValue,
		pq.Array(&rule.NotifyChannels), &autoActionsJSON, &rule.IsEnabled, &labelsJSON,
		&rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if labelsJSON != nil {
		json.Unmarshal(labelsJSON, &rule.Labels)
	}
	if autoActionsJSON != nil {
		rule.AutoActions = autoActionsJSON
	}

	return rule, nil
}

// UpdateRule updates an alert rule.
func (r *AlertRepository) UpdateRule(ctx context.Context, rule *models.AlertRule) error {
	labelsJSON, _ := json.Marshal(rule.Labels)

	_, err := r.db.Exec(ctx, `
		UPDATE alert_rules SET
			name=$2, description=$3, threshold=$4, severity=$5,
			duration_seconds=$6, cooldown_seconds=$7, eval_interval_seconds=$8,
			state=$9, state_changed_at=$10, last_evaluated=$11, last_fired_at=$12, firing_value=$13,
			notify_channels=$14, auto_actions=$15, is_enabled=$16, labels=$17
		WHERE id=$1`,
		rule.ID, rule.Name, rule.Description, rule.Threshold, rule.Severity,
		rule.Duration, rule.Cooldown, rule.EvalInterval,
		rule.State, rule.StateChangedAt, rule.LastEvaluated, rule.LastFiredAt, rule.FiringValue,
		pq.Array(rule.NotifyChannels), rule.AutoActions, rule.IsEnabled, labelsJSON,
	)
	return err
}

// DeleteRule deletes an alert rule.
func (r *AlertRepository) DeleteRule(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM alert_rules WHERE id = $1`, id)
	return err
}

// ListRules lists alert rules with filtering.
func (r *AlertRepository) ListRules(ctx context.Context, opts models.AlertListOptions) ([]*models.AlertRule, int64, error) {
	query := `SELECT id, host_id, container_id, name, description, metric, operator, threshold,
		severity, duration_seconds, cooldown_seconds, eval_interval_seconds,
		state, state_changed_at, last_evaluated, last_fired_at, firing_value,
		notify_channels, auto_actions, is_enabled, labels, created_by, created_at, updated_at
		FROM alert_rules WHERE 1=1`
	countQuery := `SELECT COUNT(*) FROM alert_rules WHERE 1=1`

	var args []interface{}
	argIdx := 1

	if opts.HostID != nil {
		clause := fmt.Sprintf(" AND (host_id = $%d OR host_id IS NULL)", argIdx)
		query += clause
		countQuery += clause
		args = append(args, *opts.HostID)
		argIdx++
	}
	if opts.Metric != nil {
		clause := fmt.Sprintf(" AND metric = $%d", argIdx)
		query += clause
		countQuery += clause
		args = append(args, *opts.Metric)
		argIdx++
	}
	if opts.Severity != nil {
		clause := fmt.Sprintf(" AND severity = $%d", argIdx)
		query += clause
		countQuery += clause
		args = append(args, *opts.Severity)
		argIdx++
	}
	if opts.State != nil {
		clause := fmt.Sprintf(" AND state = $%d", argIdx)
		query += clause
		countQuery += clause
		args = append(args, *opts.State)
		argIdx++
	}
	if opts.IsEnabled != nil {
		clause := fmt.Sprintf(" AND is_enabled = $%d", argIdx)
		query += clause
		countQuery += clause
		args = append(args, *opts.IsEnabled)
		argIdx++
	}

	var total int64
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	query += " ORDER BY created_at DESC"

	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, opts.Limit)
		argIdx++
	}
	if opts.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, opts.Offset)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var rules []*models.AlertRule
	for rows.Next() {
		rule := &models.AlertRule{}
		var labelsJSON, autoActionsJSON []byte

		err := rows.Scan(
			&rule.ID, &rule.HostID, &rule.ContainerID, &rule.Name, &rule.Description,
			&rule.Metric, &rule.Operator, &rule.Threshold, &rule.Severity,
			&rule.Duration, &rule.Cooldown, &rule.EvalInterval,
			&rule.State, &rule.StateChangedAt, &rule.LastEvaluated, &rule.LastFiredAt, &rule.FiringValue,
			pq.Array(&rule.NotifyChannels), &autoActionsJSON, &rule.IsEnabled, &labelsJSON,
			&rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt,
		)
		if err != nil {
			return nil, 0, err
		}

		if labelsJSON != nil {
			json.Unmarshal(labelsJSON, &rule.Labels)
		}
		if autoActionsJSON != nil {
			rule.AutoActions = autoActionsJSON
		}

		rules = append(rules, rule)
	}

	return rules, total, nil
}

// ListEnabledRules returns all enabled alert rules.
func (r *AlertRepository) ListEnabledRules(ctx context.Context) ([]*models.AlertRule, error) {
	enabled := true
	rules, _, err := r.ListRules(ctx, models.AlertListOptions{IsEnabled: &enabled, Limit: 1000})
	return rules, err
}

// CreateEvent creates a new alert event.
func (r *AlertRepository) CreateEvent(ctx context.Context, event *models.AlertEvent) error {
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}

	labelsJSON, _ := json.Marshal(event.Labels)

	_, err := r.db.Exec(ctx, `
		INSERT INTO alert_events (
			id, alert_id, host_id, container_id, state, value, threshold, message, labels, fired_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		event.ID, event.AlertID, event.HostID, event.ContainerID,
		event.State, event.Value, event.Threshold, event.Message, labelsJSON, event.FiredAt,
	)
	return err
}

// GetEvent retrieves an alert event by ID.
func (r *AlertRepository) GetEvent(ctx context.Context, id uuid.UUID) (*models.AlertEvent, error) {
	event := &models.AlertEvent{}
	var labelsJSON []byte

	err := r.db.QueryRow(ctx, `
		SELECT id, alert_id, host_id, container_id, state, value, threshold, message, labels,
			fired_at, resolved_at, acknowledged_at, acknowledged_by, created_at
		FROM alert_events WHERE id = $1`, id).Scan(
		&event.ID, &event.AlertID, &event.HostID, &event.ContainerID,
		&event.State, &event.Value, &event.Threshold, &event.Message, &labelsJSON,
		&event.FiredAt, &event.ResolvedAt, &event.AcknowledgedAt, &event.AcknowledgedBy, &event.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	if labelsJSON != nil {
		json.Unmarshal(labelsJSON, &event.Labels)
	}

	return event, nil
}

// UpdateEvent updates an alert event.
func (r *AlertRepository) UpdateEvent(ctx context.Context, event *models.AlertEvent) error {
	_, err := r.db.Exec(ctx, `
		UPDATE alert_events SET
			state=$2, resolved_at=$3, acknowledged_at=$4, acknowledged_by=$5
		WHERE id=$1`,
		event.ID, event.State, event.ResolvedAt, event.AcknowledgedAt, event.AcknowledgedBy,
	)
	return err
}

// ListEvents lists alert events with filtering.
func (r *AlertRepository) ListEvents(ctx context.Context, opts models.AlertEventListOptions) ([]*models.AlertEvent, int64, error) {
	query := `SELECT id, alert_id, host_id, container_id, state, value, threshold, message, labels,
		fired_at, resolved_at, acknowledged_at, acknowledged_by, created_at
		FROM alert_events WHERE 1=1`
	countQuery := `SELECT COUNT(*) FROM alert_events WHERE 1=1`

	var args []interface{}
	argIdx := 1

	if opts.AlertID != nil {
		clause := fmt.Sprintf(" AND alert_id = $%d", argIdx)
		query += clause
		countQuery += clause
		args = append(args, *opts.AlertID)
		argIdx++
	}
	if opts.HostID != nil {
		clause := fmt.Sprintf(" AND host_id = $%d", argIdx)
		query += clause
		countQuery += clause
		args = append(args, *opts.HostID)
		argIdx++
	}
	if opts.State != nil {
		clause := fmt.Sprintf(" AND state = $%d", argIdx)
		query += clause
		countQuery += clause
		args = append(args, *opts.State)
		argIdx++
	}
	if opts.From != nil {
		clause := fmt.Sprintf(" AND fired_at >= $%d", argIdx)
		query += clause
		countQuery += clause
		args = append(args, *opts.From)
		argIdx++
	}
	if opts.To != nil {
		clause := fmt.Sprintf(" AND fired_at <= $%d", argIdx)
		query += clause
		countQuery += clause
		args = append(args, *opts.To)
		argIdx++
	}

	var total int64
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	query += " ORDER BY fired_at DESC"

	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, opts.Limit)
		argIdx++
	}
	if opts.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, opts.Offset)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []*models.AlertEvent
	for rows.Next() {
		event := &models.AlertEvent{}
		var labelsJSON []byte

		err := rows.Scan(
			&event.ID, &event.AlertID, &event.HostID, &event.ContainerID,
			&event.State, &event.Value, &event.Threshold, &event.Message, &labelsJSON,
			&event.FiredAt, &event.ResolvedAt, &event.AcknowledgedAt, &event.AcknowledgedBy, &event.CreatedAt,
		)
		if err != nil {
			return nil, 0, err
		}

		if labelsJSON != nil {
			json.Unmarshal(labelsJSON, &event.Labels)
		}

		events = append(events, event)
	}

	return events, total, nil
}

// GetActiveEvents returns currently firing/pending events.
func (r *AlertRepository) GetActiveEvents(ctx context.Context) ([]*models.AlertEvent, error) {
	firing := models.AlertStateFiring
	events, _, err := r.ListEvents(ctx, models.AlertEventListOptions{State: &firing, Limit: 1000})
	return events, err
}

// CreateSilence creates a new alert silence.
func (r *AlertRepository) CreateSilence(ctx context.Context, silence *models.AlertSilence) error {
	if silence.ID == uuid.Nil {
		silence.ID = uuid.New()
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO alert_silences (id, alert_id, host_id, reason, starts_at, ends_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		silence.ID, silence.AlertID, silence.HostID, silence.Reason,
		silence.StartsAt, silence.EndsAt, silence.CreatedBy,
	)
	return err
}

// GetSilence retrieves a silence by ID.
func (r *AlertRepository) GetSilence(ctx context.Context, id uuid.UUID) (*models.AlertSilence, error) {
	silence := &models.AlertSilence{}
	err := r.db.QueryRow(ctx, `
		SELECT id, alert_id, host_id, reason, starts_at, ends_at, created_by, created_at
		FROM alert_silences WHERE id = $1`, id).Scan(
		&silence.ID, &silence.AlertID, &silence.HostID, &silence.Reason,
		&silence.StartsAt, &silence.EndsAt, &silence.CreatedBy, &silence.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return silence, nil
}

// DeleteSilence deletes a silence.
func (r *AlertRepository) DeleteSilence(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM alert_silences WHERE id = $1`, id)
	return err
}

// ListSilences returns all silences.
func (r *AlertRepository) ListSilences(ctx context.Context) ([]*models.AlertSilence, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, alert_id, host_id, reason, starts_at, ends_at, created_by, created_at
		FROM alert_silences ORDER BY starts_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var silences []*models.AlertSilence
	for rows.Next() {
		s := &models.AlertSilence{}
		if err := rows.Scan(&s.ID, &s.AlertID, &s.HostID, &s.Reason, &s.StartsAt, &s.EndsAt, &s.CreatedBy, &s.CreatedAt); err != nil {
			return nil, err
		}
		silences = append(silences, s)
	}
	return silences, nil
}

// GetActiveSilences returns currently active silences.
func (r *AlertRepository) GetActiveSilences(ctx context.Context) ([]*models.AlertSilence, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, alert_id, host_id, reason, starts_at, ends_at, created_by, created_at
		FROM alert_silences WHERE starts_at <= NOW() AND ends_at > NOW()
		ORDER BY starts_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var silences []*models.AlertSilence
	for rows.Next() {
		s := &models.AlertSilence{}
		if err := rows.Scan(&s.ID, &s.AlertID, &s.HostID, &s.Reason, &s.StartsAt, &s.EndsAt, &s.CreatedBy, &s.CreatedAt); err != nil {
			return nil, err
		}
		silences = append(silences, s)
	}
	return silences, nil
}

// GetStats returns alert statistics.
func (r *AlertRepository) GetStats(ctx context.Context) (*models.AlertStats, error) {
	stats := &models.AlertStats{
		BySeverity: make(map[string]int64),
		ByState:    make(map[string]int64),
	}

	// Count total rules
	err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM alert_rules`).Scan(&stats.TotalRules)
	if err != nil {
		return nil, err
	}

	// Count enabled rules
	err = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM alert_rules WHERE is_enabled = true`).Scan(&stats.EnabledRules)
	if err != nil {
		return nil, err
	}

	// Count firing events
	err = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM alert_events WHERE state = 'firing'`).Scan(&stats.FiringCount)
	if err != nil {
		return nil, err
	}

	// Count by state
	rows, err := r.db.Query(ctx, `SELECT state, COUNT(*) FROM alert_rules GROUP BY state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var state string
		var count int64
		if err := rows.Scan(&state, &count); err != nil {
			return nil, err
		}
		stats.ByState[state] = count
	}

	// Count by severity
	rows2, err := r.db.Query(ctx, `SELECT severity, COUNT(*) FROM alert_rules WHERE is_enabled = true GROUP BY severity`)
	if err != nil {
		return nil, err
	}
	defer rows2.Close()

	for rows2.Next() {
		var severity string
		var count int64
		if err := rows2.Scan(&severity, &count); err != nil {
			return nil, err
		}
		stats.BySeverity[severity] = count
	}

	// Events today
	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	err = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM alert_events WHERE fired_at >= $1`, todayStart).Scan(&stats.EventsToday)
	if err != nil {
		return nil, err
	}

	// Events this week
	weekStart := todayStart.AddDate(0, 0, -7)
	err = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM alert_events WHERE fired_at >= $1`, weekStart).Scan(&stats.EventsWeek)
	if err != nil {
		return nil, err
	}

	return stats, nil
}
