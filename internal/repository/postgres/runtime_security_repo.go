// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// RuntimeEventListOptions defines filtering and pagination options for listing
// runtime security events.
type RuntimeEventListOptions struct {
	ContainerID string
	Severity    string
	EventType   string
	Since       *time.Time
	Until       *time.Time
	Limit       int
	Offset      int
}

// RuntimeEventStats holds aggregated statistics for runtime security events.
type RuntimeEventStats struct {
	TotalEvents    int64                 `json:"total_events"`
	SeverityCounts map[string]int        `json:"severity_counts"`
	TypeCounts     map[string]int        `json:"type_counts"`
	TopContainers  []ContainerEventCount `json:"top_containers"`
}

// ContainerEventCount represents a container and its associated event count.
type ContainerEventCount struct {
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	EventCount    int    `json:"event_count"`
}

// RuntimeSecurityRepository implements persistence for runtime threat detection
// using pgx/v5.
type RuntimeSecurityRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewRuntimeSecurityRepository creates a new RuntimeSecurityRepository.
func NewRuntimeSecurityRepository(db *DB, log *logger.Logger) *RuntimeSecurityRepository {
	return &RuntimeSecurityRepository{
		db:     db,
		logger: log.Named("runtime_security_repo"),
	}
}

// runtimeEventColumns is the standard column list for runtime_security_events queries.
const runtimeEventColumns = `id, host_id, container_id, container_name, event_type,
	severity, rule_id, rule_name, description, details, source, action_taken,
	acknowledged, acknowledged_by, acknowledged_at, detected_at`

// scanRuntimeEventRows scans multiple pgx.Rows into a slice of models.RuntimeSecurityEvent.
func scanRuntimeEventRows(rows pgx.Rows) ([]*models.RuntimeSecurityEvent, error) {
	var events []*models.RuntimeSecurityEvent
	for rows.Next() {
		var e models.RuntimeSecurityEvent
		err := rows.Scan(
			&e.ID, &e.HostID, &e.ContainerID, &e.ContainerName, &e.EventType,
			&e.Severity, &e.RuleID, &e.RuleName, &e.Description, &e.Details,
			&e.Source, &e.ActionTaken, &e.Acknowledged, &e.AcknowledgedBy,
			&e.AcknowledgedAt, &e.DetectedAt,
		)
		if err != nil {
			return nil, err
		}
		events = append(events, &e)
	}
	return events, rows.Err()
}

// ============================================================================
// Event operations
// ============================================================================

// CreateEvent inserts a new runtime security event.
func (r *RuntimeSecurityRepository) CreateEvent(ctx context.Context, event *models.RuntimeSecurityEvent) error {
	log := logger.FromContext(ctx)

	query := `
		INSERT INTO runtime_security_events (
			host_id, container_id, container_name, event_type,
			severity, rule_id, rule_name, description, details,
			source, action_taken, detected_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8, $9,
			$10, $11, $12
		) RETURNING id`

	if event.DetectedAt.IsZero() {
		event.DetectedAt = time.Now()
	}

	err := r.db.QueryRow(ctx, query,
		event.HostID,
		event.ContainerID,
		event.ContainerName,
		event.EventType,
		event.Severity,
		event.RuleID,
		event.RuleName,
		event.Description,
		event.Details,
		event.Source,
		event.ActionTaken,
		event.DetectedAt,
	).Scan(&event.ID)

	if err != nil {
		log.Error("Failed to create runtime security event",
			"container_id", event.ContainerID,
			"event_type", event.EventType,
			"error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create runtime security event")
	}

	log.Debug("Runtime security event created",
		"event_id", event.ID,
		"container_id", event.ContainerID,
		"event_type", event.EventType,
		"severity", event.Severity)

	return nil
}

// CreateEventBatch inserts multiple runtime security events in a single transaction.
func (r *RuntimeSecurityRepository) CreateEventBatch(ctx context.Context, events []*models.RuntimeSecurityEvent) error {
	log := logger.FromContext(ctx)

	if len(events) == 0 {
		return nil
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to begin transaction for batch event insert")
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	query := `
		INSERT INTO runtime_security_events (
			host_id, container_id, container_name, event_type,
			severity, rule_id, rule_name, description, details,
			source, action_taken, detected_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8, $9,
			$10, $11, $12
		) RETURNING id`

	for _, event := range events {
		if event.DetectedAt.IsZero() {
			event.DetectedAt = time.Now()
		}

		err := tx.QueryRow(ctx, query,
			event.HostID,
			event.ContainerID,
			event.ContainerName,
			event.EventType,
			event.Severity,
			event.RuleID,
			event.RuleName,
			event.Description,
			event.Details,
			event.Source,
			event.ActionTaken,
			event.DetectedAt,
		).Scan(&event.ID)

		if err != nil {
			log.Error("Failed to create runtime security event in batch",
				"container_id", event.ContainerID,
				"error", err)
			return errors.Wrap(err, errors.CodeDatabaseError, "failed to create runtime security event in batch")
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to commit batch event insert")
	}

	log.Debug("Runtime security events batch created", "count", len(events))
	return nil
}

// ListEvents retrieves runtime security events with filtering and pagination.
// Returns the matching events, the total count (before pagination), and any error.
func (r *RuntimeSecurityRepository) ListEvents(ctx context.Context, opts RuntimeEventListOptions) ([]*models.RuntimeSecurityEvent, int64, error) {
	var conditions []string
	var args []interface{}
	argNum := 1

	if opts.ContainerID != "" {
		conditions = append(conditions, fmt.Sprintf("container_id = $%d", argNum))
		args = append(args, opts.ContainerID)
		argNum++
	}
	if opts.Severity != "" {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argNum))
		args = append(args, opts.Severity)
		argNum++
	}
	if opts.EventType != "" {
		conditions = append(conditions, fmt.Sprintf("event_type = $%d", argNum))
		args = append(args, opts.EventType)
		argNum++
	}
	if opts.Since != nil {
		conditions = append(conditions, fmt.Sprintf("detected_at >= $%d", argNum))
		args = append(args, *opts.Since)
		argNum++
	}
	if opts.Until != nil {
		conditions = append(conditions, fmt.Sprintf("detected_at <= $%d", argNum))
		args = append(args, *opts.Until)
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total matching events
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM runtime_security_events %s", whereClause)
	var total int64
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count runtime security events")
	}

	if opts.Limit <= 0 {
		opts.Limit = 50
	}

	query := fmt.Sprintf(`
		SELECT %s FROM runtime_security_events
		%s
		ORDER BY detected_at DESC
		LIMIT $%d OFFSET $%d`,
		runtimeEventColumns, whereClause, argNum, argNum+1)

	args = append(args, opts.Limit, opts.Offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to list runtime security events")
	}
	defer rows.Close()

	events, err := scanRuntimeEventRows(rows)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan runtime security event rows")
	}

	return events, total, nil
}

// AcknowledgeEvent marks a runtime security event as acknowledged.
func (r *RuntimeSecurityRepository) AcknowledgeEvent(ctx context.Context, eventID int64, userID uuid.UUID) error {
	log := logger.FromContext(ctx)

	result, err := r.db.Exec(ctx, `
		UPDATE runtime_security_events
		SET acknowledged = true, acknowledged_by = $1, acknowledged_at = $2
		WHERE id = $3 AND acknowledged = false`,
		userID, time.Now(), eventID)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to acknowledge runtime security event")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("runtime security event")
	}

	log.Debug("Runtime security event acknowledged", "event_id", eventID, "user_id", userID)
	return nil
}

// GetEventStats returns aggregated statistics for runtime security events
// detected since the given time.
func (r *RuntimeSecurityRepository) GetEventStats(ctx context.Context, since time.Time) (*RuntimeEventStats, error) {
	stats := &RuntimeEventStats{
		SeverityCounts: make(map[string]int),
		TypeCounts:     make(map[string]int),
	}

	// Total events
	err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM runtime_security_events WHERE detected_at >= $1`,
		since).Scan(&stats.TotalEvents)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to count total runtime events")
	}

	// Severity counts
	sevRows, err := r.db.Query(ctx, `
		SELECT severity, COUNT(*) as count
		FROM runtime_security_events
		WHERE detected_at >= $1
		GROUP BY severity`, since)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get severity counts")
	}
	defer sevRows.Close()

	for sevRows.Next() {
		var severity string
		var count int
		if err := sevRows.Scan(&severity, &count); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan severity count row")
		}
		stats.SeverityCounts[severity] = count
	}
	if err := sevRows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to iterate severity count rows")
	}

	// Type counts
	typeRows, err := r.db.Query(ctx, `
		SELECT event_type, COUNT(*) as count
		FROM runtime_security_events
		WHERE detected_at >= $1
		GROUP BY event_type`, since)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get event type counts")
	}
	defer typeRows.Close()

	for typeRows.Next() {
		var eventType string
		var count int
		if err := typeRows.Scan(&eventType, &count); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan event type count row")
		}
		stats.TypeCounts[eventType] = count
	}
	if err := typeRows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to iterate event type count rows")
	}

	// Top containers by event count
	topRows, err := r.db.Query(ctx, `
		SELECT container_id, container_name, COUNT(*) as event_count
		FROM runtime_security_events
		WHERE detected_at >= $1
		GROUP BY container_id, container_name
		ORDER BY event_count DESC
		LIMIT 10`, since)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get top containers")
	}
	defer topRows.Close()

	for topRows.Next() {
		var c ContainerEventCount
		if err := topRows.Scan(&c.ContainerID, &c.ContainerName, &c.EventCount); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan top container row")
		}
		stats.TopContainers = append(stats.TopContainers, c)
	}
	if err := topRows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to iterate top container rows")
	}

	return stats, nil
}

// DeleteOldEvents removes runtime security events older than the specified
// retention period. Returns the number of deleted rows.
func (r *RuntimeSecurityRepository) DeleteOldEvents(ctx context.Context, retention time.Duration) (int64, error) {
	log := logger.FromContext(ctx)

	cutoff := time.Now().Add(-retention)
	result, err := r.db.Exec(ctx,
		`DELETE FROM runtime_security_events WHERE detected_at < $1`, cutoff)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to delete old runtime security events")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected > 0 {
		log.Info("Deleted old runtime security events",
			"count", rowsAffected,
			"retention", retention.String(),
			"cutoff", cutoff)
	}

	return rowsAffected, nil
}

// ============================================================================
// Rule operations
// ============================================================================

// runtimeRuleColumns is the standard column list for runtime_security_rules queries.
const runtimeRuleColumns = `id, name, description, category, rule_type, definition,
	severity, action, is_enabled, container_filter, event_count,
	last_triggered_at, created_at, updated_at`

// scanRuntimeRuleRow scans a single pgx.Row into a models.RuntimeSecurityRule.
func scanRuntimeRuleRow(row pgx.Row) (*models.RuntimeSecurityRule, error) {
	var r models.RuntimeSecurityRule
	err := row.Scan(
		&r.ID, &r.Name, &r.Description, &r.Category, &r.RuleType, &r.Definition,
		&r.Severity, &r.Action, &r.IsEnabled, &r.ContainerFilter, &r.EventCount,
		&r.LastTriggeredAt, &r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// scanRuntimeRuleRows scans multiple pgx.Rows into a slice of models.RuntimeSecurityRule.
func scanRuntimeRuleRows(rows pgx.Rows) ([]*models.RuntimeSecurityRule, error) {
	var rules []*models.RuntimeSecurityRule
	for rows.Next() {
		var r models.RuntimeSecurityRule
		err := rows.Scan(
			&r.ID, &r.Name, &r.Description, &r.Category, &r.RuleType, &r.Definition,
			&r.Severity, &r.Action, &r.IsEnabled, &r.ContainerFilter, &r.EventCount,
			&r.LastTriggeredAt, &r.CreatedAt, &r.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		rules = append(rules, &r)
	}
	return rules, rows.Err()
}

// CreateRule inserts a new runtime security rule.
func (r *RuntimeSecurityRepository) CreateRule(ctx context.Context, rule *models.RuntimeSecurityRule) error {
	log := logger.FromContext(ctx)

	if rule.ID == uuid.Nil {
		rule.ID = uuid.New()
	}
	now := time.Now()
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = now
	}
	rule.UpdatedAt = now

	query := `
		INSERT INTO runtime_security_rules (
			id, name, description, category, rule_type, definition,
			severity, action, is_enabled, container_filter,
			event_count, last_triggered_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10,
			$11, $12, $13, $14
		)`

	_, err := r.db.Exec(ctx, query,
		rule.ID,
		rule.Name,
		rule.Description,
		rule.Category,
		rule.RuleType,
		rule.Definition,
		rule.Severity,
		rule.Action,
		rule.IsEnabled,
		rule.ContainerFilter,
		rule.EventCount,
		rule.LastTriggeredAt,
		rule.CreatedAt,
		rule.UpdatedAt,
	)

	if err != nil {
		if IsDuplicateKeyError(err) {
			return errors.AlreadyExists("runtime security rule")
		}
		log.Error("Failed to create runtime security rule",
			"rule_id", rule.ID,
			"name", rule.Name,
			"error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create runtime security rule")
	}

	log.Debug("Runtime security rule created", "rule_id", rule.ID, "name", rule.Name)
	return nil
}

// GetRule retrieves a runtime security rule by ID.
func (r *RuntimeSecurityRepository) GetRule(ctx context.Context, id uuid.UUID) (*models.RuntimeSecurityRule, error) {
	query := fmt.Sprintf(`SELECT %s FROM runtime_security_rules WHERE id = $1`, runtimeRuleColumns)

	rule, err := scanRuntimeRuleRow(r.db.QueryRow(ctx, query, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("runtime security rule")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get runtime security rule")
	}

	return rule, nil
}

// ListRules retrieves all runtime security rules ordered by severity and name.
func (r *RuntimeSecurityRepository) ListRules(ctx context.Context) ([]*models.RuntimeSecurityRule, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM runtime_security_rules
		ORDER BY
			CASE severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END,
			name ASC`, runtimeRuleColumns)

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list runtime security rules")
	}
	defer rows.Close()

	rules, err := scanRuntimeRuleRows(rows)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan runtime security rule rows")
	}

	return rules, nil
}

// UpdateRule updates an existing runtime security rule.
func (r *RuntimeSecurityRepository) UpdateRule(ctx context.Context, rule *models.RuntimeSecurityRule) error {
	log := logger.FromContext(ctx)

	rule.UpdatedAt = time.Now()

	result, err := r.db.Exec(ctx, `
		UPDATE runtime_security_rules
		SET name = $1, description = $2, category = $3, rule_type = $4,
			definition = $5, severity = $6, action = $7, is_enabled = $8,
			container_filter = $9, updated_at = $10
		WHERE id = $11`,
		rule.Name,
		rule.Description,
		rule.Category,
		rule.RuleType,
		rule.Definition,
		rule.Severity,
		rule.Action,
		rule.IsEnabled,
		rule.ContainerFilter,
		rule.UpdatedAt,
		rule.ID,
	)

	if err != nil {
		log.Error("Failed to update runtime security rule",
			"rule_id", rule.ID,
			"error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update runtime security rule")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("runtime security rule")
	}

	log.Debug("Runtime security rule updated", "rule_id", rule.ID, "name", rule.Name)
	return nil
}

// DeleteRule removes a runtime security rule by ID.
func (r *RuntimeSecurityRepository) DeleteRule(ctx context.Context, id uuid.UUID) error {
	log := logger.FromContext(ctx)

	result, err := r.db.Exec(ctx,
		`DELETE FROM runtime_security_rules WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete runtime security rule")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("runtime security rule")
	}

	log.Debug("Runtime security rule deleted", "rule_id", id)
	return nil
}

// ToggleRule enables or disables a runtime security rule.
func (r *RuntimeSecurityRepository) ToggleRule(ctx context.Context, id uuid.UUID, enabled bool) error {
	log := logger.FromContext(ctx)

	result, err := r.db.Exec(ctx, `
		UPDATE runtime_security_rules
		SET is_enabled = $1, updated_at = $2
		WHERE id = $3`,
		enabled, time.Now(), id)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to toggle runtime security rule")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("runtime security rule")
	}

	log.Debug("Runtime security rule toggled", "rule_id", id, "enabled", enabled)
	return nil
}

// IncrementRuleEventCount atomically increments the event count for a rule
// and updates its last_triggered_at timestamp.
func (r *RuntimeSecurityRepository) IncrementRuleEventCount(ctx context.Context, ruleID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE runtime_security_rules
		SET event_count = event_count + 1, last_triggered_at = $1, updated_at = $1
		WHERE id = $2`,
		time.Now(), ruleID)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to increment rule event count")
	}

	return nil
}

// ============================================================================
// Baseline operations
// ============================================================================

// CreateBaseline inserts a new runtime baseline record.
func (r *RuntimeSecurityRepository) CreateBaseline(ctx context.Context, baseline *models.RuntimeBaseline) error {
	log := logger.FromContext(ctx)

	if baseline.ID == uuid.Nil {
		baseline.ID = uuid.New()
	}
	now := time.Now()
	if baseline.CreatedAt.IsZero() {
		baseline.CreatedAt = now
	}
	baseline.UpdatedAt = now
	if baseline.LearningStartedAt.IsZero() {
		baseline.LearningStartedAt = now
	}

	query := `
		INSERT INTO runtime_baselines (
			id, container_id, container_name, image, baseline_type,
			baseline_data, sample_count, confidence, is_active,
			learning_started_at, learning_completed_at,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11,
			$12, $13
		)`

	_, err := r.db.Exec(ctx, query,
		baseline.ID,
		baseline.ContainerID,
		baseline.ContainerName,
		baseline.Image,
		baseline.BaselineType,
		baseline.BaselineData,
		baseline.SampleCount,
		baseline.Confidence,
		baseline.IsActive,
		baseline.LearningStartedAt,
		baseline.LearningCompletedAt,
		baseline.CreatedAt,
		baseline.UpdatedAt,
	)

	if err != nil {
		log.Error("Failed to create runtime baseline",
			"baseline_id", baseline.ID,
			"container_id", baseline.ContainerID,
			"error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create runtime baseline")
	}

	log.Debug("Runtime baseline created",
		"baseline_id", baseline.ID,
		"container_id", baseline.ContainerID,
		"baseline_type", baseline.BaselineType)

	return nil
}

// GetActiveBaseline retrieves the active baseline for a specific container
// and baseline type combination.
func (r *RuntimeSecurityRepository) GetActiveBaseline(ctx context.Context, containerID, baselineType string) (*models.RuntimeBaseline, error) {
	query := `
		SELECT id, container_id, container_name, image, baseline_type,
			baseline_data, sample_count, confidence, is_active,
			learning_started_at, learning_completed_at,
			created_at, updated_at
		FROM runtime_baselines
		WHERE container_id = $1 AND baseline_type = $2 AND is_active = true
		ORDER BY created_at DESC
		LIMIT 1`

	var b models.RuntimeBaseline
	err := r.db.QueryRow(ctx, query, containerID, baselineType).Scan(
		&b.ID, &b.ContainerID, &b.ContainerName, &b.Image, &b.BaselineType,
		&b.BaselineData, &b.SampleCount, &b.Confidence, &b.IsActive,
		&b.LearningStartedAt, &b.LearningCompletedAt,
		&b.CreatedAt, &b.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // No active baseline is not an error
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get active runtime baseline")
	}

	return &b, nil
}

// UpdateBaseline updates an existing runtime baseline record.
func (r *RuntimeSecurityRepository) UpdateBaseline(ctx context.Context, baseline *models.RuntimeBaseline) error {
	log := logger.FromContext(ctx)

	baseline.UpdatedAt = time.Now()

	result, err := r.db.Exec(ctx, `
		UPDATE runtime_baselines
		SET baseline_data = $1, sample_count = $2, confidence = $3,
			is_active = $4, learning_completed_at = $5, updated_at = $6
		WHERE id = $7`,
		baseline.BaselineData,
		baseline.SampleCount,
		baseline.Confidence,
		baseline.IsActive,
		baseline.LearningCompletedAt,
		baseline.UpdatedAt,
		baseline.ID,
	)

	if err != nil {
		log.Error("Failed to update runtime baseline",
			"baseline_id", baseline.ID,
			"error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update runtime baseline")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("runtime baseline")
	}

	log.Debug("Runtime baseline updated",
		"baseline_id", baseline.ID,
		"container_id", baseline.ContainerID,
		"sample_count", baseline.SampleCount,
		"confidence", baseline.Confidence)

	return nil
}
