// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package postgres provides PostgreSQL repository implementations.
// Department L: Notifications - Log Repository
package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/services/notification"
	"github.com/fr4nsys/usulnet/internal/services/notification/channels"
)

// NotificationLogRepository handles notification log persistence.
type NotificationLogRepository struct {
	db *DB
}

// NewNotificationLogRepository creates a new notification log repository.
func NewNotificationLogRepository(db *DB) *NotificationLogRepository {
	return &NotificationLogRepository{db: db}
}

// LogNotification stores a notification record.
func (r *NotificationLogRepository) LogNotification(ctx context.Context, log *notification.NotificationLog) error {
	// Generate ID if not provided
	if log.ID == uuid.Nil {
		log.ID = uuid.New()
	}

	channelsJSON, err := json.Marshal(log.Channels)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to marshal channels")
	}

	resultsJSON, err := json.Marshal(log.Results)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to marshal results")
	}

	query := `
		INSERT INTO notification_logs (
			id, type, priority, title, body, channels, results,
			throttled, success_count, failed_count, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err = r.db.Pool().Exec(ctx, query,
		log.ID,
		string(log.Type),
		int(log.Priority),
		log.Title,
		log.Body,
		channelsJSON,
		resultsJSON,
		log.Throttled,
		log.SuccessCount,
		log.FailedCount,
		log.CreatedAt,
	)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to insert notification log")
	}

	return nil
}

// GetNotificationLogs retrieves notification history with filtering.
func (r *NotificationLogRepository) GetNotificationLogs(ctx context.Context, filter notification.LogFilter) ([]*notification.NotificationLog, error) {
	// Build dynamic query
	query := `
		SELECT id, type, priority, title, body, channels, results, throttled, success_count, failed_count, created_at
		FROM notification_logs
		WHERE 1=1
	`
	args := []interface{}{}
	argNum := 1

	// Apply filters
	if len(filter.Types) > 0 {
		types := make([]string, len(filter.Types))
		for i, t := range filter.Types {
			types[i] = string(t)
		}
		query += fmt.Sprintf(" AND type = ANY($%d)", argNum)
		args = append(args, types)
		argNum++
	}

	if len(filter.Priorities) > 0 {
		priorities := make([]int, len(filter.Priorities))
		for i, p := range filter.Priorities {
			priorities[i] = int(p)
		}
		query += fmt.Sprintf(" AND priority = ANY($%d)", argNum)
		args = append(args, priorities)
		argNum++
	}

	if filter.Since != nil {
		query += fmt.Sprintf(" AND created_at >= $%d", argNum)
		args = append(args, *filter.Since)
		argNum++
	}

	if filter.Until != nil {
		query += fmt.Sprintf(" AND created_at <= $%d", argNum)
		args = append(args, *filter.Until)
		argNum++
	}

	if filter.OnlyFailed {
		query += " AND failed_count > 0"
	}

	// Channel filter (uses JSONB containment)
	if len(filter.Channels) > 0 {
		for _, ch := range filter.Channels {
			query += fmt.Sprintf(" AND channels @> $%d::jsonb", argNum)
			args = append(args, fmt.Sprintf(`["%s"]`, ch))
			argNum++
		}
	}

	// Order and pagination
	query += " ORDER BY created_at DESC"

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argNum)
		args = append(args, filter.Limit)
		argNum++
	} else {
		// Default limit
		query += fmt.Sprintf(" LIMIT $%d", argNum)
		args = append(args, 100)
		argNum++
	}

	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argNum)
		args = append(args, filter.Offset)
	}

	rows, err := r.db.Pool().Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query notification logs")
	}
	defer rows.Close()

	var logs []*notification.NotificationLog
	for rows.Next() {
		var (
			log          notification.NotificationLog
			typeStr      string
			priorityInt  int
			channelsJSON []byte
			resultsJSON  []byte
		)

		if err := rows.Scan(
			&log.ID,
			&typeStr,
			&priorityInt,
			&log.Title,
			&log.Body,
			&channelsJSON,
			&resultsJSON,
			&log.Throttled,
			&log.SuccessCount,
			&log.FailedCount,
			&log.CreatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan notification log")
		}

		log.Type = channels.NotificationType(typeStr)
		log.Priority = channels.Priority(priorityInt)

		if len(channelsJSON) > 0 {
			if err := json.Unmarshal(channelsJSON, &log.Channels); err != nil {
				return nil, errors.Wrap(err, errors.CodeInternal, "failed to unmarshal channels")
			}
		}

		if len(resultsJSON) > 0 {
			if err := json.Unmarshal(resultsJSON, &log.Results); err != nil {
				return nil, errors.Wrap(err, errors.CodeInternal, "failed to unmarshal results")
			}
		}

		logs = append(logs, &log)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "row iteration error")
	}

	return logs, nil
}

// GetNotificationStats returns aggregated statistics.
func (r *NotificationLogRepository) GetNotificationStats(ctx context.Context, since time.Time) (*notification.NotificationStats, error) {
	stats := &notification.NotificationStats{
		ByType:    make(map[string]int64),
		ByChannel: make(map[string]int64),
	}

	// Total counts
	countQuery := `
		SELECT 
			COUNT(*) as total,
			COALESCE(SUM(success_count), 0) as sent,
			COALESCE(SUM(failed_count), 0) as failed,
			COALESCE(SUM(CASE WHEN throttled THEN 1 ELSE 0 END), 0) as throttled
		FROM notification_logs
		WHERE created_at >= $1
	`

	err := r.db.Pool().QueryRow(ctx, countQuery, since).Scan(
		&stats.Total,
		&stats.Sent,
		&stats.Failed,
		&stats.Throttled,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query total stats")
	}

	// By type
	typeQuery := `
		SELECT type, COUNT(*) as count
		FROM notification_logs
		WHERE created_at >= $1
		GROUP BY type
	`

	rows, err := r.db.Pool().Query(ctx, typeQuery, since)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query type stats")
	}

	for rows.Next() {
		var typeStr string
		var count int64
		if err := rows.Scan(&typeStr, &count); err != nil {
			rows.Close()
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan type stat")
		}
		stats.ByType[typeStr] = count
	}
	rows.Close()

	// By channel (requires JSONB array expansion)
	channelQuery := `
		SELECT channel, COUNT(*) as count
		FROM notification_logs, jsonb_array_elements_text(channels) as channel
		WHERE created_at >= $1
		GROUP BY channel
	`

	rows, err = r.db.Pool().Query(ctx, channelQuery, since)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query channel stats")
	}

	for rows.Next() {
		var channel string
		var count int64
		if err := rows.Scan(&channel, &count); err != nil {
			rows.Close()
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan channel stat")
		}
		stats.ByChannel[channel] = count
	}
	rows.Close()

	// Calculate success rate
	if stats.Sent+stats.Failed > 0 {
		stats.SuccessRate = float64(stats.Sent) / float64(stats.Sent+stats.Failed)
	}

	return stats, nil
}

// GetRecentFailures retrieves recent failed notifications.
func (r *NotificationLogRepository) GetRecentFailures(ctx context.Context, limit int) ([]*notification.NotificationLog, error) {
	return r.GetNotificationLogs(ctx, notification.LogFilter{
		OnlyFailed: true,
		Limit:      limit,
	})
}

// DeleteOldLogs removes logs older than the specified duration.
func (r *NotificationLogRepository) DeleteOldLogs(ctx context.Context, olderThan time.Time) (int64, error) {
	query := `DELETE FROM notification_logs WHERE created_at < $1`

	result, err := r.db.Pool().Exec(ctx, query, olderThan)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to delete old logs")
	}

	return result.RowsAffected(), nil
}

// GetNotificationByID retrieves a single notification log by ID.
func (r *NotificationLogRepository) GetNotificationByID(ctx context.Context, id uuid.UUID) (*notification.NotificationLog, error) {
	query := `
		SELECT id, type, priority, title, body, channels, results, throttled, success_count, failed_count, created_at
		FROM notification_logs
		WHERE id = $1
	`

	var (
		log          notification.NotificationLog
		typeStr      string
		priorityInt  int
		channelsJSON []byte
		resultsJSON  []byte
	)

	err := r.db.Pool().QueryRow(ctx, query, id).Scan(
		&log.ID,
		&typeStr,
		&priorityInt,
		&log.Title,
		&log.Body,
		&channelsJSON,
		&resultsJSON,
		&log.Throttled,
		&log.SuccessCount,
		&log.FailedCount,
		&log.CreatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, errors.NotFound("notification log")
	}
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query notification log")
	}

	log.Type = channels.NotificationType(typeStr)
	log.Priority = channels.Priority(priorityInt)

	if len(channelsJSON) > 0 {
		json.Unmarshal(channelsJSON, &log.Channels)
	}

	if len(resultsJSON) > 0 {
		json.Unmarshal(resultsJSON, &log.Results)
	}

	return &log, nil
}

// NotificationRepository combines config and log repositories.
// Implements notification.Repository interface.
type NotificationRepository struct {
	*NotificationConfigRepository
	*NotificationLogRepository
}

// NewNotificationRepository creates a combined notification repository.
func NewNotificationRepository(db *DB) *NotificationRepository {
	return &NotificationRepository{
		NotificationConfigRepository: NewNotificationConfigRepository(db),
		NotificationLogRepository:    NewNotificationLogRepository(db),
	}
}
