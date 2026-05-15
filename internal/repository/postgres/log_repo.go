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

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ContainerLogCount holds a container name and its associated log count.
type ContainerLogCount struct {
	ContainerName string `json:"container_name"`
	Count         int64  `json:"count"`
}

// LogStats holds aggregated statistics about log entries.
type LogStats struct {
	TotalLogs      int64               `json:"total_logs"`
	SeverityCounts map[string]int64    `json:"severity_counts"`
	SourceCounts   map[string]int64    `json:"source_counts"`
	TopContainers  []ContainerLogCount `json:"top_containers"`
}

// LogRepository handles aggregated log database operations.
type LogRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewLogRepository creates a new LogRepository.
func NewLogRepository(db *DB, log *logger.Logger) *LogRepository {
	return &LogRepository{
		db:     db,
		logger: log.Named("log_repo"),
	}
}

// InsertLog inserts a single aggregated log entry.
func (r *LogRepository) InsertLog(ctx context.Context, log *models.AggregatedLog) error {
	query := `
		INSERT INTO aggregated_logs (
			host_id, container_id, container_name, source, stream,
			severity, message, fields, timestamp, ingested_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10
		) RETURNING id`

	var fieldsJSON []byte
	if log.Fields != nil {
		fieldsJSON = log.Fields
	}

	if log.IngestedAt.IsZero() {
		log.IngestedAt = time.Now().UTC()
	}

	err := r.db.QueryRow(ctx, query,
		log.HostID,
		log.ContainerID,
		log.ContainerName,
		log.Source,
		log.Stream,
		log.Severity,
		log.Message,
		fieldsJSON,
		log.Timestamp,
		log.IngestedAt,
	).Scan(&log.ID)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to insert aggregated log")
	}

	return nil
}

// InsertLogBatch inserts multiple aggregated log entries in a single transaction.
func (r *LogRepository) InsertLogBatch(ctx context.Context, logs []*models.AggregatedLog) error {
	if len(logs) == 0 {
		return nil
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to begin transaction for log batch insert")
	}
	defer tx.Rollback(ctx)

	query := `
		INSERT INTO aggregated_logs (
			host_id, container_id, container_name, source, stream,
			severity, message, fields, timestamp, ingested_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10
		)`

	now := time.Now().UTC()

	for _, log := range logs {
		var fieldsJSON []byte
		if log.Fields != nil {
			fieldsJSON = log.Fields
		}

		if log.IngestedAt.IsZero() {
			log.IngestedAt = now
		}

		_, err := tx.Exec(ctx, query,
			log.HostID,
			log.ContainerID,
			log.ContainerName,
			log.Source,
			log.Stream,
			log.Severity,
			log.Message,
			fieldsJSON,
			log.Timestamp,
			log.IngestedAt,
		)
		if err != nil {
			return errors.Wrap(err, errors.CodeDatabaseError, "failed to insert log in batch")
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to commit log batch insert")
	}

	return nil
}

// SearchLogs performs a full-text search on aggregated logs with optional filters.
// Returns matching logs, total count, and any error.
func (r *LogRepository) SearchLogs(ctx context.Context, opts models.AggregatedLogSearchOptions) ([]*models.AggregatedLog, int64, error) {
	var conditions []string
	var args []interface{}
	argNum := 1

	// Full-text search using PostgreSQL to_tsvector/plainto_tsquery
	if opts.Query != "" {
		conditions = append(conditions, fmt.Sprintf(
			"to_tsvector('english', message) @@ plainto_tsquery('english', $%d)", argNum,
		))
		args = append(args, opts.Query)
		argNum++
	}

	if opts.ContainerID != "" {
		conditions = append(conditions, fmt.Sprintf("container_id = $%d", argNum))
		args = append(args, opts.ContainerID)
		argNum++
	}

	if opts.ContainerName != "" {
		conditions = append(conditions, fmt.Sprintf("container_name ILIKE $%d", argNum))
		args = append(args, "%"+opts.ContainerName+"%")
		argNum++
	}

	if opts.HostID != nil {
		conditions = append(conditions, fmt.Sprintf("host_id = $%d", argNum))
		args = append(args, *opts.HostID)
		argNum++
	}

	if opts.Source != "" {
		conditions = append(conditions, fmt.Sprintf("source = $%d", argNum))
		args = append(args, opts.Source)
		argNum++
	}

	if opts.Severity != "" {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argNum))
		args = append(args, opts.Severity)
		argNum++
	}

	if opts.Since != nil {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argNum))
		args = append(args, *opts.Since)
		argNum++
	}

	if opts.Until != nil {
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argNum))
		args = append(args, *opts.Until)
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Set defaults for pagination
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}

	// Query with COUNT(*) OVER() for total count in a single pass
	query := fmt.Sprintf(`
		SELECT id, host_id, container_id, container_name, source, stream,
			severity, message, fields, timestamp, ingested_at,
			COUNT(*) OVER() AS total_count
		FROM aggregated_logs
		%s
		ORDER BY timestamp DESC
		LIMIT $%d OFFSET $%d`,
		whereClause, argNum, argNum+1)

	args = append(args, limit, offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to search aggregated logs")
	}
	defer rows.Close()

	var logs []*models.AggregatedLog
	var totalCount int64

	for rows.Next() {
		log := &models.AggregatedLog{}
		var fieldsJSON []byte

		err := rows.Scan(
			&log.ID,
			&log.HostID,
			&log.ContainerID,
			&log.ContainerName,
			&log.Source,
			&log.Stream,
			&log.Severity,
			&log.Message,
			&fieldsJSON,
			&log.Timestamp,
			&log.IngestedAt,
			&totalCount,
		)
		if err != nil {
			return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan aggregated log")
		}

		if len(fieldsJSON) > 0 {
			log.Fields = json.RawMessage(fieldsJSON)
		}

		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "error iterating aggregated logs")
	}

	return logs, totalCount, nil
}

// GetLogStats returns aggregated statistics about log entries since the given time.
func (r *LogRepository) GetLogStats(ctx context.Context, since time.Time) (*LogStats, error) {
	stats := &LogStats{
		SeverityCounts: make(map[string]int64),
		SourceCounts:   make(map[string]int64),
	}

	// Total count
	err := r.db.QueryRow(ctx,
		"SELECT COUNT(*) FROM aggregated_logs WHERE timestamp >= $1", since,
	).Scan(&stats.TotalLogs)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get total log count")
	}

	// Severity counts
	rows, err := r.db.Query(ctx, `
		SELECT severity, COUNT(*) AS count
		FROM aggregated_logs
		WHERE timestamp >= $1
		GROUP BY severity
		ORDER BY count DESC`, since)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get severity counts")
	}
	defer rows.Close()

	for rows.Next() {
		var severity string
		var count int64
		if err := rows.Scan(&severity, &count); err != nil {
			continue
		}
		stats.SeverityCounts[severity] = count
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "error iterating severity counts")
	}

	// Source counts
	rows, err = r.db.Query(ctx, `
		SELECT source, COUNT(*) AS count
		FROM aggregated_logs
		WHERE timestamp >= $1
		GROUP BY source
		ORDER BY count DESC`, since)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get source counts")
	}
	defer rows.Close()

	for rows.Next() {
		var source string
		var count int64
		if err := rows.Scan(&source, &count); err != nil {
			continue
		}
		stats.SourceCounts[source] = count
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "error iterating source counts")
	}

	// Top containers by log count
	rows, err = r.db.Query(ctx, `
		SELECT container_name, COUNT(*) AS count
		FROM aggregated_logs
		WHERE timestamp >= $1 AND container_name != ''
		GROUP BY container_name
		ORDER BY count DESC
		LIMIT 10`, since)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get top containers")
	}
	defer rows.Close()

	for rows.Next() {
		var entry ContainerLogCount
		if err := rows.Scan(&entry.ContainerName, &entry.Count); err != nil {
			continue
		}
		stats.TopContainers = append(stats.TopContainers, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "error iterating top containers")
	}

	return stats, nil
}

// DeleteOldLogs removes log entries older than the given retention duration.
// Returns the number of deleted rows.
func (r *LogRepository) DeleteOldLogs(ctx context.Context, retention time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-retention)

	result, err := r.db.Exec(ctx,
		"DELETE FROM aggregated_logs WHERE timestamp < $1", cutoff)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to delete old logs")
	}

	count := result.RowsAffected()
	if count > 0 {
		r.logger.Info("deleted old aggregated logs", "count", count, "cutoff", cutoff)
	}

	return count, nil
}

// SaveQuery saves a log search query for later reuse.
func (r *LogRepository) SaveQuery(ctx context.Context, q *models.LogSearchQuery) error {
	if q.ID == uuid.Nil {
		q.ID = uuid.New()
	}
	if q.CreatedAt.IsZero() {
		q.CreatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO log_search_queries (
			id, name, description, query, filters,
			user_id, is_shared, created_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8
		)`

	var filtersJSON []byte
	if q.Filters != nil {
		filtersJSON = q.Filters
	}

	_, err := r.db.Exec(ctx, query,
		q.ID,
		q.Name,
		q.Description,
		q.Query,
		filtersJSON,
		q.UserID,
		q.IsShared,
		q.CreatedAt,
	)
	if err != nil {
		if IsDuplicateKeyError(err) {
			return errors.New(errors.CodeConflict, "saved query with this name already exists")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to save log search query")
	}

	return nil
}

// ListSavedQueries retrieves saved log search queries.
// If userID is provided, returns queries owned by that user plus shared queries.
// If userID is nil, returns only shared queries.
func (r *LogRepository) ListSavedQueries(ctx context.Context, userID *uuid.UUID) ([]*models.LogSearchQuery, error) {
	var query string
	var args []interface{}

	if userID != nil {
		query = `
			SELECT id, name, description, query, filters,
				user_id, is_shared, created_at
			FROM log_search_queries
			WHERE user_id = $1 OR is_shared = true
			ORDER BY created_at DESC`
		args = append(args, *userID)
	} else {
		query = `
			SELECT id, name, description, query, filters,
				user_id, is_shared, created_at
			FROM log_search_queries
			WHERE is_shared = true
			ORDER BY created_at DESC`
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list saved log queries")
	}
	defer rows.Close()

	return r.scanLogSearchQueries(rows)
}

// DeleteSavedQuery deletes a saved log search query by ID.
func (r *LogRepository) DeleteSavedQuery(ctx context.Context, id uuid.UUID) error {
	result, err := r.db.Exec(ctx,
		"DELETE FROM log_search_queries WHERE id = $1", id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete saved log query")
	}

	if result.RowsAffected() == 0 {
		return errors.New(errors.CodeNotFound, "saved log query not found")
	}

	return nil
}

// scanLogSearchQueries scans multiple rows into LogSearchQuery slices.
func (r *LogRepository) scanLogSearchQueries(rows pgx.Rows) ([]*models.LogSearchQuery, error) {
	var queries []*models.LogSearchQuery

	for rows.Next() {
		q := &models.LogSearchQuery{}
		var filtersJSON []byte

		err := rows.Scan(
			&q.ID,
			&q.Name,
			&q.Description,
			&q.Query,
			&filtersJSON,
			&q.UserID,
			&q.IsShared,
			&q.CreatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan log search query")
		}

		if len(filtersJSON) > 0 {
			q.Filters = json.RawMessage(filtersJSON)
		}

		queries = append(queries, q)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "error iterating log search queries")
	}

	return queries, nil
}
