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
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ResourceOptRepository handles resource optimization database operations.
type ResourceOptRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewResourceOptRepository creates a new ResourceOptRepository.
func NewResourceOptRepository(db *DB, log *logger.Logger) *ResourceOptRepository {
	return &ResourceOptRepository{
		db:     db,
		logger: log.Named("resource_opt_repo"),
	}
}

// recommendationCols is the shared column list for SELECT queries on resource_recommendations.
const recommendationCols = `id, container_id, container_name, type, severity, status,
	current_value, recommended_value, estimated_savings, reason,
	created_at, resolved_at, resolved_by`

// scanRecommendation scans a row into a ResourceRecommendation.
func scanRecommendation(row pgx.Row) (*models.ResourceRecommendation, error) {
	var r models.ResourceRecommendation
	err := row.Scan(
		&r.ID, &r.ContainerID, &r.ContainerName, &r.Type, &r.Severity, &r.Status,
		&r.CurrentValue, &r.RecommendedValue, &r.EstimatedSavings, &r.Reason,
		&r.CreatedAt, &r.ResolvedAt, &r.ResolvedBy,
	)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// scanRecommendations scans multiple rows into a slice of ResourceRecommendation.
func scanRecommendations(rows pgx.Rows) ([]*models.ResourceRecommendation, error) {
	var recs []*models.ResourceRecommendation
	for rows.Next() {
		var r models.ResourceRecommendation
		err := rows.Scan(
			&r.ID, &r.ContainerID, &r.ContainerName, &r.Type, &r.Severity, &r.Status,
			&r.CurrentValue, &r.RecommendedValue, &r.EstimatedSavings, &r.Reason,
			&r.CreatedAt, &r.ResolvedAt, &r.ResolvedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning recommendation row: %w", err)
		}
		recs = append(recs, &r)
	}
	return recs, rows.Err()
}

// CreateSample inserts a single resource usage sample.
func (r *ResourceOptRepository) CreateSample(ctx context.Context, s *models.ResourceUsageSample) error {
	query := `
		INSERT INTO resource_usage_samples (
			container_id, container_name, host_id, sampled_at,
			cpu_usage_percent, cpu_peak_percent,
			memory_usage_bytes, memory_limit_bytes, memory_peak_bytes,
			network_rx_bytes, network_tx_bytes,
			disk_read_bytes, disk_write_bytes, pids_current
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
		) RETURNING id`

	err := r.db.QueryRow(ctx, query,
		s.ContainerID, s.ContainerName, s.HostID, s.SampledAt,
		s.CPUUsagePercent, s.CPUPeakPercent,
		s.MemoryUsageBytes, s.MemoryLimitBytes, s.MemoryPeakBytes,
		s.NetworkRxBytes, s.NetworkTxBytes,
		s.DiskReadBytes, s.DiskWriteBytes, s.PidsCurrent,
	).Scan(&s.ID)
	if err != nil {
		return fmt.Errorf("creating resource usage sample: %w", err)
	}
	return nil
}

// CreateSamples inserts multiple resource usage samples in a loop.
func (r *ResourceOptRepository) CreateSamples(ctx context.Context, samples []*models.ResourceUsageSample) error {
	for i, s := range samples {
		if err := r.CreateSample(ctx, s); err != nil {
			return fmt.Errorf("creating sample %d: %w", i, err)
		}
	}
	return nil
}

// GetContainerUsageSummary returns aggregated usage for a single container since the given time.
func (r *ResourceOptRepository) GetContainerUsageSummary(ctx context.Context, containerID string, since time.Time) (*models.ContainerUsageSummary, error) {
	query := `
		SELECT
			container_id,
			COALESCE(MAX(container_name), '') AS container_name,
			COALESCE(AVG(cpu_usage_percent), 0) AS cpu_avg,
			COALESCE(MAX(cpu_peak_percent), 0) AS cpu_peak,
			COALESCE(AVG(memory_usage_bytes), 0) AS memory_avg,
			COALESCE(MAX(memory_peak_bytes), 0) AS memory_peak,
			COALESCE(MAX(memory_limit_bytes), 0) AS memory_limit,
			COALESCE(MAX(sampled_at), $2) AS last_seen
		FROM resource_usage_samples
		WHERE container_id = $1 AND sampled_at >= $2
		GROUP BY container_id`

	var s models.ContainerUsageSummary
	err := r.db.QueryRow(ctx, query, containerID, since).Scan(
		&s.ContainerID, &s.ContainerName,
		&s.CPUAvg, &s.CPUPeak,
		&s.MemoryAvg, &s.MemoryPeak, &s.MemoryLimit,
		&s.LastSeen,
	)
	if err != nil {
		return nil, fmt.Errorf("getting container usage summary for %s: %w", containerID, err)
	}
	return &s, nil
}

// ListContainerSummaries returns aggregated usage summaries for all containers since the given time.
func (r *ResourceOptRepository) ListContainerSummaries(ctx context.Context, since time.Time, limit int) ([]*models.ContainerUsageSummary, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT
			container_id,
			COALESCE(MAX(container_name), '') AS container_name,
			COALESCE(AVG(cpu_usage_percent), 0) AS cpu_avg,
			COALESCE(MAX(cpu_peak_percent), 0) AS cpu_peak,
			COALESCE(AVG(memory_usage_bytes), 0) AS memory_avg,
			COALESCE(MAX(memory_peak_bytes), 0) AS memory_peak,
			COALESCE(MAX(memory_limit_bytes), 0) AS memory_limit,
			COALESCE(MAX(sampled_at), $1) AS last_seen
		FROM resource_usage_samples
		WHERE sampled_at >= $1
		GROUP BY container_id, container_name
		ORDER BY cpu_avg DESC
		LIMIT $2`

	rows, err := r.db.Query(ctx, query, since, limit)
	if err != nil {
		return nil, fmt.Errorf("listing container usage summaries: %w", err)
	}
	defer rows.Close()

	var summaries []*models.ContainerUsageSummary
	for rows.Next() {
		var s models.ContainerUsageSummary
		if err := rows.Scan(
			&s.ContainerID, &s.ContainerName,
			&s.CPUAvg, &s.CPUPeak,
			&s.MemoryAvg, &s.MemoryPeak, &s.MemoryLimit,
			&s.LastSeen,
		); err != nil {
			return nil, fmt.Errorf("scanning container usage summary row: %w", err)
		}
		summaries = append(summaries, &s)
	}
	return summaries, rows.Err()
}

// UpsertHourly inserts or updates an hourly aggregation record.
func (r *ResourceOptRepository) UpsertHourly(ctx context.Context, h *models.ResourceUsageHourly) error {
	query := `
		INSERT INTO resource_usage_hourly (
			container_id, container_name, hour,
			cpu_avg, cpu_peak, memory_avg_bytes, memory_peak_bytes, memory_limit_bytes,
			network_rx_total, network_tx_total, sample_count
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		) ON CONFLICT (container_id, hour) DO UPDATE SET
			container_name    = EXCLUDED.container_name,
			cpu_avg           = EXCLUDED.cpu_avg,
			cpu_peak          = EXCLUDED.cpu_peak,
			memory_avg_bytes  = EXCLUDED.memory_avg_bytes,
			memory_peak_bytes = EXCLUDED.memory_peak_bytes,
			memory_limit_bytes = EXCLUDED.memory_limit_bytes,
			network_rx_total  = EXCLUDED.network_rx_total,
			network_tx_total  = EXCLUDED.network_tx_total,
			sample_count      = EXCLUDED.sample_count`

	_, err := r.db.Exec(ctx, query,
		h.ContainerID, h.ContainerName, h.Hour,
		h.CPUAvg, h.CPUPeak, h.MemoryAvgBytes, h.MemoryPeakBytes, h.MemoryLimitBytes,
		h.NetworkRxTotal, h.NetworkTxTotal, h.SampleCount,
	)
	if err != nil {
		return fmt.Errorf("upserting hourly usage for %s: %w", h.ContainerID, err)
	}
	return nil
}

// UpsertDaily inserts or updates a daily aggregation record.
func (r *ResourceOptRepository) UpsertDaily(ctx context.Context, d *models.ResourceUsageDaily) error {
	query := `
		INSERT INTO resource_usage_daily (
			container_id, container_name, day,
			cpu_avg, cpu_peak, memory_avg_bytes, memory_peak_bytes, memory_limit_bytes,
			network_rx_total, network_tx_total, sample_count
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		) ON CONFLICT (container_id, day) DO UPDATE SET
			container_name    = EXCLUDED.container_name,
			cpu_avg           = EXCLUDED.cpu_avg,
			cpu_peak          = EXCLUDED.cpu_peak,
			memory_avg_bytes  = EXCLUDED.memory_avg_bytes,
			memory_peak_bytes = EXCLUDED.memory_peak_bytes,
			memory_limit_bytes = EXCLUDED.memory_limit_bytes,
			network_rx_total  = EXCLUDED.network_rx_total,
			network_tx_total  = EXCLUDED.network_tx_total,
			sample_count      = EXCLUDED.sample_count`

	_, err := r.db.Exec(ctx, query,
		d.ContainerID, d.ContainerName, d.Day,
		d.CPUAvg, d.CPUPeak, d.MemoryAvgBytes, d.MemoryPeakBytes, d.MemoryLimitBytes,
		d.NetworkRxTotal, d.NetworkTxTotal, d.SampleCount,
	)
	if err != nil {
		return fmt.Errorf("upserting daily usage for %s: %w", d.ContainerID, err)
	}
	return nil
}

// GetHourlyUsage retrieves hourly aggregated usage for a container since the given time.
func (r *ResourceOptRepository) GetHourlyUsage(ctx context.Context, containerID string, since time.Time) ([]*models.ResourceUsageHourly, error) {
	query := `
		SELECT id, container_id, container_name, hour,
			cpu_avg, cpu_peak, memory_avg_bytes, memory_peak_bytes, memory_limit_bytes,
			network_rx_total, network_tx_total, sample_count
		FROM resource_usage_hourly
		WHERE container_id = $1 AND hour >= $2
		ORDER BY hour DESC`

	rows, err := r.db.Query(ctx, query, containerID, since)
	if err != nil {
		return nil, fmt.Errorf("getting hourly usage for %s: %w", containerID, err)
	}
	defer rows.Close()

	var results []*models.ResourceUsageHourly
	for rows.Next() {
		var h models.ResourceUsageHourly
		if err := rows.Scan(
			&h.ID, &h.ContainerID, &h.ContainerName, &h.Hour,
			&h.CPUAvg, &h.CPUPeak, &h.MemoryAvgBytes, &h.MemoryPeakBytes, &h.MemoryLimitBytes,
			&h.NetworkRxTotal, &h.NetworkTxTotal, &h.SampleCount,
		); err != nil {
			return nil, fmt.Errorf("scanning hourly usage row: %w", err)
		}
		results = append(results, &h)
	}
	return results, rows.Err()
}

// GetDailyUsage retrieves daily aggregated usage for a container since the given time.
func (r *ResourceOptRepository) GetDailyUsage(ctx context.Context, containerID string, since time.Time) ([]*models.ResourceUsageDaily, error) {
	query := `
		SELECT id, container_id, container_name, day,
			cpu_avg, cpu_peak, memory_avg_bytes, memory_peak_bytes, memory_limit_bytes,
			network_rx_total, network_tx_total, sample_count
		FROM resource_usage_daily
		WHERE container_id = $1 AND day >= $2
		ORDER BY day DESC`

	rows, err := r.db.Query(ctx, query, containerID, since)
	if err != nil {
		return nil, fmt.Errorf("getting daily usage for %s: %w", containerID, err)
	}
	defer rows.Close()

	var results []*models.ResourceUsageDaily
	for rows.Next() {
		var d models.ResourceUsageDaily
		if err := rows.Scan(
			&d.ID, &d.ContainerID, &d.ContainerName, &d.Day,
			&d.CPUAvg, &d.CPUPeak, &d.MemoryAvgBytes, &d.MemoryPeakBytes, &d.MemoryLimitBytes,
			&d.NetworkRxTotal, &d.NetworkTxTotal, &d.SampleCount,
		); err != nil {
			return nil, fmt.Errorf("scanning daily usage row: %w", err)
		}
		results = append(results, &d)
	}
	return results, rows.Err()
}

// CreateRecommendation inserts a new optimization recommendation.
func (r *ResourceOptRepository) CreateRecommendation(ctx context.Context, rec *models.ResourceRecommendation) error {
	query := `
		INSERT INTO resource_recommendations (
			container_id, container_name, type, severity, status,
			current_value, recommended_value, estimated_savings, reason
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		) RETURNING id, created_at`

	err := r.db.QueryRow(ctx, query,
		rec.ContainerID, rec.ContainerName, rec.Type, rec.Severity, rec.Status,
		rec.CurrentValue, rec.RecommendedValue, rec.EstimatedSavings, rec.Reason,
	).Scan(&rec.ID, &rec.CreatedAt)
	if err != nil {
		return fmt.Errorf("creating recommendation: %w", err)
	}
	return nil
}

// ListRecommendations retrieves recommendations with dynamic filtering and pagination.
func (r *ResourceOptRepository) ListRecommendations(ctx context.Context, opts models.RecommendationListOptions) ([]*models.ResourceRecommendation, int, error) {
	var conditions []string
	var args []any
	argIdx := 1

	if opts.Type != "" {
		conditions = append(conditions, fmt.Sprintf("type = $%d", argIdx))
		args = append(args, opts.Type)
		argIdx++
	}
	if opts.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, opts.Status)
		argIdx++
	}
	if opts.Severity != "" {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argIdx))
		args = append(args, opts.Severity)
		argIdx++
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total matching
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM resource_recommendations %s", where)
	var total int
	if err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting recommendations: %w", err)
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
		"SELECT %s FROM resource_recommendations %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d",
		recommendationCols, where, argIdx, argIdx+1,
	)
	args = append(args, limit, offset)

	rows, err := r.db.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing recommendations: %w", err)
	}
	defer rows.Close()

	recs, err := scanRecommendations(rows)
	if err != nil {
		return nil, 0, err
	}
	return recs, total, nil
}

// ResolveRecommendation updates the status, resolved_at, and resolved_by of a recommendation.
func (r *ResourceOptRepository) ResolveRecommendation(ctx context.Context, id uuid.UUID, status string, resolvedBy *uuid.UUID) error {
	query := `
		UPDATE resource_recommendations
		SET status = $1, resolved_at = NOW(), resolved_by = $2
		WHERE id = $3`

	tag, err := r.db.Exec(ctx, query, status, resolvedBy, id)
	if err != nil {
		return fmt.Errorf("resolving recommendation %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("recommendation %s not found", id)
	}
	return nil
}

// GetOptStats returns aggregate statistics about resource optimization recommendations.
func (r *ResourceOptRepository) GetOptStats(ctx context.Context) (*models.ResourceOptStats, error) {
	stats := &models.ResourceOptStats{
		ByType:   make(map[string]int),
		ByStatus: make(map[string]int),
	}

	// Total recommendations
	err := r.db.QueryRow(ctx,
		"SELECT COUNT(*) FROM resource_recommendations",
	).Scan(&stats.TotalRecommendations)
	if err != nil {
		return nil, fmt.Errorf("counting total recommendations: %w", err)
	}

	// Open recommendations
	err = r.db.QueryRow(ctx,
		"SELECT COUNT(*) FROM resource_recommendations WHERE status = 'open'",
	).Scan(&stats.OpenRecommendations)
	if err != nil {
		return nil, fmt.Errorf("counting open recommendations: %w", err)
	}

	// By type
	rows, err := r.db.Query(ctx,
		"SELECT type, COUNT(*) FROM resource_recommendations GROUP BY type ORDER BY COUNT(*) DESC",
	)
	if err != nil {
		return nil, fmt.Errorf("getting type stats: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var t string
		var count int
		if err := rows.Scan(&t, &count); err != nil {
			return nil, err
		}
		stats.ByType[t] = count
	}

	// By status
	rows2, err := r.db.Query(ctx,
		"SELECT status, COUNT(*) FROM resource_recommendations GROUP BY status ORDER BY COUNT(*) DESC",
	)
	if err != nil {
		return nil, fmt.Errorf("getting status stats: %w", err)
	}
	defer rows2.Close()
	for rows2.Next() {
		var s string
		var count int
		if err := rows2.Scan(&s, &count); err != nil {
			return nil, err
		}
		stats.ByStatus[s] = count
	}

	// Top 5 containers by recommendation count
	rows3, err := r.db.Query(ctx,
		"SELECT container_name, COUNT(*) AS cnt FROM resource_recommendations GROUP BY container_name ORDER BY cnt DESC LIMIT 5",
	)
	if err != nil {
		return nil, fmt.Errorf("getting top container stats: %w", err)
	}
	defer rows3.Close()
	for rows3.Next() {
		var c models.ContainerRecommendCount
		if err := rows3.Scan(&c.ContainerName, &c.Count); err != nil {
			return nil, err
		}
		stats.TopContainers = append(stats.TopContainers, c)
	}

	return stats, nil
}

// DeleteOldSamples removes resource usage samples older than the given time.
func (r *ResourceOptRepository) DeleteOldSamples(ctx context.Context, before time.Time) (int64, error) {
	tag, err := r.db.Exec(ctx,
		"DELETE FROM resource_usage_samples WHERE sampled_at < $1", before,
	)
	if err != nil {
		return 0, fmt.Errorf("deleting old usage samples: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ClearOpenRecommendations deletes all recommendations with status 'open'.
// This is used before regenerating recommendations.
func (r *ResourceOptRepository) ClearOpenRecommendations(ctx context.Context) error {
	_, err := r.db.Exec(ctx,
		"DELETE FROM resource_recommendations WHERE status = 'open'",
	)
	if err != nil {
		return fmt.Errorf("clearing open recommendations: %w", err)
	}
	return nil
}
