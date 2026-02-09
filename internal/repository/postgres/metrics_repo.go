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

// MetricsRepository handles metrics_snapshots persistence.
type MetricsRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewMetricsRepository creates a new MetricsRepository.
func NewMetricsRepository(db *DB, log *logger.Logger) *MetricsRepository {
	return &MetricsRepository{
		db:     db,
		logger: log.Named("metrics_repo"),
	}
}

// snapshotColumns is the standard column list for metrics_snapshots.
const snapshotColumns = `id, host_id, metric_type, container_id, container_name,
	cpu_percent, memory_used, memory_total, memory_percent,
	network_rx_bytes, network_tx_bytes,
	disk_used, disk_total, disk_percent, block_read, block_write,
	pids, state, health, uptime_seconds,
	containers_total, containers_running, containers_stopped,
	images_total, volumes_total,
	labels, collected_at`

// scanSnapshotRow scans a single row into a MetricsSnapshot.
func scanSnapshotRow(row pgx.Row) (*models.MetricsSnapshot, error) {
	var s models.MetricsSnapshot
	var metricType string
	err := row.Scan(
		&s.ID, &s.HostID, &metricType, &s.ContainerID, &s.ContainerName,
		&s.CPUPercent, &s.MemoryUsed, &s.MemoryTotal, &s.MemoryPercent,
		&s.NetworkRxBytes, &s.NetworkTxBytes,
		&s.DiskUsed, &s.DiskTotal, &s.DiskPercent, &s.BlockRead, &s.BlockWrite,
		&s.PIDs, &s.State, &s.Health, &s.UptimeSeconds,
		&s.ContainersTotal, &s.ContainersRunning, &s.ContainersStopped,
		&s.ImagesTotal, &s.VolumesTotal,
		&s.Labels, &s.CollectedAt,
	)
	if err != nil {
		return nil, err
	}
	s.MetricType = models.MetricType(metricType)
	return &s, nil
}

// scanSnapshotRows scans multiple rows.
func scanSnapshotRows(rows pgx.Rows) ([]*models.MetricsSnapshot, error) {
	var result []*models.MetricsSnapshot
	for rows.Next() {
		s, err := scanSnapshotRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

// Insert stores a single metrics snapshot.
func (r *MetricsRepository) Insert(ctx context.Context, s *models.MetricsSnapshot) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	if s.CollectedAt.IsZero() {
		s.CollectedAt = time.Now()
	}

	query := `INSERT INTO metrics_snapshots (
		id, host_id, metric_type, container_id, container_name,
		cpu_percent, memory_used, memory_total, memory_percent,
		network_rx_bytes, network_tx_bytes,
		disk_used, disk_total, disk_percent, block_read, block_write,
		pids, state, health, uptime_seconds,
		containers_total, containers_running, containers_stopped,
		images_total, volumes_total,
		labels, collected_at
	) VALUES (
		$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27
	)`

	_, err := r.db.Exec(ctx, query,
		s.ID, s.HostID, string(s.MetricType), s.ContainerID, s.ContainerName,
		s.CPUPercent, s.MemoryUsed, s.MemoryTotal, s.MemoryPercent,
		s.NetworkRxBytes, s.NetworkTxBytes,
		s.DiskUsed, s.DiskTotal, s.DiskPercent, s.BlockRead, s.BlockWrite,
		s.PIDs, s.State, s.Health, s.UptimeSeconds,
		s.ContainersTotal, s.ContainersRunning, s.ContainersStopped,
		s.ImagesTotal, s.VolumesTotal,
		s.Labels, s.CollectedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to insert metrics snapshot")
	}
	return nil
}

// InsertBatch stores multiple snapshots efficiently via COPY protocol.
func (r *MetricsRepository) InsertBatch(ctx context.Context, snapshots []*models.MetricsSnapshot) error {
	if len(snapshots) == 0 {
		return nil
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to begin batch tx")
	}
	defer tx.Rollback(ctx)

	for _, s := range snapshots {
		if s.ID == uuid.Nil {
			s.ID = uuid.New()
		}
		if s.CollectedAt.IsZero() {
			s.CollectedAt = time.Now()
		}

		_, err := tx.Exec(ctx,
			`INSERT INTO metrics_snapshots (
				id, host_id, metric_type, container_id, container_name,
				cpu_percent, memory_used, memory_total, memory_percent,
				network_rx_bytes, network_tx_bytes,
				disk_used, disk_total, disk_percent, block_read, block_write,
				pids, state, health, uptime_seconds,
				containers_total, containers_running, containers_stopped,
				images_total, volumes_total,
				labels, collected_at
			) VALUES (
				$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27
			)`,
			s.ID, s.HostID, string(s.MetricType), s.ContainerID, s.ContainerName,
			s.CPUPercent, s.MemoryUsed, s.MemoryTotal, s.MemoryPercent,
			s.NetworkRxBytes, s.NetworkTxBytes,
			s.DiskUsed, s.DiskTotal, s.DiskPercent, s.BlockRead, s.BlockWrite,
			s.PIDs, s.State, s.Health, s.UptimeSeconds,
			s.ContainersTotal, s.ContainersRunning, s.ContainersStopped,
			s.ImagesTotal, s.VolumesTotal,
			s.Labels, s.CollectedAt,
		)
		if err != nil {
			return errors.Wrap(err, errors.CodeInternal, "failed to insert metrics snapshot in batch")
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to commit batch")
	}
	return nil
}

// GetHostHistory returns aggregated host metrics for a time range.
// interval: "1m", "5m", "15m", "1h", "1d"
func (r *MetricsRepository) GetHostHistory(ctx context.Context, hostID uuid.UUID, from, to time.Time, interval string) ([]*models.MetricsSnapshot, error) {
	bucket := intervalToPostgres(interval)

	query := fmt.Sprintf(`
		SELECT
			gen_random_uuid() AS id,
			host_id,
			'host' AS metric_type,
			NULL AS container_id,
			NULL AS container_name,
			AVG(cpu_percent) AS cpu_percent,
			AVG(memory_used) AS memory_used,
			MAX(memory_total) AS memory_total,
			AVG(memory_percent) AS memory_percent,
			MAX(network_rx_bytes) AS network_rx_bytes,
			MAX(network_tx_bytes) AS network_tx_bytes,
			AVG(disk_used) AS disk_used,
			MAX(disk_total) AS disk_total,
			AVG(disk_percent) AS disk_percent,
			NULL::bigint AS block_read,
			NULL::bigint AS block_write,
			NULL::int AS pids,
			NULL AS state,
			NULL AS health,
			NULL::bigint AS uptime_seconds,
			AVG(containers_total)::int AS containers_total,
			AVG(containers_running)::int AS containers_running,
			AVG(containers_stopped)::int AS containers_stopped,
			AVG(images_total)::int AS images_total,
			AVG(volumes_total)::int AS volumes_total,
			'{}'::jsonb AS labels,
			date_trunc('%s', collected_at) AS collected_at
		FROM metrics_snapshots
		WHERE host_id = $1
			AND metric_type = 'host'
			AND collected_at >= $2
			AND collected_at <= $3
		GROUP BY host_id, date_trunc('%s', collected_at)
		ORDER BY collected_at ASC
	`, bucket, bucket)

	rows, err := r.db.Query(ctx, query, hostID, from, to)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to query host history")
	}
	defer rows.Close()

	return scanSnapshotRows(rows)
}

// GetContainerHistory returns aggregated container metrics for a time range.
func (r *MetricsRepository) GetContainerHistory(ctx context.Context, containerID string, from, to time.Time, interval string) ([]*models.MetricsSnapshot, error) {
	bucket := intervalToPostgres(interval)

	query := fmt.Sprintf(`
		SELECT
			gen_random_uuid() AS id,
			host_id,
			'container' AS metric_type,
			container_id,
			container_name,
			AVG(cpu_percent) AS cpu_percent,
			AVG(memory_used) AS memory_used,
			MAX(memory_total) AS memory_total,
			AVG(memory_percent) AS memory_percent,
			MAX(network_rx_bytes) AS network_rx_bytes,
			MAX(network_tx_bytes) AS network_tx_bytes,
			NULL::bigint AS disk_used,
			NULL::bigint AS disk_total,
			NULL::float8 AS disk_percent,
			MAX(block_read) AS block_read,
			MAX(block_write) AS block_write,
			AVG(pids)::int AS pids,
			NULL AS state,
			NULL AS health,
			MAX(uptime_seconds) AS uptime_seconds,
			NULL::int AS containers_total,
			NULL::int AS containers_running,
			NULL::int AS containers_stopped,
			NULL::int AS images_total,
			NULL::int AS volumes_total,
			'{}'::jsonb AS labels,
			date_trunc('%s', collected_at) AS collected_at
		FROM metrics_snapshots
		WHERE container_id = $1
			AND metric_type = 'container'
			AND collected_at >= $2
			AND collected_at <= $3
		GROUP BY host_id, container_id, container_name, date_trunc('%s', collected_at)
		ORDER BY collected_at ASC
	`, bucket, bucket)

	rows, err := r.db.Query(ctx, query, containerID, from, to)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to query container history")
	}
	defer rows.Close()

	return scanSnapshotRows(rows)
}

// GetLatestHost returns the most recent host snapshot.
func (r *MetricsRepository) GetLatestHost(ctx context.Context, hostID uuid.UUID) (*models.MetricsSnapshot, error) {
	query := `SELECT ` + snapshotColumns + `
		FROM metrics_snapshots
		WHERE host_id = $1 AND metric_type = 'host'
		ORDER BY collected_at DESC
		LIMIT 1`

	row := r.db.QueryRow(ctx, query, hostID)
	s, err := scanSnapshotRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get latest host metrics")
	}
	return s, nil
}

// GetLatestContainers returns the most recent snapshot for each container on a host.
func (r *MetricsRepository) GetLatestContainers(ctx context.Context, hostID uuid.UUID) ([]*models.MetricsSnapshot, error) {
	query := `SELECT DISTINCT ON (container_id) ` + snapshotColumns + `
		FROM metrics_snapshots
		WHERE host_id = $1 AND metric_type = 'container'
		ORDER BY container_id, collected_at DESC`

	rows, err := r.db.Query(ctx, query, hostID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get latest container metrics")
	}
	defer rows.Close()

	return scanSnapshotRows(rows)
}

// CleanupOldMetrics deletes snapshots older than retentionDays.
// Returns number of rows deleted.
func (r *MetricsRepository) CleanupOldMetrics(ctx context.Context, retentionDays int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)

	result, err := r.db.Exec(ctx,
		`DELETE FROM metrics_snapshots WHERE collected_at < $1`, cutoff)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternal, "failed to cleanup old metrics")
	}

	deleted := result.RowsAffected()
	if deleted > 0 {
		r.logger.Info("cleaned up old metrics", "deleted", deleted, "older_than", cutoff)
	}
	return deleted, nil
}

// CountByHost returns total snapshot count for a host.
func (r *MetricsRepository) CountByHost(ctx context.Context, hostID uuid.UUID) (int64, error) {
	var count int64
	err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM metrics_snapshots WHERE host_id = $1`, hostID).Scan(&count)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternal, "failed to count metrics")
	}
	return count, nil
}

// intervalToPostgres converts interval strings to PostgreSQL date_trunc arguments.
// SQL injection safe: only known values returned.
func intervalToPostgres(interval string) string {
	switch strings.ToLower(interval) {
	case "1m", "minute":
		return "minute"
	case "5m":
		// PostgreSQL doesn't have 5-minute truncation natively,
		// use minute and the frontend can downsample if needed.
		return "minute"
	case "15m":
		return "minute"
	case "1h", "hour":
		return "hour"
	case "1d", "day":
		return "day"
	default:
		return "minute"
	}
}
