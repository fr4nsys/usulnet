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
	"github.com/fr4nsys/usulnet/internal/services/security"
)

// SecurityScanRepository implements security.ScanRepository using pgx
type SecurityScanRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewSecurityScanRepository creates a new SecurityScanRepository
func NewSecurityScanRepository(db *DB, log *logger.Logger) *SecurityScanRepository {
	return &SecurityScanRepository{
		db:     db,
		logger: log.Named("security_scan_repo"),
	}
}

// scanColumns is the standard column list for security_scans queries
const scanColumns = `id, host_id, container_id, container_name, image,
	score, grade, issue_count, critical_count, high_count,
	medium_count, low_count, cve_count, include_cve,
	scan_duration_ms, completed_at, created_at`

// scanScanRow scans a pgx.Row into a models.SecurityScan
func scanScanRow(row pgx.Row) (*models.SecurityScan, error) {
	var s models.SecurityScan
	var grade string
	var durationMs int64

	err := row.Scan(
		&s.ID, &s.HostID, &s.ContainerID, &s.ContainerName, &s.Image,
		&s.Score, &grade, &s.IssueCount, &s.CriticalCount, &s.HighCount,
		&s.MediumCount, &s.LowCount, &s.CVECount, &s.IncludeCVE,
		&durationMs, &s.CompletedAt, &s.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	s.Grade = models.SecurityGrade(grade)
	s.ScanDuration = time.Duration(durationMs) * time.Millisecond
	return &s, nil
}

// scanScanRows scans multiple pgx.Rows into a slice of models.SecurityScan
func scanScanRows(rows pgx.Rows) ([]*models.SecurityScan, error) {
	var scans []*models.SecurityScan
	for rows.Next() {
		var s models.SecurityScan
		var grade string
		var durationMs int64

		err := rows.Scan(
			&s.ID, &s.HostID, &s.ContainerID, &s.ContainerName, &s.Image,
			&s.Score, &grade, &s.IssueCount, &s.CriticalCount, &s.HighCount,
			&s.MediumCount, &s.LowCount, &s.CVECount, &s.IncludeCVE,
			&durationMs, &s.CompletedAt, &s.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		s.Grade = models.SecurityGrade(grade)
		s.ScanDuration = time.Duration(durationMs) * time.Millisecond
		scans = append(scans, &s)
	}
	return scans, rows.Err()
}

// Create inserts a new security scan
func (r *SecurityScanRepository) Create(ctx context.Context, scan *models.SecurityScan) error {
	log := logger.FromContext(ctx)

	query := `
		INSERT INTO security_scans (
			id, host_id, container_id, container_name, image,
			score, grade, issue_count, critical_count, high_count,
			medium_count, low_count, cve_count, include_cve,
			scan_duration_ms, completed_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12, $13, $14,
			$15, $16, $17
		)`

	if scan.ID == uuid.Nil {
		scan.ID = uuid.New()
	}
	if scan.CreatedAt.IsZero() {
		scan.CreatedAt = time.Now()
	}
	if scan.CompletedAt.IsZero() {
		scan.CompletedAt = scan.CreatedAt
	}

	_, err := r.db.Exec(ctx, query,
		scan.ID,
		scan.HostID,
		scan.ContainerID,
		scan.ContainerName,
		scan.Image,
		scan.Score,
		string(scan.Grade),
		scan.IssueCount,
		scan.CriticalCount,
		scan.HighCount,
		scan.MediumCount,
		scan.LowCount,
		scan.CVECount,
		scan.IncludeCVE,
		scan.ScanDuration.Milliseconds(),
		scan.CompletedAt,
		scan.CreatedAt,
	)

	if err != nil {
		log.Error("Failed to create security scan",
			"scan_id", scan.ID,
			"container_id", scan.ContainerID,
			"error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create security scan")
	}

	log.Debug("Security scan created",
		"scan_id", scan.ID,
		"container_id", scan.ContainerID,
		"score", scan.Score)

	return nil
}

// GetByID retrieves a security scan by ID
func (r *SecurityScanRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.SecurityScan, error) {
	query := fmt.Sprintf(`SELECT %s FROM security_scans WHERE id = $1`, scanColumns)

	scan, err := scanScanRow(r.db.QueryRow(ctx, query, id))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("security scan")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get security scan")
	}

	return scan, nil
}

// GetByContainerID retrieves scans for a specific container
func (r *SecurityScanRepository) GetByContainerID(ctx context.Context, containerID string, limit int) ([]*models.SecurityScan, error) {
	if limit <= 0 {
		limit = 10
	}

	query := fmt.Sprintf(`
		SELECT %s FROM security_scans
		WHERE container_id = $1
		ORDER BY created_at DESC
		LIMIT $2`, scanColumns)

	rows, err := r.db.Query(ctx, query, containerID, limit)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list security scans")
	}
	defer rows.Close()

	scans, err := scanScanRows(rows)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan security scan rows")
	}
	return scans, nil
}

// GetByHostID retrieves scans for a specific host
func (r *SecurityScanRepository) GetByHostID(ctx context.Context, hostID uuid.UUID, limit int) ([]*models.SecurityScan, error) {
	if limit <= 0 {
		limit = 100
	}

	query := fmt.Sprintf(`
		SELECT %s FROM security_scans
		WHERE host_id = $1
		ORDER BY created_at DESC
		LIMIT $2`, scanColumns)

	rows, err := r.db.Query(ctx, query, hostID, limit)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list security scans by host")
	}
	defer rows.Close()

	scans, err := scanScanRows(rows)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan security scan rows")
	}
	return scans, nil
}

// GetLatestByContainer retrieves the most recent scan for a container
func (r *SecurityScanRepository) GetLatestByContainer(ctx context.Context, containerID string) (*models.SecurityScan, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM security_scans
		WHERE container_id = $1
		ORDER BY created_at DESC
		LIMIT 1`, scanColumns)

	scan, err := scanScanRow(r.db.QueryRow(ctx, query, containerID))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil // No scan found is not an error
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get latest security scan")
	}

	return scan, nil
}

// List retrieves scans with filtering and pagination
func (r *SecurityScanRepository) List(ctx context.Context, opts security.ListScansOptions) ([]*models.SecurityScan, int, error) {
	var conditions []string
	var args []interface{}
	argNum := 1

	if opts.HostID != nil {
		conditions = append(conditions, fmt.Sprintf("host_id = $%d", argNum))
		args = append(args, *opts.HostID)
		argNum++
	}
	if opts.ContainerID != nil {
		conditions = append(conditions, fmt.Sprintf("container_id = $%d", argNum))
		args = append(args, *opts.ContainerID)
		argNum++
	}
	if opts.MinScore != nil {
		conditions = append(conditions, fmt.Sprintf("score >= $%d", argNum))
		args = append(args, *opts.MinScore)
		argNum++
	}
	if opts.MaxScore != nil {
		conditions = append(conditions, fmt.Sprintf("score <= $%d", argNum))
		args = append(args, *opts.MaxScore)
		argNum++
	}
	if opts.Grade != nil {
		conditions = append(conditions, fmt.Sprintf("grade = $%d", argNum))
		args = append(args, string(*opts.Grade))
		argNum++
	}
	if opts.Since != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argNum))
		args = append(args, *opts.Since)
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM security_scans %s", whereClause)
	var total int
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count security scans")
	}

	if opts.Limit <= 0 {
		opts.Limit = 50
	}

	query := fmt.Sprintf(`
		SELECT %s FROM security_scans
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`,
		scanColumns, whereClause, argNum, argNum+1)

	args = append(args, opts.Limit, opts.Offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to list security scans")
	}
	defer rows.Close()

	scans, err := scanScanRows(rows)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan security scan rows")
	}

	return scans, total, nil
}

// Delete removes a security scan
func (r *SecurityScanRepository) Delete(ctx context.Context, id uuid.UUID) error {
	log := logger.FromContext(ctx)

	result, err := r.db.Exec(ctx, `DELETE FROM security_scans WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete security scan")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("security scan")
	}

	log.Debug("Security scan deleted", "scan_id", id)
	return nil
}

// DeleteOlderThan removes scans older than the specified time
func (r *SecurityScanRepository) DeleteOlderThan(ctx context.Context, before time.Time) (int64, error) {
	log := logger.FromContext(ctx)

	result, err := r.db.Exec(ctx, `DELETE FROM security_scans WHERE created_at < $1`, before)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to delete old security scans")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected > 0 {
		log.Info("Deleted old security scans", "count", rowsAffected, "before", before)
	}

	return rowsAffected, nil
}

// GetScoreHistory retrieves score history for a container
func (r *SecurityScanRepository) GetScoreHistory(ctx context.Context, containerID string, days int) ([]models.TrendPoint, error) {
	if days <= 0 {
		days = 30
	}

	query := `
		SELECT DATE_TRUNC('day', created_at) as timestamp, AVG(score) as value
		FROM security_scans
		WHERE container_id = $1 AND created_at >= NOW() - INTERVAL '1 day' * $2
		GROUP BY DATE_TRUNC('day', created_at)
		ORDER BY timestamp ASC`

	rows, err := r.db.Query(ctx, query, containerID, days)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get score history")
	}
	defer rows.Close()

	var points []models.TrendPoint
	for rows.Next() {
		var p models.TrendPoint
		if err := rows.Scan(&p.Timestamp, &p.Value); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan trend point")
		}
		points = append(points, p)
	}

	return points, rows.Err()
}

// GetGlobalScoreHistory returns average score across all containers grouped by day
func (r *SecurityScanRepository) GetGlobalScoreHistory(ctx context.Context, days int) ([]models.TrendPoint, error) {
	if days <= 0 {
		days = 30
	}

	query := `
		SELECT DATE_TRUNC('day', created_at) as timestamp, AVG(score) as value
		FROM security_scans
		WHERE created_at >= NOW() - INTERVAL '1 day' * $1
		GROUP BY DATE_TRUNC('day', created_at)
		ORDER BY timestamp ASC`

	rows, err := r.db.Query(ctx, query, days)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get global score history")
	}
	defer rows.Close()

	var points []models.TrendPoint
	for rows.Next() {
		var p models.TrendPoint
		if err := rows.Scan(&p.Timestamp, &p.Value); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan trend point")
		}
		points = append(points, p)
	}

	return points, rows.Err()
}

// GetGradeDistribution returns the distribution of grades
func (r *SecurityScanRepository) GetGradeDistribution(ctx context.Context, hostID *uuid.UUID) (map[models.SecurityGrade]int, error) {
	var query string
	var args []interface{}

	if hostID != nil {
		query = `
			SELECT grade, COUNT(*) as count
			FROM (
				SELECT DISTINCT ON (container_id) grade
				FROM security_scans
				WHERE host_id = $1
				ORDER BY container_id, created_at DESC
			) latest
			GROUP BY grade`
		args = append(args, *hostID)
	} else {
		query = `
			SELECT grade, COUNT(*) as count
			FROM (
				SELECT DISTINCT ON (container_id) grade
				FROM security_scans
				ORDER BY container_id, created_at DESC
			) latest
			GROUP BY grade`
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get grade distribution")
	}
	defer rows.Close()

	distribution := make(map[models.SecurityGrade]int)
	for rows.Next() {
		var grade string
		var count int
		if err := rows.Scan(&grade, &count); err != nil {
			continue
		}
		distribution[models.SecurityGrade(grade)] = count
	}

	return distribution, rows.Err()
}

// GetAverageScore returns the average score across all latest scans
func (r *SecurityScanRepository) GetAverageScore(ctx context.Context, hostID *uuid.UUID) (float64, error) {
	var query string
	var args []interface{}

	if hostID != nil {
		query = `
			SELECT COALESCE(AVG(score), 0)
			FROM (
				SELECT DISTINCT ON (container_id) score
				FROM security_scans
				WHERE host_id = $1
				ORDER BY container_id, created_at DESC
			) latest`
		args = append(args, *hostID)
	} else {
		query = `
			SELECT COALESCE(AVG(score), 0)
			FROM (
				SELECT DISTINCT ON (container_id) score
				FROM security_scans
				ORDER BY container_id, created_at DESC
			) latest`
	}

	var avg float64
	err := r.db.QueryRow(ctx, query, args...).Scan(&avg)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to get average score")
	}

	return avg, nil
}
