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

// SecurityIssueRepository implements security.IssueRepository using pgx
type SecurityIssueRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewSecurityIssueRepository creates a new SecurityIssueRepository
func NewSecurityIssueRepository(db *DB, log *logger.Logger) *SecurityIssueRepository {
	return &SecurityIssueRepository{
		db:     db,
		logger: log.Named("security_issue_repo"),
	}
}

// issueColumns is the standard column list for security_issues queries
const issueColumns = `id, scan_id, container_id, host_id, severity, category,
	check_id, title, description, recommendation,
	fix_command, documentation_url, cve_id, cvss_score,
	status, acknowledged_by, acknowledged_at, resolved_by, resolved_at, detected_at`

// scanIssueRow scans a pgx row into a models.SecurityIssue
func scanIssueRow(row pgx.Row) (*models.SecurityIssue, error) {
	var i models.SecurityIssue
	var severity, category, status string
	var fixCommand, docURL, cveID *string
	var cvssScore *float64

	err := row.Scan(
		&i.ID, &i.ScanID, &i.ContainerID, &i.HostID,
		&severity, &category, &i.CheckID, &i.Title,
		&i.Description, &i.Recommendation,
		&fixCommand, &docURL, &cveID, &cvssScore,
		&status, &i.AcknowledgedBy, &i.AcknowledgedAt,
		&i.ResolvedBy, &i.ResolvedAt, &i.DetectedAt,
	)
	if err != nil {
		return nil, err
	}

	i.Severity = models.IssueSeverity(severity)
	i.Category = models.IssueCategory(category)
	i.Status = models.IssueStatus(status)
	i.FixCommand = fixCommand
	i.DocumentationURL = docURL
	i.CVEID = cveID
	i.CVSSScore = cvssScore
	return &i, nil
}

// scanIssueRows scans multiple pgx rows into a slice of models.SecurityIssue
func scanIssueRows(rows pgx.Rows) ([]*models.SecurityIssue, error) {
	var issues []*models.SecurityIssue
	for rows.Next() {
		var i models.SecurityIssue
		var severity, category, status string
		var fixCommand, docURL, cveID *string
		var cvssScore *float64

		err := rows.Scan(
			&i.ID, &i.ScanID, &i.ContainerID, &i.HostID,
			&severity, &category, &i.CheckID, &i.Title,
			&i.Description, &i.Recommendation,
			&fixCommand, &docURL, &cveID, &cvssScore,
			&status, &i.AcknowledgedBy, &i.AcknowledgedAt,
			&i.ResolvedBy, &i.ResolvedAt, &i.DetectedAt,
		)
		if err != nil {
			return nil, err
		}

		i.Severity = models.IssueSeverity(severity)
		i.Category = models.IssueCategory(category)
		i.Status = models.IssueStatus(status)
		i.FixCommand = fixCommand
		i.DocumentationURL = docURL
		i.CVEID = cveID
		i.CVSSScore = cvssScore
		issues = append(issues, &i)
	}
	return issues, rows.Err()
}

// severityOrderSQL returns the ORDER BY clause for severity sorting
const severityOrderSQL = `CASE severity
	WHEN 'critical' THEN 1
	WHEN 'high' THEN 2
	WHEN 'medium' THEN 3
	WHEN 'low' THEN 4
	ELSE 5
END`

// CreateBatch inserts multiple security issues in a batch
func (r *SecurityIssueRepository) CreateBatch(ctx context.Context, issues []models.SecurityIssue) error {
	if len(issues) == 0 {
		return nil
	}

	log := logger.FromContext(ctx)

	query := `
		INSERT INTO security_issues (
			scan_id, container_id, host_id, severity, category,
			check_id, title, description, recommendation,
			fix_command, documentation_url, cve_id, cvss_score,
			status, detected_at
		) VALUES `

	var values []string
	var args []interface{}
	argNum := 1

	for _, issue := range issues {
		if issue.DetectedAt.IsZero() {
			issue.DetectedAt = time.Now()
		}
		if issue.Status == "" {
			issue.Status = models.IssueStatusOpen
		}

		placeholder := fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			argNum, argNum+1, argNum+2, argNum+3, argNum+4,
			argNum+5, argNum+6, argNum+7, argNum+8, argNum+9,
			argNum+10, argNum+11, argNum+12, argNum+13, argNum+14)
		values = append(values, placeholder)

		args = append(args,
			issue.ScanID,
			issue.ContainerID,
			issue.HostID,
			string(issue.Severity),
			string(issue.Category),
			issue.CheckID,
			issue.Title,
			issue.Description,
			issue.Recommendation,
			issue.FixCommand,
			issue.DocumentationURL,
			issue.CVEID,
			issue.CVSSScore,
			string(issue.Status),
			issue.DetectedAt,
		)
		argNum += 15
	}

	query += strings.Join(values, ", ")

	_, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		log.Error("Failed to create security issues batch",
			"count", len(issues),
			"error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create security issues")
	}

	log.Debug("Security issues created", "count", len(issues))
	return nil
}

// GetByID retrieves a security issue by ID
func (r *SecurityIssueRepository) GetByID(ctx context.Context, id int64) (*models.SecurityIssue, error) {
	query := fmt.Sprintf(`SELECT %s FROM security_issues WHERE id = $1`, issueColumns)

	issue, err := scanIssueRow(r.db.QueryRow(ctx, query, id))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("security issue")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get security issue")
	}

	return issue, nil
}

// GetByScanID retrieves all issues for a specific scan
func (r *SecurityIssueRepository) GetByScanID(ctx context.Context, scanID uuid.UUID) ([]*models.SecurityIssue, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM security_issues
		WHERE scan_id = $1
		ORDER BY %s, detected_at DESC`, issueColumns, severityOrderSQL)

	rows, err := r.db.Query(ctx, query, scanID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list security issues by scan")
	}
	defer rows.Close()

	issues, err := scanIssueRows(rows)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan issue rows")
	}
	return issues, nil
}

// GetByContainerID retrieves issues for a specific container
func (r *SecurityIssueRepository) GetByContainerID(ctx context.Context, containerID string, status *models.IssueStatus) ([]*models.SecurityIssue, error) {
	var query string
	var args []interface{}

	baseQuery := fmt.Sprintf(`
		SELECT %s FROM security_issues
		WHERE container_id = $1`, issueColumns)

	args = append(args, containerID)

	if status != nil {
		query = baseQuery + ` AND status = $2`
		args = append(args, string(*status))
	} else {
		query = baseQuery
	}

	query += fmt.Sprintf(` ORDER BY %s, detected_at DESC`, severityOrderSQL)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list security issues by container")
	}
	defer rows.Close()

	issues, err := scanIssueRows(rows)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan issue rows")
	}
	return issues, nil
}

// GetByHostID retrieves issues for a specific host with filtering
func (r *SecurityIssueRepository) GetByHostID(ctx context.Context, hostID uuid.UUID, opts security.ListIssuesOptions) ([]*models.SecurityIssue, int, error) {
	conditions := []string{"host_id = $1"}
	args := []interface{}{hostID}
	argNum := 2

	if opts.ContainerID != nil {
		conditions = append(conditions, fmt.Sprintf("container_id = $%d", argNum))
		args = append(args, *opts.ContainerID)
		argNum++
	}
	if opts.ScanID != nil {
		conditions = append(conditions, fmt.Sprintf("scan_id = $%d", argNum))
		args = append(args, *opts.ScanID)
		argNum++
	}
	if opts.Severity != nil {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argNum))
		args = append(args, string(*opts.Severity))
		argNum++
	}
	if opts.Category != nil {
		conditions = append(conditions, fmt.Sprintf("category = $%d", argNum))
		args = append(args, string(*opts.Category))
		argNum++
	}
	if opts.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argNum))
		args = append(args, string(*opts.Status))
		argNum++
	}
	if opts.CheckID != nil {
		conditions = append(conditions, fmt.Sprintf("check_id = $%d", argNum))
		args = append(args, *opts.CheckID)
		argNum++
	}

	whereClause := "WHERE " + strings.Join(conditions, " AND ")

	// Count total
	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM security_issues %s", whereClause)
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count security issues")
	}

	if opts.Limit <= 0 {
		opts.Limit = 50
	}

	query := fmt.Sprintf(`
		SELECT %s FROM security_issues
		%s
		ORDER BY %s, detected_at DESC
		LIMIT $%d OFFSET $%d`,
		issueColumns, whereClause, severityOrderSQL, argNum, argNum+1)

	args = append(args, opts.Limit, opts.Offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to list security issues by host")
	}
	defer rows.Close()

	issues, err := scanIssueRows(rows)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan issue rows")
	}

	return issues, total, nil
}

// UpdateStatus updates the status of a security issue
func (r *SecurityIssueRepository) UpdateStatus(ctx context.Context, id int64, status models.IssueStatus, userID *uuid.UUID) error {
	log := logger.FromContext(ctx)

	var query string
	var args []interface{}
	now := time.Now()

	switch status {
	case models.IssueStatusAcknowledged:
		query = `UPDATE security_issues SET status = $1, acknowledged_by = $2, acknowledged_at = $3 WHERE id = $4`
		args = []interface{}{string(status), userID, now, id}
	case models.IssueStatusResolved:
		query = `UPDATE security_issues SET status = $1, resolved_by = $2, resolved_at = $3 WHERE id = $4`
		args = []interface{}{string(status), userID, now, id}
	default:
		query = `UPDATE security_issues SET status = $1 WHERE id = $2`
		args = []interface{}{string(status), id}
	}

	result, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update issue status")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("security issue")
	}

	log.Debug("Security issue status updated",
		"issue_id", id,
		"status", status,
		"user_id", userID)

	return nil
}

// GetOpenIssueCount returns the count of open issues for a container
func (r *SecurityIssueRepository) GetOpenIssueCount(ctx context.Context, containerID string) (int, error) {
	var count int
	err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM security_issues WHERE container_id = $1 AND status = 'open'`,
		containerID,
	).Scan(&count)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count open issues")
	}
	return count, nil
}

// DeleteByScanID removes all issues for a specific scan
func (r *SecurityIssueRepository) DeleteByScanID(ctx context.Context, scanID uuid.UUID) error {
	log := logger.FromContext(ctx)

	result, err := r.db.Exec(ctx, `DELETE FROM security_issues WHERE scan_id = $1`, scanID)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete security issues")
	}

	if result.RowsAffected() > 0 {
		log.Debug("Security issues deleted", "scan_id", scanID, "count", result.RowsAffected())
	}

	return nil
}

// GetSeverityCounts returns counts of issues by severity
func (r *SecurityIssueRepository) GetSeverityCounts(ctx context.Context, hostID *uuid.UUID, status *models.IssueStatus) (map[models.IssueSeverity]int, error) {
	var conditions []string
	var args []interface{}
	argNum := 1

	if hostID != nil {
		conditions = append(conditions, fmt.Sprintf("host_id = $%d", argNum))
		args = append(args, *hostID)
		argNum++
	}
	if status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argNum))
		args = append(args, string(*status))
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(`
		SELECT severity, COUNT(*) as count
		FROM security_issues
		%s
		GROUP BY severity`, whereClause)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get severity counts")
	}
	defer rows.Close()

	counts := make(map[models.IssueSeverity]int)
	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			continue
		}
		counts[models.IssueSeverity(severity)] = count
	}

	return counts, rows.Err()
}

// GetTopIssues returns the most common issues across containers
func (r *SecurityIssueRepository) GetTopIssues(ctx context.Context, hostID *uuid.UUID, limit int) ([]*models.SecurityIssue, error) {
	if limit <= 0 {
		limit = 10
	}

	var query string
	var args []interface{}

	if hostID != nil {
		query = fmt.Sprintf(`
			SELECT %s FROM security_issues
			WHERE host_id = $1 AND status = 'open'
			ORDER BY %s, detected_at DESC
			LIMIT $2`, issueColumns, severityOrderSQL)
		args = []interface{}{*hostID, limit}
	} else {
		query = fmt.Sprintf(`
			SELECT %s FROM security_issues
			WHERE status = 'open'
			ORDER BY %s, detected_at DESC
			LIMIT $1`, issueColumns, severityOrderSQL)
		args = []interface{}{limit}
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get top issues")
	}
	defer rows.Close()

	issues, err := scanIssueRows(rows)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan issue rows")
	}
	return issues, nil
}
