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
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// AuditLogRepository handles audit log database operations
type AuditLogRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewAuditLogRepository creates a new AuditLogRepository
func NewAuditLogRepository(db *DB, log *logger.Logger) *AuditLogRepository {
	return &AuditLogRepository{
		db:     db,
		logger: log.Named("audit_log_repo"),
	}
}

// CreateAuditLogInput represents input for creating an audit log entry
type CreateAuditLogInput struct {
	UserID       *uuid.UUID
	Username     *string
	Action       string
	ResourceType string
	ResourceID   *string
	Details      map[string]any
	IPAddress    *string
	UserAgent    *string
	Success      bool
	ErrorMsg     *string
}

// Create inserts a new audit log entry
func (r *AuditLogRepository) Create(ctx context.Context, input *CreateAuditLogInput) error {
	query := `
		INSERT INTO audit_log (
			user_id, action, resource_type, resource_id,
			details, ip_address, user_agent, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		)`

	var ipAddr *net.IP
	if input.IPAddress != nil {
		ip := net.ParseIP(*input.IPAddress)
		if ip != nil {
			ipAddr = &ip
		}
	}

	// Convert details to JSONB
	var detailsJSON []byte
	var err error
	if input.Details != nil {
		// Add success and error info to details
		detailsCopy := make(map[string]any)
		for k, v := range input.Details {
			detailsCopy[k] = v
		}
		detailsCopy["success"] = input.Success
		if input.ErrorMsg != nil {
			detailsCopy["error"] = *input.ErrorMsg
		}
		if input.Username != nil {
			detailsCopy["username"] = *input.Username
		}
		detailsJSON, err = json.Marshal(detailsCopy)
		if err != nil {
			return errors.Wrap(err, errors.CodeInternal, "failed to marshal audit details")
		}
	} else {
		details := map[string]any{
			"success": input.Success,
		}
		if input.ErrorMsg != nil {
			details["error"] = *input.ErrorMsg
		}
		if input.Username != nil {
			details["username"] = *input.Username
		}
		detailsJSON, err = json.Marshal(details)
		if err != nil {
			return errors.Wrap(err, errors.CodeInternal, "failed to marshal audit details")
		}
	}

	_, err = r.db.Exec(ctx, query,
		input.UserID,
		input.Action,
		input.ResourceType,
		input.ResourceID,
		detailsJSON,
		ipAddr,
		input.UserAgent,
		time.Now(),
	)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create audit log entry")
	}

	return nil
}

// AuditLogListOptions represents options for listing audit logs
type AuditLogListOptions struct {
	UserID       *uuid.UUID
	Action       *string
	ResourceType *string
	ResourceID   *string
	Since        *time.Time
	Until        *time.Time
	Limit        int
	Offset       int
}

// List retrieves audit logs with filtering and pagination
func (r *AuditLogRepository) List(ctx context.Context, opts AuditLogListOptions) ([]*models.AuditLogEntry, int, error) {
	// Build WHERE clause
	var conditions []string
	var args []interface{}
	argNum := 1

	if opts.UserID != nil {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argNum))
		args = append(args, *opts.UserID)
		argNum++
	}

	if opts.Action != nil {
		conditions = append(conditions, fmt.Sprintf("action = $%d", argNum))
		args = append(args, *opts.Action)
		argNum++
	}

	if opts.ResourceType != nil {
		conditions = append(conditions, fmt.Sprintf("resource_type = $%d", argNum))
		args = append(args, *opts.ResourceType)
		argNum++
	}

	if opts.ResourceID != nil {
		conditions = append(conditions, fmt.Sprintf("resource_id = $%d", argNum))
		args = append(args, *opts.ResourceID)
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
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM audit_log %s", whereClause)
	var total int
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count audit logs")
	}

	// Set defaults
	if opts.Limit <= 0 {
		opts.Limit = 50
	}

	// Build main query
	query := fmt.Sprintf(`
		SELECT id, user_id, action, resource_type, resource_id,
			details, ip_address, user_agent, created_at
		FROM audit_log
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`,
		whereClause, argNum, argNum+1)

	args = append(args, opts.Limit, opts.Offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to list audit logs")
	}
	defer rows.Close()

	logs, err := r.scanAuditLogs(rows)
	if err != nil {
		return nil, 0, err
	}

	return logs, total, nil
}

// GetByUser retrieves audit logs for a specific user
func (r *AuditLogRepository) GetByUser(ctx context.Context, userID uuid.UUID, limit int) ([]*models.AuditLogEntry, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT id, user_id, action, resource_type, resource_id,
			details, ip_address, user_agent, created_at
		FROM audit_log
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2`

	rows, err := r.db.Query(ctx, query, userID, limit)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get audit logs by user")
	}
	defer rows.Close()

	return r.scanAuditLogs(rows)
}

// GetByResource retrieves audit logs for a specific resource
func (r *AuditLogRepository) GetByResource(ctx context.Context, resourceType, resourceID string, limit int) ([]*models.AuditLogEntry, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT id, user_id, action, resource_type, resource_id,
			details, ip_address, user_agent, created_at
		FROM audit_log
		WHERE resource_type = $1 AND resource_id = $2
		ORDER BY created_at DESC
		LIMIT $3`

	rows, err := r.db.Query(ctx, query, resourceType, resourceID, limit)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get audit logs by resource")
	}
	defer rows.Close()

	return r.scanAuditLogs(rows)
}

// GetRecent retrieves recent audit logs
func (r *AuditLogRepository) GetRecent(ctx context.Context, limit int) ([]*models.AuditLogEntry, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT id, user_id, action, resource_type, resource_id,
			details, ip_address, user_agent, created_at
		FROM audit_log
		ORDER BY created_at DESC
		LIMIT $1`

	rows, err := r.db.Query(ctx, query, limit)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get recent audit logs")
	}
	defer rows.Close()

	return r.scanAuditLogs(rows)
}

// DeleteOlderThan removes audit logs older than the specified time
func (r *AuditLogRepository) DeleteOlderThan(ctx context.Context, before time.Time) (int64, error) {
	log := logger.FromContext(ctx)

	query := `DELETE FROM audit_log WHERE created_at < $1`

	result, err := r.db.Exec(ctx, query, before)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to delete old audit logs")
	}

	count := result.RowsAffected()
	if count > 0 {
		log.Info("Deleted old audit logs", "count", count, "before", before)
	}

	return count, nil
}

// GetStats returns statistics about audit logs
func (r *AuditLogRepository) GetStats(ctx context.Context, since time.Time) (map[string]int, error) {
	query := `
		SELECT action, COUNT(*) as count
		FROM audit_log
		WHERE created_at >= $1
		GROUP BY action
		ORDER BY count DESC`

	rows, err := r.db.Query(ctx, query, since)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get audit log stats")
	}
	defer rows.Close()

	stats := make(map[string]int)
	for rows.Next() {
		var action string
		var count int
		if err := rows.Scan(&action, &count); err != nil {
			continue
		}
		stats[action] = count
	}

	return stats, nil
}

// scanAuditLogs scans multiple rows into AuditLogEntry
func (r *AuditLogRepository) scanAuditLogs(rows pgx.Rows) ([]*models.AuditLogEntry, error) {
	var logs []*models.AuditLogEntry

	for rows.Next() {
		l := &models.AuditLogEntry{}
		var ipAddr *net.IP
		var detailsJSON []byte
		var id uuid.UUID

		err := rows.Scan(
			&id,
			&l.UserID,
			&l.Action,
			&l.EntityType,
			&l.EntityID,
			&detailsJSON,
			&ipAddr,
			&l.UserAgent,
			&l.CreatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan audit log")
		}

		// Parse ID to int64 (model uses int64 for ID)
		// Since DB uses UUID but model uses int64, we need to handle this
		// For now, we'll use the UUID's timestamp component
		l.ID = int64(id.ID())

		if ipAddr != nil {
			ip := ipAddr.String()
			l.IPAddress = &ip
		}

		if len(detailsJSON) > 0 {
			var details map[string]any
			if err := json.Unmarshal(detailsJSON, &details); err == nil {
				l.Details = &details
				// Extract success and error from details
				if success, ok := details["success"].(bool); ok {
					l.Success = success
				}
				if errMsg, ok := details["error"].(string); ok {
					l.ErrorMsg = &errMsg
				}
				if username, ok := details["username"].(string); ok {
					l.Username = &username
				}
			}
		}

		logs = append(logs, l)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "error iterating audit logs")
	}

	return logs, nil
}
