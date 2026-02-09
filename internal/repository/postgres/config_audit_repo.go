// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
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

// ConfigAuditRepository implements config.AuditRepository
type ConfigAuditRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewConfigAuditRepository creates a new ConfigAuditRepository
func NewConfigAuditRepository(db *DB, log *logger.Logger) *ConfigAuditRepository {
	return &ConfigAuditRepository{
		db:     db,
		logger: log.Named("config_audit_repo"),
	}
}

// LogEntry represents input for creating an audit log entry
type AuditLogEntry struct {
	Action     string
	EntityType string
	EntityID   string
	EntityName string
	OldValue   *string
	NewValue   *string
	UserID     *uuid.UUID
	Username   *string
	IPAddress  *string
	UserAgent  *string
}

// Create inserts a new audit log entry
func (r *ConfigAuditRepository) Create(ctx context.Context, entry *AuditLogEntry) error {
	query := `
		INSERT INTO config_audit_log (
			action, entity_type, entity_id, entity_name,
			old_value, new_value, user_id, username,
			ip_address, user_agent, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		)`

	var ipAddr *net.IP
	if entry.IPAddress != nil {
		ip := net.ParseIP(*entry.IPAddress)
		if ip != nil {
			ipAddr = &ip
		}
	}

	_, err := r.db.Exec(ctx, query,
		entry.Action,
		entry.EntityType,
		entry.EntityID,
		entry.EntityName,
		entry.OldValue,
		entry.NewValue,
		entry.UserID,
		entry.Username,
		ipAddr,
		entry.UserAgent,
		time.Now(),
	)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create audit log entry")
	}

	return nil
}

// AuditListOptions represents options for listing audit logs
type AuditListOptions struct {
	EntityType *string
	EntityID   *string
	UserID     *uuid.UUID
	Action     *string
	Since      *time.Time
	Until      *time.Time
	Limit      int
	Offset     int
}

// List retrieves audit logs with filtering and pagination
func (r *ConfigAuditRepository) List(ctx context.Context, opts AuditListOptions) ([]*models.ConfigAuditLog, int, error) {
	// Build WHERE clause
	var conditions []string
	var args []interface{}
	argNum := 1

	if opts.EntityType != nil {
		conditions = append(conditions, fmt.Sprintf("entity_type = $%d", argNum))
		args = append(args, *opts.EntityType)
		argNum++
	}

	if opts.EntityID != nil {
		conditions = append(conditions, fmt.Sprintf("entity_id = $%d", argNum))
		args = append(args, *opts.EntityID)
		argNum++
	}

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
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM config_audit_log %s", whereClause)
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
		SELECT id, action, entity_type, entity_id, entity_name,
			old_value, new_value, user_id, username, ip_address,
			created_at
		FROM config_audit_log
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

// GetByEntity retrieves audit logs for a specific entity
func (r *ConfigAuditRepository) GetByEntity(ctx context.Context, entityType, entityID string, limit int) ([]*models.ConfigAuditLog, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT id, action, entity_type, entity_id, entity_name,
			old_value, new_value, user_id, username, ip_address,
			created_at
		FROM config_audit_log
		WHERE entity_type = $1 AND entity_id = $2
		ORDER BY created_at DESC
		LIMIT $3`

	rows, err := r.db.Query(ctx, query, entityType, entityID, limit)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get audit logs by entity")
	}
	defer rows.Close()

	return r.scanAuditLogs(rows)
}

// DeleteOlderThan removes audit logs older than the specified time
func (r *ConfigAuditRepository) DeleteOlderThan(ctx context.Context, before time.Time) (int64, error) {
	log := logger.FromContext(ctx)

	query := `DELETE FROM config_audit_log WHERE created_at < $1`

	result, err := r.db.Exec(ctx, query, before)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to delete old audit logs")
	}

	count := result.RowsAffected()
	if count > 0 {
		log.Info("Deleted old config audit logs", "count", count, "before", before)
	}

	return count, nil
}

// scanAuditLogs scans multiple rows into ConfigAuditLog
func (r *ConfigAuditRepository) scanAuditLogs(rows pgx.Rows) ([]*models.ConfigAuditLog, error) {
	var logs []*models.ConfigAuditLog

	for rows.Next() {
		l := &models.ConfigAuditLog{}
		var ipAddr *net.IP

		err := rows.Scan(
			&l.ID,
			&l.Action,
			&l.EntityType,
			&l.EntityID,
			&l.EntityName,
			&l.OldValue,
			&l.NewValue,
			&l.UserID,
			&l.Username,
			&ipAddr,
			&l.CreatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan audit log")
		}

		if ipAddr != nil {
			ip := ipAddr.String()
			l.IPAddress = &ip
		}

		logs = append(logs, l)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "error iterating audit logs")
	}

	return logs, nil
}

// ============================================================================
// ConfigSyncRepository
// ============================================================================

// ConfigSyncRepository implements config.SyncRepository
type ConfigSyncRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewConfigSyncRepository creates a new ConfigSyncRepository
func NewConfigSyncRepository(db *DB, log *logger.Logger) *ConfigSyncRepository {
	return &ConfigSyncRepository{
		db:     db,
		logger: log.Named("config_sync_repo"),
	}
}

// Create inserts a new sync record
func (r *ConfigSyncRepository) Create(ctx context.Context, s *models.ConfigSync) error {
	log := logger.FromContext(ctx)

	query := `
		INSERT INTO config_syncs (
			id, host_id, container_id, container_name, template_id,
			template_name, status, variables_hash, synced_at,
			error_message, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)
		ON CONFLICT (host_id, container_id) DO UPDATE SET
			container_name = EXCLUDED.container_name,
			template_id = EXCLUDED.template_id,
			template_name = EXCLUDED.template_name,
			status = EXCLUDED.status,
			variables_hash = EXCLUDED.variables_hash,
			synced_at = EXCLUDED.synced_at,
			error_message = EXCLUDED.error_message,
			updated_at = EXCLUDED.updated_at`

	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	now := time.Now()
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	s.UpdatedAt = now

	_, err := r.db.Exec(ctx, query,
		s.ID,
		s.HostID,
		s.ContainerID,
		s.ContainerName,
		s.TemplateID,
		s.TemplateName,
		s.Status,
		s.VariablesHash,
		s.SyncedAt,
		s.ErrorMessage,
		s.CreatedAt,
		s.UpdatedAt,
	)

	if err != nil {
		log.Error("Failed to create/update config sync",
			"sync_id", s.ID,
			"container_id", s.ContainerID,
			"error", err)
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create config sync")
	}

	log.Debug("Config sync created/updated",
		"sync_id", s.ID,
		"container_id", s.ContainerID,
		"status", s.Status)

	return nil
}

// GetByID retrieves a sync record by ID
func (r *ConfigSyncRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ConfigSync, error) {
	query := `
		SELECT id, host_id, container_id, container_name, template_id,
			template_name, status, variables_hash, synced_at,
			error_message, created_at, updated_at
		FROM config_syncs
		WHERE id = $1`

	row := r.db.QueryRow(ctx, query, id)
	return r.scanSync(row)
}

// GetByContainer retrieves a sync record for a specific container
func (r *ConfigSyncRepository) GetByContainer(ctx context.Context, hostID uuid.UUID, containerID string) (*models.ConfigSync, error) {
	query := `
		SELECT id, host_id, container_id, container_name, template_id,
			template_name, status, variables_hash, synced_at,
			error_message, created_at, updated_at
		FROM config_syncs
		WHERE host_id = $1 AND container_id = $2`

	row := r.db.QueryRow(ctx, query, hostID, containerID)
	s, err := r.scanSync(row)
	if err != nil {
		if errors.Is(err, errors.ErrNotFound) {
			return nil, nil // Not found is not an error here
		}
		return nil, err
	}
	return s, nil
}

// UpdateStatus updates the status of a sync record
func (r *ConfigSyncRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status string, errorMsg *string) error {
	log := logger.FromContext(ctx)

	var query string
	var args []interface{}

	if status == "synced" {
		query = `
			UPDATE config_syncs
			SET status = $2, synced_at = $3, error_message = NULL, updated_at = $3
			WHERE id = $1`
		args = []interface{}{id, status, time.Now()}
	} else {
		query = `
			UPDATE config_syncs
			SET status = $2, error_message = $3, updated_at = $4
			WHERE id = $1`
		args = []interface{}{id, status, errorMsg, time.Now()}
	}

	result, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update sync status")
	}

	if result.RowsAffected() == 0 {
		return errors.NotFound("config sync")
	}

	log.Debug("Config sync status updated",
		"sync_id", id,
		"status", status)

	return nil
}

// SyncListOptions represents options for listing syncs
type SyncListOptions struct {
	HostID     *uuid.UUID
	TemplateID *uuid.UUID
	Status     *string
	Limit      int
	Offset     int
}

// List retrieves sync records with filtering
func (r *ConfigSyncRepository) List(ctx context.Context, opts SyncListOptions) ([]*models.ConfigSync, int, error) {
	// Build WHERE clause
	var conditions []string
	var args []interface{}
	argNum := 1

	if opts.HostID != nil {
		conditions = append(conditions, fmt.Sprintf("host_id = $%d", argNum))
		args = append(args, *opts.HostID)
		argNum++
	}

	if opts.TemplateID != nil {
		conditions = append(conditions, fmt.Sprintf("template_id = $%d", argNum))
		args = append(args, *opts.TemplateID)
		argNum++
	}

	if opts.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argNum))
		args = append(args, *opts.Status)
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM config_syncs %s", whereClause)
	var total int
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count syncs")
	}

	// Set defaults
	if opts.Limit <= 0 {
		opts.Limit = 50
	}

	// Build main query
	query := fmt.Sprintf(`
		SELECT id, host_id, container_id, container_name, template_id,
			template_name, status, variables_hash, synced_at,
			error_message, created_at, updated_at
		FROM config_syncs
		%s
		ORDER BY updated_at DESC
		LIMIT $%d OFFSET $%d`,
		whereClause, argNum, argNum+1)

	args = append(args, opts.Limit, opts.Offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to list syncs")
	}
	defer rows.Close()

	syncs, err := r.scanSyncs(rows)
	if err != nil {
		return nil, 0, err
	}

	return syncs, total, nil
}

// ListOutdated retrieves all syncs with outdated status
func (r *ConfigSyncRepository) ListOutdated(ctx context.Context, hostID *uuid.UUID) ([]*models.ConfigSync, error) {
	var query string
	var args []interface{}

	if hostID != nil {
		query = `
			SELECT id, host_id, container_id, container_name, template_id,
				template_name, status, variables_hash, synced_at,
				error_message, created_at, updated_at
			FROM config_syncs
			WHERE status = 'outdated' AND host_id = $1
			ORDER BY container_name`
		args = []interface{}{*hostID}
	} else {
		query = `
			SELECT id, host_id, container_id, container_name, template_id,
				template_name, status, variables_hash, synced_at,
				error_message, created_at, updated_at
			FROM config_syncs
			WHERE status = 'outdated'
			ORDER BY container_name`
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list outdated syncs")
	}
	defer rows.Close()

	return r.scanSyncs(rows)
}

// Delete removes a sync record
func (r *ConfigSyncRepository) Delete(ctx context.Context, id uuid.UUID) error {
	log := logger.FromContext(ctx)

	query := `DELETE FROM config_syncs WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete config sync")
	}

	if result.RowsAffected() == 0 {
		return errors.NotFound("config sync")
	}

	log.Debug("Config sync deleted", "sync_id", id)
	return nil
}

// DeleteByContainer removes sync record for a container
func (r *ConfigSyncRepository) DeleteByContainer(ctx context.Context, hostID uuid.UUID, containerID string) error {
	log := logger.FromContext(ctx)

	query := `DELETE FROM config_syncs WHERE host_id = $1 AND container_id = $2`

	_, err := r.db.Exec(ctx, query, hostID, containerID)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete config sync")
	}

	log.Debug("Config sync deleted by container",
		"host_id", hostID,
		"container_id", containerID)

	return nil
}

// GetSyncStats returns statistics about sync statuses
func (r *ConfigSyncRepository) GetSyncStats(ctx context.Context, hostID *uuid.UUID) (map[string]int, error) {
	var query string
	var args []interface{}

	if hostID != nil {
		query = `
			SELECT status, COUNT(*) as count
			FROM config_syncs
			WHERE host_id = $1
			GROUP BY status`
		args = []interface{}{*hostID}
	} else {
		query = `
			SELECT status, COUNT(*) as count
			FROM config_syncs
			GROUP BY status`
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get sync stats")
	}
	defer rows.Close()

	stats := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			continue
		}
		stats[status] = count
	}

	return stats, nil
}

// scanSync scans a single row into ConfigSync
func (r *ConfigSyncRepository) scanSync(row pgx.Row) (*models.ConfigSync, error) {
	s := &models.ConfigSync{}

	err := row.Scan(
		&s.ID,
		&s.HostID,
		&s.ContainerID,
		&s.ContainerName,
		&s.TemplateID,
		&s.TemplateName,
		&s.Status,
		&s.VariablesHash,
		&s.SyncedAt,
		&s.ErrorMessage,
		&s.CreatedAt,
		&s.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("config sync")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan sync")
	}

	return s, nil
}

// scanSyncs scans multiple rows into ConfigSync
func (r *ConfigSyncRepository) scanSyncs(rows pgx.Rows) ([]*models.ConfigSync, error) {
	var syncs []*models.ConfigSync

	for rows.Next() {
		s := &models.ConfigSync{}

		err := rows.Scan(
			&s.ID,
			&s.HostID,
			&s.ContainerID,
			&s.ContainerName,
			&s.TemplateID,
			&s.TemplateName,
			&s.Status,
			&s.VariablesHash,
			&s.SyncedAt,
			&s.ErrorMessage,
			&s.CreatedAt,
			&s.UpdatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan sync")
		}

		syncs = append(syncs, s)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "error iterating syncs")
	}

	return syncs, nil
}
