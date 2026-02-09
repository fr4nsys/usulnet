// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
)

// =============================================================================
// NPMConnectionRepository
// =============================================================================

type NPMConnectionRepository struct {
	db *DB
}

func NewNPMConnectionRepository(db *DB) *NPMConnectionRepository {
	return &NPMConnectionRepository{db: db}
}

func (r *NPMConnectionRepository) Create(ctx context.Context, conn *models.NPMConnection) error {
	query := `
		INSERT INTO npm_connections (
			id, host_id, base_url, admin_email, admin_password_encrypted,
			is_enabled, health_status, created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	_, err := r.db.Exec(ctx, query,
		conn.ID, conn.HostID, conn.BaseURL, conn.AdminEmail,
		conn.AdminPasswordEncrypted, conn.IsEnabled, conn.HealthStatus,
		conn.CreatedAt, conn.UpdatedAt, conn.CreatedBy, conn.UpdatedBy,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create NPM connection")
	}
	return nil
}

func (r *NPMConnectionRepository) GetByID(ctx context.Context, id string) (*models.NPMConnection, error) {
	query := `
		SELECT id, host_id, base_url, admin_email, admin_password_encrypted,
			is_enabled, health_status, health_message, last_health_check,
			created_at, updated_at, created_by, updated_by
		FROM npm_connections WHERE id = $1`
	conn := &models.NPMConnection{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&conn.ID, &conn.HostID, &conn.BaseURL, &conn.AdminEmail,
		&conn.AdminPasswordEncrypted, &conn.IsEnabled, &conn.HealthStatus,
		&conn.HealthMessage, &conn.LastHealthCheck,
		&conn.CreatedAt, &conn.UpdatedAt, &conn.CreatedBy, &conn.UpdatedBy,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "NPM connection not found")
	}
	return conn, nil
}

func (r *NPMConnectionRepository) GetByHostID(ctx context.Context, hostID string) (*models.NPMConnection, error) {
	query := `
		SELECT id, host_id, base_url, admin_email, admin_password_encrypted,
			is_enabled, health_status, health_message, last_health_check,
			created_at, updated_at, created_by, updated_by
		FROM npm_connections WHERE host_id = $1`
	conn := &models.NPMConnection{}
	err := r.db.QueryRow(ctx, query, hostID).Scan(
		&conn.ID, &conn.HostID, &conn.BaseURL, &conn.AdminEmail,
		&conn.AdminPasswordEncrypted, &conn.IsEnabled, &conn.HealthStatus,
		&conn.HealthMessage, &conn.LastHealthCheck,
		&conn.CreatedAt, &conn.UpdatedAt, &conn.CreatedBy, &conn.UpdatedBy,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNPMNotConfigured, "NPM not configured for this host")
	}
	return conn, nil
}

func (r *NPMConnectionRepository) Update(ctx context.Context, conn *models.NPMConnection) error {
	conn.UpdatedAt = time.Now()
	query := `
		UPDATE npm_connections SET
			base_url = $1, admin_email = $2, admin_password_encrypted = $3,
			is_enabled = $4, updated_at = $5, updated_by = $6
		WHERE id = $7`
	_, err := r.db.Exec(ctx, query,
		conn.BaseURL, conn.AdminEmail, conn.AdminPasswordEncrypted,
		conn.IsEnabled, conn.UpdatedAt, conn.UpdatedBy, conn.ID,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update NPM connection")
	}
	return nil
}

func (r *NPMConnectionRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx, "DELETE FROM npm_connections WHERE id = $1", id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete NPM connection")
	}
	return nil
}

func (r *NPMConnectionRepository) List(ctx context.Context) ([]*models.NPMConnection, error) {
	query := `
		SELECT id, host_id, base_url, admin_email, admin_password_encrypted,
			is_enabled, health_status, health_message, last_health_check,
			created_at, updated_at, created_by, updated_by
		FROM npm_connections ORDER BY created_at DESC`
	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list NPM connections")
	}
	defer rows.Close()

	var connections []*models.NPMConnection
	for rows.Next() {
		conn := &models.NPMConnection{}
		if err := rows.Scan(
			&conn.ID, &conn.HostID, &conn.BaseURL, &conn.AdminEmail,
			&conn.AdminPasswordEncrypted, &conn.IsEnabled, &conn.HealthStatus,
			&conn.HealthMessage, &conn.LastHealthCheck,
			&conn.CreatedAt, &conn.UpdatedAt, &conn.CreatedBy, &conn.UpdatedBy,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan NPM connection")
		}
		connections = append(connections, conn)
	}
	return connections, nil
}

func (r *NPMConnectionRepository) UpdateHealthStatus(ctx context.Context, id, status, message string) error {
	now := time.Now()
	_, err := r.db.Exec(ctx,
		`UPDATE npm_connections SET health_status = $1, health_message = $2, last_health_check = $3 WHERE id = $4`,
		status, message, now, id,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update health status")
	}
	return nil
}

// =============================================================================
// ContainerProxyMappingRepository
// =============================================================================

type ContainerProxyMappingRepository struct {
	db *DB
}

func NewContainerProxyMappingRepository(db *DB) *ContainerProxyMappingRepository {
	return &ContainerProxyMappingRepository{db: db}
}

func (r *ContainerProxyMappingRepository) Create(ctx context.Context, m *models.ContainerProxyMapping) error {
	query := `
		INSERT INTO container_proxy_mappings (
			id, host_id, container_id, container_name, npm_proxy_host_id,
			auto_created, domain_source, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (host_id, container_id) DO UPDATE SET
			npm_proxy_host_id = EXCLUDED.npm_proxy_host_id,
			container_name = EXCLUDED.container_name,
			updated_at = EXCLUDED.updated_at`
	_, err := r.db.Exec(ctx, query,
		m.ID, m.HostID, m.ContainerID, m.ContainerName, m.NPMProxyHostID,
		m.AutoCreated, m.DomainSource, m.CreatedAt, m.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create container proxy mapping")
	}
	return nil
}

func (r *ContainerProxyMappingRepository) GetByContainerID(ctx context.Context, hostID, containerID string) (*models.ContainerProxyMapping, error) {
	query := `
		SELECT id, host_id, container_id, container_name, npm_proxy_host_id,
			auto_created, domain_source, created_at, updated_at
		FROM container_proxy_mappings
		WHERE host_id = $1 AND container_id = $2`
	m := &models.ContainerProxyMapping{}
	err := r.db.QueryRow(ctx, query, hostID, containerID).Scan(
		&m.ID, &m.HostID, &m.ContainerID, &m.ContainerName, &m.NPMProxyHostID,
		&m.AutoCreated, &m.DomainSource, &m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		return nil, nil // Not found is normal
	}
	return m, nil
}

func (r *ContainerProxyMappingRepository) ListByHost(ctx context.Context, hostID string) ([]*models.ContainerProxyMapping, error) {
	query := `
		SELECT id, host_id, container_id, container_name, npm_proxy_host_id,
			auto_created, domain_source, created_at, updated_at
		FROM container_proxy_mappings
		WHERE host_id = $1 ORDER BY created_at DESC`
	rows, err := r.db.Query(ctx, query, hostID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list mappings")
	}
	defer rows.Close()

	var mappings []*models.ContainerProxyMapping
	for rows.Next() {
		m := &models.ContainerProxyMapping{}
		if err := rows.Scan(
			&m.ID, &m.HostID, &m.ContainerID, &m.ContainerName, &m.NPMProxyHostID,
			&m.AutoCreated, &m.DomainSource, &m.CreatedAt, &m.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan mapping")
		}
		mappings = append(mappings, m)
	}
	return mappings, nil
}

func (r *ContainerProxyMappingRepository) Delete(ctx context.Context, hostID, containerID string) error {
	_, err := r.db.Exec(ctx,
		"DELETE FROM container_proxy_mappings WHERE host_id = $1 AND container_id = $2",
		hostID, containerID,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete mapping")
	}
	return nil
}

// =============================================================================
// NPMAuditLogRepository
// =============================================================================

type NPMAuditLogRepository struct {
	db *DB
}

func NewNPMAuditLogRepository(db *DB) *NPMAuditLogRepository {
	return &NPMAuditLogRepository{db: db}
}

func (r *NPMAuditLogRepository) Create(ctx context.Context, log *models.NPMAuditLog) error {
	detailsJSON, err := json.Marshal(log.Details)
	if err != nil {
		detailsJSON = []byte("{}")
	}
	query := `
		INSERT INTO npm_audit_log (
			id, host_id, user_id, operation, resource_type,
			resource_id, resource_name, details, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err = r.db.Exec(ctx, query,
		log.ID, log.HostID, log.UserID, log.Operation, log.ResourceType,
		log.ResourceID, log.ResourceName, detailsJSON, log.CreatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create NPM audit log")
	}
	return nil
}

func (r *NPMAuditLogRepository) ListByHost(ctx context.Context, hostID string, limit, offset int) ([]*models.NPMAuditLog, error) {
	if limit <= 0 {
		limit = 50
	}
	query := `
		SELECT id, host_id, user_id, operation, resource_type,
			resource_id, resource_name, details, created_at
		FROM npm_audit_log
		WHERE host_id = $1
		ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := r.db.Query(ctx, query, hostID, limit, offset)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list audit logs")
	}
	defer rows.Close()

	var logs []*models.NPMAuditLog
	for rows.Next() {
		l := &models.NPMAuditLog{}
		var detailsJSON []byte
		if err := rows.Scan(
			&l.ID, &l.HostID, &l.UserID, &l.Operation, &l.ResourceType,
			&l.ResourceID, &l.ResourceName, &detailsJSON, &l.CreatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan audit log")
		}
		if len(detailsJSON) > 0 {
			_ = json.Unmarshal(detailsJSON, &l.Details)
		}
		logs = append(logs, l)
	}
	return logs, nil
}

func (r *NPMAuditLogRepository) CountByHost(ctx context.Context, hostID string) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, "SELECT COUNT(*) FROM npm_audit_log WHERE host_id = $1", hostID).Scan(&count)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count audit logs")
	}
	return count, nil
}
