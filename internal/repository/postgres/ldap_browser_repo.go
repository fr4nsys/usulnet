// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// LDAPBrowserRepository manages LDAP browser connection records.
type LDAPBrowserRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewLDAPBrowserRepository creates a new LDAPBrowserRepository.
func NewLDAPBrowserRepository(db *DB, log *logger.Logger) *LDAPBrowserRepository {
	return &LDAPBrowserRepository{
		db:     db,
		logger: log.Named("ldap_browser_repo"),
	}
}

// Create inserts a new LDAP connection.
func (r *LDAPBrowserRepository) Create(ctx context.Context, conn *models.LDAPConnection) error {
	conn.ID = uuid.New()
	now := time.Now()
	conn.CreatedAt = now
	conn.UpdatedAt = now
	conn.Status = models.LDAPStatusDisconnected

	_, err := r.db.Exec(ctx, `
		INSERT INTO ldap_browser_connections (
			id, user_id, name, host, port, use_tls, start_tls, skip_tls_verify,
			bind_dn, bind_password, base_dn, status, status_message, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		conn.ID, conn.UserID, conn.Name, conn.Host, conn.Port, conn.UseTLS,
		conn.StartTLS, conn.SkipTLSVerify, conn.BindDN, conn.BindPassword,
		conn.BaseDN, conn.Status, conn.StatusMessage, conn.CreatedAt, conn.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create LDAP connection")
	}
	return nil
}

// GetByID retrieves an LDAP connection by ID.
func (r *LDAPBrowserRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.LDAPConnection, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, user_id, name, host, port, use_tls, start_tls, skip_tls_verify,
			bind_dn, bind_password, base_dn, status, status_message,
			last_checked, last_connected_at, created_at, updated_at
		FROM ldap_browser_connections WHERE id = $1`, id)

	var conn models.LDAPConnection
	err := row.Scan(
		&conn.ID, &conn.UserID, &conn.Name, &conn.Host, &conn.Port, &conn.UseTLS,
		&conn.StartTLS, &conn.SkipTLSVerify, &conn.BindDN, &conn.BindPassword,
		&conn.BaseDN, &conn.Status, &conn.StatusMessage,
		&conn.LastChecked, &conn.LastConnectedAt, &conn.CreatedAt, &conn.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("LDAP connection")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan LDAP connection")
	}

	return &conn, nil
}

// ListByUser retrieves all LDAP connections for a user.
func (r *LDAPBrowserRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.LDAPConnection, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, user_id, name, host, port, use_tls, start_tls, skip_tls_verify,
			bind_dn, bind_password, base_dn, status, status_message,
			last_checked, last_connected_at, created_at, updated_at
		FROM ldap_browser_connections WHERE user_id = $1
		ORDER BY name ASC`, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list LDAP connections")
	}
	defer rows.Close()

	var conns []*models.LDAPConnection
	for rows.Next() {
		var conn models.LDAPConnection
		err := rows.Scan(
			&conn.ID, &conn.UserID, &conn.Name, &conn.Host, &conn.Port, &conn.UseTLS,
			&conn.StartTLS, &conn.SkipTLSVerify, &conn.BindDN, &conn.BindPassword,
			&conn.BaseDN, &conn.Status, &conn.StatusMessage,
			&conn.LastChecked, &conn.LastConnectedAt, &conn.CreatedAt, &conn.UpdatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan LDAP connection")
		}
		conns = append(conns, &conn)
	}

	return conns, nil
}

// Update updates an LDAP connection.
func (r *LDAPBrowserRepository) Update(ctx context.Context, id uuid.UUID, input models.UpdateLDAPConnectionInput) error {
	conn, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if input.Name != nil {
		conn.Name = *input.Name
	}
	if input.Host != nil {
		conn.Host = *input.Host
	}
	if input.Port != nil {
		conn.Port = *input.Port
	}
	if input.UseTLS != nil {
		conn.UseTLS = *input.UseTLS
	}
	if input.StartTLS != nil {
		conn.StartTLS = *input.StartTLS
	}
	if input.SkipTLSVerify != nil {
		conn.SkipTLSVerify = *input.SkipTLSVerify
	}
	if input.BindDN != nil {
		conn.BindDN = *input.BindDN
	}
	if input.BindPassword != nil {
		conn.BindPassword = *input.BindPassword
	}
	if input.BaseDN != nil {
		conn.BaseDN = *input.BaseDN
	}

	conn.UpdatedAt = time.Now()

	_, err = r.db.Exec(ctx, `
		UPDATE ldap_browser_connections SET
			name=$2, host=$3, port=$4, use_tls=$5, start_tls=$6, skip_tls_verify=$7,
			bind_dn=$8, bind_password=$9, base_dn=$10, updated_at=$11
		WHERE id = $1`,
		conn.ID, conn.Name, conn.Host, conn.Port, conn.UseTLS, conn.StartTLS,
		conn.SkipTLSVerify, conn.BindDN, conn.BindPassword, conn.BaseDN, conn.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update LDAP connection")
	}
	return nil
}

// UpdateStatus updates the connection status.
func (r *LDAPBrowserRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.LDAPConnectionStatus, message string) error {
	now := time.Now()
	var lastConnected *time.Time
	if status == models.LDAPStatusConnected {
		lastConnected = &now
	}

	_, err := r.db.Exec(ctx, `
		UPDATE ldap_browser_connections SET
			status=$2, status_message=$3, last_checked=$4, last_connected_at=COALESCE($5, last_connected_at), updated_at=$4
		WHERE id = $1`,
		id, status, message, now, lastConnected,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update connection status")
	}
	return nil
}

// Delete removes an LDAP connection.
func (r *LDAPBrowserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	result, err := r.db.Exec(ctx, `DELETE FROM ldap_browser_connections WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete LDAP connection")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("LDAP connection")
	}
	return nil
}
