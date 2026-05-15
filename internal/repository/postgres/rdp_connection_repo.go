// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// RDPConnectionRepository manages RDP connection records.
type RDPConnectionRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewRDPConnectionRepository creates a new RDPConnectionRepository.
func NewRDPConnectionRepository(db *DB, log *logger.Logger) *RDPConnectionRepository {
	return &RDPConnectionRepository{
		db:     db,
		logger: log.Named("rdp_conn_repo"),
	}
}

// Create inserts a new RDP connection.
func (r *RDPConnectionRepository) Create(ctx context.Context, conn *models.RDPConnection) error {
	conn.ID = uuid.New()
	now := time.Now()
	conn.CreatedAt = now
	conn.UpdatedAt = now
	conn.Status = models.RDPConnectionDisconnected

	if conn.Tags == nil {
		conn.Tags = []string{}
	}
	tagsJSON, err := json.Marshal(conn.Tags)
	if err != nil {
		tagsJSON = []byte("[]")
	}

	_, err = r.db.Exec(ctx, `
		INSERT INTO rdp_connections (
			id, user_id, name, host, port, username, domain, password,
			resolution, color_depth, security, tags,
			status, status_message, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		conn.ID, conn.UserID, conn.Name, conn.Host, conn.Port,
		conn.Username, conn.Domain, conn.Password,
		conn.Resolution, conn.ColorDepth, conn.Security, string(tagsJSON),
		conn.Status, conn.StatusMessage, conn.CreatedAt, conn.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create RDP connection")
	}
	return nil
}

// GetByID retrieves an RDP connection by ID.
func (r *RDPConnectionRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.RDPConnection, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, user_id, name, host, port, username, domain, password,
			resolution, color_depth, security, tags,
			status, status_message, last_checked, last_connected, created_at, updated_at
		FROM rdp_connections WHERE id = $1`, id)

	return r.scanConnection(row)
}

// ListByUser retrieves all RDP connections for a user.
func (r *RDPConnectionRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.RDPConnection, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, user_id, name, host, port, username, domain, password,
			resolution, color_depth, security, tags,
			status, status_message, last_checked, last_connected, created_at, updated_at
		FROM rdp_connections WHERE user_id = $1
		ORDER BY name ASC`, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list RDP connections")
	}
	defer rows.Close()

	var conns []*models.RDPConnection
	for rows.Next() {
		conn, err := r.scanConnectionRow(rows)
		if err != nil {
			return nil, err
		}
		conns = append(conns, conn)
	}
	return conns, nil
}

// Update updates an RDP connection.
func (r *RDPConnectionRepository) Update(ctx context.Context, id uuid.UUID, input models.UpdateRDPConnectionInput) error {
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
	if input.Username != nil {
		conn.Username = *input.Username
	}
	if input.Domain != nil {
		conn.Domain = *input.Domain
	}
	if input.Password != nil {
		conn.Password = *input.Password
	}
	if input.Resolution != nil {
		conn.Resolution = *input.Resolution
	}
	if input.ColorDepth != nil {
		conn.ColorDepth = *input.ColorDepth
	}
	if input.Security != nil {
		conn.Security = *input.Security
	}
	if input.Tags != nil {
		conn.Tags = input.Tags
	}
	if conn.Tags == nil {
		conn.Tags = []string{}
	}

	tagsJSON, _ := json.Marshal(conn.Tags)

	_, err = r.db.Exec(ctx, `
		UPDATE rdp_connections SET
			name=$1, host=$2, port=$3, username=$4, domain=$5, password=$6,
			resolution=$7, color_depth=$8, security=$9, tags=$10, updated_at=NOW()
		WHERE id = $11`,
		conn.Name, conn.Host, conn.Port, conn.Username, conn.Domain, conn.Password,
		conn.Resolution, conn.ColorDepth, conn.Security, string(tagsJSON), id,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update RDP connection")
	}
	return nil
}

// UpdateStatus updates the connection status.
func (r *RDPConnectionRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.RDPConnectionStatus, message string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE rdp_connections SET status=$1, status_message=$2, last_checked=NOW(), updated_at=NOW()
		WHERE id = $3`, status, message, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update RDP connection status")
	}
	return nil
}

// Delete removes an RDP connection.
func (r *RDPConnectionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM rdp_connections WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete RDP connection")
	}
	return nil
}

// scanConnection scans a single row into an RDPConnection.
func (r *RDPConnectionRepository) scanConnection(row pgx.Row) (*models.RDPConnection, error) {
	var conn models.RDPConnection
	var tagsJSON []byte
	err := row.Scan(
		&conn.ID, &conn.UserID, &conn.Name, &conn.Host, &conn.Port,
		&conn.Username, &conn.Domain, &conn.Password,
		&conn.Resolution, &conn.ColorDepth, &conn.Security, &tagsJSON,
		&conn.Status, &conn.StatusMessage, &conn.LastChecked, &conn.LastConnected,
		&conn.CreatedAt, &conn.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("RDP connection")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan RDP connection")
	}
	if len(tagsJSON) > 0 {
		if err := json.Unmarshal(tagsJSON, &conn.Tags); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "unmarshal tags")
		}
	}
	return &conn, nil
}

// scanConnectionRow scans a row from a rows iterator into an RDPConnection.
func (r *RDPConnectionRepository) scanConnectionRow(rows pgx.Rows) (*models.RDPConnection, error) {
	var conn models.RDPConnection
	var tagsJSON []byte
	err := rows.Scan(
		&conn.ID, &conn.UserID, &conn.Name, &conn.Host, &conn.Port,
		&conn.Username, &conn.Domain, &conn.Password,
		&conn.Resolution, &conn.ColorDepth, &conn.Security, &tagsJSON,
		&conn.Status, &conn.StatusMessage, &conn.LastChecked, &conn.LastConnected,
		&conn.CreatedAt, &conn.UpdatedAt,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan RDP connection")
	}
	if len(tagsJSON) > 0 {
		if err := json.Unmarshal(tagsJSON, &conn.Tags); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "unmarshal tags")
		}
	}
	return &conn, nil
}
