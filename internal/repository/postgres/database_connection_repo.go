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

// DatabaseConnectionRepository manages database connection records.
type DatabaseConnectionRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewDatabaseConnectionRepository creates a new DatabaseConnectionRepository.
func NewDatabaseConnectionRepository(db *DB, log *logger.Logger) *DatabaseConnectionRepository {
	return &DatabaseConnectionRepository{
		db:     db,
		logger: log.Named("db_conn_repo"),
	}
}

// Create inserts a new database connection.
func (r *DatabaseConnectionRepository) Create(ctx context.Context, conn *models.DatabaseConnection) error {
	conn.ID = uuid.New()
	now := time.Now()
	conn.CreatedAt = now
	conn.UpdatedAt = now
	conn.Status = models.DatabaseStatusDisconnected

	optionsJSON, err := json.Marshal(conn.Options)
	if err != nil {
		optionsJSON = []byte("{}")
	}

	_, err = r.db.Exec(ctx, `
		INSERT INTO database_connections (
			id, user_id, name, type, host, port, database, username, password,
			ssl, ssl_mode, ca_cert, client_cert, client_key, options,
			status, status_message, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		conn.ID, conn.UserID, conn.Name, conn.Type, conn.Host, conn.Port,
		conn.Database, conn.Username, conn.Password, conn.SSL, conn.SSLMode,
		conn.CACert, conn.ClientCert, conn.ClientKey, optionsJSON,
		conn.Status, conn.StatusMessage, conn.CreatedAt, conn.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create database connection")
	}
	return nil
}

// GetByID retrieves a database connection by ID.
func (r *DatabaseConnectionRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.DatabaseConnection, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, user_id, name, type, host, port, database, username, password,
			ssl, ssl_mode, ca_cert, client_cert, client_key, options,
			status, status_message, last_checked, last_connected_at, created_at, updated_at
		FROM database_connections WHERE id = $1`, id)

	var conn models.DatabaseConnection
	var optionsJSON []byte
	err := row.Scan(
		&conn.ID, &conn.UserID, &conn.Name, &conn.Type, &conn.Host, &conn.Port,
		&conn.Database, &conn.Username, &conn.Password, &conn.SSL, &conn.SSLMode,
		&conn.CACert, &conn.ClientCert, &conn.ClientKey, &optionsJSON,
		&conn.Status, &conn.StatusMessage, &conn.LastChecked, &conn.LastConnectedAt,
		&conn.CreatedAt, &conn.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("database connection")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan database connection")
	}

	if len(optionsJSON) > 0 {
		json.Unmarshal(optionsJSON, &conn.Options)
	}

	return &conn, nil
}

// ListByUser retrieves all database connections for a user.
func (r *DatabaseConnectionRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.DatabaseConnection, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, user_id, name, type, host, port, database, username, password,
			ssl, ssl_mode, ca_cert, client_cert, client_key, options,
			status, status_message, last_checked, last_connected_at, created_at, updated_at
		FROM database_connections WHERE user_id = $1
		ORDER BY name ASC`, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list database connections")
	}
	defer rows.Close()

	var conns []*models.DatabaseConnection
	for rows.Next() {
		var conn models.DatabaseConnection
		var optionsJSON []byte
		err := rows.Scan(
			&conn.ID, &conn.UserID, &conn.Name, &conn.Type, &conn.Host, &conn.Port,
			&conn.Database, &conn.Username, &conn.Password, &conn.SSL, &conn.SSLMode,
			&conn.CACert, &conn.ClientCert, &conn.ClientKey, &optionsJSON,
			&conn.Status, &conn.StatusMessage, &conn.LastChecked, &conn.LastConnectedAt,
			&conn.CreatedAt, &conn.UpdatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan database connection")
		}
		if len(optionsJSON) > 0 {
			json.Unmarshal(optionsJSON, &conn.Options)
		}
		conns = append(conns, &conn)
	}

	return conns, nil
}

// Update updates a database connection.
func (r *DatabaseConnectionRepository) Update(ctx context.Context, id uuid.UUID, input models.UpdateDatabaseConnectionInput) error {
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
	if input.Database != nil {
		conn.Database = *input.Database
	}
	if input.Username != nil {
		conn.Username = *input.Username
	}
	if input.Password != nil {
		conn.Password = *input.Password
	}
	if input.SSL != nil {
		conn.SSL = *input.SSL
	}
	if input.SSLMode != nil {
		conn.SSLMode = *input.SSLMode
	}
	if input.CACert != nil {
		conn.CACert = *input.CACert
	}
	if input.ClientCert != nil {
		conn.ClientCert = *input.ClientCert
	}
	if input.ClientKey != nil {
		conn.ClientKey = *input.ClientKey
	}
	if input.Options != nil {
		conn.Options = input.Options
	}

	conn.UpdatedAt = time.Now()

	optionsJSON, _ := json.Marshal(conn.Options)

	_, err = r.db.Exec(ctx, `
		UPDATE database_connections SET
			name=$2, host=$3, port=$4, database=$5, username=$6, password=$7,
			ssl=$8, ssl_mode=$9, ca_cert=$10, client_cert=$11, client_key=$12,
			options=$13, updated_at=$14
		WHERE id = $1`,
		conn.ID, conn.Name, conn.Host, conn.Port, conn.Database, conn.Username,
		conn.Password, conn.SSL, conn.SSLMode, conn.CACert, conn.ClientCert,
		conn.ClientKey, optionsJSON, conn.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update database connection")
	}
	return nil
}

// UpdateStatus updates the connection status.
func (r *DatabaseConnectionRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.DatabaseConnectionStatus, message string) error {
	now := time.Now()
	var lastConnected *time.Time
	if status == models.DatabaseStatusConnected {
		lastConnected = &now
	}

	_, err := r.db.Exec(ctx, `
		UPDATE database_connections SET
			status=$2, status_message=$3, last_checked=$4, last_connected_at=COALESCE($5, last_connected_at), updated_at=$4
		WHERE id = $1`,
		id, status, message, now, lastConnected,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update connection status")
	}
	return nil
}

// Delete removes a database connection.
func (r *DatabaseConnectionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	result, err := r.db.Exec(ctx, `DELETE FROM database_connections WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete database connection")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("database connection")
	}
	return nil
}
