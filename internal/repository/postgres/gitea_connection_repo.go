// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
)

// GiteaConnectionRepository handles Gitea connection persistence.
type GiteaConnectionRepository struct {
	db *DB
}

// NewGiteaConnectionRepository creates a new Gitea connection repository.
func NewGiteaConnectionRepository(db *DB) *GiteaConnectionRepository {
	return &GiteaConnectionRepository{db: db}
}

const giteaConnColumns = `id, host_id, name, url, api_token_encrypted,
	webhook_secret_encrypted, status, status_message,
	last_sync_at, repos_count, auto_sync, sync_interval_minutes,
	gitea_version, created_at, updated_at, created_by`

// Create inserts a new Gitea connection.
func (r *GiteaConnectionRepository) Create(ctx context.Context, conn *models.GiteaConnection) error {
	if conn.ID == uuid.Nil {
		conn.ID = uuid.New()
	}
	now := time.Now()
	conn.CreatedAt = now
	conn.UpdatedAt = now

	query := `
		INSERT INTO gitea_connections (
			id, host_id, name, url, api_token_encrypted,
			webhook_secret_encrypted, status, status_message,
			last_sync_at, repos_count, auto_sync, sync_interval_minutes,
			gitea_version, created_at, updated_at, created_by
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`

	_, err := r.db.Exec(ctx, query,
		conn.ID, conn.HostID, conn.Name, conn.URL, conn.APITokenEncrypted,
		conn.WebhookSecretEncrypted, conn.Status, conn.StatusMessage,
		conn.LastSyncAt, conn.ReposCount, conn.AutoSync, conn.SyncIntervalMinutes,
		conn.GiteaVersion, conn.CreatedAt, conn.UpdatedAt, conn.CreatedBy,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create gitea connection")
	}
	return nil
}

// GetByID returns a Gitea connection by ID.
func (r *GiteaConnectionRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.GiteaConnection, error) {
	query := fmt.Sprintf(`SELECT %s FROM gitea_connections WHERE id = $1`, giteaConnColumns)
	row := r.db.QueryRow(ctx, query, id)
	conn, err := scanGiteaConnRow(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.New(errors.CodeNotFound, "gitea connection not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get gitea connection")
	}
	return conn, nil
}

// ListByHost returns all Gitea connections for a host.
func (r *GiteaConnectionRepository) ListByHost(ctx context.Context, hostID uuid.UUID) ([]*models.GiteaConnection, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM gitea_connections
		WHERE host_id = $1
		ORDER BY name ASC`, giteaConnColumns)

	rows, err := r.db.Query(ctx, query, hostID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list gitea connections")
	}
	defer rows.Close()

	return scanGiteaConnRows(rows)
}

// UpdateStatus updates connection status and message.
func (r *GiteaConnectionRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.GiteaConnectionStatus, message *string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE gitea_connections
		SET status = $2, status_message = $3, updated_at = NOW()
		WHERE id = $1`, id, status, message)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update gitea connection status")
	}
	return nil
}

// UpdateSyncState updates last sync time and repos count.
func (r *GiteaConnectionRepository) UpdateSyncState(ctx context.Context, id uuid.UUID, reposCount int) error {
	now := time.Now()
	_, err := r.db.Exec(ctx, `
		UPDATE gitea_connections
		SET last_sync_at = $2, repos_count = $3, updated_at = $2
		WHERE id = $1`, id, now, reposCount)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update gitea sync state")
	}
	return nil
}

// ListAll returns all Gitea connections across all hosts.
func (r *GiteaConnectionRepository) ListAll(ctx context.Context) ([]*models.GiteaConnection, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM gitea_connections
		ORDER BY name ASC`, giteaConnColumns)

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list all gitea connections")
	}
	defer rows.Close()

	return scanGiteaConnRows(rows)
}

// UpdateVersion updates the stored Gitea server version.
func (r *GiteaConnectionRepository) UpdateVersion(ctx context.Context, id uuid.UUID, version *string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE gitea_connections
		SET gitea_version = $2, updated_at = NOW()
		WHERE id = $1`, id, version)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update gitea version")
	}
	return nil
}

// Delete removes a Gitea connection (cascades to repos and webhooks).
func (r *GiteaConnectionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM gitea_connections WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete gitea connection")
	}
	if tag.RowsAffected() == 0 {
		return errors.New(errors.CodeNotFound, "gitea connection not found")
	}
	return nil
}

// ============================================================================
// Row scanners
// ============================================================================

// ListByHostScoped returns Gitea connections for a host, filtered by resource scope.
// Opt-in model: shows allowed connections OR unassigned connections.
func (r *GiteaConnectionRepository) ListByHostScoped(ctx context.Context, hostID uuid.UUID, allowedIDs, assignedIDs []uuid.UUID) ([]*models.GiteaConnection, error) {
	if len(assignedIDs) == 0 {
		// Nothing assigned → show all (no scoping)
		return r.ListByHost(ctx, hostID)
	}

	var query string
	var args []interface{}

	if len(allowedIDs) == 0 {
		// User has no allowed connections → only show unassigned
		query = fmt.Sprintf(`
			SELECT %s FROM gitea_connections
			WHERE host_id = $1 AND NOT (id = ANY($2))
			ORDER BY name ASC`, giteaConnColumns)
		args = []interface{}{hostID, assignedIDs}
	} else {
		// Show allowed OR unassigned
		query = fmt.Sprintf(`
			SELECT %s FROM gitea_connections
			WHERE host_id = $1 AND (id = ANY($2) OR NOT (id = ANY($3)))
			ORDER BY name ASC`, giteaConnColumns)
		args = []interface{}{hostID, allowedIDs, assignedIDs}
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list scoped gitea connections")
	}
	defer rows.Close()

	return scanGiteaConnRows(rows)
}

func scanGiteaConnRow(row pgx.Row) (*models.GiteaConnection, error) {
	var c models.GiteaConnection
	err := row.Scan(
		&c.ID, &c.HostID, &c.Name, &c.URL, &c.APITokenEncrypted,
		&c.WebhookSecretEncrypted, &c.Status, &c.StatusMessage,
		&c.LastSyncAt, &c.ReposCount, &c.AutoSync, &c.SyncIntervalMinutes,
		&c.GiteaVersion, &c.CreatedAt, &c.UpdatedAt, &c.CreatedBy,
	)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func scanGiteaConnRows(rows pgx.Rows) ([]*models.GiteaConnection, error) {
	var result []*models.GiteaConnection
	for rows.Next() {
		var c models.GiteaConnection
		err := rows.Scan(
			&c.ID, &c.HostID, &c.Name, &c.URL, &c.APITokenEncrypted,
			&c.WebhookSecretEncrypted, &c.Status, &c.StatusMessage,
			&c.LastSyncAt, &c.ReposCount, &c.AutoSync, &c.SyncIntervalMinutes,
			&c.GiteaVersion, &c.CreatedAt, &c.UpdatedAt, &c.CreatedBy,
		)
		if err != nil {
			return nil, err
		}
		result = append(result, &c)
	}
	return result, rows.Err()
}
