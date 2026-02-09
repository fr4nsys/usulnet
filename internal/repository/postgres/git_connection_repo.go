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

// GitConnectionRepository handles Git connection persistence (Gitea, GitHub, GitLab).
type GitConnectionRepository struct {
	db *DB
}

// NewGitConnectionRepository creates a new Git connection repository.
func NewGitConnectionRepository(db *DB) *GitConnectionRepository {
	return &GitConnectionRepository{db: db}
}

const gitConnColumns = `id, host_id, provider_type, name, url, api_token_encrypted,
	webhook_secret_encrypted, status, status_message,
	last_sync_at, repos_count, auto_sync, sync_interval_minutes,
	gitea_version, created_at, updated_at, created_by`

// Create inserts a new Git connection.
func (r *GitConnectionRepository) Create(ctx context.Context, conn *models.GitConnection) error {
	if conn.ID == uuid.Nil {
		conn.ID = uuid.New()
	}
	now := time.Now()
	conn.CreatedAt = now
	conn.UpdatedAt = now

	// Default to gitea if not specified
	if conn.ProviderType == "" {
		conn.ProviderType = models.GitProviderGitea
	}

	query := `
		INSERT INTO gitea_connections (
			id, host_id, provider_type, name, url, api_token_encrypted,
			webhook_secret_encrypted, status, status_message,
			last_sync_at, repos_count, auto_sync, sync_interval_minutes,
			gitea_version, created_at, updated_at, created_by
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`

	_, err := r.db.Exec(ctx, query,
		conn.ID, conn.HostID, conn.ProviderType, conn.Name, conn.URL, conn.APITokenEncrypted,
		conn.WebhookSecretEncrypted, conn.Status, conn.StatusMessage,
		conn.LastSyncAt, conn.ReposCount, conn.AutoSync, conn.SyncIntervalMinutes,
		conn.ProviderVersion, conn.CreatedAt, conn.UpdatedAt, conn.CreatedBy,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create git connection")
	}
	return nil
}

// GetByID returns a Git connection by ID.
func (r *GitConnectionRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.GitConnection, error) {
	query := fmt.Sprintf(`SELECT %s FROM gitea_connections WHERE id = $1`, gitConnColumns)
	row := r.db.QueryRow(ctx, query, id)
	conn, err := scanGitConnRow(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.New(errors.CodeNotFound, "git connection not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get git connection")
	}
	return conn, nil
}

// ListByHost returns all Git connections for a host.
func (r *GitConnectionRepository) ListByHost(ctx context.Context, hostID uuid.UUID) ([]*models.GitConnection, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM gitea_connections
		WHERE host_id = $1
		ORDER BY provider_type, name ASC`, gitConnColumns)

	rows, err := r.db.Query(ctx, query, hostID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list git connections")
	}
	defer rows.Close()

	return scanGitConnRows(rows)
}

// CountAll returns the total number of Git connections across all hosts.
func (r *GitConnectionRepository) CountAll(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM gitea_connections`).Scan(&count)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count git connections")
	}
	return count, nil
}

// ListByHostAndProvider returns Git connections for a host filtered by provider type.
func (r *GitConnectionRepository) ListByHostAndProvider(ctx context.Context, hostID uuid.UUID, providerType models.GitProviderType) ([]*models.GitConnection, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM gitea_connections
		WHERE host_id = $1 AND provider_type = $2
		ORDER BY name ASC`, gitConnColumns)

	rows, err := r.db.Query(ctx, query, hostID, providerType)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list git connections by provider")
	}
	defer rows.Close()

	return scanGitConnRows(rows)
}

// ListAll returns all Git connections across all hosts.
func (r *GitConnectionRepository) ListAll(ctx context.Context) ([]*models.GitConnection, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM gitea_connections
		ORDER BY provider_type, name ASC`, gitConnColumns)

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list all git connections")
	}
	defer rows.Close()

	return scanGitConnRows(rows)
}

// UpdateStatus updates connection status and message.
func (r *GitConnectionRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.GitConnectionStatus, message *string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE gitea_connections
		SET status = $2, status_message = $3, updated_at = NOW()
		WHERE id = $1`, id, status, message)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update git connection status")
	}
	return nil
}

// UpdateSyncState updates last sync time and repos count.
func (r *GitConnectionRepository) UpdateSyncState(ctx context.Context, id uuid.UUID, reposCount int) error {
	now := time.Now()
	_, err := r.db.Exec(ctx, `
		UPDATE gitea_connections
		SET last_sync_at = $2, repos_count = $3, updated_at = $2
		WHERE id = $1`, id, now, reposCount)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update git sync state")
	}
	return nil
}

// UpdateVersion updates the stored provider version.
func (r *GitConnectionRepository) UpdateVersion(ctx context.Context, id uuid.UUID, version *string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE gitea_connections
		SET gitea_version = $2, updated_at = NOW()
		WHERE id = $1`, id, version)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update git provider version")
	}
	return nil
}

// Delete removes a Git connection (cascades to repos and webhooks).
func (r *GitConnectionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM gitea_connections WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete git connection")
	}
	if tag.RowsAffected() == 0 {
		return errors.New(errors.CodeNotFound, "git connection not found")
	}
	return nil
}

// Update updates an existing Git connection.
func (r *GitConnectionRepository) Update(ctx context.Context, conn *models.GitConnection) error {
	conn.UpdatedAt = time.Now()

	query := `
		UPDATE gitea_connections
		SET name = $2, url = $3, api_token_encrypted = $4,
			webhook_secret_encrypted = $5, auto_sync = $6,
			sync_interval_minutes = $7, updated_at = $8
		WHERE id = $1`

	tag, err := r.db.Exec(ctx, query,
		conn.ID, conn.Name, conn.URL, conn.APITokenEncrypted,
		conn.WebhookSecretEncrypted, conn.AutoSync, conn.SyncIntervalMinutes,
		conn.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update git connection")
	}
	if tag.RowsAffected() == 0 {
		return errors.New(errors.CodeNotFound, "git connection not found")
	}
	return nil
}

// Stats returns aggregated statistics for git connections.
type GitConnectionStats struct {
	TotalConnections  int
	ActiveConnections int
	TotalRepos        int
	ByProvider        map[models.GitProviderType]int
}

// GetStats returns statistics for all git connections.
func (r *GitConnectionRepository) GetStats(ctx context.Context) (*GitConnectionStats, error) {
	stats := &GitConnectionStats{
		ByProvider: make(map[models.GitProviderType]int),
	}

	// Total and active connections
	err := r.db.QueryRow(ctx, `
		SELECT 
			COUNT(*),
			COUNT(*) FILTER (WHERE status = 'connected'),
			COALESCE(SUM(repos_count), 0)
		FROM gitea_connections`).Scan(&stats.TotalConnections, &stats.ActiveConnections, &stats.TotalRepos)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get git connection stats")
	}

	// By provider
	rows, err := r.db.Query(ctx, `
		SELECT provider_type, COUNT(*) 
		FROM gitea_connections 
		GROUP BY provider_type`)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get git provider stats")
	}
	defer rows.Close()

	for rows.Next() {
		var providerType models.GitProviderType
		var count int
		if err := rows.Scan(&providerType, &count); err != nil {
			return nil, err
		}
		stats.ByProvider[providerType] = count
	}

	return stats, nil
}

// ============================================================================
// Row scanners
// ============================================================================

func scanGitConnRow(row pgx.Row) (*models.GitConnection, error) {
	var c models.GitConnection
	err := row.Scan(
		&c.ID, &c.HostID, &c.ProviderType, &c.Name, &c.URL, &c.APITokenEncrypted,
		&c.WebhookSecretEncrypted, &c.Status, &c.StatusMessage,
		&c.LastSyncAt, &c.ReposCount, &c.AutoSync, &c.SyncIntervalMinutes,
		&c.ProviderVersion, &c.CreatedAt, &c.UpdatedAt, &c.CreatedBy,
	)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func scanGitConnRows(rows pgx.Rows) ([]*models.GitConnection, error) {
	var result []*models.GitConnection
	for rows.Next() {
		var c models.GitConnection
		err := rows.Scan(
			&c.ID, &c.HostID, &c.ProviderType, &c.Name, &c.URL, &c.APITokenEncrypted,
			&c.WebhookSecretEncrypted, &c.Status, &c.StatusMessage,
			&c.LastSyncAt, &c.ReposCount, &c.AutoSync, &c.SyncIntervalMinutes,
			&c.ProviderVersion, &c.CreatedAt, &c.UpdatedAt, &c.CreatedBy,
		)
		if err != nil {
			return nil, err
		}
		result = append(result, &c)
	}
	return result, rows.Err()
}
