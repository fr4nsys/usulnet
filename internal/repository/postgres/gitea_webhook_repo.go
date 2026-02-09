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

// GiteaWebhookRepository handles Gitea webhook event persistence.
type GiteaWebhookRepository struct {
	db *DB
}

// NewGiteaWebhookRepository creates a new Gitea webhook repository.
func NewGiteaWebhookRepository(db *DB) *GiteaWebhookRepository {
	return &GiteaWebhookRepository{db: db}
}

const giteaWebhookColumns = `id, connection_id, repository_id, event_type,
	delivery_id, payload, processed, processed_at,
	process_result, process_error, received_at`

// Create inserts a new webhook event.
func (r *GiteaWebhookRepository) Create(ctx context.Context, evt *models.GiteaWebhookEvent) error {
	if evt.ID == uuid.Nil {
		evt.ID = uuid.New()
	}
	if evt.ReceivedAt.IsZero() {
		evt.ReceivedAt = time.Now()
	}

	query := `
		INSERT INTO gitea_webhooks (
			id, connection_id, repository_id, event_type,
			delivery_id, payload, processed, processed_at,
			process_result, process_error, received_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`

	_, err := r.db.Exec(ctx, query,
		evt.ID, evt.ConnectionID, evt.RepositoryID, evt.EventType,
		evt.DeliveryID, evt.Payload, evt.Processed, evt.ProcessedAt,
		evt.ProcessResult, evt.ProcessError, evt.ReceivedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create gitea webhook event")
	}
	return nil
}

// MarkProcessed marks a webhook event as processed.
func (r *GiteaWebhookRepository) MarkProcessed(ctx context.Context, id uuid.UUID, result, processError string) error {
	now := time.Now()
	var pErr *string
	if processError != "" {
		pErr = &processError
	}
	_, err := r.db.Exec(ctx, `
		UPDATE gitea_webhooks
		SET processed = true, processed_at = $2, process_result = $3, process_error = $4
		WHERE id = $1`, id, now, result, pErr)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to mark webhook processed")
	}
	return nil
}

// ListUnprocessed returns unprocessed webhook events.
func (r *GiteaWebhookRepository) ListUnprocessed(ctx context.Context, limit int) ([]*models.GiteaWebhookEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	query := fmt.Sprintf(`
		SELECT %s FROM gitea_webhooks
		WHERE processed = false
		ORDER BY received_at ASC
		LIMIT $1`, giteaWebhookColumns)

	rows, err := r.db.Query(ctx, query, limit)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list unprocessed webhooks")
	}
	defer rows.Close()

	return scanGiteaWebhookRows(rows)
}

// ListByConnection returns webhook events for a connection.
func (r *GiteaWebhookRepository) ListByConnection(ctx context.Context, connectionID uuid.UUID, limit int) ([]*models.GiteaWebhookEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	query := fmt.Sprintf(`
		SELECT %s FROM gitea_webhooks
		WHERE connection_id = $1
		ORDER BY received_at DESC
		LIMIT $2`, giteaWebhookColumns)

	rows, err := r.db.Query(ctx, query, connectionID, limit)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list webhooks by connection")
	}
	defer rows.Close()

	return scanGiteaWebhookRows(rows)
}

// DeleteOlderThan removes processed webhook events older than given time.
func (r *GiteaWebhookRepository) DeleteOlderThan(ctx context.Context, before time.Time) (int64, error) {
	tag, err := r.db.Exec(ctx, `
		DELETE FROM gitea_webhooks
		WHERE processed = true AND received_at < $1`, before)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to delete old webhooks")
	}
	return tag.RowsAffected(), nil
}

// ============================================================================
// Row scanners
// ============================================================================

func scanGiteaWebhookRow(row pgx.Row) (*models.GiteaWebhookEvent, error) {
	var e models.GiteaWebhookEvent
	err := row.Scan(
		&e.ID, &e.ConnectionID, &e.RepositoryID, &e.EventType,
		&e.DeliveryID, &e.Payload, &e.Processed, &e.ProcessedAt,
		&e.ProcessResult, &e.ProcessError, &e.ReceivedAt,
	)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func scanGiteaWebhookRows(rows pgx.Rows) ([]*models.GiteaWebhookEvent, error) {
	var result []*models.GiteaWebhookEvent
	for rows.Next() {
		var e models.GiteaWebhookEvent
		err := rows.Scan(
			&e.ID, &e.ConnectionID, &e.RepositoryID, &e.EventType,
			&e.DeliveryID, &e.Payload, &e.Processed, &e.ProcessedAt,
			&e.ProcessResult, &e.ProcessError, &e.ReceivedAt,
		)
		if err != nil {
			return nil, err
		}
		result = append(result, &e)
	}
	return result, rows.Err()
}
