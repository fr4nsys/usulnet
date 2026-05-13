// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/google/uuid"
)

// OutgoingWebhookRepository handles CRUD for outgoing webhooks.
type OutgoingWebhookRepository struct {
	db *DB
}

// NewOutgoingWebhookRepository creates a new outgoing webhook repository.
func NewOutgoingWebhookRepository(db *DB) *OutgoingWebhookRepository {
	return &OutgoingWebhookRepository{db: db}
}

// Create creates a new outgoing webhook.
func (r *OutgoingWebhookRepository) Create(ctx context.Context, wh *models.OutgoingWebhook) error {
	if wh.ID == uuid.Nil {
		wh.ID = uuid.New()
	}
	if wh.RetryCount == 0 {
		wh.RetryCount = 3
	}
	if wh.TimeoutSecs == 0 {
		wh.TimeoutSecs = 10
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO outgoing_webhooks (id, name, url, secret, events, headers, is_enabled, retry_count, timeout_secs, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		wh.ID, wh.Name, wh.URL, wh.Secret, wh.Events,
		wh.Headers, wh.IsEnabled, wh.RetryCount, wh.TimeoutSecs, wh.CreatedBy,
	)
	return err
}

// GetByID retrieves an outgoing webhook by ID.
func (r *OutgoingWebhookRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.OutgoingWebhook, error) {
	wh := &models.OutgoingWebhook{}
	err := r.db.QueryRow(ctx, `
		SELECT id, name, url, secret, events, headers, is_enabled, retry_count, timeout_secs,
			created_by, created_at, updated_at
		FROM outgoing_webhooks WHERE id = $1`, id).Scan(
		&wh.ID, &wh.Name, &wh.URL, &wh.Secret, &wh.Events,
		&wh.Headers, &wh.IsEnabled, &wh.RetryCount, &wh.TimeoutSecs,
		&wh.CreatedBy, &wh.CreatedAt, &wh.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return wh, nil
}

// List returns all outgoing webhooks.
func (r *OutgoingWebhookRepository) List(ctx context.Context) ([]*models.OutgoingWebhook, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, url, secret, events, headers, is_enabled, retry_count, timeout_secs,
			created_by, created_at, updated_at
		FROM outgoing_webhooks ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var webhooks []*models.OutgoingWebhook
	for rows.Next() {
		wh := &models.OutgoingWebhook{}
		if err := rows.Scan(
			&wh.ID, &wh.Name, &wh.URL, &wh.Secret, &wh.Events,
			&wh.Headers, &wh.IsEnabled, &wh.RetryCount, &wh.TimeoutSecs,
			&wh.CreatedBy, &wh.CreatedAt, &wh.UpdatedAt,
		); err != nil {
			return nil, err
		}
		webhooks = append(webhooks, wh)
	}
	return webhooks, nil
}

// ListEnabled returns enabled webhooks for a specific event.
func (r *OutgoingWebhookRepository) ListEnabled(ctx context.Context, event string) ([]*models.OutgoingWebhook, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, url, secret, events, headers, is_enabled, retry_count, timeout_secs,
			created_by, created_at, updated_at
		FROM outgoing_webhooks WHERE is_enabled = true AND $1 = ANY(events)`, event)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var webhooks []*models.OutgoingWebhook
	for rows.Next() {
		wh := &models.OutgoingWebhook{}
		if err := rows.Scan(
			&wh.ID, &wh.Name, &wh.URL, &wh.Secret, &wh.Events,
			&wh.Headers, &wh.IsEnabled, &wh.RetryCount, &wh.TimeoutSecs,
			&wh.CreatedBy, &wh.CreatedAt, &wh.UpdatedAt,
		); err != nil {
			return nil, err
		}
		webhooks = append(webhooks, wh)
	}
	return webhooks, nil
}

// Update updates an outgoing webhook.
func (r *OutgoingWebhookRepository) Update(ctx context.Context, wh *models.OutgoingWebhook) error {
	_, err := r.db.Exec(ctx, `
		UPDATE outgoing_webhooks SET
			name=$2, url=$3, secret=$4, events=$5, headers=$6,
			is_enabled=$7, retry_count=$8, timeout_secs=$9
		WHERE id=$1`,
		wh.ID, wh.Name, wh.URL, wh.Secret, wh.Events,
		wh.Headers, wh.IsEnabled, wh.RetryCount, wh.TimeoutSecs,
	)
	return err
}

// Delete deletes an outgoing webhook.
func (r *OutgoingWebhookRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM outgoing_webhooks WHERE id = $1`, id)
	return err
}

// CreateDelivery creates a webhook delivery record.
func (r *OutgoingWebhookRepository) CreateDelivery(ctx context.Context, d *models.WebhookDelivery) error {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	// payload JSONB bound via nullableJSONBytes (column is nullable) —
	// see encodeJSONObject in recon_repo.go for the simple-protocol rationale.
	_, err := r.db.Exec(ctx, `
		INSERT INTO webhook_deliveries (id, webhook_id, event, payload, response_code, response_body, error, duration_ms, attempt, status, delivered_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		d.ID, d.WebhookID, d.Event, nullableJSONBytes(d.Payload), d.ResponseCode,
		d.ResponseBody, d.Error, d.Duration, d.Attempt, d.Status, d.DeliveredAt,
	)
	return err
}

// UpdateDelivery updates a webhook delivery record (status, response, error, etc.).
func (r *OutgoingWebhookRepository) UpdateDelivery(ctx context.Context, d *models.WebhookDelivery) error {
	_, err := r.db.Exec(ctx, `
		UPDATE webhook_deliveries SET
			status=$2, response_code=$3, response_body=$4, error=$5,
			duration_ms=$6, attempt=$7, delivered_at=$8
		WHERE id=$1`,
		d.ID, d.Status, d.ResponseCode, d.ResponseBody, d.Error,
		d.Duration, d.Attempt, d.DeliveredAt,
	)
	return err
}

// GetDelivery retrieves a webhook delivery by ID.
func (r *OutgoingWebhookRepository) GetDelivery(ctx context.Context, id uuid.UUID) (*models.WebhookDelivery, error) {
	d := &models.WebhookDelivery{}
	err := r.db.QueryRow(ctx, `
		SELECT id, webhook_id, event, payload, response_code, response_body, error,
			duration_ms, attempt, status, delivered_at, created_at
		FROM webhook_deliveries WHERE id = $1`, id).Scan(
		&d.ID, &d.WebhookID, &d.Event, &d.Payload, &d.ResponseCode,
		&d.ResponseBody, &d.Error, &d.Duration, &d.Attempt, &d.Status, &d.DeliveredAt, &d.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// ListPendingDeliveries returns deliveries with "pending" status.
func (r *OutgoingWebhookRepository) ListPendingDeliveries(ctx context.Context, limit int) ([]*models.WebhookDelivery, error) {
	q := `SELECT id, webhook_id, event, payload, response_code, response_body, error,
		duration_ms, attempt, status, delivered_at, created_at
		FROM webhook_deliveries WHERE status = 'pending' ORDER BY created_at ASC`
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deliveries []*models.WebhookDelivery
	for rows.Next() {
		d := &models.WebhookDelivery{}
		if err := rows.Scan(
			&d.ID, &d.WebhookID, &d.Event, &d.Payload, &d.ResponseCode,
			&d.ResponseBody, &d.Error, &d.Duration, &d.Attempt, &d.Status, &d.DeliveredAt, &d.CreatedAt,
		); err != nil {
			return nil, err
		}
		deliveries = append(deliveries, d)
	}
	return deliveries, nil
}

// ListDeliveries returns webhook deliveries with filtering.
func (r *OutgoingWebhookRepository) ListDeliveries(ctx context.Context, opts models.WebhookDeliveryListOptions) ([]*models.WebhookDelivery, int64, error) {
	query := `SELECT id, webhook_id, event, payload, response_code, response_body, error, duration_ms, attempt, status, delivered_at, created_at FROM webhook_deliveries WHERE 1=1`
	countQuery := `SELECT COUNT(*) FROM webhook_deliveries WHERE 1=1`
	var args []interface{}
	argIdx := 1

	if opts.WebhookID != nil {
		clause := fmt.Sprintf(" AND webhook_id = $%d", argIdx)
		query += clause
		countQuery += clause
		args = append(args, *opts.WebhookID)
		argIdx++
	}
	if opts.Status != nil {
		clause := fmt.Sprintf(" AND status = $%d", argIdx)
		query += clause
		countQuery += clause
		args = append(args, *opts.Status)
		argIdx++
	}

	var total int64
	if err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query += " ORDER BY created_at DESC"
	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, opts.Limit)
		argIdx++
	}
	if opts.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, opts.Offset)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var deliveries []*models.WebhookDelivery
	for rows.Next() {
		d := &models.WebhookDelivery{}
		if err := rows.Scan(
			&d.ID, &d.WebhookID, &d.Event, &d.Payload, &d.ResponseCode,
			&d.ResponseBody, &d.Error, &d.Duration, &d.Attempt, &d.Status, &d.DeliveredAt, &d.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		deliveries = append(deliveries, d)
	}
	return deliveries, total, nil
}

// JobEnqueuer can enqueue background jobs for async processing.
type JobEnqueuer interface {
	EnqueueJob(ctx context.Context, input models.CreateJobInput) (*models.Job, error)
}

// WebhookDispatcher dispatches events to outgoing webhooks.
type WebhookDispatcher struct {
	repo      *OutgoingWebhookRepository
	enqueuer  JobEnqueuer
}

// NewWebhookDispatcher creates a new webhook dispatcher.
func NewWebhookDispatcher(repo *OutgoingWebhookRepository) *WebhookDispatcher {
	return &WebhookDispatcher{repo: repo}
}

// SetJobEnqueuer sets the job enqueuer for async dispatch.
func (d *WebhookDispatcher) SetJobEnqueuer(enqueuer JobEnqueuer) {
	d.enqueuer = enqueuer
}

// Dispatch sends an event to all matching enabled webhooks.
// If a job enqueuer is configured, deliveries are processed asynchronously
// via background workers. Otherwise, delivery records are created as pending.
func (d *WebhookDispatcher) Dispatch(ctx context.Context, event string, payload interface{}) error {
	webhooks, err := d.repo.ListEnabled(ctx, event)
	if err != nil {
		return err
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	for _, wh := range webhooks {
		delivery := &models.WebhookDelivery{
			WebhookID: wh.ID,
			Event:     event,
			Payload:   payloadJSON,
			Attempt:   1,
			Status:    "pending",
		}
		// Create delivery record
		if err := d.repo.CreateDelivery(ctx, delivery); err != nil {
			continue
		}

		// Enqueue dispatch job if enqueuer is available
		if d.enqueuer != nil {
			deliveryIDStr := delivery.ID.String()
			whName := wh.Name
			jobInput := models.CreateJobInput{
				Type:        models.JobTypeWebhookDispatch,
				TargetID:    &deliveryIDStr,
				TargetName:  &whName,
				Payload: models.WebhookDispatchPayload{
					DeliveryID: delivery.ID,
					WebhookID:  wh.ID,
				},
				Priority:    models.JobPriorityHigh,
				MaxAttempts: 1, // Retries are handled within the worker
			}
			d.enqueuer.EnqueueJob(ctx, jobInput)
		}
	}

	return nil
}
