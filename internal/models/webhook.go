// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// OutgoingWebhook represents a configured outgoing webhook endpoint.
type OutgoingWebhook struct {
	ID          uuid.UUID       `json:"id" db:"id"`
	Name        string          `json:"name" db:"name"`
	URL         string          `json:"url" db:"url"`
	Secret      *string         `json:"-" db:"secret"` // HMAC signing secret
	Events      []string        `json:"events" db:"events"`
	Headers     json.RawMessage `json:"headers,omitempty" db:"headers"`
	IsEnabled   bool            `json:"is_enabled" db:"is_enabled"`
	RetryCount  int             `json:"retry_count" db:"retry_count"`
	TimeoutSecs int             `json:"timeout_secs" db:"timeout_secs"`
	CreatedBy   *uuid.UUID      `json:"created_by,omitempty" db:"created_by"`
	CreatedAt   time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at" db:"updated_at"`
}

// WebhookDelivery represents a single delivery attempt for an outgoing webhook.
type WebhookDelivery struct {
	ID           uuid.UUID       `json:"id" db:"id"`
	WebhookID    uuid.UUID       `json:"webhook_id" db:"webhook_id"`
	Event        string          `json:"event" db:"event"`
	Payload      json.RawMessage `json:"payload" db:"payload"`
	ResponseCode *int            `json:"response_code,omitempty" db:"response_code"`
	ResponseBody *string         `json:"response_body,omitempty" db:"response_body"`
	Error        *string         `json:"error,omitempty" db:"error"`
	Duration     int             `json:"duration_ms" db:"duration_ms"`
	Attempt      int             `json:"attempt" db:"attempt"`
	Status       string          `json:"status" db:"status"` // pending, success, failed
	DeliveredAt  *time.Time      `json:"delivered_at,omitempty" db:"delivered_at"`
	CreatedAt    time.Time       `json:"created_at" db:"created_at"`
}

// CreateOutgoingWebhookInput represents input for creating an outgoing webhook.
type CreateOutgoingWebhookInput struct {
	Name        string            `json:"name" validate:"required,min=1,max=255"`
	URL         string            `json:"url" validate:"required,url"`
	Secret      *string           `json:"secret,omitempty"`
	Events      []string          `json:"events" validate:"required,min=1"`
	Headers     map[string]string `json:"headers,omitempty"`
	IsEnabled   bool              `json:"is_enabled"`
	RetryCount  int               `json:"retry_count,omitempty" validate:"min=0,max=10"`
	TimeoutSecs int               `json:"timeout_secs,omitempty" validate:"min=1,max=60"`
}

// UpdateOutgoingWebhookInput represents input for updating an outgoing webhook.
type UpdateOutgoingWebhookInput struct {
	Name        *string           `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	URL         *string           `json:"url,omitempty" validate:"omitempty,url"`
	Secret      *string           `json:"secret,omitempty"`
	Events      []string          `json:"events,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	IsEnabled   *bool             `json:"is_enabled,omitempty"`
	RetryCount  *int              `json:"retry_count,omitempty"`
	TimeoutSecs *int              `json:"timeout_secs,omitempty"`
}

// WebhookDeliveryListOptions represents options for listing deliveries.
type WebhookDeliveryListOptions struct {
	WebhookID *uuid.UUID `json:"webhook_id,omitempty"`
	Event     *string    `json:"event,omitempty"`
	Status    *string    `json:"status,omitempty"`
	Limit     int        `json:"limit,omitempty"`
	Offset    int        `json:"offset,omitempty"`
}

// AutoDeployRule represents a rule for automatic deployment from webhooks.
type AutoDeployRule struct {
	ID             uuid.UUID `json:"id" db:"id"`
	Name           string    `json:"name" db:"name"`
	SourceType     string    `json:"source_type" db:"source_type"` // gitea, github, dockerhub
	SourceRepo     string    `json:"source_repo" db:"source_repo"`
	SourceBranch   *string   `json:"source_branch,omitempty" db:"source_branch"`
	TargetStackID  *string   `json:"target_stack_id,omitempty" db:"target_stack_id"`
	TargetService  *string   `json:"target_service,omitempty" db:"target_service"`
	Action         string    `json:"action" db:"action"` // redeploy, pull_and_redeploy, update_image
	IsEnabled      bool      `json:"is_enabled" db:"is_enabled"`
	LastTriggeredAt *time.Time `json:"last_triggered_at,omitempty" db:"last_triggered_at"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
}
