// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package workers

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// NotificationService interface for sending notifications
type NotificationService interface {
	// Send sends a notification through the specified channel
	Send(ctx context.Context, notification *Notification) error

	// SendBatch sends multiple notifications
	SendBatch(ctx context.Context, notifications []*Notification) (*BatchSendResult, error)

	// GetChannelConfig gets the configuration for a notification channel
	GetChannelConfig(ctx context.Context, channelType string) (*ChannelConfig, error)
}

// Notification represents a notification to be sent
type Notification struct {
	ID          uuid.UUID              `json:"id"`
	Channel     string                 `json:"channel"` // email, slack, discord, telegram, webhook
	Recipient   string                 `json:"recipient"`
	Subject     string                 `json:"subject,omitempty"`
	Message     string                 `json:"message"`
	Priority    string                 `json:"priority,omitempty"` // low, normal, high, critical
	Data        map[string]interface{} `json:"data,omitempty"`
	TemplateID  string                 `json:"template_id,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
}

// ChannelConfig holds configuration for a notification channel
type ChannelConfig struct {
	Type      string                 `json:"type"`
	Enabled   bool                   `json:"enabled"`
	Settings  map[string]interface{} `json:"settings"`
}

// BatchSendResult holds the result of sending multiple notifications
type BatchSendResult struct {
	Total     int      `json:"total"`
	Sent      int      `json:"sent"`
	Failed    int      `json:"failed"`
	Errors    []string `json:"errors,omitempty"`
}

// NotificationWorker handles notification sending jobs
type NotificationWorker struct {
	BaseWorker
	notificationService NotificationService
	logger              *logger.Logger
}

// NotificationPayload represents payload for notification job
type NotificationPayload struct {
	Channel    string                 `json:"channel"`
	Recipient  string                 `json:"recipient"`
	Subject    string                 `json:"subject,omitempty"`
	Message    string                 `json:"message"`
	Priority   string                 `json:"priority,omitempty"`
	Data       map[string]interface{} `json:"data,omitempty"`
	TemplateID string                 `json:"template_id,omitempty"`
	// For batch sending
	Batch      []*NotificationPayload `json:"batch,omitempty"`
}

// NewNotificationWorker creates a new notification worker
func NewNotificationWorker(notificationService NotificationService, log *logger.Logger) *NotificationWorker {
	if log == nil {
		log = logger.Nop()
	}

	return &NotificationWorker{
		BaseWorker:          NewBaseWorker(models.JobType("notification")),
		notificationService: notificationService,
		logger:              log.Named("notification-worker"),
	}
}

// Execute performs the notification job
func (w *NotificationWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	log := w.logger.With("job_id", job.ID)

	// Parse payload
	var payload NotificationPayload
	if err := job.GetPayload(&payload); err != nil {
		return nil, errors.Wrap(err, errors.CodeValidation, "failed to parse payload")
	}

	// Check if batch or single
	if len(payload.Batch) > 0 {
		return w.sendBatch(ctx, job, payload.Batch, log)
	}

	return w.sendSingle(ctx, job, &payload, log)
}

func (w *NotificationWorker) sendSingle(ctx context.Context, job *models.Job, payload *NotificationPayload, log *logger.Logger) (interface{}, error) {
	// Validate
	if payload.Channel == "" {
		return nil, errors.New(errors.CodeValidation, "channel is required")
	}
	if payload.Recipient == "" {
		return nil, errors.New(errors.CodeValidation, "recipient is required")
	}
	if payload.Message == "" && payload.TemplateID == "" {
		return nil, errors.New(errors.CodeValidation, "message or template_id is required")
	}

	log.Info("sending notification",
		"channel", payload.Channel,
		"recipient", payload.Recipient,
		"priority", payload.Priority,
	)

	// Build notification
	notification := &Notification{
		ID:         job.ID,
		Channel:    payload.Channel,
		Recipient:  payload.Recipient,
		Subject:    payload.Subject,
		Message:    payload.Message,
		Priority:   payload.Priority,
		Data:       payload.Data,
		TemplateID: payload.TemplateID,
		CreatedAt:  time.Now(),
	}

	// Send
	startTime := time.Now()
	if err := w.notificationService.Send(ctx, notification); err != nil {
		return &NotificationResult{
			Success:   false,
			Channel:   payload.Channel,
			Recipient: payload.Recipient,
			Error:     err.Error(),
			SentAt:    time.Now(),
			Duration:  time.Since(startTime),
		}, nil // Return result, not error - let caller decide
	}

	result := &NotificationResult{
		Success:   true,
		Channel:   payload.Channel,
		Recipient: payload.Recipient,
		SentAt:    time.Now(),
		Duration:  time.Since(startTime),
	}

	log.Info("notification sent",
		"channel", payload.Channel,
		"recipient", payload.Recipient,
		"duration", result.Duration,
	)

	return result, nil
}

func (w *NotificationWorker) sendBatch(ctx context.Context, job *models.Job, batch []*NotificationPayload, log *logger.Logger) (interface{}, error) {
	log.Info("sending batch notifications", "count", len(batch))

	result := &BatchNotificationResult{
		Total:     len(batch),
		StartedAt: time.Now(),
		Results:   make([]*NotificationResult, 0, len(batch)),
	}

	// Convert payloads to notifications
	notifications := make([]*Notification, 0, len(batch))
	for _, p := range batch {
		if p.Channel == "" || p.Recipient == "" {
			continue
		}

		notifications = append(notifications, &Notification{
			ID:         uuid.New(),
			Channel:    p.Channel,
			Recipient:  p.Recipient,
			Subject:    p.Subject,
			Message:    p.Message,
			Priority:   p.Priority,
			Data:       p.Data,
			TemplateID: p.TemplateID,
			CreatedAt:  time.Now(),
		})
	}

	// Send batch
	batchResult, err := w.notificationService.SendBatch(ctx, notifications)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
	} else {
		result.Sent = batchResult.Sent
		result.Failed = batchResult.Failed
		result.Errors = batchResult.Errors
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)

	log.Info("batch notifications completed",
		"total", result.Total,
		"sent", result.Sent,
		"failed", result.Failed,
		"duration", result.Duration,
	)

	return result, nil
}

// NotificationResult holds the result of sending a single notification
type NotificationResult struct {
	Success   bool          `json:"success"`
	Channel   string        `json:"channel"`
	Recipient string        `json:"recipient"`
	Error     string        `json:"error,omitempty"`
	SentAt    time.Time     `json:"sent_at"`
	Duration  time.Duration `json:"duration"`
}

// BatchNotificationResult holds the result of sending batch notifications
type BatchNotificationResult struct {
	Total       int                   `json:"total"`
	Sent        int                   `json:"sent"`
	Failed      int                   `json:"failed"`
	StartedAt   time.Time             `json:"started_at"`
	CompletedAt time.Time             `json:"completed_at"`
	Duration    time.Duration         `json:"duration"`
	Results     []*NotificationResult `json:"results,omitempty"`
	Errors      []string              `json:"errors,omitempty"`
}

// ============================================================================
// Alert Notification Worker - specialized for system alerts
// ============================================================================

// AlertWorker handles alert notifications (security issues, update failures, etc.)
type AlertWorker struct {
	BaseWorker
	notificationService NotificationService
	logger              *logger.Logger
}

// AlertPayload represents payload for alert notification
type AlertPayload struct {
	AlertType   string                 `json:"alert_type"` // security, update, backup, health, resource
	Severity    string                 `json:"severity"`   // info, warning, error, critical
	Title       string                 `json:"title"`
	Message     string                 `json:"message"`
	HostID      *uuid.UUID             `json:"host_id,omitempty"`
	ContainerID string                 `json:"container_id,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
	Channels    []string               `json:"channels,omitempty"` // Override default channels
}

// NewAlertWorker creates a new alert worker
func NewAlertWorker(notificationService NotificationService, log *logger.Logger) *AlertWorker {
	if log == nil {
		log = logger.Nop()
	}

	return &AlertWorker{
		BaseWorker:          NewBaseWorker(models.JobType("alert")),
		notificationService: notificationService,
		logger:              log.Named("alert-worker"),
	}
}

// Execute performs the alert notification job
func (w *AlertWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	log := w.logger.With("job_id", job.ID)

	// Parse payload
	var payload AlertPayload
	if err := job.GetPayload(&payload); err != nil {
		return nil, errors.Wrap(err, errors.CodeValidation, "failed to parse payload")
	}

	// Validate
	if payload.AlertType == "" {
		return nil, errors.New(errors.CodeValidation, "alert_type is required")
	}
	if payload.Title == "" && payload.Message == "" {
		return nil, errors.New(errors.CodeValidation, "title or message is required")
	}

	log.Info("processing alert",
		"alert_type", payload.AlertType,
		"severity", payload.Severity,
	)

	result := &AlertResult{
		AlertType: payload.AlertType,
		Severity:  payload.Severity,
		StartedAt: time.Now(),
		Channels:  make(map[string]bool),
	}

	// Determine channels to notify
	channels := payload.Channels
	if len(channels) == 0 {
		// Default channels based on severity
		channels = w.getDefaultChannels(payload.Severity)
	}

	// Build notification data
	data := payload.Data
	if data == nil {
		data = make(map[string]interface{})
	}
	data["alert_type"] = payload.AlertType
	data["severity"] = payload.Severity
	if payload.HostID != nil {
		data["host_id"] = payload.HostID.String()
	}
	if payload.ContainerID != "" {
		data["container_id"] = payload.ContainerID
	}

	// Send to each channel
	for _, channel := range channels {
		// Get channel config
		config, err := w.notificationService.GetChannelConfig(ctx, channel)
		if err != nil {
			log.Warn("channel not configured", "channel", channel, "error", err)
			result.Channels[channel] = false
			continue
		}

		if !config.Enabled {
			log.Debug("channel disabled", "channel", channel)
			result.Channels[channel] = false
			continue
		}

		// Send notification
		notification := &Notification{
			ID:        uuid.New(),
			Channel:   channel,
			Subject:   payload.Title,
			Message:   payload.Message,
			Priority:  payload.Severity,
			Data:      data,
			CreatedAt: time.Now(),
		}

		if err := w.notificationService.Send(ctx, notification); err != nil {
			log.Error("failed to send alert", "channel", channel, "error", err)
			result.Channels[channel] = false
			result.Errors = append(result.Errors, channel+": "+err.Error())
		} else {
			result.Channels[channel] = true
			result.ChannelsSent++
		}
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)

	log.Info("alert processed",
		"channels_sent", result.ChannelsSent,
		"duration", result.Duration,
	)

	return result, nil
}

func (w *AlertWorker) getDefaultChannels(severity string) []string {
	switch severity {
	case "critical":
		return []string{"email", "slack", "discord", "telegram"}
	case "error":
		return []string{"email", "slack"}
	case "warning":
		return []string{"slack"}
	default:
		return []string{"slack"}
	}
}

// AlertResult holds the result of an alert notification job
type AlertResult struct {
	AlertType    string          `json:"alert_type"`
	Severity     string          `json:"severity"`
	StartedAt    time.Time       `json:"started_at"`
	CompletedAt  time.Time       `json:"completed_at"`
	Duration     time.Duration   `json:"duration"`
	Channels     map[string]bool `json:"channels"`
	ChannelsSent int             `json:"channels_sent"`
	Errors       []string        `json:"errors,omitempty"`
}
