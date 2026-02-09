// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// NotificationType represents the type of notification
type NotificationType string

const (
	NotificationTypeInfo     NotificationType = "info"
	NotificationTypeWarning  NotificationType = "warning"
	NotificationTypeError    NotificationType = "error"
	NotificationTypeSuccess  NotificationType = "success"
	NotificationTypeCritical NotificationType = "critical"
)

// NotificationChannel represents a notification channel
type NotificationChannel string

const (
	NotificationChannelWeb       NotificationChannel = "web"       // In-app notifications
	NotificationChannelEmail     NotificationChannel = "email"
	NotificationChannelSlack     NotificationChannel = "slack"
	NotificationChannelDiscord   NotificationChannel = "discord"
	NotificationChannelTelegram  NotificationChannel = "telegram"
	NotificationChannelWebhook   NotificationChannel = "webhook"
	NotificationChannelGotify    NotificationChannel = "gotify"
	NotificationChannelNtfy      NotificationChannel = "ntfy"
	NotificationChannelPagerDuty NotificationChannel = "pagerduty"
	NotificationChannelOpsgenie  NotificationChannel = "opsgenie"
)

// NotificationEvent represents what triggered the notification
type NotificationEvent string

const (
	// Security events
	NotificationEventSecurityScanComplete NotificationEvent = "security.scan.complete"
	NotificationEventSecurityScoreDrop    NotificationEvent = "security.score.drop"
	NotificationEventSecurityCritical     NotificationEvent = "security.critical"
	NotificationEventCVEDetected          NotificationEvent = "security.cve.detected"

	// Update events
	NotificationEventUpdateAvailable      NotificationEvent = "update.available"
	NotificationEventUpdateComplete       NotificationEvent = "update.complete"
	NotificationEventUpdateFailed         NotificationEvent = "update.failed"
	NotificationEventRollbackComplete     NotificationEvent = "update.rollback.complete"

	// Container events
	NotificationEventContainerStarted     NotificationEvent = "container.started"
	NotificationEventContainerStopped     NotificationEvent = "container.stopped"
	NotificationEventContainerFailed      NotificationEvent = "container.failed"
	NotificationEventContainerOOM         NotificationEvent = "container.oom"
	NotificationEventContainerUnhealthy   NotificationEvent = "container.unhealthy"

	// Host events
	NotificationEventHostOffline          NotificationEvent = "host.offline"
	NotificationEventHostOnline           NotificationEvent = "host.online"
	NotificationEventHostResourceCritical NotificationEvent = "host.resource.critical"

	// Backup events
	NotificationEventBackupComplete       NotificationEvent = "backup.complete"
	NotificationEventBackupFailed         NotificationEvent = "backup.failed"
	NotificationEventRestoreComplete      NotificationEvent = "restore.complete"
	NotificationEventRestoreFailed        NotificationEvent = "restore.failed"

	// System events
	NotificationEventLicenseExpiring      NotificationEvent = "license.expiring"
	NotificationEventLicenseExpired       NotificationEvent = "license.expired"
	NotificationEventSystemError          NotificationEvent = "system.error"
)

// Notification represents a notification
type Notification struct {
	ID          uuid.UUID        `json:"id" db:"id"`
	Type        NotificationType `json:"type" db:"type"`
	Event       NotificationEvent `json:"event" db:"event"`
	Title       string           `json:"title" db:"title"`
	Message     string           `json:"message" db:"message"`
	HostID      *uuid.UUID       `json:"host_id,omitempty" db:"host_id"`
	ContainerID *string          `json:"container_id,omitempty" db:"container_id"`
	EntityType  *string          `json:"entity_type,omitempty" db:"entity_type"` // container, host, backup, etc.
	EntityID    *string          `json:"entity_id,omitempty" db:"entity_id"`
	EntityName  *string          `json:"entity_name,omitempty" db:"entity_name"`
	Metadata    json.RawMessage  `json:"metadata,omitempty" db:"metadata"`
	Link        *string          `json:"link,omitempty" db:"link"` // Deep link to related entity
	IsRead      bool             `json:"is_read" db:"is_read"`
	ReadAt      *time.Time       `json:"read_at,omitempty" db:"read_at"`
	Channels    []string         `json:"channels,omitempty" db:"channels"` // Channels this was sent to
	CreatedAt   time.Time        `json:"created_at" db:"created_at"`
}

// MarkAsRead marks the notification as read
func (n *Notification) MarkAsRead() {
	n.IsRead = true
	now := time.Now()
	n.ReadAt = &now
}

// NotificationSend represents a notification send record
type NotificationSend struct {
	ID             uuid.UUID           `json:"id" db:"id"`
	NotificationID uuid.UUID           `json:"notification_id" db:"notification_id"`
	Channel        NotificationChannel `json:"channel" db:"channel"`
	Recipient      string              `json:"recipient" db:"recipient"` // Email, webhook URL, etc.
	Status         string              `json:"status" db:"status"` // pending, sent, failed
	Attempts       int                 `json:"attempts" db:"attempts"`
	LastAttemptAt  *time.Time          `json:"last_attempt_at,omitempty" db:"last_attempt_at"`
	SentAt         *time.Time          `json:"sent_at,omitempty" db:"sent_at"`
	ErrorMessage   *string             `json:"error_message,omitempty" db:"error_message"`
	ResponseCode   *int                `json:"response_code,omitempty" db:"response_code"`
	CreatedAt      time.Time           `json:"created_at" db:"created_at"`
}

// NotificationPreference represents user notification preferences
type NotificationPreference struct {
	ID         uuid.UUID           `json:"id" db:"id"`
	UserID     uuid.UUID           `json:"user_id" db:"user_id"`
	Channel    NotificationChannel `json:"channel" db:"channel"`
	Event      NotificationEvent   `json:"event" db:"event"`
	IsEnabled  bool                `json:"is_enabled" db:"is_enabled"`
	CreatedAt  time.Time           `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time           `json:"updated_at" db:"updated_at"`
}

// NotificationChannelConfig represents a notification channel configuration
type NotificationChannelConfig struct {
	ID          uuid.UUID           `json:"id" db:"id"`
	Channel     NotificationChannel `json:"channel" db:"channel"`
	Name        string              `json:"name" db:"name"`
	Config      json.RawMessage     `json:"config" db:"config"` // Channel-specific config
	IsEnabled   bool                `json:"is_enabled" db:"is_enabled"`
	IsDefault   bool                `json:"is_default" db:"is_default"`
	CreatedBy   *uuid.UUID          `json:"created_by,omitempty" db:"created_by"`
	CreatedAt   time.Time           `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at" db:"updated_at"`
}

// GetConfig unmarshals the config into the provided struct
func (c *NotificationChannelConfig) GetConfig(v interface{}) error {
	if c.Config == nil {
		return nil
	}
	return json.Unmarshal(c.Config, v)
}

// SetConfig marshals the provided struct into the config
func (c *NotificationChannelConfig) SetConfig(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.Config = data
	return nil
}

// Channel-specific configurations

// EmailConfig represents email notification configuration
type EmailConfig struct {
	SMTPHost     string   `json:"smtp_host"`
	SMTPPort     int      `json:"smtp_port"`
	SMTPUsername string   `json:"smtp_username,omitempty"`
	SMTPPassword string   `json:"-"` // Encrypted in DB
	FromAddress  string   `json:"from_address"`
	FromName     string   `json:"from_name,omitempty"`
	TLS          bool     `json:"tls"`
	StartTLS     bool     `json:"starttls"`
	Recipients   []string `json:"recipients"`
}

// SlackConfig represents Slack notification configuration
type SlackConfig struct {
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel,omitempty"`
	Username   string `json:"username,omitempty"`
	IconEmoji  string `json:"icon_emoji,omitempty"`
	IconURL    string `json:"icon_url,omitempty"`
}

// DiscordConfig represents Discord notification configuration
type DiscordConfig struct {
	WebhookURL string `json:"webhook_url"`
	Username   string `json:"username,omitempty"`
	AvatarURL  string `json:"avatar_url,omitempty"`
}

// TelegramConfig represents Telegram notification configuration
type TelegramConfig struct {
	BotToken  string   `json:"bot_token"`
	ChatIDs   []string `json:"chat_ids"`
	ParseMode string   `json:"parse_mode,omitempty"` // HTML, Markdown, MarkdownV2
}

// WebhookConfig represents generic webhook notification configuration
type WebhookConfig struct {
	URL            string            `json:"url"`
	Method         string            `json:"method,omitempty"` // POST, PUT
	Headers        map[string]string `json:"headers,omitempty"`
	AuthType       string            `json:"auth_type,omitempty"` // none, basic, bearer
	AuthUsername   string            `json:"auth_username,omitempty"`
	AuthPassword   string            `json:"-"` // Encrypted
	AuthToken      string            `json:"-"` // Encrypted
	PayloadFormat  string            `json:"payload_format,omitempty"` // json, form
	PayloadTemplate string           `json:"payload_template,omitempty"` // Go template
}

// CreateNotificationInput represents input for creating a notification
type CreateNotificationInput struct {
	Type        NotificationType  `json:"type" validate:"required,oneof=info warning error success critical"`
	Event       NotificationEvent `json:"event" validate:"required"`
	Title       string            `json:"title" validate:"required,min=1,max=255"`
	Message     string            `json:"message" validate:"required,min=1,max=2000"`
	HostID      *uuid.UUID        `json:"host_id,omitempty"`
	ContainerID *string           `json:"container_id,omitempty"`
	EntityType  *string           `json:"entity_type,omitempty"`
	EntityID    *string           `json:"entity_id,omitempty"`
	EntityName  *string           `json:"entity_name,omitempty"`
	Metadata    interface{}       `json:"metadata,omitempty"`
	Link        *string           `json:"link,omitempty"`
	Channels    []NotificationChannel `json:"channels,omitempty"`
}

// CreateChannelConfigInput represents input for creating a channel config
type CreateChannelConfigInput struct {
	Channel   NotificationChannel `json:"channel" validate:"required,oneof=email slack discord telegram webhook gotify ntfy pagerduty opsgenie"`
	Name      string              `json:"name" validate:"required,min=1,max=100"`
	Config    interface{}         `json:"config" validate:"required"`
	IsEnabled bool                `json:"is_enabled,omitempty"`
	IsDefault bool                `json:"is_default,omitempty"`
}

// UpdateChannelConfigInput represents input for updating a channel config
type UpdateChannelConfigInput struct {
	Name      *string     `json:"name,omitempty" validate:"omitempty,min=1,max=100"`
	Config    interface{} `json:"config,omitempty"`
	IsEnabled *bool       `json:"is_enabled,omitempty"`
	IsDefault *bool       `json:"is_default,omitempty"`
}

// UpdatePreferencesInput represents input for updating notification preferences
type UpdatePreferencesInput struct {
	Preferences []PreferenceUpdate `json:"preferences" validate:"required,dive"`
}

// PreferenceUpdate represents a single preference update
type PreferenceUpdate struct {
	Channel   NotificationChannel `json:"channel" validate:"required,oneof=web email slack discord telegram webhook gotify ntfy pagerduty opsgenie"`
	Event     NotificationEvent   `json:"event" validate:"required"`
	IsEnabled bool                `json:"is_enabled"`
}

// NotificationListOptions represents options for listing notifications
type NotificationListOptions struct {
	Type     *NotificationType `json:"type,omitempty"`
	Event    *NotificationEvent `json:"event,omitempty"`
	HostID   *uuid.UUID        `json:"host_id,omitempty"`
	IsRead   *bool             `json:"is_read,omitempty"`
	Before   *time.Time        `json:"before,omitempty"`
	After    *time.Time        `json:"after,omitempty"`
	Limit    int               `json:"limit,omitempty"`
	Offset   int               `json:"offset,omitempty"`
}

// NotificationStats represents notification statistics
type NotificationStats struct {
	TotalCount   int64            `json:"total_count"`
	UnreadCount  int64            `json:"unread_count"`
	ByType       map[string]int64 `json:"by_type"`
	ByEvent      map[string]int64 `json:"by_event"`
	Last24Hours  int64            `json:"last_24_hours"`
}

// TestChannelInput represents input for testing a notification channel
type TestChannelInput struct {
	ChannelConfigID uuid.UUID `json:"channel_config_id" validate:"required"`
	Message         string    `json:"message,omitempty"`
}
