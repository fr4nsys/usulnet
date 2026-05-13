// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package channels provides notification channel implementations.
// Department L: Notifications
package channels

import (
	"context"
	"time"
)

// Channel defines the interface for notification delivery channels.
// Each channel implementation (email, Slack, Discord, etc.) must implement this interface.
type Channel interface {
	// Name returns the unique identifier for this channel type.
	Name() string

	// Send delivers a notification message through this channel.
	// Returns an error if delivery fails.
	Send(ctx context.Context, msg RenderedMessage) error

	// Test validates the channel configuration by sending a test message.
	// Used during channel setup to verify credentials and connectivity.
	Test(ctx context.Context) error

	// IsConfigured returns true if the channel has valid configuration.
	IsConfigured() bool
}

// RenderedMessage represents a notification message ready for delivery.
// This is the output of template rendering, containing formatted content.
type RenderedMessage struct {
	// Title is the notification subject/title.
	Title string

	// Body is the main notification content.
	// May contain HTML or Markdown depending on channel capabilities.
	Body string

	// BodyPlain is a plain text version for channels that don't support formatting.
	BodyPlain string

	// Priority indicates urgency level.
	Priority Priority

	// Timestamp when the notification was created.
	Timestamp time.Time

	// Type categorizes the notification.
	Type NotificationType

	// Data contains additional structured data for rich notifications.
	Data map[string]interface{}

	// Color is an optional accent color (hex format) for supported channels.
	Color string
}

// Priority defines notification urgency levels.
type Priority int

const (
	// PriorityLow for informational notifications.
	PriorityLow Priority = iota

	// PriorityNormal for standard notifications.
	PriorityNormal

	// PriorityHigh for important notifications requiring attention.
	PriorityHigh

	// PriorityCritical for urgent notifications requiring immediate action.
	PriorityCritical
)

// String returns the string representation of Priority.
func (p Priority) String() string {
	switch p {
	case PriorityLow:
		return "low"
	case PriorityNormal:
		return "normal"
	case PriorityHigh:
		return "high"
	case PriorityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// PriorityFromString parses a priority string.
func PriorityFromString(s string) Priority {
	switch s {
	case "low":
		return PriorityLow
	case "normal":
		return PriorityNormal
	case "high":
		return PriorityHigh
	case "critical":
		return PriorityCritical
	default:
		return PriorityNormal
	}
}

// NotificationType categorizes notifications by their source/purpose.
type NotificationType string

const (
	// Security notifications
	TypeSecurityAlert    NotificationType = "security_alert"
	TypeSecurityScanDone NotificationType = "security_scan_done"
	TypeCVEDetected      NotificationType = "cve_detected"

	// Update notifications
	TypeUpdateAvailable NotificationType = "update_available"
	TypeUpdateStarted   NotificationType = "update_started"
	TypeUpdateCompleted NotificationType = "update_completed"
	TypeUpdateFailed    NotificationType = "update_failed"
	TypeUpdateRolledBack NotificationType = "update_rolled_back"

	// Backup notifications
	TypeBackupStarted   NotificationType = "backup_started"
	TypeBackupCompleted NotificationType = "backup_completed"
	TypeBackupFailed    NotificationType = "backup_failed"

	// Container notifications
	TypeContainerDown      NotificationType = "container_down"
	TypeContainerRestarted NotificationType = "container_restarted"
	TypeContainerOOM       NotificationType = "container_oom"
	TypeHealthCheckFailed  NotificationType = "healthcheck_failed"

	// Host notifications
	TypeHostOffline     NotificationType = "host_offline"
	TypeHostOnline      NotificationType = "host_online"
	TypeHostHighLoad    NotificationType = "host_high_load"
	TypeHostLowDisk     NotificationType = "host_low_disk"
	TypeAgentDisconnected NotificationType = "agent_disconnected"

	// System notifications
	TypeSystemError   NotificationType = "system_error"
	TypeSystemInfo    NotificationType = "system_info"
	TypeLicenseExpiry NotificationType = "license_expiry"
	TypeLicenseExpired NotificationType = "license_expired"
	TypeTestMessage   NotificationType = "test_message"

	// Resource notifications
	TypeResourceThreshold NotificationType = "resource_threshold"

	// Restore notifications
	TypeRestoreCompleted NotificationType = "restore_completed"
	TypeRestoreFailed    NotificationType = "restore_failed"
)

// Category returns the high-level category for this notification type.
func (t NotificationType) Category() string {
	switch t {
	case TypeSecurityAlert, TypeSecurityScanDone, TypeCVEDetected:
		return "security"
	case TypeUpdateAvailable, TypeUpdateStarted, TypeUpdateCompleted, TypeUpdateFailed, TypeUpdateRolledBack:
		return "update"
	case TypeBackupStarted, TypeBackupCompleted, TypeBackupFailed, TypeRestoreCompleted, TypeRestoreFailed:
		return "backup"
	case TypeContainerDown, TypeContainerRestarted, TypeContainerOOM, TypeHealthCheckFailed:
		return "container"
	case TypeHostOffline, TypeHostOnline, TypeHostHighLoad, TypeHostLowDisk, TypeAgentDisconnected, TypeResourceThreshold:
		return "host"
	case TypeLicenseExpiry, TypeLicenseExpired:
		return "license"
	default:
		return "system"
	}
}

// DefaultPriority returns the default priority for this notification type.
func (t NotificationType) DefaultPriority() Priority {
	switch t {
	case TypeSecurityAlert, TypeCVEDetected, TypeContainerDown, TypeHostOffline,
		TypeUpdateFailed, TypeBackupFailed, TypeRestoreFailed, TypeHealthCheckFailed, 
		TypeSystemError, TypeLicenseExpired:
		return PriorityCritical
	case TypeUpdateRolledBack, TypeContainerOOM, TypeHostHighLoad, TypeHostLowDisk,
		TypeAgentDisconnected, TypeLicenseExpiry, TypeResourceThreshold:
		return PriorityHigh
	case TypeUpdateAvailable, TypeBackupCompleted, TypeSecurityScanDone, 
		TypeRestoreCompleted:
		return PriorityNormal
	default:
		return PriorityLow
	}
}

// DefaultColor returns a color code (for Slack/Discord embeds) based on type.
func (t NotificationType) DefaultColor() string {
	switch t.DefaultPriority() {
	case PriorityCritical:
		return "#DC2626" // red-600
	case PriorityHigh:
		return "#F59E0B" // amber-500
	case PriorityNormal:
		return "#3B82F6" // blue-500
	default:
		return "#6B7280" // gray-500
	}
}

// ChannelConfig holds configuration for a specific channel instance.
type ChannelConfig struct {
	// Type identifies the channel type (email, slack, discord, webhook, telegram).
	Type string `json:"type"`

	// Name is a user-friendly name for this channel instance.
	Name string `json:"name"`

	// Enabled indicates if this channel is active.
	Enabled bool `json:"enabled"`

	// Settings contains channel-specific configuration.
	// Structure depends on channel type.
	Settings map[string]interface{} `json:"settings"`

	// NotificationTypes lists which notification types this channel should receive.
	// Empty means all types.
	NotificationTypes []NotificationType `json:"notification_types,omitempty"`

	// MinPriority is the minimum priority level to send to this channel.
	MinPriority Priority `json:"min_priority"`
}

// ShouldSend checks if a notification should be sent through this channel.
func (c *ChannelConfig) ShouldSend(notifType NotificationType, priority Priority) bool {
	if !c.Enabled {
		return false
	}

	// Check priority threshold
	if priority < c.MinPriority {
		return false
	}

	// Check notification type filter
	if len(c.NotificationTypes) > 0 {
		found := false
		for _, t := range c.NotificationTypes {
			if t == notifType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// DeliveryResult represents the outcome of sending a notification to a channel.
type DeliveryResult struct {
	// ChannelName identifies which channel was used.
	ChannelName string

	// Success indicates if delivery succeeded.
	Success bool

	// Error contains the error message if delivery failed.
	Error string

	// Timestamp when delivery was attempted.
	Timestamp time.Time

	// Duration of the delivery attempt.
	Duration time.Duration

	// ExternalID is an optional ID from the external service (e.g., message ID).
	ExternalID string
}
