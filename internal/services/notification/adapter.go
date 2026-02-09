// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package notification provides the notification service for USULNET.
// Department L: Notifications - Adapter for Department J Workers
package notification

import (
	"context"
	"fmt"

	"github.com/fr4nsys/usulnet/internal/services/notification/channels"
)

// WorkerNotification matches the Notification type from workers package.
// This allows the Service to implement the NotificationService interface
// expected by the workers in Department J.
type WorkerNotification struct {
	ID         string                 `json:"id"`
	Channel    string                 `json:"channel"`
	Recipient  string                 `json:"recipient"`
	Subject    string                 `json:"subject,omitempty"`
	Message    string                 `json:"message"`
	Priority   string                 `json:"priority,omitempty"`
	Data       map[string]interface{} `json:"data,omitempty"`
	TemplateID string                 `json:"template_id,omitempty"`
}

// WorkerChannelConfig matches the ChannelConfig type from workers package.
type WorkerChannelConfig struct {
	Type     string                 `json:"type"`
	Enabled  bool                   `json:"enabled"`
	Settings map[string]interface{} `json:"settings"`
}

// WorkerBatchSendResult matches the BatchSendResult type from workers package.
type WorkerBatchSendResult struct {
	Total  int      `json:"total"`
	Sent   int      `json:"sent"`
	Failed int      `json:"failed"`
	Errors []string `json:"errors,omitempty"`
}

// ServiceAdapter wraps the notification Service to implement the
// NotificationService interface expected by Department J workers.
type ServiceAdapter struct {
	service *Service
}

// NewServiceAdapter creates a new adapter wrapping the notification service.
func NewServiceAdapter(service *Service) *ServiceAdapter {
	return &ServiceAdapter{service: service}
}

// Send implements NotificationService.Send for Department J workers.
func (a *ServiceAdapter) Send(ctx context.Context, notification *WorkerNotification) error {
	// Map worker priority to channels.Priority
	priority := mapPriority(notification.Priority)

	// Map channel name to notification type
	notifType := mapChannelToNotificationType(notification.Channel, notification.Data)

	// Build message
	msg := Message{
		Type:     notifType,
		Title:    notification.Subject,
		Body:     notification.Message,
		Priority: priority,
		Data:     notification.Data,
		Channels: []string{notification.Channel},
	}

	// Add recipient to data if present
	if notification.Recipient != "" && msg.Data != nil {
		msg.Data["recipient"] = notification.Recipient
	}

	return a.service.Send(ctx, msg)
}

// SendBatch implements NotificationService.SendBatch for Department J workers.
func (a *ServiceAdapter) SendBatch(ctx context.Context, notifications []*WorkerNotification) (*WorkerBatchSendResult, error) {
	result := &WorkerBatchSendResult{
		Total: len(notifications),
	}

	for _, notif := range notifications {
		if err := a.Send(ctx, notif); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", notif.Channel, err))
		} else {
			result.Sent++
		}
	}

	return result, nil
}

// GetChannelConfig implements NotificationService.GetChannelConfig for Department J workers.
func (a *ServiceAdapter) GetChannelConfig(ctx context.Context, channelType string) (*WorkerChannelConfig, error) {
	// Check if channel exists
	channelNames := a.service.ListChannels()
	
	for _, name := range channelNames {
		// Match by channel type
		if name == channelType {
			return &WorkerChannelConfig{
				Type:    channelType,
				Enabled: true,
				Settings: map[string]interface{}{
					"name": name,
				},
			}, nil
		}
	}

	return nil, fmt.Errorf("channel not found: %s", channelType)
}

// mapPriority converts string priority to channels.Priority.
func mapPriority(priority string) channels.Priority {
	switch priority {
	case "critical":
		return channels.PriorityCritical
	case "high", "error":
		return channels.PriorityHigh
	case "normal", "warning":
		return channels.PriorityNormal
	case "low", "info":
		return channels.PriorityLow
	default:
		return channels.PriorityNormal
	}
}

// mapChannelToNotificationType infers notification type from channel and data.
func mapChannelToNotificationType(channel string, data map[string]interface{}) channels.NotificationType {
	// Check data for hints about the notification type
	if data != nil {
		if alertType, ok := data["alert_type"].(string); ok {
			switch alertType {
			case "security":
				return channels.TypeSecurityAlert
			case "update":
				return channels.TypeUpdateAvailable
			case "backup":
				return channels.TypeBackupCompleted
			case "health":
				return channels.TypeHealthCheckFailed
			case "resource":
				return channels.TypeResourceThreshold
			}
		}

		// Check for specific data keys
		if _, ok := data["cve_id"]; ok {
			return channels.TypeCVEDetected
		}
		if _, ok := data["container_id"]; ok {
			if _, down := data["exit_code"]; down {
				return channels.TypeContainerDown
			}
		}
		if _, ok := data["host_id"]; ok {
			return channels.TypeHostOffline
		}
	}

	// Default based on channel (fallback)
	return channels.TypeSystemInfo
}

// ============================================================================
// Interface compliance helper
// ============================================================================

// Ensure ServiceAdapter implements the interface expected by workers.
// This is a compile-time check.
var _ interface {
	Send(ctx context.Context, notification *WorkerNotification) error
	SendBatch(ctx context.Context, notifications []*WorkerNotification) (*WorkerBatchSendResult, error)
	GetChannelConfig(ctx context.Context, channelType string) (*WorkerChannelConfig, error)
} = (*ServiceAdapter)(nil)
