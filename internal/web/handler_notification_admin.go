// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/services/notification/channels"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/admin"
)

// NotificationConfigRepository defines the interface for notification config storage.
type NotificationConfigRepository interface {
	SaveChannelConfig(ctx context.Context, config *channels.ChannelConfig) error
	GetChannelConfigs(ctx context.Context) ([]*channels.ChannelConfig, error)
	GetChannelConfig(ctx context.Context, name string) (*channels.ChannelConfig, error)
	DeleteChannelConfig(ctx context.Context, name string) error
}

// SetNotificationConfigRepo sets the notification config repository.
func (h *Handler) SetNotificationConfigRepo(repo NotificationConfigRepository) {
	h.notificationConfigRepo = repo
}

// NotificationChannelsTempl renders the notification channels configuration page.
func (h *Handler) NotificationChannelsTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Notification Channels", "admin")

	var channelViews []admin.ChannelView

	if h.notificationConfigRepo != nil {
		configs, err := h.notificationConfigRepo.GetChannelConfigs(r.Context())
		if err == nil {
			for _, cfg := range configs {
				var types []string
				for _, t := range cfg.NotificationTypes {
					types = append(types, string(t))
				}
				channelViews = append(channelViews, admin.ChannelView{
					Name:              cfg.Name,
					Type:              cfg.Type,
					Enabled:           cfg.Enabled,
					Settings:          cfg.Settings,
					NotificationTypes: types,
					MinPriority:       cfg.MinPriority.String(),
				})
			}
		}
	}

	data := admin.NotificationChannelsData{
		PageData: pageData,
		Channels: channelViews,
	}

	h.renderTempl(w, r, admin.NotificationChannels(data))
}

// NotificationChannelCreate creates a new notification channel.
func (h *Handler) NotificationChannelCreate(w http.ResponseWriter, r *http.Request) {
	if h.notificationConfigRepo == nil {
		h.setFlash(w, r, "error", "Notification service not configured")
		http.Redirect(w, r, "/admin/notifications/channels", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		http.Redirect(w, r, "/admin/notifications/channels", http.StatusSeeOther)
		return
	}

	channelType := strings.TrimSpace(r.FormValue("type"))
	name := strings.TrimSpace(r.FormValue("name"))
	enabled := r.FormValue("enabled") == "true"
	minPriorityStr := r.FormValue("min_priority")

	if channelType == "" || name == "" {
		h.setFlash(w, r, "error", "Type and name are required")
		http.Redirect(w, r, "/admin/notifications/channels", http.StatusSeeOther)
		return
	}

	minPriority := channels.PriorityNormal
	if p, err := strconv.Atoi(minPriorityStr); err == nil {
		minPriority = channels.Priority(p)
	}

	// Build settings based on channel type
	settings := make(map[string]interface{})

	switch channelType {
	case "email":
		recipientsStr := strings.TrimSpace(r.FormValue("email_recipients"))
		if recipientsStr != "" {
			var recipients []string
			for _, r := range strings.Split(recipientsStr, ",") {
				if email := strings.TrimSpace(r); email != "" {
					recipients = append(recipients, email)
				}
			}
			settings["recipients"] = recipients
		}

	case "slack":
		if webhook := strings.TrimSpace(r.FormValue("slack_webhook")); webhook != "" {
			settings["webhook_url"] = webhook
		}
		if channel := strings.TrimSpace(r.FormValue("slack_channel")); channel != "" {
			settings["channel"] = channel
		}

	case "discord":
		if webhook := strings.TrimSpace(r.FormValue("discord_webhook")); webhook != "" {
			settings["webhook_url"] = webhook
		}

	case "telegram":
		if token := strings.TrimSpace(r.FormValue("telegram_token")); token != "" {
			settings["bot_token"] = token
		}
		if chatID := strings.TrimSpace(r.FormValue("telegram_chat_id")); chatID != "" {
			settings["chat_id"] = chatID
		}

	case "webhook":
		if url := strings.TrimSpace(r.FormValue("webhook_url")); url != "" {
			settings["url"] = url
		}
		if method := strings.TrimSpace(r.FormValue("webhook_method")); method != "" {
			settings["method"] = method
		}
		if headersStr := strings.TrimSpace(r.FormValue("webhook_headers")); headersStr != "" {
			var headers map[string]string
			if err := json.Unmarshal([]byte(headersStr), &headers); err == nil {
				settings["headers"] = headers
			}
		}

	case "gotify":
		if serverURL := strings.TrimSpace(r.FormValue("gotify_server_url")); serverURL != "" {
			settings["server_url"] = serverURL
		}
		if appToken := strings.TrimSpace(r.FormValue("gotify_app_token")); appToken != "" {
			settings["app_token"] = appToken
		}

	case "ntfy":
		if serverURL := strings.TrimSpace(r.FormValue("ntfy_server_url")); serverURL != "" {
			settings["server_url"] = serverURL
		}
		if topic := strings.TrimSpace(r.FormValue("ntfy_topic")); topic != "" {
			settings["topic"] = topic
		}
		if accessToken := strings.TrimSpace(r.FormValue("ntfy_access_token")); accessToken != "" {
			settings["access_token"] = accessToken
		}

	case "pagerduty":
		if routingKey := strings.TrimSpace(r.FormValue("pagerduty_routing_key")); routingKey != "" {
			settings["routing_key"] = routingKey
		}
		if component := strings.TrimSpace(r.FormValue("pagerduty_component")); component != "" {
			settings["component"] = component
		}

	case "opsgenie":
		if apiKey := strings.TrimSpace(r.FormValue("opsgenie_api_key")); apiKey != "" {
			settings["api_key"] = apiKey
		}
		if baseURL := strings.TrimSpace(r.FormValue("opsgenie_api_base_url")); baseURL != "" {
			settings["api_base_url"] = baseURL
		}
	}

	config := &channels.ChannelConfig{
		Name:        name,
		Type:        channelType,
		Enabled:     enabled,
		Settings:    settings,
		MinPriority: minPriority,
	}

	if err := h.notificationConfigRepo.SaveChannelConfig(r.Context(), config); err != nil {
		h.setFlash(w, r, "error", "Failed to save channel: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Channel created successfully")
	}

	http.Redirect(w, r, "/admin/notifications/channels", http.StatusSeeOther)
}

// NotificationChannelDelete deletes a notification channel.
func (h *Handler) NotificationChannelDelete(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		h.setFlash(w, r, "error", "Channel name is required")
		http.Redirect(w, r, "/admin/notifications/channels", http.StatusSeeOther)
		return
	}

	if h.notificationConfigRepo == nil {
		h.setFlash(w, r, "error", "Notification service not configured")
		http.Redirect(w, r, "/admin/notifications/channels", http.StatusSeeOther)
		return
	}

	if err := h.notificationConfigRepo.DeleteChannelConfig(r.Context(), name); err != nil {
		h.setFlash(w, r, "error", "Failed to delete channel: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Channel deleted")
	}

	http.Redirect(w, r, "/admin/notifications/channels", http.StatusSeeOther)
}

// NotificationChannelTest sends a test notification to a channel.
func (h *Handler) NotificationChannelTest(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	w.Header().Set("Content-Type", "application/json")

	if name == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Channel name is required",
		})
		return
	}

	if h.notificationConfigRepo == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Notification service not configured",
		})
		return
	}

	// Get the channel config
	config, err := h.notificationConfigRepo.GetChannelConfig(r.Context(), name)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Channel not found",
		})
		return
	}

	// Create the channel from config and test it
	ch, err := createChannelFromConfig(config)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Failed to create channel: " + err.Error(),
		})
		return
	}

	// Actually test the channel
	if err := ch.Test(r.Context()); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Test failed: " + err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Test notification sent successfully",
	})
}

// createChannelFromConfig creates a notification channel instance from config.
func createChannelFromConfig(config *channels.ChannelConfig) (channels.Channel, error) {
	switch config.Type {
	case "email":
		return channels.NewEmailChannelFromSettings(config.Settings)
	case "slack":
		return channels.NewSlackChannelFromSettings(config.Settings)
	case "discord":
		return channels.NewDiscordChannelFromSettings(config.Settings)
	case "telegram":
		return channels.NewTelegramChannelFromSettings(config.Settings)
	case "webhook":
		return channels.NewWebhookChannelFromSettings(config.Settings)
	case "gotify":
		return channels.NewGotifyChannelFromSettings(config.Settings)
	case "ntfy":
		return channels.NewNtfyChannelFromSettings(config.Settings)
	case "pagerduty":
		return channels.NewPagerDutyChannelFromSettings(config.Settings)
	case "opsgenie":
		return channels.NewOpsgenieChannelFromSettings(config.Settings)
	default:
		return nil, fmt.Errorf("unsupported channel type: %s", config.Type)
	}
}
