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

// NotificationChannelsTempl renders the notification channels configuration page.
func (h *Handler) NotificationChannelsTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Notification Channels", "notification-channels")

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

// NotificationChannelCreate creates or updates a notification channel.
// notificationChannelForm captures the "core" channel inputs. The
// per-backend settings (email_*, slack_*, etc.) stay read via
// parseChannelSettings because the field set depends on the
// selected `type` — a single struct DTO would have to enumerate
// every possible field across every backend.
type notificationChannelForm struct {
	Type        string `form:"type" validate:"required"`
	Name        string `form:"name" validate:"required"`
	Enabled     bool   `form:"enabled"`
	MinPriority int    `form:"min_priority"`
	EditMode    bool   `form:"edit_mode"`
}

func (h *Handler) NotificationChannelCreate(w http.ResponseWriter, r *http.Request) {
	if h.notificationConfigRepo == nil {
		h.setFlash(w, r, "error", "Notification service not configured")
		http.Redirect(w, r, "/admin/notifications/channels", http.StatusSeeOther)
		return
	}

	var form notificationChannelForm
	if msg := BindForm(r, &form); msg != "" {
		h.setFlash(w, r, "error", msg)
		http.Redirect(w, r, "/admin/notifications/channels", http.StatusSeeOther)
		return
	}

	minPriority := channels.PriorityNormal
	if form.MinPriority != 0 {
		minPriority = channels.Priority(form.MinPriority)
	}

	settings := parseChannelSettings(r, form.Type)

	config := &channels.ChannelConfig{
		Name:        form.Name,
		Type:        form.Type,
		Enabled:     form.Enabled,
		Settings:    settings,
		MinPriority: minPriority,
	}

	if err := h.notificationConfigRepo.SaveChannelConfig(r.Context(), config); err != nil {
		h.setFlash(w, r, "error", "Failed to save channel: "+err.Error())
	} else {
		if form.EditMode {
			h.setFlash(w, r, "success", "Channel updated successfully")
		} else {
			h.setFlash(w, r, "success", "Channel created successfully")
		}
	}

	http.Redirect(w, r, "/admin/notifications/channels", http.StatusSeeOther)
}

// parseChannelSettings extracts channel-specific settings from the form.
func parseChannelSettings(r *http.Request, channelType string) map[string]interface{} {
	settings := make(map[string]interface{})

	switch channelType {
	case "email":
		setIfNotEmpty(settings, "host", r.FormValue("email_host"))
		if portStr := r.FormValue("email_port"); portStr != "" {
			if port, err := strconv.Atoi(portStr); err == nil {
				settings["port"] = port
			}
		}
		setIfNotEmpty(settings, "username", r.FormValue("email_username"))
		setIfNotEmpty(settings, "password", r.FormValue("email_password"))
		setIfNotEmpty(settings, "from_address", r.FormValue("email_from"))
		setIfNotEmpty(settings, "from_name", r.FormValue("email_from_name"))
		settings["use_tls"] = r.FormValue("email_tls") == "on" || r.FormValue("email_tls") == "true"
		settings["use_ssl"] = r.FormValue("email_ssl") == "on" || r.FormValue("email_ssl") == "true"

		recipientsStr := strings.TrimSpace(r.FormValue("email_recipients"))
		if recipientsStr != "" {
			var recipients []string
			for _, addr := range strings.Split(recipientsStr, ",") {
				if email := strings.TrimSpace(addr); email != "" {
					recipients = append(recipients, email)
				}
			}
			settings["to_addresses"] = recipients
		}

	case "slack":
		setIfNotEmpty(settings, "webhook_url", r.FormValue("slack_webhook"))
		setIfNotEmpty(settings, "channel", r.FormValue("slack_channel"))
		setIfNotEmpty(settings, "username", r.FormValue("slack_username"))

	case "discord":
		setIfNotEmpty(settings, "webhook_url", r.FormValue("discord_webhook"))
		setIfNotEmpty(settings, "username", r.FormValue("discord_username"))

	case "telegram":
		setIfNotEmpty(settings, "bot_token", r.FormValue("telegram_token"))
		if chatID := strings.TrimSpace(r.FormValue("telegram_chat_id")); chatID != "" {
			settings["chat_ids"] = []string{chatID}
		}

	case "webhook":
		setIfNotEmpty(settings, "url", r.FormValue("webhook_url"))
		setIfNotEmpty(settings, "method", r.FormValue("webhook_method"))
		setIfNotEmpty(settings, "auth_type", r.FormValue("webhook_auth_type"))
		setIfNotEmpty(settings, "auth_token", r.FormValue("webhook_auth_token"))
		setIfNotEmpty(settings, "auth_username", r.FormValue("webhook_auth_username"))
		setIfNotEmpty(settings, "auth_password", r.FormValue("webhook_auth_password"))
		if headersStr := strings.TrimSpace(r.FormValue("webhook_headers")); headersStr != "" {
			var headers map[string]string
			if err := json.Unmarshal([]byte(headersStr), &headers); err == nil {
				settings["headers"] = headers
			}
		}

	case "gotify":
		setIfNotEmpty(settings, "server_url", r.FormValue("gotify_server_url"))
		setIfNotEmpty(settings, "app_token", r.FormValue("gotify_app_token"))

	case "ntfy":
		setIfNotEmpty(settings, "server_url", r.FormValue("ntfy_server_url"))
		setIfNotEmpty(settings, "topic", r.FormValue("ntfy_topic"))
		setIfNotEmpty(settings, "access_token", r.FormValue("ntfy_access_token"))

	case "pagerduty":
		setIfNotEmpty(settings, "routing_key", r.FormValue("pagerduty_routing_key"))
		setIfNotEmpty(settings, "component", r.FormValue("pagerduty_component"))

	case "opsgenie":
		setIfNotEmpty(settings, "api_key", r.FormValue("opsgenie_api_key"))
		setIfNotEmpty(settings, "api_base_url", r.FormValue("opsgenie_api_base_url"))
	}

	return settings
}

// setIfNotEmpty sets a key in the map if the value is non-empty after trimming.
func setIfNotEmpty(m map[string]interface{}, key, value string) {
	v := strings.TrimSpace(value)
	if v != "" {
		m[key] = v
	}
}

// NotificationChannelEditTempl renders the notification channel edit page.
func (h *Handler) NotificationChannelEditTempl(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		http.Redirect(w, r, "/admin/notifications/channels", http.StatusSeeOther)
		return
	}

	pageData := h.prepareTemplPageData(r, "Edit Channel: "+name, "notification-channels")

	var channelViews []admin.ChannelView
	var editChannel *admin.ChannelView

	if h.notificationConfigRepo != nil {
		configs, err := h.notificationConfigRepo.GetChannelConfigs(r.Context())
		if err == nil {
			for _, cfg := range configs {
				var types []string
				for _, t := range cfg.NotificationTypes {
					types = append(types, string(t))
				}
				cv := admin.ChannelView{
					Name:              cfg.Name,
					Type:              cfg.Type,
					Enabled:           cfg.Enabled,
					Settings:          cfg.Settings,
					NotificationTypes: types,
					MinPriority:       cfg.MinPriority.String(),
				}
				channelViews = append(channelViews, cv)
				if cfg.Name == name {
					editChannel = &cv
				}
			}
		}
	}

	if editChannel == nil {
		h.setFlash(w, r, "error", "Channel not found: "+name)
		http.Redirect(w, r, "/admin/notifications/channels", http.StatusSeeOther)
		return
	}

	data := admin.NotificationChannelsData{
		PageData:    pageData,
		Channels:    channelViews,
		EditChannel: editChannel,
	}

	h.renderTempl(w, r, admin.NotificationChannels(data))
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
