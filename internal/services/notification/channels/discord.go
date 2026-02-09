// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package channels provides notification channel implementations.
// Department L: Notifications
package channels

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DiscordChannel sends notifications via Discord webhooks.
// Supports Discord embeds for rich formatting.
type DiscordChannel struct {
	config     DiscordConfig
	httpClient *http.Client
}

// DiscordConfig holds Discord channel configuration.
type DiscordConfig struct {
	// WebhookURL is the Discord webhook URL.
	WebhookURL string `json:"webhook_url"`

	// Username overrides the webhook's default username.
	Username string `json:"username,omitempty"`

	// AvatarURL overrides the webhook's default avatar.
	AvatarURL string `json:"avatar_url,omitempty"`

	// ThreadID posts to a specific thread (optional).
	ThreadID string `json:"thread_id,omitempty"`

	// MentionRoles lists role IDs to mention for critical alerts.
	MentionRoles []string `json:"mention_roles,omitempty"`

	// MentionUsers lists user IDs to mention for critical alerts.
	MentionUsers []string `json:"mention_users,omitempty"`

	// MentionEveryone mentions @everyone for critical alerts.
	MentionEveryone bool `json:"mention_everyone,omitempty"`

	// Timeout for HTTP requests in seconds. Defaults to 30.
	Timeout int `json:"timeout,omitempty"`
}

// DiscordMessage represents a Discord webhook payload.
type DiscordMessage struct {
	Content   string         `json:"content,omitempty"`
	Username  string         `json:"username,omitempty"`
	AvatarURL string         `json:"avatar_url,omitempty"`
	TTS       bool           `json:"tts,omitempty"`
	Embeds    []DiscordEmbed `json:"embeds,omitempty"`
	AllowedMentions *DiscordAllowedMentions `json:"allowed_mentions,omitempty"`
}

// DiscordAllowedMentions controls which mentions are allowed.
type DiscordAllowedMentions struct {
	Parse []string `json:"parse,omitempty"` // "roles", "users", "everyone"
	Roles []string `json:"roles,omitempty"`
	Users []string `json:"users,omitempty"`
}

// DiscordEmbed represents a Discord embed.
type DiscordEmbed struct {
	Title       string              `json:"title,omitempty"`
	Description string              `json:"description,omitempty"`
	URL         string              `json:"url,omitempty"`
	Color       int                 `json:"color,omitempty"`
	Timestamp   string              `json:"timestamp,omitempty"`
	Footer      *DiscordEmbedFooter `json:"footer,omitempty"`
	Thumbnail   *DiscordEmbedImage  `json:"thumbnail,omitempty"`
	Author      *DiscordEmbedAuthor `json:"author,omitempty"`
	Fields      []DiscordEmbedField `json:"fields,omitempty"`
}

// DiscordEmbedFooter is the embed footer.
type DiscordEmbedFooter struct {
	Text    string `json:"text"`
	IconURL string `json:"icon_url,omitempty"`
}

// DiscordEmbedImage represents an embed image/thumbnail.
type DiscordEmbedImage struct {
	URL string `json:"url"`
}

// DiscordEmbedAuthor is the embed author section.
type DiscordEmbedAuthor struct {
	Name    string `json:"name"`
	URL     string `json:"url,omitempty"`
	IconURL string `json:"icon_url,omitempty"`
}

// DiscordEmbedField is an embed field.
type DiscordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

// NewDiscordChannel creates a new Discord notification channel.
func NewDiscordChannel(config DiscordConfig) (*DiscordChannel, error) {
	if config.WebhookURL == "" {
		return nil, fmt.Errorf("discord webhook URL is required")
	}

	if !strings.Contains(config.WebhookURL, "discord.com/api/webhooks") &&
		!strings.Contains(config.WebhookURL, "discordapp.com/api/webhooks") {
		return nil, fmt.Errorf("invalid Discord webhook URL")
	}

	// Set defaults
	if config.Username == "" {
		config.Username = "USULNET"
	}
	if config.Timeout == 0 {
		config.Timeout = 30
	}

	return &DiscordChannel{
		config: config,
		httpClient: &http.Client{
			Timeout: time.Duration(config.Timeout) * time.Second,
		},
	}, nil
}

// Name returns the channel identifier.
func (d *DiscordChannel) Name() string {
	return "discord"
}

// IsConfigured returns true if the channel has valid configuration.
func (d *DiscordChannel) IsConfigured() bool {
	return d.config.WebhookURL != ""
}

// Send delivers a notification via Discord webhook.
func (d *DiscordChannel) Send(ctx context.Context, msg RenderedMessage) error {
	discordMsg := d.buildMessage(msg)

	payload, err := json.Marshal(discordMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal discord message: %w", err)
	}

	url := d.config.WebhookURL
	if d.config.ThreadID != "" {
		url += "?thread_id=" + d.config.ThreadID
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("discord request failed: %w", err)
	}
	defer resp.Body.Close()

	// Discord returns 204 No Content on success
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("discord returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Test sends a test notification to verify configuration.
func (d *DiscordChannel) Test(ctx context.Context) error {
	testMsg := RenderedMessage{
		Title:     "USULNET Test Notification",
		Body:      "This is a test notification from USULNET to verify Discord integration.",
		BodyPlain: "This is a test notification from USULNET to verify Discord integration.",
		Priority:  PriorityNormal,
		Timestamp: time.Now(),
		Type:      TypeTestMessage,
		Color:     "#3B82F6",
	}

	return d.Send(ctx, testMsg)
}

// buildMessage constructs the Discord message.
func (d *DiscordChannel) buildMessage(msg RenderedMessage) DiscordMessage {
	discordMsg := DiscordMessage{
		Username:  d.config.Username,
		AvatarURL: d.config.AvatarURL,
	}

	// Add mentions for critical alerts
	if msg.Priority >= PriorityCritical {
		discordMsg.Content = d.buildMentions()
		discordMsg.AllowedMentions = d.buildAllowedMentions()
	}

	// Build embed
	discordMsg.Embeds = []DiscordEmbed{d.buildEmbed(msg)}

	return discordMsg
}

// buildEmbed creates a Discord embed from the notification message.
func (d *DiscordChannel) buildEmbed(msg RenderedMessage) DiscordEmbed {
	embed := DiscordEmbed{
		Title:       fmt.Sprintf("%s %s", d.getPriorityEmoji(msg.Priority), msg.Title),
		Description: msg.Body,
		Color:       d.hexToInt(msg.Color),
		Timestamp:   msg.Timestamp.Format(time.RFC3339),
		Footer: &DiscordEmbedFooter{
			Text: fmt.Sprintf("USULNET • %s • %s", msg.Type.Category(), msg.Priority.String()),
		},
		Author: &DiscordEmbedAuthor{
			Name:    "USULNET",
			IconURL: d.config.AvatarURL,
		},
	}

	// Add data fields
	if len(msg.Data) > 0 {
		embed.Fields = d.buildDataFields(msg.Data)
	}

	return embed
}

// buildDataFields converts data map to Discord embed fields.
func (d *DiscordChannel) buildDataFields(data map[string]interface{}) []DiscordEmbedField {
	fields := make([]DiscordEmbedField, 0, len(data))

	for key, value := range data {
		// Skip complex nested objects
		switch v := value.(type) {
		case string:
			fields = append(fields, DiscordEmbedField{
				Name:   key,
				Value:  v,
				Inline: len(v) < 30,
			})
		case int, int64, float64, bool:
			fields = append(fields, DiscordEmbedField{
				Name:   key,
				Value:  fmt.Sprintf("%v", v),
				Inline: true,
			})
		}
	}

	// Discord limits embed fields to 25
	if len(fields) > 25 {
		fields = fields[:25]
	}

	return fields
}

// buildMentions creates mention string for critical alerts.
func (d *DiscordChannel) buildMentions() string {
	var parts []string

	if d.config.MentionEveryone {
		parts = append(parts, "@everyone")
	}

	for _, roleID := range d.config.MentionRoles {
		parts = append(parts, fmt.Sprintf("<@&%s>", roleID))
	}

	for _, userID := range d.config.MentionUsers {
		parts = append(parts, fmt.Sprintf("<@%s>", userID))
	}

	if len(parts) == 0 {
		return ""
	}

	return "🚨 " + strings.Join(parts, " ")
}

// buildAllowedMentions creates the allowed mentions structure.
func (d *DiscordChannel) buildAllowedMentions() *DiscordAllowedMentions {
	mentions := &DiscordAllowedMentions{}

	if d.config.MentionEveryone {
		mentions.Parse = append(mentions.Parse, "everyone")
	}

	if len(d.config.MentionRoles) > 0 {
		mentions.Roles = d.config.MentionRoles
	}

	if len(d.config.MentionUsers) > 0 {
		mentions.Users = d.config.MentionUsers
	}

	return mentions
}

// getPriorityEmoji returns an emoji based on priority level.
func (d *DiscordChannel) getPriorityEmoji(priority Priority) string {
	switch priority {
	case PriorityCritical:
		return "🔴"
	case PriorityHigh:
		return "🟠"
	case PriorityNormal:
		return "🔵"
	default:
		return "⚪"
	}
}

// hexToInt converts a hex color string to Discord color integer.
func (d *DiscordChannel) hexToInt(hex string) int {
	if hex == "" {
		return 0x3B82F6 // Default blue
	}

	// Remove # prefix
	hex = strings.TrimPrefix(hex, "#")

	// Parse hex
	var color int
	fmt.Sscanf(hex, "%x", &color)
	return color
}

// NewDiscordChannelFromSettings creates a DiscordChannel from generic settings map.
func NewDiscordChannelFromSettings(settings map[string]interface{}) (*DiscordChannel, error) {
	data, err := json.Marshal(settings)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal settings: %w", err)
	}

	var config DiscordConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse discord config: %w", err)
	}

	return NewDiscordChannel(config)
}
