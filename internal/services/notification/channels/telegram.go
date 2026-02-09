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

// TelegramChannel sends notifications via Telegram Bot API.
type TelegramChannel struct {
	config     TelegramConfig
	httpClient *http.Client
	baseURL    string
}

// TelegramConfig holds Telegram channel configuration.
type TelegramConfig struct {
	// BotToken is the Telegram bot token from @BotFather.
	BotToken string `json:"bot_token"`

	// ChatID is the target chat, group, or channel ID.
	// For channels, use @channelname or numeric ID.
	ChatID string `json:"chat_id"`

	// ParseMode sets message formatting: HTML, MarkdownV2, or empty.
	ParseMode string `json:"parse_mode,omitempty"`

	// DisableNotification sends silently.
	DisableNotification bool `json:"disable_notification,omitempty"`

	// DisableWebPagePreview disables link previews.
	DisableWebPagePreview bool `json:"disable_web_page_preview,omitempty"`

	// ThreadID for posting to a specific topic in supergroups.
	ThreadID int64 `json:"thread_id,omitempty"`

	// Timeout for HTTP requests in seconds.
	Timeout int `json:"timeout,omitempty"`
}

// TelegramMessage represents a Telegram sendMessage request.
type TelegramMessage struct {
	ChatID                string `json:"chat_id"`
	Text                  string `json:"text"`
	ParseMode             string `json:"parse_mode,omitempty"`
	DisableNotification   bool   `json:"disable_notification,omitempty"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview,omitempty"`
	MessageThreadID       int64  `json:"message_thread_id,omitempty"`
}

// TelegramResponse is the Telegram API response.
type TelegramResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description,omitempty"`
	ErrorCode   int    `json:"error_code,omitempty"`
}

// NewTelegramChannel creates a new Telegram notification channel.
func NewTelegramChannel(config TelegramConfig) (*TelegramChannel, error) {
	if config.BotToken == "" {
		return nil, fmt.Errorf("telegram bot token is required")
	}
	if config.ChatID == "" {
		return nil, fmt.Errorf("telegram chat ID is required")
	}

	// Set defaults
	if config.ParseMode == "" {
		config.ParseMode = "HTML"
	}
	if config.Timeout == 0 {
		config.Timeout = 30
	}

	return &TelegramChannel{
		config: config,
		httpClient: &http.Client{
			Timeout: time.Duration(config.Timeout) * time.Second,
		},
		baseURL: fmt.Sprintf("https://api.telegram.org/bot%s", config.BotToken),
	}, nil
}

// Name returns the channel identifier.
func (t *TelegramChannel) Name() string {
	return "telegram"
}

// IsConfigured returns true if the channel has valid configuration.
func (t *TelegramChannel) IsConfigured() bool {
	return t.config.BotToken != "" && t.config.ChatID != ""
}

// Send delivers a notification via Telegram.
func (t *TelegramChannel) Send(ctx context.Context, msg RenderedMessage) error {
	text := t.formatMessage(msg)

	telegramMsg := TelegramMessage{
		ChatID:                t.config.ChatID,
		Text:                  text,
		ParseMode:             t.config.ParseMode,
		DisableNotification:   t.config.DisableNotification,
		DisableWebPagePreview: t.config.DisableWebPagePreview,
		MessageThreadID:       t.config.ThreadID,
	}

	payload, err := json.Marshal(telegramMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal telegram message: %w", err)
	}

	url := t.baseURL + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("telegram request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var telegramResp TelegramResponse
	if err := json.Unmarshal(body, &telegramResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if !telegramResp.OK {
		return fmt.Errorf("telegram API error %d: %s", telegramResp.ErrorCode, telegramResp.Description)
	}

	return nil
}

// Test sends a test notification to verify configuration.
func (t *TelegramChannel) Test(ctx context.Context) error {
	testMsg := RenderedMessage{
		Title:     "USULNET Test Notification",
		Body:      "This is a test notification from USULNET to verify Telegram integration.",
		BodyPlain: "This is a test notification from USULNET to verify Telegram integration.",
		Priority:  PriorityNormal,
		Timestamp: time.Now(),
		Type:      TypeTestMessage,
		Color:     "#3B82F6",
	}

	return t.Send(ctx, testMsg)
}

// formatMessage creates the Telegram message text.
func (t *TelegramChannel) formatMessage(msg RenderedMessage) string {
	var sb strings.Builder

	// Priority emoji and title
	emoji := t.getPriorityEmoji(msg.Priority)
	
	switch t.config.ParseMode {
	case "HTML":
		sb.WriteString(fmt.Sprintf("%s <b>%s</b>\n\n", emoji, escapeHTML(msg.Title)))
		sb.WriteString(msg.Body) // Assume body is already HTML-safe
		sb.WriteString("\n\n")
		sb.WriteString(fmt.Sprintf("<i>📌 %s | ⏰ %s | 🏷️ %s</i>",
			msg.Type.Category(),
			msg.Timestamp.Format("15:04:05"),
			msg.Priority.String(),
		))

		// Add data fields
		if len(msg.Data) > 0 {
			sb.WriteString("\n\n<b>Details:</b>\n")
			for key, value := range msg.Data {
				sb.WriteString(fmt.Sprintf("• <code>%s</code>: %v\n", escapeHTML(key), value))
			}
		}

	case "MarkdownV2":
		sb.WriteString(fmt.Sprintf("%s *%s*\n\n", emoji, escapeMarkdownV2(msg.Title)))
		sb.WriteString(escapeMarkdownV2(msg.BodyPlain))
		sb.WriteString("\n\n")
		sb.WriteString(fmt.Sprintf("_📌 %s \\| ⏰ %s \\| 🏷️ %s_",
			escapeMarkdownV2(msg.Type.Category()),
			msg.Timestamp.Format("15:04:05"),
			escapeMarkdownV2(msg.Priority.String()),
		))

		// Add data fields
		if len(msg.Data) > 0 {
			sb.WriteString("\n\n*Details:*\n")
			for key, value := range msg.Data {
				sb.WriteString(fmt.Sprintf("• `%s`: %v\n", escapeMarkdownV2(key), value))
			}
		}

	default:
		// Plain text
		sb.WriteString(fmt.Sprintf("%s %s\n\n", emoji, msg.Title))
		sb.WriteString(msg.BodyPlain)
		sb.WriteString("\n\n")
		sb.WriteString(fmt.Sprintf("📌 %s | ⏰ %s | 🏷️ %s",
			msg.Type.Category(),
			msg.Timestamp.Format("15:04:05"),
			msg.Priority.String(),
		))

		if len(msg.Data) > 0 {
			sb.WriteString("\n\nDetails:\n")
			for key, value := range msg.Data {
				sb.WriteString(fmt.Sprintf("• %s: %v\n", key, value))
			}
		}
	}

	return sb.String()
}

// getPriorityEmoji returns an emoji based on priority level.
func (t *TelegramChannel) getPriorityEmoji(priority Priority) string {
	switch priority {
	case PriorityCritical:
		return "🚨"
	case PriorityHigh:
		return "⚠️"
	case PriorityNormal:
		return "ℹ️"
	default:
		return "📋"
	}
}

// escapeHTML escapes HTML special characters.
func escapeHTML(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
	)
	return replacer.Replace(s)
}

// escapeMarkdownV2 escapes MarkdownV2 special characters.
func escapeMarkdownV2(s string) string {
	// Characters that need escaping in MarkdownV2
	chars := []string{"_", "*", "[", "]", "(", ")", "~", "`", ">", "#", "+", "-", "=", "|", "{", "}", ".", "!"}
	result := s
	for _, char := range chars {
		result = strings.ReplaceAll(result, char, "\\"+char)
	}
	return result
}

// NewTelegramChannelFromSettings creates a TelegramChannel from generic settings map.
func NewTelegramChannelFromSettings(settings map[string]interface{}) (*TelegramChannel, error) {
	config := TelegramConfig{}

	if v, ok := settings["bot_token"].(string); ok {
		config.BotToken = v
	}
	if v, ok := settings["chat_id"].(string); ok {
		config.ChatID = v
	}
	// Also accept numeric chat_id
	if v, ok := settings["chat_id"].(float64); ok {
		config.ChatID = fmt.Sprintf("%.0f", v)
	}
	if v, ok := settings["parse_mode"].(string); ok {
		config.ParseMode = v
	}
	if v, ok := settings["disable_notification"].(bool); ok {
		config.DisableNotification = v
	}
	if v, ok := settings["disable_web_page_preview"].(bool); ok {
		config.DisableWebPagePreview = v
	}
	if v, ok := settings["thread_id"].(float64); ok {
		config.ThreadID = int64(v)
	}
	if v, ok := settings["timeout"].(float64); ok {
		config.Timeout = int(v)
	}

	return NewTelegramChannel(config)
}
