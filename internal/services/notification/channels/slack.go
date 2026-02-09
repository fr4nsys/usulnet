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

// SlackChannel sends notifications via Slack webhooks.
// Supports Slack Block Kit for rich formatting.
type SlackChannel struct {
	config     SlackConfig
	httpClient *http.Client
}

// SlackConfig holds Slack channel configuration.
type SlackConfig struct {
	// WebhookURL is the Slack incoming webhook URL.
	WebhookURL string `json:"webhook_url"`

	// Channel overrides the default channel (optional, requires app scope).
	Channel string `json:"channel,omitempty"`

	// Username sets the bot username. Defaults to "USULNET".
	Username string `json:"username,omitempty"`

	// IconEmoji sets the bot icon. Defaults to ":whale:".
	IconEmoji string `json:"icon_emoji,omitempty"`

	// IconURL alternative to IconEmoji.
	IconURL string `json:"icon_url,omitempty"`

	// UseBlocks enables Block Kit formatting. Defaults to true.
	UseBlocks *bool `json:"use_blocks,omitempty"`

	// MentionUsers lists user IDs to mention for critical alerts.
	MentionUsers []string `json:"mention_users,omitempty"`

	// MentionChannel mentions @channel for critical alerts.
	MentionChannel bool `json:"mention_channel,omitempty"`

	// Timeout for HTTP requests in seconds. Defaults to 30.
	Timeout int `json:"timeout,omitempty"`
}

// SlackMessage represents a Slack webhook payload.
type SlackMessage struct {
	Channel     string        `json:"channel,omitempty"`
	Username    string        `json:"username,omitempty"`
	IconEmoji   string        `json:"icon_emoji,omitempty"`
	IconURL     string        `json:"icon_url,omitempty"`
	Text        string        `json:"text"`
	Attachments []SlackAttachment `json:"attachments,omitempty"`
	Blocks      []SlackBlock  `json:"blocks,omitempty"`
}

// SlackAttachment is a legacy attachment format.
type SlackAttachment struct {
	Color      string   `json:"color,omitempty"`
	Title      string   `json:"title,omitempty"`
	Text       string   `json:"text,omitempty"`
	Footer     string   `json:"footer,omitempty"`
	FooterIcon string   `json:"footer_icon,omitempty"`
	Timestamp  int64    `json:"ts,omitempty"`
	Fields     []SlackField `json:"fields,omitempty"`
}

// SlackField is an attachment field.
type SlackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short,omitempty"`
}

// SlackBlock represents a Block Kit block.
type SlackBlock struct {
	Type     string         `json:"type"`
	Text     *SlackTextObj  `json:"text,omitempty"`
	Elements []SlackElement `json:"elements,omitempty"`
	Fields   []SlackTextObj `json:"fields,omitempty"`
	BlockID  string         `json:"block_id,omitempty"`
}

// SlackTextObj is a text object in Block Kit.
type SlackTextObj struct {
	Type  string `json:"type"` // plain_text or mrkdwn
	Text  string `json:"text"`
	Emoji bool   `json:"emoji,omitempty"`
}

// SlackElement is a block element.
type SlackElement struct {
	Type string        `json:"type"`
	Text *SlackTextObj `json:"text,omitempty"`
}

// NewSlackChannel creates a new Slack notification channel.
func NewSlackChannel(config SlackConfig) (*SlackChannel, error) {
	if config.WebhookURL == "" {
		return nil, fmt.Errorf("slack webhook URL is required")
	}

	if !strings.Contains(config.WebhookURL, "hooks.slack.com") {
		return nil, fmt.Errorf("invalid Slack webhook URL")
	}

	// Set defaults
	if config.Username == "" {
		config.Username = "USULNET"
	}
	if config.IconEmoji == "" && config.IconURL == "" {
		config.IconEmoji = ":whale:"
	}
	if config.UseBlocks == nil {
		useBlocks := true
		config.UseBlocks = &useBlocks
	}
	if config.Timeout == 0 {
		config.Timeout = 30
	}

	return &SlackChannel{
		config: config,
		httpClient: &http.Client{
			Timeout: time.Duration(config.Timeout) * time.Second,
		},
	}, nil
}

// Name returns the channel identifier.
func (s *SlackChannel) Name() string {
	return "slack"
}

// IsConfigured returns true if the channel has valid configuration.
func (s *SlackChannel) IsConfigured() bool {
	return s.config.WebhookURL != ""
}

// Send delivers a notification via Slack webhook.
func (s *SlackChannel) Send(ctx context.Context, msg RenderedMessage) error {
	slackMsg := s.buildMessage(msg)

	payload, err := json.Marshal(slackMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal slack message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.WebhookURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("slack request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("slack returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Test sends a test notification to verify configuration.
func (s *SlackChannel) Test(ctx context.Context) error {
	testMsg := RenderedMessage{
		Title:     "USULNET Test Notification",
		Body:      "This is a test notification from USULNET to verify Slack integration.",
		BodyPlain: "This is a test notification from USULNET to verify Slack integration.",
		Priority:  PriorityNormal,
		Timestamp: time.Now(),
		Type:      TypeTestMessage,
		Color:     "#3B82F6",
	}

	return s.Send(ctx, testMsg)
}

// buildMessage constructs the Slack message.
func (s *SlackChannel) buildMessage(msg RenderedMessage) SlackMessage {
	slackMsg := SlackMessage{
		Channel:   s.config.Channel,
		Username:  s.config.Username,
		IconEmoji: s.config.IconEmoji,
		IconURL:   s.config.IconURL,
		Text:      fmt.Sprintf("%s: %s", msg.Title, msg.BodyPlain), // Fallback text
	}

	if *s.config.UseBlocks {
		slackMsg.Blocks = s.buildBlocks(msg)
	} else {
		slackMsg.Attachments = s.buildAttachments(msg)
	}

	return slackMsg
}

// buildBlocks creates Block Kit blocks for rich formatting.
func (s *SlackChannel) buildBlocks(msg RenderedMessage) []SlackBlock {
	blocks := make([]SlackBlock, 0, 4)

	// Add mentions for critical alerts
	if msg.Priority >= PriorityCritical && (len(s.config.MentionUsers) > 0 || s.config.MentionChannel) {
		mentionText := s.buildMentions()
		if mentionText != "" {
			blocks = append(blocks, SlackBlock{
				Type: "section",
				Text: &SlackTextObj{
					Type: "mrkdwn",
					Text: mentionText,
				},
			})
		}
	}

	// Header with emoji based on priority
	headerEmoji := s.getPriorityEmoji(msg.Priority)
	blocks = append(blocks, SlackBlock{
		Type: "header",
		Text: &SlackTextObj{
			Type:  "plain_text",
			Text:  fmt.Sprintf("%s %s", headerEmoji, msg.Title),
			Emoji: true,
		},
	})

	// Main content
	blocks = append(blocks, SlackBlock{
		Type: "section",
		Text: &SlackTextObj{
			Type: "mrkdwn",
			Text: msg.Body,
		},
	})

	// Context with metadata
	blocks = append(blocks, SlackBlock{
		Type: "context",
		Elements: []SlackElement{
			{
				Type: "mrkdwn",
				Text: &SlackTextObj{
					Type: "mrkdwn",
					Text: fmt.Sprintf("*Type:* %s | *Priority:* %s | *Time:* <!date^%d^{date_short_pretty} {time}|%s>",
						msg.Type.Category(),
						msg.Priority.String(),
						msg.Timestamp.Unix(),
						msg.Timestamp.Format("15:04:05"),
					),
				},
			},
		},
	})

	// Add data fields if present
	if len(msg.Data) > 0 {
		fields := s.buildDataFields(msg.Data)
		if len(fields) > 0 {
			blocks = append(blocks, SlackBlock{
				Type:   "section",
				Fields: fields,
			})
		}
	}

	// Divider at the end
	blocks = append(blocks, SlackBlock{Type: "divider"})

	return blocks
}

// buildAttachments creates legacy attachments for simpler formatting.
func (s *SlackChannel) buildAttachments(msg RenderedMessage) []SlackAttachment {
	attachment := SlackAttachment{
		Color:     msg.Color,
		Title:     msg.Title,
		Text:      msg.Body,
		Footer:    fmt.Sprintf("USULNET | %s | %s", msg.Type.Category(), msg.Priority.String()),
		Timestamp: msg.Timestamp.Unix(),
	}

	// Add data fields
	if len(msg.Data) > 0 {
		for key, value := range msg.Data {
			attachment.Fields = append(attachment.Fields, SlackField{
				Title: key,
				Value: fmt.Sprintf("%v", value),
				Short: true,
			})
		}
	}

	return []SlackAttachment{attachment}
}

// buildDataFields converts data map to Slack field objects.
func (s *SlackChannel) buildDataFields(data map[string]interface{}) []SlackTextObj {
	fields := make([]SlackTextObj, 0, len(data))

	for key, value := range data {
		// Skip complex nested objects
		switch v := value.(type) {
		case string, int, int64, float64, bool:
			fields = append(fields, SlackTextObj{
				Type: "mrkdwn",
				Text: fmt.Sprintf("*%s:*\n%v", key, v),
			})
		}
	}

	// Slack limits fields to 10
	if len(fields) > 10 {
		fields = fields[:10]
	}

	return fields
}

// buildMentions creates mention string for critical alerts.
func (s *SlackChannel) buildMentions() string {
	var parts []string

	if s.config.MentionChannel {
		parts = append(parts, "<!channel>")
	}

	for _, userID := range s.config.MentionUsers {
		parts = append(parts, fmt.Sprintf("<@%s>", userID))
	}

	if len(parts) == 0 {
		return ""
	}

	return ":rotating_light: " + strings.Join(parts, " ")
}

// getPriorityEmoji returns an emoji based on priority level.
func (s *SlackChannel) getPriorityEmoji(priority Priority) string {
	switch priority {
	case PriorityCritical:
		return ":red_circle:"
	case PriorityHigh:
		return ":large_orange_circle:"
	case PriorityNormal:
		return ":large_blue_circle:"
	default:
		return ":white_circle:"
	}
}

// NewSlackChannelFromSettings creates a SlackChannel from generic settings map.
func NewSlackChannelFromSettings(settings map[string]interface{}) (*SlackChannel, error) {
	data, err := json.Marshal(settings)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal settings: %w", err)
	}

	var config SlackConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse slack config: %w", err)
	}

	return NewSlackChannel(config)
}
