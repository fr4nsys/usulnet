// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

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

// NtfyChannel sends notifications via an ntfy server.
type NtfyChannel struct {
	config     NtfyConfig
	httpClient *http.Client
}

// NtfyConfig holds ntfy channel configuration.
type NtfyConfig struct {
	// ServerURL is the ntfy server base URL (default: https://ntfy.sh).
	ServerURL string `json:"server_url,omitempty"`

	// Topic is the ntfy topic to publish to.
	Topic string `json:"topic"`

	// Username for basic auth (optional).
	Username string `json:"username,omitempty"`

	// Password for basic auth (optional).
	Password string `json:"password,omitempty"`

	// AccessToken for token-based auth (optional).
	AccessToken string `json:"access_token,omitempty"`

	// DefaultTags are comma-separated tags to add to all messages.
	DefaultTags string `json:"default_tags,omitempty"`

	// Timeout for HTTP requests in seconds.
	Timeout int `json:"timeout,omitempty"`
}

// ntfyMessage is the ntfy JSON publish payload.
type ntfyMessage struct {
	Topic    string   `json:"topic"`
	Title    string   `json:"title,omitempty"`
	Message  string   `json:"message"`
	Priority int      `json:"priority,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

// NewNtfyChannel creates a new ntfy notification channel.
func NewNtfyChannel(config NtfyConfig) (*NtfyChannel, error) {
	if config.Topic == "" {
		return nil, fmt.Errorf("ntfy topic is required")
	}

	if config.ServerURL == "" {
		config.ServerURL = "https://ntfy.sh"
	}
	config.ServerURL = strings.TrimRight(config.ServerURL, "/")

	if config.Timeout == 0 {
		config.Timeout = 30
	}

	return &NtfyChannel{
		config: config,
		httpClient: &http.Client{
			Timeout: time.Duration(config.Timeout) * time.Second,
		},
	}, nil
}

// Name returns the channel identifier.
func (n *NtfyChannel) Name() string { return "ntfy" }

// IsConfigured returns true if the channel has valid configuration.
func (n *NtfyChannel) IsConfigured() bool {
	return n.config.Topic != ""
}

// Send delivers a notification via ntfy.
func (n *NtfyChannel) Send(ctx context.Context, msg RenderedMessage) error {
	body := msg.BodyPlain
	if body == "" {
		body = msg.Body
	}

	tags := n.buildTags(msg)

	payload := ntfyMessage{
		Topic:    n.config.Topic,
		Title:    msg.Title,
		Message:  body,
		Priority: n.mapPriority(msg.Priority),
		Tags:     tags,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal ntfy message: %w", err)
	}

	url := n.config.ServerURL
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Authentication
	if n.config.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+n.config.AccessToken)
	} else if n.config.Username != "" {
		req.SetBasicAuth(n.config.Username, n.config.Password)
	}

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ntfy request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("ntfy API error %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// Test sends a test notification.
func (n *NtfyChannel) Test(ctx context.Context) error {
	return n.Send(ctx, RenderedMessage{
		Title:     "USULNET Test Notification",
		Body:      "This is a test notification from USULNET to verify ntfy integration.",
		BodyPlain: "This is a test notification from USULNET to verify ntfy integration.",
		Priority:  PriorityNormal,
		Timestamp: time.Now(),
		Type:      TypeTestMessage,
	})
}

// mapPriority converts internal priority to ntfy priority (1-5).
func (n *NtfyChannel) mapPriority(p Priority) int {
	switch p {
	case PriorityCritical:
		return 5 // max/urgent
	case PriorityHigh:
		return 4 // high
	case PriorityNormal:
		return 3 // default
	default:
		return 2 // low
	}
}

// buildTags creates ntfy tags based on message type and config.
func (n *NtfyChannel) buildTags(msg RenderedMessage) []string {
	var tags []string

	// Add emoji tag based on priority
	switch msg.Priority {
	case PriorityCritical:
		tags = append(tags, "rotating_light")
	case PriorityHigh:
		tags = append(tags, "warning")
	case PriorityNormal:
		tags = append(tags, "information_source")
	default:
		tags = append(tags, "memo")
	}

	// Add category tag
	tags = append(tags, string(msg.Type.Category()))

	// Add configured default tags
	if n.config.DefaultTags != "" {
		for _, t := range strings.Split(n.config.DefaultTags, ",") {
			if t = strings.TrimSpace(t); t != "" {
				tags = append(tags, t)
			}
		}
	}

	return tags
}

// NewNtfyChannelFromSettings creates an NtfyChannel from generic settings map.
func NewNtfyChannelFromSettings(settings map[string]interface{}) (*NtfyChannel, error) {
	config := NtfyConfig{}

	if v, ok := settings["server_url"].(string); ok {
		config.ServerURL = v
	}
	if v, ok := settings["topic"].(string); ok {
		config.Topic = v
	}
	if v, ok := settings["username"].(string); ok {
		config.Username = v
	}
	if v, ok := settings["password"].(string); ok {
		config.Password = v
	}
	if v, ok := settings["access_token"].(string); ok {
		config.AccessToken = v
	}
	if v, ok := settings["default_tags"].(string); ok {
		config.DefaultTags = v
	}
	if v, ok := settings["timeout"].(float64); ok {
		config.Timeout = int(v)
	}

	return NewNtfyChannel(config)
}
