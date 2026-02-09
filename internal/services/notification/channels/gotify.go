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

// GotifyChannel sends notifications via a Gotify server.
type GotifyChannel struct {
	config     GotifyConfig
	httpClient *http.Client
}

// GotifyConfig holds Gotify channel configuration.
type GotifyConfig struct {
	// ServerURL is the Gotify server base URL (e.g. https://gotify.example.com).
	ServerURL string `json:"server_url"`

	// AppToken is the application token for authentication.
	AppToken string `json:"app_token"`

	// Priority for messages (0-10, default 5).
	DefaultPriority int `json:"default_priority,omitempty"`

	// Timeout for HTTP requests in seconds.
	Timeout int `json:"timeout,omitempty"`
}

// gotifyMessage is the Gotify API message payload.
type gotifyMessage struct {
	Title    string            `json:"title"`
	Message  string            `json:"message"`
	Priority int               `json:"priority"`
	Extras   map[string]interface{} `json:"extras,omitempty"`
}

// NewGotifyChannel creates a new Gotify notification channel.
func NewGotifyChannel(config GotifyConfig) (*GotifyChannel, error) {
	if config.ServerURL == "" {
		return nil, fmt.Errorf("gotify server URL is required")
	}
	if config.AppToken == "" {
		return nil, fmt.Errorf("gotify app token is required")
	}

	config.ServerURL = strings.TrimRight(config.ServerURL, "/")

	if config.DefaultPriority == 0 {
		config.DefaultPriority = 5
	}
	if config.Timeout == 0 {
		config.Timeout = 30
	}

	return &GotifyChannel{
		config: config,
		httpClient: &http.Client{
			Timeout: time.Duration(config.Timeout) * time.Second,
		},
	}, nil
}

// Name returns the channel identifier.
func (g *GotifyChannel) Name() string { return "gotify" }

// IsConfigured returns true if the channel has valid configuration.
func (g *GotifyChannel) IsConfigured() bool {
	return g.config.ServerURL != "" && g.config.AppToken != ""
}

// Send delivers a notification via Gotify.
func (g *GotifyChannel) Send(ctx context.Context, msg RenderedMessage) error {
	priority := g.mapPriority(msg.Priority)

	body := msg.BodyPlain
	if body == "" {
		body = msg.Body
	}

	payload := gotifyMessage{
		Title:    msg.Title,
		Message:  body,
		Priority: priority,
		Extras: map[string]interface{}{
			"client::notification": map[string]interface{}{
				"click": map[string]string{"url": ""},
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal gotify message: %w", err)
	}

	url := g.config.ServerURL + "/message"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gotify-Key", g.config.AppToken)

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("gotify request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("gotify API error %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// Test sends a test notification.
func (g *GotifyChannel) Test(ctx context.Context) error {
	return g.Send(ctx, RenderedMessage{
		Title:     "USULNET Test Notification",
		Body:      "This is a test notification from USULNET to verify Gotify integration.",
		BodyPlain: "This is a test notification from USULNET to verify Gotify integration.",
		Priority:  PriorityNormal,
		Timestamp: time.Now(),
		Type:      TypeTestMessage,
	})
}

// mapPriority converts internal priority to Gotify priority (0-10).
func (g *GotifyChannel) mapPriority(p Priority) int {
	switch p {
	case PriorityCritical:
		return 10
	case PriorityHigh:
		return 7
	case PriorityNormal:
		return g.config.DefaultPriority
	default:
		return 2
	}
}

// NewGotifyChannelFromSettings creates a GotifyChannel from generic settings map.
func NewGotifyChannelFromSettings(settings map[string]interface{}) (*GotifyChannel, error) {
	config := GotifyConfig{}

	if v, ok := settings["server_url"].(string); ok {
		config.ServerURL = v
	}
	if v, ok := settings["app_token"].(string); ok {
		config.AppToken = v
	}
	if v, ok := settings["default_priority"].(float64); ok {
		config.DefaultPriority = int(v)
	}
	if v, ok := settings["timeout"].(float64); ok {
		config.Timeout = int(v)
	}

	return NewGotifyChannel(config)
}
