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
	"time"
)

// PagerDutyChannel sends notifications via PagerDuty Events API v2.
type PagerDutyChannel struct {
	config     PagerDutyConfig
	httpClient *http.Client
}

// PagerDutyConfig holds PagerDuty channel configuration.
type PagerDutyConfig struct {
	// RoutingKey is the integration key (Events API v2).
	RoutingKey string `json:"routing_key"`

	// Severity overrides priority-based severity mapping.
	// Values: critical, error, warning, info.
	Severity string `json:"severity,omitempty"`

	// Component identifies the part of the system (optional).
	Component string `json:"component,omitempty"`

	// Group for logical grouping (optional).
	Group string `json:"group,omitempty"`

	// Timeout for HTTP requests in seconds.
	Timeout int `json:"timeout,omitempty"`
}

const pagerDutyEventsURL = "https://events.pagerduty.com/v2/enqueue"

// pagerDutyEvent is the PagerDuty Events API v2 payload.
type pagerDutyEvent struct {
	RoutingKey  string              `json:"routing_key"`
	EventAction string             `json:"event_action"` // trigger, acknowledge, resolve
	DedupKey    string              `json:"dedup_key,omitempty"`
	Payload     pagerDutyPayload    `json:"payload"`
}

type pagerDutyPayload struct {
	Summary   string                 `json:"summary"`
	Source    string                 `json:"source"`
	Severity  string                `json:"severity"` // critical, error, warning, info
	Timestamp string                `json:"timestamp,omitempty"`
	Component string                `json:"component,omitempty"`
	Group     string                `json:"group,omitempty"`
	Class     string                `json:"class,omitempty"`
	CustomDetails map[string]interface{} `json:"custom_details,omitempty"`
}

type pagerDutyResponse struct {
	Status   string `json:"status"`
	Message  string `json:"message"`
	DedupKey string `json:"dedup_key"`
}

// NewPagerDutyChannel creates a new PagerDuty notification channel.
func NewPagerDutyChannel(config PagerDutyConfig) (*PagerDutyChannel, error) {
	if config.RoutingKey == "" {
		return nil, fmt.Errorf("pagerduty routing key is required")
	}
	if config.Timeout == 0 {
		config.Timeout = 30
	}

	return &PagerDutyChannel{
		config: config,
		httpClient: &http.Client{
			Timeout: time.Duration(config.Timeout) * time.Second,
		},
	}, nil
}

// Name returns the channel identifier.
func (p *PagerDutyChannel) Name() string { return "pagerduty" }

// IsConfigured returns true if the channel has valid configuration.
func (p *PagerDutyChannel) IsConfigured() bool {
	return p.config.RoutingKey != ""
}

// Send delivers a notification via PagerDuty.
func (p *PagerDutyChannel) Send(ctx context.Context, msg RenderedMessage) error {
	summary := msg.Title
	if msg.BodyPlain != "" {
		summary = msg.Title + " - " + msg.BodyPlain
	}
	// PagerDuty summary max 1024 chars
	if len(summary) > 1024 {
		summary = summary[:1021] + "..."
	}

	severity := p.mapSeverity(msg.Priority)
	if p.config.Severity != "" {
		severity = p.config.Severity
	}

	event := pagerDutyEvent{
		RoutingKey:  p.config.RoutingKey,
		EventAction: "trigger",
		Payload: pagerDutyPayload{
			Summary:       summary,
			Source:        "usulnet",
			Severity:      severity,
			Timestamp:     msg.Timestamp.Format(time.RFC3339),
			Component:     p.config.Component,
			Group:         p.config.Group,
			Class:         string(msg.Type),
			CustomDetails: msg.Data,
		},
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal pagerduty event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pagerDutyEventsURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("pagerduty request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var pdResp pagerDutyResponse
		json.Unmarshal(body, &pdResp)
		return fmt.Errorf("pagerduty API error %d: %s", resp.StatusCode, pdResp.Message)
	}

	return nil
}

// Test sends a test notification.
func (p *PagerDutyChannel) Test(ctx context.Context) error {
	return p.Send(ctx, RenderedMessage{
		Title:     "USULNET Test Notification",
		Body:      "This is a test notification from USULNET to verify PagerDuty integration.",
		BodyPlain: "This is a test notification from USULNET to verify PagerDuty integration.",
		Priority:  PriorityNormal,
		Timestamp: time.Now(),
		Type:      TypeTestMessage,
	})
}

// mapSeverity converts internal priority to PagerDuty severity.
func (p *PagerDutyChannel) mapSeverity(priority Priority) string {
	switch priority {
	case PriorityCritical:
		return "critical"
	case PriorityHigh:
		return "error"
	case PriorityNormal:
		return "warning"
	default:
		return "info"
	}
}

// NewPagerDutyChannelFromSettings creates a PagerDutyChannel from generic settings map.
func NewPagerDutyChannelFromSettings(settings map[string]interface{}) (*PagerDutyChannel, error) {
	config := PagerDutyConfig{}

	if v, ok := settings["routing_key"].(string); ok {
		config.RoutingKey = v
	}
	if v, ok := settings["severity"].(string); ok {
		config.Severity = v
	}
	if v, ok := settings["component"].(string); ok {
		config.Component = v
	}
	if v, ok := settings["group"].(string); ok {
		config.Group = v
	}
	if v, ok := settings["timeout"].(float64); ok {
		config.Timeout = int(v)
	}

	return NewPagerDutyChannel(config)
}
