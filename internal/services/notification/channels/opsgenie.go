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

// OpsgenieChannel sends notifications via Opsgenie Alert API.
type OpsgenieChannel struct {
	config     OpsgenieConfig
	httpClient *http.Client
}

// OpsgenieConfig holds Opsgenie channel configuration.
type OpsgenieConfig struct {
	// APIKey is the Opsgenie API key (GenieKey).
	APIKey string `json:"api_key"`

	// APIBaseURL can override the default (e.g. for EU: https://api.eu.opsgenie.com).
	APIBaseURL string `json:"api_base_url,omitempty"`

	// Responders are teams or users to notify.
	Responders []OpsgenieResponder `json:"responders,omitempty"`

	// Tags to add to all alerts.
	Tags []string `json:"tags,omitempty"`

	// Priority overrides priority mapping (P1-P5).
	Priority string `json:"priority,omitempty"`

	// Timeout for HTTP requests in seconds.
	Timeout int `json:"timeout,omitempty"`
}

// OpsgenieResponder identifies a responder (team or user).
type OpsgenieResponder struct {
	Type string `json:"type"` // team, user, escalation, schedule
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// opsgenieAlert is the Opsgenie Create Alert payload.
type opsgenieAlert struct {
	Message     string              `json:"message"`
	Description string              `json:"description,omitempty"`
	Responders  []OpsgenieResponder `json:"responders,omitempty"`
	Tags        []string            `json:"tags,omitempty"`
	Priority    string              `json:"priority,omitempty"`
	Source      string              `json:"source,omitempty"`
	Entity      string              `json:"entity,omitempty"`
	Details     map[string]string   `json:"details,omitempty"`
}

type opsgenieResponse struct {
	Result    string  `json:"result"`
	RequestID string  `json:"requestId"`
	Took      float64 `json:"took"`
}

// NewOpsgenieChannel creates a new Opsgenie notification channel.
func NewOpsgenieChannel(config OpsgenieConfig) (*OpsgenieChannel, error) {
	if config.APIKey == "" {
		return nil, fmt.Errorf("opsgenie API key is required")
	}
	if config.APIBaseURL == "" {
		config.APIBaseURL = "https://api.opsgenie.com"
	}
	if config.Timeout == 0 {
		config.Timeout = 30
	}

	return &OpsgenieChannel{
		config: config,
		httpClient: &http.Client{
			Timeout: time.Duration(config.Timeout) * time.Second,
		},
	}, nil
}

// Name returns the channel identifier.
func (o *OpsgenieChannel) Name() string { return "opsgenie" }

// IsConfigured returns true if the channel has valid configuration.
func (o *OpsgenieChannel) IsConfigured() bool {
	return o.config.APIKey != ""
}

// Send delivers a notification via Opsgenie.
func (o *OpsgenieChannel) Send(ctx context.Context, msg RenderedMessage) error {
	message := msg.Title
	if len(message) > 130 {
		message = message[:127] + "..."
	}

	description := msg.BodyPlain
	if description == "" {
		description = msg.Body
	}
	if len(description) > 15000 {
		description = description[:14997] + "..."
	}

	priority := o.mapPriority(msg.Priority)
	if o.config.Priority != "" {
		priority = o.config.Priority
	}

	tags := append([]string{}, o.config.Tags...)
	tags = append(tags, string(msg.Type.Category()), string(msg.Type))

	details := make(map[string]string)
	details["category"] = msg.Type.Category()
	details["priority"] = msg.Priority.String()
	details["timestamp"] = msg.Timestamp.Format(time.RFC3339)
	for k, v := range msg.Data {
		details[k] = fmt.Sprintf("%v", v)
	}

	alert := opsgenieAlert{
		Message:     message,
		Description: description,
		Responders:  o.config.Responders,
		Tags:        tags,
		Priority:    priority,
		Source:      "usulnet",
		Entity:      string(msg.Type),
		Details:     details,
	}

	data, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal opsgenie alert: %w", err)
	}

	url := o.config.APIBaseURL + "/v2/alerts"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "GenieKey "+o.config.APIKey)

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("opsgenie request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("opsgenie API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Test sends a test notification.
func (o *OpsgenieChannel) Test(ctx context.Context) error {
	return o.Send(ctx, RenderedMessage{
		Title:     "USULNET Test Notification",
		Body:      "This is a test notification from USULNET to verify Opsgenie integration.",
		BodyPlain: "This is a test notification from USULNET to verify Opsgenie integration.",
		Priority:  PriorityNormal,
		Timestamp: time.Now(),
		Type:      TypeTestMessage,
	})
}

// mapPriority converts internal priority to Opsgenie priority (P1-P5).
func (o *OpsgenieChannel) mapPriority(p Priority) string {
	switch p {
	case PriorityCritical:
		return "P1"
	case PriorityHigh:
		return "P2"
	case PriorityNormal:
		return "P3"
	default:
		return "P5"
	}
}

// NewOpsgenieChannelFromSettings creates an OpsgenieChannel from generic settings map.
func NewOpsgenieChannelFromSettings(settings map[string]interface{}) (*OpsgenieChannel, error) {
	config := OpsgenieConfig{}

	if v, ok := settings["api_key"].(string); ok {
		config.APIKey = v
	}
	if v, ok := settings["api_base_url"].(string); ok {
		config.APIBaseURL = v
	}
	if v, ok := settings["priority"].(string); ok {
		config.Priority = v
	}
	if v, ok := settings["timeout"].(float64); ok {
		config.Timeout = int(v)
	}

	// Parse tags
	if v, ok := settings["tags"].([]interface{}); ok {
		for _, t := range v {
			if s, ok := t.(string); ok {
				config.Tags = append(config.Tags, s)
			}
		}
	}

	// Parse responders
	if v, ok := settings["responders"].([]interface{}); ok {
		for _, r := range v {
			if m, ok := r.(map[string]interface{}); ok {
				resp := OpsgenieResponder{}
				if t, ok := m["type"].(string); ok {
					resp.Type = t
				}
				if id, ok := m["id"].(string); ok {
					resp.ID = id
				}
				if name, ok := m["name"].(string); ok {
					resp.Name = name
				}
				if resp.Type != "" {
					config.Responders = append(config.Responders, resp)
				}
			}
		}
	}

	return NewOpsgenieChannel(config)
}
