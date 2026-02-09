// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package channels provides notification channel implementations.
// Department L: Notifications
package channels

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// WebhookChannel sends notifications via HTTP webhooks.
// Supports custom headers, authentication, and payload templates.
type WebhookChannel struct {
	config     WebhookConfig
	httpClient *http.Client
}

// WebhookConfig holds webhook channel configuration.
type WebhookConfig struct {
	// URL is the webhook endpoint.
	URL string `json:"url"`

	// Method is the HTTP method (POST, PUT). Defaults to POST.
	Method string `json:"method,omitempty"`

	// Headers are custom HTTP headers to include.
	Headers map[string]string `json:"headers,omitempty"`

	// AuthType specifies authentication type: none, basic, bearer, hmac.
	AuthType string `json:"auth_type,omitempty"`

	// AuthCredentials holds auth data based on AuthType:
	// - basic: {"username": "...", "password": "..."}
	// - bearer: {"token": "..."}
	// - hmac: {"secret": "...", "header": "X-Signature"}
	AuthCredentials map[string]string `json:"auth_credentials,omitempty"`

	// ContentType is the Content-Type header. Defaults to application/json.
	ContentType string `json:"content_type,omitempty"`

	// PayloadTemplate is a JSON template for the request body.
	// Supports placeholders: {{.Title}}, {{.Body}}, {{.Priority}}, {{.Type}}, {{.Timestamp}}
	// If empty, sends the standard payload.
	PayloadTemplate string `json:"payload_template,omitempty"`

	// Timeout for HTTP requests in seconds. Defaults to 30.
	Timeout int `json:"timeout,omitempty"`

	// RetryCount is the number of retry attempts. Defaults to 3.
	RetryCount int `json:"retry_count,omitempty"`

	// RetryDelay is the delay between retries in milliseconds. Defaults to 1000.
	RetryDelay int `json:"retry_delay,omitempty"`

	// VerifySSL enables SSL certificate verification. Defaults to true.
	VerifySSL *bool `json:"verify_ssl,omitempty"`
}

// WebhookPayload is the default payload structure.
type WebhookPayload struct {
	Title     string                 `json:"title"`
	Body      string                 `json:"body"`
	Priority  string                 `json:"priority"`
	Type      string                 `json:"type"`
	Category  string                 `json:"category"`
	Timestamp string                 `json:"timestamp"`
	Color     string                 `json:"color,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// NewWebhookChannel creates a new webhook notification channel.
func NewWebhookChannel(config WebhookConfig) (*WebhookChannel, error) {
	if config.URL == "" {
		return nil, fmt.Errorf("webhook URL is required")
	}

	// Set defaults
	if config.Method == "" {
		config.Method = http.MethodPost
	}
	if config.ContentType == "" {
		config.ContentType = "application/json"
	}
	if config.Timeout == 0 {
		config.Timeout = 30
	}
	if config.RetryCount == 0 {
		config.RetryCount = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 1000
	}
	if config.VerifySSL == nil {
		verify := true
		config.VerifySSL = &verify
	}

	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
	}

	// Note: In production, configure TLS properly if VerifySSL is false
	// For now, we always verify SSL

	return &WebhookChannel{
		config:     config,
		httpClient: client,
	}, nil
}

// Name returns the channel identifier.
func (w *WebhookChannel) Name() string {
	return "webhook"
}

// IsConfigured returns true if the channel has valid configuration.
func (w *WebhookChannel) IsConfigured() bool {
	return w.config.URL != ""
}

// Send delivers a notification via webhook.
func (w *WebhookChannel) Send(ctx context.Context, msg RenderedMessage) error {
	payload, err := w.buildPayload(msg)
	if err != nil {
		return fmt.Errorf("failed to build webhook payload: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= w.config.RetryCount; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(w.config.RetryDelay) * time.Millisecond):
			}
		}

		if err := w.doRequest(ctx, payload); err != nil {
			lastErr = err
			continue
		}
		return nil
	}

	return fmt.Errorf("webhook delivery failed after %d attempts: %w", w.config.RetryCount+1, lastErr)
}

// Test sends a test notification to verify configuration.
func (w *WebhookChannel) Test(ctx context.Context) error {
	testMsg := RenderedMessage{
		Title:     "USULNET Test Notification",
		Body:      "This is a test notification from USULNET to verify webhook configuration.",
		BodyPlain: "This is a test notification from USULNET to verify webhook configuration.",
		Priority:  PriorityNormal,
		Timestamp: time.Now(),
		Type:      TypeTestMessage,
		Color:     "#3B82F6",
	}

	return w.Send(ctx, testMsg)
}

// buildPayload creates the HTTP request body.
func (w *WebhookChannel) buildPayload(msg RenderedMessage) ([]byte, error) {
	if w.config.PayloadTemplate != "" {
		return w.buildCustomPayload(msg)
	}

	payload := WebhookPayload{
		Title:     msg.Title,
		Body:      msg.Body,
		Priority:  msg.Priority.String(),
		Type:      string(msg.Type),
		Category:  msg.Type.Category(),
		Timestamp: msg.Timestamp.Format(time.RFC3339),
		Color:     msg.Color,
		Data:      msg.Data,
	}

	return json.Marshal(payload)
}

// buildCustomPayload processes a custom payload template.
func (w *WebhookChannel) buildCustomPayload(msg RenderedMessage) ([]byte, error) {
	template := w.config.PayloadTemplate

	// Simple placeholder replacement
	replacements := map[string]string{
		"{{.Title}}":     msg.Title,
		"{{.Body}}":      msg.Body,
		"{{.BodyPlain}}": msg.BodyPlain,
		"{{.Priority}}":  msg.Priority.String(),
		"{{.Type}}":      string(msg.Type),
		"{{.Category}}":  msg.Type.Category(),
		"{{.Timestamp}}": msg.Timestamp.Format(time.RFC3339),
		"{{.Color}}":     msg.Color,
	}

	result := template
	for placeholder, value := range replacements {
		// Escape JSON special characters
		escaped, _ := json.Marshal(value)
		// Remove surrounding quotes from json.Marshal
		escapedStr := string(escaped[1 : len(escaped)-1])
		result = strings.ReplaceAll(result, placeholder, escapedStr)
	}

	// Validate JSON
	var js json.RawMessage
	if err := json.Unmarshal([]byte(result), &js); err != nil {
		return nil, fmt.Errorf("invalid JSON after template processing: %w", err)
	}

	return []byte(result), nil
}

// doRequest executes the HTTP request.
func (w *WebhookChannel) doRequest(ctx context.Context, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, w.config.Method, w.config.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type
	req.Header.Set("Content-Type", w.config.ContentType)

	// Set custom headers
	for key, value := range w.config.Headers {
		req.Header.Set(key, value)
	}

	// Apply authentication
	if err := w.applyAuth(req, payload); err != nil {
		return fmt.Errorf("failed to apply authentication: %w", err)
	}

	// Execute request
	resp, err := w.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// applyAuth adds authentication to the request.
func (w *WebhookChannel) applyAuth(req *http.Request, payload []byte) error {
	switch w.config.AuthType {
	case "", "none":
		return nil

	case "basic":
		username := w.config.AuthCredentials["username"]
		password := w.config.AuthCredentials["password"]
		if username == "" {
			return fmt.Errorf("basic auth requires username")
		}
		req.SetBasicAuth(username, password)

	case "bearer":
		token := w.config.AuthCredentials["token"]
		if token == "" {
			return fmt.Errorf("bearer auth requires token")
		}
		req.Header.Set("Authorization", "Bearer "+token)

	case "hmac":
		secret := w.config.AuthCredentials["secret"]
		header := w.config.AuthCredentials["header"]
		if secret == "" {
			return fmt.Errorf("hmac auth requires secret")
		}
		if header == "" {
			header = "X-Signature"
		}

		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(payload)
		signature := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set(header, "sha256="+signature)

	default:
		return fmt.Errorf("unsupported auth type: %s", w.config.AuthType)
	}

	return nil
}

// NewWebhookChannelFromSettings creates a WebhookChannel from generic settings map.
func NewWebhookChannelFromSettings(settings map[string]interface{}) (*WebhookChannel, error) {
	// Convert settings map to WebhookConfig
	data, err := json.Marshal(settings)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal settings: %w", err)
	}

	var config WebhookConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse webhook config: %w", err)
	}

	return NewWebhookChannel(config)
}
