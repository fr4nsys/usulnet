// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package caddy provides an HTTP client for the Caddy v2 Admin API.
// It generates and pushes JSON configuration to Caddy for reverse proxy management.
package caddy

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

// Config holds the connection settings for the Caddy admin API.
type Config struct {
	// AdminURL is the base URL of Caddy's admin API (default: http://localhost:2019).
	AdminURL string
	// Timeout for HTTP requests.
	Timeout time.Duration
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		AdminURL: "http://localhost:2019",
		Timeout:  10 * time.Second,
	}
}

// Client communicates with the Caddy v2 admin API.
type Client struct {
	cfg    Config
	http   *http.Client
}

// NewClient creates a new Caddy admin API client.
func NewClient(cfg Config) *Client {
	if cfg.AdminURL == "" {
		cfg.AdminURL = "http://localhost:2019"
	}
	cfg.AdminURL = strings.TrimRight(cfg.AdminURL, "/")

	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	return &Client{
		cfg: cfg,
		http: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// ---- Low-level API methods ----

// Load replaces the entire Caddy configuration atomically.
// POST /load
func (c *Client) Load(ctx context.Context, config *CaddyConfig) error {
	body, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("caddy: marshal config: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.AdminURL+"/load", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("caddy: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("caddy: load config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.readError(resp)
	}
	return nil
}

// GetConfig retrieves the current Caddy configuration (or a sub-path).
// GET /config/[path]
func (c *Client) GetConfig(ctx context.Context, path string) (json.RawMessage, error) {
	url := c.cfg.AdminURL + "/config/"
	if path != "" {
		url += strings.TrimLeft(path, "/")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("caddy: get config %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // path doesn't exist yet
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.readError(resp)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}

// SetConfig sets a value at a specific config path.
// POST /config/[path]
func (c *Client) SetConfig(ctx context.Context, path string, value interface{}) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}

	url := c.cfg.AdminURL + "/config/" + strings.TrimLeft(path, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("caddy: set config %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.readError(resp)
	}
	return nil
}

// DeleteConfig deletes a value at a specific config path.
// DELETE /config/[path]
func (c *Client) DeleteConfig(ctx context.Context, path string) error {
	url := c.cfg.AdminURL + "/config/" + strings.TrimLeft(path, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("caddy: delete config %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.readError(resp)
	}
	return nil
}

// Healthy checks if Caddy's admin API is reachable.
func (c *Client) Healthy(ctx context.Context) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.AdminURL+"/config/", nil)
	if err != nil {
		return false, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return false, nil // Not reachable, but not an error per se
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}

// UpstreamStatus returns the health status of reverse_proxy upstreams.
// GET /reverse_proxy/upstreams
func (c *Client) UpstreamStatus(ctx context.Context) ([]UpstreamStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.AdminURL+"/reverse_proxy/upstreams", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("caddy: upstream status: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.readError(resp)
	}

	var statuses []UpstreamStatus
	if err := json.NewDecoder(resp.Body).Decode(&statuses); err != nil {
		return nil, err
	}
	return statuses, nil
}

// readError reads the error body from a non-200 response.
func (c *Client) readError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("caddy: HTTP %d: %s", resp.StatusCode, string(body))
}

// UpstreamStatus represents the health of an upstream backend.
type UpstreamStatus struct {
	Address     string `json:"address"`
	NumRequests int    `json:"num_requests"`
	Fails       int    `json:"fails"`
	Healthy     bool   `json:"healthy"`
}
