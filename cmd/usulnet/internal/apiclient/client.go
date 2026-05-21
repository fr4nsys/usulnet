// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package apiclient is the minimal HTTP client used by the usulnet CLI to
// talk to the local server's /api/v1/recon and /api/v1/metadata endpoints.
//
// It lives in cmd/usulnet/internal/ so it's only importable from the CLI
// binary. The package exposes typed errors (ErrConfig, ErrNetwork, ErrAuth,
// ErrStatus) so the CLI's exit-code translator (cmd/usulnet/recon.go's
// hasReconError) can map them to the documented codes (70/71/72) without
// the apiclient package needing to know about exit codes.
package apiclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// EnvBaseURL is the env var consulted when Options.BaseURL is empty.
	EnvBaseURL = "USULNET_API_URL"
	// EnvToken is the env var consulted when Options.Token is empty.
	EnvToken = "USULNET_API_TOKEN"
	// DefaultTimeout is the default value for Options.Timeout.
	DefaultTimeout = 30 * time.Second
)

// Client wraps the local server's HTTP API. Constructed via New.
type Client struct {
	baseURL string
	token   string
	hc      *http.Client
}

// Options are constructor options for Client. Empty fields are resolved
// from the environment (EnvBaseURL / EnvToken).
type Options struct {
	BaseURL string
	Token   string
	Timeout time.Duration
}

// New resolves connection info from opts then env, validating that at
// least a base URL is configured.
func New(opts Options) (*Client, error) {
	if opts.BaseURL == "" {
		opts.BaseURL = os.Getenv(EnvBaseURL)
	}
	if opts.Token == "" {
		opts.Token = os.Getenv(EnvToken)
	}
	if opts.BaseURL == "" {
		return nil, &ErrConfig{Msg: "no API URL configured: set --server or $" + EnvBaseURL}
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	return &Client{
		baseURL: strings.TrimRight(opts.BaseURL, "/"),
		token:   opts.Token,
		hc:      &http.Client{Timeout: opts.Timeout},
	}, nil
}

// BaseURL returns the configured base URL with any trailing slash removed.
func (c *Client) BaseURL() string { return c.baseURL }

// Token returns the configured bearer token. Empty when no token is set.
func (c *Client) Token() string { return c.token }

// HTTPClient exposes the underlying *http.Client for callers that need to
// build a request manually (e.g. streaming raw bytes). Use Do/Stream for
// the common JSON / SSE cases.
func (c *Client) HTTPClient() *http.Client { return c.hc }

// NewRequest builds an http.Request bound to the client's BaseURL with
// the Authorization header set when a Token is configured. Use it for
// non-JSON paths (multipart upload, raw byte download) before calling
// HTTPClient().Do(req); for the common JSON case use Do().
func (c *Client) NewRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return req, nil
}

// Do executes a JSON request and decodes the response into out when non-nil.
//
//   - On a transport-level failure (dial timeout, refused, etc.) returns
//     *ErrNetwork.
//   - On HTTP 401 / 403 returns *ErrAuth.
//   - On any other 4xx / 5xx returns *ErrStatus with the response body
//     truncated to 4 KiB.
//   - On 2xx with out != nil, decodes the response body as JSON.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return &ErrNetwork{Op: fmt.Sprintf("%s %s", method, path), Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return &ErrAuth{Method: method, Path: path, Status: resp.Status}
	}
	if resp.StatusCode >= 400 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &ErrStatus{Method: method, Path: path, Status: resp.Status, Body: bytes.TrimSpace(buf)}
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Stream issues a GET that consumes a text/event-stream response, invoking
// onEvent for each parsed SSE event until the context is canceled or the
// stream closes. Lines starting with ":" (SSE comments / heartbeats) are
// silently dropped.
func (c *Client) Stream(ctx context.Context, path string, onEvent func(event, data string)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	// SSE keeps the connection open — bypass the Do() Client's Timeout.
	hc := &http.Client{Timeout: 0}
	resp, err := hc.Do(req)
	if err != nil {
		return &ErrNetwork{Op: "stream " + path, Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return &ErrStatus{Method: http.MethodGet, Path: path, Status: resp.Status}
	}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var event, data string
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			if data != "" {
				onEvent(event, data)
			}
			event, data = "", ""
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			if data != "" {
				data += "\n"
			}
			data += strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		}
	}
	return scanner.Err()
}

// =============================================================================
// Typed errors — callers translate these to exit codes.
// =============================================================================

// ErrConfig signals a missing configuration value (typically no BaseURL).
type ErrConfig struct{ Msg string }

func (e *ErrConfig) Error() string { return e.Msg }

// ErrNetwork wraps a transport-level failure (dial, TLS, timeout). The
// underlying error is accessible via the Err field.
type ErrNetwork struct {
	Op  string
	Err error
}

func (e *ErrNetwork) Error() string { return fmt.Sprintf("api %s: %v", e.Op, e.Err) }
func (e *ErrNetwork) Unwrap() error { return e.Err }

// ErrAuth signals an HTTP 401 or 403 response.
type ErrAuth struct {
	Method string
	Path   string
	Status string
}

func (e *ErrAuth) Error() string {
	return fmt.Sprintf("api %s %s: %s", e.Method, e.Path, e.Status)
}

// ErrStatus signals any non-2xx HTTP response that is not an ErrAuth.
// Body is truncated to 4 KiB by Do().
type ErrStatus struct {
	Method string
	Path   string
	Status string
	Body   []byte
}

func (e *ErrStatus) Error() string {
	if len(e.Body) == 0 {
		return fmt.Sprintf("api %s %s: %s", e.Method, e.Path, e.Status)
	}
	return fmt.Sprintf("api %s %s: %s: %s", e.Method, e.Path, e.Status, e.Body)
}
