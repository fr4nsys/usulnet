// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package spiderfoot is the recon.Engine adapter for the SpiderFoot
// OSINT engine running inside the usulnet/recon-spiderfoot container.
//
// The adapter is a thin HTTP client over SpiderFoot's web API:
// /scanstartlist, /scanstatus, /scaneventresults, /scandelete. The
// container's web UI is bound to a private network managed by the
// sandbox launcher; the client talks to it via the URL the launcher
// returns.
package spiderfoot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultRequestTimeout is the per-request timeout used when the
// caller does not override it.
const DefaultRequestTimeout = 30 * time.Second

// SpiderFoot status strings, exposed for tests and the engine's
// status mapper. These are the literal values SpiderFoot returns in
// the /scanstatus payload.
const (
	StatusCreated  = "CREATED"
	StatusStarting = "STARTING"
	StatusStarted  = "STARTED"
	StatusRunning  = "RUNNING"
	StatusFinished = "FINISHED"
	StatusAborted  = "ABORTED"

	// StatusAbortRequested is the transient state between /scandelete
	// being accepted and SpiderFoot actually stopping the modules.
	StatusAbortRequested = "ABORT-REQUESTED"
)

// ErrorPrefix is the prefix SpiderFoot uses for terminal failure
// statuses (e.g., ERROR-FAILED). The engine maps anything beginning
// with this prefix to ScanFailed.
const ErrorPrefix = "ERROR-"

// Sentinel errors so callers can distinguish failure modes without
// substring matching.
var (
	// ErrEmptyBaseURL is returned when NewClient is called with a
	// blank base URL.
	ErrEmptyBaseURL = errors.New("spiderfoot: empty base URL")

	// ErrUnexpectedStatus is returned when SpiderFoot answers with a
	// non-2xx HTTP status.
	ErrUnexpectedStatus = errors.New("spiderfoot: unexpected http status")

	// ErrAPIError is returned when SpiderFoot's JSON response carries
	// an ERROR code in the first element of the response array.
	ErrAPIError = errors.New("spiderfoot: api error")

	// ErrScanNotFound is returned when /scanstatus reports an unknown
	// scan ID (SpiderFoot answers with an empty body for that case).
	ErrScanNotFound = errors.New("spiderfoot: scan not found")
)

// Client is a typed wrapper over net/http for the SpiderFoot API.
// It is safe for concurrent use because *http.Client is.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient returns a Client bound to baseURL. If timeout is zero or
// negative, DefaultRequestTimeout is used.
func NewClient(baseURL string, timeout time.Duration) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, ErrEmptyBaseURL
	}
	if timeout <= 0 {
		timeout = DefaultRequestTimeout
	}
	return &Client{
		baseURL: baseURL,
		http: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

// BaseURL returns the configured base URL (without a trailing slash).
func (c *Client) BaseURL() string { return c.baseURL }

// ScanStatus is SpiderFoot's response from /scanstatus. SpiderFoot
// returns a JSON array shaped:
//
//	[name, target, created, started, ended, status]
//
// We decode positionally and expose the fields by name.
type ScanStatus struct {
	Name    string
	Target  string
	Created string
	Started string
	Ended   string
	Status  string
}

// ScanEvent is one row from /scaneventresults. SpiderFoot returns a
// JSON array per event:
//
//	[generated, data, source_data, source_module, event_type,
//	 confidence, visibility, risk, hash, ...]
//
// The trailing fields vary slightly across versions; we decode the
// stable prefix.
type ScanEvent struct {
	Generated    string
	Data         string
	SourceData   string
	SourceModule string
	EventType    string
	Confidence   int
	Visibility   int
	Risk         int
	Hash         string
}

// StartScan issues POST /scanstartlist with a name, target, and an
// explicit module list. SpiderFoot expects each module name to be
// prefixed by "module_" in the form value (its WebUI builds the same
// string from the module checkboxes). The function adds the prefix
// for the caller — pass plain SpiderFoot module names ("sfp_crt"),
// not "module_sfp_crt".
//
// On success it returns the engine-side scan ID.
func (c *Client) StartScan(ctx context.Context, name, target string, modules []string) (string, error) {
	form := url.Values{}
	form.Set("scanname", name)
	form.Set("scantarget", target)
	form.Set("modulelist", encodeModuleList(modules))
	// typelist and usecase are required form fields by SpiderFoot
	// even when modulelist is the actual selector. Empty strings are
	// fine.
	form.Set("typelist", "")
	form.Set("usecase", "")

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		c.baseURL+"/scanstartlist",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("spiderfoot: build scanstartlist request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	body, err := c.do(req)
	if err != nil {
		return "", err
	}

	// SpiderFoot returns ["SUCCESS", "", "<scanID>"] or
	// ["ERROR", "<message>"].
	var resp []string
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("spiderfoot: decode scanstartlist response: %w (body=%q)", err, string(body))
	}
	if len(resp) == 0 {
		return "", fmt.Errorf("%w: empty scanstartlist response", ErrAPIError)
	}
	if resp[0] != "SUCCESS" {
		msg := ""
		if len(resp) > 1 {
			msg = resp[1]
		}
		return "", fmt.Errorf("%w: %s", ErrAPIError, msg)
	}
	if len(resp) < 3 || resp[2] == "" {
		return "", fmt.Errorf("%w: missing scan id", ErrAPIError)
	}
	return resp[2], nil
}

// ScanStatus issues GET /scanstatus?id=<id>.
func (c *Client) ScanStatus(ctx context.Context, scanID string) (*ScanStatus, error) {
	q := url.Values{}
	q.Set("id", scanID)
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet,
		c.baseURL+"/scanstatus?"+q.Encode(),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("spiderfoot: build scanstatus request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	// SpiderFoot returns "" or "[]" when the scan id is unknown.
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" || trimmed == "[]" || trimmed == "null" {
		return nil, ErrScanNotFound
	}

	var raw []string
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("spiderfoot: decode scanstatus response: %w (body=%q)", err, string(body))
	}
	if len(raw) < 6 {
		return nil, fmt.Errorf("spiderfoot: scanstatus malformed: %q", string(body))
	}
	return &ScanStatus{
		Name:    raw[0],
		Target:  raw[1],
		Created: raw[2],
		Started: raw[3],
		Ended:   raw[4],
		Status:  raw[5],
	}, nil
}

// ScanEventResults issues GET /scaneventresults?id=<id>&eventType=ALL.
// SpiderFoot streams every event from the start of the scan; the
// engine de-duplicates client-side by the event hash.
func (c *Client) ScanEventResults(ctx context.Context, scanID string) ([]ScanEvent, error) {
	q := url.Values{}
	q.Set("id", scanID)
	q.Set("eventType", "ALL")
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet,
		c.baseURL+"/scaneventresults?"+q.Encode(),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("spiderfoot: build scaneventresults request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	body, err := c.do(req)
	if err != nil {
		return nil, err
	}

	// Each row is a heterogeneous array. We decode the prefix using
	// json.RawMessage so trailing fields don't break us.
	var rows [][]json.RawMessage
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("spiderfoot: decode scaneventresults response: %w (body=%q)", err, truncate(string(body)))
	}
	out := make([]ScanEvent, 0, len(rows))
	for _, row := range rows {
		evt, err := parseEventRow(row)
		if err != nil {
			// Skip malformed rows; they're not actionable but we
			// don't want a single bad row to kill the stream.
			continue
		}
		out = append(out, evt)
	}
	return out, nil
}

// DeleteScan issues POST /scandelete?id=<id>. SpiderFoot uses the
// same endpoint for "abort + delete"; the scan transitions to
// ABORT-REQUESTED and then ABORTED.
func (c *Client) DeleteScan(ctx context.Context, scanID string) error {
	q := url.Values{}
	q.Set("id", scanID)
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		c.baseURL+"/scandelete?"+q.Encode(),
		nil,
	)
	if err != nil {
		return fmt.Errorf("spiderfoot: build scandelete request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	body, err := c.do(req)
	if err != nil {
		return err
	}
	// Response is either ["SUCCESS", ""] or ["ERROR", "<msg>"]. An
	// already-deleted scan returns SUCCESS; treat empty body as
	// success too because SpiderFoot has historically returned 200
	// with no body for this endpoint.
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil
	}
	var resp []string
	if err := json.Unmarshal(body, &resp); err != nil {
		// SpiderFoot occasionally returns non-JSON on 200; treated as a
		// successful no-op rather than a hard failure.
		return nil //nolint:nilerr
	}
	if len(resp) > 0 && resp[0] != "SUCCESS" {
		msg := ""
		if len(resp) > 1 {
			msg = resp[1]
		}
		return fmt.Errorf("%w: %s", ErrAPIError, msg)
	}
	return nil
}

// do executes a request, reading and returning the body. It maps
// non-2xx into ErrUnexpectedStatus so callers can wrap intelligently.
func (c *Client) do(req *http.Request) ([]byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("spiderfoot: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("spiderfoot: read %s: %w", req.URL.Path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return body, fmt.Errorf("%w: %d %s (path=%s)", ErrUnexpectedStatus, resp.StatusCode, resp.Status, req.URL.Path)
	}
	return body, nil
}

// encodeModuleList renders a slice of SpiderFoot module names as the
// comma-separated string SpiderFoot's WebUI submits ("module_<name>").
// An empty input yields an empty string, which SpiderFoot rejects with
// an error — the engine is responsible for ensuring the list is
// non-empty before calling StartScan.
func encodeModuleList(mods []string) string {
	if len(mods) == 0 {
		return ""
	}
	parts := make([]string, 0, len(mods))
	for _, m := range mods {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if !strings.HasPrefix(m, "module_") {
			m = "module_" + m
		}
		parts = append(parts, m)
	}
	return strings.Join(parts, ",")
}

// parseEventRow decodes the heterogeneous JSON row that
// /scaneventresults returns per event. SpiderFoot's row layout is
// stable for the first 5 string fields and the 3 integer columns; we
// tolerate optional trailing columns.
func parseEventRow(row []json.RawMessage) (ScanEvent, error) {
	if len(row) < 5 {
		return ScanEvent{}, fmt.Errorf("event row too short: %d", len(row))
	}
	var evt ScanEvent
	if err := json.Unmarshal(row[0], &evt.Generated); err != nil {
		// SpiderFoot sometimes emits epoch-as-number for "generated".
		var ts float64
		if jerr := json.Unmarshal(row[0], &ts); jerr != nil {
			return ScanEvent{}, fmt.Errorf("generated: %w", err)
		}
		evt.Generated = fmt.Sprintf("%.0f", ts)
	}
	if err := json.Unmarshal(row[1], &evt.Data); err != nil {
		return ScanEvent{}, fmt.Errorf("data: %w", err)
	}
	if err := json.Unmarshal(row[2], &evt.SourceData); err != nil {
		return ScanEvent{}, fmt.Errorf("source_data: %w", err)
	}
	if err := json.Unmarshal(row[3], &evt.SourceModule); err != nil {
		return ScanEvent{}, fmt.Errorf("source_module: %w", err)
	}
	if err := json.Unmarshal(row[4], &evt.EventType); err != nil {
		return ScanEvent{}, fmt.Errorf("event_type: %w", err)
	}
	if len(row) > 5 {
		_ = json.Unmarshal(row[5], &evt.Confidence)
	}
	if len(row) > 6 {
		_ = json.Unmarshal(row[6], &evt.Visibility)
	}
	if len(row) > 7 {
		_ = json.Unmarshal(row[7], &evt.Risk)
	}
	if len(row) > 8 {
		_ = json.Unmarshal(row[8], &evt.Hash)
	}
	return evt, nil
}

// truncate clips a string to a sane length for inclusion in error
// messages so we never spam logs with a megabyte of HTML.
func truncate(s string) string {
	const max = 256
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
