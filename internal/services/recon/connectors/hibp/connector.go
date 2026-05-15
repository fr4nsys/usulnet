// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package hibp implements the Have-I-Been-Pwned recon connector. HIBP is
// the only optional external-API connector that ships in usulnet's
// recon module.
//
// Two responsibilities:
//
//  1. Satisfy recon.Connector — Kind / Enabled / HealthCheck. The health
//     check pings GET /api/v3/breaches with the user-supplied key and
//     asserts a 200; anything else (401, 429, 5xx) is reported as
//     unhealthy.
//
//  2. Produce recon.EngineEvent records for an email target when the
//     SpiderFoot engine's sfp_haveibeen module is not configured with an
//     upstream key. The Lookup method drives /breachedaccount/{account}
//     directly and maps responses into EngineEvent shape so the toolkit
//     dispatch loop can append them to a running scan.
//
// HIBP key material never appears in logs, error strings, or API
// responses. The connector keeps the key in memory only; persistence
// lives in recon_connectors (encrypted at rest) and is the caller's
// concern.
package hibp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// Kind is the stable identifier under which the connector registers in
// the recon_connectors table and in the /api/v1/recon/connectors API.
const Kind = "hibp"

// DefaultBaseURL is the production HIBP v3 API. Overridden by tests.
const DefaultBaseURL = "https://haveibeenpwned.com/api/v3"

// DefaultUserAgent is sent verbatim on every request. HIBP requires a
// non-empty, descriptive User-Agent header — opaque generic strings
// like "Go-http-client/1.1" are rejected with 403. Callers that want a
// version-stamped UA can override via Config.UserAgent.
const DefaultUserAgent = "usulnet-recon (+https://usulnet.com)"

// DefaultTimeout caps every HIBP HTTP roundtrip. HIBP enforces 1.5s
// between requests for the same key; 10 seconds is conservative.
const DefaultTimeout = 10 * time.Second

// CategoryBreach is the recon.Finding.Category every event from this
// connector carries. Exported so dispatchers and tests can assert on
// it without string-typing.
const CategoryBreach = "data_breach"

// Module is the engine-side module identifier we stamp on every
// EngineEvent we produce. Lined up with sfp_haveibeen so the UI and
// reports group HIBP findings into a single bucket regardless of
// whether SpiderFoot or this connector emitted them.
const Module = "sfp_haveibeen"

// SourceTag is the recon.Finding.Source value used so operators can
// trace which path emitted a finding (the connector, not SpiderFoot).
const SourceTag = "hibp-connector"

// Sentinel errors. Returned by Lookup and HealthCheck; never wrap a
// raw HIBP response body that may include the email back to the
// caller (the body can contain the PII we just sent up).
var (
	// ErrNoAPIKey is returned when the connector has no key configured.
	// Surfaced as "connector_unavailable" by the API layer.
	ErrNoAPIKey = errors.New("hibp: connector has no API key")

	// ErrUnauthorized is returned when HIBP rejects the key (401).
	ErrUnauthorized = errors.New("hibp: API key rejected (401)")

	// ErrRateLimited is returned on 429. Callers should back off.
	ErrRateLimited = errors.New("hibp: rate limited (429)")

	// ErrUnexpectedStatus is returned for any other non-2xx response.
	ErrUnexpectedStatus = errors.New("hibp: unexpected HTTP status")
)

// Config is the constructor input for the connector.
type Config struct {
	// APIKey is the HIBP v3 API key. Empty disables the connector;
	// HealthCheck still returns ErrNoAPIKey so the UI can render a
	// "key not set" indicator without 500ing.
	APIKey string

	// Enabled gates the connector's HealthCheck/Lookup paths even when
	// a key is present. Mirrors cfg.Recon.Connectors.HIBP.Enabled.
	Enabled bool

	// BaseURL overrides the production endpoint for tests. Empty →
	// DefaultBaseURL.
	BaseURL string

	// UserAgent overrides the default UA. Empty → DefaultUserAgent.
	UserAgent string

	// Timeout caps each HTTP roundtrip. Zero → DefaultTimeout.
	Timeout time.Duration
}

// Connector is the recon.Connector implementation for HIBP. It also
// exposes Lookup for the toolkit-engine adapter; the dispatch hook is
// kept narrow on purpose so unit tests do not need to spin up the
// whole recon.Service.
type Connector struct {
	cfg    Config
	client *http.Client
	log    *logger.Logger
}

// Compile-time interface assertion.
var _ recon.Connector = (*Connector)(nil)

// New constructs a Connector. A nil logger is fine; everything is
// logged through logger.Nop in that case. The configured APIKey is
// never echoed back; redaction tests assert this.
func New(cfg Config, log *logger.Logger) *Connector {
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.UserAgent == "" {
		cfg.UserAgent = DefaultUserAgent
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if log == nil {
		log = logger.Nop()
	}
	return &Connector{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
		log:    log.Named("recon.connector.hibp"),
	}
}

// Kind implements recon.Connector.
func (c *Connector) Kind() string { return Kind }

// Enabled implements recon.Connector. The connector is "enabled" only
// when both the feature toggle is on AND a key has been supplied. This
// matches the UI's expectation: a half-configured connector is shown
// as disabled, not "enabled but broken".
func (c *Connector) Enabled() bool {
	return c.cfg.Enabled && c.cfg.APIKey != ""
}

// HealthCheck implements recon.Connector. Pings GET /breaches with the
// configured key and asserts a 200. Returns ErrNoAPIKey when no key is
// set so the UI can render "needs configuration" without a 500. A
// non-200 response surfaces a typed sentinel error.
//
// /breaches is used (not /breachedaccount/foo@example.com) because it
// requires no PII in the URL and exercises the same auth path.
func (c *Connector) HealthCheck(ctx context.Context) error {
	if !c.cfg.Enabled {
		return nil
	}
	if c.cfg.APIKey == "" {
		return ErrNoAPIKey
	}
	req, err := c.newRequest(ctx, http.MethodGet, "/breaches", nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("hibp: health check: %w", err)
	}
	defer drain(resp.Body)
	return statusToErr(resp.StatusCode)
}

// Lookup queries /breachedaccount/{account}?truncateResponse=false for
// the supplied email and returns one EngineEvent per breach. An empty
// or nil result (HIBP returns 404 for "no breaches") yields zero
// events and a nil error — the engine should treat this as "clean".
//
// The supplied email is sent verbatim to HIBP (it is the entire point
// of the lookup) but never logged at info level: the connector emits
// only a value-hash prefix when tracing.
func (c *Connector) Lookup(ctx context.Context, email string) ([]recon.EngineEvent, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil, errors.New("hibp: lookup: empty email")
	}
	if !c.Enabled() {
		return nil, ErrNoAPIKey
	}

	path := "/breachedaccount/" + httpPathEscape(email) + "?truncateResponse=false"
	req, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hibp: lookup: %w", err)
	}
	defer drain(resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		// fall through and parse
	case http.StatusNotFound:
		// HIBP returns 404 when the email appears in zero breaches.
		return nil, nil
	default:
		return nil, statusToErr(resp.StatusCode)
	}

	var rows []breachRow
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rows); err != nil {
		return nil, fmt.Errorf("hibp: decode breaches: %w", err)
	}
	out := make([]recon.EngineEvent, 0, len(rows))
	for i := range rows {
		out = append(out, breachToEvent(email, &rows[i]))
	}
	return out, nil
}

// breachRow is the slice element shape returned by /breachedaccount.
// Only the fields we surface are decoded — anything else is dropped
// so HIBP can extend the schema without breaking us.
type breachRow struct {
	Name        string   `json:"Name"`
	Title       string   `json:"Title"`
	Domain      string   `json:"Domain"`
	BreachDate  string   `json:"BreachDate"`
	AddedDate   string   `json:"AddedDate"`
	PwnCount    int64    `json:"PwnCount"`
	DataClasses []string `json:"DataClasses"`
	IsVerified  bool     `json:"IsVerified"`
	IsSensitive bool     `json:"IsSensitive"`
}

// breachToEvent maps a HIBP row to a recon.EngineEvent. Severity is
// chosen by sensitivity:
//
//   - sensitive (incl. credentials/SSN-class fields) → high
//   - verified, non-sensitive → medium
//   - unverified                                   → low
//
// The raw payload is the JSON-encoded row; the encrypted-at-rest column
// in recon_findings_raw preserves it for forensic inspection.
func breachToEvent(email string, row *breachRow) recon.EngineEvent {
	sev := recon.SeverityLow
	switch {
	case row.IsSensitive || dataClassSensitive(row.DataClasses):
		sev = recon.SeverityHigh
	case row.IsVerified:
		sev = recon.SeverityMedium
	}
	value := row.Name
	if row.Title != "" {
		value = row.Title
	}
	raw, _ := json.Marshal(row)
	return recon.EngineEvent{
		Module:     Module,
		Category:   CategoryBreach,
		Severity:   sev,
		Value:      value,
		Source:     SourceTag,
		Confidence: 95,
		RawPayload: raw,
	}
}

// dataClassSensitive returns true when a breach's data classes include
// at least one credential-class field. HIBP's vocabulary is stable
// enough that a small allow-list is preferable to a free-form regex.
func dataClassSensitive(classes []string) bool {
	for _, c := range classes {
		switch strings.ToLower(strings.TrimSpace(c)) {
		case "passwords",
			"password hints",
			"security questions and answers",
			"credit card cvv",
			"credit cards",
			"bank account numbers",
			"social security numbers",
			"government-issued ids":
			return true
		}
	}
	return false
}

// newRequest builds an HIBP request with the standard headers. The
// API key is set on the hibp-api-key header per their docs.
func (c *Connector) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	url := c.cfg.BaseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("hibp: build request: %w", err)
	}
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("hibp-api-key", c.cfg.APIKey)
	return req, nil
}

// statusToErr maps a non-2xx HIBP HTTP status to a typed sentinel.
// 200 returns nil; everything else returns a wrapped sentinel that
// callers can match with errors.Is.
func statusToErr(code int) error {
	switch {
	case code >= 200 && code < 300:
		return nil
	case code == http.StatusUnauthorized:
		return ErrUnauthorized
	case code == http.StatusTooManyRequests:
		return ErrRateLimited
	default:
		return fmt.Errorf("%w: %d", ErrUnexpectedStatus, code)
	}
}

// httpPathEscape percent-encodes an email address for embedding in a
// path segment without converting "+" / "@" the way url.QueryEscape
// would. HIBP's docs explicitly call out that the local-part should
// be percent-encoded; net/url's PathEscape does the right thing.
func httpPathEscape(s string) string {
	// Inline a minimal allow-list rather than pulling in net/url just
	// for this. RFC 3986 unreserved + a few pchars suffices.
	const allow = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" +
		"0123456789-._~!$&'()*+,;=:@"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.IndexByte(allow, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// drain reads-and-closes the response body so the underlying connection
// can be reused. Failures are intentionally swallowed: we already have
// the status code and any caller-visible error.
func drain(r io.ReadCloser) {
	if r == nil {
		return
	}
	_, _ = io.Copy(io.Discard, r)
	_ = r.Close()
}
