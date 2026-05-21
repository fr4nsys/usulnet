// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package shodan implements the Shodan recon connector. Shodan is an
// optional bring-your-own-key connector that lands in v26.5.2 alongside
// the existing HIBP connector. It is the BYO-key fallback path used
// when SpiderFoot's sfp_shodan module is not configured with an
// upstream key — operators with a configured SpiderFoot module do not
// need this connector.
//
// Two responsibilities:
//
//  1. Satisfy recon.Connector — Kind / Enabled / HealthCheck. The
//     health check pings GET /api-info with the user-supplied key and
//     asserts a 200 carrying the documented query_credits field.
//
//  2. Produce recon.EngineEvent records for ip, domain (hostname), and
//     ip_range (cidr) targets when the engine layer fans a lookup out
//     to the connector. Lookup maps the relevant Shodan endpoint
//     responses into EngineEvent shape so the toolkit dispatch loop
//     can append them to a running scan.
//
// Shodan key material never appears in logs, error strings, or API
// responses. Because Shodan's API requires the key in the query string
// (it does not accept a header) the connector wraps every
// net/http roundtrip error through scrubErr, which redacts the key
// out of url.Error.Error() before the error reaches a caller. The
// connector keeps the key in memory only; persistence lives in
// recon_connectors (encrypted at rest) and is the caller's concern.
package shodan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// Kind is the stable identifier under which the connector registers in
// the recon_connectors table and in the /api/v1/recon/connectors API.
const Kind = "shodan"

// DefaultBaseURL is the production Shodan REST API. Overridden by tests.
const DefaultBaseURL = "https://api.shodan.io"

// DefaultUserAgent is sent verbatim on every request. Shodan does not
// enforce a UA shape, but having a descriptive one helps operators
// trace traffic in their Shodan account dashboard.
const DefaultUserAgent = "usulnet-recon (+https://usulnet.com)"

// DefaultTimeout caps every Shodan HTTP roundtrip. Shodan's freelancer
// tier is rate-limited at ~1 request per second; 10 seconds is a
// conservative ceiling on any single call.
const DefaultTimeout = 10 * time.Second

// CategoryExposedService is the recon.Finding.Category every Shodan
// host-lookup event carries. Exported so dispatchers and tests can
// assert on it without string-typing.
const CategoryExposedService = "exposed_service"

// CategoryDNSResolution is the Finding.Category used when a hostname
// lookup is mapped into one event per resolved IP. The downstream
// caller typically follows up with an ip-kind Lookup against each
// emitted address.
const CategoryDNSResolution = "dns_resolution"

// Module is the engine-side module identifier we stamp on every
// EngineEvent we produce. Lined up with sfp_shodan so the UI and
// reports group Shodan findings into a single bucket regardless of
// whether SpiderFoot or this connector emitted them.
const Module = "sfp_shodan"

// SourceTag is the recon.Finding.Source value used so operators can
// trace which path emitted a finding (the connector, not SpiderFoot).
const SourceTag = "shodan-connector"

// redactionSentinel is the fixed string substituted for the API key
// in any error message that would otherwise echo the configured key
// (e.g., url.Error from net/http). The constant is exported so tests
// can assert on it directly.
const redactionSentinel = "REDACTED"

// Sentinel errors. Returned by Lookup and HealthCheck; the body of a
// failed response is never wrapped back to the caller because it can
// contain the query (which for ip / cidr lookups is the user-supplied
// target the operator is mapping).
var (
	// ErrNoAPIKey is returned when the connector has no key configured.
	// Surfaced as "connector_unavailable" by the API layer.
	ErrNoAPIKey = errors.New("shodan: connector has no API key")

	// ErrUnauthorized is returned when Shodan rejects the key (401).
	ErrUnauthorized = errors.New("shodan: API key rejected (401)")

	// ErrRateLimited is returned on 429. Callers should back off.
	ErrRateLimited = errors.New("shodan: rate limited (429)")

	// ErrUnexpectedStatus is returned for any other non-2xx response.
	ErrUnexpectedStatus = errors.New("shodan: unexpected HTTP status")

	// ErrUnsupportedTarget is returned by Lookup when the target kind
	// is outside {ip, domain, ip_range}. Mirrors HIBP's pattern of a
	// per-connector sentinel so the dispatcher loop can handle it
	// gracefully without dropping the rest of the scan.
	ErrUnsupportedTarget = errors.New("shodan: target type unsupported")

	// ErrInvalidTargetValue is returned when the target value is empty
	// or malformed for the supplied kind (non-IP for ip, non-CIDR for
	// ip_range, etc.).
	ErrInvalidTargetValue = errors.New("shodan: target value invalid")

	// ErrUnhealthyResponse is returned by HealthCheck when /api-info
	// answers 200 but the response body is missing query_credits.
	ErrUnhealthyResponse = errors.New("shodan: /api-info response missing query_credits")
)

// Config is the constructor input for the connector.
type Config struct {
	// APIKey is the Shodan API key. Empty disables the connector;
	// HealthCheck still returns ErrNoAPIKey so the UI can render a
	// "key not set" indicator without 500ing.
	APIKey string

	// Enabled gates the connector's HealthCheck/Lookup paths even when
	// a key is present. Mirrors cfg.Recon.Connectors.Shodan.Enabled.
	Enabled bool

	// BaseURL overrides the production endpoint for tests. Empty →
	// DefaultBaseURL.
	BaseURL string

	// UserAgent overrides the default UA. Empty → DefaultUserAgent.
	UserAgent string

	// Timeout caps each HTTP roundtrip. Zero → DefaultTimeout.
	Timeout time.Duration
}

// Connector is the recon.Connector implementation for Shodan. It also
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
		log:    log.Named("recon.connector.shodan"),
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

// HealthCheck implements recon.Connector. Pings GET /api-info with the
// configured key and asserts a 200 whose body decodes to a struct
// carrying query_credits. Returns ErrNoAPIKey when no key is set so
// the UI can render "needs configuration" without a 500. A non-200
// response surfaces a typed sentinel error.
//
// /api-info is used (rather than /shodan/host/{ip} or a search query)
// because it requires no target in the URL and consumes no query
// credits — it exercises the auth path only.
func (c *Connector) HealthCheck(ctx context.Context) error {
	if !c.cfg.Enabled {
		return nil
	}
	if c.cfg.APIKey == "" {
		return ErrNoAPIKey
	}
	resp, err := c.do(ctx, "/api-info", nil)
	if err != nil {
		return err
	}
	defer drain(resp.Body)
	if err := statusToErr(resp.StatusCode); err != nil {
		return err
	}
	var info apiInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info); err != nil {
		return fmt.Errorf("shodan: decode /api-info: %w", err)
	}
	if info.QueryCredits == nil {
		return ErrUnhealthyResponse
	}
	return nil
}

// Lookup queries Shodan for the supplied target and returns one
// EngineEvent per service / resolved IP / match (the exact shape
// depends on the target kind):
//
//   - recon.TargetIP       → GET /shodan/host/{ip}        one event per port/service
//   - recon.TargetDomain   → GET /dns/resolve?hostnames=  one event per resolved IP
//   - recon.TargetIPRange  → GET /shodan/host/search      one event per match (capped at MaxSearchResults)
//
// An empty result (Shodan returns 404 for hosts with no observations,
// or an empty matches array for a search with zero hits) yields zero
// events and a nil error — the engine should treat this as "no
// exposure observed".
//
// The supplied value is sent verbatim to Shodan as part of the query
// (it is the entire point of the lookup) but never logged at info
// level — the connector emits only a value-hash prefix when tracing.
func (c *Connector) Lookup(ctx context.Context, kind recon.TargetType, value string) ([]recon.EngineEvent, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("%w: empty value", ErrInvalidTargetValue)
	}
	if !c.Enabled() {
		return nil, ErrNoAPIKey
	}

	switch kind {
	case recon.TargetIP:
		if net.ParseIP(value) == nil {
			return nil, fmt.Errorf("%w: %q is not a valid IP address", ErrInvalidTargetValue, value)
		}
		return c.lookupHost(ctx, value)
	case recon.TargetDomain:
		return c.lookupHostname(ctx, strings.ToLower(value))
	case recon.TargetIPRange:
		if _, _, err := net.ParseCIDR(value); err != nil {
			return nil, fmt.Errorf("%w: %q is not a valid CIDR", ErrInvalidTargetValue, value)
		}
		return c.lookupCIDR(ctx, value)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedTarget, kind)
	}
}

// MaxSearchResults caps the number of search hits returned from a
// /shodan/host/search call. One event per match is emitted; on the
// freelancer tier each search burns one query credit per page, so the
// cap doubles as a credit safeguard.
const MaxSearchResults = 100

// ---------------------------------------------------------------------
// Per-kind lookup helpers
// ---------------------------------------------------------------------

func (c *Connector) lookupHost(ctx context.Context, ip string) ([]recon.EngineEvent, error) {
	resp, err := c.do(ctx, "/shodan/host/"+ip, nil)
	if err != nil {
		return nil, err
	}
	defer drain(resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		// fall through
	case http.StatusNotFound:
		// Shodan returns 404 when the IP has no observed services.
		return nil, nil
	default:
		return nil, statusToErr(resp.StatusCode)
	}

	var host hostResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&host); err != nil {
		return nil, fmt.Errorf("shodan: decode /shodan/host: %w", err)
	}
	out := make([]recon.EngineEvent, 0, len(host.Data))
	for i := range host.Data {
		out = append(out, hostServiceToEvent(ip, &host, &host.Data[i]))
	}
	return out, nil
}

func (c *Connector) lookupHostname(ctx context.Context, hostname string) ([]recon.EngineEvent, error) {
	params := url.Values{"hostnames": []string{hostname}}
	resp, err := c.do(ctx, "/dns/resolve", params)
	if err != nil {
		return nil, err
	}
	defer drain(resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		// fall through
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, statusToErr(resp.StatusCode)
	}

	var resolved map[string]string
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&resolved); err != nil {
		return nil, fmt.Errorf("shodan: decode /dns/resolve: %w", err)
	}
	out := make([]recon.EngineEvent, 0, len(resolved))
	for h, ip := range resolved {
		if ip == "" {
			continue
		}
		out = append(out, dnsResolveToEvent(h, ip))
	}
	return out, nil
}

func (c *Connector) lookupCIDR(ctx context.Context, cidr string) ([]recon.EngineEvent, error) {
	params := url.Values{"query": []string{"net:" + cidr}}
	resp, err := c.do(ctx, "/shodan/host/search", params)
	if err != nil {
		return nil, err
	}
	defer drain(resp.Body)
	if err := statusToErr(resp.StatusCode); err != nil {
		return nil, err
	}

	var search searchResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&search); err != nil {
		return nil, fmt.Errorf("shodan: decode /shodan/host/search: %w", err)
	}
	limit := len(search.Matches)
	if limit > MaxSearchResults {
		limit = MaxSearchResults
	}
	out := make([]recon.EngineEvent, 0, limit)
	for i := 0; i < limit; i++ {
		out = append(out, searchMatchToEvent(cidr, &search.Matches[i]))
	}
	return out, nil
}

// ---------------------------------------------------------------------
// Wire types — only the fields we surface are decoded so Shodan can
// extend the schema without breaking us.
// ---------------------------------------------------------------------

// apiInfo decodes the documented subset of GET /api-info. query_credits
// is a *int64 so HealthCheck can distinguish "0 credits left" (still a
// valid healthy response) from "field absent" (broken payload).
type apiInfo struct {
	QueryCredits *int64 `json:"query_credits"`
	ScanCredits  *int64 `json:"scan_credits"`
	Plan         string `json:"plan"`
}

// hostResponse is the documented subset of GET /shodan/host/{ip}.
type hostResponse struct {
	IP        string     `json:"ip_str"`
	Hostnames []string   `json:"hostnames"`
	Country   string     `json:"country_name"`
	Org       string     `json:"org"`
	OS        string     `json:"os"`
	Ports     []int      `json:"ports"`
	Vulns     []string   `json:"vulns"`
	Data      []hostData `json:"data"`
}

// hostData is one observed service on a host.
type hostData struct {
	Port      int      `json:"port"`
	Transport string   `json:"transport"`
	Product   string   `json:"product"`
	Version   string   `json:"version"`
	Banner    string   `json:"data"`
	Hostnames []string `json:"hostnames"`
	Vulns     []string `json:"vulns"`
}

// searchResponse is the documented subset of GET /shodan/host/search.
type searchResponse struct {
	Total   int           `json:"total"`
	Matches []searchMatch `json:"matches"`
}

// searchMatch is one row in a search response.
type searchMatch struct {
	IP        string   `json:"ip_str"`
	Port      int      `json:"port"`
	Transport string   `json:"transport"`
	Product   string   `json:"product"`
	Version   string   `json:"version"`
	Hostnames []string `json:"hostnames"`
	Vulns     []string `json:"vulns"`
}

// ---------------------------------------------------------------------
// Wire → EngineEvent mapping
// ---------------------------------------------------------------------

// hostServiceToEvent maps one observed service on a host into an
// EngineEvent. Severity rules:
//
//   - any CVE in this service's vulns → high
//   - service belongs to a "sensitive" port (SSH/RDP/DB/etc) → medium
//   - otherwise (HTTP / HTTPS / banner-only) → low
//
// The raw payload is the JSON-encoded service row; the
// encrypted-at-rest column in recon_findings_raw preserves the full
// detail for forensic inspection.
func hostServiceToEvent(ip string, host *hostResponse, svc *hostData) recon.EngineEvent {
	sev := recon.SeverityLow
	switch {
	case len(svc.Vulns) > 0:
		sev = recon.SeverityHigh
	case isSensitivePort(svc.Port):
		sev = recon.SeverityMedium
	}
	value := formatService(ip, svc)
	raw, _ := json.Marshal(serviceFinding{
		IP:        ip,
		Port:      svc.Port,
		Transport: svc.Transport,
		Product:   svc.Product,
		Version:   svc.Version,
		Hostnames: pickHostnames(svc.Hostnames, host.Hostnames),
		Vulns:     svc.Vulns,
		Org:       host.Org,
		Country:   host.Country,
	})
	return recon.EngineEvent{
		Module:     Module,
		Category:   CategoryExposedService,
		Severity:   sev,
		Value:      value,
		Source:     SourceTag,
		Confidence: 90,
		RawPayload: raw,
	}
}

// dnsResolveToEvent maps one (hostname, ip) pair into an info-severity
// event. The downstream caller typically follows up with an ip-kind
// Lookup against the emitted address; the event itself doesn't carry
// service information, just the resolution.
func dnsResolveToEvent(hostname, ip string) recon.EngineEvent {
	raw, _ := json.Marshal(map[string]string{
		"hostname": hostname,
		"ip":       ip,
	})
	return recon.EngineEvent{
		Module:     Module,
		Category:   CategoryDNSResolution,
		Severity:   recon.SeverityInfo,
		Value:      hostname + " → " + ip,
		Source:     SourceTag,
		Confidence: 95,
		RawPayload: raw,
	}
}

// searchMatchToEvent maps one /shodan/host/search match into an
// EngineEvent. Severity is the same ladder as hostServiceToEvent.
func searchMatchToEvent(cidr string, m *searchMatch) recon.EngineEvent {
	sev := recon.SeverityLow
	switch {
	case len(m.Vulns) > 0:
		sev = recon.SeverityHigh
	case isSensitivePort(m.Port):
		sev = recon.SeverityMedium
	}
	svc := hostData{
		Port:      m.Port,
		Transport: m.Transport,
		Product:   m.Product,
		Version:   m.Version,
		Hostnames: m.Hostnames,
		Vulns:     m.Vulns,
	}
	value := formatService(m.IP, &svc)
	raw, _ := json.Marshal(serviceFinding{
		IP:        m.IP,
		Port:      m.Port,
		Transport: m.Transport,
		Product:   m.Product,
		Version:   m.Version,
		Hostnames: m.Hostnames,
		Vulns:     m.Vulns,
		Query:     "net:" + cidr,
	})
	return recon.EngineEvent{
		Module:     Module,
		Category:   CategoryExposedService,
		Severity:   sev,
		Value:      value,
		Source:     SourceTag,
		Confidence: 85,
		RawPayload: raw,
	}
}

// serviceFinding is the normalized envelope persisted as the raw
// payload. It is intentionally flat so SQL queries over the JSONB
// column don't need recursive traversal.
type serviceFinding struct {
	IP        string   `json:"ip"`
	Port      int      `json:"port"`
	Transport string   `json:"transport,omitempty"`
	Product   string   `json:"product,omitempty"`
	Version   string   `json:"version,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
	Vulns     []string `json:"vulns,omitempty"`
	Org       string   `json:"org,omitempty"`
	Country   string   `json:"country,omitempty"`
	Query     string   `json:"query,omitempty"`
}

// formatService renders a human-readable one-line label for a service.
// Examples: "1.2.3.4:22/tcp ssh OpenSSH 8.4", "1.2.3.4:443/tcp".
func formatService(ip string, svc *hostData) string {
	var b strings.Builder
	b.WriteString(ip)
	b.WriteByte(':')
	fmt.Fprintf(&b, "%d", svc.Port)
	if svc.Transport != "" {
		b.WriteByte('/')
		b.WriteString(svc.Transport)
	}
	if svc.Product != "" {
		b.WriteByte(' ')
		b.WriteString(svc.Product)
		if svc.Version != "" {
			b.WriteByte(' ')
			b.WriteString(svc.Version)
		}
	}
	return b.String()
}

// pickHostnames returns the first non-empty hostname slice. Shodan
// sometimes attaches hostnames at the service level, sometimes only at
// the host level — we surface whichever is present.
func pickHostnames(svc, host []string) []string {
	if len(svc) > 0 {
		return svc
	}
	return host
}

// isSensitivePort returns true for ports running protocols where any
// public exposure is interesting on its own. The list is intentionally
// short — long lists drown out genuine exposure with low-severity
// noise.
func isSensitivePort(p int) bool {
	switch p {
	case 22, // SSH
		23,    // Telnet
		3389,  // RDP
		445,   // SMB
		139,   // NetBIOS
		1433,  // MSSQL
		3306,  // MySQL
		5432,  // PostgreSQL
		6379,  // Redis
		9200,  // Elasticsearch
		11211, // memcached
		27017, // MongoDB
		5900,  // VNC
		161,   // SNMP
		2375,  // Docker daemon (plain)
		2376:  // Docker daemon (TLS)
		return true
	}
	return false
}

// ---------------------------------------------------------------------
// Request plumbing
// ---------------------------------------------------------------------

// do builds a GET request against c.cfg.BaseURL+path, attaches the API
// key as a query parameter (Shodan does not accept header-based auth),
// merges any extra params, executes it, and returns the response. Any
// transport-level error is scrubbed through scrubErr to strip the key
// before it reaches the caller — url.Error.Error() would otherwise
// echo the full query string including the key.
func (c *Connector) do(ctx context.Context, path string, extra url.Values) (*http.Response, error) {
	u, err := url.Parse(c.cfg.BaseURL + path)
	if err != nil {
		return nil, fmt.Errorf("shodan: build url: %w", err)
	}
	q := u.Query()
	q.Set("key", c.cfg.APIKey)
	for k, vs := range extra {
		for _, v := range vs {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("shodan: build request: %w", err)
	}
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, c.scrubErr(err)
	}
	return resp, nil
}

// scrubErr returns an error whose Error() text has the configured API
// key replaced with redactionSentinel. errors.Is/As against the
// original error still works through Unwrap. Mandatory because
// net/http errors embed the full request URL — which for Shodan
// carries the key in the query string.
func (c *Connector) scrubErr(err error) error {
	if err == nil {
		return nil
	}
	if c.cfg.APIKey == "" {
		return err
	}
	msg := err.Error()
	clean := strings.ReplaceAll(msg, c.cfg.APIKey, redactionSentinel)
	if clean == msg {
		return err
	}
	return &scrubbedError{msg: clean, wrapped: err}
}

// scrubbedError is the error type returned by scrubErr. It carries the
// redacted text and preserves the original error for errors.Is/As
// matching.
type scrubbedError struct {
	msg     string
	wrapped error
}

func (e *scrubbedError) Error() string { return e.msg }
func (e *scrubbedError) Unwrap() error { return e.wrapped }

// statusToErr maps a non-2xx Shodan HTTP status to a typed sentinel.
// 200 returns nil; everything else returns a wrapped sentinel that
// callers can match with errors.Is. The status code is included in
// the error string for ErrUnexpectedStatus so operators can diagnose
// from the message alone.
func statusToErr(code int) error {
	switch {
	case code >= 200 && code < 300:
		return nil
	case code == http.StatusUnauthorized, code == http.StatusForbidden:
		return ErrUnauthorized
	case code == http.StatusTooManyRequests:
		return ErrRateLimited
	default:
		return fmt.Errorf("%w: %d", ErrUnexpectedStatus, code)
	}
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
