// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package shodan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

const testKey = "test-api-key-deadbeef"

// newServerAndConnector spins up an httptest server and a Connector
// pointed at it. The handler argument receives every request and is
// expected to write the canned response.
func newServerAndConnector(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Connector) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := New(Config{
		APIKey:  testKey,
		Enabled: true,
		BaseURL: srv.URL,
	}, logger.Nop())
	return srv, c
}

// ============================================================================
// Constructor + Enabled
// ============================================================================

func TestNew_Defaults(t *testing.T) {
	c := New(Config{APIKey: "x", Enabled: true}, nil)
	if c.cfg.BaseURL != DefaultBaseURL {
		t.Errorf("BaseURL = %q, want %q", c.cfg.BaseURL, DefaultBaseURL)
	}
	if c.cfg.UserAgent != DefaultUserAgent {
		t.Errorf("UserAgent = %q, want %q", c.cfg.UserAgent, DefaultUserAgent)
	}
	if c.cfg.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", c.cfg.Timeout, DefaultTimeout)
	}
	if c.Kind() != Kind {
		t.Errorf("Kind = %q, want %q", c.Kind(), Kind)
	}
}

func TestNew_TrailingSlashStripped(t *testing.T) {
	c := New(Config{APIKey: "x", Enabled: true, BaseURL: "https://example.com/"}, nil)
	if c.cfg.BaseURL != "https://example.com" {
		t.Errorf("BaseURL = %q, want trailing slash stripped", c.cfg.BaseURL)
	}
}

func TestEnabled_RequiresKeyAndToggle(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		enabled bool
	}{
		{"toggle off, no key", Config{Enabled: false, APIKey: ""}, false},
		{"toggle off, key", Config{Enabled: false, APIKey: "k"}, false},
		{"toggle on, no key", Config{Enabled: true, APIKey: ""}, false},
		{"toggle on, key", Config{Enabled: true, APIKey: "k"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := New(tc.cfg, nil)
			if got := c.Enabled(); got != tc.enabled {
				t.Errorf("Enabled = %v, want %v", got, tc.enabled)
			}
		})
	}
}

// ============================================================================
// HealthCheck
// ============================================================================

func TestHealthCheck_200(t *testing.T) {
	var sawKey string
	var sawUA string
	var sawPath string
	credits := int64(42)
	srv, c := newServerAndConnector(t, func(w http.ResponseWriter, r *http.Request) {
		sawKey = r.URL.Query().Get("key")
		sawUA = r.Header.Get("User-Agent")
		sawPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(apiInfo{QueryCredits: &credits, Plan: "freelancer"})
	})
	_ = srv

	if err := c.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
	if sawKey != testKey {
		t.Errorf("?key= = %q, want %q", sawKey, testKey)
	}
	if sawUA != DefaultUserAgent {
		t.Errorf("UA = %q, want %q", sawUA, DefaultUserAgent)
	}
	if sawPath != "/api-info" {
		t.Errorf("path = %q, want /api-info", sawPath)
	}
}

func TestHealthCheck_MissingQueryCredits(t *testing.T) {
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		// query_credits absent → payload broken.
		_, _ = w.Write([]byte(`{"plan":"freelancer"}`))
	})
	if err := c.HealthCheck(context.Background()); !errors.Is(err, ErrUnhealthyResponse) {
		t.Errorf("err = %v, want ErrUnhealthyResponse", err)
	}
}

func TestHealthCheck_401(t *testing.T) {
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	if err := c.HealthCheck(context.Background()); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("err = %v, want ErrUnauthorized", err)
	}
}

func TestHealthCheck_403_AlsoUnauthorized(t *testing.T) {
	// Shodan returns 403 for revoked keys; we treat it as the same
	// auth-failure class as 401.
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	if err := c.HealthCheck(context.Background()); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("err = %v, want ErrUnauthorized", err)
	}
}

func TestHealthCheck_429(t *testing.T) {
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})
	if err := c.HealthCheck(context.Background()); !errors.Is(err, ErrRateLimited) {
		t.Errorf("err = %v, want ErrRateLimited", err)
	}
}

func TestHealthCheck_500(t *testing.T) {
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	err := c.HealthCheck(context.Background())
	if !errors.Is(err, ErrUnexpectedStatus) {
		t.Errorf("err = %v, want ErrUnexpectedStatus", err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v, want it to include the status code", err)
	}
}

func TestHealthCheck_EmptyBody(t *testing.T) {
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// Empty body → decode error from json.NewDecoder.
	err := c.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("expected decode error from empty body, got nil")
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Errorf("err = %v, want it to mention decode", err)
	}
}

func TestHealthCheck_NoKey(t *testing.T) {
	c := New(Config{Enabled: true}, nil)
	if err := c.HealthCheck(context.Background()); !errors.Is(err, ErrNoAPIKey) {
		t.Errorf("err = %v, want ErrNoAPIKey", err)
	}
}

func TestHealthCheck_Disabled_NoCall(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	c := New(Config{APIKey: testKey, Enabled: false, BaseURL: srv.URL}, nil)
	if err := c.HealthCheck(context.Background()); err != nil {
		t.Errorf("disabled HealthCheck = %v, want nil", err)
	}
	if called {
		t.Error("disabled connector hit the server")
	}
}

// ============================================================================
// Lookup — TargetIP
// ============================================================================

func TestLookup_IP_HappyPath(t *testing.T) {
	resp := hostResponse{
		IP:        "1.2.3.4",
		Hostnames: []string{"example.com"},
		Org:       "ExampleCorp",
		Country:   "US",
		Ports:     []int{22, 443},
		Data: []hostData{
			{Port: 22, Transport: "tcp", Product: "OpenSSH", Version: "8.4p1"},
			{Port: 443, Transport: "tcp", Product: "nginx", Version: "1.20.1"},
		},
	}
	var sawPath string
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(resp)
	})
	events, err := c.Lookup(context.Background(), recon.TargetIP, "1.2.3.4")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if sawPath != "/shodan/host/1.2.3.4" {
		t.Errorf("path = %q, want /shodan/host/1.2.3.4", sawPath)
	}
	if len(events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(events))
	}
	// SSH (22) is sensitive → medium; HTTPS (443) is low.
	if events[0].Severity != recon.SeverityMedium {
		t.Errorf("event[0].Severity = %q, want medium", events[0].Severity)
	}
	if events[1].Severity != recon.SeverityLow {
		t.Errorf("event[1].Severity = %q, want low", events[1].Severity)
	}
	for _, e := range events {
		if e.Module != Module {
			t.Errorf("Module = %q, want %q", e.Module, Module)
		}
		if e.Category != CategoryExposedService {
			t.Errorf("Category = %q, want %q", e.Category, CategoryExposedService)
		}
		if e.Source != SourceTag {
			t.Errorf("Source = %q, want %q", e.Source, SourceTag)
		}
		if len(e.RawPayload) == 0 {
			t.Error("RawPayload is empty")
		}
	}
}

func TestLookup_IP_WithVulns_High(t *testing.T) {
	resp := hostResponse{
		IP: "1.2.3.4",
		Data: []hostData{
			{Port: 443, Transport: "tcp", Product: "nginx", Vulns: []string{"CVE-2021-23017"}},
		},
	}
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(resp)
	})
	events, err := c.Lookup(context.Background(), recon.TargetIP, "1.2.3.4")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	if events[0].Severity != recon.SeverityHigh {
		t.Errorf("Severity = %q, want high (CVE in vulns)", events[0].Severity)
	}
}

func TestLookup_IP_404_NoObservations(t *testing.T) {
	// Shodan returns 404 when an IP has no observed services.
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	events, err := c.Lookup(context.Background(), recon.TargetIP, "1.2.3.4")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("len(events) = %d, want 0", len(events))
	}
}

func TestLookup_IP_InvalidValue(t *testing.T) {
	c := New(Config{APIKey: "k", Enabled: true}, nil)
	_, err := c.Lookup(context.Background(), recon.TargetIP, "not-an-ip")
	if !errors.Is(err, ErrInvalidTargetValue) {
		t.Errorf("err = %v, want ErrInvalidTargetValue", err)
	}
}

func TestLookup_EmptyData_NoEvents(t *testing.T) {
	resp := hostResponse{IP: "1.2.3.4"}
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(resp)
	})
	events, err := c.Lookup(context.Background(), recon.TargetIP, "1.2.3.4")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("len(events) = %d, want 0", len(events))
	}
}

// ============================================================================
// Lookup — TargetDomain (hostname)
// ============================================================================

func TestLookup_Hostname_HappyPath(t *testing.T) {
	resp := map[string]string{"example.com": "93.184.216.34"}
	var sawHostname string
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, r *http.Request) {
		sawHostname = r.URL.Query().Get("hostnames")
		_ = json.NewEncoder(w).Encode(resp)
	})
	events, err := c.Lookup(context.Background(), recon.TargetDomain, "Example.COM")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if sawHostname != "example.com" {
		t.Errorf("hostnames= = %q, want example.com", sawHostname)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	if events[0].Category != CategoryDNSResolution {
		t.Errorf("Category = %q, want %q", events[0].Category, CategoryDNSResolution)
	}
	if events[0].Severity != recon.SeverityInfo {
		t.Errorf("Severity = %q, want info", events[0].Severity)
	}
	if !strings.Contains(events[0].Value, "93.184.216.34") {
		t.Errorf("Value = %q, want it to contain the resolved IP", events[0].Value)
	}
}

// ============================================================================
// Lookup — TargetIPRange (CIDR search)
// ============================================================================

func TestLookup_CIDR_HappyPath(t *testing.T) {
	resp := searchResponse{
		Total: 2,
		Matches: []searchMatch{
			{IP: "10.0.0.1", Port: 22, Transport: "tcp", Product: "OpenSSH"},
			{IP: "10.0.0.2", Port: 80, Transport: "tcp", Product: "nginx"},
		},
	}
	var sawQuery string
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, r *http.Request) {
		sawQuery = r.URL.Query().Get("query")
		_ = json.NewEncoder(w).Encode(resp)
	})
	events, err := c.Lookup(context.Background(), recon.TargetIPRange, "10.0.0.0/24")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if sawQuery != "net:10.0.0.0/24" {
		t.Errorf("query= = %q, want net:10.0.0.0/24", sawQuery)
	}
	if len(events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(events))
	}
}

func TestLookup_CIDR_InvalidValue(t *testing.T) {
	c := New(Config{APIKey: "k", Enabled: true}, nil)
	_, err := c.Lookup(context.Background(), recon.TargetIPRange, "not-a-cidr")
	if !errors.Is(err, ErrInvalidTargetValue) {
		t.Errorf("err = %v, want ErrInvalidTargetValue", err)
	}
}

func TestLookup_CIDR_RespectsMaxResults(t *testing.T) {
	matches := make([]searchMatch, MaxSearchResults+50)
	for i := range matches {
		matches[i] = searchMatch{IP: "10.0.0.1", Port: 80, Transport: "tcp"}
	}
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(searchResponse{Total: len(matches), Matches: matches})
	})
	events, err := c.Lookup(context.Background(), recon.TargetIPRange, "10.0.0.0/24")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(events) != MaxSearchResults {
		t.Errorf("len(events) = %d, want MaxSearchResults=%d", len(events), MaxSearchResults)
	}
}

// ============================================================================
// Lookup — error paths
// ============================================================================

func TestLookup_UnsupportedTarget(t *testing.T) {
	c := New(Config{APIKey: "k", Enabled: true}, nil)
	_, err := c.Lookup(context.Background(), recon.TargetEmail, "alice@example.com")
	if !errors.Is(err, ErrUnsupportedTarget) {
		t.Errorf("err = %v, want ErrUnsupportedTarget", err)
	}
}

func TestLookup_DisabledOrNoKey(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"no key", Config{Enabled: true}},
		{"toggle off", Config{Enabled: false, APIKey: "k"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := New(tc.cfg, nil)
			_, err := c.Lookup(context.Background(), recon.TargetIP, "1.2.3.4")
			if !errors.Is(err, ErrNoAPIKey) {
				t.Errorf("err = %v, want ErrNoAPIKey", err)
			}
		})
	}
}

func TestLookup_EmptyValue(t *testing.T) {
	c := New(Config{APIKey: "k", Enabled: true}, nil)
	_, err := c.Lookup(context.Background(), recon.TargetIP, "   ")
	if !errors.Is(err, ErrInvalidTargetValue) {
		t.Errorf("err = %v, want ErrInvalidTargetValue", err)
	}
}

func TestLookup_RateLimited(t *testing.T) {
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})
	_, err := c.Lookup(context.Background(), recon.TargetIP, "1.2.3.4")
	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("err = %v, want ErrRateLimited", err)
	}
}

func TestLookup_500(t *testing.T) {
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, err := c.Lookup(context.Background(), recon.TargetIP, "1.2.3.4")
	if !errors.Is(err, ErrUnexpectedStatus) {
		t.Errorf("err = %v, want ErrUnexpectedStatus", err)
	}
}

// ============================================================================
// Adapter wiring — drive EngineEvents into a recon-engine queue
// ============================================================================

// TestDispatch_FillsEngineEventsForToolkit verifies the connector's
// EngineEvent output is shaped correctly for direct insertion into a
// running toolkit dispatch. The toolkit engine treats its dispatch as
// an append; this test asserts the connector's events do not need any
// further normalisation.
func TestDispatch_FillsEngineEventsForToolkit(t *testing.T) {
	resp := hostResponse{
		IP: "1.2.3.4",
		Data: []hostData{
			{Port: 22, Transport: "tcp", Product: "OpenSSH"},
			{Port: 443, Transport: "tcp", Product: "nginx", Vulns: []string{"CVE-2024-0001"}},
		},
	}
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(resp)
	})
	events, err := c.Lookup(context.Background(), recon.TargetIP, "1.2.3.4")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(events) != len(resp.Data) {
		t.Fatalf("len(events) = %d, want %d", len(events), len(resp.Data))
	}
	// SSH (sensitive port, no vulns) → medium.
	if events[0].Severity != recon.SeverityMedium {
		t.Errorf("sensitive-port row → severity = %q, want medium", events[0].Severity)
	}
	// HTTPS w/ CVE → high (vuln dominates).
	if events[1].Severity != recon.SeverityHigh {
		t.Errorf("CVE row → severity = %q, want high", events[1].Severity)
	}
	for i, e := range events {
		if e.Module != Module {
			t.Errorf("event[%d].Module = %q, want %q", i, e.Module, Module)
		}
		if e.Category != CategoryExposedService {
			t.Errorf("event[%d].Category = %q, want %q", i, e.Category, CategoryExposedService)
		}
		if e.Value == "" {
			t.Errorf("event[%d].Value is empty", i)
		}
	}
}

// ============================================================================
// Defensive: API key never appears in error strings or logs
// ============================================================================

// TestLookup_NoSecretInError pins HIBP's redaction discipline: even if
// the upstream echoes the key back in a 5xx body, the returned error
// must not contain the configured key.
func TestLookup_NoSecretInError(t *testing.T) {
	const sensitive = "super-secret-key"
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(sensitive))
	})
	// Re-wire the key so the test can assert it's never echoed.
	c.cfg.APIKey = sensitive

	_, err := c.Lookup(context.Background(), recon.TargetIP, "1.2.3.4")
	if err == nil {
		t.Fatal("expected error from 500, got nil")
	}
	if strings.Contains(err.Error(), sensitive) {
		t.Errorf("error string %q contains the API key", err.Error())
	}
}

// TestSecrecyInvariant_FullCycle is the comprehensive secrecy test
// called out in the v26.5.2 acceptance criteria: it runs HealthCheck
// + every supported Lookup kind under both happy and error paths,
// captures every log line emitted by the connector, and asserts the
// configured API key never appears in any log line or any returned
// error string.
//
// The test uses a connector wired to a logger.Logger writing to a
// bytes.Buffer at debug level — so even verbose tracing would surface
// in the capture. The sentinel key is deliberately long and unique to
// make a substring match definitive.
func TestSecrecyInvariant_FullCycle(t *testing.T) {
	const sentinelKey = "shodan-secret-sentinel-do-not-leak-7f2c91b4"

	// Build a debug-level logger writing to a buffer so every Info /
	// Warn / Debug / Error message lands in the capture.
	var logBuf bytes.Buffer
	log, err := logger.NewWithOutput("debug", "json", &logBuf)
	if err != nil {
		t.Fatalf("logger: %v", err)
	}

	// httptest server that echoes the key back in the body (the
	// hostile path most likely to leak it).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api-info"):
			credits := int64(1)
			_ = json.NewEncoder(w).Encode(apiInfo{QueryCredits: &credits, Plan: "freelancer"})
		case strings.HasPrefix(r.URL.Path, "/shodan/host/"):
			_ = json.NewEncoder(w).Encode(hostResponse{
				IP: "1.2.3.4",
				Data: []hostData{
					{Port: 22, Transport: "tcp", Product: "OpenSSH", Version: "8.4"},
				},
			})
		case r.URL.Path == "/dns/resolve":
			_ = json.NewEncoder(w).Encode(map[string]string{"example.com": "1.2.3.4"})
		case r.URL.Path == "/shodan/host/search":
			_ = json.NewEncoder(w).Encode(searchResponse{
				Matches: []searchMatch{{IP: "10.0.0.1", Port: 80}},
			})
		default:
			// Any other path: return a 500 with the key in the body —
			// the path the connector must scrub.
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("upstream error: key=" + sentinelKey))
		}
	}))
	t.Cleanup(srv.Close)

	c := New(Config{
		APIKey:  sentinelKey,
		Enabled: true,
		BaseURL: srv.URL,
	}, log)

	// Collect every error string produced by the cycle. We assert the
	// sentinel key never appears in any of them at the end.
	var errStrings []string
	push := func(label string, err error) {
		if err != nil {
			errStrings = append(errStrings, label+": "+err.Error())
		}
	}

	// ---- Healthy paths ----
	push("HealthCheck.happy", c.HealthCheck(context.Background()))

	if events, err := c.Lookup(context.Background(), recon.TargetIP, "1.2.3.4"); err != nil {
		push("Lookup.ip.happy", err)
	} else {
		for _, e := range events {
			if bytes.Contains(e.RawPayload, []byte(sentinelKey)) {
				t.Errorf("EngineEvent.RawPayload contains the API key")
			}
		}
	}

	if events, err := c.Lookup(context.Background(), recon.TargetDomain, "example.com"); err != nil {
		push("Lookup.domain.happy", err)
	} else {
		for _, e := range events {
			if bytes.Contains(e.RawPayload, []byte(sentinelKey)) {
				t.Errorf("EngineEvent.RawPayload contains the API key")
			}
		}
	}

	if events, err := c.Lookup(context.Background(), recon.TargetIPRange, "10.0.0.0/24"); err != nil {
		push("Lookup.cidr.happy", err)
	} else {
		for _, e := range events {
			if bytes.Contains(e.RawPayload, []byte(sentinelKey)) {
				t.Errorf("EngineEvent.RawPayload contains the API key")
			}
		}
	}

	// ---- Error paths ----
	//
	// We force a 5xx by pointing the connector at a non-existent path
	// — the test server's default branch echoes the sentinel key in
	// the response body. The error must NOT contain the key.
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("upstream error: key=" + sentinelKey))
	}))
	t.Cleanup(failServer.Close)
	c2 := New(Config{APIKey: sentinelKey, Enabled: true, BaseURL: failServer.URL}, log)
	push("HealthCheck.5xx", c2.HealthCheck(context.Background()))
	if _, err := c2.Lookup(context.Background(), recon.TargetIP, "1.2.3.4"); err != nil {
		push("Lookup.ip.5xx", err)
	}

	// ---- Unsupported / invalid target ----
	if _, err := c.Lookup(context.Background(), recon.TargetEmail, "alice@example.com"); err != nil {
		push("Lookup.unsupported", err)
	}
	if _, err := c.Lookup(context.Background(), recon.TargetIP, "not-an-ip"); err != nil {
		push("Lookup.invalid", err)
	}

	// ---- Force a transport error: dial to a closed port. The net
	// stdlib's url.Error embeds the request URL — which for Shodan
	// carries the key in the query string. The connector's scrubErr
	// must strip the key from the returned error.
	deadServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := deadServer.URL
	deadServer.Close() // force connection refused
	c3 := New(Config{APIKey: sentinelKey, Enabled: true, BaseURL: deadURL}, log)
	if _, err := c3.Lookup(context.Background(), recon.TargetIP, "1.2.3.4"); err != nil {
		push("Lookup.ip.connRefused", err)
	} else {
		t.Error("expected connection error from closed server, got nil")
	}

	// ---- Final assertions ----
	logOutput := logBuf.String()
	if strings.Contains(logOutput, sentinelKey) {
		t.Errorf("API key leaked into log output:\n%s", logOutput)
	}
	for _, s := range errStrings {
		if strings.Contains(s, sentinelKey) {
			t.Errorf("API key leaked into error string: %s", s)
		}
	}
	if len(errStrings) == 0 {
		t.Error("expected at least one error string captured (5xx or transport)")
	}
}

// TestScrubErr_PreservesUnwrap pins that scrubbedError preserves
// errors.Is / errors.As matching against the original error. The
// connector relies on this to keep sentinel-error contracts intact
// when a transport-level error is wrapped.
func TestScrubErr_PreservesUnwrap(t *testing.T) {
	c := New(Config{APIKey: "k", Enabled: true}, nil)
	original := errors.New("transport failed: https://api.shodan.io/api-info?key=k")
	scrubbed := c.scrubErr(original)
	if !errors.Is(scrubbed, original) {
		t.Errorf("scrubbed error lost errors.Is link to original")
	}
	if strings.Contains(scrubbed.Error(), "key=k") {
		t.Errorf("scrubbed error still contains key=k: %q", scrubbed.Error())
	}
	if !strings.Contains(scrubbed.Error(), redactionSentinel) {
		t.Errorf("scrubbed error missing redaction sentinel: %q", scrubbed.Error())
	}
}

func TestScrubErr_NoKeyConfigured_PassesThrough(t *testing.T) {
	c := New(Config{Enabled: false}, nil)
	original := errors.New("something failed")
	// Pointer-identity check is intentional here: scrubErr's
	// no-key short-circuit returns the input unchanged. errors.Is
	// would also succeed but would not detect a regression that
	// allocates a new error with the same text.
	if got := c.scrubErr(original); got != original { //nolint:errorlint // pointer-identity check is the assertion
		t.Errorf("scrubErr with empty key should pass through, got %v", got)
	}
}

func TestScrubErr_Nil(t *testing.T) {
	c := New(Config{APIKey: "k", Enabled: true}, nil)
	if got := c.scrubErr(nil); got != nil {
		t.Errorf("scrubErr(nil) = %v, want nil", got)
	}
}

// ============================================================================
// Helpers
// ============================================================================

func TestIsSensitivePort(t *testing.T) {
	sensitive := []int{22, 3389, 5432, 6379, 27017, 2375}
	for _, p := range sensitive {
		if !isSensitivePort(p) {
			t.Errorf("isSensitivePort(%d) = false, want true", p)
		}
	}
	notSensitive := []int{80, 443, 8080, 8443}
	for _, p := range notSensitive {
		if isSensitivePort(p) {
			t.Errorf("isSensitivePort(%d) = true, want false", p)
		}
	}
}

func TestFormatService(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		svc  hostData
		want string
	}{
		{"port only", "1.2.3.4", hostData{Port: 443}, "1.2.3.4:443"},
		{"port + transport", "1.2.3.4", hostData{Port: 22, Transport: "tcp"}, "1.2.3.4:22/tcp"},
		{
			"full",
			"1.2.3.4",
			hostData{Port: 22, Transport: "tcp", Product: "OpenSSH", Version: "8.4p1"},
			"1.2.3.4:22/tcp OpenSSH 8.4p1",
		},
		{
			"product no version",
			"1.2.3.4",
			hostData{Port: 80, Transport: "tcp", Product: "nginx"},
			"1.2.3.4:80/tcp nginx",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatService(tc.ip, &tc.svc)
			if got != tc.want {
				t.Errorf("formatService(%q, %+v) = %q, want %q", tc.ip, tc.svc, got, tc.want)
			}
		})
	}
}

func TestPickHostnames(t *testing.T) {
	svc := []string{"svc.example.com"}
	host := []string{"host.example.com"}
	if got := pickHostnames(svc, host); len(got) != 1 || got[0] != "svc.example.com" {
		t.Errorf("pickHostnames svc-priority: got %v", got)
	}
	if got := pickHostnames(nil, host); len(got) != 1 || got[0] != "host.example.com" {
		t.Errorf("pickHostnames host-fallback: got %v", got)
	}
	if got := pickHostnames(nil, nil); len(got) != 0 {
		t.Errorf("pickHostnames empty: got %v", got)
	}
}
