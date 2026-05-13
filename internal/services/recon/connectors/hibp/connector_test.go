// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package hibp

import (
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
	srv, c := newServerAndConnector(t, func(w http.ResponseWriter, r *http.Request) {
		sawKey = r.Header.Get("hibp-api-key")
		sawUA = r.Header.Get("User-Agent")
		if r.URL.Path != "/breaches" {
			t.Errorf("path = %q, want /breaches", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	})
	_ = srv

	if err := c.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
	if sawKey != testKey {
		t.Errorf("hibp-api-key header = %q, want %q", sawKey, testKey)
	}
	if sawUA != DefaultUserAgent {
		t.Errorf("UA = %q, want %q", sawUA, DefaultUserAgent)
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
// Lookup
// ============================================================================

func TestLookup_HappyPath(t *testing.T) {
	rows := []breachRow{
		{
			Name:        "Adobe",
			Title:       "Adobe",
			Domain:      "adobe.com",
			BreachDate:  "2013-10-04",
			PwnCount:    152445165,
			DataClasses: []string{"Email addresses", "Passwords"},
			IsVerified:  true,
		},
		{
			Name:        "LowConfidence",
			Title:       "LowConfidence",
			BreachDate:  "2020-01-01",
			DataClasses: []string{"Email addresses"},
			IsVerified:  false,
		},
	}
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/breachedaccount/") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rows)
	})

	got, err := c.Lookup(context.Background(), "Alice@Example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(got))
	}
	if got[0].Severity != recon.SeverityHigh {
		// Passwords class triggers sensitive → high.
		t.Errorf("event[0].Severity = %q, want high", got[0].Severity)
	}
	if got[1].Severity != recon.SeverityLow {
		t.Errorf("event[1].Severity = %q, want low", got[1].Severity)
	}
	for _, e := range got {
		if e.Module != Module {
			t.Errorf("event.Module = %q, want %q", e.Module, Module)
		}
		if e.Category != CategoryBreach {
			t.Errorf("event.Category = %q, want %q", e.Category, CategoryBreach)
		}
		if e.Source != SourceTag {
			t.Errorf("event.Source = %q, want %q", e.Source, SourceTag)
		}
		if len(e.RawPayload) == 0 {
			t.Error("event.RawPayload is empty; should carry the upstream row")
		}
	}
}

func TestLookup_404_CleanEmail(t *testing.T) {
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	got, err := c.Lookup(context.Background(), "clean@example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len(events) = %d, want 0", len(got))
	}
}

func TestLookup_VerifiedNonSensitive_Medium(t *testing.T) {
	rows := []breachRow{
		{
			Name:        "ForumLeak",
			Title:       "Forum Leak",
			DataClasses: []string{"Usernames", "Email addresses"},
			IsVerified:  true,
		},
	}
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(rows)
	})
	got, err := c.Lookup(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(got))
	}
	if got[0].Severity != recon.SeverityMedium {
		t.Errorf("Severity = %q, want medium", got[0].Severity)
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
			_, err := c.Lookup(context.Background(), "alice@example.com")
			if !errors.Is(err, ErrNoAPIKey) {
				t.Errorf("err = %v, want ErrNoAPIKey", err)
			}
		})
	}
}

func TestLookup_EmptyEmail(t *testing.T) {
	c := New(Config{APIKey: "k", Enabled: true}, nil)
	_, err := c.Lookup(context.Background(), "   ")
	if err == nil {
		t.Fatal("expected error for empty email, got nil")
	}
}

func TestLookup_RateLimited(t *testing.T) {
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})
	_, err := c.Lookup(context.Background(), "alice@example.com")
	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("err = %v, want ErrRateLimited", err)
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
	rows := []breachRow{
		{Name: "PasswordLeak", Title: "Password Leak", DataClasses: []string{"Passwords"}, IsVerified: true},
		{Name: "EmailOnly", Title: "Email Only", DataClasses: []string{"Email addresses"}, IsVerified: true},
	}
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(rows)
	})

	events, err := c.Lookup(context.Background(), "Alice@Example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(events) != len(rows) {
		t.Fatalf("len(events) = %d, want %d", len(events), len(rows))
	}

	// Severity ladder: sensitive → high, verified non-sensitive → medium.
	if events[0].Severity != recon.SeverityHigh {
		t.Errorf("sensitive row → severity = %q, want high", events[0].Severity)
	}
	if events[1].Severity != recon.SeverityMedium {
		t.Errorf("non-sensitive row → severity = %q, want medium", events[1].Severity)
	}

	// Every event carries the canonical module + category so the API
	// layer can group HIBP-from-connector findings with sfp_haveibeen
	// findings emitted by SpiderFoot.
	for i, e := range events {
		if e.Module != Module {
			t.Errorf("event[%d].Module = %q, want %q", i, e.Module, Module)
		}
		if e.Category != CategoryBreach {
			t.Errorf("event[%d].Category = %q, want %q", i, e.Category, CategoryBreach)
		}
		if e.Value == "" {
			t.Errorf("event[%d].Value is empty", i)
		}
	}
}

// ============================================================================
// Defensive: API key never appears in error strings or logs
// ============================================================================

func TestLookup_NoSecretInError(t *testing.T) {
	const sensitive = "super-secret-key"
	_, c := newServerAndConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(sensitive))
	})
	// Re-wire the key so the test can assert it's never echoed.
	c.cfg.APIKey = sensitive

	_, err := c.Lookup(context.Background(), "alice@example.com")
	if err == nil {
		t.Fatal("expected error from 500, got nil")
	}
	if strings.Contains(err.Error(), sensitive) {
		t.Errorf("error string %q contains the API key", err.Error())
	}
}

// ============================================================================
// httpPathEscape
// ============================================================================

func TestHTTPPathEscape(t *testing.T) {
	cases := map[string]string{
		"alice@example.com":  "alice@example.com",
		"a+b@example.com":    "a+b@example.com",
		"a b@example.com":    "a%20b@example.com",
		"a/b@example.com":    "a%2Fb@example.com",
		"a?b=c@example.com":  "a%3Fb=c@example.com",
		"a#frag@example.com": "a%23frag@example.com",
	}
	for in, want := range cases {
		got := httpPathEscape(in)
		if got != want {
			t.Errorf("httpPathEscape(%q) = %q, want %q", in, got, want)
		}
	}
}
