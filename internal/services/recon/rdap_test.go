// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package recon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newRDAPTestServer spins up an httptest.Server with a fixed
// path → JSON body table. Unknown paths return 404 so the
// ErrRDAPNotFound branch is exercised by tests.
func newRDAPTestServer(t *testing.T, routes map[string]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for path, body := range routes {
		body := body // capture loop var
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/rdap+json")
			_, _ = w.Write([]byte(body))
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	})
	return httptest.NewServer(mux)
}

// rdapDomainBody builds a minimal RDAP domain response carrying a
// registrant entity whose jCard "fn" equals orgName.
func rdapDomainBody(orgName string) string {
	resp := map[string]any{
		"objectClassName": "domain",
		"ldhName":         "example.com",
		"entities": []any{
			map[string]any{
				"handle": "REG-1",
				"roles":  []any{"registrant"},
				"vcardArray": []any{
					"vcard",
					[]any{
						[]any{"version", map[string]any{}, "text", "4.0"},
						[]any{"fn", map[string]any{}, "text", orgName},
					},
				},
			},
		},
	}
	b, _ := json.Marshal(resp)
	return string(b)
}

// rdapIPBody builds a minimal IP-network RDAP response.
func rdapIPBody(orgName string) string {
	resp := map[string]any{
		"objectClassName": "ip network",
		"handle":          "NET-1",
		"entities": []any{
			map[string]any{
				"roles": []any{"registrant"},
				"vcardArray": []any{
					"vcard",
					[]any{
						[]any{"version", map[string]any{}, "text", "4.0"},
						[]any{"org", map[string]any{}, "text", []any{orgName, "Inc."}},
					},
				},
			},
		},
	}
	b, _ := json.Marshal(resp)
	return string(b)
}

func TestRDAPClient_LookupDomainOrg(t *testing.T) {
	srv := newRDAPTestServer(t, map[string]string{
		"/domain/example.com": rdapDomainBody("Acme Corp"),
	})
	defer srv.Close()

	c := NewRDAPClientWithBase(srv.URL, 0)
	org, err := c.LookupDomainOrg(context.Background(), "Example.COM")
	if err != nil {
		t.Fatalf("LookupDomainOrg: %v", err)
	}
	if org != "Acme Corp" {
		t.Fatalf("org: %q", org)
	}
}

func TestRDAPClient_LookupIPOrg_OrgArrayValue(t *testing.T) {
	srv := newRDAPTestServer(t, map[string]string{
		"/ip/192.0.2.1": rdapIPBody("Acme Corp"),
	})
	defer srv.Close()

	c := NewRDAPClientWithBase(srv.URL, 0)
	org, err := c.LookupIPOrg(context.Background(), "192.0.2.1")
	if err != nil {
		t.Fatalf("LookupIPOrg: %v", err)
	}
	if !strings.Contains(org, "Acme Corp") {
		t.Fatalf("org: %q", org)
	}
}

func TestRDAPClient_LookupIPOrg_CIDR(t *testing.T) {
	srv := newRDAPTestServer(t, map[string]string{
		"/ip/192.0.2.0": rdapIPBody("Acme Corp"),
	})
	defer srv.Close()

	c := NewRDAPClientWithBase(srv.URL, 0)
	org, err := c.LookupIPOrg(context.Background(), "192.0.2.0/24")
	if err != nil {
		t.Fatalf("LookupIPOrg(CIDR): %v", err)
	}
	if org == "" {
		t.Fatalf("expected non-empty org")
	}
}

func TestRDAPClient_NotFound(t *testing.T) {
	srv := newRDAPTestServer(t, map[string]string{})
	defer srv.Close()
	c := NewRDAPClientWithBase(srv.URL, 0)
	_, err := c.LookupDomainOrg(context.Background(), "missing.example")
	if !errors.Is(err, ErrRDAPNotFound) {
		t.Fatalf("expected ErrRDAPNotFound, got: %v", err)
	}
}

func TestRDAPClient_ServerError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/domain/boom.example", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewRDAPClientWithBase(srv.URL, 0)
	_, err := c.LookupDomainOrg(context.Background(), "boom.example")
	if err == nil {
		t.Fatalf("expected error on 500")
	}
	if errors.Is(err, ErrRDAPNotFound) {
		t.Fatalf("500 must not map to ErrRDAPNotFound")
	}
}

func TestRDAPClient_BadJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/domain/example.com", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "not-json")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewRDAPClientWithBase(srv.URL, 0)
	_, err := c.LookupDomainOrg(context.Background(), "example.com")
	if err == nil {
		t.Fatalf("expected decode error")
	}
}

func TestRDAPClient_FallbackToFn(t *testing.T) {
	// Entity has no roles array but does carry an "fn" — walkEntities
	// must accept it on the second pass.
	body := `{
		"objectClassName": "domain",
		"entities": [
			{ "vcardArray": ["vcard", [
				["version", {}, "text", "4.0"],
				["fn", {}, "text", "Fallback Org"]
			]]}
		]
	}`
	srv := newRDAPTestServer(t, map[string]string{
		"/domain/fallback.example": body,
	})
	defer srv.Close()

	c := NewRDAPClientWithBase(srv.URL, 0)
	org, err := c.LookupDomainOrg(context.Background(), "fallback.example")
	if err != nil {
		t.Fatalf("LookupDomainOrg: %v", err)
	}
	if org != "Fallback Org" {
		t.Fatalf("org: %q", org)
	}
}

func TestRDAPClient_InvalidIP(t *testing.T) {
	c := NewRDAPClient(0)
	_, err := c.LookupIPOrg(context.Background(), "not-an-ip")
	if err == nil {
		t.Fatalf("expected error")
	}
}
