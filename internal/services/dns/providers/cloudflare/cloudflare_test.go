// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package cloudflare_test

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/dns"
	"github.com/fr4nsys/usulnet/internal/services/dns/providers/cloudflare"
)

// makeServer spins up an httptest server that emulates a slice of the
// Cloudflare v4 API. The handler matches on Method+Path and returns
// the canned JSON for the matched route or 404 otherwise.
func makeServer(t *testing.T, routes map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for k, h := range routes {
		parts := strings.SplitN(k, " ", 2)
		method := parts[0]
		path := parts[1]
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != method {
				http.Error(w, "method", http.StatusMethodNotAllowed)
				return
			}
			h(w, r)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newPlugin(t *testing.T, srv *httptest.Server) dns.Provider {
	t.Helper()
	creds, _ := json.Marshal(cloudflare.Credentials{APIToken: "test-token"})
	cfg := map[string]any{"base_url": srv.URL}
	p, err := cloudflare.Factory(context.Background(), creds, cfg)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	return p
}

func TestCloudflare_Capabilities(t *testing.T) {
	caps := cloudflare.Capabilities()
	if caps.DisplayName == "" || caps.Description == "" {
		t.Fatalf("missing display name/description")
	}
	if len(caps.CredentialFields) == 0 {
		t.Fatalf("expected credential fields")
	}
	foundTXT := false
	for _, r := range caps.Records {
		if r.Type == models.DNSRecordTypeTXT && r.Write {
			foundTXT = true
		}
	}
	if !foundTXT {
		t.Fatalf("TXT must be writable")
	}
}

func TestCloudflare_Factory_RejectsEmptyToken(t *testing.T) {
	_, err := cloudflare.Factory(context.Background(), []byte(`{"api_token":""}`), nil)
	if !stderrors.Is(err, dns.ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
}

func TestCloudflare_VerifyCredentials_Success(t *testing.T) {
	srv := makeServer(t, map[string]http.HandlerFunc{
		"GET /user/tokens/verify": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"success":true}`))
		},
	})
	p := newPlugin(t, srv)
	if err := p.VerifyCredentials(context.Background()); err != nil {
		t.Fatalf("VerifyCredentials: %v", err)
	}
}

func TestCloudflare_VerifyCredentials_Failure_401(t *testing.T) {
	srv := makeServer(t, map[string]http.HandlerFunc{
		"GET /user/tokens/verify": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"errors":[{"code":10000,"message":"Authentication error"}]}`, http.StatusUnauthorized)
		},
	})
	p := newPlugin(t, srv)
	err := p.VerifyCredentials(context.Background())
	if !stderrors.Is(err, dns.ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
}

func TestCloudflare_CreateAndDeleteRecord(t *testing.T) {
	zoneLookup := func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		switch name {
		case "example.com":
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"zoneABC","name":"example.com"}]}`))
		default:
			_, _ = w.Write([]byte(`{"success":true,"result":[]}`))
		}
	}
	createCalled := false
	deleteCalled := false
	srv := makeServer(t, map[string]http.HandlerFunc{
		"GET /zones": zoneLookup,
		"POST /zones/zoneABC/dns_records": func(w http.ResponseWriter, _ *http.Request) {
			createCalled = true
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"recXYZ","type":"TXT","name":"_acme-challenge.example.com","content":"v","ttl":60}}`))
		},
		"DELETE /zones/zoneABC/dns_records/recXYZ": func(w http.ResponseWriter, _ *http.Request) {
			deleteCalled = true
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"recXYZ"}}`))
		},
	})
	p := newPlugin(t, srv)

	rec, err := p.CreateRecord(context.Background(), dns.ProviderRecord{
		Name: "_acme-challenge.example.com", Type: models.DNSRecordTypeTXT, Content: "v", TTL: 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.ID != "recXYZ" {
		t.Fatalf("expected id recXYZ, got %s", rec.ID)
	}
	if !createCalled {
		t.Fatalf("create endpoint not called")
	}

	if err := p.DeleteRecord(context.Background(), "recXYZ", rec); err != nil {
		t.Fatal(err)
	}
	if !deleteCalled {
		t.Fatalf("delete endpoint not called")
	}
}

func TestCloudflare_DeleteRecord_NotFound(t *testing.T) {
	srv := makeServer(t, map[string]http.HandlerFunc{
		"GET /zones": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"zoneABC","name":"example.com"}]}`))
		},
		"DELETE /zones/zoneABC/dns_records/missing": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"success":false,"errors":[{"code":81044,"message":"not found"}]}`, http.StatusOK)
		},
	})
	p := newPlugin(t, srv)
	err := p.DeleteRecord(context.Background(), "missing", dns.ProviderRecord{
		Name: "_acme-challenge.example.com", Type: models.DNSRecordTypeTXT,
	})
	if !stderrors.Is(err, dns.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound, got %v", err)
	}
}

func TestCloudflare_ListRecords(t *testing.T) {
	srv := makeServer(t, map[string]http.HandlerFunc{
		"GET /zones": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"zoneABC","name":"example.com"}]}`))
		},
		"GET /zones/zoneABC/dns_records": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"success":true,"result":[
				{"id":"r1","type":"A","name":"a.example.com","content":"1.2.3.4","ttl":300},
				{"id":"r2","type":"TXT","name":"_acme-challenge.example.com","content":"x","ttl":60}
			]}`))
		},
	})
	p := newPlugin(t, srv)
	recs, err := p.ListRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 records, got %d", len(recs))
	}
}

func TestCloudflare_ZoneNotFound(t *testing.T) {
	srv := makeServer(t, map[string]http.HandlerFunc{
		"GET /zones": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"success":true,"result":[]}`))
		},
	})
	p := newPlugin(t, srv)
	_, err := p.CreateRecord(context.Background(), dns.ProviderRecord{
		Name: "x.unknown.tld", Type: models.DNSRecordTypeA, Content: "1.2.3.4", TTL: 60,
	})
	if !stderrors.Is(err, dns.ErrZoneNotFound) {
		t.Fatalf("expected zone not found, got %v", err)
	}
}
