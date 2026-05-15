// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package digitalocean_test

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
	"github.com/fr4nsys/usulnet/internal/services/dns/providers/digitalocean"
)

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
	creds, _ := json.Marshal(digitalocean.Credentials{APIToken: "test-token"})
	cfg := map[string]any{"base_url": srv.URL}
	p, err := digitalocean.Factory(context.Background(), creds, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDO_Capabilities(t *testing.T) {
	caps := digitalocean.Capabilities()
	if caps.DisplayName == "" {
		t.Fatalf("missing display name")
	}
	if len(caps.Records) == 0 {
		t.Fatalf("expected supported record types")
	}
}

func TestDO_VerifyCredentials(t *testing.T) {
	srv := makeServer(t, map[string]http.HandlerFunc{
		"GET /account": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"account":{"email":"test@example.com"}}`))
		},
	})
	p := newPlugin(t, srv)
	if err := p.VerifyCredentials(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDO_VerifyCredentials_BadToken(t *testing.T) {
	srv := makeServer(t, map[string]http.HandlerFunc{
		"GET /account": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"id":"unauthorized"}`, http.StatusUnauthorized)
		},
	})
	p := newPlugin(t, srv)
	err := p.VerifyCredentials(context.Background())
	if !stderrors.Is(err, dns.ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
}

func TestDO_CreateAndDeleteRecord(t *testing.T) {
	createCalled := false
	deleteCalled := false
	srv := makeServer(t, map[string]http.HandlerFunc{
		"GET /domains/example.com": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"domain":{"name":"example.com"}}`))
		},
		"GET /domains/foo": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"id":"not_found"}`, http.StatusNotFound)
		},
		"POST /domains/example.com/records": func(w http.ResponseWriter, _ *http.Request) {
			createCalled = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"domain_record":{"id":42,"type":"A","name":"foo","data":"1.2.3.4","ttl":300}}`))
		},
		"DELETE /domains/example.com/records/42": func(w http.ResponseWriter, _ *http.Request) {
			deleteCalled = true
			w.WriteHeader(http.StatusNoContent)
		},
	})
	p := newPlugin(t, srv)

	rec, err := p.CreateRecord(context.Background(), dns.ProviderRecord{
		Name: "foo.example.com", Type: models.DNSRecordTypeA, Content: "1.2.3.4", TTL: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.ID != "42" {
		t.Fatalf("expected id 42, got %s", rec.ID)
	}
	if !createCalled {
		t.Fatalf("create not called")
	}

	if err := p.DeleteRecord(context.Background(), "42", rec); err != nil {
		t.Fatal(err)
	}
	if !deleteCalled {
		t.Fatalf("delete not called")
	}
}

func TestDO_DeleteRecord_NotFound(t *testing.T) {
	srv := makeServer(t, map[string]http.HandlerFunc{
		"GET /domains/example.com": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"domain":{"name":"example.com"}}`))
		},
		"DELETE /domains/example.com/records/99": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"id":"not_found"}`, http.StatusNotFound)
		},
	})
	p := newPlugin(t, srv)
	err := p.DeleteRecord(context.Background(), "99", dns.ProviderRecord{
		Name: "x.example.com", Type: models.DNSRecordTypeA, Content: "1.1.1.1",
	})
	if !stderrors.Is(err, dns.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound, got %v", err)
	}
}

func TestDO_ListRecords(t *testing.T) {
	srv := makeServer(t, map[string]http.HandlerFunc{
		"GET /domains/example.com": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"domain":{"name":"example.com"}}`))
		},
		"GET /domains/example.com/records": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"domain_records":[
				{"id":1,"type":"A","name":"@","data":"1.2.3.4","ttl":300},
				{"id":2,"type":"TXT","name":"_acme-challenge","data":"v","ttl":60}
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

func TestDO_ZoneNotFound(t *testing.T) {
	srv := makeServer(t, map[string]http.HandlerFunc{
		"GET /domains/unknown.tld": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"id":"not_found"}`, http.StatusNotFound)
		},
		"GET /domains/tld": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"id":"not_found"}`, http.StatusNotFound)
		},
	})
	p := newPlugin(t, srv)
	_, err := p.CreateRecord(context.Background(), dns.ProviderRecord{
		Name: "x.unknown.tld", Type: models.DNSRecordTypeA, Content: "1.1.1.1",
	})
	if !stderrors.Is(err, dns.ErrZoneNotFound) {
		t.Fatalf("expected zone not found, got %v", err)
	}
}
