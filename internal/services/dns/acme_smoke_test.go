// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package dns_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/dns"
	"github.com/fr4nsys/usulnet/internal/services/dns/providers/cloudflare"
)

// TestACME_SmokeE2E_CloudflareMock wires the full DNS service against
// an httptest server that emulates Cloudflare, drives a complete ACME
// DNS-01 happy path through the persistent state machine, and asserts
// the TXT record is created upstream, then deleted at the end.
//
// This is the smoke E2E required by session-10 ("mocks Cloudflare and
// asserts TXT-drop/clean"). It exercises:
//   - Provider registration
//   - Encrypted credential storage
//   - State machine: pending → dropping → propagating → ready →
//     completing → completed
//   - Resolver-confirmed propagation (via a fake Resolver)
//   - Upstream record cleanup at completion
func TestACME_SmokeE2E_CloudflareMock(t *testing.T) {
	var (
		creates atomic.Int32
		deletes atomic.Int32
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/user/tokens/verify", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true}`))
	})
	mux.HandleFunc("/zones", func(w http.ResponseWriter, r *http.Request) {
		// "example.com" matches; anything else is empty.
		name := r.URL.Query().Get("name")
		if strings.HasPrefix(name, "example.com") || name == "example.com" {
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"zoneABC","name":"example.com"}]}`))
		} else {
			_, _ = w.Write([]byte(`{"success":true,"result":[]}`))
		}
	})
	mux.HandleFunc("/zones/zoneABC/dns_records", func(w http.ResponseWriter, _ *http.Request) {
		creates.Add(1)
		_, _ = w.Write([]byte(`{"success":true,"result":{"id":"txt-001","type":"TXT","name":"_acme-challenge.example.com","content":"value","ttl":60}}`))
	})
	mux.HandleFunc("/zones/zoneABC/dns_records/txt-001", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletes.Add(1)
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"txt-001"}}`))
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	registry := dns.NewRegistry()
	if err := cloudflare.Register(registry); err != nil {
		t.Fatal(err)
	}

	svc := dns.NewService(
		newFakeProviderRepo(), newFakeRecordRepo(), newFakeOrderRepo(), newFakeAuditRepo(),
		registry, fakeEncryptor{}, dns.DefaultConfig(), nil,
	)
	svc.SetResolver(&fakeResolver{values: []string{"value"}}) // observes the TXT immediately

	ctx := context.Background()
	host := uuid.New()
	credsBlob, _ := json.Marshal(cloudflare.Credentials{APIToken: "test-token"})
	provider, err := svc.CreateProvider(ctx, dns.CreateProviderInput{
		HostID:       host,
		Name:         "cf-primary",
		ProviderKind: models.DNSProviderKindCloudflare,
		Description:  "smoke test",
		Enabled:      true,
		Credentials:  credsBlob,
		Config:       map[string]any{"base_url": srv.URL},
	}, nil)
	if err != nil {
		t.Fatalf("CreateProvider: %v", err)
	}

	order, err := svc.StartOrder(ctx, dns.ACMEOrderRequest{
		HostID:         host,
		ProviderID:     provider.ID,
		Domain:         "app.example.com",
		ChallengeValue: "value",
	})
	if err != nil {
		t.Fatalf("StartOrder: %v", err)
	}

	processed, err := svc.ProcessOrder(ctx, order.ID)
	if err != nil {
		t.Fatalf("ProcessOrder: %v", err)
	}
	if processed.State != models.ACMEOrderStateReady {
		t.Fatalf("expected ready after one round, got %s", processed.State)
	}
	if creates.Load() != 1 {
		t.Fatalf("expected 1 upstream create, got %d", creates.Load())
	}

	// Proxy reports success.
	completed, err := svc.MarkOrderCompleted(ctx, order.ID)
	if err != nil {
		t.Fatalf("MarkOrderCompleted: %v", err)
	}
	if completed.State != models.ACMEOrderStateCompleted {
		t.Fatalf("expected completed, got %s", completed.State)
	}
	if deletes.Load() != 1 {
		t.Fatalf("expected 1 upstream delete (TXT cleanup), got %d", deletes.Load())
	}

	// And the local record table should be empty for this provider.
	if recs, err := svc.ListRecords(ctx, provider.ID); err != nil || len(recs) != 0 {
		t.Fatalf("expected 0 records after cleanup, got %d err=%v", len(recs), err)
	}
}
