// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package dns_test

import (
	"context"
	"errors"
	"testing"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/dns"
)

func TestRegistry_Register_Empty(t *testing.T) {
	r := dns.NewRegistry()
	if err := r.Register("", nil, dns.Capabilities{}); err == nil {
		t.Fatalf("expected error for empty kind")
	}
}

func TestRegistry_Register_NilFactory(t *testing.T) {
	r := dns.NewRegistry()
	if err := r.Register(models.DNSProviderKindCloudflare, nil, dns.Capabilities{}); err == nil {
		t.Fatalf("expected error for nil factory")
	}
}

func TestRegistry_Register_Duplicate(t *testing.T) {
	r := dns.NewRegistry()
	noop := func(context.Context, []byte, map[string]any) (dns.Provider, error) { return nil, nil }
	if err := r.Register(models.DNSProviderKindCloudflare, noop, dns.Capabilities{}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(models.DNSProviderKindCloudflare, noop, dns.Capabilities{}); err == nil {
		t.Fatalf("expected duplicate registration error")
	}
}

func TestRegistry_FactoryAndKinds(t *testing.T) {
	r := dns.NewRegistry()
	called := false
	factory := func(_ context.Context, _ []byte, _ map[string]any) (dns.Provider, error) {
		called = true
		return nil, nil
	}
	r.MustRegister(models.DNSProviderKindCloudflare, factory, dns.Capabilities{DisplayName: "Cloudflare"})
	r.MustRegister(models.DNSProviderKindRoute53, factory, dns.Capabilities{DisplayName: "Route 53"})

	if !r.Has(models.DNSProviderKindCloudflare) {
		t.Fatalf("expected Has(Cloudflare) to be true")
	}
	if r.Has("nope") {
		t.Fatalf("expected Has(\"nope\") to be false")
	}

	f, err := r.Factory(models.DNSProviderKindCloudflare)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f(context.Background(), nil, nil); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatalf("expected registered factory to be invoked")
	}

	_, err = r.Factory("missing")
	if !errors.Is(err, dns.ErrProviderNotFound) {
		t.Fatalf("expected ErrProviderNotFound, got %v", err)
	}

	caps := r.Capabilities()
	if len(caps) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(caps))
	}
	if caps[0].Kind != models.DNSProviderKindCloudflare {
		t.Fatalf("expected sorted Cloudflare first, got %s", caps[0].Kind)
	}

	kinds := r.Kinds()
	if len(kinds) != 2 || kinds[0] != models.DNSProviderKindCloudflare {
		t.Fatalf("Kinds returned unexpected order %v", kinds)
	}
}
