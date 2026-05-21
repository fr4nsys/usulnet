// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"testing"
)

// These tests pin the recon adapter wiring that PR #142 added.
// Pre-#142, internal/app/init_web.go set ReconEnabled = true but
// never passed the concrete recon.Service / metadata.Service into
// the ServiceRegistry, so the web reconAdapter returned
// IsEnabled() == false regardless of config. Every /recon/* page
// 404'd in v26.5.1 even though the JSON API surface worked.
//
// The fix in #142 plumbed ReconService + MetadataService through
// ServiceRegistryDeps; these tests assert that plumbing stays
// alive at the web-layer seam. If a future refactor unwires the
// fields again, the tests fail BEFORE the next release tag.

// TestServiceRegistry_ReconAdapter_DisabledByDefault asserts the
// adapter reports disabled when the feature flag is off — which is
// the v26.5.x default. The /recon/* handlers short-circuit to 404
// in that state.
func TestServiceRegistry_ReconAdapter_DisabledByDefault(t *testing.T) {
	r := NewServiceRegistry(ServiceRegistryDeps{
		ReconEnabled: false,
	})
	if r == nil {
		t.Fatal("NewServiceRegistry returned nil")
	}
	rec := r.Recon()
	if rec == nil {
		t.Fatal("ServiceRegistry.Recon() returned nil; expected non-nil disabled adapter")
	}
	if rec.IsEnabled() {
		t.Error("ReconEnabled=false but adapter.IsEnabled()=true")
	}
}

// TestServiceRegistry_ReconAdapter_EnabledNoService asserts the
// adapter stays disabled when the feature flag is on but the
// service implementation is nil (the v26.5.1 bug state).
//
// Adapter contract from internal/web/services.go:
//
//	enabled: r.reconEnabled && r.reconSvc != nil
//
// So ReconEnabled=true alone is not enough — the route still
// 404s without a wired service. This test pins that contract so
// the fix can't silently regress to "enabled but unservable".
func TestServiceRegistry_ReconAdapter_EnabledNoService(t *testing.T) {
	r := NewServiceRegistry(ServiceRegistryDeps{
		ReconEnabled: true,
		// ReconService deliberately nil — this is the v26.5.1
		// state where init_web.go set the flag but never wired
		// the concrete service.
	})
	if r == nil {
		t.Fatal("NewServiceRegistry returned nil")
	}
	rec := r.Recon()
	if rec == nil {
		t.Fatal("ServiceRegistry.Recon() returned nil")
	}
	if rec.IsEnabled() {
		t.Error("ReconEnabled=true but ReconService=nil: adapter MUST report disabled; got enabled (v26.5.1 regression)")
	}
}

// TestServiceRegistry_MetadataAdapter_FollowsFlag asserts the
// metadata adapter follows the same wired-plus-flag contract.
// metadata operations under /recon/metadata return 404 unless both
// the feature flag is set AND the service is wired.
func TestServiceRegistry_MetadataAdapter_FollowsFlag(t *testing.T) {
	// Disabled by default.
	r := NewServiceRegistry(ServiceRegistryDeps{ReconEnabled: false})
	if md := r.Metadata(); md == nil {
		t.Fatal("Metadata() returned nil; expected non-nil disabled adapter")
	} else if md.IsEnabled() {
		t.Error("ReconEnabled=false but metadata adapter.IsEnabled()=true")
	}

	// Flag on but service nil — still disabled (v26.5.1 state).
	r = NewServiceRegistry(ServiceRegistryDeps{
		ReconEnabled: true,
		// MetadataService deliberately nil.
	})
	if md := r.Metadata(); md == nil {
		t.Fatal("Metadata() returned nil with flag on")
	} else if md.IsEnabled() {
		t.Error("ReconEnabled=true but MetadataService=nil: adapter MUST report disabled; got enabled")
	}
}
