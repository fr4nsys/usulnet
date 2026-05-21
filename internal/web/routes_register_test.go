// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/web/testhelpers"
)

// This file owns the per-routes registration tests for v26.5.2's
// Tier 0 / session 02 coverage uplift. The session was motivated by
// PR #142, where a chi-router Mount() collision in routes_dns.go
// crash-looped the v26.5.1 image on startup. A single
// `assert.NotPanics(RegisterDNSRoutes)` would have caught it; this
// file adds that assertion plus a structural walk for every
// Register*Routes function in the package.
//
// The tests deliberately use zero-value `*Handler` and `*Middleware`
// — the registration code paths must not deref any of their fields
// (and PR #142 proved they don't). When a future change adds a
// Register call that touches the receivers eagerly, this test
// catches it before a release tag.

// newRegTestHandler returns a Handler skeleton sufficient for route
// registration. Handlers themselves are never invoked here; the
// tests check that registration completes without panic and that
// every documented route is mounted.
func newRegTestHandler() *Handler {
	return &Handler{
		services: &nilServices{},
		logger:   &testLogger{},
	}
}

// newRegTestMiddleware returns a Middleware with the zero-value
// session/auth/stats stack. The route-registration path uses
// m.RequirePermission(string) and m.AdminRequired — both return
// http.Handler-shaped closures that don't touch m's nil fields
// until a request arrives at runtime, so registration is safe.
func newRegTestMiddleware() *Middleware {
	return &Middleware{}
}

// regTest exercises Register<X>Routes(r, h, m) on a fresh chi.Mux,
// asserting registration does not panic and that every (method,
// pattern) tuple in want is present.
//
// want is a flat slice of "METHOD /pattern" strings.
type regTest struct {
	name     string
	register func(r chi.Router, h *Handler, m *Middleware)
	want     []string
}

func runRegTest(t *testing.T, tt regTest) {
	t.Helper()

	r := chi.NewRouter()
	h := newRegTestHandler()
	m := newRegTestMiddleware()

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("%s: registration panicked: %v", tt.name, rec)
		}
	}()
	tt.register(r, h, m)

	got := testhelpers.ChiWalk(r)
	for _, want := range tt.want {
		// "METHOD /pattern" — split on first space.
		idx := 0
		for i := range want {
			if want[i] == ' ' {
				idx = i
				break
			}
		}
		method, pattern := want[:idx], want[idx+1:]
		if !testhelpers.ChiWalkContains(got, method, pattern) {
			t.Errorf("%s: missing route %s; have:\n  %v", tt.name, want, got)
		}
	}
}

// ---------------------------------------------------------------------------
// One sub-test per Register<X>Routes function. Each declares only
// the documented public surface for that module; the tests
// deliberately do NOT assert on the full walked list, so adding a
// new route is not a backward-incompatible test change.
// ---------------------------------------------------------------------------

func TestRegisterDNSRoutes_StructuralSurface(t *testing.T) {
	runRegTest(t, regTest{
		name:     "RegisterDNSRoutes",
		register: RegisterDNSRoutes,
		want: []string{
			"GET /dns/",
			"GET /dns/new",
			"GET /dns/records",
			"GET /dns/acme",
			"GET /dns/acme/{id}",
			"GET /dns/supported",
			"GET /dns/audit",
			"POST /dns/",
			"POST /dns/records/{id}/delete",
			"POST /dns/acme/{id}/process",
			// /{id} subtree — this is the path that chi panicked on
			// before PR #142. Asserting both GET and POST inside the
			// same subtree pins the fix in place.
			"GET /dns/{id}/",
			"GET /dns/{id}/edit",
			"GET /dns/{id}/records/new",
			"POST /dns/{id}/",
			"POST /dns/{id}/delete",
			"POST /dns/{id}/records",
		},
	})
}

func TestRegisterCalendarRoutes_StructuralSurface(t *testing.T) {
	runRegTest(t, regTest{
		name:     "RegisterCalendarRoutes",
		register: RegisterCalendarRoutes,
		want: []string{
			"GET /calendar/",
			"GET /calendar/new",
			"POST /calendar/",
			"GET /calendar/{id}/edit",
			"POST /calendar/{id}/",
			"DELETE /calendar/{id}/",
		},
	})
}

func TestRegisterCrontabRoutes_StructuralSurface(t *testing.T) {
	runRegTest(t, regTest{
		name:     "RegisterCrontabRoutes",
		register: RegisterCrontabRoutes,
		want: []string{
			"GET /crontab/",
		},
	})
}

func TestRegisterFirewallRoutes_StructuralSurface(t *testing.T) {
	runRegTest(t, regTest{
		name:     "RegisterFirewallRoutes",
		register: RegisterFirewallRoutes,
		want: []string{
			"GET /firewall/",
		},
	})
}

func TestRegisterSSLObservatoryRoutes_StructuralSurface(t *testing.T) {
	runRegTest(t, regTest{
		name:     "RegisterSSLObservatoryRoutes",
		register: RegisterSSLObservatoryRoutes,
		want: []string{
			"GET /ssl/",
		},
	})
}

func TestRegisterWireGuardRoutes_StructuralSurface(t *testing.T) {
	runRegTest(t, regTest{
		name:     "RegisterWireGuardRoutes",
		register: RegisterWireGuardRoutes,
		want: []string{
			"GET /wireguard/",
		},
	})
}

func TestRegisterRollbackRoutes_StructuralSurface(t *testing.T) {
	runRegTest(t, regTest{
		name:     "RegisterRollbackRoutes",
		register: RegisterRollbackRoutes,
		want: []string{
			"GET /rollback/",
		},
	})
}

func TestRegisterBackupVerifyRoutes_StructuralSurface(t *testing.T) {
	runRegTest(t, regTest{
		name:     "RegisterBackupVerifyRoutes",
		register: RegisterBackupVerifyRoutes,
		want: []string{
			"GET /backup-verify/",
		},
	})
}

func TestRegisterImageBuilderRoutes_StructuralSurface(t *testing.T) {
	runRegTest(t, regTest{
		name:     "RegisterImageBuilderRoutes",
		register: RegisterImageBuilderRoutes,
		want: []string{
			"GET /image-builder/",
		},
	})
}

func TestRegisterDockerEngineRoutes_StructuralSurface(t *testing.T) {
	runRegTest(t, regTest{
		name:     "RegisterDockerEngineRoutes",
		register: RegisterDockerEngineRoutes,
		want: []string{
			"GET /config/docker/",
		},
	})
}

func TestRegisterMarketplaceRoutes_StructuralSurface(t *testing.T) {
	runRegTest(t, regTest{
		name:     "RegisterMarketplaceRoutes",
		register: RegisterMarketplaceRoutes,
		want: []string{
			"GET /marketplace/",
		},
	})
}

func TestRegisterEgressRoutes_StructuralSurface(t *testing.T) {
	runRegTest(t, regTest{
		name:     "RegisterEgressRoutes",
		register: RegisterEgressRoutes,
		want: []string{
			// /egress is the v26.5.2 L7 egress filter surface: list +
			// create + delete (form-encoded). The chi-walked routes
			// include the trailing slash on the index path.
			"GET /egress/",
			"POST /egress/",
			"POST /egress/{id}/delete",
		},
	})
}

func TestRegisterYARARoutes_StructuralSurface(t *testing.T) {
	runRegTest(t, regTest{
		name:     "RegisterYARARoutes",
		register: RegisterYARARoutes,
		want: []string{
			// /scan/yara is the v26.5.2 YARA scanner UI. GET renders
			// the form + ruleset list, POST submits a scan; both share
			// the single handler so the result re-renders inline.
			"GET /scan/yara/",
			"POST /scan/yara/",
		},
	})
}

func TestRegisterReconRoutes_StructuralSurface(t *testing.T) {
	runRegTest(t, regTest{
		name:     "RegisterReconRoutes",
		register: RegisterReconRoutes,
		want: []string{
			// Recon dashboard + scans + metadata — the routes that
			// returned 404 in v26.5.1 because of missing web
			// service wiring. PR #142 fixed the wiring; this asserts
			// the route surface itself stays registered.
			"GET /recon/",
			"GET /recon/dashboard",
			"GET /recon/scans",
			"GET /recon/metadata",
			"GET /recon/reports",
			"POST /recon/ack",
		},
	})
}
