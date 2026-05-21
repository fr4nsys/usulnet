// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestChiMux_UseAfterRoutePanics pins the chi v5 contract that
// broke the v26.5.2 session 04b onboarding wizard PR: calling Use()
// after a route is registered on the same mux panics with
// "all middlewares must be defined before routes on a mux".
//
// The smoke E2E caught the crash at boot, but the panic surfaces
// only when the binary actually serves HTTP, so unit tests had
// missed it. This test makes the failure cheap: if a future router
// edit reintroduces the pattern, `go test ./internal/web/` panics
// here instead of `docker logs usulnet`.
//
// The corresponding "good" path (Use BEFORE Get) is verified by
// TestRegisterFrontendRoutes_OnboardingMiddlewareOrder below.
func TestChiMux_UseAfterRoutePanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected chi to panic when Use() runs after a route is registered")
		}
		// The exact wording is the chi v5 panic text. If chi
		// rephrases it in a future release the test still
		// catches the broken order (any panic is a fail of the
		// "Use after Route" pattern); the strict-match is just
		// a maintainer hint pointing at the right doc.
		_ = r
	}()

	router := chi.NewRouter()
	router.Group(func(r chi.Router) {
		r.Get("/first", func(w http.ResponseWriter, _ *http.Request) {})
		r.Use(func(next http.Handler) http.Handler { return next })
		r.Get("/second", func(w http.ResponseWriter, _ *http.Request) {})
	})
	t.Fatal("chi did not panic — the v26.5.2 PR-153 bug class is no longer enforced")
}

// TestRegisterFrontendRoutes_OnboardingMiddlewareOrder pins the
// FIXED order: OnboardingRequired sits with the other Use() calls
// at the top of the authenticated Group, BEFORE any routes are
// registered. The chi mux accepts this order without panic.
//
// The test stops at the router-construction step. It doesn't try
// to wire the full Handler — that requires ~40 dependencies. The
// panic class we're guarding against happens at route registration,
// so reproducing the chi pattern is enough.
func TestRegisterFrontendRoutes_OnboardingMiddlewareOrder(t *testing.T) {
	router := chi.NewRouter()
	router.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler { return next })
		r.Use(OnboardingRequired(nil))
		r.Get("/onboarding/welcome", func(w http.ResponseWriter, _ *http.Request) {})
		r.Get("/dashboard", func(w http.ResponseWriter, _ *http.Request) {})
	})
	// If we got here without a panic the Use-then-Route order is correct.
}

// TestRegisterFrontendRoutes_DoesNotPanic exercises the real
// RegisterFrontendRoutes with the same zero-value Handler / Middleware
// skeleton used by the routes_register_test.go suite. The function
// declares hundreds of routes, and PR #153 introduced a chi v5
// panic by calling Use(OnboardingRequired(...)) after a Get(). This
// test now drives that registration end-to-end and panics the test
// instead of `docker logs usulnet` if the bug class recurs.
func TestRegisterFrontendRoutes_DoesNotPanic(t *testing.T) {
	r := chi.NewRouter()
	h := newRegTestHandler()
	m := newRegTestMiddleware()

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("RegisterFrontendRoutes panicked: %v", rec)
		}
	}()
	RegisterFrontendRoutes(r, h, m)
}
