// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubOnboarding is a minimal onboardingChecker for middleware tests.
type stubOnboarding struct{ done bool }

func (s stubOnboarding) IsCompleted() bool { return s.done }

// passThrough is the handler the middleware wraps in these tests. We
// record whether it ran so we can assert pass-through vs redirect.
type passThrough struct{ called bool }

func (p *passThrough) ServeHTTP(http.ResponseWriter, *http.Request) { p.called = true }

func TestOnboardingRequired_PassesThroughWhenCompleted(t *testing.T) {
	next := &passThrough{}
	mw := OnboardingRequired(stubOnboarding{done: true})(next)

	r := httptest.NewRequest(http.MethodGet, "/containers", nil)
	r = r.WithContext(context.WithValue(r.Context(), ContextKeyUser, &UserContext{Role: "admin"}))
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	if !next.called {
		t.Error("completed onboarding must pass through to the wrapped handler")
	}
	if w.Result().StatusCode == http.StatusSeeOther {
		t.Error("completed onboarding must not redirect")
	}
}

func TestOnboardingRequired_RedirectsAdminWhenIncomplete(t *testing.T) {
	next := &passThrough{}
	mw := OnboardingRequired(stubOnboarding{done: false})(next)

	r := httptest.NewRequest(http.MethodGet, "/containers", nil)
	r = r.WithContext(context.WithValue(r.Context(), ContextKeyUser, &UserContext{Role: "admin"}))
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	if next.called {
		t.Error("admin on /containers during onboarding must NOT pass through")
	}
	if got := w.Result().StatusCode; got != http.StatusSeeOther {
		t.Errorf("expected 303 See Other redirect, got %d", got)
	}
	if got := w.Header().Get("Location"); got != "/onboarding/welcome" {
		t.Errorf("expected redirect to /onboarding/welcome, got %q", got)
	}
}

func TestOnboardingRequired_NonAdminAlwaysPassesThrough(t *testing.T) {
	next := &passThrough{}
	mw := OnboardingRequired(stubOnboarding{done: false})(next)

	for _, role := range []string{"operator", "viewer"} {
		t.Run(role, func(t *testing.T) {
			next.called = false
			r := httptest.NewRequest(http.MethodGet, "/containers", nil)
			r = r.WithContext(context.WithValue(r.Context(), ContextKeyUser, &UserContext{Role: role}))
			w := httptest.NewRecorder()
			mw.ServeHTTP(w, r)

			if !next.called {
				t.Errorf("non-admin role %q must skip the wizard and pass through", role)
			}
		})
	}
}

func TestOnboardingRequired_ExemptPathsBypass(t *testing.T) {
	mw := OnboardingRequired(stubOnboarding{done: false})

	cases := []string{
		"/onboarding/welcome",
		"/onboarding/done",
		"/api/v1/containers",
		"/static/css/style.css",
		"/login",
		"/logout",
		"/auth/oauth/callback",
		"/health",
		"/metrics",
		"/favicon.ico",
	}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			next := &passThrough{}
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r = r.WithContext(context.WithValue(r.Context(), ContextKeyUser, &UserContext{Role: "admin"}))
			w := httptest.NewRecorder()
			mw(next).ServeHTTP(w, r)

			if !next.called {
				t.Errorf("exempt path %q must pass through even during onboarding", path)
			}
		})
	}
}

func TestOnboardingRequired_NilServiceFailsOpen(t *testing.T) {
	// If the wiring never plumbed an onboarding service in (e.g., a
	// build that strips out the feature), the middleware must not
	// pin every operator on the wizard forever.
	next := &passThrough{}
	mw := OnboardingRequired(nil)(next)

	r := httptest.NewRequest(http.MethodGet, "/containers", nil)
	r = r.WithContext(context.WithValue(r.Context(), ContextKeyUser, &UserContext{Role: "admin"}))
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	if !next.called {
		t.Error("nil onboarding service must pass through (fail-open on missing wiring)")
	}
}
