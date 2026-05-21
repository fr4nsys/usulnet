// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package testhelpers

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestChiWalk_EmptyRouter(t *testing.T) {
	r := chi.NewRouter()
	got := ChiWalk(r)
	if len(got) != 0 {
		t.Errorf("empty router should walk to 0 routes; got %v", got)
	}
}

func TestChiWalk_FlatRoutes(t *testing.T) {
	r := chi.NewRouter()
	r.Get("/a", noopHandler)
	r.Post("/b", noopHandler)
	r.Put("/c", noopHandler)

	got := ChiWalk(r)
	if len(got) != 3 {
		t.Fatalf("want 3 routes, got %d: %v", len(got), got)
	}
	// Sorted lex order: METHOD comes before /; "GET /a" < "POST /b" < "PUT /c"
	for i, want := range []string{"GET /a", "POST /b", "PUT /c"} {
		if got[i] != want {
			t.Errorf("position %d: want %q, got %q", i, want, got[i])
		}
	}
}

func TestChiWalk_NestedRoutes(t *testing.T) {
	r := chi.NewRouter()
	r.Route("/api", func(r chi.Router) {
		r.Get("/users", noopHandler)
		r.Post("/users", noopHandler)
		r.Route("/users/{id}", func(r chi.Router) {
			r.Get("/", noopHandler)
			r.Delete("/", noopHandler)
		})
	})

	got := ChiWalk(r)
	wants := []string{
		"GET /api/users",
		"POST /api/users",
		"GET /api/users/{id}/",
		"DELETE /api/users/{id}/",
	}
	for _, w := range wants {
		idx := indexSpace(w)
		method, pattern := w[:idx], w[idx+1:]
		if !ChiWalkContains(got, method, pattern) {
			t.Errorf("missing route %q; got: %v", w, got)
		}
	}
}

func TestChiWalkContains_MissingReturnsFalse(t *testing.T) {
	routes := []string{"GET /a", "POST /b"}
	if ChiWalkContains(routes, "DELETE", "/a") {
		t.Error("DELETE /a should not be present")
	}
	if !ChiWalkContains(routes, "GET", "/a") {
		t.Error("GET /a should be present")
	}
}

// noopHandler is the simplest http.Handler that closes over nothing
// so the walker has something to find.
func noopHandler(_ http.ResponseWriter, _ *http.Request) {}

func indexSpace(s string) int {
	for i := range s {
		if s[i] == ' ' {
			return i
		}
	}
	return -1
}
