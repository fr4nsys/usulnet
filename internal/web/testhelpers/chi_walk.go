// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package testhelpers exposes small utilities used across the web
// package's tests. The single resident today is ChiWalk, which
// serialises a chi router into a stable []"METHOD PATH" slice so
// per-routes tests can assert on the registered surface without
// reflecting into chi internals.
//
// This package is test-only by convention; the production web code
// never imports it.
package testhelpers

import (
	"fmt"
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"
)

// ChiWalk walks every (method, pattern) tuple registered on r and
// returns them as "METHOD PATTERN" strings in stable lexicographic
// order. Useful in routes_*.go tests that want to assert the public
// surface without binding to a chi-specific tree representation.
func ChiWalk(r chi.Router) []string {
	var routes []string
	walker := func(method, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		routes = append(routes, fmt.Sprintf("%s %s", method, route))
		return nil
	}
	if err := chi.Walk(r, walker); err != nil {
		panic(fmt.Sprintf("chi.Walk failed: %v", err))
	}
	sort.Strings(routes)
	return routes
}

// ChiWalkContains reports whether the walked routes contain the
// exact "METHOD PATTERN" tuple.
func ChiWalkContains(routes []string, method, pattern string) bool {
	want := fmt.Sprintf("%s %s", method, pattern)
	for _, r := range routes {
		if r == want {
			return true
		}
	}
	return false
}
