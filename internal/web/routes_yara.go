// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"github.com/go-chi/chi/v5"
)

// RegisterYARARoutes attaches the YARA scanner UI to the authenticated
// frontend tree. Same nil-safe pattern as the rest of the v26.5.x
// modules: the handler renders a "not configured" page when the
// service is unwired (typically because the toolkit image isn't
// available), so registration is unconditional.
//
// Routes:
//
//	GET  /scan/yara      — render form, list rulesets
//	POST /scan/yara      — submit scan, render result inline
//
// Both share a single handler because the result is request-scoped —
// there's no DB row to redirect to, and HTMX partial updates would be
// overkill for a manual on-demand operator action.
//
// Reads + mutations both sit under security:scan (operator+); a
// scanner is an operator surface, not a viewer one.
func RegisterYARARoutes(r chi.Router, h *Handler, m *Middleware) {
	r.Route("/scan/yara", func(r chi.Router) {
		r.Use(m.RequirePermission("security:scan"))
		r.Get("/", h.YARAScanTempl)
		r.Post("/", h.YARAScanTempl)
	})
}
