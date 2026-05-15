// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"github.com/go-chi/chi/v5"
)

// RegisterCrontabRoutes attaches the crontab web UI to the authenticated
// frontend tree. v26.2.7 mounted these on the top-level router; v26.5.1
// keeps the same paths but groups them so the session-cookie + CSRF
// middleware applied to the frontend group also gates the crontab surface.
//
// All routes degrade gracefully when the crontab service is nil
// (handler_crontab.go renders a "not configured" error page) so this
// registration is unconditional — no feature flag.
func RegisterCrontabRoutes(r chi.Router, h *Handler, m *Middleware) {
	r.Route("/crontab", func(r chi.Router) {
		// Read endpoints — viewer+.
		r.Group(func(r chi.Router) {
			r.Use(m.RequirePermission("crontab:view"))
			r.Get("/", h.CrontabListTempl)
			r.Get("/new", h.CrontabNewTempl)
		})

		// Create — operator+.
		r.Group(func(r chi.Router) {
			r.Use(m.RequirePermission("crontab:execute"))
			r.Post("/", h.CrontabCreateTempl)
		})

		// Per-entry routes.
		r.Route("/{id}", func(r chi.Router) {
			r.With(m.RequirePermission("crontab:view")).Get("/", h.CrontabDetailTempl)
			r.With(m.RequirePermission("crontab:view")).Get("/edit", h.CrontabEditTempl)
			r.With(m.RequirePermission("crontab:execute")).Post("/", h.CrontabUpdateTempl)
			r.With(m.RequirePermission("crontab:execute")).Delete("/", h.CrontabDeleteTempl)
			r.With(m.RequirePermission("crontab:execute")).Post("/toggle", h.CrontabToggleTempl)
			r.With(m.RequirePermission("crontab:execute")).Post("/run", h.CrontabRunNowTempl)
		})
	})
}
