// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"github.com/go-chi/chi/v5"
)

// RegisterCalendarRoutes attaches the calendar web UI to the authenticated
// frontend tree. All routes degrade gracefully when the calendar service
// is nil (handler_calendar.go renders a "not configured" error page), so
// registration is unconditional — no feature flag.
func RegisterCalendarRoutes(r chi.Router, h *Handler, m *Middleware) {
	r.Route("/calendar", func(r chi.Router) {
		// Read endpoints — viewer+.
		r.Group(func(r chi.Router) {
			r.Use(m.RequirePermission("calendar:view"))
			r.Get("/", h.CalendarListTempl)
			r.Get("/new", h.CalendarNewTempl)
		})

		// Create — operator+.
		r.Group(func(r chi.Router) {
			r.Use(m.RequirePermission("calendar:write"))
			r.Post("/", h.CalendarCreateTempl)
		})

		// Per-event routes.
		r.Route("/{id}", func(r chi.Router) {
			r.With(m.RequirePermission("calendar:view")).Get("/edit", h.CalendarEditTempl)
			r.With(m.RequirePermission("calendar:write")).Post("/", h.CalendarUpdateTempl)
			r.With(m.RequirePermission("calendar:write")).Delete("/", h.CalendarDeleteTempl)
		})
	})
}
