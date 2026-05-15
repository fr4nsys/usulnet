// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"github.com/go-chi/chi/v5"
)

// RegisterSSLObservatoryRoutes attaches the SSL observatory web UI to
// the authenticated frontend tree. v26.5.1 keeps the same paths as
// v26.2.7 but drops the biz gate — the registration is unconditional.
//
// All routes degrade gracefully when the service is nil
// (handler_ssl_observatory.go renders a "not configured" error page).
func RegisterSSLObservatoryRoutes(r chi.Router, h *Handler, m *Middleware) {
	r.Route("/ssl", func(r chi.Router) {
		// Dashboard (viewer+)
		r.With(m.RequirePermission("security:view")).Get("/", h.SSLDashboardTempl)

		// Scan-all (operator+ — touches outbound network)
		r.With(m.RequirePermission("security:scan")).Post("/scan-all", h.SSLScanAllTempl)

		r.Route("/targets", func(r chi.Router) {
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("security:view"))
				r.Get("/", h.SSLTargetListTempl)
				r.Get("/new", h.SSLTargetNewTempl)
			})

			r.With(m.RequirePermission("security:scan")).Post("/", h.SSLTargetCreateTempl)

			r.Route("/{id}", func(r chi.Router) {
				r.With(m.RequirePermission("security:view")).Get("/", h.SSLTargetDetailTempl)
				r.With(m.RequirePermission("security:view")).Get("/edit", h.SSLTargetEditTempl)
				r.With(m.RequirePermission("security:scan")).Post("/edit", h.SSLTargetUpdateTempl)
				r.With(m.RequirePermission("security:scan")).Post("/scan", h.SSLScanTargetTempl)
				r.With(m.RequirePermission("security:scan")).Delete("/", h.SSLTargetDeleteTempl)
			})
		})
	})
}
