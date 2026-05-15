// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"github.com/go-chi/chi/v5"
)

// RegisterFirewallRoutes attaches the firewall web UI to the
// authenticated frontend tree. v26.2.7 mounted these on the top-level
// router; v26.5.1 keeps the same paths but groups them so the
// session-cookie + CSRF middleware applied to the frontend group also
// gates the firewall surface.
//
// All routes degrade gracefully when the firewall service is nil
// (handler_firewall.go renders a "not configured" error page) so this
// registration is unconditional — no feature flag.
func RegisterFirewallRoutes(r chi.Router, h *Handler, m *Middleware) {
	r.Route("/firewall", func(r chi.Router) {
		// Audit log (viewer+): browse-only.
		r.With(m.RequirePermission("security:view")).Get("/audit", h.FirewallAuditTempl)

		// Read endpoints — viewer+.
		r.Group(func(r chi.Router) {
			r.Use(m.RequirePermission("security:view"))
			r.Get("/", h.FirewallListTempl)
			r.Get("/new", h.FirewallNewTempl)
		})

		// Mutations — operator+. The list view's "Apply All" form posts
		// to /firewall/apply and /firewall/sync, both admin actions
		// because they touch the host. Per-rule CRUD is operator+.
		r.Group(func(r chi.Router) {
			r.Use(m.RequirePermission("security:scan"))
			r.Post("/", h.FirewallCreateTempl)
		})

		// Apply / sync — admin only (touches host firewall state).
		r.Group(func(r chi.Router) {
			r.Use(m.AdminRequired)
			r.Post("/apply", h.FirewallApplyTempl)
			r.Post("/sync", h.FirewallSyncTempl)
		})

		// Per-rule routes — viewer+ for read, operator+ for change.
		r.Route("/{id}", func(r chi.Router) {
			r.With(m.RequirePermission("security:view")).Get("/", h.FirewallDetailTempl)
			r.With(m.RequirePermission("security:view")).Get("/edit", h.FirewallEditTempl)
			r.With(m.RequirePermission("security:scan")).Post("/", h.FirewallUpdateTempl)
			r.With(m.RequirePermission("security:scan")).Delete("/", h.FirewallDeleteTempl)
		})
	})
}
