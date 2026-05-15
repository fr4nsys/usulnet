// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"github.com/go-chi/chi/v5"
)

// RegisterWireGuardRoutes attaches the WireGuard web UI to the
// authenticated frontend tree. v26.2.7 mounted these on the top-level
// router; v26.5.1 keeps the same paths but applies per-method RBAC.
//
// Registration is unconditional — when the service is nil the handler
// renders a "not configured" page (typically because the data
// encryption key is unset). No biz/edition gating.
func RegisterWireGuardRoutes(r chi.Router, h *Handler, m *Middleware) {
	r.Route("/wireguard", func(r chi.Router) {
		// Top-level views — viewer+ reads, operator+ writes.
		r.With(m.RequirePermission("security:view")).Get("/", h.WireGuardListTempl)
		r.With(m.RequirePermission("security:view")).Get("/new", h.WireGuardNewTempl)
		r.With(m.RequirePermission("security:view")).Get("/peers", h.WireGuardPeerListTempl)
		r.With(m.RequirePermission("security:view")).Get("/mesh", h.WireGuardMeshTempl)

		r.With(m.RequirePermission("security:scan")).Post("/", h.WireGuardCreateTempl)

		// Interface-scoped routes.
		r.Route("/{id}", func(r chi.Router) {
			r.With(m.RequirePermission("security:view")).Get("/", h.WireGuardDetailTempl)
			r.With(m.RequirePermission("security:view")).Get("/peers/new", h.WireGuardPeerNewTempl)
			r.With(m.RequirePermission("security:scan")).Post("/delete", h.WireGuardDeleteTempl)
			r.With(m.RequirePermission("security:scan")).Post("/peers", h.WireGuardPeerCreateTempl)
		})

		// Peer-scoped routes.
		r.Route("/peers/{peerID}", func(r chi.Router) {
			r.With(m.RequirePermission("security:view")).Get("/", h.WireGuardPeerDetailTempl)
			r.With(m.RequirePermission("security:scan")).Post("/delete", h.WireGuardPeerDeleteTempl)
		})
	})
}
