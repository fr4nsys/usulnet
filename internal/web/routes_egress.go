// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"github.com/go-chi/chi/v5"
)

// RegisterEgressRoutes attaches the L7 egress filter web UI to the
// authenticated frontend tree. Same nil-safe pattern as the rest of
// the v26.5.x ports: the handler renders a "not configured" page when
// the service is unwired, so registration is unconditional — there is
// no feature flag.
//
// Routes:
//
//	GET  /egress                — list policies + recent denies
//	POST /egress                — create a policy (form-encoded)
//	POST /egress/{id}/delete    — delete a policy (form-encoded)
//
// Reads sit under security:view; mutations sit under security:scan —
// matches the firewall module so role grants compose cleanly.
func RegisterEgressRoutes(r chi.Router, h *Handler, m *Middleware) {
	r.Route("/egress", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(m.RequirePermission("security:view"))
			r.Get("/", h.EgressListTempl)
		})
		r.Group(func(r chi.Router) {
			r.Use(m.RequirePermission("security:scan"))
			r.Post("/", h.EgressCreateTempl)
			r.Post("/{id}/delete", h.EgressDeleteTempl)
		})
	})
}
