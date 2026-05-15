// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"github.com/go-chi/chi/v5"
)

// RegisterDNSRoutes attaches the DNS provider web UI to the
// authenticated frontend tree. v26.5.1 nil-safe pattern: registration
// is unconditional and the handler renders a "not configured" page
// when wiring is missing (typically because the data encryption key
// is unset).
func RegisterDNSRoutes(r chi.Router, h *Handler, m *Middleware) {
	r.Route("/dns", func(r chi.Router) {
		// Read endpoints — viewer+.
		r.Group(func(r chi.Router) {
			r.Use(m.RequirePermission("dns:view"))
			r.Get("/", h.DNSProvidersTempl)
			r.Get("/new", h.DNSProviderNewTempl)
			r.Get("/records", h.DNSRecordsTempl)
			r.Get("/acme", h.DNSACMETempl)
			r.Get("/acme/{id}", h.DNSACMEDetailTempl)
			r.Get("/supported", h.DNSSupportedTempl)
			r.Get("/audit", h.DNSAuditTempl)

			r.Route("/{id}", func(r chi.Router) {
				r.Get("/", h.DNSProviderDetailTempl)
				r.Get("/edit", h.DNSProviderEditTempl)
				r.Get("/records/new", h.DNSRecordNewTempl)
			})
		})

		// Mutating endpoints — operator+.
		r.Group(func(r chi.Router) {
			r.Use(m.RequirePermission("dns:write"))
			r.Post("/", h.DNSProviderCreateTempl)

			r.Route("/{id}", func(r chi.Router) {
				r.Post("/", h.DNSProviderUpdateTempl)
				r.Post("/delete", h.DNSProviderDeleteTempl)
				r.Post("/records", h.DNSRecordCreateTempl)
			})

			r.Post("/records/{id}/delete", h.DNSRecordDeleteTempl)

			r.Post("/acme/{id}/process", h.DNSACMEProcessTempl)
		})
	})
}
