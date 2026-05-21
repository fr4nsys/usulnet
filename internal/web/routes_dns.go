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
	view := m.RequirePermission("dns:view")
	write := m.RequirePermission("dns:write")

	r.Route("/dns", func(r chi.Router) {
		// Top-level read endpoints — viewer+.
		r.With(view).Get("/", h.DNSProvidersTempl)
		r.With(view).Get("/new", h.DNSProviderNewTempl)
		r.With(view).Get("/records", h.DNSRecordsTempl)
		r.With(view).Get("/acme", h.DNSACMETempl)
		r.With(view).Get("/acme/{id}", h.DNSACMEDetailTempl)
		r.With(view).Get("/supported", h.DNSSupportedTempl)
		r.With(view).Get("/audit", h.DNSAuditTempl)

		// Top-level mutating endpoints — operator+.
		r.With(write).Post("/", h.DNSProviderCreateTempl)
		r.With(write).Post("/records/{id}/delete", h.DNSRecordDeleteTempl)
		r.With(write).Post("/acme/{id}/process", h.DNSACMEProcessTempl)

		// Per-provider scope. A single subrouter mounted on /{id} so chi
		// doesn't panic on a second Mount() at the same path. Each child
		// route applies its own permission middleware inline.
		r.Route("/{id}", func(r chi.Router) {
			r.With(view).Get("/", h.DNSProviderDetailTempl)
			r.With(view).Get("/edit", h.DNSProviderEditTempl)
			r.With(view).Get("/records/new", h.DNSRecordNewTempl)

			r.With(write).Post("/", h.DNSProviderUpdateTempl)
			r.With(write).Post("/delete", h.DNSProviderDeleteTempl)
			r.With(write).Post("/records", h.DNSRecordCreateTempl)
		})
	})
}
