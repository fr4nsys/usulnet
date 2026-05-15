// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"github.com/go-chi/chi/v5"
)

// RegisterMarketplaceRoutes attaches the marketplace web UI to the
// authenticated frontend tree. All routes degrade gracefully when the
// marketplace service is nil (the handler renders a "not configured"
// page), so registration is unconditional — no biz gate.
func RegisterMarketplaceRoutes(r chi.Router, h *Handler, m *Middleware) {
	r.Route("/marketplace", func(r chi.Router) {
		// Read endpoints — viewer+.
		r.Group(func(r chi.Router) {
			r.Use(m.RequirePermission("marketplace:view"))
			r.Get("/", h.MarketplaceListTempl)
			r.Get("/installed", h.MarketplaceInstalledTempl)
			r.Get("/submit", h.MarketplaceSubmitTempl)
		})

		// Mutations — operator+.
		r.Group(func(r chi.Router) {
			r.Use(m.RequirePermission("marketplace:write"))
			r.Post("/submit", h.MarketplaceSubmitCreateTempl)
		})

		// Per-slug routes.
		r.Route("/{slug}", func(r chi.Router) {
			r.With(m.RequirePermission("marketplace:view")).Get("/", h.MarketplaceDetailTempl)
			r.With(m.RequirePermission("marketplace:view")).Get("/install", h.MarketplaceInstallTempl)
			r.With(m.RequirePermission("marketplace:write")).Post("/install", h.MarketplaceInstallCreateTempl)
			r.With(m.RequirePermission("marketplace:view")).Get("/review", h.MarketplaceReviewTempl)
			r.With(m.RequirePermission("marketplace:write")).Post("/review", h.MarketplaceReviewCreateTempl)
		})

		// Per-installation routes.
		r.Route("/installations/{id}", func(r chi.Router) {
			r.With(m.RequirePermission("marketplace:write")).Post("/uninstall", h.MarketplaceUninstallTempl)
		})
	})
}
