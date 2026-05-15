// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"github.com/go-chi/chi/v5"
)

// RegisterImageBuilderRoutes attaches the image builder web UI to the
// authenticated frontend tree. Per the v26.5.1 "one AGPL build"
// principle, registration is unconditional — when the service is nil
// the handler renders a "not configured" page instead.
//
// RBAC: read endpoints require `image:view`, mutations require
// `image:create` (the same permissions that gate the existing image
// pull/build buttons in the regular images view).
func RegisterImageBuilderRoutes(r chi.Router, h *Handler, m *Middleware) {
	r.Route("/image-builder", func(r chi.Router) {
		r.With(m.RequirePermission("image:view")).Get("/", h.ImageBuilderListTempl)
		r.With(m.RequirePermission("image:view")).Get("/new", h.ImageBuilderNewTempl)
		r.With(m.RequirePermission("image:create")).Post("/", h.ImageBuilderCreateTempl)

		r.With(m.RequirePermission("image:view")).Get("/templates", h.ImageBuilderTemplateListTempl)
		r.With(m.RequirePermission("image:view")).Get("/templates/new", h.ImageBuilderTemplateNewTempl)
		r.With(m.RequirePermission("image:create")).Post("/templates", h.ImageBuilderTemplateCreateTempl)
		r.With(m.RequirePermission("image:create")).Post("/templates/{id}/delete", h.ImageBuilderTemplateDeleteTempl)

		// {id} segment must come last so it does not shadow the
		// /templates and /new sub-trees above.
		r.With(m.RequirePermission("image:view")).Get("/{id}", h.ImageBuilderDetailTempl)
	})
}
