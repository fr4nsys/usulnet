// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"github.com/go-chi/chi/v5"
)

// RegisterDockerEngineRoutes attaches the Docker engine config editor
// to the authenticated frontend tree.
//
// Read endpoints (editor + history) require security:view; the
// destructive endpoints (apply + restore) require admin because they
// touch the host's daemon configuration and can take dockerd offline.
//
// Registration is unconditional — the handler renders an "unavailable"
// page when the service is nil. No biz gate, no edition check.
func RegisterDockerEngineRoutes(r chi.Router, h *Handler, m *Middleware) {
	r.Route("/config/docker", func(r chi.Router) {
		r.With(m.RequirePermission("security:view")).Get("/", h.DockerEngineEditorTempl)
		r.With(m.RequirePermission("security:view")).Get("/history", h.DockerEngineHistoryTempl)
		r.With(m.AdminRequired).Post("/apply", h.DockerEngineApplyTempl)
		r.With(m.AdminRequired).Post("/restore/{id}", h.DockerEngineRestoreTempl)
	})
}
