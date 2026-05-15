// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"github.com/go-chi/chi/v5"
)

// RegisterRollbackRoutes attaches the automated rollback web UI to the
// authenticated frontend tree.
//
// All routes degrade gracefully when the rollback service is nil
// (handler_rollback.go renders a "not configured" error page). The
// registration is unconditional — no feature flag, no biz gate.
func RegisterRollbackRoutes(r chi.Router, h *Handler, m *Middleware) {
	r.Route("/rollback", func(r chi.Router) {
		// Read endpoints — viewer+. Audit, execution log, and the
		// policy list are all viewer-readable.
		r.Group(func(r chi.Router) {
			r.Use(m.RequirePermission("security:view"))
			r.Get("/", h.RollbackListTempl)
			r.Get("/audit", h.RollbackAuditTempl)
			r.Get("/executions", h.RollbackExecutionsTempl)
			r.Get("/executions/{id}", h.RollbackExecutionDetailTempl)
		})

		// Mutations — operator+. Creating/editing policies and running
		// dry-runs append audit rows, so operator-only.
		r.Group(func(r chi.Router) {
			r.Use(m.RequirePermission("security:scan"))
			r.Get("/new", h.RollbackNewTempl)
			r.Post("/", h.RollbackCreateTempl)
		})

		// Per-policy routes — viewer+ for read, operator+ for change.
		r.Route("/{id}", func(r chi.Router) {
			r.With(m.RequirePermission("security:view")).Get("/", h.RollbackDetailTempl)
			r.With(m.RequirePermission("security:scan")).Get("/edit", h.RollbackEditTempl)
			r.With(m.RequirePermission("security:scan")).Post("/update", h.RollbackUpdateTempl)
			r.With(m.RequirePermission("security:scan")).Post("/delete", h.RollbackDeleteTempl)
			r.With(m.RequirePermission("security:scan")).Get("/dry-run", h.RollbackDryRunGetTempl)
			r.With(m.RequirePermission("security:scan")).Post("/dry-run", h.RollbackDryRunPostTempl)
		})
	})
}
