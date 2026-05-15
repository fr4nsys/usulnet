// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"github.com/go-chi/chi/v5"
)

// RegisterBackupVerifyRoutes attaches the backup verification web UI to the
// authenticated frontend tree. v26.2.7 mounted these on the top-level
// router; v26.5.1 keeps the same paths but groups them so session-cookie +
// CSRF middleware applies.
//
// All routes degrade gracefully when the service is nil (handler renders
// a "not configured" page) so this registration is unconditional — no
// edition gate, in line with principles.md §2.
func RegisterBackupVerifyRoutes(r chi.Router, h *Handler, m *Middleware) {
	r.Route("/backup-verify", func(r chi.Router) {
		// Read endpoints — viewer+.
		r.Group(func(r chi.Router) {
			r.Use(m.RequirePermission("backups:view"))
			r.Get("/", h.BackupVerifyListTempl)
			r.Get("/schedules", h.BackupVerifyScheduleListTempl)
			r.Get("/schedules/new", h.BackupVerifyScheduleNewTempl)
			r.Get("/{id}", h.BackupVerifyDetailTempl)
		})

		// Mutations — operator+.
		r.Group(func(r chi.Router) {
			r.Use(m.RequirePermission("backups:execute"))
			r.Post("/schedules", h.BackupVerifyScheduleCreateTempl)
			r.Delete("/schedules/{id}", h.BackupVerifyScheduleDeleteTempl)
			r.Post("/{backupID}/verify", h.BackupVerifyRunTempl)
		})
	})
}
