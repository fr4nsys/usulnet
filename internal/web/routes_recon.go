// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"github.com/go-chi/chi/v5"
)

// RegisterReconRoutes attaches the v26.5.0 recon and metadata routes to
// the given router. It is called from RegisterFrontendRoutes inside the
// authenticated group so the existing auth/CSRF middleware applies.
//
// The recon module is feature-flag gated at the service layer: when the
// service is nil or IsEnabled() returns false the handlers themselves
// short-circuit with 404, matching the API behavior described in
// docs/v26.5/technical-notes.md "Feature flag".
func RegisterReconRoutes(r chi.Router, h *Handler, m *Middleware) {
	// Privacy & Recon UI pages.
	//
	// All HTMX / form endpoints live under /recon/* so the session-cookie
	// auth + CSRF middleware applied to this Group is what gates them.
	// The canonical JSON API at /api/v1/recon/* and /api/v1/metadata/* is
	// owned by internal/api/handlers (Bearer / API-key auth); the web
	// layer must not mount onto those prefixes — chi's trie resolves the
	// deeper Route() to the web subtree, which would shadow every
	// /api/v1/recon/* and /api/v1/metadata/* endpoint and break the JSON
	// surface for any API client.
	r.Route("/recon", func(r chi.Router) {
		// Viewer-level pages — anyone with security:view can browse.
		r.Group(func(r chi.Router) {
			r.Use(m.RequirePermission("security:view"))
			r.Get("/", redirect301("/recon/dashboard"))
			r.Get("/dashboard", h.ReconDashboardTempl)
			r.Get("/targets", h.ReconTargetsListTempl)
			r.Get("/targets/{id}", h.ReconTargetDetailTempl)
			r.Get("/scans", h.ReconScansListTempl)
			r.Get("/scans/{id}", h.ReconScanDetailTempl)
			r.Get("/scans/{id}/findings", h.ReconScanFindingsPartial)
			r.Get("/scans/{id}/progress", h.ReconScanProgressPartial)
			r.Get("/metadata", h.MetadataUploadTempl)
			r.Get("/metadata/jobs/{id}", h.MetadataJobDetailTempl)
			r.Get("/metadata/artifacts/{id}/stripped", h.MetadataDownloadStripped)
			r.Get("/reports", h.ReconReportsTempl)
		})

		// Operator-level — metadata job creation needs security:scan.
		r.Group(func(r chi.Router) {
			r.Use(m.RequirePermission("security:scan"))
			r.Post("/metadata/jobs", h.MetadataUploadSubmit)
		})

		// Admin-only pages and actions.
		r.Group(func(r chi.Router) {
			r.Use(m.AdminRequired)
			r.Get("/connectors", h.ReconConnectorsTempl)
			r.Post("/ack", h.ReconAck)
		})
	})
}
