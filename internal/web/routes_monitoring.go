// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

// ============================================================================
// Monitoring Routes — add inside RegisterRoutes() in routes_frontend.go
// ============================================================================
//
// Add these routes within the authenticated router group:
//
//   // Monitoring
//   r.Route("/monitoring", func(r chi.Router) {
//       r.Get("/", h.MonitoringPage)                    // Global dashboard
//       r.Get("/container/{id}", h.MonitoringContainerPage) // Per-container detail
//   })
//
// Add these WebSocket routes (can be inside or outside auth middleware,
// depending on whether WS auth is handled via query param token or cookie):
//
//   // Monitoring WebSockets
//   r.Get("/ws/monitoring/stats", h.WsMonitoringStats)           // Global live stats
//   r.Get("/ws/monitoring/container/{id}", h.WsMonitoringContainer) // Per-container live stats
//
// ============================================================================
// Full example integration:
// ============================================================================
//
//  func (h *Handler) RegisterRoutes(r chi.Router) {
//      // ... existing routes ...
//
//      r.Group(func(r chi.Router) {
//          r.Use(h.authMiddleware)
//
//          // ... existing authenticated routes ...
//
//          // Monitoring
//          r.Get("/monitoring", h.MonitoringPage)
//          r.Get("/monitoring/container/{id}", h.MonitoringContainerPage)
//
//          // Monitoring WebSockets
//          r.Get("/ws/monitoring/stats", h.WsMonitoringStats)
//          r.Get("/ws/monitoring/container/{id}", h.WsMonitoringContainer)
//      })
//  }
