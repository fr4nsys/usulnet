// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

// ============================================================================
// Profile Routes — add inside RegisterRoutes() in routes_frontend.go
// ============================================================================
//
// Add these routes within the authenticated router group:
//
//   // Profile
//   r.Route("/profile", func(r chi.Router) {
//       r.Get("/", h.ProfilePage)
//       r.Put("/", h.UpdateProfile)
//       r.Put("/password", h.UpdatePassword)
//       r.Put("/preferences", h.UpdatePreferences)
//       r.Post("/preferences/reset", h.ResetPreferences)
//       r.Post("/export", h.ExportUserData)
//       r.Delete("/", h.DeleteAccount)      // if implemented
//       r.Delete("/sessions", h.DeleteAllSessions)
//       r.Delete("/sessions/{id}", h.DeleteSession)
//   })
//
//   // Quick theme toggle (called from sidebar/header button)
//   r.Post("/profile/theme", h.ToggleTheme)
//
// ============================================================================
// Middleware Registration (in main router setup)
// ============================================================================
//
// The PreferencesMiddleware should be placed AFTER auth middleware:
//
//   r.Group(func(r chi.Router) {
//       r.Use(h.authMiddleware)          // sets UserInfo in context
//       r.Use(PreferencesMiddleware(h.prefsRepo)) // loads preferences
//
//       // ... all authenticated routes here ...
//   })
//
// ============================================================================
// Handler struct additions
// ============================================================================
//
// Add these fields to your Handler struct:
//
//   type Handler struct {
//       // ... existing fields ...
//       userRepo    UserRepository
//       prefsRepo   PreferencesRepository
//       sessionRepo SessionRepository
//   }
