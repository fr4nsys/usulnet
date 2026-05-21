// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"net/http"
	"strings"

	"github.com/fr4nsys/usulnet/internal/models"
)

// onboardingChecker is the narrow contract the middleware needs from
// the onboarding service. Declared here so the middleware doesn't
// depend on the concrete service type.
type onboardingChecker interface {
	IsCompleted() bool
}

// onboardingExemptPrefixes lists paths the middleware never redirects
// regardless of the flag state. The wizard's own routes are exempt
// (otherwise we'd redirect-loop), as is the logout endpoint (so a
// confused operator can escape), every API surface (machines can't
// fill in HTML forms), and every asset path (browsers fetch them
// during the wizard render itself).
//
// The list is intentionally exhaustive — failing open here would
// silently bypass the password-change requirement.
var onboardingExemptPrefixes = []string{
	"/onboarding/",
	"/api/",
	"/static/",
	"/health",
	"/metrics",
	"/login",
	"/logout",
	"/auth/",
	"/favicon",
}

// OnboardingRequired redirects an unfinished admin to /onboarding/welcome
// before any other page renders. Non-admins and finished installs pass
// through unchanged.
//
// Mounts AFTER AuthRequired so the user is already in context. Mounts
// BEFORE the per-route permission middleware so the redirect happens
// before any RBAC denial — an admin trying to view /containers during
// onboarding ends up on the wizard, not a "Forbidden" page.
func OnboardingRequired(svc onboardingChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if svc == nil || svc.IsCompleted() {
				next.ServeHTTP(w, r)
				return
			}

			if isOnboardingExempt(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			user := GetUserFromContext(r.Context())
			if user == nil || user.Role != string(models.RoleAdmin) {
				// Non-admins (operator/viewer) skip the wizard. A fresh
				// install only has the bootstrap admin, so this branch
				// is reached after additional users are seeded out of
				// band — they get the regular app once they log in.
				next.ServeHTTP(w, r)
				return
			}

			http.Redirect(w, r, "/onboarding/welcome", http.StatusSeeOther)
		})
	}
}

func isOnboardingExempt(path string) bool {
	for _, p := range onboardingExemptPrefixes {
		if path == p || strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}
