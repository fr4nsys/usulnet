// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"net/http"
	"unicode/utf8"

	"github.com/fr4nsys/usulnet/internal/web/templates/pages/onboarding"
)

// OnboardingService is the narrow contract the wizard handler needs.
// Implemented by *services/onboarding.Service.
type OnboardingService interface {
	IsCompleted() bool
	MarkComplete(ctx context.Context) error
}

// OnboardingSvc returns the wired onboarding service, or nil if the
// dependency was never injected (e.g., in tests).
func (h *Handler) OnboardingSvc() OnboardingService {
	if h == nil {
		return nil
	}
	return h.onboardingSvc
}

// OnboardingCompleted is the nil-safe form of OnboardingSvc().IsCompleted().
// When the service isn't wired, we report completed so the wizard
// pages don't render — same fail-open behaviour as the middleware.
func (h *Handler) OnboardingCompleted() bool {
	svc := h.OnboardingSvc()
	if svc == nil {
		return true
	}
	return svc.IsCompleted()
}

// minWizardPasswordLen is the floor enforced by the wizard. The
// session-19 hardening review picked 12 — long enough to defeat
// offline brute force against the bcrypt cost factor used elsewhere
// in usulnet, short enough that operators can still type a memorable
// passphrase. The /profile password-change endpoint uses the
// configured PasswordPolicy, but the wizard ships before any policy
// can be configured, so it carries its own minimal check.
const minWizardPasswordLen = 12

// OnboardingWelcomeTempl renders the mandatory password-change form.
func (h *Handler) OnboardingWelcomeTempl(w http.ResponseWriter, r *http.Request) {
	if h.OnboardingCompleted() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	user := GetUserFromContext(r.Context())
	username := ""
	if user != nil {
		username = user.Username
	}
	h.renderTempl(w, r, onboarding.Welcome(onboarding.WelcomeData{
		Username:  username,
		CSRFToken: GetCSRFTokenFromContext(r.Context()),
	}))
}

// OnboardingWelcomeSubmit handles POST /onboarding/welcome — it
// validates and writes the new admin password, then renders the
// "done" step. It does NOT call MarkComplete yet; the operator has
// to explicitly click "Finish setup" on the done page.
func (h *Handler) OnboardingWelcomeSubmit(w http.ResponseWriter, r *http.Request) {
	if h.OnboardingCompleted() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	newPassword := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	if errMsg := validateWizardPassword(newPassword, confirm, user.Username); errMsg != "" {
		h.renderTempl(w, r, onboarding.Welcome(onboarding.WelcomeData{
			Username:  user.Username,
			CSRFToken: GetCSRFTokenFromContext(r.Context()),
			Error:     errMsg,
		}))
		return
	}

	if h.userRepo == nil {
		h.renderTempl(w, r, onboarding.Welcome(onboarding.WelcomeData{
			Username:  user.Username,
			CSRFToken: GetCSRFTokenFromContext(r.Context()),
			Error:     "User repository unavailable. The wizard cannot continue.",
		}))
		return
	}

	currentHash, err := h.userRepo.GetPasswordHash(user.ID)
	if err != nil {
		h.renderTempl(w, r, onboarding.Welcome(onboarding.WelcomeData{
			Username:  user.Username,
			CSRFToken: GetCSRFTokenFromContext(r.Context()),
			Error:     "Could not read the current admin record. Try again.",
		}))
		return
	}

	newHash := h.hashPassword(newPassword)
	if err := h.userRepo.UpdatePassword(user.ID, currentHash, newHash); err != nil {
		h.renderTempl(w, r, onboarding.Welcome(onboarding.WelcomeData{
			Username:  user.Username,
			CSRFToken: GetCSRFTokenFromContext(r.Context()),
			Error:     "Failed to save the new password. " + err.Error(),
		}))
		return
	}

	http.Redirect(w, r, "/onboarding/done", http.StatusSeeOther)
}

// OnboardingDoneTempl renders the "you're set" step. The redirect to
// here only happens after a successful password write, so reaching it
// implies the mandatory step is satisfied.
func (h *Handler) OnboardingDoneTempl(w http.ResponseWriter, r *http.Request) {
	if h.OnboardingCompleted() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	h.renderTempl(w, r, onboarding.Done(onboarding.DoneData{
		CSRFToken: GetCSRFTokenFromContext(r.Context()),
	}))
}

// OnboardingFinish handles POST /onboarding/finish — flips the
// onboarding_completed flag and sends the operator to the dashboard.
// The middleware stops redirecting after the flag flips, so future
// requests skip the wizard.
func (h *Handler) OnboardingFinish(w http.ResponseWriter, r *http.Request) {
	svc := h.OnboardingSvc()
	if svc == nil {
		// No onboarding service wired — fall back to a plain redirect
		// so the operator still reaches the dashboard. The
		// middleware's fail-open path covers subsequent navigation.
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := svc.MarkComplete(r.Context()); err != nil {
		h.renderTempl(w, r, onboarding.Done(onboarding.DoneData{
			CSRFToken: GetCSRFTokenFromContext(r.Context()),
		}))
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// validateWizardPassword runs the in-wizard password floor. The full
// PasswordPolicy isn't applied here because a fresh install hasn't
// configured one yet — see minWizardPasswordLen for the rationale.
func validateWizardPassword(newPassword, confirm, username string) string {
	if newPassword == "" {
		return "New password is required."
	}
	if newPassword != confirm {
		return "Passwords do not match."
	}
	if utf8.RuneCountInString(newPassword) < minWizardPasswordLen {
		return "Password must be at least 12 characters."
	}
	// Reject the default bootstrap credential by name. Anyone who
	// would type "usulnet" as the "new" password has not understood
	// the wizard's purpose — fail fast with a clearer message than
	// the generic length check.
	if newPassword == "usulnet" {
		return "Pick a real password — not the default bootstrap credential."
	}
	if newPassword == username {
		return "Password cannot match the username."
	}
	return ""
}
