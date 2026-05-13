// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/profile"
	"github.com/fr4nsys/usulnet/internal/web/templates/types"
)

// ============================================================================
// Repository Interfaces (implement with your DB layer)
// ============================================================================

// UserRepository defines operations for user data.
type UserRepository interface {
	GetUserByID(id string) (*UserInfo, error)
	UpdateUser(id string, username string, email string) error
	UpdatePassword(id string, currentHash string, newHash string) error
	GetPasswordHash(id string) (string, error)
	DeleteUser(id string) error
}

// PreferencesRepository defines operations for user preferences.
type PreferencesRepository interface {
	PreferencesLoader // embeds GetUserPreferences
	SaveUserPreferences(userID string, prefsJSON string) error
	DeleteUserPreferences(userID string) error
	GetSidebarPrefs(ctx context.Context, userID string) (string, error)
	SaveSidebarPrefs(ctx context.Context, userID string, prefsJSON string) error
}

// SessionRepository defines operations for user sessions.
type SessionRepository interface {
	GetUserSessions(userID string) ([]profile.SessionInfo, error)
	DeleteSession(sessionID string) error
	DeleteAllSessionsExcept(userID string, currentSessionID string) error
	GetCurrentSessionID(r *http.Request) string
}

// ============================================================================
// Profile Page Handler (GET /profile)
// ============================================================================

// ProfilePage renders the user profile page.
func (h *Handler) ProfilePage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := GetUserInfo(ctx)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	prefs := GetPreferences(ctx)
	activeTab := r.URL.Query().Get("tab")
	if activeTab == "" {
		activeTab = "profile"
	}

	// Build timezone options with selection
	timezones := make([]profile.SelectOption, 0, len(AvailableTimezones()))
	for _, tz := range AvailableTimezones() {
		timezones = append(timezones, profile.SelectOption{
			Value:    tz.Value,
			Label:    tz.Label,
			Selected: tz.Value == prefs.Timezone,
		})
	}

	// Build language options with selection
	languages := make([]profile.SelectOption, 0, len(AvailableLanguages()))
	for _, lang := range AvailableLanguages() {
		languages = append(languages, profile.SelectOption{
			Value:    lang.Value,
			Label:    lang.Label,
			Selected: lang.Value == prefs.Language,
		})
	}

	// Get sessions if on security tab
	var sessions []profile.SessionInfo
	if activeTab == "security" && h.sessionRepo != nil {
		sessions, _ = h.sessionRepo.GetUserSessions(user.ID)
		currentSID := h.sessionRepo.GetCurrentSessionID(r)
		for i := range sessions {
			if sessions[i].ID == currentSID {
				sessions[i].IsCurrent = true
			}
		}
	}

	// Flash messages from session
	var flashMsg, flashType string
	if flash := GetFlashFromContext(r.Context()); flash != nil {
		flashMsg = flash.Message
		flashType = flash.Type
	}

	data := profile.ProfilePageData{
		PageData: h.prepareTemplPageData(r, "Profile", "profile"),
		User: profile.UserProfileData{
			ID:        user.ID,
			Username:  user.Username,
			Email:     user.Email,
			Role:      user.Role,
			IsActive:  user.IsActive,
			Created:   prefs.FormatDate(h.getUserCreated(user.ID)),
			LastLogin: h.getUserLastLogin(user.ID, prefs),
		},
		Prefs: profile.PreferencesData{
			Theme:                 string(prefs.Theme),
			Language:              prefs.Language,
			Timezone:              prefs.Timezone,
			DateFormat:            string(prefs.DateFormat),
			TimeFormat:            string(prefs.TimeFormat),
			ContainerView:         string(prefs.ContainerView),
			DefaultLogLines:       int(prefs.DefaultLogLines),
			RefreshInterval:       int(prefs.RefreshInterval),
			ShowStoppedContainers: prefs.ShowStoppedContainers,
			NotifyUpdates:         prefs.NotifyUpdates,
			NotifySecurity:        prefs.NotifySecurity,
			NotifyBackups:         prefs.NotifyBackups,
			NotifyContainer:       prefs.NotifyContainer,
			EditorMode:            prefs.EditorMode,
			EditorFontSize:        prefs.EditorFontSize,
			EditorTabSize:         prefs.EditorTabSize,
		},
		Timezones: timezones,
		Languages: languages,
		Sessions:  sessions,
		ActiveTab: activeTab,
		FlashMsg:  flashMsg,
		FlashType: flashType,
		CSRFToken: h.getCSRFToken(r),
	}

	profile.Profile(data).Render(ctx, w)
}

// ============================================================================
// Update Profile (PUT /profile)
// ============================================================================

func (h *Handler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	user := GetUserInfo(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		h.redirect(w, r, "/profile")
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	email := strings.TrimSpace(r.FormValue("email"))

	if username == "" {
		h.setFlash(w, r, "error", "Username cannot be empty")
		h.redirect(w, r, "/profile")
		return
	}

	if h.userRepo != nil {
		if err := h.userRepo.UpdateUser(user.ID, username, email); err != nil {
			h.setFlash(w, r, "error", fmt.Sprintf("Failed to update profile: %s", err.Error()))
			h.redirect(w, r, "/profile")
			return
		}
	}

	h.setFlash(w, r, "success", "Profile updated successfully")
	h.redirect(w, r, "/profile")
}

// ============================================================================
// Update Password (PUT /profile/password)
// ============================================================================

func (h *Handler) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	user := GetUserInfo(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		h.redirect(w, r, "/profile?tab=security")
		return
	}

	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	// Validation
	if currentPassword == "" || newPassword == "" || confirmPassword == "" {
		h.setFlash(w, r, "error", "All password fields are required")
		h.redirect(w, r, "/profile?tab=security")
		return
	}

	if len(newPassword) < 8 {
		h.setFlash(w, r, "error", "New password must be at least 8 characters")
		h.redirect(w, r, "/profile?tab=security")
		return
	}

	if newPassword != confirmPassword {
		h.setFlash(w, r, "error", "New passwords do not match")
		h.redirect(w, r, "/profile?tab=security")
		return
	}

	if newPassword == currentPassword {
		h.setFlash(w, r, "error", "New password must be different from current password")
		h.redirect(w, r, "/profile?tab=security")
		return
	}

	// Verify current password and update
	if h.userRepo != nil {
		currentHash, err := h.userRepo.GetPasswordHash(user.ID)
		if err != nil {
			h.setFlash(w, r, "error", "Failed to verify current password")
			h.redirect(w, r, "/profile?tab=security")
			return
		}

		// Use the project's crypto.ComparePassword (from Dept A)
		if !h.verifyPassword(currentPassword, currentHash) {
			h.setFlash(w, r, "error", "Current password is incorrect")
			h.redirect(w, r, "/profile?tab=security")
			return
		}

		newHash := h.hashPassword(newPassword)
		if err := h.userRepo.UpdatePassword(user.ID, currentHash, newHash); err != nil {
			h.setFlash(w, r, "error", "Failed to update password")
			h.redirect(w, r, "/profile?tab=security")
			return
		}
	}

	h.setFlash(w, r, "success", "Password updated successfully")
	h.redirect(w, r, "/profile?tab=security")
}

// ============================================================================
// Update Preferences (PUT /profile/preferences)
// ============================================================================

func (h *Handler) UpdatePreferences(w http.ResponseWriter, r *http.Request) {
	user := GetUserInfo(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		h.redirect(w, r, "/profile?tab=preferences")
		return
	}

	// Parse form into preferences
	partial := UserPreferences{
		Theme:                 Theme(r.FormValue("theme")),
		Language:              r.FormValue("language"),
		Timezone:              r.FormValue("timezone"),
		DateFormat:            DateFormat(r.FormValue("date_format")),
		TimeFormat:            TimeFormat(r.FormValue("time_format")),
		ContainerView:         ViewMode(r.FormValue("container_view")),
		ShowStoppedContainers: r.FormValue("show_stopped_containers") == "true",
		NotifyUpdates:         r.FormValue("notify_updates") == "true",
		NotifySecurity:        r.FormValue("notify_security") == "true",
		NotifyBackups:         r.FormValue("notify_backups") == "true",
		NotifyContainer:       r.FormValue("notify_container") == "true",
		EditorMode:            r.FormValue("editor_mode"),
	}

	if v, err := strconv.Atoi(r.FormValue("default_log_lines")); err == nil && v > 0 {
		partial.DefaultLogLines = LogLineCount(v)
	}
	if v, err := strconv.Atoi(r.FormValue("refresh_interval")); err == nil && v >= 0 {
		partial.RefreshInterval = RefreshInterval(v)
	}
	if v, err := strconv.Atoi(r.FormValue("editor_font_size")); err == nil && v >= 10 && v <= 24 {
		partial.EditorFontSize = v
	}
	if v, err := strconv.Atoi(r.FormValue("editor_tab_size")); err == nil && v > 0 {
		partial.EditorTabSize = v
	}

	// Load current preferences, merge, save
	current := GetPreferences(r.Context())
	current.Merge(partial)

	if h.prefsRepo != nil {
		prefsJSON, err := current.ToJSON()
		if err != nil {
			h.setFlash(w, r, "error", "Failed to serialize preferences")
			h.redirect(w, r, "/profile?tab=preferences")
			return
		}
		if err := h.prefsRepo.SaveUserPreferences(user.ID, prefsJSON); err != nil {
			h.setFlash(w, r, "error", "Failed to save preferences")
			h.redirect(w, r, "/profile?tab=preferences")
			return
		}
	}

	// Update theme cookie immediately
	setThemeCookie(w, current.Theme)

	h.setFlash(w, r, "success", "Preferences saved successfully")
	h.redirect(w, r, "/profile?tab=preferences")
}

// ============================================================================
// Reset Preferences (POST /profile/preferences/reset)
// ============================================================================

func (h *Handler) ResetPreferences(w http.ResponseWriter, r *http.Request) {
	user := GetUserInfo(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	defaults := DefaultPreferences()
	if h.prefsRepo != nil {
		prefsJSON, _ := defaults.ToJSON()
		h.prefsRepo.SaveUserPreferences(user.ID, prefsJSON)
	}

	setThemeCookie(w, defaults.Theme)

	h.setFlash(w, r, "success", "Preferences reset to defaults")
	h.redirect(w, r, "/profile?tab=preferences")
}

// ============================================================================
// Session Management
// ============================================================================

// DeleteSession revokes a single session (DELETE /profile/sessions/{id}).
func (h *Handler) DeleteSession(w http.ResponseWriter, r *http.Request) {
	user := GetUserInfo(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	sessionID := chi.URLParam(r, "id")
	if h.sessionRepo != nil {
		h.sessionRepo.DeleteSession(sessionID)
	}

	// Return empty div so HTMX removes the row
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(""))
}

// DeleteAllSessions revokes all sessions except current (DELETE /profile/sessions).
func (h *Handler) DeleteAllSessions(w http.ResponseWriter, r *http.Request) {
	user := GetUserInfo(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if h.sessionRepo != nil {
		currentSID := h.sessionRepo.GetCurrentSessionID(r)
		h.sessionRepo.DeleteAllSessionsExcept(user.ID, currentSID)
	}

	h.setFlash(w, r, "success", "All other sessions revoked")
	h.redirect(w, r, "/profile?tab=security")
}

// ExportUserData exports user data as JSON (POST /profile/export).
func (h *Handler) ExportUserData(w http.ResponseWriter, r *http.Request) {
	user := GetUserInfo(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	prefs := GetPreferences(r.Context())
	prefsJSON, _ := prefs.ToJSON()

	export := fmt.Sprintf(`{
  "user": {
    "id": %q,
    "username": %q,
    "email": %q,
    "role": %q
  },
  "preferences": %s
}`, user.ID, user.Username, user.Email, user.Role, prefsJSON)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="usulnet-export-%s.json"`, user.Username))
	w.Write([]byte(export))
}

// ============================================================================
// Delete Account (DELETE /profile)
// ============================================================================

// DeleteAccount handles account self-deletion.
func (h *Handler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	user := GetUserInfo(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Prevent admin from deleting themselves if they are the only admin
	if user.Role == "admin" {
		ctx := r.Context()
		if st, err := h.services.Users().GetStats(ctx); err == nil && st != nil && st.Admins <= 1 {
			h.setFlash(w, r, "error", "Cannot delete the last admin account")
			h.redirect(w, r, "/profile")
			return
		}
	}

	if h.userRepo != nil {
		if err := h.userRepo.DeleteUser(user.ID); err != nil {
			slog.Error("Failed to delete account", "user_id", user.ID, "error", err)
			h.setFlash(w, r, "error", "Failed to delete account: "+err.Error())
			h.redirect(w, r, "/profile")
			return
		}
	}

	// Clear session and redirect to login
	_ = h.sessionStore.Delete(r, w, CookieSession)
	h.redirect(w, r, "/login")
}

// ============================================================================
// Toggle Theme (POST /profile/theme) — Quick toggle endpoint for header button
// ============================================================================

func (h *Handler) ToggleTheme(w http.ResponseWriter, r *http.Request) {
	user := GetUserInfo(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	current := GetPreferences(r.Context())

	var newTheme Theme
	switch current.Theme {
	case ThemeDark:
		newTheme = ThemeLight
	case ThemeLight:
		newTheme = ThemeDark
	default:
		newTheme = ThemeDark
	}

	current.Theme = newTheme
	setThemeCookie(w, newTheme)

	if h.prefsRepo != nil {
		prefsJSON, _ := current.ToJSON()
		h.prefsRepo.SaveUserPreferences(user.ID, prefsJSON)
	}

	// Redirect back to where they were
	referer := r.Header.Get("Referer")
	if referer == "" {
		referer = "/"
	}
	h.redirect(w, r, referer)
}

// ============================================================================
// Update Sidebar Preferences (PUT /profile/sidebar-prefs)
// ============================================================================

// UpdateSidebarPrefs handles sidebar collapse/visibility state updates.
// Accepts JSON body with optional "collapsed" and/or "hidden" maps.
// Merges incoming values into existing preferences.
func (h *Handler) UpdateSidebarPrefs(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var incoming struct {
		Collapsed map[string]bool `json:"collapsed"`
		Hidden    map[string]bool `json:"hidden"`
	}
	if err := json.Unmarshal(body, &incoming); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Load existing prefs from DB
	existing := types.DefaultSidebarPreferences()
	if h.prefsRepo != nil {
		prefsJSON, err := h.prefsRepo.GetSidebarPrefs(r.Context(), user.ID)
		if err == nil && prefsJSON != "" {
			var sp types.SidebarPreferences
			if err := json.Unmarshal([]byte(prefsJSON), &sp); err == nil {
				if sp.Collapsed != nil {
					existing.Collapsed = sp.Collapsed
				}
				if sp.Hidden != nil {
					existing.Hidden = sp.Hidden
				}
			}
		}
	}

	// Merge incoming state
	if incoming.Collapsed != nil {
		existing.Collapsed = incoming.Collapsed
	}
	if incoming.Hidden != nil {
		existing.Hidden = incoming.Hidden
	}

	// Save back to DB
	if h.prefsRepo != nil {
		out, err := json.Marshal(existing)
		if err != nil {
			http.Error(w, "Failed to serialize", http.StatusInternalServerError)
			return
		}
		if err := h.prefsRepo.SaveSidebarPrefs(r.Context(), user.ID, string(out)); err != nil {
			slog.Error("Failed to save sidebar prefs", "user_id", user.ID, "error", err)
			http.Error(w, "Failed to save", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

// ============================================================================
// Helper Methods (stubs — implement with your Handler struct fields)
// ============================================================================

// These reference fields that should exist on the Handler struct:
//
//   type Handler struct {
//       // ... existing fields ...
//       userRepo    UserRepository
//       prefsRepo   PreferencesRepository
//       sessionRepo SessionRepository
//   }

// getUserCreated returns the creation date of a user.
// Falls back to querying sessions if the user repository doesn't provide CreatedAt.
func (h *Handler) getUserCreated(userID string) time.Time {
	if h.userRepo != nil {
		if u, err := h.userRepo.GetUserByID(userID); err == nil && u != nil {
			if !u.CreatedAt.IsZero() {
				return u.CreatedAt
			}
		}
	}
	return time.Time{}
}

// getUserLastLogin returns the last login timestamp formatted according to preferences.
func (h *Handler) getUserLastLogin(userID string, prefs UserPreferences) string {
	if h.sessionRepo == nil {
		return ""
	}
	sessions, err := h.sessionRepo.GetUserSessions(userID)
	if err != nil || len(sessions) == 0 {
		return ""
	}
	// Find the most recent session's LastUsed time
	var latest string
	for _, s := range sessions {
		if s.LastUsed > latest {
			latest = s.LastUsed
		}
	}
	return latest
}

// verifyPassword checks if the plain password matches the hash.
func (h *Handler) verifyPassword(plain string, hash string) bool {
	return crypto.CheckPassword(plain, hash)
}

// hashPassword creates a bcrypt hash of the password.
func (h *Handler) hashPassword(plain string) string {
	hash, err := crypto.HashPassword(plain)
	if err != nil {
		return ""
	}
	return hash
}

// getCSRFToken extracts CSRF token from context.
func (h *Handler) getCSRFToken(r *http.Request) string {
	return GetCSRFTokenFromContext(r.Context())
}
