// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"net/http"
)

// ============================================================================
// Context Keys
// ============================================================================

type contextKey string

const (
	preferencesKey contextKey = "user_preferences"
	userInfoKey    contextKey = "user_info"
)

// UserInfo represents the authenticated user data available in request context.
type UserInfo struct {
	ID       string
	Username string
	Email    string
	Role     string // admin, operator, viewer
	IsActive bool
}

// ============================================================================
// Preferences Middleware
// ============================================================================

// PreferencesLoader is the interface for loading user preferences from storage.
// Implement this with your repository layer (e.g., PostgreSQL, SQLite).
type PreferencesLoader interface {
	GetUserPreferences(ctx context.Context, userID string) (string, error) // returns JSON string
}

// PreferencesMiddleware loads user preferences for the authenticated user
// and injects them into the request context. All downstream handlers and
// templates can then access preferences without additional DB calls.
//
// Must be placed AFTER authentication middleware (needs UserInfo in context).
func PreferencesMiddleware(loader PreferencesLoader) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserInfo(r.Context())
			if user == nil {
				// No authenticated user, use defaults
				ctx := context.WithValue(r.Context(), preferencesKey, DefaultPreferences())
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Load preferences from storage
			prefsJSON, err := loader.GetUserPreferences(r.Context(), user.ID)
			if err != nil {
				// On error, fall back to defaults
				ctx := context.WithValue(r.Context(), preferencesKey, DefaultPreferences())
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			prefs := PreferencesFromJSON(prefsJSON)

			// Apply theme via cookie for CSS class toggle (no JS flash)
			setThemeCookie(w, prefs.Theme)

			ctx := context.WithValue(r.Context(), preferencesKey, prefs)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ============================================================================
// Context Accessors
// ============================================================================

// GetPreferences retrieves UserPreferences from the request context.
// Returns defaults if not present.
func GetPreferences(ctx context.Context) UserPreferences {
	prefs, ok := ctx.Value(preferencesKey).(UserPreferences)
	if !ok {
		return DefaultPreferences()
	}
	return prefs
}

// GetUserInfo retrieves UserInfo from the request context.
// Returns nil if no authenticated user.
func GetUserInfo(ctx context.Context) *UserInfo {
	info, ok := ctx.Value(userInfoKey).(*UserInfo)
	if !ok {
		return nil
	}
	return info
}

// WithUserInfo adds UserInfo to the context.
// Used by the auth middleware when setting up the authenticated user.
func WithUserInfo(ctx context.Context, info *UserInfo) context.Context {
	return context.WithValue(ctx, userInfoKey, info)
}

// ============================================================================
// Theme Cookie
// ============================================================================

// setThemeCookie sets a cookie so the HTML <html> tag can read the theme
// on page load without waiting for JS. Prevents flash of wrong theme.
func setThemeCookie(w http.ResponseWriter, theme Theme) {
	http.SetCookie(w, &http.Cookie{
		Name:     "usulnet_theme",
		Value:    string(theme),
		Path:     "/",
		MaxAge:   365 * 24 * 3600, // 1 year
		HttpOnly: false,           // JS needs to read this for runtime toggle
		SameSite: http.SameSiteLaxMode,
	})
}
