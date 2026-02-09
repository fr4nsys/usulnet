// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ContextKey is a custom type for context keys to avoid collisions.
type ContextKey string

const (
	// Context keys
	ContextKeyUser       ContextKey = "user"
	ContextKeyTheme      ContextKey = "theme"
	ContextKeyRequestID  ContextKey = "request_id"
	ContextKeyCSRFToken  ContextKey = "csrf_token"
	ContextKeyFlash      ContextKey = "flash"
	ContextKeyStats      ContextKey = "stats"
	ContextKeyActiveHost ContextKey = "active_host_id"
)

// SessionStore interface for session management.
type SessionStore interface {
	Get(r *http.Request, name string) (*Session, error)
	Save(r *http.Request, w http.ResponseWriter, session *Session) error
	Delete(r *http.Request, w http.ResponseWriter, name string) error
}

// Session represents a user session.
type Session struct {
	ID        string
	UserID    string
	Username  string
	Role      string
	Theme     string
	CSRFToken string
	CreatedAt time.Time
	ExpiresAt time.Time
	Values    map[string]interface{}
}

// AuthService interface for authentication.
type AuthService interface {
	ValidateSession(ctx context.Context, sessionID string) (*UserContext, error)
	GetUserByID(ctx context.Context, userID string) (*UserContext, error)
	Login(ctx context.Context, username, password, userAgent, ipAddress string) (*UserContext, error)
	VerifyCredentials(ctx context.Context, username, password, userAgent, ipAddress string) (*UserContext, error)
	CreateSessionForUser(ctx context.Context, userID, userAgent, ipAddress string) (*UserContext, error)
	Logout(ctx context.Context, sessionID string) error
}

// StatsService interface for fetching global stats.
type StatsService interface {
	GetGlobalStats(ctx context.Context) (*GlobalStats, error)
}

// Middleware contains middleware dependencies.
type Middleware struct {
	sessionStore  SessionStore
	authService   AuthService
	statsService  StatsService
	scopeProvider ScopeProvider
	roleProvider  RoleProvider
	sessionName   string
	loginPath     string
	excludePaths  []string
}

// MiddlewareConfig contains middleware configuration.
type MiddlewareConfig struct {
	SessionName  string
	LoginPath    string
	ExcludePaths []string
}

// NewMiddleware creates a new Middleware instance.
func NewMiddleware(
	sessionStore SessionStore,
	authService AuthService,
	statsService StatsService,
	config MiddlewareConfig,
) *Middleware {
	if config.SessionName == "" {
		config.SessionName = "usulnet_session"
	}
	if config.LoginPath == "" {
		config.LoginPath = "/login"
	}
	return &Middleware{
		sessionStore: sessionStore,
		authService:  authService,
		statsService: statsService,
		sessionName:  config.SessionName,
		loginPath:    config.LoginPath,
		excludePaths: config.ExcludePaths,
	}
}

// AuthRequired middleware ensures the user is authenticated.
// Redirects to login page if not authenticated.
func (m *Middleware) AuthRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if path is excluded from auth
		if m.isExcludedPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Try to get session
		session, err := m.sessionStore.Get(r, m.sessionName)
		if err != nil || session == nil || session.UserID == "" {
			m.redirectToLogin(w, r)
			return
		}

		// Check session expiration
		if time.Now().After(session.ExpiresAt) {
			_ = m.sessionStore.Delete(r, w, m.sessionName)
			m.redirectToLogin(w, r)
			return
		}

		// Validate session with auth service
		user, err := m.authService.ValidateSession(r.Context(), session.ID)
		if err != nil || user == nil {
			_ = m.sessionStore.Delete(r, w, m.sessionName)
			m.redirectToLogin(w, r)
			return
		}

		// Add user to context
		ctx := context.WithValue(r.Context(), ContextKeyUser, user)
		
		// Add theme to context
		theme := session.Theme
		if theme == "" {
			theme = "dark"
		}
		ctx = context.WithValue(ctx, ContextKeyTheme, theme)

		// Add CSRF token to context
		if session.CSRFToken == "" {
			slog.Warn("session has empty CSRF token", "session_id", session.ID, "user_id", session.UserID)
		}
		ctx = context.WithValue(ctx, ContextKeyCSRFToken, session.CSRFToken)

		// Add active host ID from session
		if activeHost, ok := session.Values["active_host_id"].(string); ok && activeHost != "" {
			ctx = context.WithValue(ctx, ContextKeyActiveHost, activeHost)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// InjectCommonData middleware injects common data needed by all pages.
func (m *Middleware) InjectCommonData(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Fetch global stats if stats service is available
		if m.statsService != nil {
			stats, err := m.statsService.GetGlobalStats(ctx)
			if err == nil && stats != nil {
				ctx = context.WithValue(ctx, ContextKeyStats, stats)
			}
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ThemeMiddleware extracts and applies theme preference.
func (m *Middleware) ThemeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Check if theme is already in context (from auth middleware)
		if ctx.Value(ContextKeyTheme) != nil {
			next.ServeHTTP(w, r)
			return
		}

		// Try to get theme from cookie
		theme := "dark" // default
		if cookie, err := r.Cookie("usulnet_theme"); err == nil {
			if cookie.Value == "light" || cookie.Value == "dark" {
				theme = cookie.Value
			}
		}

		ctx = context.WithValue(ctx, ContextKeyTheme, theme)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// CSRFMiddleware validates CSRF token on POST/PUT/DELETE requests.
func (m *Middleware) CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only validate on state-changing methods
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		// Skip CSRF check for API endpoints (they use different auth)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		// Get expected token from context
		expectedToken, ok := r.Context().Value(ContextKeyCSRFToken).(string)
		if !ok || expectedToken == "" {
			slog.Warn("CSRF validation failed: no token in context",
				"path", r.URL.Path,
				"method", r.Method,
			)
			http.Error(w, "CSRF validation failed", http.StatusForbidden)
			return
		}

		// Get token from request
		token := r.FormValue("csrf_token")
		if token == "" {
			token = r.Header.Get("X-CSRF-Token")
		}

		// Validate token
		if token != expectedToken {
			slog.Warn("CSRF validation failed: token mismatch",
				"path", r.URL.Path,
				"method", r.Method,
				"expected_len", len(expectedToken),
				"received_len", len(token),
				"received_empty", token == "",
			)
			http.Error(w, "CSRF validation failed", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RoleRequired middleware ensures user has required role.
func (m *Middleware) RoleRequired(allowedRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := r.Context().Value(ContextKeyUser).(*UserContext)
			if !ok || user == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Check if user role is in allowed roles
			roleAllowed := false
			for _, role := range allowedRoles {
				if strings.EqualFold(user.Role, role) {
					roleAllowed = true
					break
				}
			}

			if !roleAllowed {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// AdminRequired middleware ensures user is admin.
func (m *Middleware) AdminRequired(next http.Handler) http.Handler {
	return m.RoleRequired("admin")(next)
}

// OperatorRequired middleware ensures user is admin or operator.
func (m *Middleware) OperatorRequired(next http.Handler) http.Handler {
	return m.RoleRequired("admin", "operator")(next)
}

// FlashMiddleware handles flash messages from session.
func (m *Middleware) FlashMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Get session
		session, err := m.sessionStore.Get(r, m.sessionName)
		if err == nil && session != nil {
			// Check for flash message
			if flash, ok := session.Values["flash"].(*FlashMessage); ok && flash != nil {
				ctx = context.WithValue(ctx, ContextKeyFlash, flash)
				// Clear flash from session
				delete(session.Values, "flash")
				_ = m.sessionStore.Save(r, w, session)
			}
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// redirectToLogin redirects to login page with return URL.
func (m *Middleware) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	// For HTMX requests, send HX-Redirect header
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", m.loginPath)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Store original URL for redirect after login
	returnURL := r.URL.Path
	if r.URL.RawQuery != "" {
		returnURL += "?" + r.URL.RawQuery
	}

	redirectURL := m.loginPath
	if returnURL != "/" && returnURL != m.loginPath {
		redirectURL += "?return=" + returnURL
	}

	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// isExcludedPath checks if path is excluded from auth.
func (m *Middleware) isExcludedPath(path string) bool {
	// Always exclude login path
	if path == m.loginPath {
		return true
	}

	// Check configured exclude paths
	for _, p := range m.excludePaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}

	return false
}

// GetUserFromContext extracts user from request context.
func GetUserFromContext(ctx context.Context) *UserContext {
	user, _ := ctx.Value(ContextKeyUser).(*UserContext)
	return user
}

// GetThemeFromContext extracts theme from request context.
func GetThemeFromContext(ctx context.Context) string {
	theme, _ := ctx.Value(ContextKeyTheme).(string)
	if theme == "" {
		return "dark"
	}
	return theme
}

// GetCSRFTokenFromContext extracts CSRF token from request context.
func GetCSRFTokenFromContext(ctx context.Context) string {
	token, _ := ctx.Value(ContextKeyCSRFToken).(string)
	return token
}

// GetStatsFromContext extracts global stats from request context.
func GetStatsFromContext(ctx context.Context) *GlobalStats {
	stats, _ := ctx.Value(ContextKeyStats).(*GlobalStats)
	return stats
}

// GetFlashFromContext extracts flash message from request context.
func GetFlashFromContext(ctx context.Context) *FlashMessage {
	flash, _ := ctx.Value(ContextKeyFlash).(*FlashMessage)
	return flash
}

// GetActiveHostIDFromContext extracts the active host ID from the request context.
func GetActiveHostIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(ContextKeyActiveHost).(string)
	return id
}

// SetFlash stores a flash message in the session.
func SetFlash(w http.ResponseWriter, r *http.Request, sessionStore SessionStore, sessionName string, msgType, message string) error {
	session, err := sessionStore.Get(r, sessionName)
	if err != nil {
		return err
	}
	if session.Values == nil {
		session.Values = make(map[string]interface{})
	}
	session.Values["flash"] = &FlashMessage{
		Type:    msgType,
		Message: message,
	}
	return sessionStore.Save(r, w, session)
}

// NoCache middleware adds headers to prevent caching.
func NoCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		next.ServeHTTP(w, r)
	})
}

// SecureHeaders adds security headers to response.
func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// RecoverPanic middleware recovers from panics and shows error page.
func RecoverPanic(handler *Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					log.Printf("[PANIC] recovered: %v, path: %s", err, r.URL.Path)
					handler.RenderError(w, r, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// ============================================================================
// Resource Scoping Middleware
// ============================================================================

// ContextKeyScope is the context key for the computed ResourceScope.
const ContextKeyScope ContextKey = "resource_scope"

// ScopeProvider computes user resource scope.
// Implemented by the team service.
type ScopeProvider interface {
	GetUserScope(ctx context.Context, userID string, userRole string) (*models.ResourceScope, error)
}

// SetScopeProvider sets the scope provider on the middleware.
// Call after NewMiddleware when the team service is ready.
func (m *Middleware) SetScopeProvider(sp ScopeProvider) {
	m.scopeProvider = sp
}

// ResourceScopeMiddleware computes and injects the ResourceScope into context.
// Must run AFTER AuthRequired (needs UserContext in context).
func (m *Middleware) ResourceScopeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromContext(r.Context())
		if user == nil {
			// No user in context → skip scoping (AuthRequired should have rejected)
			next.ServeHTTP(w, r)
			return
		}

		if m.scopeProvider == nil {
			// No scope provider configured → no scoping (backward compat)
			scope := &models.ResourceScope{NoTeamsExist: true}
			ctx := context.WithValue(r.Context(), ContextKeyScope, scope)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		scope, err := m.scopeProvider.GetUserScope(r.Context(), user.ID, user.Role)
		if err != nil {
			// On error, fail open (don't block the request)
			log.Printf("[WARN] scope computation failed for user %s: %v", user.ID, err)
			scope = &models.ResourceScope{NoTeamsExist: true}
		}

		ctx := context.WithValue(r.Context(), ContextKeyScope, scope)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetScopeFromContext extracts the ResourceScope from context.
// Returns a non-filtering scope if not present.
func GetScopeFromContext(ctx context.Context) *models.ResourceScope {
	scope, _ := ctx.Value(ContextKeyScope).(*models.ResourceScope)
	if scope == nil {
		return &models.ResourceScope{NoTeamsExist: true}
	}
	return scope
}

// ============================================================================
// Permission Checking
// ============================================================================

// ContextKeyRole is the context key for the user's role with permissions.
const ContextKeyRole ContextKey = "user_role"

// RoleProvider fetches a role by ID.
type RoleProvider interface {
	GetByID(ctx context.Context, id string) (*models.Role, error)
}

// SetRoleProvider sets the role provider on the middleware.
func (m *Middleware) SetRoleProvider(rp RoleProvider) {
	m.roleProvider = rp
}

// RequirePermission creates a middleware that checks for a specific permission.
// If the user doesn't have the permission, returns 403 Forbidden.
func (m *Middleware) RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Admin users have all permissions
			if user.Role == "admin" {
				next.ServeHTTP(w, r)
				return
			}

			// Get user's role and check permission
			if m.roleProvider != nil && user.RoleID != "" {
				role, err := m.roleProvider.GetByID(r.Context(), user.RoleID)
				if err == nil && role != nil && role.HasPermission(permission) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Fallback: check legacy role permissions
			if hasLegacyPermission(user.Role, permission) {
				next.ServeHTTP(w, r)
				return
			}

			http.Error(w, "Forbidden: missing permission "+permission, http.StatusForbidden)
		})
	}
}

// RequireAnyPermission creates a middleware that checks for any of the specified permissions.
func (m *Middleware) RequireAnyPermission(permissions ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Admin users have all permissions
			if user.Role == "admin" {
				next.ServeHTTP(w, r)
				return
			}

			// Get user's role and check permissions
			if m.roleProvider != nil && user.RoleID != "" {
				role, err := m.roleProvider.GetByID(r.Context(), user.RoleID)
				if err == nil && role != nil && role.HasAnyPermission(permissions...) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Fallback: check legacy role permissions
			for _, perm := range permissions {
				if hasLegacyPermission(user.Role, perm) {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, "Forbidden: missing required permissions", http.StatusForbidden)
		})
	}
}

// hasLegacyPermission checks if a legacy role (operator, viewer) has a permission.
// This provides backward compatibility during migration to custom roles.
func hasLegacyPermission(role, permission string) bool {
	// Define legacy role permissions
	operatorPerms := map[string]bool{
		"container:view": true, "container:create": true, "container:start": true,
		"container:stop": true, "container:restart": true, "container:remove": true,
		"container:exec": true, "container:logs": true,
		"image:view": true, "image:pull": true, "image:remove": true,
		"volume:view": true, "volume:create": true, "volume:remove": true,
		"network:view": true, "network:create": true, "network:remove": true,
		"stack:view": true, "stack:deploy": true, "stack:update": true, "stack:remove": true,
		"host:view": true,
		"backup:view": true, "backup:create": true,
		"security:view": true, "security:scan": true,
		"config:view": true, "config:create": true, "config:update": true, "config:remove": true,
	}

	viewerPerms := map[string]bool{
		"container:view": true, "container:logs": true,
		"image:view": true,
		"volume:view": true,
		"network:view": true,
		"stack:view": true,
		"host:view": true,
		"backup:view": true,
		"security:view": true,
		"config:view": true,
	}

	switch role {
	case "operator":
		return operatorPerms[permission]
	case "viewer":
		return viewerPerms[permission]
	default:
		return false
	}
}
