// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"sync"
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
	ContextKeySession    ContextKey = "session"
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
	// OAuth SSO
	OAuthGetAuthURL(providerName, state string) (string, error)
	OAuthCallback(ctx context.Context, providerName, code, userAgent, ipAddress string) (*UserContext, error)
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
	providerMu    sync.RWMutex
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
		config.SessionName = CookieSession
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

		// Add user and session to context (session cached to avoid re-reading in FlashMiddleware)
		ctx := context.WithValue(r.Context(), ContextKeyUser, user)
		ctx = context.WithValue(ctx, ContextKeySession, session)

		// Add theme to context
		theme := session.Theme
		if theme == "" {
			theme = "dark"
		}
		ctx = context.WithValue(ctx, ContextKeyTheme, theme)

		// Add CSRF token to context — regenerate if empty to prevent broken sessions
		if session.CSRFToken == "" {
			slog.Warn("session has empty CSRF token, regenerating", "session_id", session.ID, "user_id", session.UserID)
			b := make([]byte, 32)
			if _, err := cryptorand.Read(b); err == nil {
				session.CSRFToken = hex.EncodeToString(b)
				_ = m.sessionStore.Save(r, w, session)
			}
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
		if cookie, err := r.Cookie(CookieTheme); err == nil {
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

		// NOTE: The previous blanket skip for /api/ paths was removed because
		// the web layer registers session-authenticated routes under /api/
		// (snippets, terminal, compliance, OPA, git-sync, ephemeral, manifests,
		// host filesystem ops). Those routes use session cookies and MUST have
		// CSRF protection. The frontend already sends X-CSRF-Token on all
		// HTMX and fetch requests via the htmx:configRequest listener.

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

		// Validate token using constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
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
// Reuses session cached by AuthRequired to avoid a second Redis roundtrip.
func (m *Middleware) FlashMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Try cached session from AuthRequired first (avoids 2nd Redis read)
		session, _ := ctx.Value(ContextKeySession).(*Session)
		if session == nil {
			// Fallback: read session from store (for routes without AuthRequired)
			var err error
			session, err = m.sessionStore.Get(r, m.sessionName)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
		}

		if session != nil {
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

	// Check configured exclude paths.
	// Paths ending in "/" are treated as prefixes (e.g. "/static/" matches
	// "/static/css/style.css"). All others require an exact match so that
	// "/health" does NOT accidentally exclude "/health-dashboard".
	for _, p := range m.excludePaths {
		if strings.HasSuffix(p, "/") {
			if strings.HasPrefix(path, p) {
				return true
			}
		} else {
			if path == p {
				return true
			}
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

// WebSocketRateLimit limits WebSocket connection upgrades to 10 per minute per IP.
func WebSocketRateLimit() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// Simple concurrent connection counter using sync.Map
		type ipCount struct {
			mu    sync.Mutex
			count int
		}
		var connections sync.Map

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			if fwd := r.Header.Get("X-Real-IP"); fwd != "" {
				ip = fwd
			} else if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
				ip = strings.Split(fwd, ",")[0]
			}

			val, _ := connections.LoadOrStore(ip, &ipCount{})
			counter := val.(*ipCount)

			counter.mu.Lock()
			if counter.count >= 20 {
				counter.mu.Unlock()
				http.Error(w, "Too many WebSocket connections", http.StatusTooManyRequests)
				return
			}
			counter.count++
			counter.mu.Unlock()

			// Track connection end
			defer func() {
				counter.mu.Lock()
				counter.count--
				if counter.count <= 0 {
					counter.count = 0
					connections.Delete(ip)
				}
				counter.mu.Unlock()
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// MaxRequestBody limits the size of request bodies to prevent memory exhaustion.
// Uses http.MaxBytesReader which returns a proper 413 error when exceeded.
func MaxRequestBody(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
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
		// CSP: all assets self-hosted; unsafe-inline for inline scripts/styles used in templates;
		// unsafe-eval required by Alpine.js v3 and Monaco editor
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline' 'unsafe-eval'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; font-src 'self'; connect-src 'self' wss: ws:; "+
				"worker-src 'self' blob:; "+
				"frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		next.ServeHTTP(w, r)
	})
}

// RecoverPanic middleware recovers from panics and shows error page.
func RecoverPanic(handler *Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					slog.Error("panic recovered in frontend handler",
						"error", err,
						"path", r.URL.Path,
						"method", r.Method,
					)
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
// Thread-safe: may be called while middleware goroutines read scopeProvider.
func (m *Middleware) SetScopeProvider(sp ScopeProvider) {
	m.providerMu.Lock()
	m.scopeProvider = sp
	m.providerMu.Unlock()
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

		m.providerMu.RLock()
		sp := m.scopeProvider
		m.providerMu.RUnlock()

		if sp == nil {
			// No scope provider configured → no scoping (backward compat)
			scope := &models.ResourceScope{NoTeamsExist: true}
			ctx := context.WithValue(r.Context(), ContextKeyScope, scope)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		scope, err := sp.GetUserScope(r.Context(), user.ID, user.Role)
		if err != nil {
			// On error, fail closed (restrict access)
			log.Printf("[ERROR] scope computation failed for user %s: %v — restricting access", user.ID, err)
			scope = &models.ResourceScope{}
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
// Thread-safe: may be called while middleware goroutines read roleProvider.
func (m *Middleware) SetRoleProvider(rp RoleProvider) {
	m.providerMu.Lock()
	m.roleProvider = rp
	m.providerMu.Unlock()
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
			m.providerMu.RLock()
			rp := m.roleProvider
			m.providerMu.RUnlock()
			if rp != nil && user.RoleID != "" {
				role, err := rp.GetByID(r.Context(), user.RoleID)
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
			m.providerMu.RLock()
			rp := m.roleProvider
			m.providerMu.RUnlock()
			if rp != nil && user.RoleID != "" {
				role, err := rp.GetByID(r.Context(), user.RoleID)
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
		"image:create": true, "image:build": true,
		"volume:view": true, "volume:create": true, "volume:remove": true,
		"network:view": true, "network:create": true, "network:remove": true,
		"stack:view": true, "stack:deploy": true, "stack:update": true, "stack:remove": true,
		"host:view":   true,
		"backup:view": true, "backup:create": true,
		"security:view": true, "security:scan": true,
		"config:view": true, "config:create": true, "config:update": true, "config:remove": true,
		"crontab:view": true, "crontab:execute": true,
		"dns:view": true, "dns:write": true,
		"calendar:view": true, "calendar:write": true,
		"marketplace:view": true, "marketplace:write": true,
	}

	viewerPerms := map[string]bool{
		"container:view": true, "container:logs": true,
		"image:view":       true,
		"volume:view":      true,
		"network:view":     true,
		"stack:view":       true,
		"host:view":        true,
		"backup:view":      true,
		"security:view":    true,
		"config:view":      true,
		"crontab:view":     true,
		"dns:view":         true,
		"calendar:view":    true,
		"marketplace:view": true,
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
