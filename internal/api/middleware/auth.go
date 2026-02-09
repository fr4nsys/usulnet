// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package middleware

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
)

// Context keys for auth middleware.
const (
	// UserContextKey is the context key for user claims.
	UserContextKey contextKey = "user"

	// TokenContextKey is the context key for the raw JWT token.
	TokenContextKey contextKey = "token"
)

// HTTP headers and query params for auth.
const (
	AuthorizationHeader = "Authorization"
	BearerPrefix        = "Bearer "
	APIKeyHeader        = "X-API-KEY"
	TokenQueryParam     = "token"
)

// UserClaims contains the claims extracted from a JWT token.
type UserClaims struct {
	UserID    string   `json:"user_id"`
	Username  string   `json:"username"`
	Email     string   `json:"email,omitempty"`
	Role      string   `json:"role"`
	Teams     []string `json:"teams,omitempty"`
	SessionID string   `json:"session_id,omitempty"`
	jwt.RegisteredClaims
}

// APIKeyAuthenticator validates an API key and returns user claims.
type APIKeyAuthenticator func(ctx context.Context, apiKey string) (*UserClaims, error)

// AuthConfig contains configuration for the auth middleware.
type AuthConfig struct {
	// Secret is the JWT signing secret (required)
	Secret string

	// TokenLookup defines how to extract the token from the request.
	// Format: "<source>:<name>", e.g., "header:Authorization", "query:token", "cookie:auth"
	// Multiple lookups can be specified, separated by comma.
	// Default: "header:Authorization,query:token"
	TokenLookup string

	// AuthScheme is the authorization scheme in the header (default: "Bearer")
	AuthScheme string

	// ContextKey is the key used to store claims in context (default: UserContextKey)
	ContextKey contextKey

	// ErrorHandler is called when authentication fails
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

	// TokenValidator is an optional function to perform additional token validation
	// (e.g., check if token is revoked)
	TokenValidator func(token string, claims *UserClaims) error

	// SuccessHandler is called after successful authentication (optional)
	SuccessHandler func(w http.ResponseWriter, r *http.Request, claims *UserClaims)

	// APIKeyAuth is an optional authenticator for API key-based auth via X-API-KEY header.
	APIKeyAuth APIKeyAuthenticator
}

// DefaultAuthConfig returns a default auth configuration.
func DefaultAuthConfig(secret string) AuthConfig {
	return AuthConfig{
		Secret:       secret,
		TokenLookup:  "header:Authorization,query:token",
		AuthScheme:   "Bearer",
		ContextKey:   UserContextKey,
		ErrorHandler: defaultAuthErrorHandler,
	}
}

// Auth returns an authentication middleware that validates JWT tokens.
func Auth(config AuthConfig) func(http.Handler) http.Handler {
	if config.Secret == "" {
		panic("auth middleware: secret is required")
	}

	if config.TokenLookup == "" {
		config.TokenLookup = "header:Authorization,query:token"
	}

	if config.AuthScheme == "" {
		config.AuthScheme = "Bearer"
	}

	if config.ContextKey == "" {
		config.ContextKey = UserContextKey
	}

	if config.ErrorHandler == nil {
		config.ErrorHandler = defaultAuthErrorHandler
	}

	extractors := parseTokenLookup(config.TokenLookup, config.AuthScheme)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for API key authentication first
			if config.APIKeyAuth != nil {
				if apiKey := r.Header.Get(APIKeyHeader); apiKey != "" {
					claims, err := config.APIKeyAuth(r.Context(), apiKey)
					if err != nil {
						config.ErrorHandler(w, r, apierrors.Unauthorized("invalid API key"))
						return
					}
					ctx := context.WithValue(r.Context(), config.ContextKey, claims)
					if config.SuccessHandler != nil {
						config.SuccessHandler(w, r, claims)
					}
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// Try to extract token from configured sources
			var tokenString string
			for _, extractor := range extractors {
				if token := extractor(r); token != "" {
					tokenString = token
					break
				}
			}

			if tokenString == "" {
				config.ErrorHandler(w, r, apierrors.Unauthorized(""))
				return
			}

			// Parse and validate token
			token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (any, error) {
				// Validate signing method
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return []byte(config.Secret), nil
			})

			if err != nil {
				switch {
				case strings.Contains(err.Error(), "expired"):
					config.ErrorHandler(w, r, apierrors.ExpiredToken())
				default:
					config.ErrorHandler(w, r, apierrors.InvalidToken(err.Error()))
				}
				return
			}

			if !token.Valid {
				config.ErrorHandler(w, r, apierrors.InvalidToken(""))
				return
			}

			claims, ok := token.Claims.(*UserClaims)
			if !ok {
				config.ErrorHandler(w, r, apierrors.InvalidToken("invalid claims"))
				return
			}

			// Optional: Additional token validation (e.g., check revocation)
			if config.TokenValidator != nil {
				if err := config.TokenValidator(tokenString, claims); err != nil {
					config.ErrorHandler(w, r, apierrors.RevokedToken())
					return
				}
			}

			// Optional: Success callback
			if config.SuccessHandler != nil {
				config.SuccessHandler(w, r, claims)
			}

			// Add claims to context
			ctx := context.WithValue(r.Context(), config.ContextKey, claims)
			ctx = context.WithValue(ctx, TokenContextKey, tokenString)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AuthSimple returns a simplified auth middleware using defaults.
func AuthSimple(secret string) func(http.Handler) http.Handler {
	return Auth(DefaultAuthConfig(secret))
}

// RequireAuth is a middleware that requires authentication.
// It uses a default secret from environment or a placeholder.
// In production, this should be configured properly.
var RequireAuth = func(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := GetUserFromContext(r.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ============================================================================
// Token extraction functions
// ============================================================================

type tokenExtractor func(*http.Request) string

func parseTokenLookup(lookup, authScheme string) []tokenExtractor {
	parts := strings.Split(lookup, ",")
	extractors := make([]tokenExtractor, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}

		source := strings.ToLower(kv[0])
		name := kv[1]

		switch source {
		case "header":
			extractors = append(extractors, headerExtractor(name, authScheme))
		case "query":
			extractors = append(extractors, queryExtractor(name))
		case "cookie":
			extractors = append(extractors, cookieExtractor(name))
		}
	}

	return extractors
}

func headerExtractor(name, authScheme string) tokenExtractor {
	return func(r *http.Request) string {
		header := r.Header.Get(name)
		if header == "" {
			return ""
		}

		// Check for auth scheme prefix
		if authScheme != "" {
			prefix := authScheme + " "
			if strings.HasPrefix(header, prefix) {
				return strings.TrimPrefix(header, prefix)
			}
			// Also accept without prefix for backwards compatibility
		}

		return header
	}
}

func queryExtractor(name string) tokenExtractor {
	return func(r *http.Request) string {
		return r.URL.Query().Get(name)
	}
}

func cookieExtractor(name string) tokenExtractor {
	return func(r *http.Request) string {
		cookie, err := r.Cookie(name)
		if err != nil {
			return ""
		}
		return cookie.Value
	}
}

// ============================================================================
// Error handler
// ============================================================================

func defaultAuthErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	requestID := GetRequestID(r.Context())
	if apiErr, ok := err.(*apierrors.APIError); ok {
		apierrors.WriteErrorWithRequestID(w, apiErr, requestID)
	} else {
		apierrors.WriteErrorWithRequestID(w, apierrors.Unauthorized(err.Error()), requestID)
	}
}

// ============================================================================
// Context helpers
// ============================================================================

// GetUserFromContext retrieves user claims from the context.
// Returns nil if no user is found.
func GetUserFromContext(ctx context.Context) *UserClaims {
	if claims, ok := ctx.Value(UserContextKey).(*UserClaims); ok {
		return claims
	}
	return nil
}

// GetUserFromRequest is a convenience function to get user from http.Request.
func GetUserFromRequest(r *http.Request) *UserClaims {
	return GetUserFromContext(r.Context())
}

// GetTokenFromContext retrieves the raw JWT token from the context.
func GetTokenFromContext(ctx context.Context) string {
	if token, ok := ctx.Value(TokenContextKey).(string); ok {
		return token
	}
	return ""
}

// MustGetUser retrieves user claims from context and panics if not found.
// Use only in handlers where authentication is guaranteed.
func MustGetUser(ctx context.Context) *UserClaims {
	claims := GetUserFromContext(ctx)
	if claims == nil {
		panic("auth: user claims not found in context")
	}
	return claims
}

// ============================================================================
// Token revocation (in-memory, use Redis in production)
// ============================================================================

// TokenRevocationStore manages revoked JWT tokens.
type TokenRevocationStore struct {
	mu      sync.RWMutex
	revoked map[string]time.Time // jti -> expiration time
}

// NewTokenRevocationStore creates a new revocation store.
func NewTokenRevocationStore() *TokenRevocationStore {
	store := &TokenRevocationStore{
		revoked: make(map[string]time.Time),
	}
	go store.cleanupExpired()
	return store
}

// Revoke marks a token as revoked.
func (s *TokenRevocationStore) Revoke(jti string, exp time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[jti] = exp
}

// IsRevoked checks if a token is revoked.
func (s *TokenRevocationStore) IsRevoked(jti string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.revoked[jti]
	return ok
}

// cleanupExpired removes expired tokens from the store periodically.
func (s *TokenRevocationStore) cleanupExpired() {
	ticker := time.NewTicker(time.Hour)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for jti, exp := range s.revoked {
			if now.After(exp) {
				delete(s.revoked, jti)
			}
		}
		s.mu.Unlock()
	}
}

// ValidatorWithRevocation returns a token validator that checks revocation.
func (s *TokenRevocationStore) ValidatorWithRevocation() func(string, *UserClaims) error {
	return func(token string, claims *UserClaims) error {
		if claims.ID != "" && s.IsRevoked(claims.ID) {
			return apierrors.RevokedToken()
		}
		return nil
	}
}

// ============================================================================
// Optional authentication (for endpoints that work with or without auth)
// ============================================================================

// OptionalAuth is like Auth but doesn't reject unauthenticated requests.
// The user claims will be nil in context if not authenticated.
func OptionalAuth(config AuthConfig) func(http.Handler) http.Handler {
	if config.Secret == "" {
		panic("auth middleware: secret is required")
	}

	if config.TokenLookup == "" {
		config.TokenLookup = "header:Authorization,query:token"
	}

	if config.AuthScheme == "" {
		config.AuthScheme = "Bearer"
	}

	if config.ContextKey == "" {
		config.ContextKey = UserContextKey
	}

	extractors := parseTokenLookup(config.TokenLookup, config.AuthScheme)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try to extract token
			var tokenString string
			for _, extractor := range extractors {
				if token := extractor(r); token != "" {
					tokenString = token
					break
				}
			}

			// If no token, continue without authentication
			if tokenString == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Try to parse token
			token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (any, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return []byte(config.Secret), nil
			})

			if err != nil || !token.Valid {
				// Invalid token, continue without authentication
				next.ServeHTTP(w, r)
				return
			}

			claims, ok := token.Claims.(*UserClaims)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			// Add claims to context
			ctx := context.WithValue(r.Context(), config.ContextKey, claims)
			ctx = context.WithValue(ctx, TokenContextKey, tokenString)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
