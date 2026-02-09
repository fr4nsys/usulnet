// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"
	"net/http"
	"time"

	redisrepo "github.com/fr4nsys/usulnet/internal/repository/redis"
)

// WebSessionStore adapts redis.SessionStore to the web.SessionStore interface.
type WebSessionStore struct {
	redisStore *redisrepo.SessionStore
	ttl        time.Duration
}

// NewWebSessionStore creates a new web session store backed by Redis.
func NewWebSessionStore(redisStore *redisrepo.SessionStore, ttl time.Duration) *WebSessionStore {
	return &WebSessionStore{
		redisStore: redisStore,
		ttl:        ttl,
	}
}

// Get retrieves a session from the request cookie.
func (s *WebSessionStore) Get(r *http.Request, name string) (*Session, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		if err == http.ErrNoCookie {
			return nil, nil // No session
		}
		return nil, err
	}

	sessionID := cookie.Value
	if sessionID == "" {
		return nil, nil
	}

	ctx := r.Context()
	redisSession, err := s.redisStore.Get(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	if redisSession == nil {
		return nil, nil
	}

	// Touch the session to extend its lifetime
	_ = s.redisStore.Touch(ctx, sessionID)

	// Convert redis session to web session
	csrfToken, _ := redisSession.Data["csrf_token"].(string)

	// Auto-generate CSRF token for sessions that don't have one yet
	if csrfToken == "" {
		csrfToken = GenerateCSRFToken()
		if csrfToken != "" {
			_ = s.redisStore.SetData(ctx, sessionID, "csrf_token", csrfToken)
		}
	}

	return &Session{
		ID:        redisSession.ID,
		UserID:    redisSession.UserID,
		Username:  redisSession.Username,
		Role:      redisSession.Role,
		CSRFToken: csrfToken,
		CreatedAt: redisSession.CreatedAt,
		ExpiresAt: redisSession.ExpiresAt,
		Values:    redisSession.Data,
	}, nil
}

// Save stores a session and sets the cookie.
func (s *WebSessionStore) Save(r *http.Request, w http.ResponseWriter, session *Session) error {
	if session == nil {
		return nil
	}

	ctx := r.Context()

	// Check if session exists
	existing, _ := s.redisStore.Get(ctx, session.ID)
	if existing == nil {
		// Create new session
		userAgent := r.UserAgent()
		ipAddress := getClientIP(r)

		redisSession, err := s.redisStore.Create(ctx, session.UserID, session.Username, session.Role, userAgent, ipAddress)
		if err != nil {
			return fmt.Errorf("failed to create session: %w", err)
		}
		session.ID = redisSession.ID
	} else {
		// Update existing session
		err := s.redisStore.Update(ctx, session.ID, func(rs *redisrepo.Session) {
			rs.Data = session.Values
		})
		if err != nil {
			return fmt.Errorf("failed to update session: %w", err)
		}
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "usulnet_session",
		Value:    session.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.ttl.Seconds()),
	})

	return nil
}

// Delete removes a session and clears the cookie.
func (s *WebSessionStore) Delete(r *http.Request, w http.ResponseWriter, name string) error {
	cookie, err := r.Cookie(name)
	if err == nil && cookie.Value != "" {
		ctx := r.Context()
		_ = s.redisStore.Delete(ctx, cookie.Value)
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	return nil
}

// getClientIP extracts the client IP from the request.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		return xff
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// NullSessionStore is a no-op session store for when Redis is not available.
type NullSessionStore struct{}

// NewNullSessionStore creates a new null session store.
func NewNullSessionStore() *NullSessionStore {
	return &NullSessionStore{}
}

// Get always returns nil (no session).
func (s *NullSessionStore) Get(r *http.Request, name string) (*Session, error) {
	return nil, nil
}

// Save does nothing.
func (s *NullSessionStore) Save(r *http.Request, w http.ResponseWriter, session *Session) error {
	return nil
}

// Delete does nothing.
func (s *NullSessionStore) Delete(r *http.Request, w http.ResponseWriter, name string) error {
	return nil
}

// CreateSession creates a new session for a user (convenience method).
func (s *WebSessionStore) CreateSession(ctx context.Context, userID, username, role, userAgent, ipAddress string) (*Session, error) {
	redisSession, err := s.redisStore.Create(ctx, userID, username, role, userAgent, ipAddress)
	if err != nil {
		return nil, err
	}

	// Generate and store CSRF token
	csrfToken := GenerateCSRFToken()
	if csrfToken != "" {
		_ = s.redisStore.SetData(ctx, redisSession.ID, "csrf_token", csrfToken)
	}

	return &Session{
		ID:        redisSession.ID,
		UserID:    redisSession.UserID,
		Username:  redisSession.Username,
		Role:      redisSession.Role,
		CSRFToken: csrfToken,
		CreatedAt: redisSession.CreatedAt,
		ExpiresAt: redisSession.ExpiresAt,
		Values:    redisSession.Data,
	}, nil
}
