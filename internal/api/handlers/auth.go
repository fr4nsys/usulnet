// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/auth"
)

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	BaseHandler
	authService *auth.Service
}

// NewAuthHandler creates a new auth handler.
func NewAuthHandler(authService *auth.Service, log *logger.Logger) *AuthHandler {
	return &AuthHandler{
		BaseHandler: NewBaseHandler(log),
		authService: authService,
	}
}

// Routes returns the authentication routes.
func (h *AuthHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Post("/login", h.Login)
	r.Post("/refresh", h.RefreshToken)
	r.Post("/logout", h.Logout)

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Post("/logout/all", h.LogoutAll)
		r.Post("/logout/others", h.LogoutOthers)
		r.Get("/sessions", h.GetSessions)
		r.Delete("/sessions/{sessionID}", h.RevokeSession)
		r.Post("/change-password", h.ChangePassword)
		r.Get("/me", h.GetCurrentUser)
	})

	return r
}

// ============================================================================
// Request/Response types
// ============================================================================

// LoginRequest represents a login request.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents a login response.
type LoginResponse struct {
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	ExpiresAt    string       `json:"expires_at"`
	User         UserResponse `json:"user"`
}

// RefreshRequest represents a token refresh request.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshResponse represents a token refresh response.
type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    string `json:"expires_at"`
}

// ChangePasswordRequest represents a password change request.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// SessionResponse represents a session in API responses.
type SessionResponse struct {
	ID        string `json:"id"`
	UserAgent string `json:"user_agent,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
	IsCurrent bool   `json:"is_current"`
}

// ============================================================================
// Handlers
// ============================================================================

// Login handles user login.
// POST /api/v1/auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Username == "" {
		h.BadRequest(w, "username is required")
		return
	}
	if req.Password == "" {
		h.BadRequest(w, "password is required")
		return
	}

	input := auth.LoginInput{
		Username:  req.Username,
		Password:  req.Password,
		UserAgent: r.UserAgent(),
		IPAddress: getClientIP(r),
	}

	result, err := h.authService.Login(r.Context(), input)
	if err != nil {
		h.Error(w, apierrors.Unauthorized("invalid credentials"))
		return
	}

	resp := LoginResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresAt:    result.ExpiresAt.Format(time.RFC3339),
		User:         toUserResponse(result.User),
	}

	h.OK(w, resp)
}

// RefreshToken handles token refresh.
// POST /api/v1/auth/refresh
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.RefreshToken == "" {
		h.BadRequest(w, "refresh_token is required")
		return
	}

	input := auth.RefreshInput{
		RefreshToken: req.RefreshToken,
		UserAgent:    r.UserAgent(),
		IPAddress:    getClientIP(r),
	}

	result, err := h.authService.Refresh(r.Context(), input)
	if err != nil {
		h.Error(w, apierrors.InvalidToken("invalid or expired refresh token"))
		return
	}

	resp := RefreshResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresAt:    result.ExpiresAt.Format(time.RFC3339),
	}

	h.OK(w, resp)
}

// Logout handles user logout.
// POST /api/v1/auth/logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Try to get session from token
	claims := middleware.GetUserFromContext(r.Context())
	if claims != nil && claims.SessionID != "" {
		sessionID, err := uuid.Parse(claims.SessionID)
		if err == nil {
			if err := h.authService.Logout(r.Context(), sessionID); err != nil {
				h.logger.Warn("logout failed", "error", err)
			}
		}
	}

	// Also try refresh token from body
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if h.ParseJSON(r, &req) == nil && req.RefreshToken != "" {
		if err := h.authService.LogoutByRefreshToken(r.Context(), req.RefreshToken); err != nil {
			h.logger.Warn("logout by refresh token failed", "error", err)
		}
	}

	h.NoContent(w)
}

// LogoutAll handles logging out all sessions.
// POST /api/v1/auth/logout/all
func (h *AuthHandler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	count, err := h.authService.LogoutAll(r.Context(), userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]int64{"sessions_revoked": count})
}

// LogoutOthers handles logging out other sessions.
// POST /api/v1/auth/logout/others
func (h *AuthHandler) LogoutOthers(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	claims := middleware.GetUserFromContext(r.Context())
	if claims == nil {
		h.Forbidden(w, "session not found")
		return
	}

	sessionID, err := uuid.Parse(claims.SessionID)
	if err != nil {
		h.BadRequest(w, "invalid session")
		return
	}

	count, err := h.authService.LogoutOthers(r.Context(), userID, sessionID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]int64{"sessions_revoked": count})
}

// GetSessions returns all active sessions for the current user.
// GET /api/v1/auth/sessions
func (h *AuthHandler) GetSessions(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	claims := middleware.GetUserFromContext(r.Context())
	currentSessionID := uuid.Nil
	if claims != nil && claims.SessionID != "" {
		if parsed, err := uuid.Parse(claims.SessionID); err == nil {
			currentSessionID = parsed
		}
	}

	sessions, err := h.authService.GetUserSessions(r.Context(), userID, currentSessionID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]SessionResponse, len(sessions))
	for i, s := range sessions {
		resp[i] = SessionResponse{
			ID:        s.ID.String(),
			UserAgent: s.UserAgent,
			IPAddress: s.IPAddress,
			CreatedAt: s.CreatedAt.Format(time.RFC3339),
			ExpiresAt: s.ExpiresAt.Format(time.RFC3339),
			IsCurrent: s.IsCurrent,
		}
	}

	h.OK(w, resp)
}

// RevokeSession revokes a specific session.
// DELETE /api/v1/auth/sessions/{sessionID}
func (h *AuthHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	sessionID, err := h.URLParamUUID(r, "sessionID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.authService.RevokeSession(r.Context(), userID, sessionID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// ChangePassword handles password change.
// POST /api/v1/auth/change-password
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req ChangePasswordRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.CurrentPassword == "" {
		h.BadRequest(w, "current_password is required")
		return
	}
	if req.NewPassword == "" {
		h.BadRequest(w, "new_password is required")
		return
	}

	input := auth.ChangePasswordInput{
		UserID:          userID,
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
	}

	if err := h.authService.ChangePassword(r.Context(), input); err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]string{"message": "password changed successfully"})
}

// GetCurrentUser returns the current authenticated user.
// GET /api/v1/auth/me
func (h *AuthHandler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetUserFromContext(r.Context())
	if claims == nil {
		h.Forbidden(w, "not authenticated")
		return
	}

	h.OK(w, map[string]interface{}{
		"user_id":    claims.UserID,
		"username":   claims.Username,
		"role":       claims.Role,
		"session_id": claims.SessionID,
	})
}

// ============================================================================
// Helpers
// ============================================================================

// getClientIP extracts the client IP address from the request.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}
