// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	passwordreset "github.com/fr4nsys/usulnet/internal/services/password_reset"
)

// PasswordResetHandler handles password reset API endpoints
type PasswordResetHandler struct {
	BaseHandler
	service *passwordreset.Service
}

// NewPasswordResetHandler creates a new PasswordResetHandler
func NewPasswordResetHandler(service *passwordreset.Service, log *logger.Logger) *PasswordResetHandler {
	return &PasswordResetHandler{
		BaseHandler: NewBaseHandler(log.Named("password_reset_handler")),
		service:     service,
	}
}

// Routes returns the password reset routes
func (h *PasswordResetHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Public routes - no authentication required
	r.Post("/request", h.RequestReset)
	r.Post("/validate", h.ValidateToken)
	r.Post("/reset", h.ResetPassword)

	return r
}

// RequestResetRequest represents a password reset request
type RequestResetRequest struct {
	Email string `json:"email"`
}

// RequestResetResponse represents the response to a password reset request
type RequestResetResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// RequestReset handles POST /api/v1/password-reset/request
// @Summary Request password reset
// @Description Sends a password reset email to the user
// @Tags password-reset
// @Accept json
// @Produce json
// @Param body body RequestResetRequest true "Reset request"
// @Success 200 {object} RequestResetResponse
// @Failure 400 {object} apierrors.APIError
// @Router /api/v1/password-reset/request [post]
func (h *PasswordResetHandler) RequestReset(w http.ResponseWriter, r *http.Request) {
	var req RequestResetRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	// Validate email is provided
	if req.Email == "" {
		h.BadRequest(w, "email is required")
		return
	}

	result, err := h.service.RequestReset(r.Context(), passwordreset.RequestResetInput{
		Email:     req.Email,
		IP:        getPasswordResetClientIP(r),
		UserAgent: r.UserAgent(),
	})

	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, RequestResetResponse{
		Success: result.Success,
		Message: result.Message,
	})
}

// ValidateTokenRequest represents a token validation request
type ValidateTokenRequest struct {
	Token string `json:"token"`
}

// ValidateTokenResponse represents the response to token validation
type ValidateTokenResponse struct {
	Valid bool `json:"valid"`
}

// ValidateToken handles POST /api/v1/password-reset/validate
// @Summary Validate password reset token
// @Description Checks if a password reset token is valid
// @Tags password-reset
// @Accept json
// @Produce json
// @Param body body ValidateTokenRequest true "Token validation request"
// @Success 200 {object} ValidateTokenResponse
// @Failure 400 {object} apierrors.APIError
// @Router /api/v1/password-reset/validate [post]
func (h *PasswordResetHandler) ValidateToken(w http.ResponseWriter, r *http.Request) {
	var req ValidateTokenRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	// Validate token is provided
	if req.Token == "" {
		h.BadRequest(w, "token is required")
		return
	}

	result, err := h.service.ValidateToken(r.Context(), passwordreset.ValidateTokenInput{
		Token: req.Token,
	})

	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, ValidateTokenResponse{
		Valid: result.Valid,
	})
}

// ResetPasswordRequest represents a password reset request
type ResetPasswordRequest struct {
	Token           string `json:"token"`
	NewPassword     string `json:"new_password"`
	ConfirmPassword string `json:"confirm_password"`
}

// ResetPasswordResponse represents the response to a password reset
type ResetPasswordResponse struct {
	Success          bool     `json:"success"`
	Message          string   `json:"message"`
	ValidationErrors []string `json:"validation_errors,omitempty"`
}

// ResetPassword handles POST /api/v1/password-reset/reset
// @Summary Reset password
// @Description Resets the user's password using a valid token
// @Tags password-reset
// @Accept json
// @Produce json
// @Param body body ResetPasswordRequest true "Password reset request"
// @Success 200 {object} ResetPasswordResponse
// @Failure 400 {object} apierrors.APIError
// @Router /api/v1/password-reset/reset [post]
func (h *PasswordResetHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	// Validate required fields
	if req.Token == "" {
		h.BadRequest(w, "token is required")
		return
	}
	if req.NewPassword == "" {
		h.BadRequest(w, "new_password is required")
		return
	}
	if req.ConfirmPassword == "" {
		h.BadRequest(w, "confirm_password is required")
		return
	}

	result, err := h.service.ResetPassword(r.Context(), passwordreset.ResetPasswordInput{
		Token:           req.Token,
		NewPassword:     req.NewPassword,
		ConfirmPassword: req.ConfirmPassword,
		IP:              getPasswordResetClientIP(r),
		UserAgent:       r.UserAgent(),
	})

	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, ResetPasswordResponse{
		Success:          result.Success,
		Message:          result.Message,
		ValidationErrors: result.ValidationErrors,
	})
}

// getPasswordResetClientIP extracts the client IP address from the request
func getPasswordResetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}
	return ip
}
