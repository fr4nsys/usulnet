// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/user"
)

// UserHandler handles user management endpoints.
type UserHandler struct {
	BaseHandler
	userService     *user.Service
	licenseProvider middleware.LicenseProvider
}

// NewUserHandler creates a new user handler.
func NewUserHandler(userService *user.Service, log *logger.Logger) *UserHandler {
	return &UserHandler{
		BaseHandler: NewBaseHandler(log),
		userService: userService,
	}
}

// SetLicenseProvider sets the license provider for feature gating.
func (h *UserHandler) SetLicenseProvider(provider middleware.LicenseProvider) {
	h.licenseProvider = provider
}

// Routes returns the user routes.
func (h *UserHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// User management (admin only)
	r.Get("/", h.List)
	r.Get("/stats", h.GetStats)

	// User creation enforces MaxUsers limit
	r.Group(func(r chi.Router) {
		if h.licenseProvider != nil {
			r.Use(middleware.RequireLimit(
				h.licenseProvider,
				"users",
				func(r *http.Request) int {
					stats, err := h.userService.GetStats(r.Context())
					if err != nil {
						return 0
					}
					return int(stats.Total)
				},
				func(l license.Limits) int { return l.MaxUsers },
			))
		}
		r.Post("/", h.Create)
	})
	r.Get("/{userID}", h.Get)
	r.Put("/{userID}", h.Update)
	r.Delete("/{userID}", h.Delete)
	r.Post("/{userID}/activate", h.Activate)
	r.Post("/{userID}/deactivate", h.Deactivate)
	r.Post("/{userID}/unlock", h.Unlock)

	// API keys (listing/deleting allowed for all, creation requires api_keys feature)
	r.Get("/{userID}/api-keys", h.ListAPIKeys)
	r.Delete("/{userID}/api-keys/{keyID}", h.DeleteAPIKey)

	// Profile (self-service)
	r.Get("/profile", h.GetProfile)
	r.Put("/profile", h.UpdateProfile)
	r.Get("/profile/api-keys", h.ListMyAPIKeys)
	r.Delete("/profile/api-keys/{keyID}", h.DeleteMyAPIKey)

	// API key creation requires FeatureAPIKeys (Business+)
	r.Group(func(r chi.Router) {
		if h.licenseProvider != nil {
			r.Use(middleware.RequireFeature(h.licenseProvider, license.FeatureAPIKeys))
		}
		r.Post("/{userID}/api-keys", h.CreateAPIKey)
		r.Post("/profile/api-keys", h.CreateMyAPIKey)
	})

	return r
}

// ============================================================================
// Request/Response types
// ============================================================================

// CreateUserRequest represents a user creation request.
type CreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email,omitempty"`
	Password string `json:"password"`
	Role     string `json:"role,omitempty"`
}

// UpdateUserRequest represents a user update request.
type UpdateUserRequest struct {
	Email    *string `json:"email,omitempty"`
	Role     *string `json:"role,omitempty"`
	IsActive *bool   `json:"is_active,omitempty"`
}

// UpdateProfileRequest represents a profile update request.
type UpdateProfileRequest struct {
	Email *string `json:"email,omitempty"`
}

// CreateAPIKeyRequest represents an API key creation request.
type CreateAPIKeyRequest struct {
	Name      string  `json:"name"`
	ExpiresAt *string `json:"expires_at,omitempty"`
}

// UserResponse represents a user in API responses.
type UserResponse struct {
	ID          string  `json:"id"`
	Username    string  `json:"username"`
	Email       *string `json:"email,omitempty"`
	Role        string  `json:"role"`
	IsActive    bool    `json:"is_active"`
	IsLDAP      bool    `json:"is_ldap"`
	IsLocked    bool    `json:"is_locked"`
	LastLoginAt *string `json:"last_login_at,omitempty"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

// APIKeyResponse represents an API key in API responses.
type APIKeyResponse struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Prefix     string  `json:"prefix"`
	LastUsedAt *string `json:"last_used_at,omitempty"`
	ExpiresAt  *string `json:"expires_at,omitempty"`
	CreatedAt  string  `json:"created_at"`
	IsExpired  bool    `json:"is_expired"`
}

// APIKeyWithSecretResponse includes the secret (only on creation).
type APIKeyWithSecretResponse struct {
	APIKeyResponse
	Key string `json:"key"`
}

// UserStatsResponse represents user statistics.
type UserStatsResponse struct {
	Total    int64            `json:"total"`
	Active   int64            `json:"active"`
	Inactive int64            `json:"inactive"`
	Locked   int64            `json:"locked"`
	ByRole   map[string]int64 `json:"by_role"`
}

// ============================================================================
// Admin handlers
// ============================================================================

// List returns all users.
// GET /api/v1/users
func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	if err := h.RequireAdmin(r); err != nil {
		h.HandleError(w, err)
		return
	}

	pagination := h.GetPagination(r)

	opts := user.ListOptions{
		Page:    pagination.Page,
		PerPage: pagination.PerPage,
	}

	// Optional filters
	if role := h.QueryParam(r, "role"); role != "" {
		userRole := models.UserRole(role)
		opts.Role = &userRole
	}
	if isActive := h.QueryParam(r, "is_active"); isActive != "" {
		active := isActive == "true"
		opts.IsActive = &active
	}
	if search := h.QueryParam(r, "search"); search != "" {
		opts.Search = search
	}

	result, err := h.userService.List(r.Context(), opts)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	users := make([]UserResponse, len(result.Users))
	for i, u := range result.Users {
		users[i] = toUserResponse(u)
	}

	h.OK(w, NewPaginatedResponse(users, result.Total, pagination))
}

// Create creates a new user.
// POST /api/v1/users
func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	if err := h.RequireAdmin(r); err != nil {
		h.HandleError(w, err)
		return
	}

	var req CreateUserRequest
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

	input := user.CreateInput{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
	}

	if req.Role != "" {
		input.Role = models.UserRole(req.Role)
	}

	newUser, err := h.userService.Create(r.Context(), input)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, toUserResponse(newUser))
}

// Get returns a specific user.
// GET /api/v1/users/{userID}
func (h *UserHandler) Get(w http.ResponseWriter, r *http.Request) {
	if err := h.RequireAdmin(r); err != nil {
		h.HandleError(w, err)
		return
	}

	userID, err := h.URLParamUUID(r, "userID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	u, err := h.userService.GetByID(r.Context(), userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toUserResponse(u))
}

// Update updates a user.
// PUT /api/v1/users/{userID}
func (h *UserHandler) Update(w http.ResponseWriter, r *http.Request) {
	if err := h.RequireAdmin(r); err != nil {
		h.HandleError(w, err)
		return
	}

	userID, err := h.URLParamUUID(r, "userID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req UpdateUserRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	input := user.UpdateInput{
		Email:    req.Email,
		IsActive: req.IsActive,
	}

	if req.Role != nil {
		role := models.UserRole(*req.Role)
		input.Role = &role
	}

	u, err := h.userService.Update(r.Context(), userID, input)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toUserResponse(u))
}

// Delete deletes a user.
// DELETE /api/v1/users/{userID}
func (h *UserHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if err := h.RequireAdmin(r); err != nil {
		h.HandleError(w, err)
		return
	}

	userID, err := h.URLParamUUID(r, "userID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	// Prevent self-deletion
	currentUserID, _ := h.GetUserID(r)
	if userID == currentUserID {
		h.BadRequest(w, "cannot delete your own account")
		return
	}

	if err := h.userService.Delete(r.Context(), userID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// Activate activates a user account.
// POST /api/v1/users/{userID}/activate
func (h *UserHandler) Activate(w http.ResponseWriter, r *http.Request) {
	if err := h.RequireAdmin(r); err != nil {
		h.HandleError(w, err)
		return
	}

	userID, err := h.URLParamUUID(r, "userID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.userService.Activate(r.Context(), userID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// Deactivate deactivates a user account.
// POST /api/v1/users/{userID}/deactivate
func (h *UserHandler) Deactivate(w http.ResponseWriter, r *http.Request) {
	if err := h.RequireAdmin(r); err != nil {
		h.HandleError(w, err)
		return
	}

	userID, err := h.URLParamUUID(r, "userID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	// Prevent self-deactivation
	currentUserID, _ := h.GetUserID(r)
	if userID == currentUserID {
		h.BadRequest(w, "cannot deactivate your own account")
		return
	}

	if err := h.userService.Deactivate(r.Context(), userID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// Unlock unlocks a locked user account.
// POST /api/v1/users/{userID}/unlock
func (h *UserHandler) Unlock(w http.ResponseWriter, r *http.Request) {
	if err := h.RequireAdmin(r); err != nil {
		h.HandleError(w, err)
		return
	}

	userID, err := h.URLParamUUID(r, "userID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.userService.Unlock(r.Context(), userID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// GetStats returns user statistics.
// GET /api/v1/users/stats
func (h *UserHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	if err := h.RequireAdmin(r); err != nil {
		h.HandleError(w, err)
		return
	}

	stats, err := h.userService.GetStats(r.Context())
	if err != nil {
		h.HandleError(w, err)
		return
	}

	roleCounts, err := h.userService.GetRoleCounts(r.Context())
	if err != nil {
		h.HandleError(w, err)
		return
	}

	byRole := make(map[string]int64)
	for role, count := range roleCounts {
		byRole[string(role)] = count
	}

	resp := UserStatsResponse{
		Total:    stats.Total,
		Active:   stats.Active,
		Inactive: stats.Inactive,
		Locked:   stats.Locked,
		ByRole:   byRole,
	}

	h.OK(w, resp)
}

// ============================================================================
// API Key handlers (admin)
// ============================================================================

// ListAPIKeys returns API keys for a user.
// GET /api/v1/users/{userID}/api-keys
func (h *UserHandler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	if err := h.RequireAdmin(r); err != nil {
		h.HandleError(w, err)
		return
	}

	userID, err := h.URLParamUUID(r, "userID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	keys, err := h.userService.ListAPIKeys(r.Context(), userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]APIKeyResponse, len(keys))
	for i, k := range keys {
		resp[i] = toAPIKeyResponse(k)
	}

	h.OK(w, resp)
}

// CreateAPIKey creates an API key for a user.
// POST /api/v1/users/{userID}/api-keys
func (h *UserHandler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	if err := h.RequireAdmin(r); err != nil {
		h.HandleError(w, err)
		return
	}

	userID, err := h.URLParamUUID(r, "userID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req CreateAPIKeyRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Name == "" {
		h.BadRequest(w, "name is required")
		return
	}

	var expiresAt *time.Time
	if req.ExpiresAt != nil {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			h.BadRequest(w, "invalid expires_at format (use RFC3339)")
			return
		}
		expiresAt = &t
	}

	keyWithSecret, err := h.userService.CreateAPIKey(r.Context(), userID, req.Name, expiresAt)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := APIKeyWithSecretResponse{
		APIKeyResponse: toAPIKeyResponse(&keyWithSecret.APIKey),
		Key:            keyWithSecret.Key,
	}

	h.Created(w, resp)
}

// DeleteAPIKey deletes an API key.
// DELETE /api/v1/users/{userID}/api-keys/{keyID}
func (h *UserHandler) DeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	if err := h.RequireAdmin(r); err != nil {
		h.HandleError(w, err)
		return
	}

	userID, err := h.URLParamUUID(r, "userID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	keyID, err := h.URLParamUUID(r, "keyID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.userService.DeleteAPIKey(r.Context(), userID, keyID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// ============================================================================
// Profile handlers (self-service)
// ============================================================================

// GetProfile returns the current user's profile.
// GET /api/v1/users/profile
func (h *UserHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	u, err := h.userService.GetByID(r.Context(), userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toUserResponse(u))
}

// UpdateProfile updates the current user's profile.
// PUT /api/v1/users/profile
func (h *UserHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req UpdateProfileRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	input := user.UpdateProfileInput{
		Email: req.Email,
	}

	u, err := h.userService.UpdateProfile(r.Context(), userID, input)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toUserResponse(u))
}

// ListMyAPIKeys returns the current user's API keys.
// GET /api/v1/users/profile/api-keys
func (h *UserHandler) ListMyAPIKeys(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	keys, err := h.userService.ListAPIKeys(r.Context(), userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]APIKeyResponse, len(keys))
	for i, k := range keys {
		resp[i] = toAPIKeyResponse(k)
	}

	h.OK(w, resp)
}

// CreateMyAPIKey creates an API key for the current user.
// POST /api/v1/users/profile/api-keys
func (h *UserHandler) CreateMyAPIKey(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req CreateAPIKeyRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Name == "" {
		h.BadRequest(w, "name is required")
		return
	}

	var expiresAt *time.Time
	if req.ExpiresAt != nil {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			h.BadRequest(w, "invalid expires_at format (use RFC3339)")
			return
		}
		expiresAt = &t
	}

	keyWithSecret, err := h.userService.CreateAPIKey(r.Context(), userID, req.Name, expiresAt)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := APIKeyWithSecretResponse{
		APIKeyResponse: toAPIKeyResponse(&keyWithSecret.APIKey),
		Key:            keyWithSecret.Key,
	}

	h.Created(w, resp)
}

// DeleteMyAPIKey deletes the current user's API key.
// DELETE /api/v1/users/profile/api-keys/{keyID}
func (h *UserHandler) DeleteMyAPIKey(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	keyID, err := h.URLParamUUID(r, "keyID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.userService.DeleteAPIKey(r.Context(), userID, keyID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// ============================================================================
// Helpers
// ============================================================================

func toUserResponse(u *models.User) UserResponse {
	resp := UserResponse{
		ID:        u.ID.String(),
		Username:  u.Username,
		Email:     u.Email,
		Role:      string(u.Role),
		IsActive:  u.IsActive,
		IsLDAP:    u.IsLDAP,
		IsLocked:  u.IsLocked(),
		CreatedAt: u.CreatedAt.Format(time.RFC3339),
		UpdatedAt: u.UpdatedAt.Format(time.RFC3339),
	}

	if u.LastLoginAt != nil {
		formatted := u.LastLoginAt.Format(time.RFC3339)
		resp.LastLoginAt = &formatted
	}

	return resp
}

func toAPIKeyResponse(k *models.APIKey) APIKeyResponse {
	resp := APIKeyResponse{
		ID:        k.ID.String(),
		Name:      k.Name,
		Prefix:    k.Prefix,
		CreatedAt: k.CreatedAt.Format(time.RFC3339),
		IsExpired: k.IsExpired(),
	}

	if k.LastUsedAt != nil {
		formatted := k.LastUsedAt.Format(time.RFC3339)
		resp.LastUsedAt = &formatted
	}

	if k.ExpiresAt != nil {
		formatted := k.ExpiresAt.Format(time.RFC3339)
		resp.ExpiresAt = &formatted
	}

	return resp
}
