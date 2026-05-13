// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// OAuthConfigHandler handles OAuth config API requests
type OAuthConfigHandler struct {
	BaseHandler
	repo      *postgres.OAuthConfigRepository
	encryptor *crypto.Encryptor
}

// NewOAuthConfigHandler creates a new OAuth config handler
func NewOAuthConfigHandler(repo *postgres.OAuthConfigRepository, encryptor *crypto.Encryptor, log *logger.Logger) *OAuthConfigHandler {
	return &OAuthConfigHandler{
		BaseHandler: NewBaseHandler(log),
		repo:        repo,
		encryptor:   encryptor,
	}
}

// Routes returns the OAuth config routes
func (h *OAuthConfigHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// All routes require admin role
	r.Use(middleware.RequireAdmin)

	r.Get("/", h.List)
	r.Post("/", h.Create)
	r.Get("/{id}", h.GetByID)
	r.Put("/{id}", h.Update)
	r.Delete("/{id}", h.Delete)
	r.Post("/{id}/enable", h.Enable)
	r.Post("/{id}/disable", h.Disable)
	r.Get("/stats", h.Stats)

	return r
}

// CreateOAuthConfigRequest represents the request body for creating an OAuth config
type CreateOAuthConfigRequest struct {
	Name          string   `json:"name"`
	Provider      string   `json:"provider"`
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	AuthURL       string   `json:"auth_url,omitempty"`
	TokenURL      string   `json:"token_url,omitempty"`
	UserInfoURL   string   `json:"user_info_url,omitempty"`
	Scopes        []string `json:"scopes,omitempty"`
	RedirectURL   string   `json:"redirect_url,omitempty"`
	DefaultRole   string   `json:"default_role,omitempty"`
	AutoProvision bool     `json:"auto_provision"`
	AdminGroup    string   `json:"admin_group,omitempty"`
	OperatorGroup string   `json:"operator_group,omitempty"`
	UserIDClaim   string   `json:"user_id_claim,omitempty"`
	UsernameClaim string   `json:"username_claim,omitempty"`
	EmailClaim    string   `json:"email_claim,omitempty"`
	GroupsClaim   string   `json:"groups_claim,omitempty"`
	IsEnabled     bool     `json:"is_enabled"`
}

// OAuthConfigResponse represents an OAuth config in API responses
type OAuthConfigResponse struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Provider      string   `json:"provider"`
	ClientID      string   `json:"client_id"`
	AuthURL       string   `json:"auth_url,omitempty"`
	TokenURL      string   `json:"token_url,omitempty"`
	UserInfoURL   string   `json:"user_info_url,omitempty"`
	Scopes        []string `json:"scopes"`
	RedirectURL   string   `json:"redirect_url,omitempty"`
	DefaultRole   string   `json:"default_role"`
	AutoProvision bool     `json:"auto_provision"`
	AdminGroup    string   `json:"admin_group,omitempty"`
	OperatorGroup string   `json:"operator_group,omitempty"`
	UserIDClaim   string   `json:"user_id_claim"`
	UsernameClaim string   `json:"username_claim"`
	EmailClaim    string   `json:"email_claim"`
	GroupsClaim   string   `json:"groups_claim"`
	IsEnabled     bool     `json:"is_enabled"`
	CreatedAt     string   `json:"created_at"`
	UpdatedAt     string   `json:"updated_at"`
}

func toOAuthConfigResponse(config *models.OAuthConfig) OAuthConfigResponse {
	scopes := config.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	return OAuthConfigResponse{
		ID:            config.ID.String(),
		Name:          config.Name,
		Provider:      config.Provider,
		ClientID:      config.ClientID,
		AuthURL:       config.AuthURL,
		TokenURL:      config.TokenURL,
		UserInfoURL:   config.UserInfoURL,
		Scopes:        scopes,
		RedirectURL:   config.RedirectURL,
		DefaultRole:   string(config.DefaultRole),
		AutoProvision: config.AutoProvision,
		AdminGroup:    config.AdminGroup,
		OperatorGroup: config.OperatorGroup,
		UserIDClaim:   config.UserIDClaim,
		UsernameClaim: config.UsernameClaim,
		EmailClaim:    config.EmailClaim,
		GroupsClaim:   config.GroupsClaim,
		IsEnabled:     config.IsEnabled,
		CreatedAt:     config.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:     config.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

// List handles GET /api/v1/oauth/configs
func (h *OAuthConfigHandler) List(w http.ResponseWriter, r *http.Request) {
	configs, err := h.repo.List(r.Context())
	if err != nil {
		h.InternalError(w, err)
		return
	}

	response := make([]OAuthConfigResponse, len(configs))
	for i, config := range configs {
		response[i] = toOAuthConfigResponse(config)
	}

	h.OK(w, map[string]any{
		"configs": response,
		"count":   len(response),
	})
}

// Create handles POST /api/v1/oauth/configs
func (h *OAuthConfigHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateOAuthConfigRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	// Validate required fields
	if req.Name == "" {
		h.BadRequest(w, "name is required")
		return
	}
	if req.Provider == "" {
		h.BadRequest(w, "provider is required")
		return
	}
	if req.ClientID == "" {
		h.BadRequest(w, "client_id is required")
		return
	}
	if req.ClientSecret == "" {
		h.BadRequest(w, "client_secret is required")
		return
	}

	// Validate provider type
	validProviders := map[string]bool{
		models.OAuthProviderGeneric:   true,
		models.OAuthProviderOIDC:      true,
		models.OAuthProviderGitHub:    true,
		models.OAuthProviderGoogle:    true,
		models.OAuthProviderMicrosoft: true,
	}
	if !validProviders[req.Provider] {
		h.BadRequest(w, "invalid provider type, must be one of: generic, oidc, github, google, microsoft")
		return
	}

	// Set defaults
	if req.DefaultRole == "" {
		req.DefaultRole = "viewer"
	}
	if req.UserIDClaim == "" {
		req.UserIDClaim = "sub"
	}
	if req.UsernameClaim == "" {
		req.UsernameClaim = "preferred_username"
	}
	if req.EmailClaim == "" {
		req.EmailClaim = "email"
	}
	if req.GroupsClaim == "" {
		req.GroupsClaim = "groups"
	}
	if req.Scopes == nil {
		req.Scopes = []string{}
	}

	// Encrypt client secret
	encryptedSecret, err := h.encryptor.EncryptString(req.ClientSecret)
	if err != nil {
		h.InternalError(w, err)
		return
	}

	input := &postgres.CreateOAuthConfigInput{
		Name:          req.Name,
		Provider:      req.Provider,
		ClientID:      req.ClientID,
		ClientSecret:  encryptedSecret,
		AuthURL:       req.AuthURL,
		TokenURL:      req.TokenURL,
		UserInfoURL:   req.UserInfoURL,
		Scopes:        req.Scopes,
		RedirectURL:   req.RedirectURL,
		DefaultRole:   req.DefaultRole,
		AutoProvision: req.AutoProvision,
		AdminGroup:    req.AdminGroup,
		OperatorGroup: req.OperatorGroup,
		UserIDClaim:   req.UserIDClaim,
		UsernameClaim: req.UsernameClaim,
		EmailClaim:    req.EmailClaim,
		GroupsClaim:   req.GroupsClaim,
		IsEnabled:     req.IsEnabled,
	}

	config, err := h.repo.Create(r.Context(), input)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, toOAuthConfigResponse(config))
}

// GetByID handles GET /api/v1/oauth/configs/{id}
func (h *OAuthConfigHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	config, err := h.repo.GetByID(r.Context(), id)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toOAuthConfigResponse(config))
}

// UpdateOAuthConfigRequest represents the request body for updating an OAuth config
type UpdateOAuthConfigRequest struct {
	Name          *string  `json:"name,omitempty"`
	Provider      *string  `json:"provider,omitempty"`
	ClientID      *string  `json:"client_id,omitempty"`
	ClientSecret  *string  `json:"client_secret,omitempty"`
	AuthURL       *string  `json:"auth_url,omitempty"`
	TokenURL      *string  `json:"token_url,omitempty"`
	UserInfoURL   *string  `json:"user_info_url,omitempty"`
	Scopes        []string `json:"scopes,omitempty"`
	RedirectURL   *string  `json:"redirect_url,omitempty"`
	DefaultRole   *string  `json:"default_role,omitempty"`
	AutoProvision *bool    `json:"auto_provision,omitempty"`
	AdminGroup    *string  `json:"admin_group,omitempty"`
	OperatorGroup *string  `json:"operator_group,omitempty"`
	UserIDClaim   *string  `json:"user_id_claim,omitempty"`
	UsernameClaim *string  `json:"username_claim,omitempty"`
	EmailClaim    *string  `json:"email_claim,omitempty"`
	GroupsClaim   *string  `json:"groups_claim,omitempty"`
	IsEnabled     *bool    `json:"is_enabled,omitempty"`
}

// Update handles PUT /api/v1/oauth/configs/{id}
func (h *OAuthConfigHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req UpdateOAuthConfigRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	// Validate provider type if provided
	if req.Provider != nil {
		validProviders := map[string]bool{
			models.OAuthProviderGeneric:   true,
			models.OAuthProviderOIDC:      true,
			models.OAuthProviderGitHub:    true,
			models.OAuthProviderGoogle:    true,
			models.OAuthProviderMicrosoft: true,
		}
		if !validProviders[*req.Provider] {
			h.BadRequest(w, "invalid provider type")
			return
		}
	}

	input := &postgres.UpdateOAuthConfigInput{
		Name:          req.Name,
		Provider:      req.Provider,
		ClientID:      req.ClientID,
		AuthURL:       req.AuthURL,
		TokenURL:      req.TokenURL,
		UserInfoURL:   req.UserInfoURL,
		Scopes:        req.Scopes,
		RedirectURL:   req.RedirectURL,
		DefaultRole:   req.DefaultRole,
		AutoProvision: req.AutoProvision,
		AdminGroup:    req.AdminGroup,
		OperatorGroup: req.OperatorGroup,
		UserIDClaim:   req.UserIDClaim,
		UsernameClaim: req.UsernameClaim,
		EmailClaim:    req.EmailClaim,
		GroupsClaim:   req.GroupsClaim,
		IsEnabled:     req.IsEnabled,
	}

	// Encrypt client secret if provided
	if req.ClientSecret != nil && *req.ClientSecret != "" {
		encryptedSecret, err := h.encryptor.EncryptString(*req.ClientSecret)
		if err != nil {
			h.InternalError(w, err)
			return
		}
		input.ClientSecret = &encryptedSecret
	}

	config, err := h.repo.Update(r.Context(), id, input)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toOAuthConfigResponse(config))
}

// Delete handles DELETE /api/v1/oauth/configs/{id}
func (h *OAuthConfigHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.repo.Delete(r.Context(), id); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// Enable handles POST /api/v1/oauth/configs/{id}/enable
func (h *OAuthConfigHandler) Enable(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	enabled := true
	input := &postgres.UpdateOAuthConfigInput{
		IsEnabled: &enabled,
	}

	config, err := h.repo.Update(r.Context(), id, input)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toOAuthConfigResponse(config))
}

// Disable handles POST /api/v1/oauth/configs/{id}/disable
func (h *OAuthConfigHandler) Disable(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	enabled := false
	input := &postgres.UpdateOAuthConfigInput{
		IsEnabled: &enabled,
	}

	config, err := h.repo.Update(r.Context(), id, input)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toOAuthConfigResponse(config))
}

// Stats handles GET /api/v1/oauth/configs/stats
func (h *OAuthConfigHandler) Stats(w http.ResponseWriter, r *http.Request) {
	total, err := h.repo.Count(r.Context())
	if err != nil {
		h.InternalError(w, err)
		return
	}

	enabled, err := h.repo.CountEnabled(r.Context())
	if err != nil {
		h.InternalError(w, err)
		return
	}

	// Get provider distribution
	configs, err := h.repo.List(r.Context())
	if err != nil {
		h.InternalError(w, err)
		return
	}

	providerCounts := make(map[string]int)
	for _, config := range configs {
		providerCounts[config.Provider]++
	}

	h.OK(w, map[string]any{
		"total":     total,
		"enabled":   enabled,
		"disabled":  total - enabled,
		"providers": providerCounts,
	})
}

// GetProviderDefaults returns default configuration for a provider type
func GetProviderDefaults(provider string) map[string]any {
	defaults := map[string]any{
		"user_id_claim":   "sub",
		"username_claim":  "preferred_username",
		"email_claim":     "email",
		"groups_claim":    "groups",
		"auto_provision":  true,
		"default_role":    "viewer",
	}

	switch strings.ToLower(provider) {
	case models.OAuthProviderGitHub:
		defaults["auth_url"] = "https://github.com/login/oauth/authorize"
		defaults["token_url"] = "https://github.com/login/oauth/access_token"
		defaults["user_info_url"] = "https://api.github.com/user"
		defaults["scopes"] = []string{"read:user", "user:email"}
		defaults["username_claim"] = "login"
		defaults["user_id_claim"] = "id"
	case models.OAuthProviderGoogle:
		defaults["auth_url"] = "https://accounts.google.com/o/oauth2/v2/auth"
		defaults["token_url"] = "https://oauth2.googleapis.com/token"
		defaults["user_info_url"] = "https://openidconnect.googleapis.com/v1/userinfo"
		defaults["scopes"] = []string{"openid", "profile", "email"}
	case models.OAuthProviderMicrosoft:
		defaults["auth_url"] = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
		defaults["token_url"] = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
		defaults["user_info_url"] = "https://graph.microsoft.com/oidc/userinfo"
		defaults["scopes"] = []string{"openid", "profile", "email"}
	case models.OAuthProviderOIDC:
		defaults["scopes"] = []string{"openid", "profile", "email"}
	default:
		defaults["scopes"] = []string{}
	}

	return defaults
}
