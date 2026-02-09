// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/admin"
)

// OAuthConfigRepository defines the interface for OAuth config operations.
type OAuthConfigRepository interface {
	Create(ctx context.Context, input *postgres.CreateOAuthConfigInput) (*models.OAuthConfig, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.OAuthConfig, error)
	GetByName(ctx context.Context, name string) (*models.OAuthConfig, error)
	List(ctx context.Context) ([]*models.OAuthConfig, error)
	ListEnabled(ctx context.Context) ([]*models.OAuthConfig, error)
	Update(ctx context.Context, id uuid.UUID, input *postgres.UpdateOAuthConfigInput) (*models.OAuthConfig, error)
	Delete(ctx context.Context, id uuid.UUID) error
	Count(ctx context.Context) (int64, error)
	CountEnabled(ctx context.Context) (int64, error)
}

// Encryptor defines the interface for encryption operations.
type Encryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

// Logger defines the interface for logging operations.
type Logger interface {
	Error(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
}

// SetOAuthConfigRepo sets the OAuth config repository.
func (h *Handler) SetOAuthConfigRepo(repo OAuthConfigRepository) {
	h.oauthConfigRepo = repo
}

// SetEncryptor sets the encryptor for secret encryption.
func (h *Handler) SetEncryptor(enc Encryptor) {
	h.encryptor = enc
}

// SetLogger sets the logger for the handler.
func (h *Handler) SetLogger(log Logger) {
	h.logger = log
}

// OAuthProvidersTempl renders the OAuth providers list page.
func (h *Handler) OAuthProvidersTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.preparePageData(r, "OAuth Providers", "settings")

	providers, err := h.oauthConfigRepo.List(r.Context())
	if err != nil {
		h.logger.Error("failed to list OAuth providers", "error", err)
		h.RenderError(w, r, http.StatusInternalServerError, "Error", "Failed to load OAuth providers")
		return
	}

	total, _ := h.oauthConfigRepo.Count(r.Context())
	enabled, _ := h.oauthConfigRepo.CountEnabled(r.Context())

	// Convert to template format
	providerItems := make([]admin.OAuthProviderItem, len(providers))
	for i, p := range providers {
		providerItems[i] = admin.OAuthProviderItem{
			ID:            p.ID.String(),
			Name:          p.Name,
			Provider:      p.Provider,
			ClientID:      p.ClientID,
			AuthURL:       p.AuthURL,
			DefaultRole:   string(p.DefaultRole),
			AutoProvision: p.AutoProvision,
			IsEnabled:     p.IsEnabled,
			CreatedAt:     p.CreatedAt.Format("2006-01-02 15:04"),
			UpdatedAt:     p.UpdatedAt.Format("2006-01-02 15:04"),
		}
	}

	data := admin.OAuthProvidersData{
		PageData:  ToTemplPageData(pageData),
		Providers: providerItems,
		Stats: admin.OAuthStats{
			Total:    total,
			Enabled:  enabled,
			Disabled: total - enabled,
		},
	}

	h.renderTempl(w, r, admin.OAuthProvidersList(data))
}

// OAuthProviderEditTempl renders the OAuth provider edit page.
func (h *Handler) OAuthProviderEditTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.preparePageData(r, "Edit OAuth Provider", "settings")

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.RenderError(w, r, http.StatusBadRequest, "Error", "Invalid provider ID")
		return
	}

	provider, err := h.oauthConfigRepo.GetByID(r.Context(), id)
	if err != nil {
		h.RenderError(w, r, http.StatusNotFound, "Error", "OAuth provider not found")
		return
	}

	scopes := ""
	if provider.Scopes != nil {
		scopes = strings.Join(provider.Scopes, " ")
	}

	data := admin.OAuthProviderEditData{
		PageData: ToTemplPageData(pageData),
		Provider: admin.OAuthProviderDetail{
			ID:            provider.ID.String(),
			Name:          provider.Name,
			Provider:      provider.Provider,
			ClientID:      provider.ClientID,
			AuthURL:       provider.AuthURL,
			TokenURL:      provider.TokenURL,
			UserInfoURL:   provider.UserInfoURL,
			Scopes:        scopes,
			RedirectURL:   provider.RedirectURL,
			DefaultRole:   string(provider.DefaultRole),
			AutoProvision: provider.AutoProvision,
			AdminGroup:    provider.AdminGroup,
			OperatorGroup: provider.OperatorGroup,
			UserIDClaim:   provider.UserIDClaim,
			UsernameClaim: provider.UsernameClaim,
			EmailClaim:    provider.EmailClaim,
			GroupsClaim:   provider.GroupsClaim,
			IsEnabled:     provider.IsEnabled,
			CreatedAt:     provider.CreatedAt.Format("2006-01-02 15:04:05"),
			UpdatedAt:     provider.UpdatedAt.Format("2006-01-02 15:04:05"),
		},
	}

	h.renderTempl(w, r, admin.OAuthProviderEdit(data))
}

// OAuthProviderCreate handles creating a new OAuth provider.
func (h *Handler) OAuthProviderCreate(w http.ResponseWriter, r *http.Request) {
	// Enforce MaxOAuthProviders license limit
	if h.licenseProvider != nil {
		info := h.licenseProvider.GetInfo()
		if info != nil {
			limit := info.Limits.MaxOAuthProviders
			if limit > 0 {
				count, err := h.oauthConfigRepo.Count(r.Context())
				if err == nil && int(count) >= limit {
					h.redirect(w, r, fmt.Sprintf("/admin/oauth?error=OAuth+provider+limit+reached+(%d/%d),+upgrade+your+license", count, limit))
					return
				}
			}
		}
	}

	if err := r.ParseForm(); err != nil {
		h.redirect(w, r, "/admin/oauth?error=Invalid+form+data")
		return
	}

	scopes := []string{}
	if scopesStr := r.FormValue("scopes"); scopesStr != "" {
		scopes = strings.Fields(scopesStr)
	}

	// Encrypt client secret
	encryptedSecret, err := h.encryptor.Encrypt(r.FormValue("client_secret"))
	if err != nil {
		h.logger.Error("failed to encrypt client secret", "error", err)
		h.redirect(w, r, "/admin/oauth?error=Failed+to+encrypt+credentials")
		return
	}

	input := &postgres.CreateOAuthConfigInput{
		Name:          r.FormValue("name"),
		Provider:      r.FormValue("provider"),
		ClientID:      r.FormValue("client_id"),
		ClientSecret:  encryptedSecret,
		AuthURL:       r.FormValue("auth_url"),
		TokenURL:      r.FormValue("token_url"),
		UserInfoURL:   r.FormValue("user_info_url"),
		Scopes:        scopes,
		RedirectURL:   r.FormValue("redirect_url"),
		DefaultRole:   r.FormValue("default_role"),
		AutoProvision: r.FormValue("auto_provision") == "on",
		AdminGroup:    r.FormValue("admin_group"),
		OperatorGroup: r.FormValue("operator_group"),
		UserIDClaim:   r.FormValue("user_id_claim"),
		UsernameClaim: r.FormValue("username_claim"),
		EmailClaim:    r.FormValue("email_claim"),
		GroupsClaim:   r.FormValue("groups_claim"),
		IsEnabled:     r.FormValue("is_enabled") == "on",
	}

	// Set defaults if not provided
	if input.DefaultRole == "" {
		input.DefaultRole = "viewer"
	}
	if input.UserIDClaim == "" {
		input.UserIDClaim = "sub"
	}
	if input.UsernameClaim == "" {
		input.UsernameClaim = "preferred_username"
	}
	if input.EmailClaim == "" {
		input.EmailClaim = "email"
	}
	if input.GroupsClaim == "" {
		input.GroupsClaim = "groups"
	}

	_, err = h.oauthConfigRepo.Create(r.Context(), input)
	if err != nil {
		h.logger.Error("failed to create OAuth provider", "error", err)
		h.redirect(w, r, "/admin/oauth?error=Failed+to+create+provider")
		return
	}

	h.redirect(w, r, "/admin/oauth?success=Provider+created+successfully")
}

// OAuthProviderUpdate handles updating an OAuth provider.
func (h *Handler) OAuthProviderUpdate(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/admin/oauth?error=Invalid+provider+ID")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.redirect(w, r, "/admin/oauth/"+idStr+"?error=Invalid+form+data")
		return
	}

	name := r.FormValue("name")
	provider := r.FormValue("provider")
	clientID := r.FormValue("client_id")
	authURL := r.FormValue("auth_url")
	tokenURL := r.FormValue("token_url")
	userInfoURL := r.FormValue("user_info_url")
	redirectURL := r.FormValue("redirect_url")
	defaultRole := r.FormValue("default_role")
	adminGroup := r.FormValue("admin_group")
	operatorGroup := r.FormValue("operator_group")
	userIDClaim := r.FormValue("user_id_claim")
	usernameClaim := r.FormValue("username_claim")
	emailClaim := r.FormValue("email_claim")
	groupsClaim := r.FormValue("groups_claim")
	autoProvision := r.FormValue("auto_provision") == "on"
	isEnabled := r.FormValue("is_enabled") == "on"

	var scopes []string
	if scopesStr := r.FormValue("scopes"); scopesStr != "" {
		scopes = strings.Fields(scopesStr)
	}

	input := &postgres.UpdateOAuthConfigInput{
		Name:          &name,
		Provider:      &provider,
		ClientID:      &clientID,
		AuthURL:       &authURL,
		TokenURL:      &tokenURL,
		UserInfoURL:   &userInfoURL,
		Scopes:        scopes,
		RedirectURL:   &redirectURL,
		DefaultRole:   &defaultRole,
		AutoProvision: &autoProvision,
		AdminGroup:    &adminGroup,
		OperatorGroup: &operatorGroup,
		UserIDClaim:   &userIDClaim,
		UsernameClaim: &usernameClaim,
		EmailClaim:    &emailClaim,
		GroupsClaim:   &groupsClaim,
		IsEnabled:     &isEnabled,
	}

	// Only update client secret if provided
	if clientSecret := r.FormValue("client_secret"); clientSecret != "" {
		encryptedSecret, err := h.encryptor.Encrypt(clientSecret)
		if err != nil {
			h.logger.Error("failed to encrypt client secret", "error", err)
			h.redirect(w, r, "/admin/oauth/"+idStr+"?error=Failed+to+encrypt+credentials")
			return
		}
		input.ClientSecret = &encryptedSecret
	}

	_, err = h.oauthConfigRepo.Update(r.Context(), id, input)
	if err != nil {
		h.logger.Error("failed to update OAuth provider", "error", err)
		h.redirect(w, r, "/admin/oauth/"+idStr+"?error=Failed+to+update+provider")
		return
	}

	h.redirect(w, r, "/admin/oauth?success=Provider+updated+successfully")
}

// OAuthProviderDelete handles deleting an OAuth provider.
func (h *Handler) OAuthProviderDelete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/admin/oauth?error=Invalid+provider+ID")
		return
	}

	if err := h.oauthConfigRepo.Delete(r.Context(), id); err != nil {
		h.logger.Error("failed to delete OAuth provider", "error", err)
		h.redirect(w, r, "/admin/oauth?error=Failed+to+delete+provider")
		return
	}

	h.redirect(w, r, "/admin/oauth?success=Provider+deleted+successfully")
}

// OAuthProviderEnable handles enabling an OAuth provider.
func (h *Handler) OAuthProviderEnable(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/admin/oauth?error=Invalid+provider+ID")
		return
	}

	enabled := true
	input := &postgres.UpdateOAuthConfigInput{
		IsEnabled: &enabled,
	}

	if _, err := h.oauthConfigRepo.Update(r.Context(), id, input); err != nil {
		h.logger.Error("failed to enable OAuth provider", "error", err)
		h.redirect(w, r, "/admin/oauth?error=Failed+to+enable+provider")
		return
	}

	h.redirect(w, r, "/admin/oauth?success=Provider+enabled")
}

// OAuthProviderDisable handles disabling an OAuth provider.
func (h *Handler) OAuthProviderDisable(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/admin/oauth?error=Invalid+provider+ID")
		return
	}

	enabled := false
	input := &postgres.UpdateOAuthConfigInput{
		IsEnabled: &enabled,
	}

	if _, err := h.oauthConfigRepo.Update(r.Context(), id, input); err != nil {
		h.logger.Error("failed to disable OAuth provider", "error", err)
		h.redirect(w, r, "/admin/oauth?error=Failed+to+disable+provider")
		return
	}

	h.redirect(w, r, "/admin/oauth?success=Provider+disabled")
}
