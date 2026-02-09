// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package oauth provides OAuth2/OIDC authentication support.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// OAuth errors
var (
	ErrProviderDisabled   = errors.New("OAuth provider is disabled")
	ErrInvalidCode        = errors.New("invalid authorization code")
	ErrTokenExchange      = errors.New("token exchange failed")
	ErrUserInfoFetch      = errors.New("failed to fetch user info")
	ErrInvalidToken       = errors.New("invalid token")
	ErrMissingUserID      = errors.New("user ID not found in response")
	ErrMissingUsername    = errors.New("username not found in response")
	ErrProviderNotFound   = errors.New("OAuth provider not found")
	ErrInvalidConfig      = errors.New("invalid OAuth configuration")
)

// ProviderType represents the type of OAuth provider.
type ProviderType string

const (
	ProviderTypeGeneric ProviderType = "generic"
	ProviderTypeOIDC    ProviderType = "oidc"
	ProviderTypeGitHub  ProviderType = "github"
	ProviderTypeGoogle  ProviderType = "google"
	ProviderTypeMicrosoft ProviderType = "microsoft"
)

// Config contains OAuth provider configuration.
type Config struct {
	// Name is a friendly name for the provider
	Name string

	// Type is the provider type
	Type ProviderType

	// ClientID is the OAuth client ID
	ClientID string

	// ClientSecret is the OAuth client secret
	ClientSecret string

	// AuthURL is the authorization endpoint
	AuthURL string

	// TokenURL is the token endpoint
	TokenURL string

	// UserInfoURL is the user info endpoint
	UserInfoURL string

	// Scopes are the OAuth scopes to request
	Scopes []string

	// RedirectURL is the callback URL
	RedirectURL string

	// UserIDClaim is the claim containing the user ID
	UserIDClaim string

	// UsernameClaim is the claim containing the username
	UsernameClaim string

	// EmailClaim is the claim containing the email
	EmailClaim string

	// GroupsClaim is the claim containing groups (optional)
	GroupsClaim string

	// AdminGroup is the group name for admin role
	AdminGroup string

	// OperatorGroup is the group name for operator role
	OperatorGroup string

	// DefaultRole is the default role for new users
	DefaultRole models.UserRole

	// AutoProvision enables automatic user creation
	AutoProvision bool

	// Enabled indicates if this provider is active
	Enabled bool

	// IssuerURL for OIDC providers
	IssuerURL string
}

// DefaultConfig returns default configuration for a provider type.
func DefaultConfig(providerType ProviderType) Config {
	config := Config{
		Type:          providerType,
		DefaultRole:   models.RoleViewer,
		AutoProvision: true,
		Enabled:       false,
		UserIDClaim:   "sub",
		UsernameClaim: "preferred_username",
		EmailClaim:    "email",
	}

	switch providerType {
	case ProviderTypeGitHub:
		config.Name = "GitHub"
		config.AuthURL = "https://github.com/login/oauth/authorize"
		config.TokenURL = "https://github.com/login/oauth/access_token"
		config.UserInfoURL = "https://api.github.com/user"
		config.Scopes = []string{"read:user", "user:email"}
		config.UserIDClaim = "id"
		config.UsernameClaim = "login"

	case ProviderTypeGoogle:
		config.Name = "Google"
		config.IssuerURL = "https://accounts.google.com"
		config.Scopes = []string{"openid", "profile", "email"}

	case ProviderTypeMicrosoft:
		config.Name = "Microsoft"
		config.IssuerURL = "https://login.microsoftonline.com/common/v2.0"
		config.Scopes = []string{"openid", "profile", "email"}

	case ProviderTypeOIDC:
		config.Name = "OIDC"
		config.Scopes = []string{"openid", "profile", "email"}
	}

	return config
}

// Validate validates the OAuth configuration.
func (c *Config) Validate() error {
	if c.ClientID == "" {
		return fmt.Errorf("%w: client ID is required", ErrInvalidConfig)
	}
	if c.ClientSecret == "" {
		return fmt.Errorf("%w: client secret is required", ErrInvalidConfig)
	}
	if c.RedirectURL == "" {
		return fmt.Errorf("%w: redirect URL is required", ErrInvalidConfig)
	}

	// OIDC providers need issuer URL
	if c.Type == ProviderTypeOIDC || c.Type == ProviderTypeGoogle || c.Type == ProviderTypeMicrosoft {
		if c.IssuerURL == "" {
			return fmt.Errorf("%w: issuer URL is required for OIDC providers", ErrInvalidConfig)
		}
	} else {
		// Generic/GitHub need explicit URLs
		if c.AuthURL == "" {
			return fmt.Errorf("%w: auth URL is required", ErrInvalidConfig)
		}
		if c.TokenURL == "" {
			return fmt.Errorf("%w: token URL is required", ErrInvalidConfig)
		}
	}

	return nil
}

// ============================================================================
// User Info
// ============================================================================

// User represents an OAuth authenticated user.
type User struct {
	ID       string
	Username string
	Email    string
	Name     string
	Groups   []string
	Role     models.UserRole
	Provider string
	RawData  map[string]interface{}
}

// ============================================================================
// Provider Interface
// ============================================================================

// Provider is the interface for OAuth providers.
type Provider interface {
	GetName() string
	IsEnabled() bool
	GetAuthURL(state string) string
	Exchange(ctx context.Context, code string) (*User, error)
}

// ============================================================================
// Generic OAuth2 Provider
// ============================================================================

// GenericProvider implements OAuth2 authentication.
type GenericProvider struct {
	config      Config
	oauth2Cfg   *oauth2.Config
	httpClient  *http.Client
	logger      *logger.Logger
	mu          sync.RWMutex
}

// NewGenericProvider creates a new generic OAuth2 provider.
func NewGenericProvider(config Config, log *logger.Logger) (*GenericProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	if log == nil {
		log = logger.Nop()
	}

	oauth2Cfg := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Scopes:       config.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.AuthURL,
			TokenURL: config.TokenURL,
		},
	}

	return &GenericProvider{
		config:    config,
		oauth2Cfg: oauth2Cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: log.Named("oauth." + strings.ToLower(config.Name)),
	}, nil
}

// GetName returns the provider name.
func (p *GenericProvider) GetName() string {
	return p.config.Name
}

// IsEnabled returns whether the provider is enabled.
func (p *GenericProvider) IsEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.config.Enabled
}

// GetAuthURL returns the authorization URL.
func (p *GenericProvider) GetAuthURL(state string) string {
	return p.oauth2Cfg.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// Exchange exchanges an authorization code for user info.
func (p *GenericProvider) Exchange(ctx context.Context, code string) (*User, error) {
	if !p.IsEnabled() {
		return nil, ErrProviderDisabled
	}

	// Exchange code for token
	token, err := p.oauth2Cfg.Exchange(ctx, code)
	if err != nil {
		p.logger.Error("token exchange failed", "error", err)
		return nil, fmt.Errorf("%w: %v", ErrTokenExchange, err)
	}

	// Fetch user info
	user, err := p.fetchUserInfo(ctx, token)
	if err != nil {
		return nil, err
	}

	p.logger.Info("OAuth authentication successful",
		"provider", p.config.Name,
		"username", user.Username,
	)

	return user, nil
}

// fetchUserInfo fetches user information from the provider.
func (p *GenericProvider) fetchUserInfo(ctx context.Context, token *oauth2.Token) (*User, error) {
	if p.config.UserInfoURL == "" {
		return nil, fmt.Errorf("%w: user info URL not configured", ErrUserInfoFetch)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", p.config.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")

	// Execute request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUserInfoFetch, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: status %d: %s", ErrUserInfoFetch, resp.StatusCode, string(body))
	}

	// Parse response
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return p.parseUserInfo(data)
}

// parseUserInfo extracts user information from the response.
func (p *GenericProvider) parseUserInfo(data map[string]interface{}) (*User, error) {
	user := &User{
		Provider: p.config.Name,
		RawData:  data,
	}

	// Extract user ID
	if id := getStringClaim(data, p.config.UserIDClaim); id != "" {
		user.ID = id
	} else {
		return nil, ErrMissingUserID
	}

	// Extract username
	if username := getStringClaim(data, p.config.UsernameClaim); username != "" {
		user.Username = username
	} else {
		// Fallback to email or ID
		if email := getStringClaim(data, p.config.EmailClaim); email != "" {
			user.Username = strings.Split(email, "@")[0]
		} else {
			user.Username = user.ID
		}
	}

	// Extract email
	user.Email = getStringClaim(data, p.config.EmailClaim)

	// Extract name
	if name := getStringClaim(data, "name"); name != "" {
		user.Name = name
	}

	// Extract groups
	if p.config.GroupsClaim != "" {
		user.Groups = getStringSliceClaim(data, p.config.GroupsClaim)
	}

	// Determine role
	user.Role = p.determineRole(user.Groups)

	return user, nil
}

// determineRole determines the user role based on groups.
func (p *GenericProvider) determineRole(groups []string) models.UserRole {
	groupSet := make(map[string]bool)
	for _, g := range groups {
		groupSet[strings.ToLower(g)] = true
	}

	if p.config.AdminGroup != "" && groupSet[strings.ToLower(p.config.AdminGroup)] {
		return models.RoleAdmin
	}

	if p.config.OperatorGroup != "" && groupSet[strings.ToLower(p.config.OperatorGroup)] {
		return models.RoleOperator
	}

	return p.config.DefaultRole
}

// UpdateConfig updates the provider configuration.
func (p *GenericProvider) UpdateConfig(config Config) error {
	if err := config.Validate(); err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.config = config
	p.oauth2Cfg = &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Scopes:       config.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.AuthURL,
			TokenURL: config.TokenURL,
		},
	}

	return nil
}

// ============================================================================
// OIDC Provider
// ============================================================================

// OIDCProvider implements OpenID Connect authentication.
type OIDCProvider struct {
	config     Config
	oauth2Cfg  *oauth2.Config
	oidcProvider *oidc.Provider
	verifier   *oidc.IDTokenVerifier
	logger     *logger.Logger
	mu         sync.RWMutex
}

// NewOIDCProvider creates a new OIDC provider.
func NewOIDCProvider(ctx context.Context, config Config, log *logger.Logger) (*OIDCProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	if log == nil {
		log = logger.Nop()
	}

	// Discover OIDC provider
	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}

	oauth2Cfg := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Scopes:       config.Scopes,
		Endpoint:     provider.Endpoint(),
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.ClientID,
	})

	return &OIDCProvider{
		config:       config,
		oauth2Cfg:    oauth2Cfg,
		oidcProvider: provider,
		verifier:     verifier,
		logger:       log.Named("oidc." + strings.ToLower(config.Name)),
	}, nil
}

// GetName returns the provider name.
func (p *OIDCProvider) GetName() string {
	return p.config.Name
}

// IsEnabled returns whether the provider is enabled.
func (p *OIDCProvider) IsEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.config.Enabled
}

// GetAuthURL returns the authorization URL.
func (p *OIDCProvider) GetAuthURL(state string) string {
	return p.oauth2Cfg.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// Exchange exchanges an authorization code for user info.
func (p *OIDCProvider) Exchange(ctx context.Context, code string) (*User, error) {
	if !p.IsEnabled() {
		return nil, ErrProviderDisabled
	}

	// Exchange code for token
	token, err := p.oauth2Cfg.Exchange(ctx, code)
	if err != nil {
		p.logger.Error("token exchange failed", "error", err)
		return nil, fmt.Errorf("%w: %v", ErrTokenExchange, err)
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("%w: no id_token in response", ErrInvalidToken)
	}

	// Verify ID token
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Extract claims
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("extract claims: %w", err)
	}

	user, err := p.parseUserInfo(claims)
	if err != nil {
		return nil, err
	}

	p.logger.Info("OIDC authentication successful",
		"provider", p.config.Name,
		"username", user.Username,
	)

	return user, nil
}

// parseUserInfo extracts user information from OIDC claims.
func (p *OIDCProvider) parseUserInfo(claims map[string]interface{}) (*User, error) {
	user := &User{
		Provider: p.config.Name,
		RawData:  claims,
	}

	// Extract user ID (sub claim is required in OIDC)
	if sub := getStringClaim(claims, "sub"); sub != "" {
		user.ID = sub
	} else {
		return nil, ErrMissingUserID
	}

	// Extract username
	if username := getStringClaim(claims, p.config.UsernameClaim); username != "" {
		user.Username = username
	} else if email := getStringClaim(claims, "email"); email != "" {
		user.Username = strings.Split(email, "@")[0]
	} else {
		user.Username = user.ID
	}

	// Extract email
	user.Email = getStringClaim(claims, "email")

	// Extract name
	if name := getStringClaim(claims, "name"); name != "" {
		user.Name = name
	}

	// Extract groups
	if p.config.GroupsClaim != "" {
		user.Groups = getStringSliceClaim(claims, p.config.GroupsClaim)
	}

	// Determine role
	user.Role = p.determineRole(user.Groups)

	return user, nil
}

// determineRole determines the user role based on groups.
func (p *OIDCProvider) determineRole(groups []string) models.UserRole {
	groupSet := make(map[string]bool)
	for _, g := range groups {
		groupSet[strings.ToLower(g)] = true
	}

	if p.config.AdminGroup != "" && groupSet[strings.ToLower(p.config.AdminGroup)] {
		return models.RoleAdmin
	}

	if p.config.OperatorGroup != "" && groupSet[strings.ToLower(p.config.OperatorGroup)] {
		return models.RoleOperator
	}

	return p.config.DefaultRole
}

// ============================================================================
// GitHub Provider
// ============================================================================

// NewGitHubProvider creates a GitHub OAuth provider.
func NewGitHubProvider(clientID, clientSecret, redirectURL string, log *logger.Logger) (*GenericProvider, error) {
	config := DefaultConfig(ProviderTypeGitHub)
	config.ClientID = clientID
	config.ClientSecret = clientSecret
	config.RedirectURL = redirectURL
	config.Enabled = true

	return NewGenericProvider(config, log)
}

// ============================================================================
// Helper Functions
// ============================================================================

// getStringClaim extracts a string claim from a map.
func getStringClaim(data map[string]interface{}, key string) string {
	if val, ok := data[key]; ok {
		switch v := val.(type) {
		case string:
			return v
		case float64:
			return fmt.Sprintf("%.0f", v)
		case int:
			return fmt.Sprintf("%d", v)
		case int64:
			return fmt.Sprintf("%d", v)
		}
	}
	return ""
}

// getStringSliceClaim extracts a string slice claim from a map.
func getStringSliceClaim(data map[string]interface{}, key string) []string {
	if val, ok := data[key]; ok {
		switch v := val.(type) {
		case []interface{}:
			result := make([]string, 0, len(v))
			for _, item := range v {
				if s, ok := item.(string); ok {
					result = append(result, s)
				}
			}
			return result
		case []string:
			return v
		}
	}
	return nil
}

// ============================================================================
// Provider Registry
// ============================================================================

// Registry manages multiple OAuth providers.
type Registry struct {
	providers map[string]Provider
	mu        sync.RWMutex
	logger    *logger.Logger
}

// NewRegistry creates a new provider registry.
func NewRegistry(log *logger.Logger) *Registry {
	if log == nil {
		log = logger.Nop()
	}

	return &Registry{
		providers: make(map[string]Provider),
		logger:    log.Named("oauth.registry"),
	}
}

// Register registers a provider.
func (r *Registry) Register(name string, provider Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.providers[strings.ToLower(name)] = provider
	r.logger.Info("OAuth provider registered", "name", name)
}

// Get retrieves a provider by name.
func (r *Registry) Get(name string) (Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	provider, ok := r.providers[strings.ToLower(name)]
	if !ok {
		return nil, ErrProviderNotFound
	}

	return provider, nil
}

// List returns all registered providers.
func (r *Registry) List() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	providers := make([]Provider, 0, len(r.providers))
	for _, p := range r.providers {
		providers = append(providers, p)
	}

	return providers
}

// ListEnabled returns all enabled providers.
func (r *Registry) ListEnabled() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	providers := make([]Provider, 0)
	for _, p := range r.providers {
		if p.IsEnabled() {
			providers = append(providers, p)
		}
	}

	return providers
}

// Remove removes a provider.
func (r *Registry) Remove(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.providers, strings.ToLower(name))
	r.logger.Info("OAuth provider removed", "name", name)
}
