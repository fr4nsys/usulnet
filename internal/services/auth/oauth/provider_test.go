// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package oauth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ============================================================================
// Config Validation Tests
// ============================================================================

func TestConfig_Validate_Valid(t *testing.T) {
	cfg := Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "http://localhost/callback",
		AuthURL:      "http://idp/auth",
		TokenURL:     "http://idp/token",
		Type:         ProviderTypeGeneric,
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
}

func TestConfig_Validate_MissingClientID(t *testing.T) {
	cfg := Config{
		ClientSecret: "secret",
		RedirectURL:  "http://localhost/callback",
		AuthURL:      "http://idp/auth",
		TokenURL:     "http://idp/token",
		Type:         ProviderTypeGeneric,
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing client ID")
	}
	if !strings.Contains(err.Error(), "client ID is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfig_Validate_MissingClientSecret(t *testing.T) {
	cfg := Config{
		ClientID:    "client-id",
		RedirectURL: "http://localhost/callback",
		AuthURL:     "http://idp/auth",
		TokenURL:    "http://idp/token",
		Type:        ProviderTypeGeneric,
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing client secret")
	}
	if !strings.Contains(err.Error(), "client secret is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfig_Validate_MissingRedirectURL(t *testing.T) {
	cfg := Config{
		ClientID:     "client-id",
		ClientSecret: "secret",
		AuthURL:      "http://idp/auth",
		TokenURL:     "http://idp/token",
		Type:         ProviderTypeGeneric,
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing redirect URL")
	}
	if !strings.Contains(err.Error(), "redirect URL is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfig_Validate_GenericMissingAuthURL(t *testing.T) {
	cfg := Config{
		ClientID:     "client-id",
		ClientSecret: "secret",
		RedirectURL:  "http://localhost/callback",
		TokenURL:     "http://idp/token",
		Type:         ProviderTypeGeneric,
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing auth URL")
	}
	if !strings.Contains(err.Error(), "auth URL is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfig_Validate_GenericMissingTokenURL(t *testing.T) {
	cfg := Config{
		ClientID:     "client-id",
		ClientSecret: "secret",
		RedirectURL:  "http://localhost/callback",
		AuthURL:      "http://idp/auth",
		Type:         ProviderTypeGeneric,
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing token URL")
	}
	if !strings.Contains(err.Error(), "token URL is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfig_Validate_OIDCRequiresIssuerURL(t *testing.T) {
	for _, pt := range []ProviderType{ProviderTypeOIDC, ProviderTypeGoogle, ProviderTypeMicrosoft} {
		cfg := Config{
			ClientID:     "client-id",
			ClientSecret: "secret",
			RedirectURL:  "http://localhost/callback",
			Type:         pt,
		}

		err := cfg.Validate()
		if err == nil {
			t.Fatalf("expected error for %s missing issuer URL", pt)
		}
		if !strings.Contains(err.Error(), "issuer URL is required") {
			t.Fatalf("unexpected error for %s: %v", pt, err)
		}
	}
}

func TestConfig_Validate_OIDCWithIssuerURL(t *testing.T) {
	cfg := Config{
		ClientID:     "client-id",
		ClientSecret: "secret",
		RedirectURL:  "http://localhost/callback",
		Type:         ProviderTypeOIDC,
		IssuerURL:    "https://accounts.example.com",
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid OIDC config, got error: %v", err)
	}
}

func TestConfig_Validate_GitHubNeedsURLsNotIssuer(t *testing.T) {
	cfg := Config{
		ClientID:     "client-id",
		ClientSecret: "secret",
		RedirectURL:  "http://localhost/callback",
		Type:         ProviderTypeGitHub,
		AuthURL:      "https://github.com/login/oauth/authorize",
		TokenURL:     "https://github.com/login/oauth/access_token",
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid GitHub config, got error: %v", err)
	}
}

// ============================================================================
// DefaultConfig Tests
// ============================================================================

func TestDefaultConfig_Generic(t *testing.T) {
	cfg := DefaultConfig(ProviderTypeGeneric)

	if cfg.Type != ProviderTypeGeneric {
		t.Fatalf("expected type generic, got %s", cfg.Type)
	}
	if cfg.DefaultRole != models.RoleViewer {
		t.Fatalf("expected default role viewer, got %s", cfg.DefaultRole)
	}
	if !cfg.AutoProvision {
		t.Fatal("expected auto-provision enabled")
	}
	if cfg.Enabled {
		t.Fatal("expected disabled by default")
	}
	if cfg.UserIDClaim != "sub" {
		t.Fatalf("expected sub claim, got %s", cfg.UserIDClaim)
	}
	if cfg.UsernameClaim != "preferred_username" {
		t.Fatalf("expected preferred_username claim, got %s", cfg.UsernameClaim)
	}
	if cfg.EmailClaim != "email" {
		t.Fatalf("expected email claim, got %s", cfg.EmailClaim)
	}
}

func TestDefaultConfig_GitHub(t *testing.T) {
	cfg := DefaultConfig(ProviderTypeGitHub)

	if cfg.Name != "GitHub" {
		t.Fatalf("expected name GitHub, got %s", cfg.Name)
	}
	if cfg.AuthURL != "https://github.com/login/oauth/authorize" {
		t.Fatalf("unexpected auth URL: %s", cfg.AuthURL)
	}
	if cfg.TokenURL != "https://github.com/login/oauth/access_token" {
		t.Fatalf("unexpected token URL: %s", cfg.TokenURL)
	}
	if cfg.UserInfoURL != "https://api.github.com/user" {
		t.Fatalf("unexpected user info URL: %s", cfg.UserInfoURL)
	}
	if cfg.UserIDClaim != "id" {
		t.Fatalf("expected id claim for GitHub, got %s", cfg.UserIDClaim)
	}
	if cfg.UsernameClaim != "login" {
		t.Fatalf("expected login claim for GitHub, got %s", cfg.UsernameClaim)
	}
	if len(cfg.Scopes) != 2 || cfg.Scopes[0] != "read:user" || cfg.Scopes[1] != "user:email" {
		t.Fatalf("unexpected scopes: %v", cfg.Scopes)
	}
}

func TestDefaultConfig_Google(t *testing.T) {
	cfg := DefaultConfig(ProviderTypeGoogle)

	if cfg.Name != "Google" {
		t.Fatalf("expected name Google, got %s", cfg.Name)
	}
	if cfg.IssuerURL != "https://accounts.google.com" {
		t.Fatalf("unexpected issuer URL: %s", cfg.IssuerURL)
	}
	if len(cfg.Scopes) != 3 {
		t.Fatalf("expected 3 scopes, got %d", len(cfg.Scopes))
	}
}

func TestDefaultConfig_Microsoft(t *testing.T) {
	cfg := DefaultConfig(ProviderTypeMicrosoft)

	if cfg.Name != "Microsoft" {
		t.Fatalf("expected name Microsoft, got %s", cfg.Name)
	}
	if cfg.IssuerURL != "https://login.microsoftonline.com/common/v2.0" {
		t.Fatalf("unexpected issuer URL: %s", cfg.IssuerURL)
	}
}

func TestDefaultConfig_OIDC(t *testing.T) {
	cfg := DefaultConfig(ProviderTypeOIDC)

	if cfg.Name != "OIDC" {
		t.Fatalf("expected name OIDC, got %s", cfg.Name)
	}
	if len(cfg.Scopes) != 3 {
		t.Fatalf("expected 3 scopes, got %d", len(cfg.Scopes))
	}
}

// ============================================================================
// GenericProvider Tests
// ============================================================================

func newTestProvider(t *testing.T) *GenericProvider {
	t.Helper()
	cfg := Config{
		Name:          "TestProvider",
		Type:          ProviderTypeGeneric,
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		AuthURL:       "http://localhost/auth",
		TokenURL:      "http://localhost/token",
		UserInfoURL:   "http://localhost/userinfo",
		RedirectURL:   "http://localhost/callback",
		Scopes:        []string{"openid", "profile"},
		UserIDClaim:   "sub",
		UsernameClaim: "preferred_username",
		EmailClaim:    "email",
		DefaultRole:   models.RoleViewer,
		Enabled:       true,
	}

	p, err := NewGenericProvider(cfg, nil)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}
	return p
}

func TestGenericProvider_GetName(t *testing.T) {
	p := newTestProvider(t)
	if p.GetName() != "TestProvider" {
		t.Fatalf("expected TestProvider, got %s", p.GetName())
	}
}

func TestGenericProvider_IsEnabled(t *testing.T) {
	p := newTestProvider(t)
	if !p.IsEnabled() {
		t.Fatal("expected enabled")
	}
}

func TestGenericProvider_AutoProvisionEnabled(t *testing.T) {
	cfg := Config{
		Name:          "Test",
		Type:          ProviderTypeGeneric,
		ClientID:      "id",
		ClientSecret:  "secret",
		AuthURL:       "http://localhost/auth",
		TokenURL:      "http://localhost/token",
		RedirectURL:   "http://localhost/callback",
		AutoProvision: true,
		Enabled:       true,
	}

	p, err := NewGenericProvider(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !p.AutoProvisionEnabled() {
		t.Fatal("expected auto-provision enabled")
	}
}

func TestGenericProvider_GetAuthURL(t *testing.T) {
	p := newTestProvider(t)
	url := p.GetAuthURL("test-state-123")

	if !strings.Contains(url, "http://localhost/auth") {
		t.Fatalf("expected auth URL base, got %s", url)
	}
	if !strings.Contains(url, "state=test-state-123") {
		t.Fatalf("expected state parameter, got %s", url)
	}
	if !strings.Contains(url, "client_id=test-client-id") {
		t.Fatalf("expected client_id parameter, got %s", url)
	}
	if !strings.Contains(url, "redirect_uri=") {
		t.Fatalf("expected redirect_uri parameter, got %s", url)
	}
	if !strings.Contains(url, "access_type=offline") {
		t.Fatalf("expected access_type=offline, got %s", url)
	}
}

func TestGenericProvider_Exchange_DisabledProvider(t *testing.T) {
	cfg := Config{
		Name:         "Disabled",
		Type:         ProviderTypeGeneric,
		ClientID:     "id",
		ClientSecret: "secret",
		AuthURL:      "http://localhost/auth",
		TokenURL:     "http://localhost/token",
		RedirectURL:  "http://localhost/callback",
		Enabled:      false,
	}

	p, err := NewGenericProvider(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = p.Exchange(context.Background(), "some-code")
	if !errors.Is(err, ErrProviderDisabled) {
		t.Fatalf("expected ErrProviderDisabled, got %v", err)
	}
}

func TestGenericProvider_UpdateConfig(t *testing.T) {
	p := newTestProvider(t)

	newCfg := Config{
		Name:         "UpdatedProvider",
		Type:         ProviderTypeGeneric,
		ClientID:     "new-client-id",
		ClientSecret: "new-secret",
		AuthURL:      "http://new/auth",
		TokenURL:     "http://new/token",
		RedirectURL:  "http://new/callback",
		Enabled:      false,
	}

	if err := p.UpdateConfig(newCfg); err != nil {
		t.Fatalf("failed to update config: %v", err)
	}

	if p.GetName() != "UpdatedProvider" {
		t.Fatalf("expected UpdatedProvider, got %s", p.GetName())
	}
	if p.IsEnabled() {
		t.Fatal("expected disabled after update")
	}
}

func TestGenericProvider_UpdateConfig_Invalid(t *testing.T) {
	p := newTestProvider(t)

	invalidCfg := Config{
		Name: "Invalid",
		// Missing required fields
	}

	if err := p.UpdateConfig(invalidCfg); err == nil {
		t.Fatal("expected error for invalid config update")
	}

	// Original config should be preserved
	if p.GetName() != "TestProvider" {
		t.Fatalf("config should not have changed, got name %s", p.GetName())
	}
}

func TestNewGenericProvider_NilLogger(t *testing.T) {
	cfg := Config{
		Name:         "Test",
		Type:         ProviderTypeGeneric,
		ClientID:     "id",
		ClientSecret: "secret",
		AuthURL:      "http://localhost/auth",
		TokenURL:     "http://localhost/token",
		RedirectURL:  "http://localhost/callback",
	}

	p, err := NewGenericProvider(cfg, nil)
	if err != nil {
		t.Fatalf("should handle nil logger: %v", err)
	}
	if p == nil {
		t.Fatal("provider should not be nil")
	}
}

func TestNewGenericProvider_InvalidConfig(t *testing.T) {
	_, err := NewGenericProvider(Config{}, nil)
	if err == nil {
		t.Fatal("expected error for empty config")
	}
}

// ============================================================================
// determineRole Tests
// ============================================================================

func TestGenericProvider_DetermineRole_Admin(t *testing.T) {
	cfg := Config{
		Name:          "Test",
		Type:          ProviderTypeGeneric,
		ClientID:      "id",
		ClientSecret:  "secret",
		AuthURL:       "http://localhost/auth",
		TokenURL:      "http://localhost/token",
		RedirectURL:   "http://localhost/callback",
		AdminGroup:    "admins",
		OperatorGroup: "operators",
		DefaultRole:   models.RoleViewer,
	}

	p, err := NewGenericProvider(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	role := p.determineRole([]string{"users", "admins"})
	if role != models.RoleAdmin {
		t.Fatalf("expected admin, got %s", role)
	}
}

func TestGenericProvider_DetermineRole_Operator(t *testing.T) {
	cfg := Config{
		Name:          "Test",
		Type:          ProviderTypeGeneric,
		ClientID:      "id",
		ClientSecret:  "secret",
		AuthURL:       "http://localhost/auth",
		TokenURL:      "http://localhost/token",
		RedirectURL:   "http://localhost/callback",
		AdminGroup:    "admins",
		OperatorGroup: "operators",
		DefaultRole:   models.RoleViewer,
	}

	p, err := NewGenericProvider(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	role := p.determineRole([]string{"users", "operators"})
	if role != models.RoleOperator {
		t.Fatalf("expected operator, got %s", role)
	}
}

func TestGenericProvider_DetermineRole_Default(t *testing.T) {
	cfg := Config{
		Name:          "Test",
		Type:          ProviderTypeGeneric,
		ClientID:      "id",
		ClientSecret:  "secret",
		AuthURL:       "http://localhost/auth",
		TokenURL:      "http://localhost/token",
		RedirectURL:   "http://localhost/callback",
		AdminGroup:    "admins",
		OperatorGroup: "operators",
		DefaultRole:   models.RoleViewer,
	}

	p, err := NewGenericProvider(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	role := p.determineRole([]string{"users", "developers"})
	if role != models.RoleViewer {
		t.Fatalf("expected viewer, got %s", role)
	}
}

func TestGenericProvider_DetermineRole_CaseInsensitive(t *testing.T) {
	cfg := Config{
		Name:          "Test",
		Type:          ProviderTypeGeneric,
		ClientID:      "id",
		ClientSecret:  "secret",
		AuthURL:       "http://localhost/auth",
		TokenURL:      "http://localhost/token",
		RedirectURL:   "http://localhost/callback",
		AdminGroup:    "Admins",
		OperatorGroup: "Operators",
		DefaultRole:   models.RoleViewer,
	}

	p, err := NewGenericProvider(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	role := p.determineRole([]string{"ADMINS"})
	if role != models.RoleAdmin {
		t.Fatalf("expected admin (case-insensitive), got %s", role)
	}
}

func TestGenericProvider_DetermineRole_AdminTakesPriority(t *testing.T) {
	cfg := Config{
		Name:          "Test",
		Type:          ProviderTypeGeneric,
		ClientID:      "id",
		ClientSecret:  "secret",
		AuthURL:       "http://localhost/auth",
		TokenURL:      "http://localhost/token",
		RedirectURL:   "http://localhost/callback",
		AdminGroup:    "admins",
		OperatorGroup: "operators",
		DefaultRole:   models.RoleViewer,
	}

	p, err := NewGenericProvider(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	role := p.determineRole([]string{"operators", "admins"})
	if role != models.RoleAdmin {
		t.Fatalf("expected admin to take priority, got %s", role)
	}
}

func TestGenericProvider_DetermineRole_NoGroups(t *testing.T) {
	cfg := Config{
		Name:         "Test",
		Type:         ProviderTypeGeneric,
		ClientID:     "id",
		ClientSecret: "secret",
		AuthURL:      "http://localhost/auth",
		TokenURL:     "http://localhost/token",
		RedirectURL:  "http://localhost/callback",
		AdminGroup:   "admins",
		DefaultRole:  models.RoleViewer,
	}

	p, err := NewGenericProvider(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	role := p.determineRole(nil)
	if role != models.RoleViewer {
		t.Fatalf("expected viewer for nil groups, got %s", role)
	}
}

// ============================================================================
// parseUserInfo Tests
// ============================================================================

func TestGenericProvider_ParseUserInfo_Complete(t *testing.T) {
	p := newTestProvider(t)
	p.config.GroupsClaim = "groups"
	p.config.AdminGroup = "admins"

	data := map[string]interface{}{
		"sub":                "user-123",
		"preferred_username": "jdoe",
		"email":              "jdoe@example.com",
		"name":               "John Doe",
		"groups":             []interface{}{"users", "admins"},
	}

	user, err := p.parseUserInfo(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.ID != "user-123" {
		t.Fatalf("expected ID user-123, got %s", user.ID)
	}
	if user.Username != "jdoe" {
		t.Fatalf("expected username jdoe, got %s", user.Username)
	}
	if user.Email != "jdoe@example.com" {
		t.Fatalf("expected email jdoe@example.com, got %s", user.Email)
	}
	if user.Name != "John Doe" {
		t.Fatalf("expected name John Doe, got %s", user.Name)
	}
	if user.Provider != "TestProvider" {
		t.Fatalf("expected provider TestProvider, got %s", user.Provider)
	}
	if user.Role != models.RoleAdmin {
		t.Fatalf("expected admin role, got %s", user.Role)
	}
	if len(user.Groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(user.Groups))
	}
}

func TestGenericProvider_ParseUserInfo_MissingUserID(t *testing.T) {
	p := newTestProvider(t)

	data := map[string]interface{}{
		"preferred_username": "jdoe",
	}

	_, err := p.parseUserInfo(data)
	if !errors.Is(err, ErrMissingUserID) {
		t.Fatalf("expected ErrMissingUserID, got %v", err)
	}
}

func TestGenericProvider_ParseUserInfo_FallbackUsernameToEmail(t *testing.T) {
	p := newTestProvider(t)

	data := map[string]interface{}{
		"sub":   "user-123",
		"email": "jdoe@example.com",
	}

	user, err := p.parseUserInfo(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should use email prefix as username
	if user.Username != "jdoe" {
		t.Fatalf("expected username jdoe (from email), got %s", user.Username)
	}
}

func TestGenericProvider_ParseUserInfo_FallbackUsernameToID(t *testing.T) {
	p := newTestProvider(t)

	data := map[string]interface{}{
		"sub": "user-123",
	}

	user, err := p.parseUserInfo(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.Username != "user-123" {
		t.Fatalf("expected username user-123 (from ID), got %s", user.Username)
	}
}

func TestGenericProvider_ParseUserInfo_NumericID(t *testing.T) {
	p := newTestProvider(t)

	data := map[string]interface{}{
		"sub":                float64(12345),
		"preferred_username": "jdoe",
	}

	user, err := p.parseUserInfo(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.ID != "12345" {
		t.Fatalf("expected ID 12345, got %s", user.ID)
	}
}

func TestGenericProvider_ParseUserInfo_NoGroupsClaim(t *testing.T) {
	p := newTestProvider(t)
	p.config.GroupsClaim = "" // No groups claim configured

	data := map[string]interface{}{
		"sub":                "user-123",
		"preferred_username": "jdoe",
	}

	user, err := p.parseUserInfo(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.Groups != nil {
		t.Fatalf("expected nil groups when no claim configured, got %v", user.Groups)
	}
}

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestGetStringClaim_String(t *testing.T) {
	data := map[string]interface{}{"name": "test"}
	if v := getStringClaim(data, "name"); v != "test" {
		t.Fatalf("expected test, got %s", v)
	}
}

func TestGetStringClaim_Float64(t *testing.T) {
	data := map[string]interface{}{"id": float64(12345)}
	if v := getStringClaim(data, "id"); v != "12345" {
		t.Fatalf("expected 12345, got %s", v)
	}
}

func TestGetStringClaim_Int(t *testing.T) {
	data := map[string]interface{}{"id": int(42)}
	if v := getStringClaim(data, "id"); v != "42" {
		t.Fatalf("expected 42, got %s", v)
	}
}

func TestGetStringClaim_Int64(t *testing.T) {
	data := map[string]interface{}{"id": int64(999)}
	if v := getStringClaim(data, "id"); v != "999" {
		t.Fatalf("expected 999, got %s", v)
	}
}

func TestGetStringClaim_Missing(t *testing.T) {
	data := map[string]interface{}{"name": "test"}
	if v := getStringClaim(data, "missing"); v != "" {
		t.Fatalf("expected empty string, got %s", v)
	}
}

func TestGetStringClaim_UnsupportedType(t *testing.T) {
	data := map[string]interface{}{"flag": true}
	if v := getStringClaim(data, "flag"); v != "" {
		t.Fatalf("expected empty for bool, got %s", v)
	}
}

func TestGetStringSliceClaim_InterfaceSlice(t *testing.T) {
	data := map[string]interface{}{
		"groups": []interface{}{"admin", "users"},
	}

	result := getStringSliceClaim(data, "groups")
	if len(result) != 2 || result[0] != "admin" || result[1] != "users" {
		t.Fatalf("unexpected result: %v", result)
	}
}

func TestGetStringSliceClaim_StringSlice(t *testing.T) {
	data := map[string]interface{}{
		"groups": []string{"admin", "users"},
	}

	result := getStringSliceClaim(data, "groups")
	if len(result) != 2 || result[0] != "admin" || result[1] != "users" {
		t.Fatalf("unexpected result: %v", result)
	}
}

func TestGetStringSliceClaim_Missing(t *testing.T) {
	data := map[string]interface{}{}
	result := getStringSliceClaim(data, "groups")
	if result != nil {
		t.Fatalf("expected nil, got %v", result)
	}
}

func TestGetStringSliceClaim_NonStringItems(t *testing.T) {
	data := map[string]interface{}{
		"groups": []interface{}{"admin", 123, "users"},
	}

	result := getStringSliceClaim(data, "groups")
	// Should skip non-string items
	if len(result) != 2 || result[0] != "admin" || result[1] != "users" {
		t.Fatalf("expected 2 string items, got %v", result)
	}
}

// ============================================================================
// NewGitHubProvider Tests
// ============================================================================

func TestNewGitHubProvider(t *testing.T) {
	p, err := NewGitHubProvider("gh-id", "gh-secret", "http://localhost/callback", nil)
	if err != nil {
		t.Fatalf("failed to create GitHub provider: %v", err)
	}

	if p.GetName() != "GitHub" {
		t.Fatalf("expected name GitHub, got %s", p.GetName())
	}
	if !p.IsEnabled() {
		t.Fatal("GitHub provider should be enabled by default")
	}
}

// ============================================================================
// Registry Tests
// ============================================================================

// mockProvider implements the Provider interface for testing.
type mockProvider struct {
	name    string
	enabled bool
}

func (m *mockProvider) GetName() string                                     { return m.name }
func (m *mockProvider) IsEnabled() bool                                     { return m.enabled }
func (m *mockProvider) GetAuthURL(state string) string                      { return "http://mock/auth?state=" + state }
func (m *mockProvider) Exchange(_ context.Context, _ string) (*User, error) { return nil, nil }

func TestRegistry_RegisterAndGet(t *testing.T) {
	reg := NewRegistry(nil)

	mock := &mockProvider{name: "test", enabled: true}
	reg.Register("test", mock)

	p, err := reg.Get("test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.GetName() != "test" {
		t.Fatalf("expected name test, got %s", p.GetName())
	}
}

func TestRegistry_Get_NotFound(t *testing.T) {
	reg := NewRegistry(nil)

	_, err := reg.Get("nonexistent")
	if !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("expected ErrProviderNotFound, got %v", err)
	}
}

func TestRegistry_Get_CaseInsensitive(t *testing.T) {
	reg := NewRegistry(nil)

	mock := &mockProvider{name: "GitHub", enabled: true}
	reg.Register("GitHub", mock)

	p, err := reg.Get("github")
	if err != nil {
		t.Fatalf("expected case-insensitive lookup: %v", err)
	}
	if p.GetName() != "GitHub" {
		t.Fatalf("expected name GitHub, got %s", p.GetName())
	}
}

func TestRegistry_List(t *testing.T) {
	reg := NewRegistry(nil)

	reg.Register("a", &mockProvider{name: "a", enabled: true})
	reg.Register("b", &mockProvider{name: "b", enabled: false})
	reg.Register("c", &mockProvider{name: "c", enabled: true})

	providers := reg.List()
	if len(providers) != 3 {
		t.Fatalf("expected 3 providers, got %d", len(providers))
	}
}

func TestRegistry_ListEnabled(t *testing.T) {
	reg := NewRegistry(nil)

	reg.Register("a", &mockProvider{name: "a", enabled: true})
	reg.Register("b", &mockProvider{name: "b", enabled: false})
	reg.Register("c", &mockProvider{name: "c", enabled: true})

	enabled := reg.ListEnabled()
	if len(enabled) != 2 {
		t.Fatalf("expected 2 enabled providers, got %d", len(enabled))
	}
}

func TestRegistry_Remove(t *testing.T) {
	reg := NewRegistry(nil)

	reg.Register("test", &mockProvider{name: "test", enabled: true})

	// Verify it exists
	_, err := reg.Get("test")
	if err != nil {
		t.Fatalf("provider should exist: %v", err)
	}

	// Remove it
	reg.Remove("test")

	// Verify it's gone
	_, err = reg.Get("test")
	if !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("expected ErrProviderNotFound after removal, got %v", err)
	}
}

func TestRegistry_Remove_CaseInsensitive(t *testing.T) {
	reg := NewRegistry(nil)

	reg.Register("GitHub", &mockProvider{name: "GitHub"})
	reg.Remove("github")

	_, err := reg.Get("github")
	if !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("expected removal via case-insensitive name")
	}
}

func TestRegistry_Overwrite(t *testing.T) {
	reg := NewRegistry(nil)

	reg.Register("test", &mockProvider{name: "v1", enabled: false})
	reg.Register("test", &mockProvider{name: "v2", enabled: true})

	p, err := reg.Get("test")
	if err != nil {
		t.Fatal(err)
	}

	if p.GetName() != "v2" {
		t.Fatalf("expected overwritten provider v2, got %s", p.GetName())
	}
}

func TestRegistry_Empty(t *testing.T) {
	reg := NewRegistry(nil)

	if providers := reg.List(); len(providers) != 0 {
		t.Fatalf("expected empty list, got %d", len(providers))
	}
	if enabled := reg.ListEnabled(); len(enabled) != 0 {
		t.Fatalf("expected empty enabled list, got %d", len(enabled))
	}
}

// ============================================================================
// Error Sentinel Tests
// ============================================================================

func TestErrorSentinels(t *testing.T) {
	errors := []error{
		ErrProviderDisabled,
		ErrInvalidCode,
		ErrTokenExchange,
		ErrUserInfoFetch,
		ErrInvalidToken,
		ErrMissingUserID,
		ErrMissingUsername,
		ErrProviderNotFound,
		ErrInvalidConfig,
	}

	for _, e := range errors {
		if e == nil {
			t.Fatal("sentinel error should not be nil")
		}
		if e.Error() == "" {
			t.Fatal("sentinel error message should not be empty")
		}
	}
}
