// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

const testSecret = "test-secret-key-at-least-32-chars-long"

func newTestJWTService() *JWTService {
	return NewJWTService(DefaultJWTConfig(testSecret))
}

func testUser() *models.User {
	email := "test@example.com"
	return &models.User{
		ID:       uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		Username: "testuser",
		Email:    &email,
		Role:     models.RoleAdmin,
		IsActive: true,
	}
}

// ============================================================================
// Constructor tests
// ============================================================================

func TestNewJWTService_EmptySecret_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for empty secret, got nil")
		}
	}()
	NewJWTService(JWTConfig{Secret: ""})
}

func TestNewJWTService_Defaults(t *testing.T) {
	svc := NewJWTService(JWTConfig{Secret: testSecret})
	if svc.config.Issuer != "usulnet" {
		t.Errorf("expected issuer 'usulnet', got %q", svc.config.Issuer)
	}
	if svc.config.AccessTokenTTL != 15*time.Minute {
		t.Errorf("expected access TTL 15m, got %v", svc.config.AccessTokenTTL)
	}
	if svc.config.RefreshTokenTTL != 7*24*time.Hour {
		t.Errorf("expected refresh TTL 7d, got %v", svc.config.RefreshTokenTTL)
	}
	if svc.config.RefreshSecret != testSecret {
		t.Error("expected RefreshSecret to default to Secret")
	}
	if svc.config.TokenIDGenerator == nil {
		t.Error("expected default TokenIDGenerator")
	}
}

func TestDefaultJWTConfig(t *testing.T) {
	cfg := DefaultJWTConfig("my-secret")
	if cfg.Secret != "my-secret" {
		t.Errorf("expected secret 'my-secret', got %q", cfg.Secret)
	}
	if cfg.RefreshSecret != "my-secret" {
		t.Errorf("expected refresh secret 'my-secret', got %q", cfg.RefreshSecret)
	}
	if cfg.Issuer != "usulnet" {
		t.Errorf("expected issuer 'usulnet', got %q", cfg.Issuer)
	}
}

// ============================================================================
// Access token round-trip
// ============================================================================

func TestGenerateAndValidateAccessToken(t *testing.T) {
	svc := newTestJWTService()
	user := testUser()

	tokenStr, expiresAt, err := svc.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("expected non-empty token")
	}
	if expiresAt.Before(time.Now()) {
		t.Error("expected expiry in the future")
	}

	claims, err := svc.ValidateAccessToken(tokenStr)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.UserID != user.ID.String() {
		t.Errorf("expected user ID %s, got %s", user.ID, claims.UserID)
	}
	if claims.Username != user.Username {
		t.Errorf("expected username %q, got %q", user.Username, claims.Username)
	}
	if claims.Email != *user.Email {
		t.Errorf("expected email %q, got %q", *user.Email, claims.Email)
	}
	if claims.Role != user.Role {
		t.Errorf("expected role %q, got %q", user.Role, claims.Role)
	}
	if claims.Type != TokenTypeAccess {
		t.Errorf("expected type %q, got %q", TokenTypeAccess, claims.Type)
	}
	if claims.Issuer != "usulnet" {
		t.Errorf("expected issuer 'usulnet', got %q", claims.Issuer)
	}
	if claims.ID == "" {
		t.Error("expected non-empty JTI")
	}
}

func TestGenerateAccessToken_NilEmail(t *testing.T) {
	svc := newTestJWTService()
	user := testUser()
	user.Email = nil

	tokenStr, _, err := svc.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	claims, err := svc.ValidateAccessToken(tokenStr)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.Email != "" {
		t.Errorf("expected empty email for nil user.Email, got %q", claims.Email)
	}
}

// ============================================================================
// Refresh token round-trip
// ============================================================================

func TestGenerateAndValidateRefreshToken(t *testing.T) {
	svc := newTestJWTService()
	userID := uuid.New()
	sessionID := uuid.New()

	tokenStr, expiresAt, err := svc.GenerateRefreshToken(userID, sessionID)
	if err != nil {
		t.Fatalf("GenerateRefreshToken: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("expected non-empty token")
	}
	if expiresAt.Before(time.Now()) {
		t.Error("expected expiry in the future")
	}

	claims, err := svc.ValidateRefreshToken(tokenStr)
	if err != nil {
		t.Fatalf("ValidateRefreshToken: %v", err)
	}
	if claims.UserID != userID.String() {
		t.Errorf("expected user ID %s, got %s", userID, claims.UserID)
	}
	if claims.SessionID != sessionID.String() {
		t.Errorf("expected session ID %s, got %s", sessionID, claims.SessionID)
	}
	if claims.Type != TokenTypeRefresh {
		t.Errorf("expected type %q, got %q", TokenTypeRefresh, claims.Type)
	}
}

// ============================================================================
// Token pair
// ============================================================================

func TestGenerateTokenPair(t *testing.T) {
	svc := newTestJWTService()
	user := testUser()
	sessionID := uuid.New()

	pair, err := svc.GenerateTokenPair(user, sessionID)
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}
	if pair.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
	if pair.RefreshToken == "" {
		t.Error("expected non-empty refresh token")
	}
	if pair.TokenType != "Bearer" {
		t.Errorf("expected token type 'Bearer', got %q", pair.TokenType)
	}
	if pair.AccessTokenExpiresAt.After(pair.RefreshTokenExpiresAt) {
		t.Error("access token should expire before refresh token")
	}

	// Validate access token
	accessClaims, err := svc.ValidateAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken from pair: %v", err)
	}
	if accessClaims.UserID != user.ID.String() {
		t.Errorf("access token user ID: expected %s, got %s", user.ID, accessClaims.UserID)
	}

	// Validate refresh token
	refreshClaims, err := svc.ValidateRefreshToken(pair.RefreshToken)
	if err != nil {
		t.Fatalf("ValidateRefreshToken from pair: %v", err)
	}
	if refreshClaims.UserID != user.ID.String() {
		t.Errorf("refresh token user ID: expected %s, got %s", user.ID, refreshClaims.UserID)
	}
	if refreshClaims.SessionID != sessionID.String() {
		t.Errorf("refresh token session ID: expected %s, got %s", sessionID, refreshClaims.SessionID)
	}
}

// ============================================================================
// Cross-validation (token type mismatch)
// ============================================================================

func TestValidateAccessToken_WithRefreshToken_Fails(t *testing.T) {
	svc := newTestJWTService()
	userID := uuid.New()
	sessionID := uuid.New()

	refreshToken, _, err := svc.GenerateRefreshToken(userID, sessionID)
	if err != nil {
		t.Fatalf("GenerateRefreshToken: %v", err)
	}

	_, err = svc.ValidateAccessToken(refreshToken)
	if err == nil {
		t.Fatal("expected error validating refresh token as access token")
	}
}

func TestValidateRefreshToken_WithAccessToken_Fails(t *testing.T) {
	svc := newTestJWTService()
	user := testUser()

	accessToken, _, err := svc.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}

	_, err = svc.ValidateRefreshToken(accessToken)
	if err == nil {
		t.Fatal("expected error validating access token as refresh token")
	}
}

// ============================================================================
// Wrong secret
// ============================================================================

func TestValidateAccessToken_WrongSecret(t *testing.T) {
	svc1 := NewJWTService(DefaultJWTConfig("secret-one-at-least-32-chars-long"))
	svc2 := NewJWTService(DefaultJWTConfig("secret-two-at-least-32-chars-long"))
	user := testUser()

	tokenStr, _, err := svc1.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}

	_, err = svc2.ValidateAccessToken(tokenStr)
	if err == nil {
		t.Fatal("expected error for wrong secret")
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestValidateRefreshToken_WrongSecret(t *testing.T) {
	svc1 := NewJWTService(DefaultJWTConfig("secret-one-at-least-32-chars-long"))
	svc2 := NewJWTService(JWTConfig{
		Secret:        "secret-two-at-least-32-chars-long",
		RefreshSecret: "different-refresh-secret-long-enough",
	})
	userID := uuid.New()
	sessionID := uuid.New()

	tokenStr, _, err := svc1.GenerateRefreshToken(userID, sessionID)
	if err != nil {
		t.Fatalf("GenerateRefreshToken: %v", err)
	}

	_, err = svc2.ValidateRefreshToken(tokenStr)
	if err == nil {
		t.Fatal("expected error for wrong refresh secret")
	}
}

// ============================================================================
// Expired token
// ============================================================================

func TestValidateAccessToken_Expired(t *testing.T) {
	svc := newTestJWTService()
	user := testUser()

	// Generate token with TTL already in the past
	tokenStr, _, err := svc.GenerateAccessTokenWithTTL(user, -1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateAccessTokenWithTTL: %v", err)
	}

	_, err = svc.ValidateAccessToken(tokenStr)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if !errors.Is(err, ErrExpiredToken) {
		t.Errorf("expected ErrExpiredToken, got %v", err)
	}
}

// ============================================================================
// Garbage token
// ============================================================================

func TestValidateAccessToken_InvalidString(t *testing.T) {
	svc := newTestJWTService()

	tests := []struct {
		name  string
		token string
	}{
		{"empty string", ""},
		{"random text", "not-a-jwt-token"},
		{"almost JWT", "aaa.bbb.ccc"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.ValidateAccessToken(tc.token)
			if err == nil {
				t.Fatal("expected error for invalid token")
			}
		})
	}
}

// ============================================================================
// Custom TTL
// ============================================================================

func TestGenerateAccessTokenWithTTL(t *testing.T) {
	svc := newTestJWTService()
	user := testUser()
	customTTL := 1 * time.Hour

	tokenStr, expiresAt, err := svc.GenerateAccessTokenWithTTL(user, customTTL)
	if err != nil {
		t.Fatalf("GenerateAccessTokenWithTTL: %v", err)
	}

	// Expiry should be approximately 1 hour from now (within 5 seconds)
	expected := time.Now().Add(customTTL)
	diff := expiresAt.Sub(expected)
	if diff < -5*time.Second || diff > 5*time.Second {
		t.Errorf("expected expiry ~%v, got %v (diff: %v)", expected, expiresAt, diff)
	}

	// Token should validate
	claims, err := svc.ValidateAccessToken(tokenStr)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.UserID != user.ID.String() {
		t.Errorf("expected user ID %s, got %s", user.ID, claims.UserID)
	}
}

// ============================================================================
// ParseUnverified
// ============================================================================

func TestParseUnverified(t *testing.T) {
	svc := newTestJWTService()
	user := testUser()

	tokenStr, _, err := svc.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}

	claims, err := svc.ParseUnverified(tokenStr)
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if claims.UserID != user.ID.String() {
		t.Errorf("expected user ID %s, got %s", user.ID, claims.UserID)
	}
}

func TestParseUnverified_ExpiredToken(t *testing.T) {
	svc := newTestJWTService()
	user := testUser()

	tokenStr, _, err := svc.GenerateAccessTokenWithTTL(user, -1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateAccessTokenWithTTL: %v", err)
	}

	// ParseUnverified should succeed even on expired tokens
	claims, err := svc.ParseUnverified(tokenStr)
	if err != nil {
		t.Fatalf("ParseUnverified on expired: %v", err)
	}
	if claims.UserID != user.ID.String() {
		t.Errorf("expected user ID %s, got %s", user.ID, claims.UserID)
	}
}

// ============================================================================
// Token utilities
// ============================================================================

func TestGetTokenID(t *testing.T) {
	svc := newTestJWTService()
	user := testUser()

	tokenStr, _, err := svc.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}

	jti, err := svc.GetTokenID(tokenStr)
	if err != nil {
		t.Fatalf("GetTokenID: %v", err)
	}
	if jti == "" {
		t.Error("expected non-empty JTI")
	}
	// JTI should be a valid UUID
	if _, err := uuid.Parse(jti); err != nil {
		t.Errorf("expected JTI to be a UUID, got %q: %v", jti, err)
	}
}

func TestGetExpirationTime(t *testing.T) {
	svc := newTestJWTService()
	user := testUser()

	tokenStr, expectedExp, err := svc.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}

	exp, err := svc.GetExpirationTime(tokenStr)
	if err != nil {
		t.Fatalf("GetExpirationTime: %v", err)
	}
	// Should match within 1 second
	diff := exp.Sub(expectedExp)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("expiry mismatch: expected %v, got %v", expectedExp, exp)
	}
}

func TestIsExpired(t *testing.T) {
	svc := newTestJWTService()
	user := testUser()

	// Valid token
	validToken, _, err := svc.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	if svc.IsExpired(validToken) {
		t.Error("expected valid token to not be expired")
	}

	// Expired token
	expiredToken, _, err := svc.GenerateAccessTokenWithTTL(user, -1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateAccessTokenWithTTL: %v", err)
	}
	if !svc.IsExpired(expiredToken) {
		t.Error("expected expired token to be expired")
	}

	// Garbage token
	if !svc.IsExpired("not-a-token") {
		t.Error("expected garbage token to be treated as expired")
	}
}

func TestGetUserIDFromToken(t *testing.T) {
	svc := newTestJWTService()
	user := testUser()

	tokenStr, _, err := svc.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}

	userID, err := svc.GetUserIDFromToken(tokenStr)
	if err != nil {
		t.Fatalf("GetUserIDFromToken: %v", err)
	}
	if userID != user.ID {
		t.Errorf("expected user ID %s, got %s", user.ID, userID)
	}
}

// ============================================================================
// TTL configuration
// ============================================================================

func TestSetAccessTokenTTL(t *testing.T) {
	svc := newTestJWTService()
	newTTL := 30 * time.Minute
	svc.SetAccessTokenTTL(newTTL)
	if svc.GetAccessTokenTTL() != newTTL {
		t.Errorf("expected access TTL %v, got %v", newTTL, svc.GetAccessTokenTTL())
	}
}

func TestSetRefreshTokenTTL(t *testing.T) {
	svc := newTestJWTService()
	newTTL := 14 * 24 * time.Hour
	svc.SetRefreshTokenTTL(newTTL)
	if svc.GetRefreshTokenTTL() != newTTL {
		t.Errorf("expected refresh TTL %v, got %v", newTTL, svc.GetRefreshTokenTTL())
	}
}

// ============================================================================
// Separate refresh secret
// ============================================================================

func TestSeparateRefreshSecret(t *testing.T) {
	cfg := JWTConfig{
		Secret:        "access-secret-at-least-32-chars-long",
		RefreshSecret: "refresh-secret-at-least-32-chars-long",
	}
	svc := NewJWTService(cfg)
	user := testUser()
	userID := user.ID
	sessionID := uuid.New()

	// Access token uses Secret
	accessToken, _, err := svc.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	_, err = svc.ValidateAccessToken(accessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}

	// Refresh token uses RefreshSecret
	refreshToken, _, err := svc.GenerateRefreshToken(userID, sessionID)
	if err != nil {
		t.Fatalf("GenerateRefreshToken: %v", err)
	}
	_, err = svc.ValidateRefreshToken(refreshToken)
	if err != nil {
		t.Fatalf("ValidateRefreshToken: %v", err)
	}
}

// ============================================================================
// Token uniqueness
// ============================================================================

func TestTokensAreUnique(t *testing.T) {
	svc := newTestJWTService()
	user := testUser()

	token1, _, err := svc.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("GenerateAccessToken (1): %v", err)
	}
	token2, _, err := svc.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("GenerateAccessToken (2): %v", err)
	}
	if token1 == token2 {
		t.Error("expected different tokens for subsequent calls")
	}

	jti1, _ := svc.GetTokenID(token1)
	jti2, _ := svc.GetTokenID(token2)
	if jti1 == jti2 {
		t.Error("expected different JTIs for subsequent tokens")
	}
}

// ============================================================================
// Secure token generation
// ============================================================================

func TestGenerateSecureToken(t *testing.T) {
	token1, err := GenerateSecureToken(32)
	if err != nil {
		t.Fatalf("GenerateSecureToken: %v", err)
	}
	if token1 == "" {
		t.Fatal("expected non-empty token")
	}

	token2, err := GenerateSecureToken(32)
	if err != nil {
		t.Fatalf("GenerateSecureToken: %v", err)
	}
	if token1 == token2 {
		t.Error("expected different secure tokens")
	}
}

func TestGenerateSecureToken_DefaultLength(t *testing.T) {
	token, err := GenerateSecureToken(0)
	if err != nil {
		t.Fatalf("GenerateSecureToken(0): %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token for length=0")
	}
}

func TestGenerateRefreshTokenRaw(t *testing.T) {
	token, err := GenerateRefreshTokenRaw()
	if err != nil {
		t.Fatalf("GenerateRefreshTokenRaw: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty raw refresh token")
	}
}

// ============================================================================
// Custom TokenIDGenerator
// ============================================================================

func TestCustomTokenIDGenerator(t *testing.T) {
	callCount := 0
	cfg := JWTConfig{
		Secret: testSecret,
		TokenIDGenerator: func() string {
			callCount++
			return "custom-id-" + strings.Repeat("0", callCount)
		},
	}
	svc := NewJWTService(cfg)
	user := testUser()

	tokenStr, _, err := svc.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}

	claims, err := svc.ParseUnverified(tokenStr)
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if claims.ID != "custom-id-0" {
		t.Errorf("expected custom JTI 'custom-id-0', got %q", claims.ID)
	}
	if callCount != 1 {
		t.Errorf("expected TokenIDGenerator called once, got %d", callCount)
	}
}

// ============================================================================
// mapJWTError (tested through public methods)
// ============================================================================

func TestMapJWTError_ExpiredToken(t *testing.T) {
	svc := newTestJWTService()
	user := testUser()

	token, _, _ := svc.GenerateAccessTokenWithTTL(user, -1*time.Hour)
	_, err := svc.ValidateAccessToken(token)
	if !errors.Is(err, ErrExpiredToken) {
		t.Errorf("expected ErrExpiredToken, got %v", err)
	}
}

func TestMapJWTError_InvalidSignature(t *testing.T) {
	svc1 := NewJWTService(DefaultJWTConfig("key-one-at-least-32-characters-x"))
	svc2 := NewJWTService(DefaultJWTConfig("key-two-at-least-32-characters-y"))
	user := testUser()

	token, _, _ := svc1.GenerateAccessToken(user)
	_, err := svc2.ValidateAccessToken(token)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}
