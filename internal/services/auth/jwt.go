// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package auth provides authentication services for the application.
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// JWT errors
var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrExpiredToken     = errors.New("token has expired")
	ErrInvalidClaims    = errors.New("invalid token claims")
	ErrInvalidSignature = errors.New("invalid token signature")
	ErrTokenNotYetValid = errors.New("token not yet valid")
)

// TokenType represents the type of JWT token.
type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)

// JWTConfig contains configuration for JWT service.
type JWTConfig struct {
	// Secret is the signing key for access tokens (required)
	Secret string

	// RefreshSecret is the signing key for refresh tokens (defaults to Secret if empty)
	RefreshSecret string

	// Issuer is the token issuer claim
	Issuer string

	// AccessTokenTTL is the access token lifetime (default: 15 minutes)
	AccessTokenTTL time.Duration

	// RefreshTokenTTL is the refresh token lifetime (default: 7 days)
	RefreshTokenTTL time.Duration

	// TokenIDGenerator generates unique token IDs (default: UUID)
	TokenIDGenerator func() string
}

// DefaultJWTConfig returns default JWT configuration.
func DefaultJWTConfig(secret string) JWTConfig {
	return JWTConfig{
		Secret:          secret,
		RefreshSecret:   secret,
		Issuer:          "usulnet",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		TokenIDGenerator: func() string {
			return uuid.New().String()
		},
	}
}

// Claims represents the JWT claims for access tokens.
type Claims struct {
	UserID   string          `json:"user_id"`
	Username string          `json:"username"`
	Email    string          `json:"email,omitempty"`
	Role     models.UserRole `json:"role"`
	Teams    []string        `json:"teams,omitempty"`
	Type     TokenType       `json:"type"`
	jwt.RegisteredClaims
}

// RefreshClaims represents the JWT claims for refresh tokens.
type RefreshClaims struct {
	UserID    string    `json:"user_id"`
	SessionID string    `json:"session_id"`
	Type      TokenType `json:"type"`
	jwt.RegisteredClaims
}

// JWTService handles JWT token generation and validation.
type JWTService struct {
	config JWTConfig
}

// NewJWTService creates a new JWT service.
func NewJWTService(config JWTConfig) *JWTService {
	if config.Secret == "" {
		panic("jwt: secret is required")
	}

	if config.RefreshSecret == "" {
		config.RefreshSecret = config.Secret
	}

	if config.Issuer == "" {
		config.Issuer = "usulnet"
	}

	if config.AccessTokenTTL == 0 {
		config.AccessTokenTTL = 15 * time.Minute
	}

	if config.RefreshTokenTTL == 0 {
		config.RefreshTokenTTL = 7 * 24 * time.Hour
	}

	if config.TokenIDGenerator == nil {
		config.TokenIDGenerator = func() string {
			return uuid.New().String()
		}
	}

	return &JWTService{config: config}
}

// ============================================================================
// Token Generation
// ============================================================================

// TokenPair contains an access token and refresh token.
type TokenPair struct {
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	TokenType             string    `json:"token_type"`
}

// GenerateTokenPair generates both access and refresh tokens for a user.
func (s *JWTService) GenerateTokenPair(user *models.User, sessionID uuid.UUID) (*TokenPair, error) {

	// Generate access token
	accessToken, accessExp, err := s.GenerateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, refreshExp, err := s.GenerateRefreshToken(user.ID, sessionID)
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  accessExp,
		RefreshTokenExpiresAt: refreshExp,
		TokenType:             "Bearer",
	}, nil
}

// GenerateAccessToken generates an access token for a user.
func (s *JWTService) GenerateAccessToken(user *models.User) (string, time.Time, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(s.config.AccessTokenTTL)

	claims := &Claims{
		UserID:   user.ID.String(),
		Username: user.Username,
		Role:     user.Role,
		Type:     TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        s.config.TokenIDGenerator(),
			Issuer:    s.config.Issuer,
			Subject:   user.ID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	if user.Email != nil {
		claims.Email = *user.Email
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(s.config.Secret))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign access token: %w", err)
	}

	return signedToken, expiresAt, nil
}

// GenerateRefreshToken generates a refresh token for a session.
func (s *JWTService) GenerateRefreshToken(userID, sessionID uuid.UUID) (string, time.Time, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(s.config.RefreshTokenTTL)

	claims := &RefreshClaims{
		UserID:    userID.String(),
		SessionID: sessionID.String(),
		Type:      TokenTypeRefresh,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        s.config.TokenIDGenerator(),
			Issuer:    s.config.Issuer,
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(s.config.RefreshSecret))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign refresh token: %w", err)
	}

	return signedToken, expiresAt, nil
}

// GenerateAccessTokenWithTTL generates an access token with custom TTL.
func (s *JWTService) GenerateAccessTokenWithTTL(user *models.User, ttl time.Duration) (string, time.Time, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)

	claims := &Claims{
		UserID:   user.ID.String(),
		Username: user.Username,
		Role:     user.Role,
		Type:     TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        s.config.TokenIDGenerator(),
			Issuer:    s.config.Issuer,
			Subject:   user.ID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	if user.Email != nil {
		claims.Email = *user.Email
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(s.config.Secret))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign access token: %w", err)
	}

	return signedToken, expiresAt, nil
}

// ============================================================================
// Token Validation
// ============================================================================

// ValidateAccessToken validates an access token and returns the claims.
func (s *JWTService) ValidateAccessToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.Secret), nil
	})

	if err != nil {
		return nil, s.mapJWTError(err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidClaims
	}

	// Verify token type
	if claims.Type != TokenTypeAccess {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// ValidateRefreshToken validates a refresh token and returns the claims.
func (s *JWTService) ValidateRefreshToken(tokenString string) (*RefreshClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.RefreshSecret), nil
	})

	if err != nil {
		return nil, s.mapJWTError(err)
	}

	claims, ok := token.Claims.(*RefreshClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidClaims
	}

	// Verify token type
	if claims.Type != TokenTypeRefresh {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// ParseUnverified parses a token without verifying the signature.
// Useful for extracting claims from expired tokens.
func (s *JWTService) ParseUnverified(tokenString string) (*Claims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, ErrInvalidClaims
	}

	return claims, nil
}

// mapJWTError maps jwt-go errors to our custom errors.
func (s *JWTService) mapJWTError(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return ErrExpiredToken
	case errors.Is(err, jwt.ErrSignatureInvalid):
		return ErrInvalidSignature
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return ErrTokenNotYetValid
	default:
		return ErrInvalidToken
	}
}

// ============================================================================
// Token Utilities
// ============================================================================

// GetTokenID extracts the JTI (token ID) from a token string without full validation.
func (s *JWTService) GetTokenID(tokenString string) (string, error) {
	claims, err := s.ParseUnverified(tokenString)
	if err != nil {
		return "", err
	}
	return claims.ID, nil
}

// GetExpirationTime extracts the expiration time from a token without full validation.
func (s *JWTService) GetExpirationTime(tokenString string) (time.Time, error) {
	claims, err := s.ParseUnverified(tokenString)
	if err != nil {
		return time.Time{}, err
	}
	if claims.ExpiresAt == nil {
		return time.Time{}, ErrInvalidClaims
	}
	return claims.ExpiresAt.Time, nil
}

// IsExpired checks if a token is expired without full validation.
func (s *JWTService) IsExpired(tokenString string) bool {
	exp, err := s.GetExpirationTime(tokenString)
	if err != nil {
		return true
	}
	return time.Now().After(exp)
}

// GetUserIDFromToken extracts the user ID from a token without full validation.
func (s *JWTService) GetUserIDFromToken(tokenString string) (uuid.UUID, error) {
	claims, err := s.ParseUnverified(tokenString)
	if err != nil {
		return uuid.Nil, err
	}
	return uuid.Parse(claims.UserID)
}

// ============================================================================
// Configuration Access
// ============================================================================

// GetAccessTokenTTL returns the access token TTL.
func (s *JWTService) GetAccessTokenTTL() time.Duration {
	return s.config.AccessTokenTTL
}

// GetRefreshTokenTTL returns the refresh token TTL.
func (s *JWTService) GetRefreshTokenTTL() time.Duration {
	return s.config.RefreshTokenTTL
}

// SetAccessTokenTTL updates the access token TTL.
func (s *JWTService) SetAccessTokenTTL(ttl time.Duration) {
	s.config.AccessTokenTTL = ttl
}

// SetRefreshTokenTTL updates the refresh token TTL.
func (s *JWTService) SetRefreshTokenTTL(ttl time.Duration) {
	s.config.RefreshTokenTTL = ttl
}

// ============================================================================
// Secure Token Generation (for refresh tokens stored in DB)
// ============================================================================

// GenerateSecureToken generates a cryptographically secure random token.
// Used for refresh tokens that are stored hashed in the database.
func GenerateSecureToken(length int) (string, error) {
	if length <= 0 {
		length = 32
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateRefreshTokenRaw generates a raw refresh token (not JWT).
// This is stored hashed in the database and used for session validation.
func GenerateRefreshTokenRaw() (string, error) {
	return GenerateSecureToken(32)
}
