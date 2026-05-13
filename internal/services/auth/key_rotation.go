// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// SigningKey represents a JWT signing key with metadata.
type SigningKey struct {
	ID          uuid.UUID  `json:"id"`
	KeyHash     string     `json:"key_hash"`
	Secret      string     `json:"-"` // never serialized
	Algorithm   string     `json:"algorithm"`
	Status      string     `json:"status"` // active, retired, revoked
	CreatedAt   time.Time  `json:"created_at"`
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

// SigningKeyRepository interface for persisting signing keys.
type SigningKeyRepository interface {
	Create(ctx context.Context, key *SigningKey, encryptedKey []byte) error
	GetActiveKeys(ctx context.Context) ([]*SigningKey, error)
	GetByID(ctx context.Context, id uuid.UUID) (*SigningKey, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status string, revokedAt *time.Time, revokedBy *uuid.UUID) error
	DeleteExpired(ctx context.Context) (int64, error)
}

// KeyRotationConfig holds configuration for JWT key rotation.
type KeyRotationConfig struct {
	// EncryptionKey is used to encrypt signing keys at rest in the database.
	EncryptionKey string

	// MaxActiveKeys is the maximum number of active keys to maintain (default: 2).
	MaxActiveKeys int

	// KeyRetentionPeriod is how long a retired key remains valid for token verification
	// after being replaced by a new key (default: 7 days).
	KeyRetentionPeriod time.Duration

	// RotationInterval is how often keys should be rotated (default: 7 days).
	// Used by the scheduler for automatic rotation.
	RotationInterval time.Duration

	// KeyLength is the length of generated signing keys in bytes (default: 64).
	KeyLength int
}

// DefaultKeyRotationConfig returns default key rotation configuration.
func DefaultKeyRotationConfig() *KeyRotationConfig {
	return &KeyRotationConfig{
		MaxActiveKeys:      2,
		KeyRetentionPeriod: 7 * 24 * time.Hour,
		RotationInterval:   7 * 24 * time.Hour,
		KeyLength:          64,
	}
}

// KeyRotationService manages JWT signing key rotation.
type KeyRotationService struct {
	config     *KeyRotationConfig
	repo       SigningKeyRepository
	logger     *logger.Logger
	jwtService *JWTService

	mu         sync.RWMutex
	signingKey *SigningKey   // current key used for signing
	validKeys  []*SigningKey // all keys valid for verification
}

// NewKeyRotationService creates a new key rotation service.
func NewKeyRotationService(
	config *KeyRotationConfig,
	repo SigningKeyRepository,
	jwtService *JWTService,
	log *logger.Logger,
) *KeyRotationService {
	if config == nil {
		config = DefaultKeyRotationConfig()
	}
	if config.MaxActiveKeys < 1 {
		config.MaxActiveKeys = 2
	}
	if config.KeyLength < 32 {
		config.KeyLength = 64
	}
	if config.KeyRetentionPeriod == 0 {
		config.KeyRetentionPeriod = 7 * 24 * time.Hour
	}

	return &KeyRotationService{
		config:     config,
		repo:       repo,
		jwtService: jwtService,
		logger:     log.Named("key-rotation"),
	}
}

// Initialize loads active keys from the database.
// If no keys exist, the current JWT secret from config is registered as the initial key.
func (s *KeyRotationService) Initialize(ctx context.Context) error {
	s.logger.Info("Initializing JWT key rotation service")

	keys, err := s.repo.GetActiveKeys(ctx)
	if err != nil {
		return fmt.Errorf("load active keys: %w", err)
	}

	if len(keys) == 0 {
		s.logger.Info("No signing keys found, registering initial key from configuration")
		if err := s.registerInitialKey(ctx); err != nil {
			return fmt.Errorf("register initial key: %w", err)
		}
		keys, err = s.repo.GetActiveKeys(ctx)
		if err != nil {
			return fmt.Errorf("reload keys after init: %w", err)
		}
	}

	// Decrypt keys and set up the signing/validation key sets
	if err := s.loadKeys(ctx, keys); err != nil {
		return fmt.Errorf("load keys: %w", err)
	}

	s.logger.Info("Key rotation service initialized",
		"active_keys", len(s.validKeys),
		"signing_key_id", s.signingKey.ID)

	return nil
}

// RotateKey generates a new signing key and retires the current one.
// The retired key remains valid for token verification until it expires.
func (s *KeyRotationService) RotateKey(ctx context.Context, rotatedBy *uuid.UUID) (*SigningKey, error) {
	s.logger.Info("Starting JWT key rotation")

	// Generate new key
	newSecret, err := generateSigningKey(s.config.KeyLength)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}

	keyHash := hashKey(newSecret)
	now := time.Now().UTC()
	expiresAt := now.Add(s.config.KeyRetentionPeriod + s.config.RotationInterval)

	newKey := &SigningKey{
		ID:          uuid.New(),
		KeyHash:     keyHash,
		Secret:      newSecret,
		Algorithm:   "HS256",
		Status:      "active",
		CreatedAt:   now,
		ActivatedAt: &now,
		ExpiresAt:   &expiresAt,
	}

	// Encrypt the key for storage
	encryptedKey, err := s.encryptKey(newSecret)
	if err != nil {
		return nil, fmt.Errorf("encrypt key: %w", err)
	}

	// Persist new key
	if err := s.repo.Create(ctx, newKey, encryptedKey); err != nil {
		return nil, fmt.Errorf("persist key: %w", err)
	}

	// Retire old signing key(s) beyond MaxActiveKeys
	s.mu.RLock()
	oldKeys := make([]*SigningKey, len(s.validKeys))
	copy(oldKeys, s.validKeys)
	s.mu.RUnlock()

	if len(oldKeys) >= s.config.MaxActiveKeys {
		// Retire the oldest active key
		for i := len(oldKeys) - 1; i >= 0; i-- {
			if oldKeys[i].Status == "active" && len(oldKeys)-i >= s.config.MaxActiveKeys {
				retireExpiry := time.Now().UTC().Add(s.config.KeyRetentionPeriod)
				if err := s.repo.UpdateStatus(ctx, oldKeys[i].ID, "retired", nil, nil); err != nil {
					s.logger.Error("Failed to retire old key", "key_id", oldKeys[i].ID, "error", err)
				} else {
					s.logger.Info("Retired old signing key",
						"key_id", oldKeys[i].ID,
						"valid_until", retireExpiry)
				}
			}
		}
	}

	// Update JWT service with new signing key
	s.mu.Lock()
	s.signingKey = newKey
	s.validKeys = append([]*SigningKey{newKey}, s.validKeys...)
	s.jwtService.config.Secret = newSecret
	s.jwtService.config.RefreshSecret = newSecret
	s.mu.Unlock()

	s.logger.Info("JWT key rotation completed",
		"new_key_id", newKey.ID,
		"key_hash", keyHash[:16]+"...")

	return newKey, nil
}

// ValidateTokenWithRotation validates a JWT token trying all active keys.
// Returns the claims if any key validates the token successfully.
func (s *KeyRotationService) ValidateTokenWithRotation(tokenString string) (*Claims, error) {
	s.mu.RLock()
	keys := make([]*SigningKey, len(s.validKeys))
	copy(keys, s.validKeys)
	s.mu.RUnlock()

	var lastErr error
	for _, key := range keys {
		if key.Status == "revoked" {
			continue
		}
		// Skip expired keys
		if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
			continue
		}

		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(key.Secret), nil
		})

		if err != nil {
			lastErr = err
			continue
		}

		claims, ok := token.Claims.(*Claims)
		if !ok || !token.Valid {
			lastErr = ErrInvalidClaims
			continue
		}

		if claims.Type != TokenTypeAccess {
			lastErr = ErrInvalidToken
			continue
		}

		return claims, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrInvalidToken
}

// GetSigningKey returns the current signing key's secret.
func (s *KeyRotationService) GetSigningKey() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.signingKey != nil {
		return s.signingKey.Secret
	}
	return ""
}

// GetActiveKeyCount returns the number of active signing keys.
func (s *KeyRotationService) GetActiveKeyCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.validKeys)
}

// CleanupExpiredKeys removes expired keys from the database.
func (s *KeyRotationService) CleanupExpiredKeys(ctx context.Context) (int64, error) {
	count, err := s.repo.DeleteExpired(ctx)
	if err != nil {
		return 0, fmt.Errorf("cleanup expired keys: %w", err)
	}
	if count > 0 {
		s.logger.Info("Cleaned up expired JWT signing keys", "count", count)
		// Reload active keys
		keys, err := s.repo.GetActiveKeys(ctx)
		if err != nil {
			return count, fmt.Errorf("reload keys after cleanup: %w", err)
		}
		if err := s.loadKeys(ctx, keys); err != nil {
			return count, fmt.Errorf("load keys after cleanup: %w", err)
		}
	}
	return count, nil
}

// NeedsRotation checks if the current signing key needs rotation.
func (s *KeyRotationService) NeedsRotation() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.signingKey == nil {
		return true
	}
	return time.Since(s.signingKey.CreatedAt) > s.config.RotationInterval
}

// ============================================================================
// Internal helpers
// ============================================================================

func (s *KeyRotationService) registerInitialKey(ctx context.Context) error {
	secret := s.jwtService.config.Secret
	keyHash := hashKey(secret)
	now := time.Now().UTC()

	key := &SigningKey{
		ID:          uuid.New(),
		KeyHash:     keyHash,
		Secret:      secret,
		Algorithm:   "HS256",
		Status:      "active",
		CreatedAt:   now,
		ActivatedAt: &now,
	}

	encryptedKey, err := s.encryptKey(secret)
	if err != nil {
		return fmt.Errorf("encrypt initial key: %w", err)
	}

	return s.repo.Create(ctx, key, encryptedKey)
}

func (s *KeyRotationService) loadKeys(ctx context.Context, keys []*SigningKey) error {
	var validKeys []*SigningKey
	var signingKey *SigningKey

	for _, key := range keys {
		if key.Status == "revoked" {
			continue
		}
		if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
			continue
		}
		validKeys = append(validKeys, key)
		if signingKey == nil || key.CreatedAt.After(signingKey.CreatedAt) {
			signingKey = key
		}
	}

	if signingKey == nil {
		return fmt.Errorf("no valid signing key available")
	}

	s.mu.Lock()
	s.signingKey = signingKey
	s.validKeys = validKeys
	// Update JWT service to use the current signing key
	s.jwtService.config.Secret = signingKey.Secret
	s.jwtService.config.RefreshSecret = signingKey.Secret
	s.mu.Unlock()

	return nil
}

func (s *KeyRotationService) encryptKey(secret string) ([]byte, error) {
	if s.config.EncryptionKey == "" {
		// If no encryption key configured, store as-is
		// This is acceptable for dev environments but should be configured in prod
		return []byte(secret), nil
	}
	encryptor, err := crypto.NewAESEncryptor(s.config.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("create encryptor: %w", err)
	}
	encrypted, err := encryptor.EncryptString(secret)
	if err != nil {
		return nil, fmt.Errorf("encrypt key: %w", err)
	}
	return []byte(encrypted), nil
}

func generateSigningKey(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

func hashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// KeyRotationInfo provides information about the current key rotation state.
type KeyRotationInfo struct {
	CurrentKeyID     uuid.UUID  `json:"current_key_id"`
	CurrentKeyHash   string     `json:"current_key_hash"`
	ActiveKeyCount   int        `json:"active_key_count"`
	LastRotatedAt    time.Time  `json:"last_rotated_at"`
	NextRotationAt   *time.Time `json:"next_rotation_at,omitempty"`
	RotationInterval string     `json:"rotation_interval"`
}

// GetRotationInfo returns information about the current key rotation state.
func (s *KeyRotationService) GetRotationInfo() *KeyRotationInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	info := &KeyRotationInfo{
		ActiveKeyCount:   len(s.validKeys),
		RotationInterval: s.config.RotationInterval.String(),
	}

	if s.signingKey != nil {
		info.CurrentKeyID = s.signingKey.ID
		info.CurrentKeyHash = s.signingKey.KeyHash[:16] + "..."
		info.LastRotatedAt = s.signingKey.CreatedAt
		nextRotation := s.signingKey.CreatedAt.Add(s.config.RotationInterval)
		info.NextRotationAt = &nextRotation
	}

	return info
}

// RevokeKey immediately revokes a specific key, making it invalid for token validation.
func (s *KeyRotationService) RevokeKey(ctx context.Context, keyID uuid.UUID, revokedBy *uuid.UUID) error {
	s.mu.RLock()
	if s.signingKey != nil && s.signingKey.ID == keyID {
		s.mu.RUnlock()
		return fmt.Errorf("cannot revoke the current signing key; rotate first")
	}
	s.mu.RUnlock()

	now := time.Now().UTC()
	if err := s.repo.UpdateStatus(ctx, keyID, "revoked", &now, revokedBy); err != nil {
		return fmt.Errorf("revoke key: %w", err)
	}

	// Remove from valid keys
	s.mu.Lock()
	var updated []*SigningKey
	for _, k := range s.validKeys {
		if k.ID != keyID {
			updated = append(updated, k)
		}
	}
	s.validKeys = updated
	s.mu.Unlock()

	s.logger.Info("JWT signing key revoked", "key_id", keyID)
	return nil
}

// GenerateTokenWithKey generates an access token using a specific key for signing.
// This is used internally and should not be called directly.
func (s *KeyRotationService) GenerateTokenWithKey(user *models.User) (string, time.Time, error) {
	s.mu.RLock()
	key := s.signingKey
	s.mu.RUnlock()

	if key == nil {
		return "", time.Time{}, fmt.Errorf("no signing key available")
	}

	now := time.Now().UTC()
	expiresAt := now.Add(s.jwtService.config.AccessTokenTTL)

	claims := &Claims{
		UserID:   user.ID.String(),
		Username: user.Username,
		Role:     user.Role,
		Type:     TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        s.jwtService.config.TokenIDGenerator(),
			Issuer:    s.jwtService.config.Issuer,
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
	signedToken, err := token.SignedString([]byte(key.Secret))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign access token: %w", err)
	}

	return signedToken, expiresAt, nil
}
