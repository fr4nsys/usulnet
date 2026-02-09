// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package gateway provides agent registration and token management.
package gateway

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

const (
	// TokenLength is the length of generated agent tokens (in bytes, before base64)
	TokenLength = 32

	// TokenPrefix is added to agent tokens for identification
	TokenPrefix = "usulnet_agent_"
)

// RegistrationService handles agent registration and token management.
type RegistrationService struct {
	hostRepo    HostRepository
	tokenStore  TokenStore
	log         *logger.Logger

	// In-memory token cache for fast validation
	tokenCache  map[string]uuid.UUID // token -> hostID
	cacheMu     sync.RWMutex
	cacheExpiry time.Duration
}

// TokenStore defines the interface for persistent token storage.
type TokenStore interface {
	// StoreToken stores a token for a host
	StoreToken(ctx context.Context, hostID uuid.UUID, token string, expiresAt *time.Time) error
	// GetHostByToken retrieves the host ID for a token
	GetHostByToken(ctx context.Context, token string) (uuid.UUID, error)
	// RevokeToken revokes a token
	RevokeToken(ctx context.Context, token string) error
	// RevokeAllForHost revokes all tokens for a host
	RevokeAllForHost(ctx context.Context, hostID uuid.UUID) error
	// ListTokensForHost lists all active tokens for a host
	ListTokensForHost(ctx context.Context, hostID uuid.UUID) ([]TokenInfo, error)
}

// TokenInfo contains information about a token.
type TokenInfo struct {
	Token     string     `json:"token"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
}

// NewRegistrationService creates a new registration service.
func NewRegistrationService(hostRepo HostRepository, tokenStore TokenStore, log *logger.Logger) *RegistrationService {
	return &RegistrationService{
		hostRepo:    hostRepo,
		tokenStore:  tokenStore,
		log:         log.Named("registration"),
		tokenCache:  make(map[string]uuid.UUID),
		cacheExpiry: 5 * time.Minute,
	}
}

// GenerateToken generates a new agent token for a host.
func (s *RegistrationService) GenerateToken(ctx context.Context, hostID uuid.UUID, expiresAt *time.Time) (string, error) {
	// Generate random bytes
	tokenBytes := make([]byte, TokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode as base64 with prefix
	token := TokenPrefix + base64.URLEncoding.EncodeToString(tokenBytes)

	// Store token
	if err := s.tokenStore.StoreToken(ctx, hostID, token, expiresAt); err != nil {
		return "", fmt.Errorf("failed to store token: %w", err)
	}

	// Update cache
	s.cacheMu.Lock()
	s.tokenCache[token] = hostID
	s.cacheMu.Unlock()

	s.log.Info("Agent token generated",
		"host_id", hostID,
		"expires_at", expiresAt,
	)

	return token, nil
}

// ValidateToken validates an agent token and returns the host ID.
func (s *RegistrationService) ValidateToken(ctx context.Context, token string) (uuid.UUID, error) {
	// Check cache first
	s.cacheMu.RLock()
	hostID, cached := s.tokenCache[token]
	s.cacheMu.RUnlock()

	if cached {
		return hostID, nil
	}

	// Check persistent store
	hostID, err := s.tokenStore.GetHostByToken(ctx, token)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid token: %w", err)
	}

	// Update cache
	s.cacheMu.Lock()
	s.tokenCache[token] = hostID
	s.cacheMu.Unlock()

	return hostID, nil
}

// RevokeToken revokes an agent token.
func (s *RegistrationService) RevokeToken(ctx context.Context, token string) error {
	// Remove from cache
	s.cacheMu.Lock()
	delete(s.tokenCache, token)
	s.cacheMu.Unlock()

	// Remove from store
	if err := s.tokenStore.RevokeToken(ctx, token); err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	s.log.Info("Agent token revoked")
	return nil
}

// RevokeAllTokens revokes all tokens for a host.
func (s *RegistrationService) RevokeAllTokens(ctx context.Context, hostID uuid.UUID) error {
	// Get tokens for host to remove from cache
	tokens, err := s.tokenStore.ListTokensForHost(ctx, hostID)
	if err != nil {
		s.log.Warn("Failed to list tokens for cache cleanup", "error", err)
	}

	// Remove from cache
	s.cacheMu.Lock()
	for _, t := range tokens {
		delete(s.tokenCache, t.Token)
	}
	s.cacheMu.Unlock()

	// Remove from store
	if err := s.tokenStore.RevokeAllForHost(ctx, hostID); err != nil {
		return fmt.Errorf("failed to revoke tokens: %w", err)
	}

	s.log.Info("All agent tokens revoked", "host_id", hostID)
	return nil
}

// RotateToken revokes the old token and generates a new one.
func (s *RegistrationService) RotateToken(ctx context.Context, hostID uuid.UUID, oldToken string, expiresAt *time.Time) (string, error) {
	// Generate new token first
	newToken, err := s.GenerateToken(ctx, hostID, expiresAt)
	if err != nil {
		return "", err
	}

	// Revoke old token
	if err := s.RevokeToken(ctx, oldToken); err != nil {
		s.log.Warn("Failed to revoke old token during rotation", "error", err)
		// Continue anyway - new token is valid
	}

	return newToken, nil
}

// ClearCache clears the token cache.
func (s *RegistrationService) ClearCache() {
	s.cacheMu.Lock()
	s.tokenCache = make(map[string]uuid.UUID)
	s.cacheMu.Unlock()
}

// ============================================================================
// Registration Validator
// ============================================================================

// RegistrationValidator validates agent registration requests.
type RegistrationValidator struct {
	minAgentVersion string
	allowedOS       []string
	allowedArch     []string
}

// NewRegistrationValidator creates a new validator.
func NewRegistrationValidator() *RegistrationValidator {
	return &RegistrationValidator{
		minAgentVersion: "1.0.0",
		allowedOS:       []string{"linux", "darwin", "windows"},
		allowedArch:     []string{"amd64", "arm64", "arm"},
	}
}

// SetMinAgentVersion sets the minimum required agent version.
func (v *RegistrationValidator) SetMinAgentVersion(version string) {
	v.minAgentVersion = version
}

// Validate validates a registration request.
func (v *RegistrationValidator) Validate(req *protocol.RegistrationRequest) error {
	if req.Token == "" {
		return fmt.Errorf("token is required")
	}

	info := &req.Info

	// Validate agent ID format (optional)
	if info.AgentID != "" {
		if _, err := uuid.Parse(info.AgentID); err != nil {
			// Not a valid UUID, check if it's at least reasonable
			if len(info.AgentID) < 8 || len(info.AgentID) > 64 {
				return fmt.Errorf("invalid agent ID format")
			}
		}
	}

	// Validate version
	if info.Version != "" {
		if !v.isVersionValid(info.Version) {
			return fmt.Errorf("agent version %s is below minimum %s", info.Version, v.minAgentVersion)
		}
	}

	// Validate OS
	if info.OS != "" && !v.isOSAllowed(info.OS) {
		return fmt.Errorf("unsupported OS: %s", info.OS)
	}

	// Validate architecture
	if info.Arch != "" && !v.isArchAllowed(info.Arch) {
		return fmt.Errorf("unsupported architecture: %s", info.Arch)
	}

	return nil
}

func (v *RegistrationValidator) isVersionValid(version string) bool {
	// Simple version comparison - could be enhanced with semver
	// For now, accept any non-empty version
	return version != ""
}

func (v *RegistrationValidator) isOSAllowed(os string) bool {
	for _, allowed := range v.allowedOS {
		if os == allowed {
			return true
		}
	}
	return false
}

func (v *RegistrationValidator) isArchAllowed(arch string) bool {
	for _, allowed := range v.allowedArch {
		if arch == allowed {
			return true
		}
	}
	return false
}

// ============================================================================
// Token Comparison (Constant-Time)
// ============================================================================

// SecureCompareTokens compares two tokens in constant time to prevent timing attacks.
func SecureCompareTokens(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ============================================================================
// In-Memory Token Store (for testing/single-node)
// ============================================================================

// MemoryTokenStore is an in-memory implementation of TokenStore.
type MemoryTokenStore struct {
	tokens map[string]memoryToken
	mu     sync.RWMutex
}

type memoryToken struct {
	HostID    uuid.UUID
	CreatedAt time.Time
	ExpiresAt *time.Time
	LastUsed  *time.Time
}

// NewMemoryTokenStore creates a new in-memory token store.
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{
		tokens: make(map[string]memoryToken),
	}
}

func (s *MemoryTokenStore) StoreToken(ctx context.Context, hostID uuid.UUID, token string, expiresAt *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[token] = memoryToken{
		HostID:    hostID,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
	}
	return nil
}

func (s *MemoryTokenStore) GetHostByToken(ctx context.Context, token string) (uuid.UUID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, exists := s.tokens[token]
	if !exists {
		return uuid.Nil, fmt.Errorf("token not found")
	}

	// Check expiry
	if t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) {
		return uuid.Nil, fmt.Errorf("token expired")
	}

	return t.HostID, nil
}

func (s *MemoryTokenStore) RevokeToken(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tokens, token)
	return nil
}

func (s *MemoryTokenStore) RevokeAllForHost(ctx context.Context, hostID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for token, t := range s.tokens {
		if t.HostID == hostID {
			delete(s.tokens, token)
		}
	}
	return nil
}

func (s *MemoryTokenStore) ListTokensForHost(ctx context.Context, hostID uuid.UUID) ([]TokenInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []TokenInfo
	for token, t := range s.tokens {
		if t.HostID == hostID {
			result = append(result, TokenInfo{
				Token:     token,
				CreatedAt: t.CreatedAt,
				ExpiresAt: t.ExpiresAt,
				LastUsed:  t.LastUsed,
			})
		}
	}
	return result, nil
}
