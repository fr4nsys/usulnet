// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// SessionConfig contains configuration for the session service.
type SessionConfig struct {
	// MaxSessionsPerUser limits concurrent sessions per user (0 = unlimited)
	MaxSessionsPerUser int

	// SessionTTL is the default session lifetime
	SessionTTL time.Duration

	// CleanupInterval is how often to run session cleanup
	CleanupInterval time.Duration

	// ExtendOnActivity extends session on each activity
	ExtendOnActivity bool

	// ExtendThreshold only extend if less than this time remaining
	ExtendThreshold time.Duration
}

// DefaultSessionConfig returns default session configuration.
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		MaxSessionsPerUser: 10,
		SessionTTL:         7 * 24 * time.Hour, // 7 days
		CleanupInterval:    1 * time.Hour,
		ExtendOnActivity:   true,
		ExtendThreshold:    24 * time.Hour,
	}
}

// SessionService manages user sessions.
type SessionService struct {
	sessionRepo *postgres.SessionRepository
	jwtService  *JWTService
	config      SessionConfig
	logger      *logger.Logger
}

// NewSessionService creates a new session service.
func NewSessionService(
	sessionRepo *postgres.SessionRepository,
	jwtService *JWTService,
	config SessionConfig,
	log *logger.Logger,
) *SessionService {
	if log == nil {
		log = logger.Nop()
	}

	return &SessionService{
		sessionRepo: sessionRepo,
		jwtService:  jwtService,
		config:      config,
		logger:      log.Named("session"),
	}
}

// ============================================================================
// Session Creation
// ============================================================================

// CreateSessionInput contains input for creating a session.
type CreateSessionInput struct {
	UserID    uuid.UUID
	UserAgent string
	IPAddress string
}

// SessionWithTokens contains a session and its associated tokens.
type SessionWithTokens struct {
	Session      *models.Session
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// Create creates a new session for a user.
func (s *SessionService) Create(ctx context.Context, user *models.User, input CreateSessionInput) (*SessionWithTokens, error) {
	// Enforce max sessions limit
	if s.config.MaxSessionsPerUser > 0 {
		count, err := s.sessionRepo.CountActiveByUserID(ctx, user.ID)
		if err != nil {
			return nil, fmt.Errorf("count sessions: %w", err)
		}

		if int(count) >= s.config.MaxSessionsPerUser {
			// Delete oldest sessions to make room
			_, err := s.sessionRepo.DeleteOldest(ctx, user.ID, s.config.MaxSessionsPerUser-1)
			if err != nil {
				s.logger.Warn("failed to delete oldest sessions",
					"user_id", user.ID,
					"error", err,
				)
			}
		}
	}

	// Generate refresh token (raw, will be stored hashed)
	refreshTokenRaw, err := GenerateRefreshTokenRaw()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	// Create session
	sessionID := uuid.New()
	expiresAt := time.Now().UTC().Add(s.config.SessionTTL)

	session := &models.Session{
		ID:               sessionID,
		UserID:           user.ID,
		RefreshTokenHash: crypto.HashToken(refreshTokenRaw),
		ExpiresAt:        expiresAt,
	}

	if input.UserAgent != "" {
		session.UserAgent = &input.UserAgent
	}
	if input.IPAddress != "" {
		session.IPAddress = &input.IPAddress
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	// Generate JWT token pair
	tokenPair, err := s.jwtService.GenerateTokenPair(user, sessionID)
	if err != nil {
		// Rollback session creation
		_ = s.sessionRepo.Delete(ctx, sessionID)
		return nil, fmt.Errorf("generate tokens: %w", err)
	}

	s.logger.Info("session created",
		"session_id", sessionID,
		"user_id", user.ID,
		"username", user.Username,
		"ip", input.IPAddress,
	)

	return &SessionWithTokens{
		Session:      session,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: refreshTokenRaw, // Return raw token, not hash
		ExpiresAt:    expiresAt,
	}, nil
}

// ============================================================================
// Session Refresh
// ============================================================================

// Refresh refreshes a session using a refresh token.
func (s *SessionService) Refresh(ctx context.Context, refreshToken string, user *models.User) (*SessionWithTokens, error) {
	// Find session by refresh token hash
	tokenHash := crypto.HashToken(refreshToken)
	session, err := s.sessionRepo.GetByRefreshTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Check if session is expired
	if session.IsExpired() {
		// Delete expired session
		_ = s.sessionRepo.Delete(ctx, session.ID)
		return nil, ErrExpiredToken
	}

	// Verify session belongs to user
	if session.UserID != user.ID {
		return nil, ErrInvalidToken
	}

	// Generate new refresh token
	newRefreshTokenRaw, err := GenerateRefreshTokenRaw()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	// Calculate new expiration
	newExpiresAt := time.Now().UTC().Add(s.config.SessionTTL)

	// Update session with new refresh token
	newTokenHash := crypto.HashToken(newRefreshTokenRaw)
	if err := s.sessionRepo.UpdateRefreshToken(ctx, session.ID, newTokenHash, newExpiresAt); err != nil {
		return nil, fmt.Errorf("update session: %w", err)
	}

	// Generate new JWT access token
	accessToken, accessExp, err := s.jwtService.GenerateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	session.RefreshTokenHash = newTokenHash
	session.ExpiresAt = newExpiresAt

	s.logger.Debug("session refreshed",
		"session_id", session.ID,
		"user_id", user.ID,
	)

	return &SessionWithTokens{
		Session:      session,
		AccessToken:  accessToken,
		RefreshToken: newRefreshTokenRaw,
		ExpiresAt:    accessExp,
	}, nil
}

// ============================================================================
// Session Validation
// ============================================================================

// Validate validates a session by ID.
func (s *SessionService) Validate(ctx context.Context, sessionID uuid.UUID) (*models.Session, error) {
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if session.IsExpired() {
		return nil, ErrExpiredToken
	}

	return session, nil
}

// ValidateRefreshToken validates a refresh token and returns the session.
func (s *SessionService) ValidateRefreshToken(ctx context.Context, refreshToken string) (*models.Session, error) {
	tokenHash := crypto.HashToken(refreshToken)
	session, err := s.sessionRepo.GetByRefreshTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, ErrInvalidToken
	}

	if session.IsExpired() {
		return nil, ErrExpiredToken
	}

	return session, nil
}

// IsValid checks if a session is valid.
func (s *SessionService) IsValid(ctx context.Context, sessionID uuid.UUID) bool {
	valid, err := s.sessionRepo.IsValid(ctx, sessionID)
	if err != nil {
		return false
	}
	return valid
}

// ============================================================================
// Session Extension
// ============================================================================

// ExtendIfNeeded extends the session if it's close to expiring.
func (s *SessionService) ExtendIfNeeded(ctx context.Context, sessionID uuid.UUID) error {
	if !s.config.ExtendOnActivity {
		return nil
	}

	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		return err
	}

	// Check if extension is needed
	timeRemaining := time.Until(session.ExpiresAt)
	if timeRemaining > s.config.ExtendThreshold {
		return nil // No extension needed
	}

	// Extend session
	newExpiresAt := time.Now().UTC().Add(s.config.SessionTTL)
	if err := s.sessionRepo.Extend(ctx, sessionID, newExpiresAt); err != nil {
		return fmt.Errorf("extend session: %w", err)
	}

	s.logger.Debug("session extended",
		"session_id", sessionID,
		"new_expires_at", newExpiresAt,
	)

	return nil
}

// ============================================================================
// Session Termination
// ============================================================================

// Revoke revokes a specific session.
func (s *SessionService) Revoke(ctx context.Context, sessionID uuid.UUID) error {
	if err := s.sessionRepo.Delete(ctx, sessionID); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}

	s.logger.Info("session revoked", "session_id", sessionID)
	return nil
}

// RevokeByRefreshToken revokes a session using its refresh token.
func (s *SessionService) RevokeByRefreshToken(ctx context.Context, refreshToken string) error {
	tokenHash := crypto.HashToken(refreshToken)
	session, err := s.sessionRepo.GetByRefreshTokenHash(ctx, tokenHash)
	if err != nil {
		return err
	}

	return s.Revoke(ctx, session.ID)
}

// RevokeAllForUser revokes all sessions for a user.
func (s *SessionService) RevokeAllForUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	count, err := s.sessionRepo.DeleteByUserID(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("revoke all sessions: %w", err)
	}

	s.logger.Info("all sessions revoked for user",
		"user_id", userID,
		"count", count,
	)

	return count, nil
}

// RevokeAllExcept revokes all sessions for a user except the specified one.
func (s *SessionService) RevokeAllExcept(ctx context.Context, userID uuid.UUID, keepSessionID uuid.UUID) (int64, error) {
	count, err := s.sessionRepo.DeleteAllExcept(ctx, userID, keepSessionID)
	if err != nil {
		return 0, fmt.Errorf("revoke sessions except: %w", err)
	}

	s.logger.Info("other sessions revoked",
		"user_id", userID,
		"kept_session", keepSessionID,
		"revoked_count", count,
	)

	return count, nil
}

// ============================================================================
// Session Listing
// ============================================================================

// ListForUser lists all sessions for a user.
func (s *SessionService) ListForUser(ctx context.Context, userID uuid.UUID) ([]*models.Session, error) {
	return s.sessionRepo.ListByUserID(ctx, userID)
}

// ListActiveForUser lists all active (non-expired) sessions for a user.
func (s *SessionService) ListActiveForUser(ctx context.Context, userID uuid.UUID) ([]*models.Session, error) {
	return s.sessionRepo.ListActiveByUserID(ctx, userID)
}

// CountActiveForUser counts active sessions for a user.
func (s *SessionService) CountActiveForUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	return s.sessionRepo.CountActiveByUserID(ctx, userID)
}

// ============================================================================
// Session Cleanup
// ============================================================================

// Cleanup removes expired sessions.
func (s *SessionService) Cleanup(ctx context.Context) (int64, error) {
	count, err := s.sessionRepo.DeleteExpired(ctx)
	if err != nil {
		return 0, fmt.Errorf("cleanup expired sessions: %w", err)
	}

	if count > 0 {
		s.logger.Info("expired sessions cleaned up", "count", count)
	}

	return count, nil
}

// StartCleanupWorker starts a background worker that periodically cleans up expired sessions.
func (s *SessionService) StartCleanupWorker(ctx context.Context) {
	if s.config.CleanupInterval <= 0 {
		return
	}

	ticker := time.NewTicker(s.config.CleanupInterval)
	go func() {
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				if _, err := s.Cleanup(ctx); err != nil {
					s.logger.Error("session cleanup failed", "error", err)
				}
			}
		}
	}()

	s.logger.Info("session cleanup worker started",
		"interval", s.config.CleanupInterval,
	)
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats retrieves session statistics.
func (s *SessionService) GetStats(ctx context.Context) (*postgres.SessionStats, error) {
	return s.sessionRepo.GetStats(ctx)
}

// ============================================================================
// Session Info (for API responses)
// ============================================================================

// SessionInfo contains session information for API responses.
type SessionInfo struct {
	ID        uuid.UUID  `json:"id"`
	UserAgent string     `json:"user_agent,omitempty"`
	IPAddress string     `json:"ip_address,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	IsCurrent bool       `json:"is_current"`
}

// ToSessionInfo converts a session to API-safe info.
func ToSessionInfo(session *models.Session, currentSessionID uuid.UUID) *SessionInfo {
	info := &SessionInfo{
		ID:        session.ID,
		CreatedAt: session.CreatedAt,
		ExpiresAt: session.ExpiresAt,
		IsCurrent: session.ID == currentSessionID,
	}

	if session.UserAgent != nil {
		info.UserAgent = *session.UserAgent
	}
	if session.IPAddress != nil {
		info.IPAddress = *session.IPAddress
	}

	return info
}

// ToSessionInfoList converts sessions to API-safe info list.
func ToSessionInfoList(sessions []*models.Session, currentSessionID uuid.UUID) []*SessionInfo {
	result := make([]*SessionInfo, len(sessions))
	for i, session := range sessions {
		result[i] = ToSessionInfo(session, currentSessionID)
	}
	return result
}
