// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// Auth errors
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserLocked         = errors.New("user account is locked")
	ErrUserDisabled       = errors.New("user account is disabled")
	ErrPasswordMismatch   = errors.New("passwords do not match")
	ErrWeakPassword       = errors.New("password does not meet requirements")
)

// AuthConfig contains configuration for the auth service.
type AuthConfig struct {
	// MaxLoginAttempts before account lockout (0 = unlimited)
	MaxLoginAttempts int

	// LockoutDuration is how long an account stays locked
	LockoutDuration time.Duration

	// RequirePasswordChange forces password change on first login
	RequirePasswordChange bool

	// PasswordMinLength minimum password length (deprecated, use PasswordPolicy)
	PasswordMinLength int

	// PasswordPolicy defines password requirements
	PasswordPolicy crypto.PasswordPolicy

	// AllowAPIKeyAuth allows authentication via API keys
	AllowAPIKeyAuth bool
}

// DefaultAuthConfig returns default auth configuration.
func DefaultAuthConfig() AuthConfig {
	return AuthConfig{
		MaxLoginAttempts:      5,
		LockoutDuration:       15 * time.Minute,
		RequirePasswordChange: false,
		PasswordMinLength:     8,
		PasswordPolicy:        crypto.DefaultPasswordPolicy(),
		AllowAPIKeyAuth:       true,
	}
}

// AuditLogger interface for audit logging
type AuditLogger interface {
	LogLogin(ctx context.Context, userID *uuid.UUID, username, ip, userAgent string, success bool, errorMsg *string)
	LogLogout(ctx context.Context, userID uuid.UUID, username, ip, userAgent string)
	LogPasswordChange(ctx context.Context, userID uuid.UUID, username, ip, userAgent string, success bool)
}

// JWTBlacklist interface for token blacklisting
type JWTBlacklist interface {
	// BlacklistToken adds a token to the blacklist until its expiration
	BlacklistToken(ctx context.Context, jti string, expiresAt time.Time, reason string) error
	// IsBlacklisted checks if a token JTI is blacklisted
	IsBlacklisted(ctx context.Context, jti string) (bool, error)
	// BlacklistUserTokens blacklists all tokens for a user issued before a timestamp
	BlacklistUserTokens(ctx context.Context, userID string, issuedBefore time.Time, ttl time.Duration) error
	// IsUserTokenBlacklisted checks if a user's token is blacklisted by issue time
	IsUserTokenBlacklisted(ctx context.Context, userID string, issuedAt time.Time) (bool, error)
}

// Service is the main authentication service.
type Service struct {
	userRepo    *postgres.UserRepository
	sessionRepo *postgres.SessionRepository
	apiKeyRepo  *postgres.APIKeyRepository
	jwtService  *JWTService
	sessionSvc  *SessionService
	config      AuthConfig
	logger      *logger.Logger
	auditSvc    AuditLogger

	// Optional: JWT blacklist for immediate token revocation
	jwtBlacklist JWTBlacklist

	// Optional: LDAP and OAuth providers (injected separately)
	ldapProviders  []LDAPProvider
	oauthProviders map[string]OAuthProvider
}

// LDAPProvider interface for LDAP authentication.
type LDAPProvider interface {
	Authenticate(ctx context.Context, username, password string) (*LDAPUser, error)
	GetName() string
	IsEnabled() bool
}

// LDAPUser represents a user authenticated via LDAP.
type LDAPUser struct {
	Username string
	Email    string
	DN       string
	Groups   []string
	Role     models.UserRole
}

// OAuthProvider interface for OAuth authentication.
type OAuthProvider interface {
	GetAuthURL(state string) string
	Exchange(ctx context.Context, code string) (*OAuthUser, error)
	GetName() string
	IsEnabled() bool
}

// OAuthUser represents a user authenticated via OAuth.
type OAuthUser struct {
	ID       string
	Username string
	Email    string
	Name     string
	Provider string
	Role     models.UserRole
}

// NewService creates a new auth service.
func NewService(
	userRepo *postgres.UserRepository,
	sessionRepo *postgres.SessionRepository,
	apiKeyRepo *postgres.APIKeyRepository,
	jwtService *JWTService,
	sessionSvc *SessionService,
	config AuthConfig,
	log *logger.Logger,
) *Service {
	if log == nil {
		log = logger.Nop()
	}

	return &Service{
		userRepo:       userRepo,
		sessionRepo:    sessionRepo,
		apiKeyRepo:     apiKeyRepo,
		jwtService:     jwtService,
		sessionSvc:     sessionSvc,
		config:         config,
		logger:         log.Named("auth"),
		oauthProviders: make(map[string]OAuthProvider),
	}
}

// SetJWTBlacklist sets the JWT blacklist for immediate token revocation.
func (s *Service) SetJWTBlacklist(blacklist JWTBlacklist) {
	s.jwtBlacklist = blacklist
}

// HasJWTBlacklist returns true if JWT blacklisting is enabled.
func (s *Service) HasJWTBlacklist() bool {
	return s.jwtBlacklist != nil
}

// ============================================================================
// JWT Blacklisting
// ============================================================================

// BlacklistToken adds a token to the blacklist by its JTI.
// This is used for immediate token revocation (e.g., on logout).
func (s *Service) BlacklistToken(ctx context.Context, tokenString string, reason string) error {
	if s.jwtBlacklist == nil {
		s.logger.Debug("JWT blacklist not configured, skipping blacklist")
		return nil
	}

	// Parse the token to get JTI and expiration
	claims, err := s.jwtService.ParseUnverified(tokenString)
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	if claims.ID == "" {
		s.logger.Warn("Token has no JTI, cannot blacklist")
		return nil
	}

	expiresAt := time.Now().Add(s.jwtService.GetAccessTokenTTL())
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time
	}

	if err := s.jwtBlacklist.BlacklistToken(ctx, claims.ID, expiresAt, reason); err != nil {
		return fmt.Errorf("failed to blacklist token: %w", err)
	}

	s.logger.Debug("Token blacklisted",
		"jti", claims.ID,
		"reason", reason,
		"expires_at", expiresAt)

	return nil
}

// BlacklistUserTokens blacklists all tokens for a user.
// This is used for "logout from all devices" or when a password is changed.
func (s *Service) BlacklistUserTokens(ctx context.Context, userID uuid.UUID, reason string) error {
	if s.jwtBlacklist == nil {
		s.logger.Debug("JWT blacklist not configured, skipping user blacklist")
		return nil
	}

	// Blacklist all tokens issued before now
	// TTL should match the maximum token lifetime
	ttl := s.jwtService.GetRefreshTokenTTL()
	if err := s.jwtBlacklist.BlacklistUserTokens(ctx, userID.String(), time.Now(), ttl); err != nil {
		return fmt.Errorf("failed to blacklist user tokens: %w", err)
	}

	s.logger.Debug("User tokens blacklisted",
		"user_id", userID,
		"reason", reason)

	return nil
}

// IsTokenBlacklisted checks if a token is in the blacklist.
func (s *Service) IsTokenBlacklisted(ctx context.Context, tokenString string) (bool, error) {
	if s.jwtBlacklist == nil {
		return false, nil
	}

	claims, err := s.jwtService.ParseUnverified(tokenString)
	if err != nil {
		return false, fmt.Errorf("failed to parse token: %w", err)
	}

	// Check individual token blacklist
	if claims.ID != "" {
		blacklisted, err := s.jwtBlacklist.IsBlacklisted(ctx, claims.ID)
		if err != nil {
			return false, err
		}
		if blacklisted {
			return true, nil
		}
	}

	// Check user-level blacklist
	if claims.UserID != "" && claims.IssuedAt != nil {
		blacklisted, err := s.jwtBlacklist.IsUserTokenBlacklisted(ctx, claims.UserID, claims.IssuedAt.Time)
		if err != nil {
			return false, err
		}
		if blacklisted {
			return true, nil
		}
	}

	return false, nil
}

// CreateTokenValidator returns a function for use with auth middleware.
// It checks if tokens are blacklisted.
func (s *Service) CreateTokenValidator() func(ctx context.Context, tokenString string, userID string, jti string, issuedAt time.Time) error {
	return func(ctx context.Context, tokenString string, userID string, jti string, issuedAt time.Time) error {
		if s.jwtBlacklist == nil {
			return nil
		}

		// Check individual token blacklist
		if jti != "" {
			blacklisted, err := s.jwtBlacklist.IsBlacklisted(ctx, jti)
			if err != nil {
				s.logger.Warn("Failed to check token blacklist", "error", err)
				// On error, allow the request (fail open)
				return nil
			}
			if blacklisted {
				return ErrTokenRevoked
			}
		}

		// Check user-level blacklist
		if userID != "" && !issuedAt.IsZero() {
			blacklisted, err := s.jwtBlacklist.IsUserTokenBlacklisted(ctx, userID, issuedAt)
			if err != nil {
				s.logger.Warn("Failed to check user token blacklist", "error", err)
				return nil
			}
			if blacklisted {
				return ErrTokenRevoked
			}
		}

		return nil
	}
}

// ErrTokenRevoked is returned when a token has been revoked/blacklisted.
var ErrTokenRevoked = errors.New("token has been revoked")

// ============================================================================
// Local Authentication
// ============================================================================

// LoginInput contains input for login.
type LoginInput struct {
	Username  string
	Password  string
	UserAgent string
	IPAddress string
}

// LoginResult contains the result of a successful login.
type LoginResult struct {
	User         *models.User
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	SessionID    uuid.UUID
}

// Login authenticates a user with username and password.
// VerifyCredentials checks username/password without creating a session.
// Use this for the first step of a 2FA login flow.
func (s *Service) VerifyCredentials(ctx context.Context, input LoginInput) (*models.User, error) {
	user, err := s.userRepo.GetByUsername(ctx, input.Username)
	if err != nil {
		s.logger.Warn("login attempt for unknown user",
			"username", input.Username,
			"ip", input.IPAddress,
		)
		_ = crypto.CheckPassword(input.Password, "$2a$12$dummy.hash.to.prevent.timing.attacks")
		return nil, ErrInvalidCredentials
	}

	if !user.IsActive {
		s.logLoginAttempt(ctx, user, input.IPAddress, false, "account disabled")
		return nil, ErrUserDisabled
	}

	if user.IsLDAP {
		// LDAP verification without session creation
		if err := s.verifyLDAPCredentials(ctx, user, input); err != nil {
			return nil, err
		}
		return user, nil
	}

	if user.IsLocked() {
		s.logLoginAttempt(ctx, user, input.IPAddress, false, "account locked")
		return nil, ErrUserLocked
	}

	if !crypto.CheckPassword(input.Password, user.PasswordHash) {
		if s.config.MaxLoginAttempts > 0 {
			if err := s.userRepo.IncrementFailedAttempts(
				ctx,
				user.ID,
				s.config.MaxLoginAttempts,
				s.config.LockoutDuration,
			); err != nil {
				s.logger.Error("failed to increment login attempts", "error", err)
			}
		}
		s.logLoginAttempt(ctx, user, input.IPAddress, false, "invalid password")
		return nil, ErrInvalidCredentials
	}

	return user, nil
}

// verifyLDAPCredentials checks LDAP bind without creating a session.
func (s *Service) verifyLDAPCredentials(ctx context.Context, user *models.User, input LoginInput) error {
	if len(s.ldapProviders) == 0 {
		return errors.New("LDAP authentication not configured")
	}

	for _, provider := range s.ldapProviders {
		if !provider.IsEnabled() {
			continue
		}

		ldapUser, err := provider.Authenticate(ctx, input.Username, input.Password)
		if err != nil {
			s.logger.Debug("LDAP auth failed",
				"provider", provider.GetName(),
				"username", input.Username,
				"error", err,
			)
			continue
		}

		if ldapUser != nil {
			// Update user role from LDAP groups if changed
			if ldapUser.Role != user.Role {
				user.Role = ldapUser.Role
				if err := s.userRepo.Update(ctx, user); err != nil {
					s.logger.Warn("failed to update user role from LDAP", "error", err)
				}
			}
			return nil
		}
	}

	s.logLoginAttempt(ctx, user, input.IPAddress, false, "LDAP auth failed")
	return ErrInvalidCredentials
}

// CreateSessionForUser creates a login session for an already-authenticated user.
// Use after TOTP verification in a 2FA flow.
func (s *Service) CreateSessionForUser(ctx context.Context, user *models.User, input LoginInput) (*LoginResult, error) {
	return s.createLoginSession(ctx, user, input)
}

func (s *Service) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {
	// Get user by username
	user, err := s.userRepo.GetByUsername(ctx, input.Username)
	if err != nil {
		// Log attempt but return generic error
		s.logger.Warn("login attempt for unknown user",
			"username", input.Username,
			"ip", input.IPAddress,
		)
		// Perform dummy password check to prevent timing attacks
		_ = crypto.CheckPassword(input.Password, "$2a$12$dummy.hash.to.prevent.timing.attacks")
		return nil, ErrInvalidCredentials
	}

	// Check if user is LDAP user
	if user.IsLDAP {
		return s.loginLDAP(ctx, user, input)
	}

	// Check if user can login
	if !user.IsActive {
		s.logLoginAttempt(ctx, user, input.IPAddress, false, "account disabled")
		return nil, ErrUserDisabled
	}

	if user.IsLocked() {
		s.logLoginAttempt(ctx, user, input.IPAddress, false, "account locked")
		return nil, ErrUserLocked
	}

	// Verify password
	if !crypto.CheckPassword(input.Password, user.PasswordHash) {
		// Increment failed attempts
		if s.config.MaxLoginAttempts > 0 {
			if err := s.userRepo.IncrementFailedAttempts(
				ctx,
				user.ID,
				s.config.MaxLoginAttempts,
				s.config.LockoutDuration,
			); err != nil {
				s.logger.Error("failed to increment login attempts", "error", err)
			}
		}

		s.logLoginAttempt(ctx, user, input.IPAddress, false, "invalid password")
		return nil, ErrInvalidCredentials
	}

	// Success - create session
	return s.createLoginSession(ctx, user, input)
}

// createLoginSession creates a session for a successfully authenticated user.
func (s *Service) createLoginSession(ctx context.Context, user *models.User, input LoginInput) (*LoginResult, error) {
	// Update last login
	if err := s.userRepo.UpdateLastLogin(ctx, user.ID); err != nil {
		s.logger.Error("failed to update last login", "error", err)
	}

	// Create session
	sessionResult, err := s.sessionSvc.Create(ctx, user, CreateSessionInput{
		UserID:    user.ID,
		UserAgent: input.UserAgent,
		IPAddress: input.IPAddress,
	})
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	s.logLoginAttempt(ctx, user, input.IPAddress, true, "")

	return &LoginResult{
		User:         user,
		AccessToken:  sessionResult.AccessToken,
		RefreshToken: sessionResult.RefreshToken,
		ExpiresAt:    sessionResult.ExpiresAt,
		SessionID:    sessionResult.Session.ID,
	}, nil
}

// loginLDAP handles login for LDAP users.
func (s *Service) loginLDAP(ctx context.Context, user *models.User, input LoginInput) (*LoginResult, error) {
	if len(s.ldapProviders) == 0 {
		return nil, errors.New("LDAP authentication not configured")
	}

	// Check if user can login
	if !user.IsActive {
		s.logLoginAttempt(ctx, user, input.IPAddress, false, "account disabled")
		return nil, ErrUserDisabled
	}

	// Try LDAP authentication
	var authenticated bool
	for _, provider := range s.ldapProviders {
		if !provider.IsEnabled() {
			continue
		}

		ldapUser, err := provider.Authenticate(ctx, input.Username, input.Password)
		if err != nil {
			s.logger.Debug("LDAP auth failed",
				"provider", provider.GetName(),
				"username", input.Username,
				"error", err,
			)
			continue
		}

		if ldapUser != nil {
			authenticated = true
			// Update user role from LDAP groups if changed
			if ldapUser.Role != user.Role {
				user.Role = ldapUser.Role
				if err := s.userRepo.Update(ctx, user); err != nil {
					s.logger.Warn("failed to update user role from LDAP", "error", err)
				}
			}
			break
		}
	}

	if !authenticated {
		s.logLoginAttempt(ctx, user, input.IPAddress, false, "LDAP auth failed")
		return nil, ErrInvalidCredentials
	}

	return s.createLoginSession(ctx, user, input)
}

// ============================================================================
// Token Refresh
// ============================================================================

// RefreshInput contains input for token refresh.
type RefreshInput struct {
	RefreshToken string
	UserAgent    string
	IPAddress    string
}

// Refresh refreshes an access token using a refresh token.
func (s *Service) Refresh(ctx context.Context, input RefreshInput) (*LoginResult, error) {
	// Validate refresh token and get session
	session, err := s.sessionSvc.ValidateRefreshToken(ctx, input.RefreshToken)
	if err != nil {
		return nil, err
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, session.UserID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	// Check if user can still login
	if !user.IsActive {
		_ = s.sessionSvc.Revoke(ctx, session.ID)
		return nil, ErrUserDisabled
	}

	if user.IsLocked() {
		_ = s.sessionSvc.Revoke(ctx, session.ID)
		return nil, ErrUserLocked
	}

	// Refresh session
	sessionResult, err := s.sessionSvc.Refresh(ctx, input.RefreshToken, user)
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		User:         user,
		AccessToken:  sessionResult.AccessToken,
		RefreshToken: sessionResult.RefreshToken,
		ExpiresAt:    sessionResult.ExpiresAt,
		SessionID:    sessionResult.Session.ID,
	}, nil
}

// ============================================================================
// Logout
// ============================================================================

// Logout revokes a session.
func (s *Service) Logout(ctx context.Context, sessionID uuid.UUID) error {
	return s.sessionSvc.Revoke(ctx, sessionID)
}

// LogoutWithToken revokes a session and blacklists the current token.
func (s *Service) LogoutWithToken(ctx context.Context, sessionID uuid.UUID, tokenString string) error {
	// Blacklist the token first
	if tokenString != "" {
		if err := s.BlacklistToken(ctx, tokenString, "logout"); err != nil {
			s.logger.Warn("Failed to blacklist token on logout", "error", err)
			// Continue with session revocation
		}
	}
	return s.sessionSvc.Revoke(ctx, sessionID)
}

// LogoutByRefreshToken revokes a session using its refresh token.
func (s *Service) LogoutByRefreshToken(ctx context.Context, refreshToken string) error {
	return s.sessionSvc.RevokeByRefreshToken(ctx, refreshToken)
}

// LogoutAll revokes all sessions for a user and blacklists all their tokens.
func (s *Service) LogoutAll(ctx context.Context, userID uuid.UUID) (int64, error) {
	// Blacklist all user tokens first
	if err := s.BlacklistUserTokens(ctx, userID, "logout_all"); err != nil {
		s.logger.Warn("Failed to blacklist user tokens on logout all", "error", err)
		// Continue with session revocation
	}
	return s.sessionSvc.RevokeAllForUser(ctx, userID)
}

// LogoutOthers revokes all other sessions for a user and blacklists their tokens.
func (s *Service) LogoutOthers(ctx context.Context, userID uuid.UUID, currentSessionID uuid.UUID) (int64, error) {
	// Note: We blacklist all user tokens, which will also invalidate the current session's token.
	// The current session will need to get a new token after this operation.
	// For a more surgical approach, we'd need to track which tokens belong to which sessions.
	if err := s.BlacklistUserTokens(ctx, userID, "logout_others"); err != nil {
		s.logger.Warn("Failed to blacklist user tokens on logout others", "error", err)
	}
	return s.sessionSvc.RevokeAllExcept(ctx, userID, currentSessionID)
}

// ============================================================================
// API Key Authentication
// ============================================================================

// AuthenticateAPIKey authenticates using an API key.
func (s *Service) AuthenticateAPIKey(ctx context.Context, apiKey string) (*models.User, *models.APIKey, error) {
	if !s.config.AllowAPIKeyAuth {
		return nil, nil, apperrors.Forbidden("API key authentication is disabled")
	}

	// Hash the API key
	keyHash := crypto.HashAPIKey(apiKey)

	// Find API key
	key, err := s.apiKeyRepo.GetByKeyHash(ctx, keyHash)
	if err != nil {
		return nil, nil, apperrors.Unauthorized("invalid API key")
	}

	// Check if key is expired
	if key.IsExpired() {
		return nil, nil, apperrors.Unauthorized("API key has expired")
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, key.UserID)
	if err != nil {
		return nil, nil, err
	}

	// Check if user can login
	if !user.IsActive {
		return nil, nil, ErrUserDisabled
	}

	// Update last used
	if err := s.apiKeyRepo.UpdateLastUsed(ctx, key.ID); err != nil {
		s.logger.Warn("failed to update API key last used", "error", err)
	}

	return user, key, nil
}

// ============================================================================
// Password Management
// ============================================================================

// ChangePasswordInput contains input for changing password.
type ChangePasswordInput struct {
	UserID          uuid.UUID
	CurrentPassword string
	NewPassword     string
}

// ChangePassword changes a user's password.
func (s *Service) ChangePassword(ctx context.Context, input ChangePasswordInput) error {
	user, err := s.userRepo.GetByID(ctx, input.UserID)
	if err != nil {
		return err
	}

	// LDAP users cannot change password locally
	if user.IsLDAP {
		return apperrors.Forbidden("LDAP users must change password via LDAP")
	}

	// Verify current password
	if !crypto.CheckPassword(input.CurrentPassword, user.PasswordHash) {
		return ErrInvalidCredentials
	}

	// Validate new password (with username check)
	if err := s.validatePasswordForUser(input.NewPassword, user.Username); err != nil {
		return err
	}

	// Hash new password
	newHash, err := crypto.HashPassword(input.NewPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	// Update password
	if err := s.userRepo.UpdatePassword(ctx, user.ID, newHash); err != nil {
		return err
	}

	s.logger.Info("password changed", "user_id", user.ID)

	// Audit log
	if s.auditSvc != nil {
		s.auditSvc.LogPasswordChange(ctx, user.ID, user.Username, "", "", true)
	}

	return nil
}

// ResetPassword resets a user's password (admin action).
func (s *Service) ResetPassword(ctx context.Context, userID uuid.UUID, newPassword string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// LDAP users cannot have local password
	if user.IsLDAP {
		return apperrors.Forbidden("LDAP users cannot have local password")
	}

	// Validate new password
	if err := s.validatePassword(newPassword); err != nil {
		return err
	}

	// Hash new password
	newHash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	// Update password
	if err := s.userRepo.UpdatePassword(ctx, user.ID, newHash); err != nil {
		return err
	}

	// Revoke all sessions
	_, _ = s.sessionSvc.RevokeAllForUser(ctx, userID)

	s.logger.Info("password reset", "user_id", userID)

	// Audit log (password reset by admin)
	if s.auditSvc != nil {
		s.auditSvc.LogPasswordChange(ctx, user.ID, user.Username, "", "", true)
	}

	return nil
}

// validatePassword validates password requirements.
func (s *Service) validatePassword(password string) error {
	return s.validatePasswordForUser(password, "")
}

// validatePasswordForUser validates password requirements with username check.
func (s *Service) validatePasswordForUser(password, username string) error {
	// Use password policy if configured
	result := s.config.PasswordPolicy.ValidatePassword(password, username)
	if !result.Valid {
		if len(result.Errors) > 0 {
			return fmt.Errorf("%w: %s", ErrWeakPassword, result.Errors[0])
		}
		return ErrWeakPassword
	}
	return nil
}

// ============================================================================
// OAuth Authentication
// ============================================================================

// RegisterOAuthProvider registers an OAuth provider.
func (s *Service) RegisterOAuthProvider(name string, provider OAuthProvider) {
	s.oauthProviders[name] = provider
}

// GetOAuthAuthURL returns the OAuth authorization URL for a provider.
func (s *Service) GetOAuthAuthURL(providerName, state string) (string, error) {
	provider, ok := s.oauthProviders[providerName]
	if !ok {
		return "", fmt.Errorf("unknown OAuth provider: %s", providerName)
	}

	if !provider.IsEnabled() {
		return "", fmt.Errorf("OAuth provider %s is disabled", providerName)
	}

	return provider.GetAuthURL(state), nil
}

// OAuthCallback handles OAuth callback and returns login result.
func (s *Service) OAuthCallback(ctx context.Context, providerName, code string, input LoginInput) (*LoginResult, error) {
	provider, ok := s.oauthProviders[providerName]
	if !ok {
		return nil, fmt.Errorf("unknown OAuth provider: %s", providerName)
	}

	if !provider.IsEnabled() {
		return nil, fmt.Errorf("OAuth provider %s is disabled", providerName)
	}

	// Exchange code for user info
	oauthUser, err := provider.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("OAuth exchange failed: %w", err)
	}

	// Find or create user
	user, err := s.userRepo.GetByUsername(ctx, oauthUser.Username)
	if err != nil {
		// Create new user
		var appErr *apperrors.AppError
		if !errors.As(err, &appErr) {
			return nil, err
		}

		user = &models.User{
			ID:       uuid.New(),
			Username: oauthUser.Username,
			Role:     oauthUser.Role,
			IsActive: true,
			IsLDAP:   false, // OAuth users are not LDAP
		}

		if oauthUser.Email != "" {
			user.Email = &oauthUser.Email
		}

		if err := s.userRepo.Create(ctx, user); err != nil {
			return nil, fmt.Errorf("create OAuth user: %w", err)
		}

		s.logger.Info("OAuth user created",
			"username", user.Username,
			"provider", providerName,
		)
	}

	// Check if user can login
	if !user.IsActive {
		return nil, ErrUserDisabled
	}

	return s.createLoginSession(ctx, user, input)
}

// ============================================================================
// LDAP Providers
// ============================================================================

// RegisterLDAPProvider registers an LDAP provider.
func (s *Service) RegisterLDAPProvider(provider LDAPProvider) {
	s.ldapProviders = append(s.ldapProviders, provider)
}

// SetAuditService sets the audit logger for the auth service.
func (s *Service) SetAuditService(auditSvc AuditLogger) {
	s.auditSvc = auditSvc
}

// ============================================================================
// Session Management
// ============================================================================

// GetUserSessions returns all sessions for a user.
func (s *Service) GetUserSessions(ctx context.Context, userID uuid.UUID, currentSessionID uuid.UUID) ([]*SessionInfo, error) {
	sessions, err := s.sessionSvc.ListActiveForUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	return ToSessionInfoList(sessions, currentSessionID), nil
}

// RevokeSession revokes a specific session.
func (s *Service) RevokeSession(ctx context.Context, userID, sessionID uuid.UUID) error {
	// Verify session belongs to user
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		return err
	}

	if session.UserID != userID {
		return apperrors.Forbidden("session does not belong to user")
	}

	return s.sessionSvc.Revoke(ctx, sessionID)
}

// ============================================================================
// Audit Logging
// ============================================================================

func (s *Service) logLoginAttempt(ctx context.Context, user *models.User, ip string, success bool, reason string) {
	if success {
		s.logger.Info("login successful",
			"user_id", user.ID,
			"username", user.Username,
			"ip", ip,
		)
	} else {
		s.logger.Warn("login failed",
			"user_id", user.ID,
			"username", user.Username,
			"ip", ip,
			"reason", reason,
		)
	}

	// Write to audit log
	if s.auditSvc != nil {
		var errorMsg *string
		if reason != "" {
			errorMsg = &reason
		}
		s.auditSvc.LogLogin(ctx, &user.ID, user.Username, ip, "", success, errorMsg)
	}
}

// ============================================================================
// Token Validation (for middleware)
// ============================================================================

// ValidateAccessToken validates an access token and returns the claims.
func (s *Service) ValidateAccessToken(token string) (*Claims, error) {
	return s.jwtService.ValidateAccessToken(token)
}

// GetUserByID gets a user by ID (for middleware).
func (s *Service) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	return s.userRepo.GetByID(ctx, userID)
}

// ============================================================================
// Cleanup
// ============================================================================

// StartCleanupWorkers starts background cleanup workers.
func (s *Service) StartCleanupWorkers(ctx context.Context) {
	s.sessionSvc.StartCleanupWorker(ctx)

	// API key cleanup
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				count, err := s.apiKeyRepo.DeleteExpired(ctx)
				if err != nil {
					s.logger.Error("API key cleanup failed", "error", err)
				} else if count > 0 {
					s.logger.Info("expired API keys cleaned up", "count", count)
				}
			}
		}
	}()
}
