// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package user provides user management services.
package user

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// ServiceConfig contains configuration for the user service.
type ServiceConfig struct {
	// PasswordMinLength minimum password length (range: 8-128)
	PasswordMinLength int

	// PasswordRequireUpper requires at least one uppercase letter
	PasswordRequireUpper bool

	// PasswordRequireLower requires at least one lowercase letter
	PasswordRequireLower bool

	// PasswordRequireNumber requires at least one digit
	PasswordRequireNumber bool

	// PasswordRequireSymbol requires at least one special character
	PasswordRequireSymbol bool

	// PasswordHistoryCount prevents reuse of N previous passwords (0 = disabled, default: 5)
	PasswordHistoryCount int

	// PasswordExpiryDays forces password change after N days (0 = never, default: 0)
	PasswordExpiryDays int

	// PasswordExpiryWarningDays notifies user N days before password expires (default: 7)
	PasswordExpiryWarningDays int

	// MaxFailedLogins before account lockout (0 = disabled)
	MaxFailedLogins int

	// LockoutDuration is how long to lock accounts after max failed logins
	LockoutDuration time.Duration

	// DefaultRole for new users
	DefaultRole models.UserRole

	// AllowSelfRegistration allows users to register themselves
	AllowSelfRegistration bool

	// RequireEmailVerification requires email verification
	RequireEmailVerification bool

	// MaxAPIKeysPerUser limits API keys per user (0 = unlimited)
	MaxAPIKeysPerUser int

	// APIKeyLength is the length in bytes for generated API keys (default 32 → 64 hex chars)
	APIKeyLength int
}

// DefaultServiceConfig returns default service configuration.
func DefaultServiceConfig() ServiceConfig {
	return ServiceConfig{
		PasswordMinLength:         8,
		PasswordRequireUpper:      true,
		PasswordRequireLower:      false,
		PasswordRequireNumber:     true,
		PasswordRequireSymbol:     false,
		PasswordHistoryCount:      5,
		PasswordExpiryDays:        0, // disabled by default
		PasswordExpiryWarningDays: 7,
		MaxFailedLogins:           5,
		LockoutDuration:           15 * time.Minute,
		DefaultRole:               models.RoleViewer,
		AllowSelfRegistration:     false,
		RequireEmailVerification:  false,
		MaxAPIKeysPerUser:         10,
		APIKeyLength:              32,
	}
}

// Service handles user management operations.
type Service struct {
	userRepo   UserRepository
	apiKeyRepo APIKeyRepository
	config     ServiceConfig
	logger     *logger.Logger
	limitMu    sync.RWMutex
	limitProvider license.LimitProvider
}

// UserRepository defines the persistence interface for user operations.
type UserRepository interface {
	Create(ctx context.Context, user *models.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetByUsername(ctx context.Context, username string) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	Update(ctx context.Context, user *models.User) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, opts postgres.UserListOptions) ([]*models.User, int64, error)
	ExistsByUsername(ctx context.Context, username string) (bool, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	Unlock(ctx context.Context, id uuid.UUID) error
	GetPasswordHistory(ctx context.Context, userID uuid.UUID, limit int) ([]string, error)
	SavePasswordHistory(ctx context.Context, userID uuid.UUID, passwordHash string) error
	GetStats(ctx context.Context) (*postgres.UserStats, error)
	CountByRole(ctx context.Context) (map[models.UserRole]int64, error)
}

// APIKeyRepository defines the persistence interface for API key operations.
type APIKeyRepository interface {
	Create(ctx context.Context, key *models.APIKey) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.APIKey, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*models.APIKey, error)
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error)
	CountByUserID(ctx context.Context, userID uuid.UUID) (int64, error)
	CountAll(ctx context.Context) (int64, error)
	ExistsByName(ctx context.Context, userID uuid.UUID, name string) (bool, error)
}

// SetLimitProvider sets the license limit provider for resource cap enforcement.
func (s *Service) SetLimitProvider(lp license.LimitProvider) {
	s.limitMu.Lock()
	s.limitProvider = lp
	s.limitMu.Unlock()
}

// NewService creates a new user service.
func NewService(
	userRepo UserRepository,
	apiKeyRepo APIKeyRepository,
	config ServiceConfig,
	log *logger.Logger,
) *Service {
	if log == nil {
		log = logger.Nop()
	}

	return &Service{
		userRepo:   userRepo,
		apiKeyRepo: apiKeyRepo,
		config:     config,
		logger:     log.Named("user"),
	}
}

// ============================================================================
// User CRUD
// ============================================================================

// CreateInput contains input for creating a user.
type CreateInput struct {
	Username string
	Email    string
	Password string
	Role     models.UserRole
}

// Create creates a new user.
func (s *Service) Create(ctx context.Context, input CreateInput) (*models.User, error) {
	// Enforce license user limit (fail-closed: error on stats failure)
	s.limitMu.RLock()
	lp := s.limitProvider
	s.limitMu.RUnlock()
	if lp != nil {
		limit := lp.GetLimits().MaxUsers
		if limit > 0 {
			stats, err := s.GetStats(ctx)
			if err != nil {
				return nil, fmt.Errorf("check user limit: %w", err)
			}
			current := int(stats.Total)
			if current >= limit {
				return nil, apperrors.LimitExceeded("users", current, limit)
			}
		}
	}

	// Validate input
	if err := s.validateCreateInput(input); err != nil {
		return nil, err
	}

	// Check if username exists
	exists, err := s.userRepo.ExistsByUsername(ctx, input.Username)
	if err != nil {
		return nil, fmt.Errorf("check username: %w", err)
	}
	if exists {
		return nil, apperrors.AlreadyExists("username")
	}

	// Check if email exists (if provided)
	if input.Email != "" {
		exists, err := s.userRepo.ExistsByEmail(ctx, input.Email)
		if err != nil {
			return nil, fmt.Errorf("check email: %w", err)
		}
		if exists {
			return nil, apperrors.AlreadyExists("email")
		}
	}

	// Hash password
	passwordHash, err := crypto.HashPassword(input.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	// Set default role if not provided
	role := input.Role
	if !role.IsValid() {
		role = s.config.DefaultRole
	}

	// Create user
	user := &models.User{
		ID:           uuid.New(),
		Username:     strings.TrimSpace(input.Username),
		PasswordHash: passwordHash,
		Role:         role,
		IsActive:     true,
		IsLDAP:       false,
	}

	if input.Email != "" {
		email := strings.TrimSpace(strings.ToLower(input.Email))
		user.Email = &email
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	s.logger.Info("user created",
		"user_id", user.ID,
		"username", user.Username,
		"role", user.Role,
	)

	return user, nil
}

// validateCreateInput validates user creation input.
func (s *Service) validateCreateInput(input CreateInput) error {
	if strings.TrimSpace(input.Username) == "" {
		return apperrors.InvalidInput("username is required")
	}

	if len(input.Username) < 3 {
		return apperrors.InvalidInput("username must be at least 3 characters")
	}

	if len(input.Username) > 50 {
		return apperrors.InvalidInput("username must not exceed 50 characters")
	}

	// Check for valid username characters
	for _, r := range input.Username {
		if !isValidUsernameChar(r) {
			return apperrors.InvalidInput("username contains invalid characters")
		}
	}

	if len(input.Password) < s.config.PasswordMinLength {
		return apperrors.InvalidInput(fmt.Sprintf("password must be at least %d characters", s.config.PasswordMinLength))
	}

	if err := s.validatePasswordPolicy(input.Password); err != nil {
		return err
	}

	if input.Email != "" && !isValidEmail(input.Email) {
		return apperrors.InvalidInput("invalid email format")
	}

	return nil
}

// validatePasswordPolicy enforces configured password complexity requirements.
func (s *Service) validatePasswordPolicy(password string) error {
	// Enforce maximum length
	if len(password) > 128 {
		return apperrors.InvalidInput("password must not exceed 128 characters")
	}

	if s.config.PasswordRequireUpper {
		hasUpper := false
		for _, r := range password {
			if r >= 'A' && r <= 'Z' {
				hasUpper = true
				break
			}
		}
		if !hasUpper {
			return apperrors.InvalidInput("password must contain at least one uppercase letter")
		}
	}

	if s.config.PasswordRequireLower {
		hasLower := false
		for _, r := range password {
			if r >= 'a' && r <= 'z' {
				hasLower = true
				break
			}
		}
		if !hasLower {
			return apperrors.InvalidInput("password must contain at least one lowercase letter")
		}
	}

	if s.config.PasswordRequireNumber {
		hasDigit := false
		for _, r := range password {
			if r >= '0' && r <= '9' {
				hasDigit = true
				break
			}
		}
		if !hasDigit {
			return apperrors.InvalidInput("password must contain at least one digit")
		}
	}

	if s.config.PasswordRequireSymbol {
		hasSymbol := false
		for _, r := range password {
			if !isAlphaNumeric(r) {
				hasSymbol = true
				break
			}
		}
		if !hasSymbol {
			return apperrors.InvalidInput("password must contain at least one special character")
		}
	}

	return nil
}

// CheckPasswordHistory checks if a password has been used recently by the user.
// Returns an error if the password matches any of the N most recent passwords.
func (s *Service) CheckPasswordHistory(ctx context.Context, userID uuid.UUID, newPassword string) error {
	if s.config.PasswordHistoryCount <= 0 {
		return nil
	}

	// Get recent password hashes from the password_history table
	hashes, err := s.userRepo.GetPasswordHistory(ctx, userID, s.config.PasswordHistoryCount)
	if err != nil {
		s.logger.Warn("Failed to check password history", "user_id", userID, "error", err)
		return nil // Don't block password change if history check fails
	}

	for _, hash := range hashes {
		if crypto.CheckPassword(newPassword, hash) {
			return apperrors.InvalidInput(
				fmt.Sprintf("password was used recently; cannot reuse any of the last %d passwords",
					s.config.PasswordHistoryCount))
		}
	}

	return nil
}

// SavePasswordHistory stores the current password hash in the history table.
func (s *Service) SavePasswordHistory(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	if s.config.PasswordHistoryCount <= 0 {
		return nil
	}
	return s.userRepo.SavePasswordHistory(ctx, userID, passwordHash)
}

// IsPasswordExpired checks if a user's password has expired based on the configured policy.
func (s *Service) IsPasswordExpired(user *models.User) bool {
	if s.config.PasswordExpiryDays <= 0 {
		return false
	}
	if user.PasswordChangedAt == nil {
		return false
	}
	expiryTime := user.PasswordChangedAt.Add(time.Duration(s.config.PasswordExpiryDays) * 24 * time.Hour)
	return time.Now().After(expiryTime)
}

// PasswordExpiresIn returns how many days until the password expires.
// Returns -1 if expiry is disabled or no password change date is set.
func (s *Service) PasswordExpiresIn(user *models.User) int {
	if s.config.PasswordExpiryDays <= 0 || user.PasswordChangedAt == nil {
		return -1
	}
	expiryTime := user.PasswordChangedAt.Add(time.Duration(s.config.PasswordExpiryDays) * 24 * time.Hour)
	days := int(time.Until(expiryTime).Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}

// ShouldWarnPasswordExpiry checks if the user should be warned about upcoming password expiry.
func (s *Service) ShouldWarnPasswordExpiry(user *models.User) bool {
	days := s.PasswordExpiresIn(user)
	if days < 0 {
		return false
	}
	return days <= s.config.PasswordExpiryWarningDays
}

// GetPasswordPolicyInfo returns the current password policy for display to users.
func (s *Service) GetPasswordPolicyInfo() map[string]interface{} {
	return map[string]interface{}{
		"min_length":        s.config.PasswordMinLength,
		"max_length":        128,
		"require_uppercase": s.config.PasswordRequireUpper,
		"require_lowercase": s.config.PasswordRequireLower,
		"require_number":    s.config.PasswordRequireNumber,
		"require_special":   s.config.PasswordRequireSymbol,
		"history_count":     s.config.PasswordHistoryCount,
		"expiry_days":       s.config.PasswordExpiryDays,
		"warning_days":      s.config.PasswordExpiryWarningDays,
	}
}

// isAlphaNumeric checks if a rune is a letter or digit.
func isAlphaNumeric(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// isValidUsernameChar checks if a character is valid for usernames.
func isValidUsernameChar(r rune) bool {
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') ||
		r == '_' || r == '-' || r == '.'
}

// isValidEmail performs basic email validation.
func isValidEmail(email string) bool {
	// Basic check - contains @ and at least one dot after @
	atIdx := strings.Index(email, "@")
	if atIdx < 1 {
		return false
	}
	domain := email[atIdx+1:]
	return strings.Contains(domain, ".") && len(domain) > 2
}

// GetByID retrieves a user by ID.
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	return s.userRepo.GetByID(ctx, id)
}

// GetByUsername retrieves a user by username.
func (s *Service) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	return s.userRepo.GetByUsername(ctx, username)
}

// GetByEmail retrieves a user by email.
func (s *Service) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	return s.userRepo.GetByEmail(ctx, email)
}

// UpdateInput contains input for updating a user.
type UpdateInput struct {
	Email    *string
	Role     *models.UserRole
	IsActive *bool
}

// Update updates a user.
func (s *Service) Update(ctx context.Context, id uuid.UUID, input UpdateInput) (*models.User, error) {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Update fields if provided
	if input.Email != nil {
		email := strings.TrimSpace(strings.ToLower(*input.Email))
		if email != "" {
			if !isValidEmail(email) {
				return nil, apperrors.InvalidInput("invalid email format")
			}

			// Check if email is taken by another user
			existingUser, err := s.userRepo.GetByEmail(ctx, email)
			if err == nil && existingUser.ID != id {
				return nil, apperrors.AlreadyExists("email")
			}
		}
		if email == "" {
			user.Email = nil
		} else {
			user.Email = &email
		}
	}

	if input.Role != nil {
		if !input.Role.IsValid() {
			return nil, apperrors.InvalidInput("invalid role")
		}
		user.Role = *input.Role
	}

	if input.IsActive != nil {
		user.IsActive = *input.IsActive
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}

	s.logger.Info("user updated",
		"user_id", user.ID,
		"username", user.Username,
	)

	return user, nil
}

// Delete deletes a user.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Delete associated API keys
	if _, err := s.apiKeyRepo.DeleteByUserID(ctx, id); err != nil {
		s.logger.Warn("failed to delete user API keys", "user_id", id, "error", err)
	}

	if err := s.userRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}

	s.logger.Info("user deleted",
		"user_id", id,
		"username", user.Username,
	)

	return nil
}

// ============================================================================
// User Listing
// ============================================================================

// ListOptions contains options for listing users.
type ListOptions struct {
	Page     int
	PerPage  int
	Search   string
	Role     *models.UserRole
	IsActive *bool
	IsLDAP   *bool
	SortBy   string
	SortDesc bool
}

// ListResult contains the result of listing users.
type ListResult struct {
	Users      []*models.User
	Total      int64
	Page       int
	PerPage    int
	TotalPages int
}

// List lists users with pagination and filtering.
func (s *Service) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	users, total, err := s.userRepo.List(ctx, postgres.UserListOptions{
		Page:     opts.Page,
		PerPage:  opts.PerPage,
		Search:   opts.Search,
		Role:     opts.Role,
		IsActive: opts.IsActive,
		IsLDAP:   opts.IsLDAP,
		SortBy:   opts.SortBy,
		SortDesc: opts.SortDesc,
	})
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}

	totalPages := int(total) / opts.PerPage
	if int(total)%opts.PerPage > 0 {
		totalPages++
	}

	return &ListResult{
		Users:      users,
		Total:      total,
		Page:       opts.Page,
		PerPage:    opts.PerPage,
		TotalPages: totalPages,
	}, nil
}

// ============================================================================
// User Status Management
// ============================================================================

// Activate activates a user account.
func (s *Service) Activate(ctx context.Context, id uuid.UUID) error {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if user.IsActive {
		return nil // Already active
	}

	user.IsActive = true
	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("activate user: %w", err)
	}

	s.logger.Info("user activated", "user_id", id)
	return nil
}

// Deactivate deactivates a user account.
func (s *Service) Deactivate(ctx context.Context, id uuid.UUID) error {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if !user.IsActive {
		return nil // Already inactive
	}

	user.IsActive = false
	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("deactivate user: %w", err)
	}

	s.logger.Info("user deactivated", "user_id", id)
	return nil
}

// Unlock unlocks a locked user account.
func (s *Service) Unlock(ctx context.Context, id uuid.UUID) error {
	if err := s.userRepo.Unlock(ctx, id); err != nil {
		return fmt.Errorf("unlock user: %w", err)
	}

	s.logger.Info("user unlocked", "user_id", id)
	return nil
}

// ============================================================================
// API Key Management
// ============================================================================

// CreateAPIKey creates a new API key for a user.
func (s *Service) CreateAPIKey(ctx context.Context, userID uuid.UUID, name string, expiresAt *time.Time) (*models.APIKeyWithSecret, error) {
	// Check user exists
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Check global API keys limit (license)
	s.limitMu.RLock()
	lp := s.limitProvider
	s.limitMu.RUnlock()
	if lp != nil {
		limit := lp.GetLimits().MaxAPIKeys
		if limit > 0 {
			globalCount, err := s.apiKeyRepo.CountAll(ctx)
			if err != nil {
				return nil, fmt.Errorf("count API keys: %w", err)
			}
			if int(globalCount) >= limit {
				return nil, apperrors.NewWithStatus(apperrors.CodeLimitExceeded,
					fmt.Sprintf("global API key limit reached (%d/%d), upgrade your license for more", globalCount, limit), 402)
			}
		}
	}

	// Check max API keys per-user limit
	if s.config.MaxAPIKeysPerUser > 0 {
		count, err := s.apiKeyRepo.CountByUserID(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("count API keys: %w", err)
		}
		if int(count) >= s.config.MaxAPIKeysPerUser {
			return nil, apperrors.InvalidInput(fmt.Sprintf("maximum of %d API keys per user allowed", s.config.MaxAPIKeysPerUser))
		}
	}

	// Check name uniqueness
	exists, err := s.apiKeyRepo.ExistsByName(ctx, userID, name)
	if err != nil {
		return nil, fmt.Errorf("check API key name: %w", err)
	}
	if exists {
		return nil, apperrors.AlreadyExists("API key with this name")
	}

	// Generate API key
	rawKey, err := generateAPIKey(s.config.APIKeyLength)
	if err != nil {
		return nil, fmt.Errorf("generate API key: %w", err)
	}

	// Create API key record
	apiKey := &models.APIKey{
		ID:        uuid.New(),
		UserID:    userID,
		Name:      strings.TrimSpace(name),
		KeyHash:   crypto.HashAPIKey(rawKey),
		Prefix:    rawKey[:8], // First 8 chars for identification
		ExpiresAt: expiresAt,
	}

	if err := s.apiKeyRepo.Create(ctx, apiKey); err != nil {
		return nil, fmt.Errorf("create API key: %w", err)
	}

	s.logger.Info("API key created",
		"key_id", apiKey.ID,
		"user_id", userID,
		"username", user.Username,
		"name", name,
	)

	return &models.APIKeyWithSecret{
		APIKey: *apiKey,
		Key:    rawKey,
	}, nil
}

// generateAPIKey generates a new API key with configurable byte length.
func generateAPIKey(length int) (string, error) {
	if length <= 0 {
		length = 32
	}
	token, err := crypto.RandomHex(length)
	if err != nil {
		return "", err
	}
	// Prefix with "usn_" for easy identification
	return "usn_" + token, nil
}

// ListAPIKeys lists all API keys for a user.
func (s *Service) ListAPIKeys(ctx context.Context, userID uuid.UUID) ([]*models.APIKey, error) {
	return s.apiKeyRepo.ListByUserID(ctx, userID)
}

// DeleteAPIKey deletes an API key.
func (s *Service) DeleteAPIKey(ctx context.Context, userID, keyID uuid.UUID) error {
	// Get API key
	apiKey, err := s.apiKeyRepo.GetByID(ctx, keyID)
	if err != nil {
		return err
	}

	// Verify ownership
	if apiKey.UserID != userID {
		return apperrors.Forbidden("API key does not belong to user")
	}

	if err := s.apiKeyRepo.Delete(ctx, keyID); err != nil {
		return fmt.Errorf("delete API key: %w", err)
	}

	s.logger.Info("API key deleted",
		"key_id", keyID,
		"user_id", userID,
	)

	return nil
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats retrieves user statistics.
func (s *Service) GetStats(ctx context.Context) (*postgres.UserStats, error) {
	return s.userRepo.GetStats(ctx)
}

// GetRoleCounts retrieves user counts by role.
func (s *Service) GetRoleCounts(ctx context.Context) (map[models.UserRole]int64, error) {
	return s.userRepo.CountByRole(ctx)
}

// ============================================================================
// Profile Management (self-service)
// ============================================================================

// UpdateProfileInput contains input for updating user's own profile.
type UpdateProfileInput struct {
	Email *string
}

// UpdateProfile updates a user's own profile.
func (s *Service) UpdateProfile(ctx context.Context, userID uuid.UUID, input UpdateProfileInput) (*models.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Only allow updating email for self
	if input.Email != nil {
		email := strings.TrimSpace(strings.ToLower(*input.Email))
		if email != "" {
			if !isValidEmail(email) {
				return nil, apperrors.InvalidInput("invalid email format")
			}

			// Check if email is taken
			existingUser, err := s.userRepo.GetByEmail(ctx, email)
			if err == nil && existingUser.ID != userID {
				return nil, apperrors.AlreadyExists("email")
			}
		}
		if email == "" {
			user.Email = nil
		} else {
			user.Email = &email
		}
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("update profile: %w", err)
	}

	s.logger.Info("profile updated", "user_id", userID)

	return user, nil
}

// ============================================================================
// User Response (API-safe)
// ============================================================================

// UserResponse is the API-safe representation of a user.
type UserResponse struct {
	ID          uuid.UUID       `json:"id"`
	Username    string          `json:"username"`
	Email       *string         `json:"email,omitempty"`
	Role        models.UserRole `json:"role"`
	IsActive    bool            `json:"is_active"`
	IsLDAP      bool            `json:"is_ldap"`
	IsLocked    bool            `json:"is_locked"`
	LastLoginAt *time.Time      `json:"last_login_at,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// ToResponse converts a user to API-safe response.
func ToResponse(user *models.User) *UserResponse {
	return &UserResponse{
		ID:          user.ID,
		Username:    user.Username,
		Email:       user.Email,
		Role:        user.Role,
		IsActive:    user.IsActive,
		IsLDAP:      user.IsLDAP,
		IsLocked:    user.IsLocked(),
		LastLoginAt: user.LastLoginAt,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
	}
}

// ToResponseList converts users to API-safe response list.
func ToResponseList(users []*models.User) []*UserResponse {
	result := make([]*UserResponse, len(users))
	for i, user := range users {
		result[i] = ToResponse(user)
	}
	return result
}

// APIKeyResponse is the API-safe representation of an API key.
type APIKeyResponse struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	IsExpired  bool       `json:"is_expired"`
}

// ToAPIKeyResponse converts an API key to API-safe response.
func ToAPIKeyResponse(key *models.APIKey) *APIKeyResponse {
	return &APIKeyResponse{
		ID:         key.ID,
		Name:       key.Name,
		Prefix:     key.Prefix,
		LastUsedAt: key.LastUsedAt,
		ExpiresAt:  key.ExpiresAt,
		CreatedAt:  key.CreatedAt,
		IsExpired:  key.IsExpired(),
	}
}

// ToAPIKeyResponseList converts API keys to API-safe response list.
func ToAPIKeyResponseList(keys []*models.APIKey) []*APIKeyResponse {
	result := make([]*APIKeyResponse, len(keys))
	for i, key := range keys {
		result[i] = ToAPIKeyResponse(key)
	}
	return result
}
