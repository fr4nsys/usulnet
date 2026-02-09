// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package passwordreset

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

const (
	// DefaultTokenExpiration is the default expiration time for password reset tokens
	DefaultTokenExpiration = 1 * time.Hour
	// MaxTokensPerUser is the maximum number of active reset tokens per user
	MaxTokensPerUser = 3
)

// UserRepository defines the interface for user operations needed by password reset
type UserRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error
}

// EmailSender defines the interface for sending password reset emails
type EmailSender interface {
	SendPasswordResetEmail(ctx context.Context, email, username, resetToken string, expiresAt time.Time) error
}

// AuditLogger defines the interface for audit logging
type AuditLogger interface {
	LogPasswordReset(ctx context.Context, userID *uuid.UUID, email, ip, userAgent string, success bool, errorMsg *string)
}

// Config holds configuration for password reset service
type Config struct {
	TokenExpiration time.Duration
	ResetURL        string // Base URL for password reset (e.g., https://example.com/reset-password)
	PasswordPolicy  *crypto.PasswordPolicy
}

// Service handles password reset operations
type Service struct {
	resetRepo      *postgres.PasswordResetRepository
	userRepo       UserRepository
	emailSender    EmailSender
	auditLogger    AuditLogger
	passwordPolicy *crypto.PasswordPolicy
	config         Config
	logger         *logger.Logger
}

// NewService creates a new password reset service
func NewService(
	resetRepo *postgres.PasswordResetRepository,
	userRepo UserRepository,
	emailSender EmailSender,
	auditLogger AuditLogger,
	config Config,
	log *logger.Logger,
) *Service {
	if config.TokenExpiration == 0 {
		config.TokenExpiration = DefaultTokenExpiration
	}

	if config.PasswordPolicy == nil {
		policy := crypto.DefaultPasswordPolicy()
		config.PasswordPolicy = &policy
	}

	return &Service{
		resetRepo:      resetRepo,
		userRepo:       userRepo,
		emailSender:    emailSender,
		auditLogger:    auditLogger,
		passwordPolicy: config.PasswordPolicy,
		config:         config,
		logger:         log.Named("password_reset"),
	}
}

// RequestResetInput represents input for requesting a password reset
type RequestResetInput struct {
	Email     string
	IP        string
	UserAgent string
}

// RequestResetResult represents the result of a password reset request
type RequestResetResult struct {
	Success bool
	Message string
}

// RequestReset initiates a password reset request
// Note: Always returns success to prevent email enumeration attacks
func (s *Service) RequestReset(ctx context.Context, input RequestResetInput) (*RequestResetResult, error) {
	// Always return the same message to prevent email enumeration
	successResult := &RequestResetResult{
		Success: true,
		Message: "If an account exists with this email, a password reset link has been sent.",
	}

	// Look up user by email
	user, err := s.userRepo.GetByEmail(ctx, input.Email)
	if err != nil {
		// Log but don't reveal to user
		s.logger.Debug("password reset requested for non-existent email", "email", input.Email)
		return successResult, nil
	}

	// Check if user is active
	if !user.IsActive {
		s.logger.Debug("password reset requested for inactive user", "email", input.Email)
		return successResult, nil
	}

	// Generate reset token
	token, err := s.resetRepo.Create(ctx, user.ID, s.config.TokenExpiration)
	if err != nil {
		s.logger.Error("failed to create password reset token", "error", err, "user_id", user.ID)
		// Still return success to prevent enumeration
		return successResult, nil
	}

	// Calculate expiration time
	expiresAt := time.Now().Add(s.config.TokenExpiration)

	// Get user email (may be nil)
	userEmail := ""
	if user.Email != nil {
		userEmail = *user.Email
	}

	// Send reset email
	if s.emailSender != nil && userEmail != "" {
		err = s.emailSender.SendPasswordResetEmail(ctx, userEmail, user.Username, token, expiresAt)
		if err != nil {
			s.logger.Error("failed to send password reset email", "error", err, "user_id", user.ID)
			// We still consider this a success from the user's perspective
		}
	} else if s.emailSender == nil {
		s.logger.Warn("no email sender configured, token generated but not sent", "user_id", user.ID)
	}

	// Log the reset request
	if s.auditLogger != nil {
		s.auditLogger.LogPasswordReset(ctx, &user.ID, userEmail, input.IP, input.UserAgent, true, nil)
	}

	s.logger.Info("password reset token generated", "user_id", user.ID, "email", userEmail)

	return successResult, nil
}

// ValidateTokenInput represents input for validating a reset token
type ValidateTokenInput struct {
	Token string
}

// ValidateTokenResult represents the result of token validation
type ValidateTokenResult struct {
	Valid  bool
	UserID uuid.UUID
}

// ValidateToken validates a password reset token
func (s *Service) ValidateToken(ctx context.Context, input ValidateTokenInput) (*ValidateTokenResult, error) {
	userID, err := s.resetRepo.ValidateToken(ctx, input.Token)
	if err != nil {
		return &ValidateTokenResult{Valid: false}, nil
	}

	return &ValidateTokenResult{
		Valid:  true,
		UserID: userID,
	}, nil
}

// ResetPasswordInput represents input for resetting a password
type ResetPasswordInput struct {
	Token           string
	NewPassword     string
	ConfirmPassword string
	IP              string
	UserAgent       string
}

// ResetPasswordResult represents the result of a password reset
type ResetPasswordResult struct {
	Success          bool
	Message          string
	ValidationErrors []string
}

// ResetPassword completes the password reset process
func (s *Service) ResetPassword(ctx context.Context, input ResetPasswordInput) (*ResetPasswordResult, error) {
	// Validate passwords match
	if input.NewPassword != input.ConfirmPassword {
		return &ResetPasswordResult{
			Success:          false,
			Message:          "Passwords do not match",
			ValidationErrors: []string{"Passwords do not match"},
		}, nil
	}

	// Validate the token
	userID, err := s.resetRepo.ValidateToken(ctx, input.Token)
	if err != nil {
		errMsg := "Invalid or expired reset token"
		if s.auditLogger != nil {
			s.auditLogger.LogPasswordReset(ctx, nil, "", input.IP, input.UserAgent, false, &errMsg)
		}
		return &ResetPasswordResult{
			Success:          false,
			Message:          errMsg,
			ValidationErrors: []string{errMsg},
		}, nil
	}

	// Get user for password validation
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("failed to get user for password reset", "error", err, "user_id", userID)
		return &ResetPasswordResult{
			Success: false,
			Message: "Unable to complete password reset",
		}, nil
	}

	// Get user email (may be nil)
	userEmail := ""
	if user.Email != nil {
		userEmail = *user.Email
	}

	// Validate password against policy
	if s.passwordPolicy != nil {
		result := s.passwordPolicy.ValidatePassword(input.NewPassword, user.Username)
		if !result.Valid {
			if s.auditLogger != nil {
				errMsg := "Password does not meet requirements"
				s.auditLogger.LogPasswordReset(ctx, &userID, userEmail, input.IP, input.UserAgent, false, &errMsg)
			}
			return &ResetPasswordResult{
				Success:          false,
				Message:          "Password does not meet requirements",
				ValidationErrors: result.Errors,
			}, nil
		}
	}

	// Hash the new password
	passwordHash, err := crypto.HashPassword(input.NewPassword)
	if err != nil {
		s.logger.Error("failed to hash password", "error", err)
		return &ResetPasswordResult{
			Success: false,
			Message: "Unable to complete password reset",
		}, nil
	}

	// Update the user's password
	err = s.userRepo.UpdatePassword(ctx, userID, passwordHash)
	if err != nil {
		s.logger.Error("failed to update password", "error", err, "user_id", userID)
		errMsg := "Failed to update password"
		if s.auditLogger != nil {
			s.auditLogger.LogPasswordReset(ctx, &userID, userEmail, input.IP, input.UserAgent, false, &errMsg)
		}
		return &ResetPasswordResult{
			Success: false,
			Message: "Unable to complete password reset",
		}, nil
	}

	// Mark the token as used
	err = s.resetRepo.MarkAsUsed(ctx, input.Token)
	if err != nil {
		s.logger.Warn("failed to mark token as used", "error", err)
		// Don't fail the reset, password was already updated
	}

	// Invalidate all other reset tokens for this user
	err = s.resetRepo.InvalidateAllForUser(ctx, userID)
	if err != nil {
		s.logger.Warn("failed to invalidate other tokens", "error", err)
	}

	// Log successful reset
	if s.auditLogger != nil {
		s.auditLogger.LogPasswordReset(ctx, &userID, userEmail, input.IP, input.UserAgent, true, nil)
	}

	s.logger.Info("password reset completed", "user_id", userID)

	return &ResetPasswordResult{
		Success: true,
		Message: "Password has been reset successfully",
	}, nil
}

// CleanupExpiredTokens removes expired tokens from the database
func (s *Service) CleanupExpiredTokens(ctx context.Context) (int64, error) {
	count, err := s.resetRepo.DeleteExpired(ctx)
	if err != nil {
		return 0, err
	}

	if count > 0 {
		s.logger.Info("cleaned up expired password reset tokens", "count", count)
	}

	return count, nil
}
