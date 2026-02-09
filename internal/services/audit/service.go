// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package audit

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// Resource types for audit logging
const (
	ResourceTypeUser      = "user"
	ResourceTypeSession   = "session"
	ResourceTypeAPIKey    = "api_key"
	ResourceTypeContainer = "container"
	ResourceTypeImage     = "image"
	ResourceTypeVolume    = "volume"
	ResourceTypeNetwork   = "network"
	ResourceTypeStack     = "stack"
	ResourceTypeHost      = "host"
	ResourceTypeBackup    = "backup"
	ResourceTypeConfig    = "config"
	ResourceTypeTeam      = "team"
	ResourceTypeProxy     = "proxy"
	ResourceTypeSecurity  = "security"
)

// Service handles audit logging operations
type Service struct {
	repo   *postgres.AuditLogRepository
	logger *logger.Logger
	config Config
}

// Config contains configuration for the audit service
type Config struct {
	// Enabled controls whether audit logging is active
	Enabled bool

	// RetentionDays is how long to keep audit logs (0 = forever)
	RetentionDays int

	// CleanupInterval is how often to run cleanup
	CleanupInterval time.Duration
}

// DefaultConfig returns default audit configuration
func DefaultConfig() Config {
	return Config{
		Enabled:         true,
		RetentionDays:   90,
		CleanupInterval: 24 * time.Hour,
	}
}

// NewService creates a new audit service
func NewService(repo *postgres.AuditLogRepository, log *logger.Logger, config Config) *Service {
	if log == nil {
		log = logger.Nop()
	}

	return &Service{
		repo:   repo,
		logger: log.Named("audit"),
		config: config,
	}
}

// LogEntry represents an entry to be logged
type LogEntry struct {
	UserID       *uuid.UUID
	Username     *string
	Action       string
	ResourceType string
	ResourceID   *string
	Details      map[string]any
	IPAddress    *string
	UserAgent    *string
	Success      bool
	ErrorMsg     *string
}

// Log creates a new audit log entry
func (s *Service) Log(ctx context.Context, entry LogEntry) error {
	if !s.config.Enabled {
		return nil
	}

	input := &postgres.CreateAuditLogInput{
		UserID:       entry.UserID,
		Username:     entry.Username,
		Action:       entry.Action,
		ResourceType: entry.ResourceType,
		ResourceID:   entry.ResourceID,
		Details:      entry.Details,
		IPAddress:    entry.IPAddress,
		UserAgent:    entry.UserAgent,
		Success:      entry.Success,
		ErrorMsg:     entry.ErrorMsg,
	}

	if err := s.repo.Create(ctx, input); err != nil {
		s.logger.Error("failed to create audit log entry",
			"action", entry.Action,
			"resource_type", entry.ResourceType,
			"error", err,
		)
		// Don't return error - audit logging should not break the main operation
		return nil
	}

	return nil
}

// LogAsync logs an entry asynchronously (fire-and-forget)
func (s *Service) LogAsync(ctx context.Context, entry LogEntry) {
	go func() {
		// Create a new context since the original might be cancelled
		bgCtx := context.Background()
		_ = s.Log(bgCtx, entry)
	}()
}

// ============================================================================
// Convenience methods for common audit actions
// ============================================================================

// LogLogin logs a login attempt
func (s *Service) LogLogin(ctx context.Context, userID *uuid.UUID, username, ip, userAgent string, success bool, errorMsg *string) {
	action := models.AuditActionLogin
	if !success {
		action = models.AuditActionLoginFailed
	}

	s.LogAsync(ctx, LogEntry{
		UserID:       userID,
		Username:     &username,
		Action:       action,
		ResourceType: ResourceTypeSession,
		IPAddress:    &ip,
		UserAgent:    &userAgent,
		Success:      success,
		ErrorMsg:     errorMsg,
	})
}

// LogLogout logs a logout
func (s *Service) LogLogout(ctx context.Context, userID uuid.UUID, username, ip, userAgent string) {
	s.LogAsync(ctx, LogEntry{
		UserID:       &userID,
		Username:     &username,
		Action:       models.AuditActionLogout,
		ResourceType: ResourceTypeSession,
		IPAddress:    &ip,
		UserAgent:    &userAgent,
		Success:      true,
	})
}

// LogPasswordChange logs a password change
func (s *Service) LogPasswordChange(ctx context.Context, userID uuid.UUID, username, ip, userAgent string, success bool) {
	s.LogAsync(ctx, LogEntry{
		UserID:       &userID,
		Username:     &username,
		Action:       models.AuditActionPasswordChange,
		ResourceType: ResourceTypeUser,
		ResourceID:   ptr(userID.String()),
		IPAddress:    &ip,
		UserAgent:    &userAgent,
		Success:      success,
	})
}

// LogPasswordReset logs a password reset request or completion
func (s *Service) LogPasswordReset(ctx context.Context, userID *uuid.UUID, email, ip, userAgent string, success bool, errorMsg *string) {
	var resourceID *string
	var username *string
	if userID != nil {
		resourceID = ptr(userID.String())
	}
	if email != "" {
		username = &email
	}

	s.LogAsync(ctx, LogEntry{
		UserID:       userID,
		Username:     username,
		Action:       models.AuditActionPasswordReset,
		ResourceType: ResourceTypeUser,
		ResourceID:   resourceID,
		Details: map[string]any{
			"email": email,
		},
		IPAddress: &ip,
		UserAgent: &userAgent,
		Success:   success,
		ErrorMsg:  errorMsg,
	})
}

// LogUserCreate logs user creation
func (s *Service) LogUserCreate(ctx context.Context, actorID uuid.UUID, actorUsername string, targetUserID uuid.UUID, targetUsername, ip, userAgent string) {
	s.LogAsync(ctx, LogEntry{
		UserID:       &actorID,
		Username:     &actorUsername,
		Action:       models.AuditActionCreate,
		ResourceType: ResourceTypeUser,
		ResourceID:   ptr(targetUserID.String()),
		Details: map[string]any{
			"target_username": targetUsername,
		},
		IPAddress: &ip,
		UserAgent: &userAgent,
		Success:   true,
	})
}

// LogUserUpdate logs user update
func (s *Service) LogUserUpdate(ctx context.Context, actorID uuid.UUID, actorUsername string, targetUserID uuid.UUID, changes map[string]any, ip, userAgent string) {
	s.LogAsync(ctx, LogEntry{
		UserID:       &actorID,
		Username:     &actorUsername,
		Action:       models.AuditActionUpdate,
		ResourceType: ResourceTypeUser,
		ResourceID:   ptr(targetUserID.String()),
		Details:      changes,
		IPAddress:    &ip,
		UserAgent:    &userAgent,
		Success:      true,
	})
}

// LogUserDelete logs user deletion
func (s *Service) LogUserDelete(ctx context.Context, actorID uuid.UUID, actorUsername string, targetUserID uuid.UUID, targetUsername, ip, userAgent string) {
	s.LogAsync(ctx, LogEntry{
		UserID:       &actorID,
		Username:     &actorUsername,
		Action:       models.AuditActionDelete,
		ResourceType: ResourceTypeUser,
		ResourceID:   ptr(targetUserID.String()),
		Details: map[string]any{
			"target_username": targetUsername,
		},
		IPAddress: &ip,
		UserAgent: &userAgent,
		Success:   true,
	})
}

// LogAPIKeyCreate logs API key creation
func (s *Service) LogAPIKeyCreate(ctx context.Context, userID uuid.UUID, username string, keyID uuid.UUID, keyName, ip, userAgent string) {
	s.LogAsync(ctx, LogEntry{
		UserID:       &userID,
		Username:     &username,
		Action:       models.AuditActionAPIKeyCreate,
		ResourceType: ResourceTypeAPIKey,
		ResourceID:   ptr(keyID.String()),
		Details: map[string]any{
			"key_name": keyName,
		},
		IPAddress: &ip,
		UserAgent: &userAgent,
		Success:   true,
	})
}

// LogAPIKeyDelete logs API key deletion
func (s *Service) LogAPIKeyDelete(ctx context.Context, userID uuid.UUID, username string, keyID uuid.UUID, keyName, ip, userAgent string) {
	s.LogAsync(ctx, LogEntry{
		UserID:       &userID,
		Username:     &username,
		Action:       models.AuditActionAPIKeyDelete,
		ResourceType: ResourceTypeAPIKey,
		ResourceID:   ptr(keyID.String()),
		Details: map[string]any{
			"key_name": keyName,
		},
		IPAddress: &ip,
		UserAgent: &userAgent,
		Success:   true,
	})
}

// LogResourceAction logs a generic resource action
func (s *Service) LogResourceAction(ctx context.Context, userID uuid.UUID, username, action, resourceType, resourceID, resourceName, ip, userAgent string, success bool, details map[string]any) {
	if details == nil {
		details = make(map[string]any)
	}
	if resourceName != "" {
		details["resource_name"] = resourceName
	}

	s.LogAsync(ctx, LogEntry{
		UserID:       &userID,
		Username:     &username,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   &resourceID,
		Details:      details,
		IPAddress:    &ip,
		UserAgent:    &userAgent,
		Success:      success,
	})
}

// ============================================================================
// Query methods
// ============================================================================

// List retrieves audit logs with filtering
func (s *Service) List(ctx context.Context, opts postgres.AuditLogListOptions) ([]*models.AuditLogEntry, int, error) {
	return s.repo.List(ctx, opts)
}

// GetByUser retrieves audit logs for a user
func (s *Service) GetByUser(ctx context.Context, userID uuid.UUID, limit int) ([]*models.AuditLogEntry, error) {
	return s.repo.GetByUser(ctx, userID, limit)
}

// GetByResource retrieves audit logs for a resource
func (s *Service) GetByResource(ctx context.Context, resourceType, resourceID string, limit int) ([]*models.AuditLogEntry, error) {
	return s.repo.GetByResource(ctx, resourceType, resourceID, limit)
}

// GetRecent retrieves recent audit logs
func (s *Service) GetRecent(ctx context.Context, limit int) ([]*models.AuditLogEntry, error) {
	return s.repo.GetRecent(ctx, limit)
}

// GetStats retrieves audit log statistics
func (s *Service) GetStats(ctx context.Context, since time.Time) (map[string]int, error) {
	return s.repo.GetStats(ctx, since)
}

// ============================================================================
// Cleanup
// ============================================================================

// StartCleanupWorker starts a background worker to clean up old logs
func (s *Service) StartCleanupWorker(ctx context.Context) {
	if s.config.RetentionDays <= 0 {
		s.logger.Info("audit log retention disabled (keeping forever)")
		return
	}

	go func() {
		ticker := time.NewTicker(s.config.CleanupInterval)
		defer ticker.Stop()

		// Run initial cleanup
		s.cleanup(ctx)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.cleanup(ctx)
			}
		}
	}()

	s.logger.Info("audit log cleanup worker started",
		"retention_days", s.config.RetentionDays,
		"cleanup_interval", s.config.CleanupInterval,
	)
}

func (s *Service) cleanup(ctx context.Context) {
	before := time.Now().AddDate(0, 0, -s.config.RetentionDays)
	count, err := s.repo.DeleteOlderThan(ctx, before)
	if err != nil {
		s.logger.Error("audit log cleanup failed", "error", err)
		return
	}
	if count > 0 {
		s.logger.Info("audit logs cleaned up", "count", count, "older_than", before)
	}
}

// ptr returns a pointer to a string
func ptr(s string) *string {
	return &s
}
