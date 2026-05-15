// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package passwordreset

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ---------------------------------------------------------------------------
// Mock dependencies
// ---------------------------------------------------------------------------

type mockUserRepo struct {
	users    map[uuid.UUID]*models.User
	byEmail  map[string]*models.User
	updatePW map[uuid.UUID]string
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{
		users:    make(map[uuid.UUID]*models.User),
		byEmail:  make(map[string]*models.User),
		updatePW: make(map[uuid.UUID]string),
	}
}

func (r *mockUserRepo) GetByID(_ context.Context, id uuid.UUID) (*models.User, error) {
	if u, ok := r.users[id]; ok {
		return u, nil
	}
	return nil, errors.New("user not found")
}

func (r *mockUserRepo) GetByEmail(_ context.Context, email string) (*models.User, error) {
	if u, ok := r.byEmail[email]; ok {
		return u, nil
	}
	return nil, errors.New("user not found")
}

func (r *mockUserRepo) UpdatePassword(_ context.Context, userID uuid.UUID, hash string) error {
	r.updatePW[userID] = hash
	return nil
}

func (r *mockUserRepo) addUser(u *models.User) {
	r.users[u.ID] = u
	if u.Email != nil {
		r.byEmail[*u.Email] = u
	}
}

type mockResetRepo struct {
	tokens       map[string]uuid.UUID
	created      []uuid.UUID
	markedUsed   []string
	invalidated  []uuid.UUID
	deletedCount int64
	createErr    error
	validateErr  error
}

func newMockResetRepo() *mockResetRepo {
	return &mockResetRepo{
		tokens: make(map[string]uuid.UUID),
	}
}

func (r *mockResetRepo) Create(_ context.Context, userID uuid.UUID, _ time.Duration) (string, error) {
	if r.createErr != nil {
		return "", r.createErr
	}
	token := "tok-" + uuid.New().String()[:8]
	r.tokens[token] = userID
	r.created = append(r.created, userID)
	return token, nil
}

func (r *mockResetRepo) ValidateToken(_ context.Context, token string) (uuid.UUID, error) {
	if r.validateErr != nil {
		return uuid.Nil, r.validateErr
	}
	if uid, ok := r.tokens[token]; ok {
		return uid, nil
	}
	return uuid.Nil, errors.New("invalid token")
}

func (r *mockResetRepo) MarkAsUsed(_ context.Context, token string) error {
	r.markedUsed = append(r.markedUsed, token)
	return nil
}

func (r *mockResetRepo) InvalidateAllForUser(_ context.Context, userID uuid.UUID) error {
	r.invalidated = append(r.invalidated, userID)
	return nil
}

func (r *mockResetRepo) DeleteExpired(_ context.Context) (int64, error) {
	return r.deletedCount, nil
}

type mockEmailSender struct {
	sentTo []string
	err    error
}

func (s *mockEmailSender) SendPasswordResetEmail(_ context.Context, email, _, _ string, _ time.Time) error {
	if s.err != nil {
		return s.err
	}
	s.sentTo = append(s.sentTo, email)
	return nil
}

type mockAuditLogger struct {
	logs []auditEntry
}

type auditEntry struct {
	UserID  *uuid.UUID
	Email   string
	Success bool
}

func (l *mockAuditLogger) LogPasswordReset(_ context.Context, userID *uuid.UUID, email, _, _ string, success bool, _ *string) {
	l.logs = append(l.logs, auditEntry{UserID: userID, Email: email, Success: success})
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newTestService(t *testing.T) (*Service, *mockUserRepo, *mockResetRepo, *mockEmailSender, *mockAuditLogger) {
	t.Helper()
	userRepo := newMockUserRepo()
	resetRepo := newMockResetRepo()
	emailSender := &mockEmailSender{}
	audit := &mockAuditLogger{}
	log := logger.Nop()

	policy := crypto.DefaultPasswordPolicy()
	cfg := Config{
		TokenExpiration: 1 * time.Hour,
		ResetURL:        "https://example.com/reset",
		PasswordPolicy:  &policy,
	}

	svc := NewService(resetRepo, userRepo, emailSender, audit, cfg, log)

	return svc, userRepo, resetRepo, emailSender, audit
}

func testUser() *models.User {
	id := uuid.New()
	email := "user@example.com"
	return &models.User{
		ID:       id,
		Username: "testuser",
		Email:    &email,
		IsActive: true,
	}
}

// ---------------------------------------------------------------------------
// Tests: Config
// ---------------------------------------------------------------------------

func TestConfig_Defaults(t *testing.T) {
	cfg := Config{}
	log := logger.Nop()
	svc := NewService(newMockResetRepo(), newMockUserRepo(), nil, nil, cfg, log)

	if svc.config.TokenExpiration != DefaultTokenExpiration {
		t.Errorf("expected default token expiration %v, got %v", DefaultTokenExpiration, svc.config.TokenExpiration)
	}
	if svc.passwordPolicy == nil {
		t.Error("expected default password policy")
	}
}

func TestDefaultTokenExpiration(t *testing.T) {
	if DefaultTokenExpiration != 1*time.Hour {
		t.Errorf("expected 1 hour default, got %v", DefaultTokenExpiration)
	}
}

func TestMaxTokensPerUser(t *testing.T) {
	if MaxTokensPerUser != 3 {
		t.Errorf("expected max 3 tokens per user, got %d", MaxTokensPerUser)
	}
}

// ---------------------------------------------------------------------------
// Tests: RequestReset
// ---------------------------------------------------------------------------

func TestRequestReset_Success(t *testing.T) {
	svc, userRepo, resetRepo, emailSender, audit := newTestService(t)
	ctx := context.Background()

	user := testUser()
	userRepo.addUser(user)

	result, err := svc.RequestReset(ctx, RequestResetInput{
		Email:     *user.Email,
		IP:        "192.168.1.1",
		UserAgent: "test-agent",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if len(resetRepo.created) != 1 {
		t.Errorf("expected 1 token created, got %d", len(resetRepo.created))
	}
	if resetRepo.created[0] != user.ID {
		t.Error("token created for wrong user")
	}
	if len(emailSender.sentTo) != 1 || emailSender.sentTo[0] != *user.Email {
		t.Error("expected reset email sent to user")
	}
	if len(audit.logs) != 1 || !audit.logs[0].Success {
		t.Error("expected successful audit log")
	}
}

func TestRequestReset_NonExistentEmail(t *testing.T) {
	svc, _, resetRepo, _, _ := newTestService(t)
	ctx := context.Background()

	// Should still return success to prevent email enumeration
	result, err := svc.RequestReset(ctx, RequestResetInput{
		Email: "nonexistent@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success even for non-existent email")
	}
	if len(resetRepo.created) != 0 {
		t.Error("should not create token for non-existent user")
	}
}

func TestRequestReset_InactiveUser(t *testing.T) {
	svc, userRepo, resetRepo, _, _ := newTestService(t)
	ctx := context.Background()

	user := testUser()
	user.IsActive = false
	userRepo.addUser(user)

	result, err := svc.RequestReset(ctx, RequestResetInput{Email: *user.Email})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success even for inactive user (anti-enumeration)")
	}
	if len(resetRepo.created) != 0 {
		t.Error("should not create token for inactive user")
	}
}

func TestRequestReset_CreateTokenError(t *testing.T) {
	svc, userRepo, resetRepo, _, _ := newTestService(t)
	ctx := context.Background()

	user := testUser()
	userRepo.addUser(user)
	resetRepo.createErr = errors.New("db error")

	result, err := svc.RequestReset(ctx, RequestResetInput{Email: *user.Email})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success even on token creation failure (anti-enumeration)")
	}
}

// ---------------------------------------------------------------------------
// Tests: ValidateToken
// ---------------------------------------------------------------------------

func TestValidateToken_Valid(t *testing.T) {
	svc, _, resetRepo, _, _ := newTestService(t)
	ctx := context.Background()

	userID := uuid.New()
	resetRepo.tokens["valid-token"] = userID

	result, err := svc.ValidateToken(ctx, ValidateTokenInput{Token: "valid-token"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Error("expected token to be valid")
	}
	if result.UserID != userID {
		t.Errorf("expected user ID %s, got %s", userID, result.UserID)
	}
}

func TestValidateToken_Invalid(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	result, err := svc.ValidateToken(ctx, ValidateTokenInput{Token: "bad-token"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Error("expected token to be invalid")
	}
}

// ---------------------------------------------------------------------------
// Tests: ResetPassword
// ---------------------------------------------------------------------------

func TestResetPassword_PasswordMismatch(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	result, err := svc.ResetPassword(ctx, ResetPasswordInput{
		Token:           "any-token",
		NewPassword:     "password1",
		ConfirmPassword: "password2",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("should fail on password mismatch")
	}
	if !strings.Contains(result.Message, "do not match") {
		t.Errorf("expected mismatch message, got %s", result.Message)
	}
}

func TestResetPassword_InvalidToken(t *testing.T) {
	svc, _, _, _, audit := newTestService(t)
	ctx := context.Background()

	result, err := svc.ResetPassword(ctx, ResetPasswordInput{
		Token:           "invalid-token",
		NewPassword:     "StrongP@ss1!",
		ConfirmPassword: "StrongP@ss1!",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("should fail on invalid token")
	}
	if !strings.Contains(result.Message, "Invalid or expired") {
		t.Errorf("expected invalid token message, got %s", result.Message)
	}
	// Audit log should record failure
	if len(audit.logs) == 0 || audit.logs[0].Success {
		t.Error("expected failed audit log for invalid token")
	}
}

func TestResetPassword_Success(t *testing.T) {
	svc, userRepo, resetRepo, _, audit := newTestService(t)
	ctx := context.Background()

	user := testUser()
	userRepo.addUser(user)
	resetRepo.tokens["good-token"] = user.ID

	result, err := svc.ResetPassword(ctx, ResetPasswordInput{
		Token:           "good-token",
		NewPassword:     "NewStr0ng!Pass",
		ConfirmPassword: "NewStr0ng!Pass",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got: %s (errors: %v)", result.Message, result.ValidationErrors)
	}
	// Verify password was updated
	if _, ok := userRepo.updatePW[user.ID]; !ok {
		t.Error("expected password to be updated")
	}
	// Verify token was marked as used
	if len(resetRepo.markedUsed) == 0 || resetRepo.markedUsed[0] != "good-token" {
		t.Error("expected token to be marked as used")
	}
	// Verify all other tokens invalidated
	if len(resetRepo.invalidated) == 0 || resetRepo.invalidated[0] != user.ID {
		t.Error("expected all tokens invalidated for user")
	}
	// Verify audit log
	found := false
	for _, entry := range audit.logs {
		if entry.Success && entry.UserID != nil && *entry.UserID == user.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected successful audit log entry")
	}
}

func TestResetPassword_WeakPassword(t *testing.T) {
	svc, userRepo, resetRepo, _, _ := newTestService(t)
	ctx := context.Background()

	user := testUser()
	userRepo.addUser(user)
	resetRepo.tokens["token-123"] = user.ID

	result, err := svc.ResetPassword(ctx, ResetPasswordInput{
		Token:           "token-123",
		NewPassword:     "weak",
		ConfirmPassword: "weak",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("should fail for weak password")
	}
	if len(result.ValidationErrors) == 0 {
		t.Error("expected validation errors")
	}
}

// ---------------------------------------------------------------------------
// Tests: CleanupExpiredTokens
// ---------------------------------------------------------------------------

func TestCleanupExpiredTokens(t *testing.T) {
	svc, _, resetRepo, _, _ := newTestService(t)
	ctx := context.Background()

	resetRepo.deletedCount = 5

	count, err := svc.CleanupExpiredTokens(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 5 {
		t.Errorf("expected 5 deleted, got %d", count)
	}
}

func TestCleanupExpiredTokens_Zero(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	count, err := svc.CleanupExpiredTokens(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 deleted, got %d", count)
	}
}
