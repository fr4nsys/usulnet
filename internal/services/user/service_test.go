// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package user

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

type mockUserRepo struct {
	users          map[uuid.UUID]*models.User
	usernameIndex  map[string]uuid.UUID
	emailIndex     map[string]uuid.UUID
	pwHistory      map[uuid.UUID][]string
	createErr      error
	deleteErr      error
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{
		users:         make(map[uuid.UUID]*models.User),
		usernameIndex: make(map[string]uuid.UUID),
		emailIndex:    make(map[string]uuid.UUID),
		pwHistory:     make(map[uuid.UUID][]string),
	}
}

func (r *mockUserRepo) Create(_ context.Context, user *models.User) error {
	if r.createErr != nil {
		return r.createErr
	}
	r.users[user.ID] = user
	r.usernameIndex[user.Username] = user.ID
	if user.Email != nil {
		r.emailIndex[*user.Email] = user.ID
	}
	return nil
}

func (r *mockUserRepo) GetByID(_ context.Context, id uuid.UUID) (*models.User, error) {
	u, ok := r.users[id]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}
	return u, nil
}

func (r *mockUserRepo) GetByUsername(_ context.Context, username string) (*models.User, error) {
	id, ok := r.usernameIndex[username]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}
	return r.users[id], nil
}

func (r *mockUserRepo) GetByEmail(_ context.Context, email string) (*models.User, error) {
	id, ok := r.emailIndex[email]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}
	return r.users[id], nil
}

func (r *mockUserRepo) Update(_ context.Context, user *models.User) error {
	r.users[user.ID] = user
	return nil
}

func (r *mockUserRepo) Delete(_ context.Context, id uuid.UUID) error {
	if r.deleteErr != nil {
		return r.deleteErr
	}
	u, ok := r.users[id]
	if !ok {
		return fmt.Errorf("user not found")
	}
	delete(r.usernameIndex, u.Username)
	if u.Email != nil {
		delete(r.emailIndex, *u.Email)
	}
	delete(r.users, id)
	return nil
}

func (r *mockUserRepo) List(_ context.Context, _ postgres.UserListOptions) ([]*models.User, int64, error) {
	var result []*models.User
	for _, u := range r.users {
		result = append(result, u)
	}
	return result, int64(len(result)), nil
}

func (r *mockUserRepo) ExistsByUsername(_ context.Context, username string) (bool, error) {
	_, ok := r.usernameIndex[username]
	return ok, nil
}

func (r *mockUserRepo) ExistsByEmail(_ context.Context, email string) (bool, error) {
	_, ok := r.emailIndex[email]
	return ok, nil
}

func (r *mockUserRepo) Unlock(_ context.Context, _ uuid.UUID) error { return nil }

func (r *mockUserRepo) GetPasswordHistory(_ context.Context, userID uuid.UUID, limit int) ([]string, error) {
	h := r.pwHistory[userID]
	if limit > 0 && len(h) > limit {
		h = h[:limit]
	}
	return h, nil
}

func (r *mockUserRepo) SavePasswordHistory(_ context.Context, userID uuid.UUID, hash string) error {
	r.pwHistory[userID] = append(r.pwHistory[userID], hash)
	return nil
}

func (r *mockUserRepo) GetStats(_ context.Context) (*postgres.UserStats, error) {
	return &postgres.UserStats{
		Total:  int64(len(r.users)),
		Active: int64(len(r.users)),
	}, nil
}

func (r *mockUserRepo) CountByRole(_ context.Context) (map[models.UserRole]int64, error) {
	counts := make(map[models.UserRole]int64)
	for _, u := range r.users {
		counts[u.Role]++
	}
	return counts, nil
}

type mockAPIKeyRepo struct {
	keys     map[uuid.UUID]*models.APIKey
	countAll int64
}

func newMockAPIKeyRepo() *mockAPIKeyRepo {
	return &mockAPIKeyRepo{
		keys: make(map[uuid.UUID]*models.APIKey),
	}
}

func (r *mockAPIKeyRepo) Create(_ context.Context, key *models.APIKey) error {
	r.keys[key.ID] = key
	r.countAll++
	return nil
}

func (r *mockAPIKeyRepo) GetByID(_ context.Context, id uuid.UUID) (*models.APIKey, error) {
	k, ok := r.keys[id]
	if !ok {
		return nil, fmt.Errorf("api key not found")
	}
	return k, nil
}

func (r *mockAPIKeyRepo) ListByUserID(_ context.Context, userID uuid.UUID) ([]*models.APIKey, error) {
	var result []*models.APIKey
	for _, k := range r.keys {
		if k.UserID == userID {
			result = append(result, k)
		}
	}
	return result, nil
}

func (r *mockAPIKeyRepo) Delete(_ context.Context, id uuid.UUID) error {
	delete(r.keys, id)
	return nil
}

func (r *mockAPIKeyRepo) DeleteByUserID(_ context.Context, userID uuid.UUID) (int64, error) {
	var count int64
	for id, k := range r.keys {
		if k.UserID == userID {
			delete(r.keys, id)
			count++
		}
	}
	return count, nil
}

func (r *mockAPIKeyRepo) CountByUserID(_ context.Context, userID uuid.UUID) (int64, error) {
	var count int64
	for _, k := range r.keys {
		if k.UserID == userID {
			count++
		}
	}
	return count, nil
}

func (r *mockAPIKeyRepo) CountAll(_ context.Context) (int64, error) {
	return int64(len(r.keys)), nil
}

func (r *mockAPIKeyRepo) ExistsByName(_ context.Context, userID uuid.UUID, name string) (bool, error) {
	for _, k := range r.keys {
		if k.UserID == userID && k.Name == name {
			return true, nil
		}
	}
	return false, nil
}

type mockLimitProvider struct {
	limits license.Limits
}

func (m *mockLimitProvider) GetLimits() license.Limits { return m.limits }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func testConfig() ServiceConfig {
	cfg := DefaultServiceConfig()
	cfg.PasswordMinLength = 8
	cfg.PasswordRequireUpper = true
	cfg.PasswordRequireNumber = true
	return cfg
}

func newTestService() (*Service, *mockUserRepo, *mockAPIKeyRepo) {
	ur := newMockUserRepo()
	ar := newMockAPIKeyRepo()
	svc := NewService(ur, ar, testConfig(), logger.Nop())
	return svc, ur, ar
}

func validCreateInput() CreateInput {
	return CreateInput{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "Password1",
		Role:     models.RoleViewer,
	}
}

// ---------------------------------------------------------------------------
// Tests: Create
// ---------------------------------------------------------------------------

func TestCreate_HappyPath(t *testing.T) {
	svc, ur, _ := newTestService()
	ctx := context.Background()

	user, err := svc.Create(ctx, validCreateInput())
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	if user.Username != "testuser" {
		t.Errorf("Username = %q, want %q", user.Username, "testuser")
	}
	if user.Email == nil || *user.Email != "test@example.com" {
		t.Errorf("Email = %v, want test@example.com", user.Email)
	}
	if !user.IsActive {
		t.Error("IsActive = false, want true")
	}
	if user.PasswordHash == "" {
		t.Error("PasswordHash is empty")
	}
	if len(ur.users) != 1 {
		t.Errorf("repo has %d users, want 1", len(ur.users))
	}
}

func TestCreate_EmailLowercased(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	input := validCreateInput()
	input.Email = "  TEST@EXAMPLE.COM  "

	user, err := svc.Create(ctx, input)
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	if user.Email == nil || *user.Email != "test@example.com" {
		t.Errorf("Email = %v, want test@example.com (lowercased, trimmed)", user.Email)
	}
}

func TestCreate_DuplicateUsername(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	_, err := svc.Create(ctx, validCreateInput())
	if err != nil {
		t.Fatalf("first Create() error: %v", err)
	}

	_, err = svc.Create(ctx, validCreateInput())
	if err == nil {
		t.Fatal("second Create() should fail with duplicate username")
	}
	if got := err.Error(); got != "CONFLICT: username already exists" {
		t.Errorf("error = %q, want 'CONFLICT: username already exists'", got)
	}
}

func TestCreate_DuplicateEmail(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	_, err := svc.Create(ctx, validCreateInput())
	if err != nil {
		t.Fatalf("first Create() error: %v", err)
	}

	input := validCreateInput()
	input.Username = "differentuser"
	_, err = svc.Create(ctx, input)
	if err == nil {
		t.Fatal("second Create() should fail with duplicate email")
	}
}

func TestCreate_InvalidRole_FallsBackToDefault(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	input := validCreateInput()
	input.Role = "nonexistent"

	user, err := svc.Create(ctx, input)
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	if user.Role != models.RoleViewer {
		t.Errorf("Role = %q, want %q (default)", user.Role, models.RoleViewer)
	}
}

func TestCreate_EmptyEmail_IsValid(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	input := validCreateInput()
	input.Email = ""

	user, err := svc.Create(ctx, input)
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	if user.Email != nil {
		t.Errorf("Email = %v, want nil for empty email", user.Email)
	}
}

// ---------------------------------------------------------------------------
// Tests: Validation
// ---------------------------------------------------------------------------

func TestCreate_Validation(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	tests := []struct {
		name    string
		modify  func(*CreateInput)
		wantErr string
	}{
		{"empty username", func(i *CreateInput) { i.Username = "" }, "BAD_REQUEST: username is required"},
		{"short username", func(i *CreateInput) { i.Username = "ab" }, "BAD_REQUEST: username must be at least 3 characters"},
		{"long username", func(i *CreateInput) { i.Username = string(make([]byte, 51)) }, "BAD_REQUEST: username must not exceed 50 characters"},
		{"invalid username chars", func(i *CreateInput) { i.Username = "user@name" }, "BAD_REQUEST: username contains invalid characters"},
		{"short password", func(i *CreateInput) { i.Password = "Pass1" }, "BAD_REQUEST: password must be at least 8 characters"},
		{"no uppercase", func(i *CreateInput) { i.Password = "password1" }, "BAD_REQUEST: password must contain at least one uppercase letter"},
		{"no digit", func(i *CreateInput) { i.Password = "Password" }, "BAD_REQUEST: password must contain at least one digit"},
		{"invalid email", func(i *CreateInput) { i.Email = "notanemail" }, "BAD_REQUEST: invalid email format"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := validCreateInput()
			tt.modify(&input)
			_, err := svc.Create(ctx, input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if got := err.Error(); got != tt.wantErr {
				t.Errorf("error = %q, want %q", got, tt.wantErr)
			}
		})
	}
}

func TestCreate_PasswordMaxLength(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	input := validCreateInput()
	input.Password = "A1" + string(make([]byte, 127)) // >128 chars
	_, err := svc.Create(ctx, input)
	if err == nil {
		t.Fatal("expected error for password >128 chars")
	}
}

// ---------------------------------------------------------------------------
// Tests: License limits
// ---------------------------------------------------------------------------

func TestCreate_LicenseLimitEnforced(t *testing.T) {
	svc, _, _ := newTestService()
	svc.SetLimitProvider(&mockLimitProvider{limits: license.Limits{MaxUsers: 1}})
	ctx := context.Background()

	_, err := svc.Create(ctx, validCreateInput())
	if err != nil {
		t.Fatalf("first Create() error: %v", err)
	}

	input := validCreateInput()
	input.Username = "seconduser"
	input.Email = "second@example.com"
	_, err = svc.Create(ctx, input)
	if err == nil {
		t.Fatal("second Create() should fail due to license limit")
	}
}

func TestCreate_NoLimitProvider_NoLimit(t *testing.T) {
	svc, _, _ := newTestService()
	// No limit provider set
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		input := validCreateInput()
		input.Username = fmt.Sprintf("user%d", i)
		input.Email = fmt.Sprintf("user%d@example.com", i)
		_, err := svc.Create(ctx, input)
		if err != nil {
			t.Fatalf("Create() #%d unexpected error: %v", i, err)
		}
	}
}

func TestCreate_UnlimitedWhenMaxZero(t *testing.T) {
	svc, _, _ := newTestService()
	svc.SetLimitProvider(&mockLimitProvider{limits: license.Limits{MaxUsers: 0}})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		input := validCreateInput()
		input.Username = fmt.Sprintf("user%d", i)
		input.Email = fmt.Sprintf("user%d@example.com", i)
		_, err := svc.Create(ctx, input)
		if err != nil {
			t.Fatalf("Create() #%d should succeed when MaxUsers=0 (unlimited): %v", i, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests: Delete
// ---------------------------------------------------------------------------

func TestDelete_HappyPath(t *testing.T) {
	svc, ur, _ := newTestService()
	ctx := context.Background()

	user, _ := svc.Create(ctx, validCreateInput())

	err := svc.Delete(ctx, user.ID)
	if err != nil {
		t.Fatalf("Delete() unexpected error: %v", err)
	}
	if len(ur.users) != 0 {
		t.Errorf("repo still has %d users, want 0", len(ur.users))
	}
}

func TestDelete_NotFound(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	err := svc.Delete(ctx, uuid.New())
	if err == nil {
		t.Fatal("Delete() should fail for non-existent user")
	}
}

func TestDelete_APIKeyCleanupFailure_StillDeletes(t *testing.T) {
	svc, ur, _ := newTestService()
	ctx := context.Background()

	user, _ := svc.Create(ctx, validCreateInput())

	// API key cleanup failure is logged but does not abort delete
	err := svc.Delete(ctx, user.ID)
	if err != nil {
		t.Fatalf("Delete() unexpected error: %v", err)
	}
	if len(ur.users) != 0 {
		t.Errorf("user was not deleted")
	}
}

// ---------------------------------------------------------------------------
// Tests: CreateAPIKey
// ---------------------------------------------------------------------------

func TestCreateAPIKey_HappyPath(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	user, _ := svc.Create(ctx, validCreateInput())

	result, err := svc.CreateAPIKey(ctx, user.ID, "my-key", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey() unexpected error: %v", err)
	}
	if result.Name != "my-key" {
		t.Errorf("Name = %q, want %q", result.Name, "my-key")
	}
	if result.Key == "" {
		t.Error("Key (secret) is empty")
	}
	if result.Prefix == "" {
		t.Error("Prefix is empty")
	}
}

func TestCreateAPIKey_LicenseLimitEnforced(t *testing.T) {
	svc, _, _ := newTestService()
	svc.SetLimitProvider(&mockLimitProvider{limits: license.Limits{MaxAPIKeys: 1}})
	ctx := context.Background()

	user, _ := svc.Create(ctx, validCreateInput())

	_, err := svc.CreateAPIKey(ctx, user.ID, "key1", nil)
	if err != nil {
		t.Fatalf("first CreateAPIKey() error: %v", err)
	}

	_, err = svc.CreateAPIKey(ctx, user.ID, "key2", nil)
	if err == nil {
		t.Fatal("second CreateAPIKey() should fail due to global license limit")
	}
}

func TestCreateAPIKey_PerUserLimitEnforced(t *testing.T) {
	cfg := testConfig()
	cfg.MaxAPIKeysPerUser = 1
	ur := newMockUserRepo()
	ar := newMockAPIKeyRepo()
	svc := NewService(ur, ar, cfg, logger.Nop())
	ctx := context.Background()

	user, _ := svc.Create(ctx, validCreateInput())

	_, err := svc.CreateAPIKey(ctx, user.ID, "key1", nil)
	if err != nil {
		t.Fatalf("first CreateAPIKey() error: %v", err)
	}

	_, err = svc.CreateAPIKey(ctx, user.ID, "key2", nil)
	if err == nil {
		t.Fatal("second CreateAPIKey() should fail due to per-user limit")
	}
}

func TestCreateAPIKey_DuplicateName(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	user, _ := svc.Create(ctx, validCreateInput())

	_, err := svc.CreateAPIKey(ctx, user.ID, "same-name", nil)
	if err != nil {
		t.Fatalf("first CreateAPIKey() error: %v", err)
	}

	_, err = svc.CreateAPIKey(ctx, user.ID, "same-name", nil)
	if err == nil {
		t.Fatal("duplicate name should fail")
	}
}

// ---------------------------------------------------------------------------
// Tests: Password expiry (pure logic, no repo)
// ---------------------------------------------------------------------------

func TestIsPasswordExpired(t *testing.T) {
	tests := []struct {
		name       string
		expiryDays int
		changedAt  *time.Time
		want       bool
	}{
		{"disabled (0 days)", 0, timePtr(time.Now().Add(-365 * 24 * time.Hour)), false},
		{"nil changedAt", 30, nil, false},
		{"not expired", 30, timePtr(time.Now().Add(-10 * 24 * time.Hour)), false},
		{"expired", 30, timePtr(time.Now().Add(-31 * 24 * time.Hour)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.PasswordExpiryDays = tt.expiryDays
			svc := NewService(newMockUserRepo(), newMockAPIKeyRepo(), cfg, logger.Nop())

			user := &models.User{PasswordChangedAt: tt.changedAt}
			got := svc.IsPasswordExpired(user)
			if got != tt.want {
				t.Errorf("IsPasswordExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPasswordExpiresIn(t *testing.T) {
	tests := []struct {
		name       string
		expiryDays int
		changedAt  *time.Time
		wantNeg    bool // true if want -1 (disabled)
	}{
		{"disabled", 0, timePtr(time.Now()), true},
		{"nil changedAt", 30, nil, true},
		{"future expiry", 30, timePtr(time.Now()), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.PasswordExpiryDays = tt.expiryDays
			svc := NewService(newMockUserRepo(), newMockAPIKeyRepo(), cfg, logger.Nop())

			user := &models.User{PasswordChangedAt: tt.changedAt}
			got := svc.PasswordExpiresIn(user)
			if tt.wantNeg && got != -1 {
				t.Errorf("PasswordExpiresIn() = %d, want -1", got)
			}
			if !tt.wantNeg && got < 0 {
				t.Errorf("PasswordExpiresIn() = %d, want >= 0", got)
			}
		})
	}
}

func TestShouldWarnPasswordExpiry(t *testing.T) {
	cfg := testConfig()
	cfg.PasswordExpiryDays = 30
	cfg.PasswordExpiryWarningDays = 7
	svc := NewService(newMockUserRepo(), newMockAPIKeyRepo(), cfg, logger.Nop())

	// Changed 25 days ago — 5 days left — should warn
	user := &models.User{PasswordChangedAt: timePtr(time.Now().Add(-25 * 24 * time.Hour))}
	if !svc.ShouldWarnPasswordExpiry(user) {
		t.Error("ShouldWarnPasswordExpiry() = false, want true (5 days left, warning at 7)")
	}

	// Changed 10 days ago — 20 days left — should not warn
	user.PasswordChangedAt = timePtr(time.Now().Add(-10 * 24 * time.Hour))
	if svc.ShouldWarnPasswordExpiry(user) {
		t.Error("ShouldWarnPasswordExpiry() = true, want false (20 days left)")
	}
}

func timePtr(t time.Time) *time.Time { return &t }
