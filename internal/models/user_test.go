// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// UserRole
// ============================================================================

func TestUserRole_IsValid(t *testing.T) {
	tests := []struct {
		role UserRole
		want bool
	}{
		{RoleAdmin, true},
		{RoleOperator, true},
		{RoleViewer, true},
		{"invalid", false},
		{"", false},
		{"superadmin", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			if got := tt.role.IsValid(); got != tt.want {
				t.Errorf("UserRole(%q).IsValid() = %v, want %v", tt.role, got, tt.want)
			}
		})
	}
}

func TestUserRole_CanManageUsers(t *testing.T) {
	tests := []struct {
		role UserRole
		want bool
	}{
		{RoleAdmin, true},
		{RoleOperator, false},
		{RoleViewer, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			if got := tt.role.CanManageUsers(); got != tt.want {
				t.Errorf("UserRole(%q).CanManageUsers() = %v, want %v", tt.role, got, tt.want)
			}
		})
	}
}

func TestUserRole_CanModifyResources(t *testing.T) {
	tests := []struct {
		role UserRole
		want bool
	}{
		{RoleAdmin, true},
		{RoleOperator, true},
		{RoleViewer, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			if got := tt.role.CanModifyResources(); got != tt.want {
				t.Errorf("UserRole(%q).CanModifyResources() = %v, want %v", tt.role, got, tt.want)
			}
		})
	}
}

// ============================================================================
// Role constants
// ============================================================================

func TestRoleConstants(t *testing.T) {
	if RoleAdmin != "admin" {
		t.Errorf("RoleAdmin = %q, want 'admin'", RoleAdmin)
	}
	if RoleOperator != "operator" {
		t.Errorf("RoleOperator = %q, want 'operator'", RoleOperator)
	}
	if RoleViewer != "viewer" {
		t.Errorf("RoleViewer = %q, want 'viewer'", RoleViewer)
	}
}

// ============================================================================
// User.IsLocked
// ============================================================================

func TestUser_IsLocked_Nil(t *testing.T) {
	u := &User{LockedUntil: nil}
	if u.IsLocked() {
		t.Error("User with nil LockedUntil should not be locked")
	}
}

func TestUser_IsLocked_Future(t *testing.T) {
	future := time.Now().Add(1 * time.Hour)
	u := &User{LockedUntil: &future}
	if !u.IsLocked() {
		t.Error("User locked until future should be locked")
	}
}

func TestUser_IsLocked_Past(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour)
	u := &User{LockedUntil: &past}
	if u.IsLocked() {
		t.Error("User locked until past should not be locked")
	}
}

// ============================================================================
// User.CanLogin
// ============================================================================

func TestUser_CanLogin(t *testing.T) {
	tests := []struct {
		name   string
		active bool
		locked *time.Time
		want   bool
	}{
		{"active unlocked", true, nil, true},
		{"inactive unlocked", false, nil, false},
		{"active locked (future)", true, timePtr(time.Now().Add(1 * time.Hour)), false},
		{"active locked (past)", true, timePtr(time.Now().Add(-1 * time.Hour)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{IsActive: tt.active, LockedUntil: tt.locked}
			if got := u.CanLogin(); got != tt.want {
				t.Errorf("CanLogin() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// User.HasTOTP
// ============================================================================

func TestUser_HasTOTP(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	empty := ""

	tests := []struct {
		name    string
		enabled bool
		secret  *string
		want    bool
	}{
		{"enabled with secret", true, &secret, true},
		{"enabled no secret", true, nil, false},
		{"enabled empty secret", true, &empty, false},
		{"disabled with secret", false, &secret, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{TOTPEnabled: tt.enabled, TOTPSecret: tt.secret}
			if got := u.HasTOTP(); got != tt.want {
				t.Errorf("HasTOTP() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// User.HasBackupCodes
// ============================================================================

func TestUser_HasBackupCodes(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name        string
		codes       []byte
		generatedAt *time.Time
		want        bool
	}{
		{"has codes and date", []byte(`[{"hash":"abc"}]`), &now, true},
		{"no codes", nil, &now, false},
		{"empty codes", []byte{}, &now, false},
		{"no generated at", []byte(`[{"hash":"abc"}]`), nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{BackupCodes: tt.codes, BackupCodesGeneratedAt: tt.generatedAt}
			if got := u.HasBackupCodes(); got != tt.want {
				t.Errorf("HasBackupCodes() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// Session.IsExpired
// ============================================================================

func TestSession_IsExpired(t *testing.T) {
	past := &Session{ExpiresAt: time.Now().Add(-1 * time.Hour)}
	if !past.IsExpired() {
		t.Error("past session should be expired")
	}

	future := &Session{ExpiresAt: time.Now().Add(1 * time.Hour)}
	if future.IsExpired() {
		t.Error("future session should not be expired")
	}
}

// ============================================================================
// APIKey.IsExpired
// ============================================================================

func TestAPIKey_IsExpired_NoExpiry(t *testing.T) {
	k := &APIKey{ExpiresAt: nil}
	if k.IsExpired() {
		t.Error("API key with no expiry should not be expired")
	}
}

func TestAPIKey_IsExpired_Future(t *testing.T) {
	future := time.Now().Add(24 * time.Hour)
	k := &APIKey{ExpiresAt: &future}
	if k.IsExpired() {
		t.Error("API key with future expiry should not be expired")
	}
}

func TestAPIKey_IsExpired_Past(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	k := &APIKey{ExpiresAt: &past}
	if !k.IsExpired() {
		t.Error("API key with past expiry should be expired")
	}
}

// ============================================================================
// Audit action constants
// ============================================================================

func TestAuditActionConstants(t *testing.T) {
	actions := []string{
		AuditActionLogin, AuditActionLogout, AuditActionLoginFailed,
		AuditActionCreate, AuditActionUpdate, AuditActionDelete,
		AuditActionStart, AuditActionStop, AuditActionRestart,
		AuditActionBackup, AuditActionRestore,
		AuditActionSecurityScan, AuditActionRollback,
		AuditActionPasswordChange, AuditActionPasswordReset,
		AuditActionAPIKeyCreate, AuditActionAPIKeyDelete,
	}

	for _, a := range actions {
		if a == "" {
			t.Error("audit action constant should not be empty")
		}
	}
}

// ============================================================================
// OAuth provider constants
// ============================================================================

func TestOAuthProviderConstants(t *testing.T) {
	providers := []string{
		OAuthProviderGeneric, OAuthProviderOIDC,
		OAuthProviderGitHub, OAuthProviderGoogle, OAuthProviderMicrosoft,
	}
	for _, p := range providers {
		if p == "" {
			t.Error("OAuth provider constant should not be empty")
		}
	}
}

// ============================================================================
// User struct zero value
// ============================================================================

func TestUser_ZeroValue(t *testing.T) {
	var u User
	if u.IsActive {
		t.Error("zero value User should not be active")
	}
	if u.IsLocked() {
		t.Error("zero value User should not be locked")
	}
	if u.HasTOTP() {
		t.Error("zero value User should not have TOTP")
	}
	if u.HasBackupCodes() {
		t.Error("zero value User should not have backup codes")
	}
	if u.ID != uuid.Nil {
		t.Error("zero value User ID should be nil UUID")
	}
}

// helper
func timePtr(t time.Time) *time.Time {
	return &t
}
