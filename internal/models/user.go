// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// UserRole represents user permission level
type UserRole string

const (
	RoleAdmin    UserRole = "admin"
	RoleOperator UserRole = "operator"
	RoleViewer   UserRole = "viewer"
)

// IsValid checks if the role is valid
func (r UserRole) IsValid() bool {
	switch r {
	case RoleAdmin, RoleOperator, RoleViewer:
		return true
	}
	return false
}

// CanManageUsers returns true if role can manage users
func (r UserRole) CanManageUsers() bool {
	return r == RoleAdmin
}

// CanModifyResources returns true if role can modify resources
func (r UserRole) CanModifyResources() bool {
	return r == RoleAdmin || r == RoleOperator
}

// User represents a platform user
type User struct {
	ID                     uuid.UUID  `json:"id" db:"id"`
	Username               string     `json:"username" db:"username"`
	Email                  *string    `json:"email,omitempty" db:"email"`
	PasswordHash           string     `json:"-" db:"password_hash"`
	Role                   UserRole   `json:"role" db:"role"`
	IsActive               bool       `json:"is_active" db:"is_active"`
	IsLDAP                 bool       `json:"is_ldap" db:"is_ldap"`
	LDAPDN                 *string    `json:"ldap_dn,omitempty" db:"ldap_dn"`
	FailedLoginAttempts    int        `json:"failed_login_attempts" db:"failed_login_attempts"`
	LockedUntil            *time.Time `json:"locked_until,omitempty" db:"locked_until"`
	LastLoginAt            *time.Time `json:"last_login_at,omitempty" db:"last_login_at"`
	PasswordChangedAt      *time.Time `json:"password_changed_at,omitempty" db:"password_changed_at"`
	PasswordExpiresAt      *time.Time `json:"password_expires_at,omitempty" db:"password_expires_at"`
	TOTPSecret             *string    `json:"-" db:"totp_secret"`                                    // Encrypted
	TOTPEnabled            bool       `json:"totp_enabled" db:"totp_enabled"`
	TOTPVerifiedAt         *time.Time `json:"totp_verified_at,omitempty" db:"totp_verified_at"`
	BackupCodes            []byte     `json:"-" db:"backup_codes"`                                   // JSONB array of {hash, used}
	BackupCodesGeneratedAt *time.Time `json:"backup_codes_generated_at,omitempty" db:"backup_codes_generated_at"`
	CreatedAt              time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at" db:"updated_at"`
}

// BackupCodeEntry represents a stored backup code
type BackupCodeEntry struct {
	Hash string `json:"hash"`
	Used bool   `json:"used"`
}

// IsLocked returns true if user is currently locked
func (u *User) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.LockedUntil)
}

// CanLogin returns true if user can log in
func (u *User) CanLogin() bool {
	return u.IsActive && !u.IsLocked()
}

// HasTOTP returns true if user has TOTP 2FA enabled and verified
func (u *User) HasTOTP() bool {
	return u.TOTPEnabled && u.TOTPSecret != nil && *u.TOTPSecret != ""
}

// HasBackupCodes returns true if user has backup codes available
func (u *User) HasBackupCodes() bool {
	return len(u.BackupCodes) > 0 && u.BackupCodesGeneratedAt != nil
}

// CreateUserInput represents input for creating a user
type CreateUserInput struct {
	Username string   `json:"username" validate:"required,username,min=3,max=50"`
	Email    *string  `json:"email,omitempty" validate:"omitempty,email"`
	Password string   `json:"password" validate:"required,password_strength"`
	Role     UserRole `json:"role" validate:"required,oneof=admin operator viewer"`
}

// UpdateUserInput represents input for updating a user
type UpdateUserInput struct {
	Email    *string   `json:"email,omitempty" validate:"omitempty,email"`
	Role     *UserRole `json:"role,omitempty" validate:"omitempty,oneof=admin operator viewer"`
	IsActive *bool     `json:"is_active,omitempty"`
}

// ChangePasswordInput represents input for changing password
type ChangePasswordInput struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,password_strength"`
}

// Session represents a user session
type Session struct {
	ID               uuid.UUID `json:"id" db:"id"`
	UserID           uuid.UUID `json:"user_id" db:"user_id"`
	RefreshTokenHash string    `json:"-" db:"refresh_token_hash"`
	UserAgent        *string   `json:"user_agent,omitempty" db:"user_agent"`
	IPAddress        *string   `json:"ip_address,omitempty" db:"ip_address"`
	ExpiresAt        time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
}

// IsExpired returns true if session is expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// APIKey represents an API key for programmatic access
type APIKey struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	UserID     uuid.UUID  `json:"user_id" db:"user_id"`
	Name       string     `json:"name" db:"name"`
	KeyHash    string     `json:"-" db:"key_hash"`
	Prefix     string     `json:"prefix" db:"prefix"` // First 8 chars for identification
	LastUsedAt *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
}

// IsExpired returns true if API key is expired
func (k *APIKey) IsExpired() bool {
	if k.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*k.ExpiresAt)
}

// CreateAPIKeyInput represents input for creating an API key
type CreateAPIKeyInput struct {
	Name      string     `json:"name" validate:"required,min=1,max=100"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// APIKeyWithSecret includes the plaintext key (only returned on creation)
type APIKeyWithSecret struct {
	APIKey
	Key string `json:"key"`
}

// AuditLogEntry represents an audit log entry
type AuditLogEntry struct {
	ID          int64           `json:"id" db:"id"`
	UserID      *uuid.UUID      `json:"user_id,omitempty" db:"user_id"`
	Username    *string         `json:"username,omitempty" db:"username"`
	Action      string          `json:"action" db:"action"`
	EntityType  string          `json:"entity_type" db:"entity_type"`
	EntityID    *string         `json:"entity_id,omitempty" db:"entity_id"`
	Details     *map[string]any `json:"details,omitempty" db:"details"`
	IPAddress   *string         `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent   *string         `json:"user_agent,omitempty" db:"user_agent"`
	Success     bool            `json:"success" db:"success"`
	ErrorMsg    *string         `json:"error_msg,omitempty" db:"error_msg"`
	CreatedAt   time.Time       `json:"created_at" db:"created_at"`
}

// AuditAction constants
const (
	AuditActionLogin          = "login"
	AuditActionLogout         = "logout"
	AuditActionLoginFailed    = "login_failed"
	AuditActionCreate         = "create"
	AuditActionUpdate         = "update"
	AuditActionDelete         = "delete"
	AuditActionStart          = "start"
	AuditActionStop           = "stop"
	AuditActionRestart        = "restart"
	AuditActionBackup         = "backup"
	AuditActionRestore        = "restore"
	AuditActionSecurityScan   = "security_scan"
	AuditActionUpdate_        = "update_container"
	AuditActionRollback       = "rollback"
	AuditActionConfigSync     = "config_sync"
	AuditActionPasswordChange = "password_change"
	AuditActionPasswordReset  = "password_reset"
	AuditActionAPIKeyCreate   = "api_key_create"
	AuditActionAPIKeyDelete   = "api_key_delete"
)

// LDAP-related types

// LDAPConfig represents LDAP server configuration
type LDAPConfig struct {
	ID             uuid.UUID `json:"id" db:"id"`
	Name           string    `json:"name" db:"name"`
	Host           string    `json:"host" db:"host"`
	Port           int       `json:"port" db:"port"`
	UseTLS         bool      `json:"use_tls" db:"use_tls"`
	StartTLS       bool      `json:"start_tls" db:"start_tls"`
	SkipTLSVerify  bool      `json:"skip_tls_verify" db:"skip_tls_verify"`
	BindDN         string    `json:"bind_dn" db:"bind_dn"`
	BindPassword   string    `json:"-" db:"bind_password"` // Encrypted
	BaseDN         string    `json:"base_dn" db:"base_dn"`
	UserFilter     string    `json:"user_filter" db:"user_filter"`
	UsernameAttr   string    `json:"username_attr" db:"username_attr"`
	EmailAttr      string    `json:"email_attr" db:"email_attr"`
	GroupFilter    string    `json:"group_filter,omitempty" db:"group_filter"`
	GroupAttr      string    `json:"group_attr,omitempty" db:"group_attr"`
	AdminGroup     string    `json:"admin_group,omitempty" db:"admin_group"`
	OperatorGroup  string    `json:"operator_group,omitempty" db:"operator_group"`
	DefaultRole    UserRole  `json:"default_role" db:"default_role"`
	IsEnabled      bool      `json:"is_enabled" db:"is_enabled"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

// OAuthConfig represents OAuth provider configuration
type OAuthConfig struct {
	ID            uuid.UUID `json:"id" db:"id"`
	Name          string    `json:"name" db:"name"`
	Provider      string    `json:"provider" db:"provider"` // generic, oidc, github, google, microsoft
	ClientID      string    `json:"client_id" db:"client_id"`
	ClientSecret  string    `json:"-" db:"client_secret"` // Encrypted
	AuthURL       string    `json:"auth_url,omitempty" db:"auth_url"`
	TokenURL      string    `json:"token_url,omitempty" db:"token_url"`
	UserInfoURL   string    `json:"user_info_url,omitempty" db:"user_info_url"`
	Scopes        []string  `json:"scopes" db:"scopes"`
	RedirectURL   string    `json:"redirect_url,omitempty" db:"redirect_url"`
	DefaultRole   UserRole  `json:"default_role" db:"default_role"`
	AutoProvision bool      `json:"auto_provision" db:"auto_provision"`
	AdminGroup    string    `json:"admin_group,omitempty" db:"admin_group"`
	OperatorGroup string    `json:"operator_group,omitempty" db:"operator_group"`
	UserIDClaim   string    `json:"user_id_claim" db:"user_id_claim"`
	UsernameClaim string    `json:"username_claim" db:"username_claim"`
	EmailClaim    string    `json:"email_claim" db:"email_claim"`
	GroupsClaim   string    `json:"groups_claim" db:"groups_claim"`
	IsEnabled     bool      `json:"is_enabled" db:"is_enabled"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
}

// OAuth provider types
const (
	OAuthProviderGeneric   = "generic"
	OAuthProviderOIDC      = "oidc"
	OAuthProviderGitHub    = "github"
	OAuthProviderGoogle    = "google"
	OAuthProviderMicrosoft = "microsoft"
)
