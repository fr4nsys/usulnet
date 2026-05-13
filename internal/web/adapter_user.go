// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/totp"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	authsvc "github.com/fr4nsys/usulnet/internal/services/auth"
)

type userAdapter struct {
	repo      *postgres.UserRepository
	authSvc   *authsvc.Service
	encryptor *crypto.AESEncryptor
}

func (a *userAdapter) List(ctx context.Context, search string, role string) ([]UserView, int64, error) {
	if a.repo == nil {
		return nil, 0, fmt.Errorf("user repository not configured")
	}

	opts := postgres.UserListOptions{
		Page:    1,
		PerPage: 500,
		Search:  search,
	}
	if role != "" {
		r := models.UserRole(role)
		opts.Role = &r
	}

	users, total, err := a.repo.List(ctx, opts)
	if err != nil {
		return nil, 0, err
	}

	views := make([]UserView, 0, len(users))
	for _, u := range users {
		views = append(views, userModelToView(u))
	}

	return views, total, nil
}

func (a *userAdapter) Get(ctx context.Context, id string) (*UserView, error) {
	if a.repo == nil {
		return nil, fmt.Errorf("user repository not configured")
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	u, err := a.repo.GetByID(ctx, uid)
	if err != nil {
		return nil, err
	}

	v := userModelToView(u)
	return &v, nil
}

func (a *userAdapter) Create(ctx context.Context, username, email, password, role string) (*UserView, error) {
	if a.repo == nil {
		return nil, fmt.Errorf("user repository not configured")
	}

	// Hash password
	hash, err := crypto.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &models.User{
		ID:           uuid.New(),
		Username:     username,
		PasswordHash: hash,
		Role:         models.UserRole(role),
		IsActive:     true,
		IsLDAP:       false,
	}
	if email != "" {
		user.Email = &email
	}

	if err := a.repo.Create(ctx, user); err != nil {
		return nil, err
	}

	v := userModelToView(user)
	return &v, nil
}

func (a *userAdapter) Update(ctx context.Context, id string, email *string, role *string, isActive *bool) error {
	if a.repo == nil {
		return fmt.Errorf("user repository not configured")
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}

	user, err := a.repo.GetByID(ctx, uid)
	if err != nil {
		return err
	}

	if email != nil {
		user.Email = email
	}
	if role != nil {
		user.Role = models.UserRole(*role)
	}
	if isActive != nil {
		user.IsActive = *isActive
	}

	return a.repo.Update(ctx, user)
}

func (a *userAdapter) Delete(ctx context.Context, id string) error {
	if a.repo == nil {
		return fmt.Errorf("user repository not configured")
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}
	return a.repo.Delete(ctx, uid)
}

func (a *userAdapter) Enable(ctx context.Context, id string) error {
	active := true
	return a.Update(ctx, id, nil, nil, &active)
}

func (a *userAdapter) Disable(ctx context.Context, id string) error {
	active := false
	return a.Update(ctx, id, nil, nil, &active)
}

func (a *userAdapter) Unlock(ctx context.Context, id string) error {
	if a.repo == nil {
		return fmt.Errorf("user repository not configured")
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}
	return a.repo.Unlock(ctx, uid)
}

func (a *userAdapter) ResetPassword(ctx context.Context, id string, newPassword string) error {
	if a.authSvc == nil {
		return fmt.Errorf("auth service not configured")
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}
	return a.authSvc.ResetPassword(ctx, uid, newPassword)
}

func (a *userAdapter) GetStats(ctx context.Context) (*UserStatsView, error) {
	if a.repo == nil {
		return nil, fmt.Errorf("user repository not configured")
	}

	stats, err := a.repo.GetStats(ctx)
	if err != nil {
		return nil, err
	}

	return &UserStatsView{
		Total:    stats.Total,
		Active:   stats.Active,
		Inactive: stats.Inactive,
		LDAP:     stats.LDAP,
		Local:    stats.Local,
		Locked:   stats.Locked,
		Admins:   stats.Admins,
	}, nil
}

func userModelToView(u *models.User) UserView {
	v := UserView{
		ID:        u.ID.String(),
		Username:  u.Username,
		Role:      string(u.Role),
		IsActive:  u.IsActive,
		IsLDAP:    u.IsLDAP,
		IsLocked:  u.IsLocked(),
		HasTOTP:   u.HasTOTP(),
		LastLogin: u.LastLoginAt,
		CreatedAt: u.CreatedAt,
	}
	if u.Email != nil {
		v.Email = *u.Email
	}
	if u.LDAPDN != nil {
		v.LDAPDN = *u.LDAPDN
	}
	return v
}

func (a *userAdapter) SetupTOTP(ctx context.Context, userID string) (string, string, error) {
	if a.repo == nil || a.encryptor == nil {
		return "", "", fmt.Errorf("totp not configured")
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		return "", "", fmt.Errorf("invalid user ID: %w", err)
	}

	user, err := a.repo.GetByID(ctx, uid)
	if err != nil {
		return "", "", err
	}

	// Generate new secret
	secret, err := totp.GenerateSecret()
	if err != nil {
		return "", "", err
	}

	// Encrypt and store
	encrypted, err := a.encryptor.EncryptString(secret)
	if err != nil {
		return "", "", fmt.Errorf("encrypt totp secret: %w", err)
	}

	if err := a.repo.SetTOTPSecret(ctx, uid, encrypted); err != nil {
		return "", "", err
	}

	account := user.Username
	if user.Email != nil && *user.Email != "" {
		account = *user.Email
	}
	qrURI := totp.OTPAuthURI(secret, account, "")

	return secret, qrURI, nil
}

func (a *userAdapter) VerifyAndEnableTOTP(ctx context.Context, userID string, code string) error {
	if a.repo == nil || a.encryptor == nil {
		return fmt.Errorf("totp not configured")
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}

	user, err := a.repo.GetByID(ctx, uid)
	if err != nil {
		return err
	}

	if user.TOTPSecret == nil || *user.TOTPSecret == "" {
		return fmt.Errorf("totp not set up")
	}

	// Decrypt secret
	secret, err := a.encryptor.DecryptString(*user.TOTPSecret)
	if err != nil {
		return fmt.Errorf("decrypt totp secret: %w", err)
	}

	// Validate code
	valid, err := totp.Validate(code, secret)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("invalid totp code")
	}

	return a.repo.EnableTOTP(ctx, uid)
}

func (a *userAdapter) ValidateTOTPCode(ctx context.Context, userID string, code string) (bool, error) {
	if a.repo == nil || a.encryptor == nil {
		return false, fmt.Errorf("totp not configured")
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		return false, fmt.Errorf("invalid user ID: %w", err)
	}

	user, err := a.repo.GetByID(ctx, uid)
	if err != nil {
		return false, err
	}

	if !user.HasTOTP() {
		return false, fmt.Errorf("totp not enabled")
	}

	secret, err := a.encryptor.DecryptString(*user.TOTPSecret)
	if err != nil {
		return false, fmt.Errorf("decrypt totp secret: %w", err)
	}

	return totp.Validate(code, secret)
}

func (a *userAdapter) DisableTOTP(ctx context.Context, userID string, code string) error {
	// Validate current code before disabling
	valid, err := a.ValidateTOTPCode(ctx, userID, code)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("invalid totp code")
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}

	return a.repo.DisableTOTP(ctx, uid)
}

func (a *userAdapter) HasTOTP(ctx context.Context, userID string) (bool, error) {
	if a.repo == nil {
		return false, fmt.Errorf("user repository not configured")
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		return false, fmt.Errorf("invalid user ID: %w", err)
	}

	user, err := a.repo.GetByID(ctx, uid)
	if err != nil {
		return false, err
	}

	return user.HasTOTP(), nil
}
