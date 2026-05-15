// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"fmt"
	"time"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// RunMigrations runs database migrations.
func RunMigrations(cfgFile, action string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cfg, err := LoadConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	ApplyLocalServicesTLS(cfg)

	db, err := postgres.New(ctx, cfg.EffectiveDatabaseURL(), postgres.Options{
		MaxOpenConns:    cfg.Database.MaxOpenConns,
		MaxIdleConns:    cfg.Database.MaxIdleConns,
		ConnMaxLifetime: cfg.Database.ConnMaxLifetime,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	switch action {
	case "up":
		return db.Migrate(ctx)
	case "status":
		return db.MigrationStatus(ctx)
	default:
		if len(action) > 5 && action[:5] == "down:" {
			return db.MigrateDown(ctx, action[5:])
		}
		return fmt.Errorf("unknown migration action: %s", action)
	}
}

// ResetAdminPassword resets the admin user password or creates the admin if
// missing.
func ResetAdminPassword(cfgFile, newPassword string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg, err := LoadConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	ApplyLocalServicesTLS(cfg)

	db, err := postgres.New(ctx, cfg.EffectiveDatabaseURL(), postgres.Options{
		MaxOpenConns: 2,
		MaxIdleConns: 1,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	userRepo := postgres.NewUserRepository(db)

	hash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	admin, err := userRepo.GetByUsername(ctx, "admin")
	if err != nil {
		adminUser := &models.User{
			Username:     "admin",
			PasswordHash: hash,
			Role:         models.RoleAdmin,
			IsActive:     true,
		}
		if err := userRepo.Create(ctx, adminUser); err != nil {
			return fmt.Errorf("failed to create admin user: %w", err)
		}
		fmt.Println("Admin user created with new password.")
		return nil
	}

	admin.PasswordHash = hash
	admin.IsActive = true
	if err := userRepo.Update(ctx, admin); err != nil {
		return fmt.Errorf("failed to update admin password: %w", err)
	}

	if err := userRepo.Unlock(ctx, admin.ID); err != nil {
		return fmt.Errorf("failed to unlock admin account: %w", err)
	}

	fmt.Println("Admin password reset successfully. Account unlocked.")
	return nil
}
