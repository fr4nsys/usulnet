// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"fmt"
	"time"

	apimiddleware "github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/repository/redis"
	auditsvc "github.com/fr4nsys/usulnet/internal/services/audit"
	authsvc "github.com/fr4nsys/usulnet/internal/services/auth"
	"github.com/fr4nsys/usulnet/internal/web"
)

// initAuth initializes authentication services, JWT, sessions, audit logging,
// blacklist, and API key auth, and bootstraps the admin user if none exists.
// Requires ic.serverCfg to be populated by initServer.
func (app *Application) initAuth(ctx context.Context, ic *initContext) error {
	userRepo := postgres.NewUserRepository(app.DB)
	sessionRepo := postgres.NewSessionRepository(app.DB)
	apiKeyRepo := postgres.NewAPIKeyRepository(app.DB)

	jwtSecret := app.Config.Security.JWTSecret
	if jwtSecret == "" {
		// Config.Validate() requires jwt_secret. Fail hard rather than
		// silently running with an insecure default.
		return fmt.Errorf("security.jwt_secret is required — set USULNET_JWT_SECRET")
	}
	accessTTL := app.Config.Security.JWTExpiry
	if accessTTL <= 0 {
		accessTTL = 24 * time.Hour
	}
	refreshTTL := app.Config.Security.RefreshExpiry
	if refreshTTL <= 0 {
		refreshTTL = 7 * 24 * time.Hour
	}
	jwtService := authsvc.NewJWTService(authsvc.JWTConfig{
		Secret:          jwtSecret,
		Issuer:          "usulnet",
		AccessTokenTTL:  accessTTL,
		RefreshTokenTTL: refreshTTL,
	})

	sessionSvc := authsvc.NewSessionService(
		sessionRepo,
		jwtService,
		authsvc.SessionConfig{
			MaxSessionsPerUser: 10,
			SessionTTL:         accessTTL,
			CleanupInterval:    1 * time.Hour,
			ExtendOnActivity:   true,
			ExtendThreshold:    accessTTL / 4,
		},
		app.Logger,
	)

	authService := authsvc.NewService(
		userRepo,
		sessionRepo,
		apiKeyRepo,
		jwtService,
		sessionSvc,
		authsvc.DefaultAuthConfig(),
		app.Logger,
	)

	jwtBlacklist := redis.NewJWTBlacklist(app.Redis)
	authService.SetJWTBlacklist(jwtBlacklist)
	app.Logger.Info("JWT blacklist enabled for immediate token revocation")

	auditLogRepo := postgres.NewAuditLogRepository(app.DB, app.Logger)
	auditService := auditsvc.NewService(auditLogRepo, app.Logger, auditsvc.DefaultConfig())
	authService.SetAuditService(auditService)
	auditService.StartCleanupWorker(ctx)
	web.SetAuditDBService(auditService)
	app.Logger.Info("Audit logging service enabled (persistent DB + in-memory cache)")

	// NOTE: The TokenValidator and APIKeyAuth assignments below mutate the
	// stashed ic.serverCfg, but api.NewServer (called in initServer) already
	// stored the config by value. This mirrors v26.5.0's existing behavior
	// and v26.2.7's init_auth.go exactly. See PR notes for the follow-up
	// to add Server.SetTokenValidator / Server.SetAPIKeyAuth helpers.
	ic.serverCfg.RouterConfig.TokenValidator = func(ctx context.Context, _ string, claims *apimiddleware.UserClaims) error {
		var issuedAt time.Time
		if claims.IssuedAt != nil {
			issuedAt = claims.IssuedAt.Time
		}
		return jwtBlacklist.ValidateToken(ctx, redis.TokenValidator{
			JTI:      claims.ID,
			UserID:   claims.UserID,
			IssuedAt: issuedAt,
		})
	}
	app.Logger.Info("JWT blacklist wired to API middleware")

	ic.serverCfg.RouterConfig.APIKeyAuth = func(ctx context.Context, apiKey string) (*apimiddleware.UserClaims, error) {
		user, _, err := authService.AuthenticateAPIKey(ctx, apiKey)
		if err != nil {
			return nil, err
		}
		email := ""
		if user.Email != nil {
			email = *user.Email
		}
		return &apimiddleware.UserClaims{
			UserID:   user.ID.String(),
			Username: user.Username,
			Email:    email,
			Role:     string(user.Role),
		}, nil
	}
	app.Logger.Info("API key authentication enabled")

	if err := app.bootstrapAdminUser(ctx, userRepo); err != nil {
		app.Logger.Error("Failed to bootstrap admin user", "error", err)
		// Non-fatal: continue startup.
	}

	ic.authService = authService
	ic.userRepo = userRepo
	ic.sessionRepo = sessionRepo
	ic.apiKeyRepo = apiKeyRepo
	ic.auditLogRepo = auditLogRepo
	ic.auditService = auditService
	ic.jwtSecret = jwtSecret
	ic.accessTTL = accessTTL

	return nil
}
