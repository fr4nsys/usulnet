// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"fmt"
	"os"
	"time"

	"github.com/fr4nsys/usulnet/internal/api"
	apimiddleware "github.com/fr4nsys/usulnet/internal/api/middleware"
)

// initServer builds the API server configuration, sets up HTTPS TLS via the
// PKI manager, and constructs app.Server. The router is NOT set up here —
// app.Server.Setup() runs later (in initAPI) after every handler is
// populated. The composed serverCfg is stashed on ic so later phases can
// thread additional middleware (token validator, API key auth) into it.
func (app *Application) initServer(ic *initContext) error {
	routerCfg := api.DefaultRouterConfig(app.Config.Security.JWTSecret)
	if app.Config.Server.RateLimitRPS > 0 {
		routerCfg.RateLimitPerMinute = app.Config.Server.RateLimitRPS
	}
	routerCfg.MetricsEnabled = app.Config.Metrics.Enabled
	if app.Config.Metrics.Path != "" {
		routerCfg.MetricsPath = app.Config.Metrics.Path
	}

	serverCfg := api.ServerConfig{
		Host:            app.Config.Server.Host,
		Port:            app.Config.Server.Port,
		HTTPSPort:       app.Config.Server.HTTPSPort,
		ReadTimeout:     app.Config.Server.ReadTimeout,
		WriteTimeout:    app.Config.Server.WriteTimeout,
		IdleTimeout:     app.Config.Server.IdleTimeout,
		MaxHeaderBytes:  int(parseSize(app.Config.Server.MaxRequestSize, 1<<20)),
		ShutdownTimeout: app.Config.Server.ShutdownTimeout,
		RouterConfig:    routerCfg,
	}

	serverCfg.RouterConfig.Logger = app.Logger
	// Stack deploys (docker compose pull+up) need more than the default
	// 30s request timeout.
	serverCfg.RouterConfig.RequestTimeout = 5 * time.Minute

	// Override CORS if USULNET_CORS_ORIGINS is set. CookieSecure from
	// config is respected for CORS AllowCredentials.
	if corsOrigins := os.Getenv("USULNET_CORS_ORIGINS"); corsOrigins != "" {
		serverCfg.RouterConfig.CORSConfig = apimiddleware.CORSFromEnv(corsOrigins, app.Config.Security.CookieSecure)
		app.Logger.Info("CORS configured from USULNET_CORS_ORIGINS",
			"origins", corsOrigins,
			"cookie_secure", app.Config.Security.CookieSecure,
		)
	}

	if app.Config.Server.TLS.Enabled && app.pkiManager != nil {
		certPath, keyPath, tlsErr := app.pkiManager.EnsureHTTPSCert(
			app.Config.Server.TLS.CertFile,
			app.Config.Server.TLS.KeyFile,
		)
		if tlsErr != nil {
			return fmt.Errorf("failed to ensure HTTPS certificate: %w", tlsErr)
		}

		tlsCfg, tlsBuildErr := app.pkiManager.BuildTLSConfig(certPath, keyPath)
		if tlsBuildErr != nil {
			return fmt.Errorf("failed to build TLS config: %w", tlsBuildErr)
		}
		serverCfg.TLSConfig = tlsCfg

		app.Logger.Info("HTTPS enabled",
			"https_port", app.Config.Server.HTTPSPort,
			"cert", certPath,
			"pki_dir", app.pkiManager.DataDir(),
		)
	}

	serverCfg.Version = Version
	serverCfg.Commit = Commit
	serverCfg.BuildTime = BuildTime
	serverCfg.Logger = app.Logger
	serverCfg.RedirectHTTPS = app.Config.Server.RedirectHTTPS
	app.Server = api.NewServer(serverCfg)
	// Setup() is called later, after all API handlers are populated.

	ic.serverCfg = serverCfg
	return nil
}
