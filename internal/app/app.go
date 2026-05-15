// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package app is the application bootstrap. The Run entry point loads
// configuration, opens the infrastructure connections (PostgreSQL, Redis,
// NATS, PKI), then hands off to a mode-specific startup path. Mode startup
// is split across init_*.go files via the phased initContext pipeline so
// adding a new module is a localized change rather than another insertion
// into a 2,700-line function.
package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"

	agentpkg "github.com/fr4nsys/usulnet/internal/agent"
	"github.com/fr4nsys/usulnet/internal/api"
	"github.com/fr4nsys/usulnet/internal/api/handlers"
	dockerpkg "github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/gateway"
	licensepkg "github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/nats"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/repository/redis"
	"github.com/fr4nsys/usulnet/internal/scheduler"
	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
	backupsvc "github.com/fr4nsys/usulnet/internal/services/backup"
	backupverifysvc "github.com/fr4nsys/usulnet/internal/services/backupverify"
	capturesvc "github.com/fr4nsys/usulnet/internal/services/capture"
	containersvc "github.com/fr4nsys/usulnet/internal/services/container"
	crontabsvc "github.com/fr4nsys/usulnet/internal/services/crontab"
	hostsvc "github.com/fr4nsys/usulnet/internal/services/host"
	notificationsvc "github.com/fr4nsys/usulnet/internal/services/notification"
	wireguardsvc "github.com/fr4nsys/usulnet/internal/services/wireguard"
)

// Application holds the long-lived dependencies that are constructed in Run
// and consumed by the phased init pipeline. Fields wired by an init_*.go
// phase live on the initContext (defined in init_context.go) unless they
// also require graceful shutdown.
type Application struct {
	Config *Config
	Logger *logger.Logger
	DB     *postgres.DB
	Redis  *redis.Client
	NATS   *nats.Client
	Server *api.Server

	// Services requiring graceful shutdown.
	backupService       *backupsvc.Service
	notificationService *notificationsvc.Service
	schedulerService    *scheduler.Scheduler
	crontabService      *crontabsvc.Service
	backupVerifyService *backupverifysvc.Service
	rollbackEventWorker *workers.RollbackEventWorker
	wireguardService    *wireguardsvc.Service

	// License provider (background goroutine).
	licenseProvider *licensepkg.Provider

	// Multi-host components.
	gatewayServer *gateway.Server
	agentInstance *agentpkg.Agent
	hostService   *hostsvc.Service

	// PKI.
	pkiManager *crypto.PKIManager

	// Packet capture (requires cleanup on shutdown).
	captureService *capturesvc.Service

	// Container service.
	containerService *containersvc.Service

	// Recon module acknowledgement store. The pointer is held on the
	// Application so the (future) recon.Service implementation can
	// share the same checker with the API middleware.
	reconAckStore *handlers.MemoryAckStore
}

// Run starts the application with the given configuration.
func Run(cfgFile, mode string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := LoadConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if mode != "" {
		cfg.Mode = mode
	}
	// Rewrite the Postgres / Redis / NATS connection settings to TLS
	// when server.tls.local_services is on. No-op when off — defaults
	// keep talking plain TCP on the private docker network.
	ApplyLocalServicesTLS(cfg)
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	// Docker socket: explicit config wins, otherwise auto-detect.
	if cfg.Docker.Socket != "" {
		dockerpkg.SetLocalSocketPath(cfg.Docker.Socket)
	} else {
		dockerpkg.SetLocalSocketPath(dockerpkg.DetectSocketPath())
	}

	log, err := logger.NewFromConfig(cfg.Logging.Level, cfg.Logging.Format, logger.OutputConfig{
		Output: cfg.Logging.Output,
		File: logger.FileConfig{
			Path:       cfg.Logging.File.Path,
			MaxSize:    parseSize(cfg.Logging.File.MaxSize, 100*1024*1024),
			MaxBackups: cfg.Logging.File.MaxBackups,
			MaxAge:     cfg.Logging.File.MaxAge,
			Compress:   cfg.Logging.File.Compress,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer log.Sync()

	log.Info("Starting usulnet", "version", Version, "commit", Commit, "mode", cfg.Mode)
	log.Info(dockerpkg.FormatDetectedSocket(dockerpkg.LocalSocketPath()),
		"socket", dockerpkg.LocalSocketPath(),
		"configured", cfg.Docker.Socket != "",
	)

	db, err := connectPostgres(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer db.Close()

	rdb, err := connectRedis(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer rdb.Close()

	// PKI initialization (before NATS, so certs are available for mTLS).
	pkiMgr, err := initPKI(cfg, log)
	if err != nil {
		return err
	}

	nc, err := connectNATS(ctx, cfg, log)
	if err != nil {
		return err
	}
	if nc != nil {
		defer nc.Close()
	}

	app := &Application{
		Config:     cfg,
		Logger:     log,
		DB:         db,
		Redis:      rdb,
		NATS:       nc,
		pkiManager: pkiMgr,
	}

	if err := app.startComponents(ctx); err != nil {
		return fmt.Errorf("failed to start components: %w", err)
	}

	log.Info("usulnet started successfully",
		"host", cfg.Server.Host,
		"port", cfg.Server.Port,
	)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info("Shutdown signal received")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer shutdownCancel()

	if err := app.shutdown(shutdownCtx); err != nil {
		log.Error("Error during shutdown", "error", err)
		return err
	}

	log.Info("usulnet stopped gracefully")
	return nil
}

// startComponents dispatches to the mode-specific startup path.
func (app *Application) startComponents(ctx context.Context) error {
	switch app.Config.Mode {
	case "standalone":
		return app.startStandalone(ctx)
	case "master":
		return app.startMaster(ctx)
	case "agent":
		return app.startAgent(ctx)
	default:
		return fmt.Errorf("unknown mode: %s", app.Config.Mode)
	}
}

// startStandalone runs the standalone bootstrap pipeline. Each phase
// populates the shared initContext that later phases consume.
func (app *Application) startStandalone(ctx context.Context) error {
	app.Logger.Info("Starting in standalone mode")

	ic := &initContext{}

	if err := app.initServer(ic); err != nil {
		return fmt.Errorf("init server: %w", err)
	}
	if err := app.initAuth(ctx, ic); err != nil {
		return fmt.Errorf("init auth: %w", err)
	}
	if err := app.initDocker(ctx, ic); err != nil {
		return fmt.Errorf("init docker: %w", err)
	}
	if err := app.initServices(ctx, ic); err != nil {
		return fmt.Errorf("init services: %w", err)
	}
	if err := app.initScheduler(ctx, ic); err != nil {
		return fmt.Errorf("init scheduler: %w", err)
	}
	if err := app.initAPI(ctx, ic); err != nil {
		return fmt.Errorf("init api: %w", err)
	}
	if err := app.initWeb(ctx, ic); err != nil {
		return fmt.Errorf("init web: %w", err)
	}

	errCh := app.Server.StartAsync()
	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("failed to start API server: %w", err)
		}
	case <-time.After(100 * time.Millisecond):
		// Server started successfully.
	}

	return nil
}

// startMaster runs the standalone pipeline and adds the gateway server for
// NATS-based agent management.
func (app *Application) startMaster(ctx context.Context) error {
	app.Logger.Info("Starting in master mode")

	if err := app.startStandalone(ctx); err != nil {
		return fmt.Errorf("failed to start standalone services: %w", err)
	}

	if app.NATS == nil {
		return fmt.Errorf("NATS connection required for master mode - configure nats.url in config")
	}

	stdDBGateway := stdlib.OpenDBFromPool(app.DB.Pool())
	sqlxDB := sqlx.NewDb(stdDBGateway, "pgx")
	hostRepo := postgres.NewHostRepository(sqlxDB)

	gatewayCfg := gateway.DefaultServerConfig()
	gw, err := gateway.NewServer(app.NATS, hostRepo, app.containerService, gatewayCfg, app.Logger)
	if err != nil {
		return fmt.Errorf("failed to create gateway server: %w", err)
	}

	agentEventRepo := postgres.NewAgentEventRepository(app.DB)
	gw.SetEventStore(agentEventRepo)
	app.Logger.Info("Agent event persistence enabled")

	if err := gw.Start(ctx); err != nil {
		return fmt.Errorf("failed to start gateway server: %w", err)
	}
	app.gatewayServer = gw

	if app.hostService != nil {
		app.hostService.SetRepository(hostRepo)
		app.hostService.SetCommandSender(gw)
		app.Logger.Info("Master mode: host service upgraded with repository and command sender")
	}

	// WireGuard mesh propagation runs through the same gateway. In
	// standalone mode the sender stays nil and the service skips the
	// propagation step (peers are persisted but not pushed to remote
	// agents — see services/wireguard/service.go).
	if app.wireguardService != nil {
		app.wireguardService.SetCommandSender(gw)
		app.Logger.Info("Master mode: wireguard mesh propagation enabled")
	}

	gatewayAPI := gateway.NewAPIHandler(gw, app.Logger)
	gatewayAPI.RegisterRoutes(app.Server.Router())

	app.Logger.Info("Master mode: gateway server started",
		"heartbeat_interval", gatewayCfg.HeartbeatInterval,
		"heartbeat_timeout", gatewayCfg.HeartbeatTimeout,
		"command_timeout", gatewayCfg.CommandTimeout,
	)

	return nil
}

// shutdown gracefully stops all components.
func (app *Application) shutdown(ctx context.Context) error {
	app.Logger.Info("Shutting down components...")

	if app.schedulerService != nil {
		if err := app.schedulerService.Stop(); err != nil {
			app.Logger.Error("Error stopping scheduler", "error", err)
		} else {
			app.Logger.Info("Scheduler stopped")
		}
	}
	if app.notificationService != nil {
		app.notificationService.Stop()
		app.Logger.Info("Notification service stopped")
	}
	if app.crontabService != nil {
		if err := app.crontabService.Stop(); err != nil {
			app.Logger.Error("Error stopping crontab service", "error", err)
		} else {
			app.Logger.Info("Crontab service stopped")
		}
	}
	if app.rollbackEventWorker != nil {
		app.rollbackEventWorker.Stop()
		app.Logger.Info("Rollback event worker stopped")
	}
	if app.captureService != nil {
		app.captureService.Cleanup()
		app.Logger.Info("Packet capture service stopped")
	}
	if app.backupService != nil {
		if err := app.backupService.Stop(); err != nil {
			app.Logger.Error("Error stopping backup service", "error", err)
		} else {
			app.Logger.Info("Backup service stopped")
		}
	}
	if app.gatewayServer != nil {
		if err := app.gatewayServer.Stop(); err != nil {
			app.Logger.Error("Error stopping gateway server", "error", err)
		} else {
			app.Logger.Info("Gateway server stopped")
		}
	}
	if app.agentInstance != nil {
		app.agentInstance.Stop()
		app.Logger.Info("Agent stopped")
	}
	if app.licenseProvider != nil {
		app.licenseProvider.Stop()
		app.Logger.Info("License provider stopped")
	}
	if app.Server != nil {
		if err := app.Server.Shutdown(ctx); err != nil {
			app.Logger.Error("Error stopping API server", "error", err)
			return err
		}
	}

	return nil
}
