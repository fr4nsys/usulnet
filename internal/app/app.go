// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"

	"github.com/fr4nsys/usulnet/internal/api"
	agentpkg "github.com/fr4nsys/usulnet/internal/agent"
	dockerpkg "github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/gateway"
	giteapkg "github.com/fr4nsys/usulnet/internal/integrations/gitea"
	licensepkg "github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/integrations/npm"
	"github.com/fr4nsys/usulnet/internal/nats"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/repository/redis"
	authsvc "github.com/fr4nsys/usulnet/internal/services/auth"
	backupsvc "github.com/fr4nsys/usulnet/internal/services/backup"
	backupstorage "github.com/fr4nsys/usulnet/internal/services/backup/storage"
	configsvc "github.com/fr4nsys/usulnet/internal/services/config"
	containersvc "github.com/fr4nsys/usulnet/internal/services/container"
	hostsvc "github.com/fr4nsys/usulnet/internal/services/host"
	imagesvc "github.com/fr4nsys/usulnet/internal/services/image"
	networksvc "github.com/fr4nsys/usulnet/internal/services/network"
	notificationsvc "github.com/fr4nsys/usulnet/internal/services/notification"
	proxysvc "github.com/fr4nsys/usulnet/internal/services/proxy"
	securitysvc "github.com/fr4nsys/usulnet/internal/services/security"
	securityanalyzer "github.com/fr4nsys/usulnet/internal/services/security/analyzer"
	trivypkg "github.com/fr4nsys/usulnet/internal/services/security/trivy"
	stacksvc "github.com/fr4nsys/usulnet/internal/services/stack"
	shortcutssvc "github.com/fr4nsys/usulnet/internal/services/shortcuts"
	sshsvc "github.com/fr4nsys/usulnet/internal/services/ssh"
	deploysvc "github.com/fr4nsys/usulnet/internal/services/deploy"
	databasesvc "github.com/fr4nsys/usulnet/internal/services/database"
	capturesvc "github.com/fr4nsys/usulnet/internal/services/capture"
	swarmsvc "github.com/fr4nsys/usulnet/internal/services/swarm"
	ldapbrowsersvc "github.com/fr4nsys/usulnet/internal/services/ldapbrowser"
	storagesvc "github.com/fr4nsys/usulnet/internal/services/storage"
	teamsvc "github.com/fr4nsys/usulnet/internal/services/team"
	gitsvc "github.com/fr4nsys/usulnet/internal/services/git"
	metricssvc "github.com/fr4nsys/usulnet/internal/services/metrics"
	monitoringsvc "github.com/fr4nsys/usulnet/internal/services/monitoring"
	updatesvc "github.com/fr4nsys/usulnet/internal/services/update"
	usersvc "github.com/fr4nsys/usulnet/internal/services/user"
	volumesvc "github.com/fr4nsys/usulnet/internal/services/volume"
	"github.com/fr4nsys/usulnet/internal/api/handlers"
	apimiddleware "github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/scheduler"
	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
	"github.com/fr4nsys/usulnet/internal/web"

	"go.uber.org/zap"
)

// zapLicenseLogger adapts zap.SugaredLogger to satisfy license.Logger.
type zapLicenseLogger struct {
	sugar *zap.SugaredLogger
}

func (z *zapLicenseLogger) Info(msg string, keysAndValues ...any)  { z.sugar.Infow(msg, keysAndValues...) }
func (z *zapLicenseLogger) Warn(msg string, keysAndValues ...any)  { z.sugar.Warnw(msg, keysAndValues...) }
func (z *zapLicenseLogger) Error(msg string, keysAndValues ...any) { z.sugar.Errorw(msg, keysAndValues...) }

// encryptorAdapter wraps *crypto.AESEncryptor to satisfy the web.Encryptor interface
// which expects Encrypt(string)(string,error) and Decrypt(string)(string,error).
type encryptorAdapter struct {
	enc *crypto.AESEncryptor
}

func (a *encryptorAdapter) Encrypt(plaintext string) (string, error) {
	return a.enc.EncryptString(plaintext)
}

func (a *encryptorAdapter) Decrypt(ciphertext string) (string, error) {
	return a.enc.DecryptString(ciphertext)
}

// Application holds all application dependencies
type Application struct {
	Config *Config
	Logger *logger.Logger
	DB     *postgres.DB
	Redis  *redis.Client
	NATS   *nats.Client
	Server *api.Server

	// Services requiring graceful shutdown
	backupService       *backupsvc.Service
	notificationService *notificationsvc.Service
	schedulerService    *scheduler.Scheduler

	// License provider (background goroutine)
	licenseProvider *licensepkg.Provider

	// Multi-host components
	gatewayServer *gateway.Server
	agentInstance *agentpkg.Agent
	hostService   *hostsvc.Service

	// PKI
	pkiManager *crypto.PKIManager
}

// Run starts the application with the given configuration
func Run(cfgFile, mode string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load configuration
	cfg, err := LoadConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Override mode if provided via CLI
	if mode != "" {
		cfg.Mode = mode
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	// Initialize logger
	log, err := logger.New(cfg.Logging.Level, cfg.Logging.Format)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer log.Sync()

	log.Info("Starting usulnet",
		"version", Version,
		"commit", Commit,
		"mode", cfg.Mode,
	)

	// Initialize PostgreSQL
	log.Info("Connecting to PostgreSQL...")
	db, err := postgres.New(ctx, cfg.Database.URL, postgres.Options{
		MaxOpenConns:    cfg.Database.MaxOpenConns,
		MaxIdleConns:    cfg.Database.MaxIdleConns,
		ConnMaxLifetime: cfg.Database.ConnMaxLifetime,
		ConnMaxIdleTime: cfg.Database.ConnMaxIdleTime,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}
	defer db.Close()
	log.Info("PostgreSQL connected")

	// Run migrations
	log.Info("Running database migrations...")
	if err := db.Migrate(ctx); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}
	log.Info("Migrations completed")

	// Initialize Redis
	log.Info("Connecting to Redis...")
	rdb, err := redis.New(ctx, cfg.Redis.URL, redis.Options{
		PoolSize:     cfg.Redis.PoolSize,
		MinIdleConns: cfg.Redis.MinIdleConns,
		DialTimeout:  cfg.Redis.DialTimeout,
		ReadTimeout:  cfg.Redis.ReadTimeout,
		WriteTimeout: cfg.Redis.WriteTimeout,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to Redis: %w", err)
	}
	defer rdb.Close()
	log.Info("Redis connected")

	// =========================================================================
	// PKI INITIALIZATION (before NATS, so certs are available for mTLS)
	// =========================================================================

	var pkiMgr *crypto.PKIManager
	if cfg.Server.TLS.Enabled && cfg.Mode != "agent" {
		pkiDataDir := cfg.Server.TLS.DataDir
		if pkiDataDir == "" {
			pkiDataDir = cfg.Storage.Path + "/pki"
		}

		pkiMgr, err = crypto.NewPKIManager(pkiDataDir)
		if err != nil {
			return fmt.Errorf("failed to initialize PKI: %w", err)
		}
		log.Info("PKI initialized", "data_dir", pkiDataDir)

		// Auto-generate NATS server cert (for the NATS service to use)
		natsCertPath, natsKeyPath, natsErr := pkiMgr.EnsureNATSServerCert("nats", "localhost")
		if natsErr != nil {
			return fmt.Errorf("failed to ensure NATS server cert: %w", natsErr)
		}
		log.Info("NATS server certificate ready",
			"cert", natsCertPath,
			"key", natsKeyPath,
			"ca", pkiMgr.CACertPath(),
		)

		// Auto-configure NATS client TLS if not explicitly configured
		if !cfg.NATS.TLS.Enabled && (cfg.Mode == "master" || cfg.NATS.URL != "") {
			// Generate a client cert for the master's NATS connection
			masterCertPath, masterKeyPath, masterErr := pkiMgr.EnsureMasterNATSClientCert()
			if masterErr != nil {
				return fmt.Errorf("failed to ensure master NATS client cert: %w", masterErr)
			}

			cfg.NATS.TLS.Enabled = true
			cfg.NATS.TLS.CertFile = masterCertPath
			cfg.NATS.TLS.KeyFile = masterKeyPath
			cfg.NATS.TLS.CAFile = pkiMgr.CACertPath()
			log.Info("NATS mTLS auto-configured from PKI",
				"cert", masterCertPath,
				"ca", pkiMgr.CACertPath(),
			)
		}
	}

	// Initialize NATS (only for master/agent modes or if URL is configured)
	var nc *nats.Client
	if cfg.Mode != "standalone" || cfg.NATS.URL != "" {
		log.Info("Connecting to NATS...")

		natsCfg := nats.Config{
			URL:           cfg.NATS.URL,
			Name:          cfg.NATS.Name,
			Token:         cfg.NATS.Token,
			Username:      cfg.NATS.Username,
			Password:      cfg.NATS.Password,
			MaxReconnects: cfg.NATS.MaxReconnects,
			ReconnectWait: cfg.NATS.ReconnectWait,
		}

		// Build TLS config if enabled (manual or auto-configured from PKI)
		if cfg.NATS.TLS.Enabled {
			tlsCfg, tlsErr := buildNATSTLSConfig(cfg.NATS.TLS.CertFile, cfg.NATS.TLS.KeyFile, cfg.NATS.TLS.CAFile, cfg.NATS.TLS.SkipVerify)
			if tlsErr != nil {
				return fmt.Errorf("failed to configure NATS TLS: %w", tlsErr)
			}
			natsCfg.TLSConfig = tlsCfg
			log.Info("NATS TLS enabled", "ca_file", cfg.NATS.TLS.CAFile, "cert_file", cfg.NATS.TLS.CertFile)
		}

		nc, err = nats.NewClient(natsCfg, log.Base())
		if err != nil {
			return fmt.Errorf("failed to connect to NATS: %w", err)
		}
		defer nc.Close()
		log.Info("NATS connected", "url", cfg.NATS.URL)
	}

	app := &Application{
		Config:     cfg,
		Logger:     log,
		DB:         db,
		Redis:      rdb,
		NATS:       nc,
		pkiManager: pkiMgr,
	}

	// Start components based on mode
	if err := app.startComponents(ctx); err != nil {
		return fmt.Errorf("failed to start components: %w", err)
	}

	log.Info("usulnet started successfully",
		"host", cfg.Server.Host,
		"port", cfg.Server.Port,
	)

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit
	log.Info("Shutdown signal received")

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer shutdownCancel()

	if err := app.shutdown(shutdownCtx); err != nil {
		log.Error("Error during shutdown", "error", err)
		return err
	}

	log.Info("usulnet stopped gracefully")
	return nil
}

// startComponents initializes and starts all required components based on mode
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

func (app *Application) startStandalone(ctx context.Context) error {
	app.Logger.Info("Starting in standalone mode")

	// Initialize API server with RouterConfig
	serverCfg := api.ServerConfig{
		Host:            app.Config.Server.Host,
		Port:            app.Config.Server.Port,
		HTTPSPort:       app.Config.Server.HTTPSPort,
		ReadTimeout:     app.Config.Server.ReadTimeout,
		WriteTimeout:    app.Config.Server.WriteTimeout,
		IdleTimeout:     app.Config.Server.IdleTimeout,
		MaxHeaderBytes:  1 << 20, // 1MB default
		ShutdownTimeout: app.Config.Server.ShutdownTimeout,
		RouterConfig:    api.DefaultRouterConfig(app.Config.Security.JWTSecret),
	}

	// Set logger so Recovery middleware actually logs panics
	serverCfg.RouterConfig.Logger = app.Logger
	// Increase request timeout - stack deploys (docker compose pull+up) need more than 30s
	serverCfg.RouterConfig.RequestTimeout = 5 * time.Minute

	// =========================================================================
	// HTTPS TLS SETUP (PKI already initialized in Run())
	// =========================================================================

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

	app.Server = api.NewServer(serverCfg)
	app.Server.SetVersion(Version, Commit, BuildTime)
	// NOTE: Setup() is called later, after all API handlers are populated

	// =========================================================================
	// AUTH SERVICE INITIALIZATION
	// =========================================================================

	// Create repositories
	userRepo := postgres.NewUserRepository(app.DB)
	sessionRepo := postgres.NewSessionRepository(app.DB)
	apiKeyRepo := postgres.NewAPIKeyRepository(app.DB)

	// Create JWT service
	jwtSecret := app.Config.Security.JWTSecret
	if jwtSecret == "" {
		jwtSecret = "usulnet-dev-secret-change-me"
		app.Logger.Warn("Using default JWT secret - change security.jwt_secret in config for production")
	}
	jwtService := authsvc.NewJWTService(authsvc.JWTConfig{
		Secret:          jwtSecret,
		Issuer:          "usulnet",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
	})

	// Create session service
	sessionSvc := authsvc.NewSessionService(
		sessionRepo,
		jwtService,
		authsvc.SessionConfig{
			MaxSessionsPerUser: 10,
			SessionTTL:         24 * time.Hour,
			CleanupInterval:    1 * time.Hour,
			ExtendOnActivity:   true,
			ExtendThreshold:    6 * time.Hour,
		},
		app.Logger,
	)

	// Create auth service
	authService := authsvc.NewService(
		userRepo,
		sessionRepo,
		apiKeyRepo,
		jwtService,
		sessionSvc,
		authsvc.DefaultAuthConfig(),
		app.Logger,
	)

	// Initialize JWT blacklist for immediate token revocation
	jwtBlacklist := redis.NewJWTBlacklist(app.Redis)
	authService.SetJWTBlacklist(jwtBlacklist)
	app.Logger.Info("JWT blacklist enabled for immediate token revocation")

	// Wire API key authentication into API middleware
	serverCfg.RouterConfig.APIKeyAuth = func(ctx context.Context, apiKey string) (*apimiddleware.UserClaims, error) {
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

	// Bootstrap admin user if no users exist
	if err := app.bootstrapAdminUser(ctx, userRepo); err != nil {
		app.Logger.Error("Failed to bootstrap admin user", "error", err)
		// Non-fatal: continue startup
	}

	// =========================================================================
	// DOCKER SERVICES INITIALIZATION
	// =========================================================================

	defaultHostID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	// Host service in standalone mode with DB-backed repository for host CRUD
	hostService := hostsvc.NewStandaloneService(hostsvc.DefaultConfig(), app.Logger)
	app.hostService = hostService

	// Wire host repository so Create/Update/Delete hosts work in standalone mode
	stdDBHosts := stdlib.OpenDBFromPool(app.DB.Pool())
	hostRepo := postgres.NewHostRepository(sqlx.NewDb(stdDBHosts, "pgx"))
	hostService.SetRepository(hostRepo)

	// Create local Docker client and register it
	dockerClient, err := dockerpkg.NewLocalClient(ctx)
	if err != nil {
		app.Logger.Error("Failed to connect to local Docker", "error", err)
		// Non-fatal: services will return errors but app still works
	} else {
		hostService.RegisterClient(defaultHostID.String(), dockerClient)
		app.Logger.Info("Connected to local Docker engine")
	}

	// Start host service (health checks)
	if err := hostService.Start(ctx); err != nil {
		app.Logger.Error("Failed to start host service", "error", err)
	}

	// Bootstrap local host in DB (needed for foreign key in containers table)
	if err := app.bootstrapLocalHost(ctx, defaultHostID); err != nil {
		app.Logger.Error("Failed to bootstrap local host in DB", "error", err)
	}

	// Container service (syncs container state from Docker to DB)
	containerRepo := postgres.NewContainerRepository(app.DB)
	containerService := containersvc.NewService(containerRepo, hostService, containersvc.DefaultConfig(), app.Logger)
	if err := containerService.Start(ctx); err != nil {
		app.Logger.Error("Failed to start container service", "error", err)
	}

	// Do initial sync so dashboard has data immediately
	go func() {
		// Small delay to let host connection initialize
		time.Sleep(1 * time.Second)
		if err := containerService.SyncHost(ctx, defaultHostID); err != nil {
			app.Logger.Warn("Initial container sync failed (will retry on next interval)", "error", err)
		} else {
			app.Logger.Info("Initial container sync completed")
		}
	}()

	// Image, Volume, Network services (query Docker directly via host service)
	imageService := imagesvc.NewService(hostService, app.Logger)
	volumeService := volumesvc.NewService(hostService, app.Logger)
	networkService := networksvc.NewService(hostService, app.Logger)

	// Stack service
	stackRepo := postgres.NewStackRepository(app.DB)
	stackService := stacksvc.NewService(stackRepo, hostService, containerService, stacksvc.ServiceConfig{
		StacksDir:      "/app/data/stacks",
		ComposeCommand: "docker compose",
		DefaultTimeout: 5 * time.Minute,
	}, app.Logger)

	app.Logger.Info("Docker services initialized",
		"host_id", defaultHostID,
		"sync_interval", "30s",
	)

	// =========================================================================
	// LICENSE PROVIDER (initialized early — needed by team service and router)
	// =========================================================================

	licenseDataDir := app.Config.Storage.Path
	if licenseDataDir == "" {
		licenseDataDir = "/app/data"
	}
	licenseProvider, err := licensepkg.NewProvider(licenseDataDir, &zapLicenseLogger{sugar: app.Logger.Base().Sugar()})
	if err != nil {
		app.Logger.Warn("License provider initialization failed, running as CE", "error", err)
	} else {
		app.licenseProvider = licenseProvider
		app.Server.SetLicenseProvider(licenseProvider)

		// Wire limit provider to services created earlier
		hostService.SetLimitProvider(licenseProvider)

		app.Logger.Info("License provider initialized",
			"edition", licenseProvider.Edition(),
			"instance_id", licenseProvider.InstanceID(),
		)
	}

	// =========================================================================
	// TEAM SERVICE INITIALIZATION
	// =========================================================================

	teamRepo := postgres.NewTeamRepository(app.DB)
	permRepo := postgres.NewResourcePermissionRepository(app.DB)
	licenseLimits := licensepkg.CELimits()
	if licenseProvider != nil {
		licenseLimits = licenseProvider.GetLimits()
	}
	teamService := teamsvc.NewService(teamRepo, permRepo, teamsvc.Config{
		MaxTeams: licenseLimits.MaxTeams,
	}, app.Logger)
	if licenseProvider != nil {
		teamService.SetLimitProvider(licenseProvider)
	}

	app.Logger.Info("Team service initialized", "max_teams", licenseLimits.MaxTeams)

	// =========================================================================
	// SECURITY SERVICE INITIALIZATION
	// =========================================================================

	secScanRepo := postgres.NewSecurityScanRepository(app.DB, app.Logger)
	secIssueRepo := postgres.NewSecurityIssueRepository(app.DB, app.Logger)

	secCfg := securitysvc.DefaultServiceConfig()
	secCfg.ScannerConfig.IncludeCVE = app.Config.Trivy.Enabled

	securityService := securitysvc.NewService(
		secCfg,
		secScanRepo,
		secIssueRepo,
		app.Logger,
	)

	// Register all security analyzers including CIS Docker Benchmark
	securityService.SetAnalyzers([]securitysvc.Analyzer{
		securityanalyzer.NewPrivilegedAnalyzer(),
		securityanalyzer.NewUserAnalyzer(),
		securityanalyzer.NewCapabilitiesAnalyzer(),
		securityanalyzer.NewResourcesAnalyzer(),
		securityanalyzer.NewNetworkAnalyzer(),
		securityanalyzer.NewPortsAnalyzer(),
		securityanalyzer.NewMountsAnalyzer(),
		securityanalyzer.NewEnvAnalyzer(),
		securityanalyzer.NewHealthcheckAnalyzer(),
		securityanalyzer.NewRestartPolicyAnalyzer(),
		securityanalyzer.NewLoggingAnalyzer(),
		securityanalyzer.NewCISBenchmarkAnalyzer(),
	})

	// Initialize Trivy CVE scanner (optional - works if trivy binary is available)
	trivyCfg := trivypkg.DefaultClientConfig()
	if app.Config.Trivy.CacheDir != "" {
		trivyCfg.CacheDir = app.Config.Trivy.CacheDir
	}
	if app.Config.Trivy.Timeout > 0 {
		trivyCfg.Timeout = app.Config.Trivy.Timeout
	}
	if app.Config.Trivy.Severity != "" {
		trivyCfg.Severities = strings.Split(app.Config.Trivy.Severity, ",")
	}
	trivyCfg.IgnoreUnfixed = app.Config.Trivy.IgnoreUnfixed
	trivyClient := trivypkg.NewClient(trivyCfg, app.Logger)
	if app.Config.Trivy.Enabled && trivyClient.IsAvailable() {
		securityService.SetTrivyClient(trivyClient)
		// Update Trivy vulnerability database on startup if configured
		if app.Config.Trivy.UpdateDBOnStart {
			go func() {
				dbCtx, dbCancel := context.WithTimeout(context.Background(), 10*time.Minute)
				defer dbCancel()
				if err := trivyClient.UpdateDB(dbCtx); err != nil {
					app.Logger.Warn("Failed to update Trivy DB on startup", "error", err)
				} else {
					app.Logger.Info("Trivy vulnerability database updated")
				}
			}()
		}
		app.Logger.Info("Trivy CVE scanner enabled", "cve_scanning", true, "cache_dir", trivyCfg.CacheDir)
	} else if !app.Config.Trivy.Enabled {
		app.Logger.Info("Trivy CVE scanning disabled in config (trivy.enabled=false)")
	} else {
		app.Logger.Info("Trivy not available - CVE scanning disabled (install trivy to enable)")
	}

	app.Logger.Info("Security service initialized", "analyzers", 12)

	// =========================================================================
	// ENCRYPTOR (shared by Config, TOTP, NPM)
	// =========================================================================

	var encryptor *crypto.AESEncryptor
	{
		encKey := app.Config.Security.ConfigEncryptionKey
		if encKey == "" {
			// Derive a 32-byte hex key from JWT secret via SHA-256
			h := crypto.SHA256String(jwtSecret)
			encKey = h[:64] // 64 hex chars = 32 bytes
		}
		var encErr error
		encryptor, encErr = crypto.NewAESEncryptor(encKey)
		if encErr != nil {
			app.Logger.Warn("Failed to create encryptor, TOTP/NPM/ConfigService will be unavailable", "error", encErr)
		}
	}

	// =========================================================================
	// BACKUP SERVICE INITIALIZATION
	// =========================================================================

	var backupService *backupsvc.Service
	{
		// Backup storage backend (local filesystem)
		storagePath := app.Config.Storage.Path + "/backups"
		localStorage, storageErr := backupstorage.NewLocalStorage(storagePath)
		if storageErr != nil {
			app.Logger.Warn("Failed to initialize backup storage, backup service disabled", "error", storageErr, "path", storagePath)
		} else {
			// BackupRepository uses database/sql - bridge from pgx pool via stdlib adapter
			stdDB := stdlib.OpenDBFromPool(app.DB.Pool())

			backupRepo := postgres.NewBackupRepository(stdDB)

			// Providers bridge backup service to Docker operations
			volumeProvider := backupsvc.NewDockerVolumeProvider(hostService, volumeService)
			containerProvider := backupsvc.NewDockerContainerProvider(hostService, containerService)

			// Backup config from app config
			backupCfg := backupsvc.DefaultConfig()
			backupCfg.StoragePath = storagePath
			if app.Config.Storage.Backup.RetentionDays > 0 {
				backupCfg.DefaultRetentionDays = app.Config.Storage.Backup.RetentionDays
			}

			var bkErr error
			backupService, bkErr = backupsvc.NewService(
				localStorage,
				backupRepo,
				volumeProvider,
				containerProvider,
				backupCfg,
				app.Logger,
			)
			if bkErr != nil {
				app.Logger.Error("Failed to create backup service", "error", bkErr)
				backupService = nil
			} else {
				app.backupService = backupService
				if licenseProvider != nil {
					backupService.SetLimitProvider(licenseProvider)
				}
				app.Logger.Info("Backup service initialized", "storage", storagePath)
			}
		}
	}

	// =========================================================================
	// CONFIG SERVICE INITIALIZATION
	// =========================================================================

	var configService *configsvc.Service
	var configSyncService *configsvc.SyncService
	if encryptor != nil {
		configVariableRepo := postgres.NewConfigVariableRepository(app.DB, app.Logger)
		configTemplateRepo := postgres.NewConfigTemplateRepository(app.DB, app.Logger)
		configAuditRepo := postgres.NewConfigAuditRepository(app.DB, app.Logger)
		configSyncRepo := postgres.NewConfigSyncRepository(app.DB, app.Logger)

		configService = configsvc.NewService(
			configVariableRepo,
			configTemplateRepo,
			configAuditRepo,
			configSyncRepo,
			encryptor,
			app.Logger,
		)

		configSyncService = configsvc.NewSyncService(
			configVariableRepo,
			configTemplateRepo,
			configSyncRepo,
			configAuditRepo,
			app.Logger,
		)

		app.Logger.Info("Config service initialized")
	} else {
		app.Logger.Warn("Config service disabled (encryptor not available)")
	}

	// =========================================================================
	// UPDATE SERVICE INITIALIZATION
	// =========================================================================

	updateRepo := postgres.NewUpdateRepository(app.DB.Pool())

	// Docker client adapter for update service (lazy resolution via host service)
	updateDockerAdapter := updatesvc.NewDockerClientAdapter(hostService, defaultHostID)

	// Version checker with in-memory cache
	versionCache := updatesvc.NewMemoryVersionCache()
	checker := updatesvc.NewChecker(nil, versionCache, app.Logger)

	// Register Docker Hub registry client
	dockerHubClient := updatesvc.NewDockerHubClient(nil, app.Logger)
	checker.RegisterClient(dockerHubClient)

	// GHCR registry client
	ghcrClient := updatesvc.NewGHCRClient(nil, app.Logger)
	checker.RegisterClient(ghcrClient)

	// Changelog fetcher with in-memory cache
	changelogCache := updatesvc.NewMemoryChangelogCache()
	changelogFetcher := updatesvc.NewChangelogFetcher(nil, changelogCache, app.Logger)

	// Bridge adapters for backup and security integration
	var updateBackup updatesvc.BackupService
	if backupService != nil {
		updateBackup = &updateBackupAdapter{svc: backupService, hostID: defaultHostID}
	}
	updateSecurity := &updateSecurityAdapter{svc: securityService}

	updateService := updatesvc.NewService(
		updateRepo,
		checker,
		changelogFetcher,
		updateDockerAdapter,
		updateBackup,
		updateSecurity,
		containerRepo,
		nil, // Use default config
		app.Logger,
	)

	app.Logger.Info("Update service initialized",
		"backup_enabled", backupService != nil,
		"security_enabled", true,
	)

	// =========================================================================
	// NOTIFICATION SERVICE INITIALIZATION
	// =========================================================================

	notificationRepo := postgres.NewNotificationRepository(app.DB)
	notificationService := notificationsvc.New(notificationRepo, notificationsvc.DefaultConfig())
	if licenseProvider != nil {
		notificationService.SetLimitProvider(licenseProvider)
	}

	if err := notificationService.Start(ctx); err != nil {
		app.Logger.Error("Failed to start notification service", "error", err)
	} else {
		app.notificationService = notificationService
		app.Logger.Info("Notification service initialized")
	}

	// =========================================================================
	// SCHEDULER SERVICE INITIALIZATION
	// =========================================================================

	jobRepo := postgres.NewJobRepository(app.DB)

	queueConfig := scheduler.DefaultQueueConfig()
	jobQueue := scheduler.NewQueue(app.Redis, app.Logger, queueConfig)

	schedulerConfig := scheduler.DefaultConfig()
	sched := scheduler.New(jobQueue, jobRepo, schedulerConfig, app.Logger)

	// Build worker dependencies — MetricsService and InventoryService are nil
	// (workers for those will not be registered, which is safe).
	schedulerDeps := &workers.Dependencies{
		SecurityService: &schedulerSecurityAdapter{svc: securityService},
		DockerClient: &schedulerDockerScanAdapter{
			hostService: hostService,
			hostID:      defaultHostID,
		},
		UpdateService: &schedulerUpdateAdapter{
			svc:    updateService,
			hostID: defaultHostID,
		},
		CleanupService: &schedulerCleanupAdapter{
			imageService:     imageService,
			volumeService:    volumeService,
			networkService:   networkService,
			containerService: containerService,
			hostID:           defaultHostID,
		},
		JobCleanupService:   &schedulerJobCleanupAdapter{db: app.DB},
		RetentionService:    &schedulerRetentionAdapter{db: app.DB},
		NotificationService: &schedulerNotificationAdapter{svc: notificationService},
		MetricsService:      nil, // Assigned later after metrics init
		InventoryService:    nil, // Not implemented yet
		Logger:              app.Logger,
	}

	// BackupService can be nil if storage initialization failed
	if backupService != nil {
		schedulerDeps.BackupService = &schedulerBackupAdapter{
			svc:    backupService,
			hostID: defaultHostID,
		}
	}

	// Register all available workers
	workers.RegisterDefaultWorkers(sched.Registry(), schedulerDeps)

	// Start scheduler (queue processor, cron, worker pool)
	if err := sched.Start(ctx); err != nil {
		app.Logger.Error("Failed to start scheduler", "error", err)
	} else {
		app.schedulerService = sched
		app.Logger.Info("Scheduler service initialized",
			"worker_pool_size", schedulerConfig.WorkerPoolSize,
		)

		// Register default retention scheduled job (daily at 03:00 UTC)
		app.ensureRetentionScheduledJob(ctx, sched)
	}

	// =========================================================================
	// API HANDLERS & ROUTER SETUP
	// =========================================================================

	// Create user service for API handler
	userService := usersvc.NewService(
		userRepo,
		apiKeyRepo,
		usersvc.DefaultServiceConfig(),
		app.Logger,
	)
	if licenseProvider != nil {
		userService.SetLimitProvider(licenseProvider)
	}

	// Populate API handlers
	apiHandlers := app.Server.Handlers()
	apiHandlers.Auth = handlers.NewAuthHandler(authService, app.Logger)
	apiHandlers.Container = handlers.NewContainerHandler(containerService, app.Logger)
	apiHandlers.Image = handlers.NewImageHandler(imageService, app.Logger)
	apiHandlers.Volume = handlers.NewVolumeHandler(volumeService, app.Logger)
	apiHandlers.Network = handlers.NewNetworkHandler(networkService, app.Logger)
	apiHandlers.Stack = handlers.NewStackHandler(stackService, app.Logger)
	apiHandlers.Host = handlers.NewHostHandler(hostService, app.Logger)
	apiHandlers.User = handlers.NewUserHandler(userService, app.Logger)
	apiHandlers.Security = handlers.NewSecurityHandler(securityService, app.Logger)
	apiHandlers.Update = handlers.NewUpdateHandler(updateService, app.Logger)
	apiHandlers.WebSocket = handlers.NewWebSocketHandler(containerService, app.Logger)

	if backupService != nil {
		apiHandlers.Backup = handlers.NewBackupHandler(backupService, app.Logger)
	}
	if configService != nil && configSyncService != nil {
		apiHandlers.Config = handlers.NewConfigHandler(configService, configSyncService, app.Logger)
	}
	if notificationService != nil {
		apiHandlers.Notification = handlers.NewNotificationHandler(notificationService, app.Logger)
	}

	// Wire license provider to handlers that enforce feature/limit gates
	if licenseProvider != nil {
		apiHandlers.User.SetLicenseProvider(licenseProvider)
		apiHandlers.Host.SetLicenseProvider(licenseProvider)
		if apiHandlers.Notification != nil {
			apiHandlers.Notification.SetLicenseProvider(licenseProvider)
		}
		if apiHandlers.Audit != nil {
			apiHandlers.Audit.SetLicenseProvider(licenseProvider)
		}
		if apiHandlers.Backup != nil {
			apiHandlers.Backup.SetLicenseProvider(licenseProvider)
		}
	}
	if app.schedulerService != nil {
		apiHandlers.Job = handlers.NewJobsHandler(app.schedulerService, app.Logger)
	}

	// OpenAPI documentation endpoint
	apiHandlers.OpenAPI = handlers.NewOpenAPIHandler(Version)

	// Now build the router with all handlers populated
	app.Server.Setup()

	app.Logger.Info("API handlers initialized",
		"handlers_active", countActiveHandlers(apiHandlers),
	)

	// =========================================================================
	// FRONTEND INTEGRATION (Templ templates compiled into binary)
	// =========================================================================

	// Initialize ServiceRegistry with default host ID for standalone mode
	serviceRegistry := web.NewServiceRegistry(defaultHostID)

	// Inject all services
	serviceRegistry.SetAuthService(authService)
	serviceRegistry.SetUserRepository(userRepo)
	serviceRegistry.SetHostService(hostService)
	serviceRegistry.SetContainerService(containerService)
	serviceRegistry.SetImageService(imageService)
	serviceRegistry.SetVolumeService(volumeService)
	serviceRegistry.SetNetworkService(networkService)
	serviceRegistry.SetStackService(stackService)
	serviceRegistry.SetTeamService(teamService)
	serviceRegistry.SetSecurityService(securityService)
	serviceRegistry.SetUpdateService(updateService)
	if backupService != nil {
		serviceRegistry.SetBackupService(backupService)
	}
	if configService != nil {
		serviceRegistry.SetConfigService(configService)
	}

	// Create session store
	var sessionStore web.SessionStore
	var webSessionStore *web.WebSessionStore
	if app.Redis != nil {
		redisSessionStore := redis.NewSessionStore(app.Redis, 24*time.Hour)
		webSessionStore = web.NewWebSessionStore(redisSessionStore, 24*time.Hour)
		sessionStore = webSessionStore
		
		// Set session store in registry for auth validation
		serviceRegistry.SetSessionStore(webSessionStore)
	} else {
		sessionStore = web.NewNullSessionStore()
	}

	// Create web handler using Templ (all templates compiled into binary)
	webHandler := web.NewTemplHandler(serviceRegistry, Version, sessionStore)

	// Wire license provider to web handler (initialized earlier, before router Setup)
	if licenseProvider != nil {
		webHandler.SetLicenseProvider(licenseProvider)
	}

	// TOTP and NPM use the encryptor created earlier

	// Setup TOTP 2FA support and encryptor for web handler
	if encryptor != nil {
		serviceRegistry.SetEncryptor(encryptor)
		webHandler.SetEncryptor(&encryptorAdapter{enc: encryptor})
		webHandler.SetTOTPSigningKey([]byte(jwtSecret))
		app.Logger.Info("TOTP 2FA support enabled")
	}

	// Setup NPM Integration (manual connection via Settings UI)
	if encryptor != nil {
		npmConnRepo := postgres.NewNPMConnectionRepository(app.DB)
		npmMappingRepo := postgres.NewContainerProxyMappingRepository(app.DB)
		npmAuditRepo := postgres.NewNPMAuditLogRepository(app.DB)

		npmService := npm.NewService(
			npmConnRepo,
			npmMappingRepo,
			npmAuditRepo,
			encryptor,
			app.Logger.Base(),
		)
		serviceRegistry.SetNPMService(npmService)
		app.Logger.Info("NPM integration available (connect via Settings)")
	}

	// Setup Caddy Proxy Service (manual connection via Settings UI)
	if encryptor != nil {
		proxyHostRepo := postgres.NewProxyHostRepository(app.DB, app.Logger)
		proxyHeaderRepo := postgres.NewProxyHeaderRepository(app.DB)
		proxyCertRepo := postgres.NewProxyCertificateRepository(app.DB, app.Logger)
		proxyDNSRepo := postgres.NewProxyDNSProviderRepository(app.DB, app.Logger)
		proxyAuditRepo := postgres.NewProxyAuditLogRepository(app.DB)

		proxyCfg := proxysvc.Config{
			CaddyAdminURL: app.Config.Caddy.AdminURL,
			ACMEEmail:     app.Config.Caddy.ACMEEmail,
			ListenHTTP:    app.Config.Caddy.ListenHTTP,
			ListenHTTPS:   app.Config.Caddy.ListenHTTPS,
			DefaultHostID: defaultHostID,
		}

		proxyService := proxysvc.NewService(
			proxyHostRepo,
			proxyHeaderRepo,
			proxyCertRepo,
			proxyDNSRepo,
			proxyAuditRepo,
			encryptor,
			proxyCfg,
			app.Logger,
		)
		serviceRegistry.SetProxyService(proxyService)
		app.Logger.Info("Caddy proxy service available (connect via Settings)")
	}

	// Setup Storage Service (S3/MinIO - manual connection via Settings UI)
	if encryptor != nil {
		storageConnRepo := postgres.NewStorageConnectionRepository(app.DB, app.Logger)
		storageBucketRepo := postgres.NewStorageBucketRepository(app.DB, app.Logger)
		storageAuditRepo := postgres.NewStorageAuditLogRepository(app.DB, app.Logger)

		storageCfg := storagesvc.Config{
			DefaultHostID: defaultHostID,
		}

		storageService := storagesvc.NewService(
			storageConnRepo,
			storageBucketRepo,
			storageAuditRepo,
			encryptor,
			storageCfg,
			app.Logger,
		)
		serviceRegistry.SetStorageService(storageService)
		if licenseProvider != nil {
			storageService.SetLimitProvider(licenseProvider)
		}
		app.Logger.Info("Storage service (S3/MinIO) available (connect via Settings)")
	}

	// Setup Gitea Integration
	if encryptor != nil {
		giteaConnRepo := postgres.NewGiteaConnectionRepository(app.DB)
		giteaRepoRepo := postgres.NewGiteaRepositoryRepository(app.DB)
		giteaWebhookRepo := postgres.NewGiteaWebhookRepository(app.DB)

		giteaService := giteapkg.NewService(
			giteaConnRepo,
			giteaRepoRepo,
			giteaWebhookRepo,
			encryptor,
			app.Logger,
		)
		serviceRegistry.SetGiteaService(giteaService)
		app.Logger.Info("Gitea integration service enabled")

		// Setup unified Git service (multi-provider: Gitea, GitHub, GitLab)
		gitConnRepo := postgres.NewGitConnectionRepository(app.DB)
		gitRepoRepo := postgres.NewGitRepositoryRepository(app.DB)
		
		gitService := gitsvc.NewService(
			gitConnRepo,
			gitRepoRepo,
			encryptor,
			app.Logger,
		)
		serviceRegistry.SetGitService(gitService)
		if licenseProvider != nil {
			gitService.SetLimitProvider(licenseProvider)
		}
		app.Logger.Info("Unified Git service enabled (Gitea, GitHub, GitLab)")
	}

	// Setup SSH Service
	if encryptor != nil {
		sshKeyRepo := postgres.NewSSHKeyRepository(app.DB, app.Logger)
		sshConnRepo := postgres.NewSSHConnectionRepository(app.DB, app.Logger)
		sshSessionRepo := postgres.NewSSHSessionRepository(app.DB, app.Logger)
		sshTunnelRepo := postgres.NewSSHTunnelRepository(app.DB, app.Logger)

		sshService := sshsvc.NewService(
			sshKeyRepo,
			sshConnRepo,
			sshSessionRepo,
			encryptor,
			app.Logger,
		)
		sshService.SetTunnelRepo(sshTunnelRepo)
		serviceRegistry.SetSSHService(sshService)
		webHandler.SetSSHService(sshService)
		apiHandlers.SSH = handlers.NewSSHHandler(sshService, app.Logger)
		app.Logger.Info("SSH service enabled with tunnel support")
	}

	// Setup Agent Deploy Service (requires PKI for TLS cert generation)
	{
		deploySvc := deploysvc.NewService(app.pkiManager, app.Logger)
		webHandler.SetDeployService(deploySvc)
		app.Logger.Info("Agent deploy service enabled",
			"pki_available", app.pkiManager != nil,
		)
	}

	// Setup Shortcuts Service
	{
		shortcutRepo := postgres.NewWebShortcutRepository(app.DB, app.Logger)
		categoryRepo := postgres.NewShortcutCategoryRepository(app.DB, app.Logger)

		shortcutsService := shortcutssvc.NewService(
			shortcutRepo,
			categoryRepo,
			app.Logger,
		)
		webHandler.SetShortcutsService(shortcutsService)
		app.Logger.Info("Shortcuts service enabled")
	}

	// Setup Database Connections Service
	if encryptor != nil {
		dbConnRepo := postgres.NewDatabaseConnectionRepository(app.DB, app.Logger)
		databaseService := databasesvc.NewService(
			dbConnRepo,
			encryptor,
			app.Logger,
		)
		webHandler.SetDatabaseService(databaseService)
		app.Logger.Info("Database connections service enabled")

		// LDAP Browser Service
		ldapBrowserRepo := postgres.NewLDAPBrowserRepository(app.DB, app.Logger)
		ldapBrowserService := ldapbrowsersvc.NewService(
			ldapBrowserRepo,
			encryptor,
			app.Logger,
		)
		webHandler.SetLDAPBrowserService(ldapBrowserService)
		app.Logger.Info("LDAP browser service enabled")
	}

	// Setup Packet Capture Service
	{
		captureRepo := postgres.NewCaptureRepository(app.DB, app.Logger)
		captureService := capturesvc.NewService(captureRepo, app.Logger)
		webHandler.SetCaptureService(captureService)
		app.Logger.Info("Packet capture service enabled")
	}

	// Swarm service - wraps Docker Swarm operations with business logic
	swarmService := swarmsvc.NewService(hostService, app.Logger)
	webHandler.SetSwarmService(swarmService)
	app.Logger.Info("Swarm service enabled")

	// Notification config repository for web handler
	notificationConfigRepo := postgres.NewNotificationConfigRepository(app.DB)
	webHandler.SetNotificationConfigRepo(notificationConfigRepo)
	app.Logger.Info("Notification config repository enabled")

	// Inject repositories for admin pages (roles, oauth, ldap)
	roleRepo := postgres.NewRoleRepository(app.DB, app.Logger)
	webHandler.SetRoleRepo(roleRepo)
	app.Logger.Info("Role repository enabled for web handler")

	oauthConfigRepo := postgres.NewOAuthConfigRepository(app.DB, app.Logger)
	webHandler.SetOAuthConfigRepo(oauthConfigRepo)
	app.Logger.Info("OAuth config repository enabled for web handler")

	ldapConfigRepo := postgres.NewLDAPConfigRepository(app.DB, app.Logger)
	webHandler.SetLDAPConfigRepo(ldapConfigRepo)
	app.Logger.Info("LDAP config repository enabled for web handler")

	// Snippet repository (requires database/sql adapter)
	stdDBSnippets := stdlib.OpenDBFromPool(app.DB.Pool())
	snippetRepo := postgres.NewSnippetRepository(stdDBSnippets)
	webHandler.SetSnippetRepo(snippetRepo)
	app.Logger.Info("Snippet repository enabled for web handler")

	// Custom log upload repository
	customLogUploadRepo := postgres.NewCustomLogUploadRepository(app.DB, app.Logger)
	webHandler.SetCustomLogUploadRepo(customLogUploadRepo)
	app.Logger.Info("Custom log upload repository enabled for web handler")

	// Preferences repository
	prefsRepo := postgres.NewPreferencesRepo(app.DB.Pool())
	webHandler.SetPrefsRepo(prefsRepo)
	app.Logger.Info("Preferences repository enabled for web handler")

	// H1: User repository adapter for profile update/password change
	webHandler.SetUserRepo(&webUserRepoAdapter{repo: userRepo})
	app.Logger.Info("User repository adapter enabled for web handler")

	// H2: Session repository adapter for profile active sessions list
	if app.Redis != nil {
		redisSessionStore := redis.NewSessionStore(app.Redis, 24*time.Hour)
		webHandler.SetSessionRepo(&webSessionRepoAdapter{redisStore: redisSessionStore})
		app.Logger.Info("Session repository adapter enabled for web handler")
	}

	// H3: Terminal session repository for terminal history API
	terminalSessionRepo := postgres.NewTerminalSessionRepository(app.DB, app.Logger)
	webHandler.SetTerminalSessionRepo(&webTerminalSessionRepoAdapter{repo: terminalSessionRepo})
	app.Logger.Info("Terminal session repository enabled for web handler")

	// Registry, Webhook, Runbook, AutoDeploy repositories
	registryRepo := postgres.NewRegistryRepository(app.DB)
	webHandler.SetRegistryRepo(registryRepo)
	app.Logger.Info("Registry repository enabled for web handler")

	webhookRepo := postgres.NewOutgoingWebhookRepository(app.DB)
	webHandler.SetWebhookRepo(webhookRepo)
	app.Logger.Info("Outgoing webhook repository enabled for web handler")

	runbookRepo := postgres.NewRunbookRepository(app.DB)
	webHandler.SetRunbookRepo(runbookRepo)
	app.Logger.Info("Runbook repository enabled for web handler")

	autoDeployRepo := postgres.NewAutoDeployRuleRepository(app.DB)
	webHandler.SetAutoDeployRepo(autoDeployRepo)
	app.Logger.Info("Auto-deploy rule repository enabled for web handler")

	// H4: Docker client for events page
	if dockerClient != nil {
		serviceRegistry.SetDockerClient(dockerClient)
		app.Logger.Info("Docker events enabled for events page")
	}

	// M2: Logger for OAuth/LDAP admin, connections, roles, etc.
	webHandler.SetLogger(app.Logger)

	// Metrics service
	metricsRepo := postgres.NewMetricsRepository(app.DB, app.Logger)
	metricsCollector := metricssvc.NewCollector(hostService, app.Logger)
	metricsService := metricssvc.NewService(metricsRepo, metricsCollector, app.Logger)
	serviceRegistry.SetMetricsService(metricsService)
	schedulerDeps.MetricsService = metricsService
	app.Logger.Info("Metrics service enabled")

	// Alert monitoring service
	alertRepo := postgres.NewAlertRepository(app.DB)
	alertSvc := monitoringsvc.NewAlertService(
		alertRepo,
		nil, // MetricsProvider: connected when host metrics are available
		nil, // NotificationSender: connected when notification dispatch is available
		monitoringsvc.DefaultAlertConfig(),
		app.Logger,
	)
	serviceRegistry.SetAlertService(alertSvc)
	if err := alertSvc.Start(ctx); err != nil {
		app.Logger.Error("Failed to start alert service", "error", err)
	} else {
		app.Logger.Info("Alert monitoring service started")
	}

	// Set scheduler service in registry for web handlers
	if sched != nil {
		serviceRegistry.SetSchedulerService(sched)
	}

	// Create middleware
	webMiddleware := web.NewMiddleware(
		sessionStore,
		serviceRegistry.Auth(),
		serviceRegistry.Stats(),
		web.MiddlewareConfig{
			SessionName: "usulnet_session",
			LoginPath:   "/login",
			ExcludePaths: []string{
				"/static/",
				"/favicon.ico",
				"/health",
			},
		},
	)

	// Register web routes (all Templ handlers)
	webMiddleware.SetScopeProvider(teamService)
	web.RegisterFrontendRoutes(app.Server.Router(), webHandler, webMiddleware)

	app.Logger.Info("Web frontend initialized",
		"engine", "templ",
		"mode", app.Config.Mode,
	)

	// =========================================================================
	// END FRONTEND INTEGRATION
	// =========================================================================

	// Start server in background
	errCh := app.Server.StartAsync()

	// Check for immediate startup errors
	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("failed to start API server: %w", err)
		}
	case <-time.After(100 * time.Millisecond):
		// Server started successfully
	}

	return nil
}

func (app *Application) startMaster(ctx context.Context) error {
	app.Logger.Info("Starting in master mode")

	// Master mode = standalone (all services + web UI) + gateway (agent management)
	// First, initialize everything standalone does
	if err := app.startStandalone(ctx); err != nil {
		return fmt.Errorf("failed to start standalone services: %w", err)
	}

	// =========================================================================
	// GATEWAY INITIALIZATION (Master-only)
	// =========================================================================

	if app.NATS == nil {
		return fmt.Errorf("NATS connection required for master mode - configure nats.url in config")
	}

	// Create host repository for gateway (uses sqlx for agent token validation)
	stdDBGateway := stdlib.OpenDBFromPool(app.DB.Pool())
	sqlxDB := sqlx.NewDb(stdDBGateway, "pgx")
	hostRepo := postgres.NewHostRepository(sqlxDB)

	// Create gateway server
	gatewayCfg := gateway.DefaultServerConfig()
	gw, err := gateway.NewServer(app.NATS, hostRepo, gatewayCfg, app.Logger)
	if err != nil {
		return fmt.Errorf("failed to create gateway server: %w", err)
	}

	// Start gateway (subscriptions, heartbeat monitoring, cleanup loop)
	if err := gw.Start(ctx); err != nil {
		return fmt.Errorf("failed to start gateway server: %w", err)
	}
	app.gatewayServer = gw

	// Wire gateway as command sender and host repo for remote host proxy clients
	if app.hostService != nil {
		app.hostService.SetRepository(hostRepo)
		app.hostService.SetCommandSender(gw)
		app.Logger.Info("Master mode: host service upgraded with repository and command sender")
	}

	// Register gateway API routes on the existing router
	gatewayAPI := gateway.NewAPIHandler(gw, app.Logger)
	gatewayAPI.RegisterRoutes(app.Server.Router())

	app.Logger.Info("Master mode: gateway server started",
		"heartbeat_interval", gatewayCfg.HeartbeatInterval,
		"heartbeat_timeout", gatewayCfg.HeartbeatTimeout,
		"command_timeout", gatewayCfg.CommandTimeout,
	)

	return nil
}

func (app *Application) startAgent(ctx context.Context) error {
	app.Logger.Info("Starting in agent mode")

	// Validate agent configuration
	if app.Config.Agent.Token == "" {
		return fmt.Errorf("agent token required - configure agent.token in config or set USULNET_AGENT_TOKEN")
	}

	// Determine NATS gateway URL
	gatewayURL := app.Config.NATS.URL
	if app.Config.Agent.MasterURL != "" {
		gatewayURL = app.Config.Agent.MasterURL
	}
	if gatewayURL == "" {
		return fmt.Errorf("NATS URL required for agent mode - configure nats.url or agent.master_url")
	}

	// Build agent configuration
	agentCfg := agentpkg.Config{
		AgentID:     app.Config.Agent.ID,
		Token:       app.Config.Agent.Token,
		GatewayURL:  gatewayURL,
		DockerHost:  "unix:///var/run/docker.sock",
		Hostname:    app.Config.Agent.Name,
		LogLevel:    app.Config.Logging.Level,
		DataDir:     "/var/lib/usulnet-agent",
		TLSEnabled:  app.Config.Agent.TLSEnabled,
		TLSCertFile: app.Config.Agent.TLSCertFile,
		TLSKeyFile:  app.Config.Agent.TLSKeyFile,
		TLSCAFile:   app.Config.Agent.TLSCAFile,
	}

	// Auto-detect hostname if not configured
	if agentCfg.Hostname == "" {
		agentCfg.Hostname, _ = os.Hostname()
	}

	// Create agent instance
	ag, err := agentpkg.New(agentCfg, app.Logger)
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}
	app.agentInstance = ag

	// Run agent in background (blocks until context cancelled)
	agentErrCh := make(chan error, 1)
	go func() {
		if err := ag.Run(ctx); err != nil {
			app.Logger.Error("Agent error", "error", err)
			agentErrCh <- err
		}
	}()

	// Wait briefly for connection errors
	select {
	case err := <-agentErrCh:
		return fmt.Errorf("agent failed to start: %w", err)
	case <-time.After(3 * time.Second):
		// Agent started successfully
	}

	app.Logger.Info("Agent mode: connected and running",
		"agent_id", agentCfg.AgentID,
		"gateway", gatewayURL,
		"hostname", agentCfg.Hostname,
	)

	return nil
}

// shutdown gracefully stops all components
func (app *Application) shutdown(ctx context.Context) error {
	app.Logger.Info("Shutting down components...")

	// Stop scheduler first (it may be submitting jobs/notifications)
	if app.schedulerService != nil {
		if err := app.schedulerService.Stop(); err != nil {
			app.Logger.Error("Error stopping scheduler", "error", err)
		} else {
			app.Logger.Info("Scheduler stopped")
		}
	}

	// Stop notification service
	if app.notificationService != nil {
		app.notificationService.Stop()
		app.Logger.Info("Notification service stopped")
	}

	// Stop backup service
	if app.backupService != nil {
		if err := app.backupService.Stop(); err != nil {
			app.Logger.Error("Error stopping backup service", "error", err)
		} else {
			app.Logger.Info("Backup service stopped")
		}
	}

	// Stop gateway server if running (master mode)
	if app.gatewayServer != nil {
		if err := app.gatewayServer.Stop(); err != nil {
			app.Logger.Error("Error stopping gateway server", "error", err)
		} else {
			app.Logger.Info("Gateway server stopped")
		}
	}

	// Stop agent if running (agent mode)
	if app.agentInstance != nil {
		app.agentInstance.Stop()
		app.Logger.Info("Agent stopped")
	}

	// Stop license provider background goroutine
	if app.licenseProvider != nil {
		app.licenseProvider.Stop()
		app.Logger.Info("License provider stopped")
	}

	// Stop API server if running
	if app.Server != nil {
		if err := app.Server.Shutdown(ctx); err != nil {
			app.Logger.Error("Error stopping API server", "error", err)
			return err
		}
	}

	return nil
}

// ensureRetentionScheduledJob creates the default database retention cleanup job
// if it doesn't already exist. Runs daily at 03:00 UTC.
func (app *Application) ensureRetentionScheduledJob(ctx context.Context, sched *scheduler.Scheduler) {
	existing, err := sched.ListScheduledJobs(ctx, false)
	if err != nil {
		app.Logger.Warn("Failed to list scheduled jobs for retention check", "error", err)
		return
	}

	// Check if a retention job already exists
	for _, job := range existing {
		if job.Type == models.JobTypeRetention {
			app.Logger.Debug("Retention scheduled job already exists", "job_id", job.ID, "schedule", job.Schedule)
			return
		}
	}

	// Create default retention job: daily at 03:00 UTC
	_, err = sched.CreateScheduledJob(ctx, models.CreateScheduledJobInput{
		Name:        "Database Retention Cleanup",
		Type:        models.JobTypeRetention,
		Schedule:    "0 3 * * *",
		IsEnabled:   true,
		MaxAttempts: 1,
		Priority:    models.JobPriorityLow,
	})
	if err != nil {
		app.Logger.Error("Failed to create retention scheduled job", "error", err)
		return
	}

	app.Logger.Info("Retention scheduled job created (daily at 03:00 UTC)")
}

// bootstrapLocalHost ensures a local Docker host row exists in the hosts table.
// This is required for foreign key constraints when syncing containers.
func (app *Application) bootstrapLocalHost(ctx context.Context, hostID uuid.UUID) error {
	// Check if host already exists
	var exists bool
	err := app.DB.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM hosts WHERE id = $1)", hostID).Scan(&exists)
	if err != nil {
		return fmt.Errorf("check host exists: %w", err)
	}
	if exists {
		return nil
	}

	// Insert local host
	_, err = app.DB.Exec(ctx, `
		INSERT INTO hosts (id, name, display_name, endpoint_type, endpoint_url, tls_enabled, status, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, false, 'online', CURRENT_TIMESTAMP)
		ON CONFLICT (id) DO NOTHING`,
		hostID, "local", "Local Docker", "local", "unix:///var/run/docker.sock",
	)
	if err != nil {
		return fmt.Errorf("insert local host: %w", err)
	}

	app.Logger.Info("Local Docker host bootstrapped in DB", "host_id", hostID)
	return nil
}

func (app *Application) bootstrapAdminUser(ctx context.Context, userRepo *postgres.UserRepository) error {
	// Check if any users exist
	users, total, err := userRepo.List(ctx, postgres.UserListOptions{
		Page:    1,
		PerPage: 1,
	})
	if err != nil {
		return fmt.Errorf("check existing users: %w", err)
	}

	_ = users // only need the count
	if total > 0 {
		app.Logger.Info("Users already exist, skipping admin bootstrap", "count", total)
		return nil
	}

	// No users exist - create default admin
	defaultPassword := "usulnet"
	hash, err := crypto.HashPassword(defaultPassword)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}

	adminUser := &models.User{
		Username:     "admin",
		PasswordHash: hash,
		Role:         models.RoleAdmin,
		IsActive:     true,
	}

	if err := userRepo.Create(ctx, adminUser); err != nil {
		return fmt.Errorf("create admin user: %w", err)
	}

	app.Logger.Info("Default admin user created",
		"username", "admin",
		"password", defaultPassword,
		"warning", "CHANGE PASSWORD AFTER FIRST LOGIN",
	)

	return nil
}

// RunMigrations runs database migrations
func RunMigrations(cfgFile, action string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cfg, err := LoadConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	db, err := postgres.New(ctx, cfg.Database.URL, postgres.Options{
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
		// Handle down:N format
		if len(action) > 5 && action[:5] == "down:" {
			return db.MigrateDown(ctx, action[5:])
		}
		return fmt.Errorf("unknown migration action: %s", action)
	}
}

// ResetAdminPassword resets the admin user password or creates the admin if missing.
func ResetAdminPassword(cfgFile, newPassword string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg, err := LoadConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	db, err := postgres.New(ctx, cfg.Database.URL, postgres.Options{
		MaxOpenConns: 2,
		MaxIdleConns: 1,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	userRepo := postgres.NewUserRepository(db)

	// Hash the new password
	hash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Try to find admin user
	admin, err := userRepo.GetByUsername(ctx, "admin")
	if err != nil {
		// Admin doesn't exist - create it
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

	// Update existing admin
	admin.PasswordHash = hash
	admin.IsActive = true
	admin.FailedLoginAttempts = 0
	admin.LockedUntil = nil
	if err := userRepo.Update(ctx, admin); err != nil {
		return fmt.Errorf("failed to update admin password: %w", err)
	}

	fmt.Println("Admin password reset successfully. Account unlocked.")
	return nil
}

// countActiveHandlers counts non-nil handlers in the Handlers struct.
func countActiveHandlers(h *api.Handlers) int {
	count := 0
	if h.System != nil {
		count++
	}
	if h.WebSocket != nil {
		count++
	}
	if h.Auth != nil {
		count++
	}
	if h.Container != nil {
		count++
	}
	if h.Image != nil {
		count++
	}
	if h.Volume != nil {
		count++
	}
	if h.Network != nil {
		count++
	}
	if h.Stack != nil {
		count++
	}
	if h.Host != nil {
		count++
	}
	if h.User != nil {
		count++
	}
	if h.Backup != nil {
		count++
	}
	if h.Security != nil {
		count++
	}
	if h.Config != nil {
		count++
	}
	if h.Update != nil {
		count++
	}
	if h.Job != nil {
		count++
	}
	if h.Notification != nil {
		count++
	}
	return count
}

// buildNATSTLSConfig creates a *tls.Config from certificate file paths.
func buildNATSTLSConfig(certFile, keyFile, caFile string, skipVerify bool) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: skipVerify, //nolint:gosec // Configurable for dev environments
	}

	// Load CA certificate
	if caFile != "" {
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate %s: %w", caFile, err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", caFile)
		}
		tlsCfg.RootCAs = caCertPool
	}

	// Load client certificate and key for mutual TLS
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}
