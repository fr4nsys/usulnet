// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"

	agentpkg "github.com/fr4nsys/usulnet/internal/agent"
	"github.com/fr4nsys/usulnet/internal/api"
	"github.com/fr4nsys/usulnet/internal/api/handlers"
	apimiddleware "github.com/fr4nsys/usulnet/internal/api/middleware"
	dockerpkg "github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/gateway"
	giteapkg "github.com/fr4nsys/usulnet/internal/integrations/gitea"
	"github.com/fr4nsys/usulnet/internal/integrations/npm"
	licensepkg "github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/nats"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/repository/redis"
	"github.com/fr4nsys/usulnet/internal/scheduler"
	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
	auditsvc "github.com/fr4nsys/usulnet/internal/services/audit"
	authsvc "github.com/fr4nsys/usulnet/internal/services/auth"
	ldapauthsvc "github.com/fr4nsys/usulnet/internal/services/auth/ldap"
	oauthauthsvc "github.com/fr4nsys/usulnet/internal/services/auth/oauth"
	backupsvc "github.com/fr4nsys/usulnet/internal/services/backup"
	backupstorage "github.com/fr4nsys/usulnet/internal/services/backup/storage"
	capturesvc "github.com/fr4nsys/usulnet/internal/services/capture"
	configsvc "github.com/fr4nsys/usulnet/internal/services/config"
	containersvc "github.com/fr4nsys/usulnet/internal/services/container"
	databasesvc "github.com/fr4nsys/usulnet/internal/services/database"
	deploysvc "github.com/fr4nsys/usulnet/internal/services/deploy"
	gitsvc "github.com/fr4nsys/usulnet/internal/services/git"
	hostsvc "github.com/fr4nsys/usulnet/internal/services/host"
	imagesvc "github.com/fr4nsys/usulnet/internal/services/image"
	ldapbrowsersvc "github.com/fr4nsys/usulnet/internal/services/ldapbrowser"
	metricssvc "github.com/fr4nsys/usulnet/internal/services/metrics"
	monitoringsvc "github.com/fr4nsys/usulnet/internal/services/monitoring"
	networksvc "github.com/fr4nsys/usulnet/internal/services/network"
	notificationsvc "github.com/fr4nsys/usulnet/internal/services/notification"
	proxysvc "github.com/fr4nsys/usulnet/internal/services/proxy"
	"github.com/fr4nsys/usulnet/internal/services/proxy/caddy"
	nginxbackend "github.com/fr4nsys/usulnet/internal/services/proxy/nginx"
	rdpsvc "github.com/fr4nsys/usulnet/internal/services/rdp"
	recordingsvc "github.com/fr4nsys/usulnet/internal/services/recording"
	securitysvc "github.com/fr4nsys/usulnet/internal/services/security"
	securityanalyzer "github.com/fr4nsys/usulnet/internal/services/security/analyzer"
	trivypkg "github.com/fr4nsys/usulnet/internal/services/security/trivy"
	shortcutssvc "github.com/fr4nsys/usulnet/internal/services/shortcuts"
	sshsvc "github.com/fr4nsys/usulnet/internal/services/ssh"
	stacksvc "github.com/fr4nsys/usulnet/internal/services/stack"
	storagesvc "github.com/fr4nsys/usulnet/internal/services/storage"
	swarmsvc "github.com/fr4nsys/usulnet/internal/services/swarm"
	teamsvc "github.com/fr4nsys/usulnet/internal/services/team"
	// Enterprise Phase 2-5 services
	changessvc "github.com/fr4nsys/usulnet/internal/services/changes"
	compliancesvc "github.com/fr4nsys/usulnet/internal/services/compliance"
	costoptsvc "github.com/fr4nsys/usulnet/internal/services/costopt"
	driftsvc "github.com/fr4nsys/usulnet/internal/services/drift"
	imagesignsvc "github.com/fr4nsys/usulnet/internal/services/imagesign"
	logaggsvc "github.com/fr4nsys/usulnet/internal/services/logagg"
	// Phase 3: Market Expansion - GitOps
	dashboardsvc "github.com/fr4nsys/usulnet/internal/services/dashboard"
	ephemeralsvc "github.com/fr4nsys/usulnet/internal/services/ephemeral"
	gitsyncsvc "github.com/fr4nsys/usulnet/internal/services/gitsync"
	manifestsvc "github.com/fr4nsys/usulnet/internal/services/manifest"
	opasvc "github.com/fr4nsys/usulnet/internal/services/opa"
	reconconnectors "github.com/fr4nsys/usulnet/internal/services/recon/connectors"
	hibpconnector "github.com/fr4nsys/usulnet/internal/services/recon/connectors/hibp"
	reconwiring "github.com/fr4nsys/usulnet/internal/services/recon/wiring"
	registrysvc "github.com/fr4nsys/usulnet/internal/services/registry"
	runtimesvc "github.com/fr4nsys/usulnet/internal/services/runtime"
	updatesvc "github.com/fr4nsys/usulnet/internal/services/update"
	usersvc "github.com/fr4nsys/usulnet/internal/services/user"
	volumesvc "github.com/fr4nsys/usulnet/internal/services/volume"
	"github.com/fr4nsys/usulnet/internal/web"

	"go.uber.org/zap"
)

// standaloneHostID is the well-known host ID used for the local Docker
// daemon in standalone (non-agent) mode.
var standaloneHostID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

// zapLicenseLogger adapts zap.SugaredLogger to satisfy license.Logger.
type zapLicenseLogger struct {
	sugar *zap.SugaredLogger
}

func (z *zapLicenseLogger) Info(msg string, keysAndValues ...any) {
	z.sugar.Infow(msg, keysAndValues...)
}
func (z *zapLicenseLogger) Warn(msg string, keysAndValues ...any) {
	z.sugar.Warnw(msg, keysAndValues...)
}
func (z *zapLicenseLogger) Error(msg string, keysAndValues ...any) {
	z.sugar.Errorw(msg, keysAndValues...)
}

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

// connectorRegistryAdapter bridges *reconconnectors.Registry (which uses
// the package-local Info type to avoid a handlers→connectors import
// cycle) to handlers.ReconConnectorService. The adapter copies field
// values across; the types are structurally identical.
type connectorRegistryAdapter struct {
	reg *reconconnectors.Registry
}

func newConnectorRegistryAdapter(reg *reconconnectors.Registry) *connectorRegistryAdapter {
	return &connectorRegistryAdapter{reg: reg}
}

func (a *connectorRegistryAdapter) ListConnectors(ctx context.Context) ([]handlers.ReconConnectorInfo, error) {
	infos, err := a.reg.ListConnectors(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]handlers.ReconConnectorInfo, len(infos))
	for i, in := range infos {
		out[i] = handlers.ReconConnectorInfo{
			Kind:    in.Kind,
			Enabled: in.Enabled,
			Healthy: in.Healthy,
		}
	}
	return out, nil
}

func (a *connectorRegistryAdapter) SetConnector(ctx context.Context, kind string, creds map[string]string, enabled bool) error {
	return a.reg.SetConnector(ctx, kind, creds, enabled)
}

func (a *connectorRegistryAdapter) DeleteConnector(ctx context.Context, kind string) error {
	return a.reg.DeleteConnector(ctx, kind)
}

// resolveHIBPKey returns the HIBP API key + the enabled flag for the
// connector at boot. The lookup order is:
//
//  1. recon_connectors row (kind='hibp') decrypted via the
//     CredentialStore — operator-managed via the API.
//  2. USULNET_RECON_HIBP_API_KEY environment variable — kept as a
//     migration grace for installs that predate v26.5.1.
//
// When neither yields a key, the connector still registers (so the
// /connectors API can render "not configured"), but Enabled is false
// so HealthCheck returns ErrNoAPIKey without producing a 5xx.
func resolveHIBPKey(ctx context.Context, store reconconnectors.CredentialStore, log *logger.Logger) (string, bool) {
	if store != nil {
		// CredentialStore is the narrow interface (Save / Delete only);
		// the postgres impl also exposes Load(). Type-assert so we
		// don't widen the interface for every consumer that only
		// writes.
		if loader, ok := store.(interface {
			Load(ctx context.Context, kind string) (map[string]string, bool, error)
		}); ok {
			creds, enabled, err := loader.Load(ctx, hibpconnector.Kind)
			if err == nil {
				if key := creds["api_key"]; key != "" {
					return key, enabled
				}
				// Row exists but holds no key — treat as "not
				// configured" so the env-var fallback can fill in.
			} else if !errors.Is(err, postgres.ErrConnectorNotFound) {
				log.Warn("recon: load HIBP credentials failed", "error", err)
			}
		}
	}
	envKey := os.Getenv("USULNET_RECON_HIBP_API_KEY")
	return envKey, envKey != ""
}

// hibpKeySource returns a non-secret tag describing where the key
// came from. The value is only ever logged as `key_source=db` /
// `key_source=env` / `key_source=none` — never the key itself.
func hibpKeySource(store reconconnectors.CredentialStore, key string) string {
	if key == "" {
		return "none"
	}
	if store == nil {
		return "env"
	}
	// We don't re-query here — the resolveHIBPKey path is the
	// authority. If the DB held the key, store was non-nil and the
	// Load() returned the same string we got back; otherwise we fell
	// through to the env var.
	if os.Getenv("USULNET_RECON_HIBP_API_KEY") == key {
		return "env"
	}
	return "db"
}

// natsProberAdapter wraps *nats.Client to satisfy the web.NATSProber interface.
// ServerInfo() returns a formatted string instead of the nats.ServerInfo struct.
type natsProberAdapter struct {
	client *nats.Client
}

func (a *natsProberAdapter) IsConnected() bool { return a.client.IsConnected() }
func (a *natsProberAdapter) IsTLS() bool       { return a.client.IsTLS() }
func (a *natsProberAdapter) ServerInfo() string {
	info := a.client.ServerInfo()
	if info.ServerName != "" {
		return fmt.Sprintf("NATS %s (%s)", info.ServerName, info.URL)
	}
	if info.URL != "" {
		return info.URL
	}
	return "NATS"
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

	// Packet capture (requires cleanup on shutdown)
	captureService *capturesvc.Service

	// Container service
	containerService *containersvc.Service

	// Recon module acknowledgement store. The pointer is held on the
	// Application so the (future) recon.Service implementation can
	// share the same checker with the API middleware.
	reconAckStore *handlers.MemoryAckStore
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

	// Configure Docker socket path: use explicit config, or auto-detect
	if cfg.Docker.Socket != "" {
		dockerpkg.SetLocalSocketPath(cfg.Docker.Socket)
	} else {
		detected := dockerpkg.DetectSocketPath()
		dockerpkg.SetLocalSocketPath(detected)
	}

	// Initialize logger (supports stdout, stderr, and file with rotation)
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

	log.Info("Starting usulnet",
		"version", Version,
		"commit", Commit,
		"mode", cfg.Mode,
	)

	log.Info(dockerpkg.FormatDetectedSocket(dockerpkg.LocalSocketPath()),
		"socket", dockerpkg.LocalSocketPath(),
		"configured", cfg.Docker.Socket != "",
	)

	// Initialize PostgreSQL
	dbURL := cfg.Database.URL
	// Enforce SSL mode from config if the URL doesn't already specify one
	if cfg.Database.SSLMode != "" && !strings.Contains(dbURL, "sslmode=") {
		sep := "?"
		if strings.Contains(dbURL, "?") {
			sep = "&"
		}
		dbURL += sep + "sslmode=" + cfg.Database.SSLMode
	}
	log.Info("Connecting to PostgreSQL...", "sslmode", cfg.Database.SSLMode)
	db, err := postgres.New(ctx, dbURL, postgres.Options{
		MaxOpenConns:    cfg.Database.MaxOpenConns,
		MaxIdleConns:    cfg.Database.MaxIdleConns,
		ConnMaxLifetime: cfg.Database.ConnMaxLifetime,
		ConnMaxIdleTime: cfg.Database.ConnMaxIdleTime,
		QueryTimeout:    cfg.Database.QueryTimeout,
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
			URL:              cfg.NATS.URL,
			Name:             cfg.NATS.Name,
			Token:            cfg.NATS.Token,
			Username:         cfg.NATS.Username,
			Password:         cfg.NATS.Password,
			MaxReconnects:    cfg.NATS.MaxReconnects,
			ReconnectWait:    cfg.NATS.ReconnectWait,
			JetStreamEnabled: cfg.NATS.JetStream.Enabled,
			JetStreamDomain:  cfg.NATS.JetStream.Domain,
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
	routerCfg := api.DefaultRouterConfig(app.Config.Security.JWTSecret)
	// Wire rate limit from config (default 100 req/min from config.yaml)
	if app.Config.Server.RateLimitRPS > 0 {
		routerCfg.RateLimitPerMinute = app.Config.Server.RateLimitRPS
	}
	// Wire metrics config
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

	// Set logger so Recovery middleware actually logs panics
	serverCfg.RouterConfig.Logger = app.Logger
	// Increase request timeout - stack deploys (docker compose pull+up) need more than 30s
	serverCfg.RouterConfig.RequestTimeout = 5 * time.Minute

	// Override CORS if USULNET_CORS_ORIGINS is set (comma-separated origins).
	// CookieSecure from config is respected for CORS AllowCredentials.
	if corsOrigins := os.Getenv("USULNET_CORS_ORIGINS"); corsOrigins != "" {
		serverCfg.RouterConfig.CORSConfig = apimiddleware.CORSFromEnv(corsOrigins, app.Config.Security.CookieSecure)
		app.Logger.Info("CORS configured from USULNET_CORS_ORIGINS",
			"origins", corsOrigins,
			"cookie_secure", app.Config.Security.CookieSecure,
		)
	}

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

	serverCfg.Version = Version
	serverCfg.Commit = Commit
	serverCfg.BuildTime = BuildTime
	serverCfg.Logger = app.Logger
	serverCfg.RedirectHTTPS = app.Config.Server.RedirectHTTPS
	app.Server = api.NewServer(serverCfg)
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
		// This should never happen — Config.Validate() requires jwt_secret.
		// Fail hard rather than silently running with an insecure default.
		return fmt.Errorf("security.jwt_secret is required — set USULNET_JWT_SECRET")
	}
	// Wire JWT/refresh expiry from config (defaults: 24h / 168h)
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

	// Create session service (session TTL matches JWT expiry from config)
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

	// Wire audit logging service for auth events (login/logout/password change)
	auditLogRepo := postgres.NewAuditLogRepository(app.DB, app.Logger)
	auditService := auditsvc.NewService(auditLogRepo, app.Logger, auditsvc.DefaultConfig())
	authService.SetAuditService(auditService)
	auditService.StartCleanupWorker(ctx)
	web.SetAuditDBService(auditService)
	app.Logger.Info("Audit logging service enabled (persistent DB + in-memory cache)")

	// Wire JWT blacklist into API middleware for immediate token revocation.
	// Every incoming JWT is checked against Redis to catch logouts, password changes,
	// and admin-initiated revocations before the token's natural expiry.
	serverCfg.RouterConfig.TokenValidator = func(ctx context.Context, _ string, claims *apimiddleware.UserClaims) error {
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

	defaultHostID := standaloneHostID

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
	app.containerService = containerService
	if err := containerService.Start(ctx); err != nil {
		app.Logger.Error("Failed to start container service", "error", err)
	}

	// Do initial sync so dashboard has data immediately
	go func() {
		// Small delay to let host connection initialize (cancelable)
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			return
		}
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
		app.Server.RegisterLicenseProvider(licenseProvider)

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
			// Derive a 32-byte hex key from JWT secret via SHA-256.
			// WARNING: changing jwt_secret will invalidate all encrypted data
			// (TOTP secrets, NPM credentials, config values). Set
			// USULNET_ENCRYPTION_KEY explicitly for independent key rotation.
			h := crypto.SHA256String(jwtSecret)
			encKey = h[:64] // 64 hex chars = 32 bytes
			app.Logger.Warn("encryption_key not set — deriving from jwt_secret (set USULNET_ENCRYPTION_KEY for independent rotation)")
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
			backupRepo := postgres.NewBackupRepository(app.DB)

			// Providers bridge backup service to Docker operations
			volumeProvider := backupsvc.NewDockerVolumeProvider(hostService, volumeService)
			containerProvider := backupsvc.NewDockerContainerProvider(hostService, containerService)

			// Backup config from app config
			backupCfg := backupsvc.DefaultConfig()
			backupCfg.StoragePath = storagePath
			backupCfg.StorageType = app.Config.Storage.Type
			if app.Config.Storage.Backup.RetentionDays > 0 {
				backupCfg.DefaultRetentionDays = app.Config.Storage.Backup.RetentionDays
			}
			// Wire compression from config (default zstd / level 3)
			if comp := app.Config.Storage.Backup.Compression; comp != "" {
				backupCfg.DefaultCompression = models.BackupCompression(comp)
			}
			if app.Config.Storage.Backup.CompressionLevel > 0 {
				backupCfg.CompressionLevel = app.Config.Storage.Backup.CompressionLevel
			}

			// Stack provider bridges backup service to stack operations
			stackProvider := backupsvc.NewDockerStackProvider(stackService, containerService)

			var bkErr error
			backupService, bkErr = backupsvc.NewService(
				localStorage,
				backupRepo,
				volumeProvider,
				containerProvider,
				backupCfg,
				app.Logger,
				backupsvc.WithStackProviderOption(stackProvider),
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
			hostService:      hostService,
			hostID:           defaultHostID,
		},
		JobCleanupService:   &schedulerJobCleanupAdapter{db: app.DB},
		RetentionService:    &schedulerRetentionAdapter{db: app.DB},
		NotificationService: &schedulerNotificationAdapter{svc: notificationService},
		MetricsService:      nil, // Assigned later after metrics init
		InventoryService:    &schedulerInventoryAdapter{hostService: hostService},
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

		// Register automatic database backup job (daily at 02:00 UTC)
		if backupService != nil {
			app.ensureDatabaseBackupScheduledJob(ctx, sched, defaultHostID)
		}
	}

	// =========================================================================
	// API HANDLERS & ROUTER SETUP
	// =========================================================================

	// Create user service for API handler (wire password policy from config)
	userServiceConfig := usersvc.DefaultServiceConfig()
	if app.Config.Security.PasswordMinLength > 0 {
		userServiceConfig.PasswordMinLength = app.Config.Security.PasswordMinLength
	}
	userServiceConfig.PasswordRequireUpper = app.Config.Security.PasswordRequireUpper
	userServiceConfig.PasswordRequireNumber = app.Config.Security.PasswordRequireNumber
	userServiceConfig.PasswordRequireSymbol = app.Config.Security.PasswordRequireSymbol
	if app.Config.Security.MaxFailedLogins > 0 {
		userServiceConfig.MaxFailedLogins = app.Config.Security.MaxFailedLogins
	}
	if app.Config.Security.LockoutDuration > 0 {
		userServiceConfig.LockoutDuration = app.Config.Security.LockoutDuration
	}
	if app.Config.Security.APIKeyLength > 0 {
		userServiceConfig.APIKeyLength = app.Config.Security.APIKeyLength
	}
	userService := usersvc.NewService(
		userRepo,
		apiKeyRepo,
		userServiceConfig,
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

	// Settings handler (uses config variable repo for app settings + LDAP config repo)
	{
		settingsConfigRepo := postgres.NewConfigVariableRepository(app.DB, app.Logger)
		settingsLDAPRepo := postgres.NewLDAPConfigRepository(app.DB, app.Logger)
		apiHandlers.Settings = handlers.NewSettingsHandler(settingsConfigRepo, settingsLDAPRepo, nil, app.Logger)
	}

	// License handler
	if licenseProvider != nil {
		apiHandlers.License = handlers.NewLicenseHandler(licenseProvider, nil, app.Logger)
	}

	// Registry browsing service and handler
	{
		registryBrowseRepo := postgres.NewRegistryRepository(app.DB)
		var registryEncryptor registrysvc.Encryptor
		if encryptor != nil {
			registryEncryptor = &encryptorAdapter{enc: encryptor}
		}
		registryBrowseSvc := registrysvc.NewService(registryBrowseRepo, registryEncryptor, app.Logger)
		apiHandlers.Registry = handlers.NewRegistryHandler(registryBrowseSvc, app.Logger)
		app.Logger.Info("Registry browsing service enabled")
	}

	// OpenAPI documentation endpoint
	apiHandlers.OpenAPI = handlers.NewOpenAPIHandler(Version)

	// Recon + metadata module handlers (v26.5.0). The recon.Service
	// implementation lands in a follow-up; until then the handler
	// constructors accept nil services and every gated route returns
	// 503 engine_unavailable. The feature-flag middleware short-
	// circuits the whole subtree with 404 when recon.enabled is false.
	{
		reconAck := handlers.NewMemoryAckStore()

		// Connectors (v26.5.0 ships HIBP only; Shodan + IntelX in
		// v26.5.2). When the feature flag is off we still register a
		// nil registry so the handler returns an empty list; when on,
		// every Connectors.X.Enabled toggle wires its connector
		// behind the registry.
		//
		// Credentials live in recon_connectors (encrypted at rest;
		// AES-256-GCM with the installation-wide data key). The
		// registry's CredentialStore is the postgres repo; the
		// USULNET_RECON_HIBP_API_KEY env var is honoured only when
		// the DB has no row yet (migration grace), and any
		// successful Save() write through the API takes precedence
		// from then on.
		var connectorSvc handlers.ReconConnectorService
		if app.Config.Recon.Enabled {
			var credStore reconconnectors.CredentialStore
			if app.DB != nil && encryptor != nil {
				credStore = postgres.NewReconConnectorsRepository(app.DB, encryptor)
			} else {
				app.Logger.Warn("recon: connector credential store unavailable (no DB / encryptor); SetConnector/DeleteConnector will 501")
			}

			reg := reconconnectors.NewRegistry(credStore, app.Logger)
			if app.Config.Recon.Connectors.HIBP.Enabled {
				hibpKey, hibpKeyEnabled := resolveHIBPKey(ctx, credStore, app.Logger)
				if err := reg.Register(hibpconnector.New(hibpconnector.Config{
					APIKey:  hibpKey,
					Enabled: hibpKeyEnabled,
				}, app.Logger)); err != nil {
					app.Logger.Warn("recon: HIBP connector registration failed", "error", err)
				} else {
					app.Logger.Info("recon: HIBP connector registered",
						"key_source", hibpKeySource(credStore, hibpKey),
					)
				}
			}
			connectorSvc = newConnectorRegistryAdapter(reg)
		}

		apiHandlers.Recon = handlers.NewReconHandler(nil, connectorSvc, reconAck, app.Logger)
		apiHandlers.Metadata = handlers.NewMetadataHandler(nil, handlers.DefaultMetadataUploadLimits(), app.Logger)
		app.Server.RegisterReconConfig(app.Config.Recon.Enabled, reconAck)
		app.reconAckStore = reconAck
	}

	// Now build the router with all handlers populated
	app.Server.Setup()

	// =========================================================================
	// HEALTH CHECKER REGISTRATION
	// =========================================================================
	// Register health checkers for all infrastructure dependencies so that
	// /health, /healthz, and /ready endpoints report component-level status.

	// PostgreSQL health checker
	if app.DB != nil {
		app.Server.RegisterDatabaseHealth(func(ctx context.Context) error {
			return app.DB.Pool().Ping(ctx)
		})
		app.Logger.Info("Health checker registered: postgresql")
	}

	// Redis health checker (uses HealthCheck: Ping + pool connectivity)
	if app.Redis != nil {
		app.Server.RegisterRedisHealth(func(ctx context.Context) error {
			return app.Redis.HealthCheck(ctx)
		})
		app.Logger.Info("Health checker registered: redis")
	}

	// Docker Engine health checker
	if dockerClient != nil {
		app.Server.RegisterDockerHealth(func(ctx context.Context) error {
			return dockerClient.Ping(ctx)
		})
		app.Logger.Info("Health checker registered: docker")
	}

	// NATS health checker (uses Health: IsConnected + FlushTimeout round-trip)
	if app.NATS != nil {
		app.Server.RegisterNATSHealth(func(ctx context.Context) error {
			return app.NATS.Health(ctx)
		})
		app.Logger.Info("Health checker registered: nats")
	}

	app.Logger.Info("API handlers initialized",
		"handlers_active", countActiveHandlers(apiHandlers),
	)

	// =========================================================================
	// FRONTEND INTEGRATION (Templ templates compiled into binary)
	// =========================================================================

	// -------------------------------------------------------------------------
	// Build ServiceRegistry + Handler deps incrementally (constructor injection)
	// -------------------------------------------------------------------------

	// ServiceRegistry deps — core services
	regDeps := web.ServiceRegistryDeps{
		DefaultHostID:    defaultHostID,
		AuthService:      authService,
		UserRepository:   userRepo,
		AuditLogRepo:     auditLogRepo,
		HostService:      hostService,
		ContainerService: containerService,
		ImageService:     imageService,
		VolumeService:    volumeService,
		NetworkService:   networkService,
		StackService:     stackService,
		TeamService:      teamService,
		SecurityService:  securityService,
		UpdateService:    updateService,
		BackupService:    backupService, // nil-safe
		ConfigService:    configService, // nil-safe
	}

	// Create session store (reused later for session repo adapter)
	var sessionStore web.SessionStore
	var webSessionStore *web.WebSessionStore
	var redisSessionStore *redis.SessionStore
	if app.Redis != nil {
		redisSessionStore = redis.NewSessionStore(app.Redis, accessTTL)
		cookieCfg := web.CookieConfig{
			Secure:   app.Config.Security.CookieSecure,
			SameSite: parseSameSite(app.Config.Security.CookieSameSite),
			Domain:   app.Config.Security.CookieDomain,
		}
		webSessionStore = web.NewWebSessionStore(redisSessionStore, accessTTL, cookieCfg)
		sessionStore = webSessionStore
		regDeps.SessionStore = webSessionStore
	} else {
		sessionStore = web.NewNullSessionStore()
	}

	// Handler deps — start with core fields, populated incrementally below
	hdlDeps := web.HandlerDeps{
		Version:         Version,
		Commit:          Commit,
		BuildTime:       BuildTime,
		Mode:            app.Config.Mode,
		SessionStore:    sessionStore,
		BaseURL:         app.Config.Server.BaseURL,
		TerminalEnabled: app.Config.Terminal.Enabled,
		TerminalUser:    app.Config.Terminal.User,
		TerminalShell:   app.Config.Terminal.Shell,
		GuacdEnabled:    app.Config.Guacd.Enabled,
		GuacdHost:       app.Config.Guacd.Host,
		GuacdPort:       app.Config.Guacd.Port,
		Logger:          app.Logger,
		RedisURL:        app.Config.Redis.URL,
		DBSSLMode:       app.Config.Database.SSLMode,
	}

	// Wire About page probes (nil-safe — handler checks before use)
	if app.DB != nil {
		hdlDeps.DB = app.DB
	}
	if app.Redis != nil {
		hdlDeps.RedisProber = app.Redis
	}
	if app.NATS != nil {
		hdlDeps.NATSProber = &natsProberAdapter{client: app.NATS}
	}

	if licenseProvider != nil {
		hdlDeps.LicenseProvider = licenseProvider
	}

	// TOTP and NPM use the encryptor created earlier
	if encryptor != nil {
		regDeps.Encryptor = encryptor
		hdlDeps.Encryptor = &encryptorAdapter{enc: encryptor}
		hdlDeps.BackupEncryptor = encryptor // *crypto.AESEncryptor satisfies BackupEncryptor directly
		hdlDeps.TOTPSigningKey = []byte(jwtSecret)
		app.Logger.Info("TOTP 2FA support enabled")
	}

	// Setup NPM Integration (manual connection via Settings UI, gated by npm.enabled)
	if encryptor != nil && app.Config.NPM.Enabled {
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
		regDeps.NPMService = npmService
		app.Logger.Info("NPM integration available (connect via Settings)")
	}

	// Setup Reverse Proxy Service (nginx by default, Caddy as fallback)
	if encryptor != nil && (app.Config.Nginx.Enabled || app.Config.Caddy.Enabled) {
		proxyHostRepo := postgres.NewProxyHostRepository(app.DB, app.Logger)
		proxyHeaderRepo := postgres.NewProxyHeaderRepository(app.DB)
		proxyCertRepo := postgres.NewProxyCertificateRepository(app.DB, app.Logger)
		proxyDNSRepo := postgres.NewProxyDNSProviderRepository(app.DB, app.Logger)
		proxyAuditRepo := postgres.NewProxyAuditLogRepository(app.DB)

		var backend proxysvc.SyncBackend
		var proxyCfg proxysvc.Config

		if app.Config.Nginx.Enabled {
			// nginx backend (default/recommended)
			nginxCfg := nginxbackend.Config{
				ConfigDir:      app.Config.Nginx.ConfigDir,
				CertDir:        app.Config.Nginx.CertDir,
				ACMEWebRoot:    app.Config.Nginx.ACMEWebRoot,
				ACMEAccountDir: app.Config.Nginx.ACMEAccountDir,
			}
			if nginxCfg.ConfigDir == "" {
				nginxCfg.ConfigDir = "/etc/nginx/conf.d/usulnet"
			}
			if nginxCfg.CertDir == "" {
				nginxCfg.CertDir = "/etc/usulnet/certs"
			}
			if nginxCfg.ACMEWebRoot == "" {
				nginxCfg.ACMEWebRoot = "/var/lib/usulnet/acme"
			}
			if nginxCfg.ACMEAccountDir == "" {
				nginxCfg.ACMEAccountDir = "/var/lib/usulnet/acme/account"
			}
			backend = nginxbackend.NewBackend(nginxCfg)
			proxyCfg = proxysvc.Config{
				ACMEEmail:     app.Config.Nginx.ACMEEmail,
				ListenHTTP:    app.Config.Nginx.ListenHTTP,
				ListenHTTPS:   app.Config.Nginx.ListenHTTPS,
				DefaultHostID: defaultHostID,
			}
			app.Logger.Info("Reverse proxy service: nginx backend")
		} else {
			// Caddy backend (legacy)
			caddyClient := caddy.NewClient(caddy.Config{
				AdminURL: app.Config.Caddy.AdminURL,
				Timeout:  10 * time.Second,
			})
			backend = proxysvc.NewCaddyBackend(caddyClient)
			proxyCfg = proxysvc.Config{
				CaddyAdminURL: app.Config.Caddy.AdminURL,
				ACMEEmail:     app.Config.Caddy.ACMEEmail,
				ListenHTTP:    app.Config.Caddy.ListenHTTP,
				ListenHTTPS:   app.Config.Caddy.ListenHTTPS,
				DefaultHostID: defaultHostID,
			}
			app.Logger.Info("Reverse proxy service: Caddy backend")
		}

		proxyService := proxysvc.NewService(
			proxyHostRepo,
			proxyHeaderRepo,
			proxyCertRepo,
			proxyDNSRepo,
			proxyAuditRepo,
			encryptor,
			backend,
			proxyCfg,
			app.Logger,
		)
		regDeps.ProxyService = proxyService
	}

	// Setup Storage Service (S3, Azure, GCS, B2, SFTP, Local — requires encryption key)
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
		regDeps.StorageService = storageService
		if licenseProvider != nil {
			storageService.SetLimitProvider(licenseProvider)
		}
		app.Logger.Info("Storage service available (S3, Azure, GCS, B2, SFTP, Local)")
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
		regDeps.GiteaService = giteaService
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
		regDeps.GitService = gitService
		hdlDeps.GitSvcFull = gitService
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
		regDeps.SSHService = sshService
		hdlDeps.SSHService = sshService
		apiHandlers.SSH = handlers.NewSSHHandler(sshService, app.Logger)
		app.Logger.Info("SSH service enabled with tunnel support")
	}

	// Setup Agent Deploy Service (requires PKI for TLS cert generation)
	{
		deploySvc := deploysvc.NewService(app.pkiManager, app.Logger)
		hdlDeps.DeployService = deploySvc
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
		hdlDeps.ShortcutsService = shortcutsService
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
		hdlDeps.DatabaseService = databaseService
		app.Logger.Info("Database connections service enabled")

		// LDAP Browser Service
		ldapBrowserRepo := postgres.NewLDAPBrowserRepository(app.DB, app.Logger)
		ldapBrowserService := ldapbrowsersvc.NewService(
			ldapBrowserRepo,
			encryptor,
			app.Logger,
		)
		hdlDeps.LDAPBrowserService = ldapBrowserService
		app.Logger.Info("LDAP browser service enabled")

		// RDP Connection Service
		rdpConnRepo := postgres.NewRDPConnectionRepository(app.DB, app.Logger)
		rdpService := rdpsvc.NewService(rdpConnRepo, encryptor, app.Logger)
		hdlDeps.RDPService = rdpService
		app.Logger.Info("RDP connections service enabled")
	}

	// Setup Packet Capture Service
	{
		captureRepo := postgres.NewCaptureRepository(app.DB, app.Logger)
		app.captureService = capturesvc.NewService(captureRepo, app.Logger)
		hdlDeps.CaptureService = app.captureService
		app.Logger.Info("Packet capture service enabled")
	}

	// Swarm service - wraps Docker Swarm operations with business logic
	swarmService := swarmsvc.NewService(hostService, app.Logger)
	hdlDeps.SwarmService = swarmService
	app.Logger.Info("Swarm service enabled")

	// Notification config repository for web handler
	notificationConfigRepo := postgres.NewNotificationConfigRepository(app.DB)
	hdlDeps.NotificationConfigRepo = notificationConfigRepo
	if notificationService != nil {
		hdlDeps.NotificationSvc = &runbookNotificationAdapter{svc: notificationService}
	}
	app.Logger.Info("Notification config repository enabled")

	// Inject repositories for admin pages (roles, oauth, ldap)
	roleRepo := postgres.NewRoleRepository(app.DB, app.Logger)
	hdlDeps.RoleRepo = roleRepo
	app.Logger.Info("Role repository enabled for web handler")

	oauthConfigRepo := postgres.NewOAuthConfigRepository(app.DB, app.Logger)
	hdlDeps.OAuthConfigRepo = oauthConfigRepo
	app.Logger.Info("OAuth config repository enabled for web handler")

	ldapConfigRepo := postgres.NewLDAPConfigRepository(app.DB, app.Logger)
	hdlDeps.LDAPConfigRepo = ldapConfigRepo
	app.Logger.Info("LDAP config repository enabled for web handler")

	// =========================================================================
	// WIRE LDAP AUTH PROVIDERS INTO AUTH SERVICE
	// Load enabled LDAP configs from DB, build auth providers, and register
	// them with the auth service so that LDAP users can actually log in.
	// =========================================================================
	if encryptor != nil {
		ldapConfigs, ldapErr := ldapConfigRepo.ListEnabled(ctx)
		if ldapErr != nil {
			app.Logger.Warn("Failed to load enabled LDAP configs", "error", ldapErr)
		} else {
			for _, cfg := range ldapConfigs {
				client := ldapauthsvc.ProviderFromModel(cfg, encryptor, app.Logger)
				authService.RegisterLDAPProvider(authsvc.NewLDAPClientAdapter(client))
				app.Logger.Info("LDAP auth provider registered",
					"name", cfg.Name,
					"host", cfg.Host,
				)
			}
			if len(ldapConfigs) > 0 {
				app.Logger.Info("LDAP authentication enabled",
					"providers", len(ldapConfigs),
				)
			}
		}
	}

	// =========================================================================
	// WIRE OAUTH PROVIDERS INTO AUTH SERVICE
	// Load enabled OAuth configs from DB, build providers, and register
	// them with the auth service for OAuth/OIDC login flows.
	// =========================================================================
	{
		oauthConfigs, oauthErr := oauthConfigRepo.ListEnabled(ctx)
		if oauthErr != nil {
			app.Logger.Warn("Failed to load enabled OAuth configs", "error", oauthErr)
		} else {
			for _, cfg := range oauthConfigs {
				oauthCfg := oauthauthsvc.Config{
					Name:          cfg.Name,
					Type:          oauthauthsvc.ProviderType(cfg.Provider),
					ClientID:      cfg.ClientID,
					ClientSecret:  cfg.ClientSecret,
					AuthURL:       cfg.AuthURL,
					TokenURL:      cfg.TokenURL,
					UserInfoURL:   cfg.UserInfoURL,
					Scopes:        cfg.Scopes,
					RedirectURL:   cfg.RedirectURL,
					UserIDClaim:   cfg.UserIDClaim,
					UsernameClaim: cfg.UsernameClaim,
					EmailClaim:    cfg.EmailClaim,
					GroupsClaim:   cfg.GroupsClaim,
					AdminGroup:    cfg.AdminGroup,
					OperatorGroup: cfg.OperatorGroup,
					DefaultRole:   cfg.DefaultRole,
					AutoProvision: cfg.AutoProvision,
					Enabled:       cfg.IsEnabled,
				}

				var rawProvider authsvc.OAuthProvider
				var provErr error

				switch oauthauthsvc.ProviderType(cfg.Provider) {
				case oauthauthsvc.ProviderTypeOIDC, oauthauthsvc.ProviderTypeGoogle, oauthauthsvc.ProviderTypeMicrosoft:
					p, err := oauthauthsvc.NewOIDCProvider(ctx, oauthCfg, app.Logger)
					if err == nil {
						rawProvider = authsvc.NewOAuthProviderAdapter(p)
					}
					provErr = err
				default:
					p, err := oauthauthsvc.NewGenericProvider(oauthCfg, app.Logger)
					if err == nil {
						rawProvider = authsvc.NewOAuthProviderAdapter(p)
					}
					provErr = err
				}

				if provErr != nil {
					app.Logger.Warn("Failed to create OAuth provider",
						"name", cfg.Name,
						"provider", cfg.Provider,
						"error", provErr,
					)
					continue
				}

				authService.RegisterOAuthProvider(cfg.Name, rawProvider)
				app.Logger.Info("OAuth auth provider registered",
					"name", cfg.Name,
					"provider", cfg.Provider,
				)
			}
			if len(oauthConfigs) > 0 {
				app.Logger.Info("OAuth authentication enabled",
					"providers", len(oauthConfigs),
				)
			}
		}
	}

	snippetRepo := postgres.NewSnippetRepository(app.DB)
	hdlDeps.SnippetRepo = snippetRepo
	app.Logger.Info("Snippet repository enabled for web handler")

	// Custom log upload repository
	customLogUploadRepo := postgres.NewCustomLogUploadRepository(app.DB, app.Logger)
	hdlDeps.CustomLogUploadRepo = customLogUploadRepo
	app.Logger.Info("Custom log upload repository enabled for web handler")

	// Preferences repository
	prefsRepo := postgres.NewPreferencesRepo(app.DB.Pool())
	hdlDeps.PrefsRepo = prefsRepo
	app.Logger.Info("Preferences repository enabled for web handler")

	// H1: User repository adapter for profile update/password change
	hdlDeps.UserRepo = &webUserRepoAdapter{repo: userRepo}
	app.Logger.Info("User repository adapter enabled for web handler")

	// H2: Session repository adapter for profile active sessions list
	if redisSessionStore != nil {
		hdlDeps.SessionRepo = &webSessionRepoAdapter{redisStore: redisSessionStore}
		app.Logger.Info("Session repository adapter enabled for web handler")
	}

	// H3: Terminal session repository for terminal history API
	terminalSessionRepo := postgres.NewTerminalSessionRepository(app.DB, app.Logger)
	hdlDeps.TerminalSessionRepo = &webTerminalSessionRepoAdapter{repo: terminalSessionRepo}
	app.Logger.Info("Terminal session repository enabled for web handler")

	// Session recording service (Phase 7.2)
	sessionRecordingRepo := postgres.NewSessionRecordingRepository(app.DB, app.Logger)
	recordingSvc := recordingsvc.NewService("/tmp/usulnet/recordings", sessionRecordingRepo, app.Logger)
	hdlDeps.RecordingSvc = recordingSvc
	app.Logger.Info("Session recording service enabled")

	// Registry, Webhook, Runbook, AutoDeploy repositories
	registryRepo := postgres.NewRegistryRepository(app.DB)
	hdlDeps.RegistryRepo = registryRepo
	var webRegistryEncryptor registrysvc.Encryptor
	if encryptor != nil {
		webRegistryEncryptor = &encryptorAdapter{enc: encryptor}
	}
	hdlDeps.RegistryBrowseSvc = registrysvc.NewService(registryRepo, webRegistryEncryptor, app.Logger)
	app.Logger.Info("Registry repository and browsing service enabled for web handler")

	webhookRepo := postgres.NewOutgoingWebhookRepository(app.DB)
	hdlDeps.WebhookRepo = webhookRepo
	app.Logger.Info("Outgoing webhook repository enabled for web handler")

	runbookRepo := postgres.NewRunbookRepository(app.DB)
	hdlDeps.RunbookRepo = runbookRepo
	app.Logger.Info("Runbook repository enabled for web handler")

	autoDeployRepo := postgres.NewAutoDeployRuleRepository(app.DB)
	hdlDeps.AutoDeployRepo = autoDeployRepo
	app.Logger.Info("Auto-deploy rule repository enabled for web handler")

	// Tracked vulnerability repo is needed both by the late-bound SLA
	// breach worker and the web handler dependencies below, so wire it
	// up before the worker registration block.
	trackedVulnRepoEarly := postgres.NewTrackedVulnerabilityRepository(app.DB)

	// Late-bind workers that depend on repos created after scheduler startup
	if sched != nil {
		// Register webhook dispatch, runbook execute, and auto-deploy workers
		sched.Registry().Register(workers.NewWebhookDispatchWorker(webhookRepo, app.Logger))
		sched.Registry().Register(workers.NewRunbookExecuteWorker(runbookRepo, nil, hdlDeps.NotificationSvc, app.Logger))
		sched.Registry().Register(workers.NewAutoDeployWorker(autoDeployRepo, nil, app.Logger))
		sched.Registry().Register(workers.NewSLABreachWorker(trackedVulnRepoEarly, nil, app.Logger))
		app.Logger.Info("Late-bound workers registered (webhook_dispatch, runbook_execute, auto_deploy, sla_breach)")

		// Wire job enqueuer to webhook dispatcher for async delivery
		webhookDispatcher := postgres.NewWebhookDispatcher(webhookRepo)
		webhookDispatcher.SetJobEnqueuer(sched)
		app.Logger.Info("Webhook dispatcher wired with job enqueuer")
	}

	// Wire auto-deploy deps to Gitea service (if available)
	if regDeps.GiteaService != nil && sched != nil {
		regDeps.GiteaService.SetAutoDeployDeps(autoDeployRepo, sched)
		app.Logger.Info("Auto-deploy deps wired to Gitea service")
	}

	// Persistent feature repositories (compliance, secrets, lifecycle, maintenance, gitops, quotas, templates, vulns)
	complianceRepo := postgres.NewComplianceRepository(app.DB)
	hdlDeps.ComplianceRepo = complianceRepo
	app.Logger.Info("Compliance repository enabled for web handler")

	managedSecretRepo := postgres.NewManagedSecretRepository(app.DB)
	hdlDeps.ManagedSecretRepo = managedSecretRepo
	app.Logger.Info("Managed secret repository enabled for web handler")

	lifecycleRepo := postgres.NewLifecycleRepository(app.DB)
	hdlDeps.LifecycleRepo = lifecycleRepo
	app.Logger.Info("Lifecycle repository enabled for web handler")

	maintenanceRepo := postgres.NewMaintenanceRepository(app.DB)
	hdlDeps.MaintenanceRepo = maintenanceRepo
	app.Logger.Info("Maintenance repository enabled for web handler")

	gitOpsRepo := postgres.NewGitOpsRepository(app.DB)
	hdlDeps.GitOpsRepo = gitOpsRepo
	app.Logger.Info("GitOps repository enabled for web handler")

	resourceQuotaRepo := postgres.NewResourceQuotaRepository(app.DB)
	hdlDeps.ResourceQuotaRepo = resourceQuotaRepo
	app.Logger.Info("Resource quota repository enabled for web handler")

	containerTemplateRepo := postgres.NewContainerTemplateRepository(app.DB)
	hdlDeps.ContainerTemplateRepo = containerTemplateRepo
	app.Logger.Info("Container template repository enabled for web handler")

	hdlDeps.TrackedVulnRepo = trackedVulnRepoEarly
	app.Logger.Info("Tracked vulnerability repository enabled for web handler")

	// Change Management Audit Trail (Phase 3 Enterprise)
	changeEventRepo := postgres.NewChangeEventRepository(app.DB, app.Logger)
	changesSvc := changessvc.NewService(changeEventRepo, app.Logger)
	hdlDeps.ChangesSvc = changesSvc
	app.Logger.Info("Change management audit trail enabled")

	// Drift Detection (Phase 4 Enterprise)
	driftRepo := postgres.NewDriftRepository(app.DB, app.Logger)
	driftSvc := driftsvc.NewService(driftRepo, app.Logger)
	hdlDeps.DriftSvc = driftSvc
	app.Logger.Info("Drift detection enabled")

	// Cost/Resource Optimization (Phase 5 Enterprise)
	resourceOptRepo := postgres.NewResourceOptRepository(app.DB, app.Logger)
	costOptSvc := costoptsvc.NewService(resourceOptRepo, app.Logger)
	hdlDeps.CostOptSvc = costOptSvc
	app.Logger.Info("Cost/resource optimization enabled")

	// H4: Docker client for events page
	if dockerClient != nil {
		regDeps.DockerClient = dockerClient
		app.Logger.Info("Docker events enabled for events page")
	}

	// Metrics service
	metricsRepo := postgres.NewMetricsRepository(app.DB, app.Logger)
	metricsCollector := metricssvc.NewCollector(hostService, app.Logger)
	metricsService := metricssvc.NewService(metricsRepo, metricsCollector, app.Logger)
	regDeps.MetricsService = metricsService
	schedulerDeps.MetricsService = metricsService
	app.Logger.Info("Metrics service enabled")

	// Alert monitoring service — wire MetricsProvider and NotificationSender adapters
	alertRepo := postgres.NewAlertRepository(app.DB)
	var alertMetrics monitoringsvc.MetricsProvider
	if metricsService != nil {
		alertMetrics = &alertMetricsProviderAdapter{
			metrics: metricsService,
			hostID:  defaultHostID,
		}
	}
	var alertNotifier monitoringsvc.NotificationSender
	if notificationService != nil {
		alertNotifier = &alertNotificationSenderAdapter{svc: notificationService}
	}
	alertSvc := monitoringsvc.NewAlertService(
		alertRepo,
		alertMetrics,
		alertNotifier,
		monitoringsvc.DefaultAlertConfig(),
		app.Logger,
	)
	regDeps.AlertService = alertSvc
	if err := alertSvc.Start(ctx); err != nil {
		app.Logger.Error("Failed to start alert service", "error", err)
	} else {
		app.Logger.Info("Alert monitoring service started",
			"metrics_provider", alertMetrics != nil,
			"notification_sender", alertNotifier != nil,
		)
	}

	// =========================================================================
	// Enterprise Phase 2: Compliance, OPA, Log Aggregation, Image Signing, Runtime Security
	// =========================================================================

	// Log aggregation service
	logRepo := postgres.NewLogRepository(app.DB, app.Logger)
	logAggService := logaggsvc.NewService(logRepo, hostService, logaggsvc.DefaultConfig(), app.Logger)
	hdlDeps.LogAggSvc = logAggService
	app.Logger.Info("Log aggregation service enabled")

	// Compliance framework service
	complianceFrameworkRepo := postgres.NewComplianceFrameworkRepository(app.DB)
	complianceService := compliancesvc.NewService(complianceFrameworkRepo, app.Logger)
	hdlDeps.ComplianceFrameworkSvc = complianceService
	app.Logger.Info("Compliance framework service enabled")

	// OPA policy engine service
	opaRepo := postgres.NewOPARepository(app.DB)
	opaService := opasvc.NewService(opaRepo, opasvc.DefaultConfig(), app.Logger)
	hdlDeps.OPASvc = opaService
	app.Logger.Info("OPA policy engine service enabled")

	// Image signing service
	imageSignRepo := postgres.NewImageSigningRepository(app.DB)
	imageSignService := imagesignsvc.NewService(imageSignRepo, imagesignsvc.DefaultConfig(), app.Logger)
	hdlDeps.ImageSignSvc = imageSignService
	app.Logger.Info("Image signing service enabled")

	// Runtime security service
	runtimeSecRepo := postgres.NewRuntimeSecurityRepository(app.DB, app.Logger)
	runtimeSecService := runtimesvc.NewService(runtimeSecRepo, hostService, runtimesvc.DefaultConfig(), app.Logger)
	hdlDeps.RuntimeSecSvc = runtimeSecService
	app.Logger.Info("Runtime security service enabled")

	// =========================================================================
	// Phase 3: Market Expansion - GitOps
	// =========================================================================

	// Bidirectional Git sync service
	gitSyncRepo := postgres.NewGitSyncRepository(app.DB, app.Logger)
	gitSyncService := gitsyncsvc.NewService(gitSyncRepo, gitsyncsvc.DefaultConfig(), app.Logger)
	hdlDeps.GitSyncSvc = gitSyncService
	app.Logger.Info("Git sync service enabled")

	// Ephemeral environments service
	ephemeralRepo := postgres.NewEphemeralEnvironmentRepository(app.DB, app.Logger)
	ephemeralCfg := ephemeralsvc.DefaultConfig()
	if app.Config.Server.BaseURL != "" {
		ephemeralCfg.BaseURL = app.Config.Server.BaseURL
	}
	ephemeralService := ephemeralsvc.NewService(ephemeralRepo, ephemeralCfg, app.Logger)
	hdlDeps.EphemeralSvc = ephemeralService
	app.Logger.Info("Ephemeral environments service enabled")

	// Manifest builder service
	manifestRepo := postgres.NewManifestBuilderRepository(app.DB, app.Logger)
	manifestService := manifestsvc.NewService(manifestRepo, manifestsvc.DefaultConfig(), app.Logger)
	hdlDeps.ManifestSvc = manifestService
	app.Logger.Info("Manifest builder service enabled")

	// =========================================================================
	// Phase 4: Custom Dashboards
	// =========================================================================

	dashboardRepo := postgres.NewDashboardRepository(app.DB)
	dashboardService := dashboardsvc.NewService(dashboardRepo, app.Logger)
	hdlDeps.DashboardSvc = dashboardService
	app.Logger.Info("Dashboard layout service enabled")

	// Set scheduler service in registry deps
	if sched != nil {
		regDeps.SchedulerService = sched
	}

	// =========================================================================
	// Recon / privacy module (v26.5.0) — gated by cfg.Recon.Enabled
	// =========================================================================
	//
	// When Enabled=false (default), buildReconModule short-circuits and
	// returns (nil, nil). No new services, containers, or networks are
	// constructed; the system functions identically to pre-v26.5.0.
	//
	// When Enabled=true, the recon engines, metadata service, and ownership
	// verifiers are constructed eagerly; the SpiderFoot container itself is
	// lazy-started on first scan via the sandbox launcher.
	reconBaseURL := app.Config.Recon.BaseURL
	if reconBaseURL == "" {
		reconBaseURL = app.Config.Server.BaseURL
	}
	reconModule, err := reconwiring.Build(ctx, reconwiring.Config{
		Enabled:            app.Config.Recon.Enabled,
		RetentionDays:      app.Config.Recon.RetentionDays,
		MaxConcurrentScans: app.Config.Recon.MaxConcurrentScans,
		InstallationOrg:    app.Config.Recon.InstallationOrg,
		BaseURL:            reconBaseURL,
		EgressAllowlist:    app.Config.Recon.Egress.Allowlist,
	}, reconwiring.Deps{
		DB:           app.DB,
		DockerClient: dockerClient,
		Encryptor:    encryptor,
		StoragePath:  app.Config.Storage.Path,
		Logger:       app.Logger,
	})
	if err != nil {
		app.Logger.Warn("recon module: build failed", "error", err)
	}
	if reconModule != nil && sched != nil {
		if reconModule.MetadataService != nil {
			sched.Registry().Register(workers.NewMetadataJobWorker(reconModule.MetadataService, nil, app.Logger))
			app.Logger.Info("Recon metadata job worker registered")
		}
		if reconModule.ReconScanService != nil {
			sched.Registry().Register(workers.NewReconScanWorker(reconModule.ReconScanService, nil, app.Logger))
			app.Logger.Info("Recon scan worker registered")
		} else {
			app.Logger.Info("Recon module enabled; scan worker not wired (no DB / encryptor)")
		}
		if reconModule.Service != nil && apiHandlers.Recon != nil {
			apiHandlers.Recon.SetService(reconModule.Service)
			app.Logger.Info("Recon API handler wired to recon.Service")
		}

		// Retention worker — prunes findings/scans/audit/metadata-
		// artifacts on a daily cadence. Lives behind the recon feature
		// flag because the underlying DELETEs only touch recon_*
		// tables, but registering it is idempotent.
		if app.DB != nil {
			retentionRepo := postgres.NewReconRetentionRepository(
				app.DB,
				app.Config.Storage.Path+"/recon/artifacts",
				app.Logger,
			)
			sched.Registry().Register(workers.NewReconRetentionWorker(
				retentionRepo,
				workers.ReconRetentionConfig{
					RetentionDays:   app.Config.Recon.RetentionDays,
					GracePeriodDays: workers.DefaultGracePeriodDays,
				},
				app.Logger,
			))
			app.Logger.Info("Recon retention worker registered",
				"retention_days", app.Config.Recon.RetentionDays,
			)
			app.ensureReconRetentionScheduledJob(ctx, sched)
		}
	}

	// Expose the recon/metadata feature flag and acknowledgement recorder
	// to the web layer. The concrete recon.Service / metadata.Service
	// implementations are still TBD (see the wiring package): when they
	// land, populate regDeps.ReconService / regDeps.MetadataService here
	// to power the /recon/* pages with real data.
	regDeps.ReconEnabled = app.Config.Recon.Enabled
	if app.reconAckStore != nil {
		regDeps.ReconAck = app.reconAckStore
	}

	// -------------------------------------------------------------------------
	// Construct ServiceRegistry + Handler (all deps collected above)
	// -------------------------------------------------------------------------
	serviceRegistry := web.NewServiceRegistry(regDeps)
	hdlDeps.Services = serviceRegistry
	webHandler := web.NewTemplHandler(hdlDeps)

	// Create middleware
	webMiddleware := web.NewMiddleware(
		sessionStore,
		serviceRegistry.Auth(),
		serviceRegistry.Stats(),
		web.MiddlewareConfig{
			SessionName: web.CookieSession,
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
	webMiddleware.SetRoleProvider(&roleProviderAdapter{repo: roleRepo})
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
	gw, err := gateway.NewServer(app.NATS, hostRepo, app.containerService, gatewayCfg, app.Logger)
	if err != nil {
		return fmt.Errorf("failed to create gateway server: %w", err)
	}

	// Wire agent event persistence
	agentEventRepo := postgres.NewAgentEventRepository(app.DB)
	gw.SetEventStore(agentEventRepo)
	app.Logger.Info("Agent event persistence enabled")

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
		DockerHost:  "unix://" + dockerpkg.LocalSocketPath(),
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

	// Stop active packet captures
	if app.captureService != nil {
		app.captureService.Cleanup()
		app.Logger.Info("Packet capture service stopped")
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

// ensureReconRetentionScheduledJob creates the recon-specific
// retention job if it doesn't already exist. Daily at 03:30 UTC —
// offset from the database-wide retention job at 03:00 so the two
// runs do not contend for I/O.
func (app *Application) ensureReconRetentionScheduledJob(ctx context.Context, sched *scheduler.Scheduler) {
	existing, err := sched.ListScheduledJobs(ctx, false)
	if err != nil {
		app.Logger.Warn("Failed to list scheduled jobs for recon retention check", "error", err)
		return
	}
	for _, job := range existing {
		if job.Type == models.JobTypeReconRetention {
			app.Logger.Debug("Recon retention scheduled job already exists",
				"job_id", job.ID, "schedule", job.Schedule,
			)
			return
		}
	}
	if _, err := sched.CreateScheduledJob(ctx, models.CreateScheduledJobInput{
		Name:        "Recon Retention",
		Type:        models.JobTypeReconRetention,
		Schedule:    "30 3 * * *",
		IsEnabled:   true,
		MaxAttempts: 1,
		Priority:    models.JobPriorityLow,
	}); err != nil {
		app.Logger.Error("Failed to create recon retention scheduled job", "error", err)
		return
	}
	app.Logger.Info("Recon retention scheduled job created (daily at 03:30 UTC)")
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

// ensureDatabaseBackupScheduledJob creates the default automatic database backup
// job if it doesn't already exist. Runs daily at 02:00 UTC with gzip compression,
// encryption enabled, and 7-day retention.
func (app *Application) ensureDatabaseBackupScheduledJob(ctx context.Context, sched *scheduler.Scheduler, hostID uuid.UUID) {
	existing, err := sched.ListScheduledJobs(ctx, false)
	if err != nil {
		app.Logger.Warn("Failed to list scheduled jobs for backup check", "error", err)
		return
	}

	// Check if a database backup job already exists
	for _, job := range existing {
		if job.Type == models.JobTypeBackupCreate && job.Name == "Automatic Database Backup" {
			app.Logger.Debug("Database backup scheduled job already exists", "job_id", job.ID, "schedule", job.Schedule)
			return
		}
	}

	// Create default database backup job: daily at 02:00 UTC
	targetID := "postgresql"
	targetName := "PostgreSQL Database"
	retentionDays := 7
	_, err = sched.CreateScheduledJob(ctx, models.CreateScheduledJobInput{
		Name:        "Automatic Database Backup",
		Type:        models.JobTypeBackupCreate,
		Schedule:    "0 2 * * *",
		HostID:      &hostID,
		TargetID:    &targetID,
		TargetName:  &targetName,
		IsEnabled:   true,
		MaxAttempts: 3,
		Priority:    models.JobPriorityNormal,
		Payload: models.BackupPayload{
			Type:          string(models.BackupTypeSystem),
			TargetID:      targetID,
			Compression:   "gzip",
			Encrypted:     true,
			RetentionDays: retentionDays,
		},
	})
	if err != nil {
		app.Logger.Error("Failed to create database backup scheduled job", "error", err)
		return
	}

	app.Logger.Info("Automatic database backup scheduled job created (daily at 02:00 UTC, 7-day retention)")
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
		hostID, "local", "Local Docker", "local", "unix://"+dockerpkg.LocalSocketPath(),
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

	app.Logger.Warn("Default admin user created — CHANGE PASSWORD IMMEDIATELY after first login",
		"username", "admin",
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
	if err := userRepo.Update(ctx, admin); err != nil {
		return fmt.Errorf("failed to update admin password: %w", err)
	}

	// Actually unlock the account (Update doesn't touch failed_login_attempts/locked_until)
	if err := userRepo.Unlock(ctx, admin.ID); err != nil {
		return fmt.Errorf("failed to unlock admin account: %w", err)
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
