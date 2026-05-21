// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/api/handlers"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	reconconnectors "github.com/fr4nsys/usulnet/internal/services/recon/connectors"
	hibpconnector "github.com/fr4nsys/usulnet/internal/services/recon/connectors/hibp"
	shodanconnector "github.com/fr4nsys/usulnet/internal/services/recon/connectors/shodan"
	registrysvc "github.com/fr4nsys/usulnet/internal/services/registry"
	usersvc "github.com/fr4nsys/usulnet/internal/services/user"
)

// initAPI populates the API handler struct, registers infrastructure health
// checkers, wires the recon module handler shells (the recon.Service
// implementation lands in a follow-up; see internal/services/recon/wiring),
// and finally calls Server.Setup() to build the router.
func (app *Application) initAPI(ctx context.Context, ic *initContext) error {
	// User service for API handler (wire password policy from config).
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
		ic.userRepo,
		ic.apiKeyRepo,
		userServiceConfig,
		app.Logger,
	)
	if ic.licenseProvider != nil {
		userService.SetLimitProvider(ic.licenseProvider)
	}

	apiHandlers := app.Server.Handlers()
	apiHandlers.Auth = handlers.NewAuthHandler(ic.authService, app.Logger)
	apiHandlers.Container = handlers.NewContainerHandler(ic.containerService, app.Logger)
	apiHandlers.Image = handlers.NewImageHandler(ic.imageService, app.Logger)
	apiHandlers.Volume = handlers.NewVolumeHandler(ic.volumeService, app.Logger)
	apiHandlers.Network = handlers.NewNetworkHandler(ic.networkService, app.Logger)
	apiHandlers.Stack = handlers.NewStackHandler(ic.stackService, app.Logger)
	apiHandlers.Host = handlers.NewHostHandler(ic.hostService, app.Logger)
	apiHandlers.User = handlers.NewUserHandler(userService, app.Logger)
	apiHandlers.Security = handlers.NewSecurityHandler(ic.securityService, app.Logger)
	apiHandlers.Update = handlers.NewUpdateHandler(ic.updateService, app.Logger)
	apiHandlers.WebSocket = handlers.NewWebSocketHandler(ic.containerService, app.Logger)

	if ic.backupService != nil {
		apiHandlers.Backup = handlers.NewBackupHandler(ic.backupService, app.Logger)
	}
	if ic.configService != nil && ic.configSyncService != nil {
		apiHandlers.Config = handlers.NewConfigHandler(ic.configService, ic.configSyncService, app.Logger)
	}
	if ic.notificationService != nil {
		apiHandlers.Notification = handlers.NewNotificationHandler(ic.notificationService, app.Logger)
	}
	if ic.firewallService != nil {
		defaultHostID := ic.defaultHostID
		apiHandlers.Firewall = handlers.NewFirewallHandler(
			ic.firewallService,
			func(_ *http.Request) uuid.UUID { return defaultHostID },
			app.Logger,
		)
	}
	if ic.crontabService != nil {
		defaultHostID := ic.defaultHostID
		apiHandlers.Crontab = handlers.NewCrontabHandler(
			ic.crontabService,
			func(_ *http.Request) uuid.UUID { return defaultHostID },
			app.Logger,
		)
	}
	if ic.backupVerifyService != nil {
		defaultHostID := ic.defaultHostID
		apiHandlers.BackupVerify = handlers.NewBackupVerifyHandler(
			ic.backupVerifyService,
			func(_ *http.Request) uuid.UUID { return defaultHostID },
			app.Logger,
		)
	}
	if ic.rollbackService != nil {
		apiHandlers.Rollback = handlers.NewRollbackHandler(ic.rollbackService, app.Logger)
	}
	if ic.sslObsService != nil {
		defaultHostID := ic.defaultHostID
		apiHandlers.SSLObservatory = handlers.NewSSLObservatoryHandler(
			ic.sslObsService,
			func(_ *http.Request) uuid.UUID { return defaultHostID },
			app.Logger,
		)
	}
	if ic.dockerEngineService != nil {
		apiHandlers.DockerEngine = handlers.NewDockerEngineHandler(ic.dockerEngineService, app.Logger)
	}
	if ic.wireguardService != nil {
		defaultHostID := ic.defaultHostID
		apiHandlers.WireGuard = handlers.NewWireGuardHandler(
			ic.wireguardService,
			func(_ *http.Request) uuid.UUID { return defaultHostID },
			app.Logger,
		)
	}
	if ic.imageBuilderService != nil {
		defaultHostID := ic.defaultHostID
		var logStream handlers.LogStream
		if ic.imageBuilderLogPub != nil {
			if pub := ic.imageBuilderLogPub.PubSub(); pub != nil {
				logStream = pub
			}
		}
		apiHandlers.ImageBuilder = handlers.NewImageBuilderHandler(
			ic.imageBuilderService,
			logStream,
			func(_ *http.Request) uuid.UUID { return defaultHostID },
			app.Logger,
		)
	}
	if ic.dnsService != nil {
		defaultHostID := ic.defaultHostID
		apiHandlers.DNS = handlers.NewDNSHandler(
			ic.dnsService,
			func(_ *http.Request) uuid.UUID { return defaultHostID },
			app.Logger,
		)
	}
	if ic.calendarService != nil {
		defaultHostID := ic.defaultHostID
		apiHandlers.Calendar = handlers.NewCalendarHandler(
			ic.calendarService,
			func(_ *http.Request) uuid.UUID { return defaultHostID },
			app.Logger,
		)
	}
	if ic.marketplaceService != nil {
		defaultHostID := ic.defaultHostID
		apiHandlers.Marketplace = handlers.NewMarketplaceHandler(
			ic.marketplaceService,
			func(_ *http.Request) uuid.UUID { return defaultHostID },
			app.Logger,
		)
	}
	if ic.egressService != nil {
		apiHandlers.Egress = handlers.NewEgressHandler(ic.egressService, app.Logger)
	}
	if ic.yaraService != nil {
		apiHandlers.YARA = handlers.NewYARAHandler(ic.yaraService, app.Logger)
	}

	if ic.licenseProvider != nil {
		apiHandlers.User.SetLicenseProvider(ic.licenseProvider)
		apiHandlers.Host.SetLicenseProvider(ic.licenseProvider)
		if apiHandlers.Notification != nil {
			apiHandlers.Notification.SetLicenseProvider(ic.licenseProvider)
		}
		if apiHandlers.Audit != nil {
			apiHandlers.Audit.SetLicenseProvider(ic.licenseProvider)
		}
		if apiHandlers.Backup != nil {
			apiHandlers.Backup.SetLicenseProvider(ic.licenseProvider)
		}
	}
	if app.schedulerService != nil {
		apiHandlers.Job = handlers.NewJobsHandler(app.schedulerService, app.Logger)
	}

	// Settings handler (app settings + LDAP config repo).
	{
		settingsConfigRepo := postgres.NewConfigVariableRepository(app.DB, app.Logger)
		settingsLDAPRepo := postgres.NewLDAPConfigRepository(app.DB, app.Logger)
		apiHandlers.Settings = handlers.NewSettingsHandler(settingsConfigRepo, settingsLDAPRepo, nil, app.Logger)
	}

	if ic.licenseProvider != nil {
		apiHandlers.License = handlers.NewLicenseHandler(ic.licenseProvider, nil, app.Logger)
	}

	// Registry browsing service + handler.
	{
		registryBrowseRepo := postgres.NewRegistryRepository(app.DB)
		var registryEncryptor registrysvc.Encryptor
		if ic.encryptor != nil {
			registryEncryptor = &encryptorAdapter{enc: ic.encryptor}
		}
		registryBrowseSvc := registrysvc.NewService(registryBrowseRepo, registryEncryptor, app.Logger)
		apiHandlers.Registry = handlers.NewRegistryHandler(registryBrowseSvc, app.Logger)
		app.Logger.Info("Registry browsing service enabled")
	}

	apiHandlers.OpenAPI = handlers.NewOpenAPIHandler(Version)

	// Recon + metadata module handlers (v26.5.0). The recon.Service
	// implementation lands in a follow-up; until then the handler
	// constructors accept nil services and every gated route returns
	// 503 engine_unavailable. The feature-flag middleware short-circuits
	// the whole subtree with 404 when recon.enabled is false.
	{
		reconAck := handlers.NewMemoryAckStore()

		var connectorSvc handlers.ReconConnectorService
		if app.Config.Recon.Enabled {
			var credStore reconconnectors.CredentialStore
			if app.DB != nil && ic.encryptor != nil {
				credStore = postgres.NewReconConnectorsRepository(app.DB, ic.encryptor)
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
			if app.Config.Recon.Connectors.Shodan.Enabled {
				shodanKey, shodanKeyEnabled := resolveShodanKey(ctx, credStore, app.Logger)
				if err := reg.Register(shodanconnector.New(shodanconnector.Config{
					APIKey:  shodanKey,
					Enabled: shodanKeyEnabled,
				}, app.Logger)); err != nil {
					app.Logger.Warn("recon: Shodan connector registration failed", "error", err)
				} else {
					app.Logger.Info("recon: Shodan connector registered",
						"key_source", shodanKeySource(credStore, shodanKey),
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

	// Build the router with all handlers populated.
	app.Server.Setup()

	// =========================================================================
	// HEALTH CHECKER REGISTRATION
	// =========================================================================
	if app.DB != nil {
		app.Server.RegisterDatabaseHealth(func(ctx context.Context) error {
			return app.DB.Pool().Ping(ctx)
		})
		app.Logger.Info("Health checker registered: postgresql")
	}
	if app.Redis != nil {
		app.Server.RegisterRedisHealth(func(ctx context.Context) error {
			return app.Redis.HealthCheck(ctx)
		})
		app.Logger.Info("Health checker registered: redis")
	}
	if ic.dockerClient != nil {
		app.Server.RegisterDockerHealth(func(ctx context.Context) error {
			return ic.dockerClient.Ping(ctx)
		})
		app.Logger.Info("Health checker registered: docker")
	}
	if app.NATS != nil {
		app.Server.RegisterNATSHealth(func(ctx context.Context) error {
			return app.NATS.Health(ctx)
		})
		app.Logger.Info("Health checker registered: nats")
	}

	app.Logger.Info("API handlers initialized",
		"handlers_active", countActiveHandlers(apiHandlers),
	)

	return nil
}
