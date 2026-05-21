// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"time"

	"github.com/fr4nsys/usulnet/internal/api/handlers"
	giteapkg "github.com/fr4nsys/usulnet/internal/integrations/gitea"
	"github.com/fr4nsys/usulnet/internal/integrations/npm"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/repository/redis"
	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
	authsvc "github.com/fr4nsys/usulnet/internal/services/auth"
	ldapauthsvc "github.com/fr4nsys/usulnet/internal/services/auth/ldap"
	oauthauthsvc "github.com/fr4nsys/usulnet/internal/services/auth/oauth"
	capturesvc "github.com/fr4nsys/usulnet/internal/services/capture"
	changessvc "github.com/fr4nsys/usulnet/internal/services/changes"
	compliancesvc "github.com/fr4nsys/usulnet/internal/services/compliance"
	costoptsvc "github.com/fr4nsys/usulnet/internal/services/costopt"
	dashboardsvc "github.com/fr4nsys/usulnet/internal/services/dashboard"
	databasesvc "github.com/fr4nsys/usulnet/internal/services/database"
	deploysvc "github.com/fr4nsys/usulnet/internal/services/deploy"
	driftsvc "github.com/fr4nsys/usulnet/internal/services/drift"
	ephemeralsvc "github.com/fr4nsys/usulnet/internal/services/ephemeral"
	gitsvc "github.com/fr4nsys/usulnet/internal/services/git"
	gitsyncsvc "github.com/fr4nsys/usulnet/internal/services/gitsync"
	imagesignsvc "github.com/fr4nsys/usulnet/internal/services/imagesign"
	ldapbrowsersvc "github.com/fr4nsys/usulnet/internal/services/ldapbrowser"
	logaggsvc "github.com/fr4nsys/usulnet/internal/services/logagg"
	manifestsvc "github.com/fr4nsys/usulnet/internal/services/manifest"
	metricssvc "github.com/fr4nsys/usulnet/internal/services/metrics"
	onboardingsvc "github.com/fr4nsys/usulnet/internal/services/onboarding"
	monitoringsvc "github.com/fr4nsys/usulnet/internal/services/monitoring"
	opasvc "github.com/fr4nsys/usulnet/internal/services/opa"
	proxysvc "github.com/fr4nsys/usulnet/internal/services/proxy"
	"github.com/fr4nsys/usulnet/internal/services/proxy/caddy"
	nginxbackend "github.com/fr4nsys/usulnet/internal/services/proxy/nginx"
	rdpsvc "github.com/fr4nsys/usulnet/internal/services/rdp"
	reconwiring "github.com/fr4nsys/usulnet/internal/services/recon/wiring"
	recordingsvc "github.com/fr4nsys/usulnet/internal/services/recording"
	registrysvc "github.com/fr4nsys/usulnet/internal/services/registry"
	runtimesvc "github.com/fr4nsys/usulnet/internal/services/runtime"
	shortcutssvc "github.com/fr4nsys/usulnet/internal/services/shortcuts"
	sshsvc "github.com/fr4nsys/usulnet/internal/services/ssh"
	storagesvc "github.com/fr4nsys/usulnet/internal/services/storage"
	swarmsvc "github.com/fr4nsys/usulnet/internal/services/swarm"
	"github.com/fr4nsys/usulnet/internal/web"
)

// initWeb wires the templ frontend: the ServiceRegistry, all
// web-only services and repositories, LDAP/OAuth providers, the recon
// module construction (gated by cfg.Recon.Enabled), late-bound
// scheduler workers, and the web route registration.
//
// initWeb is the largest phase by design — it is the surface that grows
// with every new module session. The bulk lives here so app.go stays
// thin and so future modules add wiring near the related service rather
// than at the top of a 2,700-line file.
//
//nolint:gocyclo,funlen // initWeb intentionally aggregates all web wiring.
func (app *Application) initWeb(ctx context.Context, ic *initContext) error {
	apiHandlers := app.Server.Handlers()

	// =========================================================================
	// ServiceRegistry deps — core services already constructed.
	// =========================================================================
	regDeps := web.ServiceRegistryDeps{
		DefaultHostID:         ic.defaultHostID,
		AuthService:           ic.authService,
		UserRepository:        ic.userRepo,
		AuditLogRepo:          ic.auditLogRepo,
		HostService:           ic.hostService,
		ContainerService:      ic.containerService,
		ImageService:          ic.imageService,
		VolumeService:         ic.volumeService,
		NetworkService:        ic.networkService,
		StackService:          ic.stackService,
		TeamService:           ic.teamService,
		SecurityService:       ic.securityService,
		UpdateService:         ic.updateService,
		BackupService:         ic.backupService,       // nil-safe
		ConfigService:         ic.configService,       // nil-safe
		FirewallService:       ic.firewallService,     // v26.5.1 — ported from v26.2.7
		CrontabService:        ic.crontabService,      // v26.5.1 — ported from v26.2.7
		BackupVerifyService:   ic.backupVerifyService, // v26.5.1 — ported from v26.2.7
		RollbackService:       ic.rollbackService,     // v26.5.1 — ported from v26.2.7
		SSLObservatoryService: ic.sslObsService,       // v26.5.1 — ported from v26.2.7
		DockerEngineService:   ic.dockerEngineService, // v26.5.1 — ported from v26.2.7
		WireGuardService:      ic.wireguardService,    // v26.5.1 — ported from v26.2.7 (mesh-aware)
		WireGuardProbe:        ic.wireguardProbe,      // v26.5.1 — local wg/wg-quick availability
		ImageBuilderService:   ic.imageBuilderService, // v26.5.1 — ported from v26.2.7
		DNSService:            ic.dnsService,          // v26.5.1 — DNS provider plugins (session-10)
		CalendarService:       ic.calendarService,     // v26.5.1 — operations calendar (session-11)
		MarketplaceService:    ic.marketplaceService,  // v26.5.1 — curated marketplace (session-12)
		EgressService:         ic.egressService,       // v26.5.2 — L7 egress forward proxy
		EgressListenAddr:      ic.egressListenAddr,    // v26.5.2 — listener addr for info panel
		YARAService:           ic.yaraService,         // v26.5.2 — one-shot YARA scanner
		YARAToolkitImage:      ic.yaraToolkitImage,    // v26.5.2 — toolkit image for the info panel
	}

	// Session store (reused later for the session repo adapter).
	var sessionStore web.SessionStore
	var webSessionStore *web.WebSessionStore
	var redisSessionStore *redis.SessionStore
	if app.Redis != nil {
		redisSessionStore = redis.NewSessionStore(app.Redis, ic.accessTTL)
		cookieCfg := web.CookieConfig{
			Secure:   app.Config.Security.CookieSecure,
			SameSite: parseSameSite(app.Config.Security.CookieSameSite),
			Domain:   app.Config.Security.CookieDomain,
		}
		webSessionStore = web.NewWebSessionStore(redisSessionStore, ic.accessTTL, cookieCfg)
		sessionStore = webSessionStore
		regDeps.SessionStore = webSessionStore
	} else {
		sessionStore = web.NewNullSessionStore()
	}

	// =========================================================================
	// Handler deps — start with core fields, populated incrementally below.
	// =========================================================================
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

	if app.DB != nil {
		hdlDeps.DB = app.DB
	}
	if app.Redis != nil {
		hdlDeps.RedisProber = app.Redis
	}
	if app.NATS != nil {
		hdlDeps.NATSProber = &natsProberAdapter{client: app.NATS}
	}
	if ic.licenseProvider != nil {
		hdlDeps.LicenseProvider = ic.licenseProvider
	}

	// TOTP and NPM use the encryptor created earlier.
	if ic.encryptor != nil {
		regDeps.Encryptor = ic.encryptor
		hdlDeps.Encryptor = &encryptorAdapter{enc: ic.encryptor}
		hdlDeps.BackupEncryptor = ic.encryptor // *crypto.AESEncryptor satisfies BackupEncryptor directly.
		hdlDeps.TOTPSigningKey = []byte(ic.jwtSecret)
		app.Logger.Info("TOTP 2FA support enabled")
	}

	// NPM integration (manual connection via Settings UI, gated by npm.enabled).
	if ic.encryptor != nil && app.Config.NPM.Enabled {
		npmConnRepo := postgres.NewNPMConnectionRepository(app.DB)
		npmMappingRepo := postgres.NewContainerProxyMappingRepository(app.DB)
		npmAuditRepo := postgres.NewNPMAuditLogRepository(app.DB)

		npmService := npm.NewService(
			npmConnRepo,
			npmMappingRepo,
			npmAuditRepo,
			ic.encryptor,
			app.Logger.Base(),
		)
		regDeps.NPMService = npmService
		app.Logger.Info("NPM integration available (connect via Settings)")
	}

	// Reverse proxy service (nginx by default, Caddy as fallback).
	if ic.encryptor != nil && (app.Config.Nginx.Enabled || app.Config.Caddy.Enabled) {
		proxyHostRepo := postgres.NewProxyHostRepository(app.DB, app.Logger)
		proxyHeaderRepo := postgres.NewProxyHeaderRepository(app.DB)
		proxyCertRepo := postgres.NewProxyCertificateRepository(app.DB, app.Logger)
		proxyDNSRepo := postgres.NewProxyDNSProviderRepository(app.DB, app.Logger)
		proxyAuditRepo := postgres.NewProxyAuditLogRepository(app.DB)

		var backend proxysvc.SyncBackend
		var proxyCfg proxysvc.Config

		if app.Config.Nginx.Enabled {
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
				DefaultHostID: ic.defaultHostID,
			}
			app.Logger.Info("Reverse proxy service: nginx backend")
		} else {
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
				DefaultHostID: ic.defaultHostID,
			}
			app.Logger.Info("Reverse proxy service: Caddy backend")
		}

		proxyService := proxysvc.NewService(
			proxyHostRepo,
			proxyHeaderRepo,
			proxyCertRepo,
			proxyDNSRepo,
			proxyAuditRepo,
			ic.encryptor,
			backend,
			proxyCfg,
			app.Logger,
		)

		// Wire the v26.5.1 extended-feature repositories (access lists,
		// dead hosts, locations, redirections, streams). The service is
		// nil-safe: passing nil for individual repositories disables
		// that feature with a 422 ErrFeatureNotSupported at the API.
		proxyService.WithExtendedRepositories(
			postgres.NewProxyAccessListRepository(app.DB, app.Logger),
			postgres.NewProxyDeadHostRepository(app.DB, app.Logger),
			postgres.NewProxyLocationRepository(app.DB, app.Logger),
			postgres.NewProxyRedirectionRepository(app.DB, app.Logger),
			postgres.NewProxyStreamRepository(app.DB, app.Logger),
		)

		regDeps.ProxyService = proxyService

		// Wire the REST API proxy handlers. initAPI runs before
		// initWeb, so the proxy service is not available at that
		// stage; we attach the handlers here.
		if app.Server != nil {
			apiH := app.Server.Handlers()
			apiH.Proxy = handlers.NewProxyHandler(proxyService, app.Logger)
			apiH.ProxyExtended = handlers.NewExtendedProxyHandler(apiH.Proxy, proxyService)
		}
	}

	// Storage service (S3, Azure, GCS, B2, SFTP, Local — requires encryption key).
	if ic.encryptor != nil {
		storageConnRepo := postgres.NewStorageConnectionRepository(app.DB, app.Logger)
		storageBucketRepo := postgres.NewStorageBucketRepository(app.DB, app.Logger)
		storageAuditRepo := postgres.NewStorageAuditLogRepository(app.DB, app.Logger)

		storageCfg := storagesvc.Config{
			DefaultHostID: ic.defaultHostID,
		}

		storageService := storagesvc.NewService(
			storageConnRepo,
			storageBucketRepo,
			storageAuditRepo,
			ic.encryptor,
			storageCfg,
			app.Logger,
		)
		regDeps.StorageService = storageService
		if ic.licenseProvider != nil {
			storageService.SetLimitProvider(ic.licenseProvider)
		}
		app.Logger.Info("Storage service available (S3, Azure, GCS, B2, SFTP, Local)")
	}

	// Gitea integration + unified Git service (multi-provider).
	if ic.encryptor != nil {
		giteaConnRepo := postgres.NewGiteaConnectionRepository(app.DB)
		giteaRepoRepo := postgres.NewGiteaRepositoryRepository(app.DB)
		giteaWebhookRepo := postgres.NewGiteaWebhookRepository(app.DB)

		giteaService := giteapkg.NewService(
			giteaConnRepo,
			giteaRepoRepo,
			giteaWebhookRepo,
			ic.encryptor,
			app.Logger,
		)
		regDeps.GiteaService = giteaService
		app.Logger.Info("Gitea integration service enabled")

		gitConnRepo := postgres.NewGitConnectionRepository(app.DB)
		gitRepoRepo := postgres.NewGitRepositoryRepository(app.DB)

		gitService := gitsvc.NewService(
			gitConnRepo,
			gitRepoRepo,
			ic.encryptor,
			app.Logger,
		)
		regDeps.GitService = gitService
		hdlDeps.GitSvcFull = gitService
		if ic.licenseProvider != nil {
			gitService.SetLimitProvider(ic.licenseProvider)
		}
		app.Logger.Info("Unified Git service enabled (Gitea, GitHub, GitLab)")
	}

	// SSH service.
	if ic.encryptor != nil {
		sshKeyRepo := postgres.NewSSHKeyRepository(app.DB, app.Logger)
		sshConnRepo := postgres.NewSSHConnectionRepository(app.DB, app.Logger)
		sshSessionRepo := postgres.NewSSHSessionRepository(app.DB, app.Logger)
		sshTunnelRepo := postgres.NewSSHTunnelRepository(app.DB, app.Logger)

		sshService := sshsvc.NewService(
			sshKeyRepo,
			sshConnRepo,
			sshSessionRepo,
			ic.encryptor,
			app.Logger,
		)
		sshService.SetTunnelRepo(sshTunnelRepo)
		regDeps.SSHService = sshService
		hdlDeps.SSHService = sshService
		apiHandlers.SSH = handlers.NewSSHHandler(sshService, app.Logger)
		app.Logger.Info("SSH service enabled with tunnel support")
	}

	// Agent deploy service (requires PKI for TLS cert generation).
	{
		deploySvc := deploysvc.NewService(app.pkiManager, app.Logger)
		hdlDeps.DeployService = deploySvc
		app.Logger.Info("Agent deploy service enabled",
			"pki_available", app.pkiManager != nil,
		)
	}

	// Shortcuts service.
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

	// Database / LDAP browser / RDP services.
	if ic.encryptor != nil {
		dbConnRepo := postgres.NewDatabaseConnectionRepository(app.DB, app.Logger)
		databaseService := databasesvc.NewService(
			dbConnRepo,
			ic.encryptor,
			app.Logger,
		)
		hdlDeps.DatabaseService = databaseService
		app.Logger.Info("Database connections service enabled")

		ldapBrowserRepo := postgres.NewLDAPBrowserRepository(app.DB, app.Logger)
		ldapBrowserService := ldapbrowsersvc.NewService(
			ldapBrowserRepo,
			ic.encryptor,
			app.Logger,
		)
		hdlDeps.LDAPBrowserService = ldapBrowserService
		app.Logger.Info("LDAP browser service enabled")

		rdpConnRepo := postgres.NewRDPConnectionRepository(app.DB, app.Logger)
		rdpService := rdpsvc.NewService(rdpConnRepo, ic.encryptor, app.Logger)
		hdlDeps.RDPService = rdpService
		app.Logger.Info("RDP connections service enabled")
	}

	// Packet capture service.
	{
		captureRepo := postgres.NewCaptureRepository(app.DB, app.Logger)
		app.captureService = capturesvc.NewService(captureRepo, app.Logger)
		hdlDeps.CaptureService = app.captureService
		app.Logger.Info("Packet capture service enabled")
	}

	// Swarm service (wraps Docker Swarm operations with business logic).
	swarmService := swarmsvc.NewService(ic.hostService, app.Logger)
	hdlDeps.SwarmService = swarmService
	app.Logger.Info("Swarm service enabled")

	// Notification config repository for web handler.
	notificationConfigRepo := postgres.NewNotificationConfigRepository(app.DB)
	hdlDeps.NotificationConfigRepo = notificationConfigRepo
	if ic.notificationService != nil {
		hdlDeps.NotificationSvc = &runbookNotificationAdapter{svc: ic.notificationService}
	}
	app.Logger.Info("Notification config repository enabled")

	// Admin-page repositories (roles, oauth, ldap).
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
	// them with the auth service so LDAP users can log in.
	// =========================================================================
	if ic.encryptor != nil {
		ldapConfigs, ldapErr := ldapConfigRepo.ListEnabled(ctx)
		if ldapErr != nil {
			app.Logger.Warn("Failed to load enabled LDAP configs", "error", ldapErr)
		} else {
			for _, cfg := range ldapConfigs {
				client := ldapauthsvc.ProviderFromModel(cfg, ic.encryptor, app.Logger)
				ic.authService.RegisterLDAPProvider(authsvc.NewLDAPClientAdapter(client))
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

				ic.authService.RegisterOAuthProvider(cfg.Name, rawProvider)
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

	customLogUploadRepo := postgres.NewCustomLogUploadRepository(app.DB, app.Logger)
	hdlDeps.CustomLogUploadRepo = customLogUploadRepo
	app.Logger.Info("Custom log upload repository enabled for web handler")

	prefsRepo := postgres.NewPreferencesRepo(app.DB.Pool())
	hdlDeps.PrefsRepo = prefsRepo
	app.Logger.Info("Preferences repository enabled for web handler")

	hdlDeps.UserRepo = &webUserRepoAdapter{repo: ic.userRepo}
	app.Logger.Info("User repository adapter enabled for web handler")

	// First-run onboarding wizard (v26.5.2 session 04b). The service
	// reads its flag once on boot; the wizard middleware caches via
	// IsCompleted() so every request after onboarding finishes pays
	// only an atomic load.
	systemStateRepo := postgres.NewSystemStateRepository(app.DB)
	onboardingSvcInst := onboardingsvc.NewService(context.Background(), systemStateRepo, app.Logger)
	hdlDeps.OnboardingSvc = onboardingSvcInst
	app.Logger.Info("Onboarding service enabled for web handler",
		"completed", onboardingSvcInst.IsCompleted())

	if redisSessionStore != nil {
		hdlDeps.SessionRepo = &webSessionRepoAdapter{redisStore: redisSessionStore}
		app.Logger.Info("Session repository adapter enabled for web handler")
	}

	terminalSessionRepo := postgres.NewTerminalSessionRepository(app.DB, app.Logger)
	hdlDeps.TerminalSessionRepo = &webTerminalSessionRepoAdapter{repo: terminalSessionRepo}
	app.Logger.Info("Terminal session repository enabled for web handler")

	// Session recording service.
	sessionRecordingRepo := postgres.NewSessionRecordingRepository(app.DB, app.Logger)
	recordingSvc := recordingsvc.NewService("/tmp/usulnet/recordings", sessionRecordingRepo, app.Logger)
	hdlDeps.RecordingSvc = recordingSvc
	app.Logger.Info("Session recording service enabled")

	// Registry, webhook, runbook, auto-deploy repositories.
	registryRepo := postgres.NewRegistryRepository(app.DB)
	hdlDeps.RegistryRepo = registryRepo
	var webRegistryEncryptor registrysvc.Encryptor
	if ic.encryptor != nil {
		webRegistryEncryptor = &encryptorAdapter{enc: ic.encryptor}
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

	// Tracked vulnerability repo is needed by both the late-bound SLA breach
	// worker and the web handler dependencies below.
	trackedVulnRepoEarly := postgres.NewTrackedVulnerabilityRepository(app.DB)

	// Late-bind workers that depend on repos created after scheduler startup.
	if ic.scheduler != nil {
		ic.scheduler.Registry().Register(workers.NewWebhookDispatchWorker(webhookRepo, app.Logger))
		ic.scheduler.Registry().Register(workers.NewRunbookExecuteWorker(runbookRepo, nil, hdlDeps.NotificationSvc, app.Logger))
		ic.scheduler.Registry().Register(workers.NewAutoDeployWorker(autoDeployRepo, nil, app.Logger))
		ic.scheduler.Registry().Register(workers.NewSLABreachWorker(trackedVulnRepoEarly, nil, app.Logger))
		app.Logger.Info("Late-bound workers registered (webhook_dispatch, runbook_execute, auto_deploy, sla_breach)")

		webhookDispatcher := postgres.NewWebhookDispatcher(webhookRepo)
		webhookDispatcher.SetJobEnqueuer(ic.scheduler)
		app.Logger.Info("Webhook dispatcher wired with job enqueuer")
	}

	if regDeps.GiteaService != nil && ic.scheduler != nil {
		regDeps.GiteaService.SetAutoDeployDeps(autoDeployRepo, ic.scheduler)
		app.Logger.Info("Auto-deploy deps wired to Gitea service")
	}

	// Persistent feature repositories (compliance, secrets, lifecycle,
	// maintenance, gitops, quotas, templates, vulns).
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

	// Change management audit trail.
	changeEventRepo := postgres.NewChangeEventRepository(app.DB, app.Logger)
	changesSvc := changessvc.NewService(changeEventRepo, app.Logger)
	hdlDeps.ChangesSvc = changesSvc
	app.Logger.Info("Change management audit trail enabled")

	// =========================================================================
	// Rollback event-driven worker (v26.5.1 — ported from v26.2.7 as AGPL
	// feature). The worker subscribes to the in-process change_events
	// stream and dispatches matching stack events to the rollback service.
	// Subscription is via the new changes.Service.Subscribe API; the
	// worker manages a single background goroutine and is stopped during
	// app shutdown.
	// =========================================================================
	if ic.rollbackService != nil {
		app.rollbackEventWorker = workers.NewRollbackEventWorker(changesSvc, ic.rollbackService, app.Logger)
		if err := app.rollbackEventWorker.Start(ctx); err != nil {
			app.Logger.Warn("Rollback event worker start failed", "error", err)
		} else {
			app.Logger.Info("Rollback event worker started")
		}
	}

	// SSL observatory cert-expiry notifier (v26.5.1). Bridges the
	// notification service into the SSL scan path so per-target
	// thresholds (30/14/7/3/1 days) surface a critical/high alert
	// when crossed. Best-effort — silent if no notification service
	// is wired.
	if ic.sslObsService != nil && ic.notificationService != nil {
		ic.sslObsService.SetNotifier(&sslExpiryNotifierAdapter{svc: ic.notificationService})
		app.Logger.Info("ssl observatory cert-expiry notifier wired")
	}

	// Drift detection.
	driftRepo := postgres.NewDriftRepository(app.DB, app.Logger)
	driftSvc := driftsvc.NewService(driftRepo, app.Logger)
	hdlDeps.DriftSvc = driftSvc
	app.Logger.Info("Drift detection enabled")

	// Cost / resource optimization.
	resourceOptRepo := postgres.NewResourceOptRepository(app.DB, app.Logger)
	costOptSvc := costoptsvc.NewService(resourceOptRepo, app.Logger)
	hdlDeps.CostOptSvc = costOptSvc
	app.Logger.Info("Cost/resource optimization enabled")

	if ic.dockerClient != nil {
		regDeps.DockerClient = ic.dockerClient
		app.Logger.Info("Docker events enabled for events page")
	}

	// Metrics service.
	metricsRepo := postgres.NewMetricsRepository(app.DB, app.Logger)
	metricsCollector := metricssvc.NewCollector(ic.hostService, app.Logger)
	metricsService := metricssvc.NewService(metricsRepo, metricsCollector, app.Logger)
	regDeps.MetricsService = metricsService
	if ic.schedulerDeps != nil {
		ic.schedulerDeps.MetricsService = metricsService
	}
	app.Logger.Info("Metrics service enabled")

	// Alert monitoring service.
	alertRepo := postgres.NewAlertRepository(app.DB)
	var alertMetrics monitoringsvc.MetricsProvider
	if metricsService != nil {
		alertMetrics = &alertMetricsProviderAdapter{
			metrics: metricsService,
			hostID:  ic.defaultHostID,
		}
	}
	var alertNotifier monitoringsvc.NotificationSender
	if ic.notificationService != nil {
		alertNotifier = &alertNotificationSenderAdapter{svc: ic.notificationService}
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
	// Enterprise Phase 2: Compliance, OPA, Log Aggregation, Image Signing,
	// Runtime Security.
	// =========================================================================
	logRepo := postgres.NewLogRepository(app.DB, app.Logger)
	logAggService := logaggsvc.NewService(logRepo, ic.hostService, logaggsvc.DefaultConfig(), app.Logger)
	hdlDeps.LogAggSvc = logAggService
	app.Logger.Info("Log aggregation service enabled")

	complianceFrameworkRepo := postgres.NewComplianceFrameworkRepository(app.DB)
	complianceService := compliancesvc.NewService(complianceFrameworkRepo, app.Logger)
	hdlDeps.ComplianceFrameworkSvc = complianceService
	app.Logger.Info("Compliance framework service enabled")

	opaRepo := postgres.NewOPARepository(app.DB)
	opaService := opasvc.NewService(opaRepo, opasvc.DefaultConfig(), app.Logger)
	hdlDeps.OPASvc = opaService
	app.Logger.Info("OPA policy engine service enabled")

	imageSignRepo := postgres.NewImageSigningRepository(app.DB)
	imageSignService := imagesignsvc.NewService(imageSignRepo, imagesignsvc.DefaultConfig(), app.Logger)
	hdlDeps.ImageSignSvc = imageSignService
	app.Logger.Info("Image signing service enabled")

	// Optional cosign hook on successful image builds (v26.5.1). The
	// service-level flag (`image_sign.enabled`) gates the hook so the
	// default install never burns the cost of a cosign call without an
	// explicit opt-in. The signing service itself is wired regardless
	// because it also powers the trust-policy admin pages.
	if ic.imageBuilderService != nil && app.Config.ImageSign.Enabled {
		imageBuilderSign := imageSignService
		ic.imageBuilderService.SetSignHook(func(ctx context.Context, imageRef string) (string, error) {
			sig, err := imageBuilderSign.SignImage(ctx, imageRef, imagesignsvc.SignOptions{})
			if err != nil {
				return "", err
			}
			if sig == nil {
				return "", nil
			}
			return sig.ID.String(), nil
		})
		app.Logger.Info("Image builder cosign hook enabled")
	}

	runtimeSecRepo := postgres.NewRuntimeSecurityRepository(app.DB, app.Logger)
	runtimeSecService := runtimesvc.NewService(runtimeSecRepo, ic.hostService, runtimesvc.DefaultConfig(), app.Logger)
	hdlDeps.RuntimeSecSvc = runtimeSecService
	app.Logger.Info("Runtime security service enabled")

	// =========================================================================
	// Phase 3: GitOps.
	// =========================================================================
	gitSyncRepo := postgres.NewGitSyncRepository(app.DB, app.Logger)
	gitSyncService := gitsyncsvc.NewService(gitSyncRepo, gitsyncsvc.DefaultConfig(), app.Logger)
	hdlDeps.GitSyncSvc = gitSyncService
	app.Logger.Info("Git sync service enabled")

	ephemeralRepo := postgres.NewEphemeralEnvironmentRepository(app.DB, app.Logger)
	ephemeralCfg := ephemeralsvc.DefaultConfig()
	if app.Config.Server.BaseURL != "" {
		ephemeralCfg.BaseURL = app.Config.Server.BaseURL
	}
	ephemeralService := ephemeralsvc.NewService(ephemeralRepo, ephemeralCfg, app.Logger)
	hdlDeps.EphemeralSvc = ephemeralService
	app.Logger.Info("Ephemeral environments service enabled")

	manifestRepo := postgres.NewManifestBuilderRepository(app.DB, app.Logger)
	manifestService := manifestsvc.NewService(manifestRepo, manifestsvc.DefaultConfig(), app.Logger)
	hdlDeps.ManifestSvc = manifestService
	app.Logger.Info("Manifest builder service enabled")

	// =========================================================================
	// Phase 4: Custom dashboards.
	// =========================================================================
	dashboardRepo := postgres.NewDashboardRepository(app.DB)
	dashboardService := dashboardsvc.NewService(dashboardRepo, app.Logger)
	hdlDeps.DashboardSvc = dashboardService
	app.Logger.Info("Dashboard layout service enabled")

	if ic.scheduler != nil {
		regDeps.SchedulerService = ic.scheduler
	}

	// =========================================================================
	// Recon / privacy module (v26.5.0) — gated by cfg.Recon.Enabled.
	//
	// When Enabled=false (default), reconwiring.Build short-circuits and
	// returns (nil, nil). No new services, containers, or networks are
	// constructed; the system functions identically to pre-v26.5.0.
	//
	// When Enabled=true, the recon engines, metadata service, and ownership
	// verifiers are constructed eagerly; the SpiderFoot container itself is
	// lazy-started on first scan via the sandbox launcher.
	// =========================================================================
	reconBaseURL := app.Config.Recon.BaseURL
	if reconBaseURL == "" {
		reconBaseURL = app.Config.Server.BaseURL
	}
	reconModule, reconErr := reconwiring.Build(ctx, reconwiring.Config{
		Enabled:            app.Config.Recon.Enabled,
		RetentionDays:      app.Config.Recon.RetentionDays,
		MaxConcurrentScans: app.Config.Recon.MaxConcurrentScans,
		InstallationOrg:    app.Config.Recon.InstallationOrg,
		BaseURL:            reconBaseURL,
		EgressAllowlist:    app.Config.Recon.Egress.Allowlist,
	}, reconwiring.Deps{
		DB:           app.DB,
		DockerClient: ic.dockerClient,
		Encryptor:    ic.encryptor,
		StoragePath:  app.Config.Storage.Path,
		Logger:       app.Logger,
	})
	if reconErr != nil {
		app.Logger.Warn("recon module: build failed", "error", reconErr)
	}
	if reconModule != nil && ic.scheduler != nil {
		if reconModule.MetadataService != nil {
			ic.scheduler.Registry().Register(workers.NewMetadataJobWorker(reconModule.MetadataService, nil, app.Logger))
			app.Logger.Info("Recon metadata job worker registered")
		}
		if reconModule.ReconScanService != nil {
			ic.scheduler.Registry().Register(workers.NewReconScanWorker(reconModule.ReconScanService, nil, app.Logger))
			app.Logger.Info("Recon scan worker registered")
		} else {
			app.Logger.Info("Recon module enabled; scan worker not wired (no DB / encryptor)")
		}
		if reconModule.Service != nil && apiHandlers.Recon != nil {
			apiHandlers.Recon.SetService(reconModule.Service)
			app.Logger.Info("Recon API handler wired to recon.Service")
		}

		// Retention worker — prunes findings/scans/audit/metadata-artifacts on
		// a daily cadence. Idempotent if scheduled twice.
		if app.DB != nil {
			retentionRepo := postgres.NewReconRetentionRepository(
				app.DB,
				app.Config.Storage.Path+"/recon/artifacts",
				app.Logger,
			)
			ic.scheduler.Registry().Register(workers.NewReconRetentionWorker(
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
			app.ensureReconRetentionScheduledJob(ctx, ic.scheduler)
		}
	}

	// Expose the recon/metadata feature flag and acknowledgement recorder to
	// the web layer. Wire the concrete recon.Service / metadata.Service
	// implementations built above so the /recon/* and /recon/metadata
	// pages render instead of 404-ing.
	regDeps.ReconEnabled = app.Config.Recon.Enabled
	if reconModule != nil {
		if reconModule.Service != nil {
			regDeps.ReconService = reconModule.Service
		}
		if reconModule.MetadataFullService != nil {
			regDeps.MetadataService = reconModule.MetadataFullService
		}
	}
	if app.reconAckStore != nil {
		regDeps.ReconAck = app.reconAckStore
	}

	// =========================================================================
	// Build ServiceRegistry + handler (all deps collected above).
	// =========================================================================
	serviceRegistry := web.NewServiceRegistry(regDeps)
	hdlDeps.Services = serviceRegistry
	webHandler := web.NewTemplHandler(hdlDeps)

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

	webMiddleware.SetScopeProvider(ic.teamService)
	webMiddleware.SetRoleProvider(&roleProviderAdapter{repo: roleRepo})
	web.RegisterFrontendRoutes(app.Server.Router(), webHandler, webMiddleware)

	app.Logger.Info("Web frontend initialized",
		"engine", "templ",
		"mode", app.Config.Mode,
	)

	return nil
}
