// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"strings"
	"time"

	licensepkg "github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/repository/redis"
	backupsvc "github.com/fr4nsys/usulnet/internal/services/backup"
	backupstorage "github.com/fr4nsys/usulnet/internal/services/backup/storage"
	backupverifysvc "github.com/fr4nsys/usulnet/internal/services/backupverify"
	calendarsvc "github.com/fr4nsys/usulnet/internal/services/calendar"
	configsvc "github.com/fr4nsys/usulnet/internal/services/config"
	crontabsvc "github.com/fr4nsys/usulnet/internal/services/crontab"
	dnssvc "github.com/fr4nsys/usulnet/internal/services/dns"
	dnsproviders "github.com/fr4nsys/usulnet/internal/services/dns/providers"
	dockerconfigsvc "github.com/fr4nsys/usulnet/internal/services/dockerconfig"
	firewallsvc "github.com/fr4nsys/usulnet/internal/services/firewall"
	imagebuildersvc "github.com/fr4nsys/usulnet/internal/services/imagebuilder"
	marketplacesvc "github.com/fr4nsys/usulnet/internal/services/marketplace"
	notificationsvc "github.com/fr4nsys/usulnet/internal/services/notification"
	rollbacksvc "github.com/fr4nsys/usulnet/internal/services/rollback"
	securitysvc "github.com/fr4nsys/usulnet/internal/services/security"
	securityanalyzer "github.com/fr4nsys/usulnet/internal/services/security/analyzer"
	trivypkg "github.com/fr4nsys/usulnet/internal/services/security/trivy"
	sslobssvc "github.com/fr4nsys/usulnet/internal/services/sslobservatory"
	teamsvc "github.com/fr4nsys/usulnet/internal/services/team"
	updatesvc "github.com/fr4nsys/usulnet/internal/services/update"
	wireguardsvc "github.com/fr4nsys/usulnet/internal/services/wireguard"
)

// initServices initializes the business-logic services: license provider,
// team, security (with analyzers + optional Trivy), encryptor, backup,
// config, update, and notification.
// Requires ic.hostService, ic.containerService, ic.imageService,
// ic.volumeService, ic.networkService, ic.stackService, ic.defaultHostID,
// ic.containerRepo, and ic.jwtSecret.
func (app *Application) initServices(ctx context.Context, ic *initContext) error {
	// =========================================================================
	// LICENSE PROVIDER (needed by team service and router)
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
		ic.hostService.SetLimitProvider(licenseProvider)
		app.Logger.Info("License provider initialized",
			"edition", licenseProvider.Edition(),
			"instance_id", licenseProvider.InstanceID(),
		)
	}
	ic.licenseProvider = licenseProvider

	// =========================================================================
	// TEAM SERVICE
	// =========================================================================
	teamRepo := postgres.NewTeamRepository(app.DB)
	permRepo := postgres.NewResourcePermissionRepository(app.DB)
	teamService := teamsvc.NewService(teamRepo, permRepo, teamsvc.Config{}, app.Logger)
	app.Logger.Info("Team service initialized")
	ic.teamService = teamService

	// =========================================================================
	// SECURITY SERVICE (12 analyzers + optional Trivy CVE scanner)
	// =========================================================================
	secScanRepo := postgres.NewSecurityScanRepository(app.DB, app.Logger)
	secIssueRepo := postgres.NewSecurityIssueRepository(app.DB, app.Logger)
	secCfg := securitysvc.DefaultServiceConfig()
	secCfg.ScannerConfig.IncludeCVE = app.Config.Trivy.Enabled
	securityService := securitysvc.NewService(secCfg, secScanRepo, secIssueRepo, app.Logger)
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
	switch {
	case app.Config.Trivy.Enabled && trivyClient.IsAvailable():
		securityService.SetTrivyClient(trivyClient)
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
	case !app.Config.Trivy.Enabled:
		app.Logger.Info("Trivy CVE scanning disabled in config (trivy.enabled=false)")
	default:
		app.Logger.Info("Trivy not available - CVE scanning disabled (install trivy to enable)")
	}
	app.Logger.Info("Security service initialized", "analyzers", 12)
	ic.securityService = securityService

	// =========================================================================
	// ENCRYPTOR (shared by Config, TOTP, NPM, recon connectors, ...)
	// =========================================================================
	var encryptor *crypto.AESEncryptor
	{
		encKey := app.Config.Security.ConfigEncryptionKey
		if encKey == "" {
			// Derive a 32-byte hex key from JWT secret via SHA-256.
			// WARNING: changing jwt_secret invalidates all encrypted data
			// (TOTP secrets, NPM credentials, config values). Set
			// USULNET_ENCRYPTION_KEY explicitly for independent rotation.
			h := crypto.SHA256String(ic.jwtSecret)
			encKey = h[:64]
			app.Logger.Warn("encryption_key not set — deriving from jwt_secret (set USULNET_ENCRYPTION_KEY for independent rotation)")
		}
		var encErr error
		encryptor, encErr = crypto.NewAESEncryptor(encKey)
		if encErr != nil {
			app.Logger.Warn("Failed to create encryptor, TOTP/NPM/ConfigService will be unavailable", "error", encErr)
		}
	}
	ic.encryptor = encryptor

	// =========================================================================
	// BACKUP SERVICE
	// =========================================================================
	var backupService *backupsvc.Service
	{
		storagePath := app.Config.Storage.Path + "/backups"
		localStorage, storageErr := backupstorage.NewLocalStorage(storagePath)
		if storageErr != nil {
			app.Logger.Warn("Failed to initialize backup storage, backup service disabled", "error", storageErr, "path", storagePath)
		} else {
			backupRepo := postgres.NewBackupRepository(app.DB)
			volumeProvider := backupsvc.NewDockerVolumeProvider(ic.hostService, ic.volumeService)
			containerProvider := backupsvc.NewDockerContainerProvider(ic.hostService, ic.containerService)

			backupCfg := backupsvc.DefaultConfig()
			backupCfg.StoragePath = storagePath
			backupCfg.StorageType = app.Config.Storage.Type
			if app.Config.Storage.Backup.RetentionDays > 0 {
				backupCfg.DefaultRetentionDays = app.Config.Storage.Backup.RetentionDays
			}
			if comp := app.Config.Storage.Backup.Compression; comp != "" {
				backupCfg.DefaultCompression = models.BackupCompression(comp)
			}
			if app.Config.Storage.Backup.CompressionLevel > 0 {
				backupCfg.CompressionLevel = app.Config.Storage.Backup.CompressionLevel
			}

			stackProvider := backupsvc.NewDockerStackProvider(ic.stackService, ic.containerService)

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
	ic.backupService = backupService

	// =========================================================================
	// CONFIG SERVICE
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
	ic.configService = configService
	ic.configSyncService = configSyncService

	// =========================================================================
	// UPDATE SERVICE (Docker Hub + GHCR registry clients)
	// =========================================================================
	updateRepo := postgres.NewUpdateRepository(app.DB.Pool())
	updateDockerAdapter := updatesvc.NewDockerClientAdapter(ic.hostService, ic.defaultHostID)
	versionCache := updatesvc.NewMemoryVersionCache()
	checker := updatesvc.NewChecker(nil, versionCache, app.Logger)
	dockerHubClient := updatesvc.NewDockerHubClient(nil, app.Logger)
	checker.RegisterClient(dockerHubClient)
	ghcrClient := updatesvc.NewGHCRClient(nil, app.Logger)
	checker.RegisterClient(ghcrClient)

	changelogCache := updatesvc.NewMemoryChangelogCache()
	changelogFetcher := updatesvc.NewChangelogFetcher(nil, changelogCache, app.Logger)

	var updateBackup updatesvc.BackupService
	if backupService != nil {
		updateBackup = &updateBackupAdapter{svc: backupService, hostID: ic.defaultHostID}
	}
	updateSecurity := &updateSecurityAdapter{svc: securityService}

	updateService := updatesvc.NewService(
		updateRepo,
		checker,
		changelogFetcher,
		updateDockerAdapter,
		updateBackup,
		updateSecurity,
		ic.containerRepo,
		nil,
		app.Logger,
	)
	app.Logger.Info("Update service initialized",
		"backup_enabled", backupService != nil,
		"security_enabled", true,
	)
	ic.updateService = updateService

	// =========================================================================
	// FIREWALL SERVICE (v26.5.1 — ported from v26.2.7 as AGPL feature)
	// =========================================================================
	{
		firewallRuleRepo := postgres.NewFirewallRuleRepository(app.DB, app.Logger)
		firewallAuditRepo := postgres.NewFirewallAuditRepository(app.DB, app.Logger)
		firewallService := firewallsvc.NewService(firewallRuleRepo, firewallAuditRepo, app.Logger)
		ic.firewallService = firewallService
		app.Logger.Info("Firewall service initialized")
	}

	// =========================================================================
	// CRONTAB SERVICE (v26.5.1 — ported from v26.2.7 as AGPL feature)
	//
	// Schedules jobs in-process via robfig/cron/v3 and records execution
	// rows in PostgreSQL. The cleanup worker prunes executions older than
	// 30 days. Start is deferred to init_runtime once the default host UUID
	// is finalized.
	// =========================================================================
	{
		crontabEntryRepo := postgres.NewCrontabEntryRepository(app.DB, app.Logger)
		crontabExecRepo := postgres.NewCrontabExecutionRepository(app.DB, app.Logger)
		crontabService := crontabsvc.NewService(crontabEntryRepo, crontabExecRepo, app.Logger)
		if err := crontabService.Start(ctx, ic.defaultHostID); err != nil {
			app.Logger.Warn("Crontab service start failed", "error", err)
		} else {
			ic.crontabService = crontabService
			app.crontabService = crontabService
			app.Logger.Info("Crontab service initialized", "host_id", ic.defaultHostID)
		}
	}

	// =========================================================================
	// BACKUP VERIFICATION SERVICE (v26.5.1 — ported from v26.2.7 as AGPL feature)
	//
	// Bridges the existing backup service via a narrow BackupGetter
	// interface so verification jobs can reuse the same checksum +
	// extract pipeline as manual /backups verify clicks. Schedules are
	// persisted; the scheduler worker (init_scheduler.go) drains them.
	// =========================================================================
	if backupService != nil {
		bvRepo := postgres.NewBackupVerificationRepository(app.DB, app.Logger)
		bvSchedRepo := postgres.NewBackupVerificationScheduleRepository(app.DB, app.Logger)
		bvBridge := &backupVerifyBackupBridge{svc: backupService}
		bvService := backupverifysvc.NewService(bvRepo, bvSchedRepo, bvBridge, app.Logger)
		ic.backupVerifyService = bvService
		app.backupVerifyService = bvService
		app.Logger.Info("Backup verification service initialized")
	} else {
		app.Logger.Info("Backup verification service skipped (backup service not configured)")
	}

	// =========================================================================
	// ROLLBACK SERVICE (v26.5.1 — ported from v26.2.7 as AGPL feature)
	//
	// Reacts to change_events that indicate a failed deploy and reverts
	// the affected stack to its last known-good version via the existing
	// stack-revert API. The append-only audit table is enforced by the
	// rollback_audit_log_append_only_trigger Postgres trigger (migration
	// 054). The event-driven scheduler worker is wired later, after the
	// changes service is constructed in init_web.
	// =========================================================================
	{
		policyRepo := postgres.NewRollbackPolicyRepository(app.DB, app.Logger)
		execRepo := postgres.NewRollbackExecutionRepository(app.DB, app.Logger)
		auditRepo := postgres.NewRollbackAuditRepository(app.DB, app.Logger)
		rollbackService := rollbacksvc.NewService(policyRepo, execRepo, auditRepo, ic.stackService, app.Logger)
		ic.rollbackService = rollbackService
		app.Logger.Info("Rollback service initialized")
	}

	// =========================================================================
	// SSL OBSERVATORY SERVICE (v26.5.1 — ported from v26.2.7 as AGPL feature)
	//
	// Periodically dials TLS endpoints, extracts and grades the cert
	// chain, and persists scan results. Notifier wiring happens in
	// init_web once the notification adapter is built. The scheduler
	// worker (registered later) drains the 24h scan cadence.
	// =========================================================================
	{
		sslTargetRepo := postgres.NewSSLTargetRepository(app.DB, app.Logger)
		sslScanRepo := postgres.NewSSLScanResultRepository(app.DB, app.Logger)
		sslObsService := sslobssvc.NewService(sslTargetRepo, sslScanRepo, app.Logger)
		ic.sslObsService = sslObsService
		app.Logger.Info("SSL observatory service initialized")
	}

	// =========================================================================
	// WIREGUARD VPN SERVICE (v26.5.1 — ported from v26.2.7 as AGPL feature,
	// extended with master→agent mesh propagation over the existing NATS
	// transport).
	//
	// Private keys and preshared keys are stored AES-256-GCM-encrypted at
	// rest using the installation data encryption key (USULNET_ENCRYPTION_KEY,
	// shared with the recon module). When the encryptor is unavailable
	// the service is intentionally NOT constructed so we never persist
	// cleartext keys.
	//
	// The local host's `wg`/`wg-quick` binaries are probed once at
	// startup; a non-fatal log line surfaces the result. The probe
	// result also feeds the list page so operators see a banner when
	// the host is missing the tooling.
	// =========================================================================
	{
		ic.wireguardProbe = wireguardsvc.ProbeLocal(ctx)
		if ic.wireguardProbe.HasFullTooling() {
			app.Logger.Info("WireGuard tooling detected",
				"wg_version", ic.wireguardProbe.WGVersion)
		} else {
			app.Logger.Warn("WireGuard tooling missing — peers can be defined but interfaces cannot be brought up locally",
				"wg_available", ic.wireguardProbe.WGAvailable,
				"wg_quick_available", ic.wireguardProbe.WGQuickAvailable)
		}

		if encryptor == nil {
			app.Logger.Warn("WireGuard service skipped (encryptor not available — set USULNET_ENCRYPTION_KEY)")
		} else {
			wgIfaceRepo := postgres.NewWireGuardInterfaceRepository(app.DB, app.Logger)
			wgPeerRepo := postgres.NewWireGuardPeerRepository(app.DB, app.Logger)
			wgMeshRepo := postgres.NewWireGuardMeshLinkRepository(app.DB, app.Logger)
			wgService := wireguardsvc.NewService(
				wgIfaceRepo, wgPeerRepo, wgMeshRepo,
				encryptor, app.Logger,
			)
			ic.wireguardService = wgService
			app.wireguardService = wgService
			app.Logger.Info("WireGuard service initialized",
				"mesh_links_table", "wireguard_mesh_links")
		}
	}

	// =========================================================================
	// IMAGE BUILDER SERVICE (v26.5.1 — ported from v26.2.7 as AGPL feature)
	//
	// Tracks Dockerfile build jobs against the local Docker daemon. Build
	// logs stream live through Redis pub/sub instead of being buffered in
	// memory; the row only retains a trailing window after the build
	// completes. The build-context upload is capped at the configured
	// MaxContextBytes (default 256 MiB) so a runaway tarball cannot
	// exhaust the server's RAM.
	//
	// The optional cosign sign hook is wired in init_web once the
	// imagesign service is constructed (see init_web.go).
	// =========================================================================
	{
		buildJobRepo := postgres.NewImageBuildJobRepository(app.DB, app.Logger)
		dockerfileTplRepo := postgres.NewDockerfileTemplateRepository(app.DB, app.Logger)

		ibCfg := imagebuildersvc.DefaultConfig()
		if app.Config.ImageBuilder.MaxContextBytes > 0 {
			ibCfg.MaxContextBytes = app.Config.ImageBuilder.MaxContextBytes
		}
		if app.Config.ImageBuilder.LogTailBytes > 0 {
			ibCfg.LogTailBytes = app.Config.ImageBuilder.LogTailBytes
		}
		if p := app.Config.ImageBuilder.LogChannelPrefix; p != "" {
			ibCfg.LogChannelPrefix = p
		}

		var publisher *imagebuildersvc.RedisLogPublisher
		if app.Redis != nil {
			publisher = imagebuildersvc.NewRedisLogPublisher(redis.NewPubSub(app.Redis, "usulnet:"))
		}
		ic.imageBuilderLogPub = publisher

		var builder imagebuildersvc.DockerBuilder
		if ic.dockerClient != nil {
			builder = ic.dockerClient
		}

		ibService := imagebuildersvc.NewService(buildJobRepo, dockerfileTplRepo, builder, publisher, ibCfg, app.Logger)

		// Best-effort seed of the AGPL-compatible starter Dockerfile
		// templates. Failure is non-fatal — operators can still author
		// their own templates via the UI.
		if err := ibService.SeedBuiltinTemplates(ctx, ic.defaultHostID); err != nil {
			app.Logger.Warn("Image builder template seeding failed", "error", err)
		}

		ic.imageBuilderService = ibService
		app.Logger.Info("Image builder service initialized",
			"max_context_bytes", ibCfg.MaxContextBytes,
			"log_tail_bytes", ibCfg.LogTailBytes,
			"log_channel_prefix", ibCfg.LogChannelPrefix,
			"docker_available", builder != nil,
			"redis_pubsub", publisher != nil,
		)
	}

	// =========================================================================
	// DNS PROVIDER PLUGINS (v26.5.1 — session-10)
	//
	// Builds the explicit plugin registry (Cloudflare, Route53,
	// DigitalOcean, RFC 2136), wires the persistence layer, and resumes
	// any in-flight ACME DNS-01 orders. Skipped when the encryptor is
	// unavailable because provider credentials must be encrypted at
	// rest.
	// =========================================================================
	if encryptor == nil {
		app.Logger.Warn("DNS service skipped (encryptor not available — set USULNET_ENCRYPTION_KEY)")
	} else {
		registry := dnssvc.NewRegistry()
		if err := dnsproviders.RegisterAll(registry); err != nil {
			app.Logger.Error("Failed to register DNS provider plugins", "error", err)
		} else {
			providerRepo := postgres.NewDNSProviderRepository(app.DB, app.Logger)
			recordRepo := postgres.NewDNSRecordRepository(app.DB, app.Logger)
			orderRepo := postgres.NewDNSACMEOrderRepository(app.DB, app.Logger)
			auditRepo := postgres.NewDNSAuditLogRepository(app.DB, app.Logger)

			dnsService := dnssvc.NewService(
				providerRepo, recordRepo, orderRepo, auditRepo,
				registry, encryptor, dnssvc.DefaultConfig(), app.Logger,
			)
			ic.dnsService = dnsService
			app.Logger.Info("DNS service initialized",
				"plugins", registry.Kinds(),
			)
			// Resume any in-flight ACME orders that were mid-flight at
			// last shutdown. Best-effort — failures are logged inside
			// the service.
			dnsService.ResumeInFlightOrders(ctx)
		}
	}

	// =========================================================================
	// DOCKER ENGINE CONFIG SERVICE (v26.5.1 — ported from v26.2.7 as AGPL)
	//
	// Manages /etc/docker/daemon.json with atomic writes, snapshot history,
	// and reload-with-rollback (60s hard timeout). The container deployment
	// must volume-mount the host's /etc/docker into this location as :rw;
	// the v26.2.7 nsenter-via-docker-exec self-exec path is not ported.
	//
	// HealthChecker is wired below in this same phase, after the docker
	// client is available, so the rollback verification can call Ping.
	// =========================================================================
	{
		dockerEngineService := dockerconfigsvc.NewService(dockerconfigsvc.Config{}, app.Logger)
		if ic.dockerClient != nil {
			dockerEngineService.SetHealthChecker(ic.dockerClient)
		}
		ic.dockerEngineService = dockerEngineService
		app.Logger.Info("Docker engine config service initialized",
			"config_path", dockerEngineService.ConfigPath(),
			"reload_timeout", dockerEngineService.ReloadTimeout().String(),
		)
	}

	// =========================================================================
	// NOTIFICATION SERVICE
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
	ic.notificationService = notificationService

	// =========================================================================
	// CALENDAR SERVICE (v26.5.1 — ported from v26.2.7 as AGPL feature)
	//
	// Persists manually-entered operations events (maintenance windows,
	// deploys, notes) and aggregates read-only events from other services
	// via the EventSource interface. Sources are registered here so the
	// dependencies are explicit; the service itself only knows the
	// interface, never the concrete repositories.
	// =========================================================================
	{
		calendarRepo := postgres.NewCalendarRepository(app.DB, app.Logger)
		calendarService := calendarsvc.NewService(calendarRepo, app.Logger)

		// EventSource: backup runs + scheduled backups. The backup
		// repository is constructed here directly rather than threaded
		// through the backup service so the calendar surfaces backups
		// even on installs where the backup service is disabled (in
		// which case the table is just empty).
		backupRepo := postgres.NewBackupRepository(app.DB)
		calendarService.RegisterSource(calendarsvc.NewBackupSource(backupRepo))

		// EventSource: scheduled jobs from the in-process job scheduler.
		jobRepo := postgres.NewJobRepository(app.DB)
		calendarService.RegisterSource(calendarsvc.NewScheduledJobSource(jobRepo))

		ic.calendarService = calendarService
		app.Logger.Info("Calendar service initialized",
			"sources", calendarService.Sources())
	}

	// =========================================================================
	// MARKETPLACE SERVICE (v26.5.1 — ported from v26.2.7 as AGPL feature,
	// session-12).
	//
	// The catalog is baked into the binary via an embedded filesystem;
	// the service hydrates the embedded entries into the marketplace_apps
	// table on every boot, idempotently. There are no outbound HTTP
	// requests — the "no call-home" principle is enforced by both the
	// embedded CatalogSource implementation and a unit test that asserts
	// zero dials during HydrateCatalog.
	// =========================================================================
	{
		appsRepo := postgres.NewMarketplaceAppRepository(app.DB, app.Logger)
		installsRepo := postgres.NewMarketplaceInstallationRepository(app.DB, app.Logger)
		reviewsRepo := postgres.NewMarketplaceReviewRepository(app.DB, app.Logger)

		var stackInstaller marketplacesvc.StackInstaller
		if ic.stackService != nil {
			stackInstaller = ic.stackService
		}

		marketplaceService := marketplacesvc.NewService(
			appsRepo,
			installsRepo,
			reviewsRepo,
			stackInstaller,
			marketplacesvc.NewEmbeddedCatalog(),
			app.Logger,
		)

		// Hydrate is best-effort: if it fails (e.g. migration drift),
		// log and continue so the rest of the app boots. The next boot
		// will retry, and operators can audit via the failing log.
		if err := marketplaceService.HydrateCatalog(ctx); err != nil {
			app.Logger.Warn("Marketplace catalog hydration failed", "error", err)
		}

		ic.marketplaceService = marketplaceService
		app.Logger.Info("Marketplace service initialized")
	}

	return nil
}
