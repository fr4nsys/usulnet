// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package web provides the web UI layer for usulnet.
package web

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	giteapkg "github.com/fr4nsys/usulnet/internal/integrations/gitea"
	"github.com/fr4nsys/usulnet/internal/integrations/npm"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/scheduler"
	authsvc "github.com/fr4nsys/usulnet/internal/services/auth"
	backupsvc "github.com/fr4nsys/usulnet/internal/services/backup"
	backupverifysvc "github.com/fr4nsys/usulnet/internal/services/backupverify"
	calendarsvc "github.com/fr4nsys/usulnet/internal/services/calendar"
	configsvc "github.com/fr4nsys/usulnet/internal/services/config"
	containersvc "github.com/fr4nsys/usulnet/internal/services/container"
	crontabsvc "github.com/fr4nsys/usulnet/internal/services/crontab"
	dnssvc "github.com/fr4nsys/usulnet/internal/services/dns"
	dockerconfigsvc "github.com/fr4nsys/usulnet/internal/services/dockerconfig"
	egresssvc "github.com/fr4nsys/usulnet/internal/services/egress"
	firewallsvc "github.com/fr4nsys/usulnet/internal/services/firewall"
	gitsvc "github.com/fr4nsys/usulnet/internal/services/git"
	hostsvc "github.com/fr4nsys/usulnet/internal/services/host"
	imagesvc "github.com/fr4nsys/usulnet/internal/services/image"
	imagebuildersvc "github.com/fr4nsys/usulnet/internal/services/imagebuilder"
	marketplacesvc "github.com/fr4nsys/usulnet/internal/services/marketplace"
	metadatasvc "github.com/fr4nsys/usulnet/internal/services/metadata"
	"github.com/fr4nsys/usulnet/internal/services/monitoring"
	networksvc "github.com/fr4nsys/usulnet/internal/services/network"
	proxysvc "github.com/fr4nsys/usulnet/internal/services/proxy"
	reconsvc "github.com/fr4nsys/usulnet/internal/services/recon"
	rollbacksvc "github.com/fr4nsys/usulnet/internal/services/rollback"
	securitysvc "github.com/fr4nsys/usulnet/internal/services/security"
	sshsvc "github.com/fr4nsys/usulnet/internal/services/ssh"
	sslobssvc "github.com/fr4nsys/usulnet/internal/services/sslobservatory"
	stacksvc "github.com/fr4nsys/usulnet/internal/services/stack"
	storagesvc "github.com/fr4nsys/usulnet/internal/services/storage"
	teamsvc "github.com/fr4nsys/usulnet/internal/services/team"
	updatesvc "github.com/fr4nsys/usulnet/internal/services/update"
	volumesvc "github.com/fr4nsys/usulnet/internal/services/volume"
	wireguardsvc "github.com/fr4nsys/usulnet/internal/services/wireguard"
	yarasvc "github.com/fr4nsys/usulnet/internal/services/yara"
)

// ErrServiceNotConfigured is returned when an operation is attempted on a service that is not configured.
var ErrServiceNotConfigured = errors.New("service not configured")

// ServiceRegistry holds all backend services and provides adapted interfaces for the web layer.
type ServiceRegistry struct {
	// Backend services
	containerSvc    *containersvc.Service
	imageSvc        *imagesvc.Service
	volumeSvc       *volumesvc.Service
	networkSvc      *networksvc.Service
	stackSvc        *stacksvc.Service
	backupSvc       *backupsvc.Service
	configSvc       *configsvc.Service
	securitySvc     *securitysvc.Service
	updateSvc       *updatesvc.Service
	hostSvc         *hostsvc.Service
	authSvc         *authsvc.Service
	npmSvc          *npm.Service
	proxySvc        *proxysvc.Service
	storageSvc      *storagesvc.Service
	teamSvc         *teamsvc.Service
	giteaSvc        *giteapkg.Service
	gitSvc          *gitsvc.Service
	sshSvc          *sshsvc.Service
	metricsSvc      MetricsServiceFull
	alertSvc        *monitoring.AlertService
	schedulerSvc    *scheduler.Scheduler
	firewallSvc     *firewallsvc.Service
	crontabSvc      *crontabsvc.Service
	backupVerifySvc *backupverifysvc.Service
	rollbackSvc     *rollbacksvc.Service
	sslObsSvc       *sslobssvc.Service
	dockerEngineSvc *dockerconfigsvc.Service
	wireguardSvc    *wireguardsvc.Service
	wgProbe         wireguardsvc.ProbeResult
	imageBuilderSvc *imagebuildersvc.Service
	dnsSvc          *dnssvc.Service
	calendarSvc     *calendarsvc.Service
	marketplaceSvc  *marketplacesvc.Service
	egressSvc        *egresssvc.Service
	egressListenAddr string
	yaraSvc          *yarasvc.Service
	yaraToolkitImage string

	// Recon / privacy module (v26.5.0). All three are optional and nil
	// when the recon feature flag is off — see docs/v26.5/technical-notes.md.
	reconSvc     reconsvc.Service
	metadataSvc  metadatasvc.Service
	reconAck     AckRecorder
	reconEnabled bool

	// User repository for user management
	userRepo *postgres.UserRepository

	// Audit log repository for recent events
	auditLogRepo *postgres.AuditLogRepository

	// Encryptor for TOTP secrets
	encryptor *crypto.AESEncryptor

	// Session store for auth validation
	sessionStore *WebSessionStore

	// Docker client for events
	dockerClient docker.ClientAPI

	// Default host ID for standalone mode
	defaultHostID uuid.UUID
}

// ServiceRegistryDeps holds all dependencies for ServiceRegistry constructor injection.
// Optional fields (nil-safe) can be left nil if the corresponding feature is disabled.
type ServiceRegistryDeps struct {
	DefaultHostID         uuid.UUID
	ContainerService      *containersvc.Service
	ImageService          *imagesvc.Service
	VolumeService         *volumesvc.Service
	NetworkService        *networksvc.Service
	StackService          *stacksvc.Service
	BackupService         *backupsvc.Service
	ConfigService         *configsvc.Service
	SecurityService       *securitysvc.Service
	UpdateService         *updatesvc.Service
	HostService           *hostsvc.Service
	AuthService           *authsvc.Service
	NPMService            *npm.Service        // Optional: requires npm.enabled
	ProxyService          *proxysvc.Service   // Optional: requires nginx.enabled or caddy.enabled
	StorageService        *storagesvc.Service // Optional: requires minio.enabled
	TeamService           *teamsvc.Service
	GiteaService          *giteapkg.Service // Optional: requires Gitea integration
	GitService            *gitsvc.Service   // Optional: requires Git integration
	SSHService            *sshsvc.Service   // Optional: requires SSH service
	MetricsService        MetricsServiceFull
	AlertService          *monitoring.AlertService
	SchedulerService      *scheduler.Scheduler     // Optional: set after scheduler init
	FirewallService       *firewallsvc.Service     // Optional: firewall rule management (v26.5.1)
	CrontabService        *crontabsvc.Service      // Optional: managed cron jobs (v26.5.1)
	BackupVerifyService   *backupverifysvc.Service // Optional: backup verification (v26.5.1)
	RollbackService       *rollbacksvc.Service     // Optional: automated rollback (v26.5.1)
	SSLObservatoryService *sslobssvc.Service       // Optional: SSL observatory (v26.5.1)
	DockerEngineService   *dockerconfigsvc.Service // Optional: docker engine config (v26.5.1)
	WireGuardService      *wireguardsvc.Service    // Optional: WireGuard mesh (v26.5.1)
	WireGuardProbe        wireguardsvc.ProbeResult // Optional: local wg/wg-quick availability
	ImageBuilderService   *imagebuildersvc.Service // Optional: image builder (v26.5.1)
	DNSService            *dnssvc.Service          // Optional: DNS provider plugins (v26.5.1)
	CalendarService       *calendarsvc.Service     // Optional: operations calendar (v26.5.1)
	MarketplaceService    *marketplacesvc.Service  // Optional: curated app marketplace (v26.5.1)
	EgressService         *egresssvc.Service       // Optional: L7 egress forward proxy (v26.5.2)
	EgressListenAddr      string                   // Optional: proxy listener address for the UI info panel
	YARAService           *yarasvc.Service         // Optional: one-shot YARA scanner (v26.5.2)
	YARAToolkitImage      string                   // Optional: toolkit image name for the UI info panel
	UserRepository        *postgres.UserRepository
	AuditLogRepo          *postgres.AuditLogRepository // Optional: for recent events feed
	Encryptor             *crypto.AESEncryptor         // Optional: requires encryption key
	SessionStore          *WebSessionStore             // Optional: requires Redis
	DockerClient          docker.ClientAPI             // Optional: set after Docker init

	// Recon module (v26.5.0). Pass the service implementations and the
	// in-memory or Postgres-backed acknowledgement recorder. Leave nil
	// when cfg.Recon.Enabled is false.
	ReconService    reconsvc.Service
	MetadataService metadatasvc.Service
	ReconAck        AckRecorder
	ReconEnabled    bool
}

// NewServiceRegistry creates a new service registry with all dependencies injected.
func NewServiceRegistry(deps ServiceRegistryDeps) *ServiceRegistry {
	return &ServiceRegistry{
		defaultHostID:   deps.DefaultHostID,
		containerSvc:    deps.ContainerService,
		imageSvc:        deps.ImageService,
		volumeSvc:       deps.VolumeService,
		networkSvc:      deps.NetworkService,
		stackSvc:        deps.StackService,
		backupSvc:       deps.BackupService,
		configSvc:       deps.ConfigService,
		securitySvc:     deps.SecurityService,
		updateSvc:       deps.UpdateService,
		hostSvc:         deps.HostService,
		authSvc:         deps.AuthService,
		npmSvc:          deps.NPMService,
		proxySvc:        deps.ProxyService,
		storageSvc:      deps.StorageService,
		teamSvc:         deps.TeamService,
		giteaSvc:        deps.GiteaService,
		gitSvc:          deps.GitService,
		sshSvc:          deps.SSHService,
		metricsSvc:      deps.MetricsService,
		alertSvc:        deps.AlertService,
		schedulerSvc:    deps.SchedulerService,
		firewallSvc:     deps.FirewallService,
		crontabSvc:      deps.CrontabService,
		backupVerifySvc: deps.BackupVerifyService,
		rollbackSvc:     deps.RollbackService,
		sslObsSvc:       deps.SSLObservatoryService,
		dockerEngineSvc: deps.DockerEngineService,
		wireguardSvc:    deps.WireGuardService,
		wgProbe:         deps.WireGuardProbe,
		imageBuilderSvc: deps.ImageBuilderService,
		dnsSvc:          deps.DNSService,
		calendarSvc:     deps.CalendarService,
		marketplaceSvc:  deps.MarketplaceService,
		egressSvc:        deps.EgressService,
		egressListenAddr: deps.EgressListenAddr,
		yaraSvc:          deps.YARAService,
		yaraToolkitImage: deps.YARAToolkitImage,
		userRepo:        deps.UserRepository,
		auditLogRepo:    deps.AuditLogRepo,
		encryptor:       deps.Encryptor,
		sessionStore:    deps.SessionStore,
		dockerClient:    deps.DockerClient,
		reconSvc:        deps.ReconService,
		metadataSvc:     deps.MetadataService,
		reconAck:        deps.ReconAck,
		reconEnabled:    deps.ReconEnabled,
	}
}

// resolveHostID extracts the active host ID from context, falling back to the default.
// This enables all service adapters to route operations to the host selected by the user.
func resolveHostID(ctx context.Context, defaultID uuid.UUID) uuid.UUID {
	activeHostID := GetActiveHostIDFromContext(ctx)
	if activeHostID != "" {
		if id, err := uuid.Parse(activeHostID); err == nil {
			return id
		}
	}
	return defaultID
}

// ============================================================================
// Services interface implementation
// ============================================================================

func (r *ServiceRegistry) Containers() ContainerService {
	return &containerAdapter{svc: r.containerSvc, hostID: r.defaultHostID}
}

func (r *ServiceRegistry) Images() ImageService {
	return &imageAdapter{svc: r.imageSvc, hostID: r.defaultHostID}
}

func (r *ServiceRegistry) Volumes() VolumeService {
	return &volumeAdapter{svc: r.volumeSvc, containerSvc: r.containerSvc, hostID: r.defaultHostID}
}

func (r *ServiceRegistry) Networks() NetworkService {
	return &networkAdapter{svc: r.networkSvc, hostID: r.defaultHostID}
}

func (r *ServiceRegistry) Stacks() StackService {
	return &stackAdapter{svc: r.stackSvc, userRepo: r.userRepo, hostID: r.defaultHostID}
}

func (r *ServiceRegistry) Backups() BackupService {
	return &backupAdapter{svc: r.backupSvc, hostID: r.defaultHostID}
}

func (r *ServiceRegistry) Config() ConfigService {
	return &configAdapter{svc: r.configSvc}
}

func (r *ServiceRegistry) Security() SecurityService {
	return &securityAdapter{svc: r.securitySvc, hostSvc: r.hostSvc, containerSvc: r.containerSvc, hostID: r.defaultHostID}
}

func (r *ServiceRegistry) Updates() UpdateService {
	return &updateAdapter{svc: r.updateSvc, hostID: r.defaultHostID}
}

func (r *ServiceRegistry) Hosts() HostService {
	return &hostAdapter{svc: r.hostSvc, hostID: r.defaultHostID}
}

func (r *ServiceRegistry) Events() EventService {
	return &eventAdapter{dockerClient: r.dockerClient, auditLogRepo: r.auditLogRepo}
}

func (r *ServiceRegistry) Proxy() ProxyService {
	// Prefer native proxy (nginx/Caddy backend) if configured
	if r.proxySvc != nil {
		return newCaddyProxyAdapter(r.proxySvc)
	}
	// Fallback to NPM adapter (external connection)
	return &proxyAdapter{npmSvc: r.npmSvc, hostID: r.defaultHostID}
}

func (r *ServiceRegistry) Storage() StorageService {
	if r.storageSvc == nil {
		return nil
	}
	return &storageAdapter{svc: r.storageSvc}
}

func (r *ServiceRegistry) Auth() AuthService {
	return &authAdapter{svc: r.authSvc, sessionStore: r.sessionStore}
}

func (r *ServiceRegistry) Users() UserService {
	return &userAdapter{repo: r.userRepo, authSvc: r.authSvc, encryptor: r.encryptor}
}

func (r *ServiceRegistry) Stats() StatsService {
	return &statsAdapter{
		containerSvc: r.containerSvc,
		imageSvc:     r.imageSvc,
		volumeSvc:    r.volumeSvc,
		networkSvc:   r.networkSvc,
		stackSvc:     r.stackSvc,
		securitySvc:  r.securitySvc,
		hostSvc:      r.hostSvc,
		hostID:       r.defaultHostID,
	}
}

func (r *ServiceRegistry) Teams() TeamService {
	return r.teamSvc
}

// Gitea returns the Gitea integration service, or nil if not configured.
func (r *ServiceRegistry) Gitea() GiteaService {
	if r.giteaSvc == nil {
		return nil
	}
	return r.giteaSvc
}

// Git returns the unified Git service, or nil if not configured.
func (r *ServiceRegistry) Git() GitService {
	if r.gitSvc == nil {
		return nil
	}
	return r.gitSvc
}

// Metrics returns the metrics service, or nil if not configured.
func (r *ServiceRegistry) Metrics() MetricsServiceFull {
	return r.metricsSvc
}

// SSH returns the SSH service, or nil if not configured.
func (r *ServiceRegistry) SSH() *sshsvc.Service {
	return r.sshSvc
}

// Alerts returns the alert monitoring service, or nil if not configured.
func (r *ServiceRegistry) Alerts() AlertsService {
	if r.alertSvc == nil {
		return nil
	}
	return r.alertSvc
}

// Scheduler returns the scheduler service, or nil if not configured.
func (r *ServiceRegistry) Scheduler() *scheduler.Scheduler {
	return r.schedulerSvc
}

// Firewall returns the firewall service, or nil if not configured.
// Web handlers must check for nil before use; the standalone-mode app
// wires this in every install (no edition gate), but installs that
// disable migration 050_firewall would observe a nil here.
func (r *ServiceRegistry) Firewall() *firewallsvc.Service {
	return r.firewallSvc
}

// Crontab returns the crontab service, or nil if not configured.
// Web handlers must check for nil before use; the standalone-mode app
// wires this in every install (no edition gate).
func (r *ServiceRegistry) Crontab() *crontabsvc.Service {
	return r.crontabSvc
}

// BackupVerify returns the backup verification service, or nil if not
// configured. Web handlers must check for nil before use; the
// standalone-mode app wires this in every install (no edition gate).
func (r *ServiceRegistry) BackupVerify() *backupverifysvc.Service {
	return r.backupVerifySvc
}

// Rollback returns the automated rollback service, or nil if not
// configured. v26.5.1 wires this in every install — no biz gate.
func (r *ServiceRegistry) Rollback() *rollbacksvc.Service {
	return r.rollbackSvc
}

// SSLObservatory returns the SSL observatory service, or nil if not
// configured. v26.5.1 wires this in every install — no biz gate.
func (r *ServiceRegistry) SSLObservatory() *sslobssvc.Service {
	return r.sslObsSvc
}

// DockerEngine returns the docker engine config service, or nil if
// not configured. The web handler renders an "unavailable" page when
// nil — typically because the operator did not mount /etc/docker into
// the container.
func (r *ServiceRegistry) DockerEngine() *dockerconfigsvc.Service {
	return r.dockerEngineSvc
}

// WireGuard returns the wireguard service, or nil if not configured
// (typically because the data encryption key is unset). v26.5.1 wires
// this in every install — no biz gate.
func (r *ServiceRegistry) WireGuard() *wireguardsvc.Service {
	return r.wireguardSvc
}

// ImageBuilder returns the image builder service, or nil if not
// configured. v26.5.1 wires this in every install — no biz gate.
func (r *ServiceRegistry) ImageBuilder() *imagebuildersvc.Service {
	return r.imageBuilderSvc
}

// Calendar returns the operations calendar service, or nil if not
// configured. v26.5.1 wires this in every install — no biz gate.
func (r *ServiceRegistry) Calendar() *calendarsvc.Service {
	return r.calendarSvc
}

// Marketplace returns the curated app marketplace service, or nil if
// not configured. v26.5.1 wires this in every install — no biz gate.
func (r *ServiceRegistry) Marketplace() *marketplacesvc.Service {
	return r.marketplaceSvc
}

// Egress returns the L7 egress filter service, or nil if not configured
// (typically because cfg.EgressProxy.Enabled is false). v26.5.2 wires
// this in every install — no biz gate.
func (r *ServiceRegistry) Egress() *egresssvc.Service {
	return r.egressSvc
}

// YARA returns the YARA scanner service, or nil if not configured
// (typically because recon is disabled and the toolkit image isn't
// available). v26.5.2 wires this in every install — no biz gate.
func (r *ServiceRegistry) YARA() *yarasvc.Service {
	return r.yaraSvc
}

// Recon returns the recon module adapter. It always returns a non-nil
// pointer so handlers can call methods without nil-checks; IsEnabled()
// reflects whether the underlying service is wired.
func (r *ServiceRegistry) Recon() ReconService {
	return &reconAdapter{
		svc:     r.reconSvc,
		ack:     r.reconAck,
		enabled: r.reconEnabled && r.reconSvc != nil,
	}
}

// Metadata returns the metadata hygiene adapter. Always non-nil for the
// same reason as Recon().
func (r *ServiceRegistry) Metadata() MetadataService {
	return &metadataAdapter{
		svc:     r.metadataSvc,
		enabled: r.reconEnabled && r.metadataSvc != nil,
	}
}
