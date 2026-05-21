// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/api"
	dockerpkg "github.com/fr4nsys/usulnet/internal/docker"
	licensepkg "github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/scheduler"
	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
	auditsvc "github.com/fr4nsys/usulnet/internal/services/audit"
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
	hostsvc "github.com/fr4nsys/usulnet/internal/services/host"
	imagesvc "github.com/fr4nsys/usulnet/internal/services/image"
	imagebuildersvc "github.com/fr4nsys/usulnet/internal/services/imagebuilder"
	marketplacesvc "github.com/fr4nsys/usulnet/internal/services/marketplace"
	networksvc "github.com/fr4nsys/usulnet/internal/services/network"
	notificationsvc "github.com/fr4nsys/usulnet/internal/services/notification"
	rollbacksvc "github.com/fr4nsys/usulnet/internal/services/rollback"
	securitysvc "github.com/fr4nsys/usulnet/internal/services/security"
	sslobssvc "github.com/fr4nsys/usulnet/internal/services/sslobservatory"
	stacksvc "github.com/fr4nsys/usulnet/internal/services/stack"
	teamsvc "github.com/fr4nsys/usulnet/internal/services/team"
	updatesvc "github.com/fr4nsys/usulnet/internal/services/update"
	volumesvc "github.com/fr4nsys/usulnet/internal/services/volume"
	wireguardsvc "github.com/fr4nsys/usulnet/internal/services/wireguard"
	yarasvc "github.com/fr4nsys/usulnet/internal/services/yara"
)

// initContext carries shared state between the phased init_*.go
// functions. Each phase populates the fields it produces; later
// phases consume them. The struct is passed by pointer so phases
// can mutate it.
//
// The mutation of serverCfg after app.Server has been constructed is
// dead-code in v26.5.0 (the api.Server stores the config by value);
// the field is kept on the initContext to mirror the v26.2.7 phase
// ordering exactly and to leave a single, obvious place to wire a
// future Server.SetTokenValidator / SetAPIKeyAuth fix.
type initContext struct {
	// Phase 1 — initServer
	serverCfg api.ServerConfig

	// Phase 2 — initAuth
	authService  *authsvc.Service
	userRepo     *postgres.UserRepository
	sessionRepo  *postgres.SessionRepository
	apiKeyRepo   *postgres.APIKeyRepository
	auditLogRepo *postgres.AuditLogRepository
	auditService *auditsvc.Service
	jwtSecret    string
	accessTTL    time.Duration

	// Phase 3 — initDocker
	defaultHostID    uuid.UUID
	hostService      *hostsvc.Service
	containerService *containersvc.Service
	containerRepo    *postgres.ContainerRepository
	imageService     *imagesvc.Service
	volumeService    *volumesvc.Service
	networkService   *networksvc.Service
	stackService     *stacksvc.Service
	dockerClient     *dockerpkg.Client

	// Phase 4 — initServices
	licenseProvider     *licensepkg.Provider
	teamService         *teamsvc.Service
	securityService     *securitysvc.Service
	encryptor           *crypto.AESEncryptor
	backupService       *backupsvc.Service
	configService       *configsvc.Service
	configSyncService   *configsvc.SyncService
	updateService       *updatesvc.Service
	notificationService *notificationsvc.Service
	firewallService     *firewallsvc.Service
	crontabService      *crontabsvc.Service
	backupVerifyService *backupverifysvc.Service
	rollbackService     *rollbacksvc.Service
	sslObsService       *sslobssvc.Service
	dockerEngineService *dockerconfigsvc.Service
	wireguardService    *wireguardsvc.Service
	wireguardProbe      wireguardsvc.ProbeResult
	imageBuilderService *imagebuildersvc.Service
	imageBuilderLogPub  *imagebuildersvc.RedisLogPublisher
	dnsService          *dnssvc.Service
	calendarService     *calendarsvc.Service
	marketplaceService  *marketplacesvc.Service
	egressService       *egresssvc.Service
	egressProxy         *egresssvc.Proxy
	egressListenAddr    string
	yaraService         *yarasvc.Service
	yaraToolkitImage    string

	// Phase 5 — initScheduler
	scheduler     *scheduler.Scheduler
	schedulerDeps *workers.Dependencies
}
