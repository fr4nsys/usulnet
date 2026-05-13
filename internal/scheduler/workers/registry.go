// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package workers

import (
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Dependencies holds all service dependencies for workers
type Dependencies struct {
	SecurityService     SecurityService
	DockerClient        DockerClientForScan
	BackupService       BackupService
	UpdateService       UpdateService
	CleanupService      CleanupService
	JobCleanupService   JobCleanupService
	RetentionService    RetentionService
	MetricsService      MetricsService
	InventoryService    InventoryService
	NotificationService NotificationService
	WebhookRepo         WebhookDeliveryRepo
	RunbookRepo         RunbookRepo
	ContainerService    ContainerActionService
	RunbookNotifySvc    RunbookNotificationSender
	AutoDeployRepo      AutoDeployRuleRepo
	StackService        StackDeployService
	TrackedVulnRepo     TrackedVulnRepository
	Logger              *logger.Logger
}

// RegisterDefaultWorkers registers all default workers with the registry
func RegisterDefaultWorkers(registry *WorkerRegistry, deps *Dependencies) {
	log := deps.Logger
	if log == nil {
		log = logger.Nop()
	}

	// Security scan worker
	if deps.SecurityService != nil && deps.DockerClient != nil {
		registry.Register(NewSecurityScanWorker(deps.SecurityService, deps.DockerClient, log))
	}

	// Backup workers
	if deps.BackupService != nil {
		registry.Register(NewBackupWorker(deps.BackupService, log))
		registry.Register(NewBackupRestoreWorker(deps.BackupService, log))
	}

	// Update workers
	if deps.UpdateService != nil {
		registry.Register(NewUpdateCheckWorker(deps.UpdateService, log))
		registry.Register(NewContainerUpdateWorker(deps.UpdateService, log))
	}

	// Cleanup workers
	if deps.CleanupService != nil || deps.JobCleanupService != nil {
		registry.Register(NewCleanupWorker(deps.CleanupService, deps.JobCleanupService, log))
	}

	// Prune workers (specialized cleanup)
	if deps.CleanupService != nil {
		registry.Register(NewImagePruneWorker(deps.CleanupService, log))
		registry.Register(NewVolumePruneWorker(deps.CleanupService, log))
		registry.Register(NewNetworkPruneWorker(deps.CleanupService, log))
	}

	// Metrics workers
	if deps.MetricsService != nil {
		registry.Register(NewMetricsCollectionWorker(deps.MetricsService, log))
	}

	// Inventory worker
	if deps.InventoryService != nil {
		registry.Register(NewHostInventoryWorker(deps.InventoryService, log))
	}

	// Retention worker (database cleanup of old metrics, logs, sessions)
	if deps.RetentionService != nil {
		registry.Register(NewRetentionWorker(deps.RetentionService, log))
	}

	// Notification workers
	if deps.NotificationService != nil {
		registry.Register(NewNotificationWorker(deps.NotificationService, log))
		registry.Register(NewAlertWorker(deps.NotificationService, log))
	}

	// Webhook dispatch worker
	if deps.WebhookRepo != nil {
		registry.Register(NewWebhookDispatchWorker(deps.WebhookRepo, log))
	}

	// Runbook execution worker
	if deps.RunbookRepo != nil {
		registry.Register(NewRunbookExecuteWorker(deps.RunbookRepo, deps.ContainerService, deps.RunbookNotifySvc, log))
	}

	// Auto-deploy worker
	if deps.AutoDeployRepo != nil {
		registry.Register(NewAutoDeployWorker(deps.AutoDeployRepo, deps.StackService, log))
	}

	// SLA breach detection worker
	if deps.TrackedVulnRepo != nil {
		registry.Register(NewSLABreachWorker(deps.TrackedVulnRepo, deps.NotificationService, log))
	}
}

// WorkerInfo holds information about a registered worker
type WorkerInfo struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

// GetWorkerDescriptions returns descriptions for all job types
func GetWorkerDescriptions() []WorkerInfo {
	return []WorkerInfo{
		{Type: "security_scan", Description: "Scans containers for security issues and best practices violations"},
		{Type: "update_check", Description: "Checks containers for available image updates"},
		{Type: "container_update", Description: "Updates a container to a newer image version with backup and rollback support"},
		{Type: "backup_create", Description: "Creates a backup of volumes or container data"},
		{Type: "backup_restore", Description: "Restores data from a backup"},
		{Type: "config_sync", Description: "Synchronizes environment variables and configuration to containers"},
		{Type: "image_pull", Description: "Pulls a Docker image from registry"},
		{Type: "image_prune", Description: "Removes unused Docker images"},
		{Type: "volume_prune", Description: "Removes unused Docker volumes"},
		{Type: "network_prune", Description: "Removes unused Docker networks"},
		{Type: "stack_deploy", Description: "Deploys or updates a compose stack"},
		{Type: "npm_sync", Description: "Synchronizes with Nginx Proxy Manager"},
		{Type: "host_inventory", Description: "Collects complete inventory of Docker resources on a host"},
		{Type: "metrics_collection", Description: "Collects resource usage metrics from host and containers"},
		{Type: "cleanup", Description: "Performs system cleanup (images, volumes, networks, old jobs)"},
		{Type: "notification", Description: "Sends notifications through configured channels"},
		{Type: "alert", Description: "Sends alert notifications based on severity"},
		{Type: "retention", Description: "Cleans up old metrics, audit logs, sessions, and expired tokens"},
		{Type: "webhook_dispatch", Description: "Sends HTTP requests for outgoing webhook deliveries"},
		{Type: "runbook_execute", Description: "Executes runbook steps in background"},
		{Type: "auto_deploy", Description: "Performs auto-deploy actions triggered by webhooks"},
		{Type: "sla_breach", Description: "Checks for vulnerability SLA deadline breaches and notifies assignees"},
	}
}
