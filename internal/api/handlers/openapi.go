// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// OpenAPIHandler serves the OpenAPI 3.0 specification.
type OpenAPIHandler struct {
	version string
}

// NewOpenAPIHandler creates a new OpenAPI handler.
func NewOpenAPIHandler(version string) *OpenAPIHandler {
	return &OpenAPIHandler{version: version}
}

// Spec returns the OpenAPI 3.0 JSON specification.
func (h *OpenAPIHandler) Spec(w http.ResponseWriter, r *http.Request) {
	spec := h.buildSpec()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(spec)
}

func (h *OpenAPIHandler) buildSpec() map[string]any {
	return map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       "usulnet API",
			"description": "Docker Management Platform REST API. Provides endpoints for managing containers, images, volumes, networks, stacks, hosts, backups, security scanning, and more.",
			"version":     h.version,
			"license": map[string]any{
				"name": "AGPL-3.0-or-later",
				"url":  "https://www.gnu.org/licenses/agpl-3.0.html",
			},
			"contact": map[string]any{
				"name": "usulnet",
				"url":  "https://github.com/fr4nsys/usulnet",
			},
		},
		"servers": []map[string]any{
			{"url": "/api/v1", "description": "API v1"},
		},
		"tags": h.buildTags(),
		"paths": h.buildPaths(),
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "JWT",
					"description":  "JWT token obtained from /api/v1/auth/login",
				},
				"apiKeyAuth": map[string]any{
					"type":        "apiKey",
					"in":          "header",
					"name":        "X-API-KEY",
					"description": "API key for programmatic access",
				},
			},
			"schemas": h.buildSchemas(),
		},
		"security": []map[string]any{
			{"bearerAuth": []string{}},
			{"apiKeyAuth": []string{}},
		},
	}
}

func (h *OpenAPIHandler) buildTags() []map[string]any {
	return []map[string]any{
		{"name": "Auth", "description": "Authentication and authorization"},
		{"name": "PasswordReset", "description": "Password reset flow"},
		{"name": "System", "description": "System information, health checks, and metrics"},
		{"name": "Containers", "description": "Docker container management (host-scoped)"},
		{"name": "Images", "description": "Docker image management (host-scoped)"},
		{"name": "Volumes", "description": "Docker volume management (host-scoped)"},
		{"name": "Networks", "description": "Docker network management (host-scoped)"},
		{"name": "Stacks", "description": "Docker Compose stack management"},
		{"name": "Hosts", "description": "Host/node management"},
		{"name": "Backups", "description": "Backup, restore, and schedule operations"},
		{"name": "Security", "description": "Security scanning and vulnerability management"},
		{"name": "Config", "description": "Configuration variable and template management"},
		{"name": "ConfigSync", "description": "Configuration synchronization to containers"},
		{"name": "Settings", "description": "Application settings management (admin)"},
		{"name": "LDAP", "description": "LDAP authentication settings (Business+)"},
		{"name": "License", "description": "License management (admin)"},
		{"name": "Updates", "description": "Container image update management"},
		{"name": "Jobs", "description": "Background job and scheduled task management"},
		{"name": "Notifications", "description": "Notification channel and delivery management"},
		{"name": "Users", "description": "User management (admin)"},
		{"name": "Audit", "description": "Audit log viewing and export (admin)"},
		{"name": "Proxy", "description": "Caddy reverse proxy management"},
		{"name": "NPM", "description": "Nginx Proxy Manager integration"},
		{"name": "SSH", "description": "SSH key and connection management"},
		{"name": "Registries", "description": "Container registry management and browsing (Business+)"},
		{"name": "WebSocket", "description": "Real-time container logs, stats, and exec via WebSocket"},
	}
}

func (h *OpenAPIHandler) buildPaths() map[string]any {
	return map[string]any{
		// =====================================================================
		// Auth
		// =====================================================================
		"/auth/login": map[string]any{
			"post": op("Auth", "Login", "Authenticate with username and password", http.StatusOK),
		},
		"/auth/refresh": map[string]any{
			"post": op("Auth", "RefreshToken", "Refresh an expired JWT token", http.StatusOK),
		},
		"/auth/logout": map[string]any{
			"post": op("Auth", "Logout", "Invalidate the current session", http.StatusNoContent),
		},
		"/auth/logout/all": map[string]any{
			"post": op("Auth", "LogoutAll", "Invalidate all sessions for the current user", http.StatusNoContent),
		},
		"/auth/logout/others": map[string]any{
			"post": op("Auth", "LogoutOthers", "Invalidate all sessions except the current one", http.StatusNoContent),
		},
		"/auth/sessions": map[string]any{
			"get": op("Auth", "ListSessions", "List active sessions for the current user", http.StatusOK),
		},
		"/auth/sessions/{sessionID}": map[string]any{
			"delete": op("Auth", "RevokeSession", "Revoke a specific session", http.StatusNoContent),
		},
		"/auth/change-password": map[string]any{
			"post": op("Auth", "ChangePassword", "Change the current user's password", http.StatusOK),
		},
		"/auth/me": map[string]any{
			"get": op("Auth", "GetCurrentUser", "Get the current user's profile", http.StatusOK),
		},

		// =====================================================================
		// Password Reset (public)
		// =====================================================================
		"/password-reset/request": map[string]any{
			"post": publicOp("PasswordReset", "RequestPasswordReset", "Request a password reset email"),
		},
		"/password-reset/validate": map[string]any{
			"post": publicOp("PasswordReset", "ValidateResetToken", "Validate a password reset token"),
		},
		"/password-reset/reset": map[string]any{
			"post": publicOp("PasswordReset", "ResetPassword", "Reset password using a valid token"),
		},

		// =====================================================================
		// System
		// =====================================================================
		"/system/version": map[string]any{
			"get": publicOp("System", "GetVersion", "Get the API and application version"),
		},
		"/system/info": map[string]any{
			"get": op("System", "GetSystemInfo", "Get system information including runtime details", http.StatusOK),
		},
		"/system/health": map[string]any{
			"get": op("System", "GetHealth", "Get health status of all components", http.StatusOK),
		},
		"/system/metrics": map[string]any{
			"get": op("System", "GetMetrics", "Get basic system metrics (viewer+)", http.StatusOK),
		},

		// =====================================================================
		// Containers (host-scoped)
		// =====================================================================
		"/containers": map[string]any{
			"get": op("Containers", "ListContainers", "List all containers across hosts with pagination", http.StatusOK),
		},
		"/containers/stats": map[string]any{
			"get": op("Containers", "GetAggregateStats", "Get aggregate container statistics", http.StatusOK),
		},
		"/containers/{hostID}": map[string]any{
			"get": op("Containers", "ListContainersByHost", "List containers on a specific host", http.StatusOK),
		},
		"/containers/{hostID}/{containerID}": map[string]any{
			"get":    op("Containers", "GetContainer", "Get detailed container information", http.StatusOK),
			"delete": op("Containers", "RemoveContainer", "Remove a container", http.StatusNoContent),
		},
		"/containers/{hostID}/{containerID}/start": map[string]any{
			"post": op("Containers", "StartContainer", "Start a stopped container", http.StatusNoContent),
		},
		"/containers/{hostID}/{containerID}/stop": map[string]any{
			"post": op("Containers", "StopContainer", "Stop a running container", http.StatusNoContent),
		},
		"/containers/{hostID}/{containerID}/restart": map[string]any{
			"post": op("Containers", "RestartContainer", "Restart a container", http.StatusNoContent),
		},
		"/containers/{hostID}/{containerID}/pause": map[string]any{
			"post": op("Containers", "PauseContainer", "Pause a running container", http.StatusNoContent),
		},
		"/containers/{hostID}/{containerID}/unpause": map[string]any{
			"post": op("Containers", "UnpauseContainer", "Unpause a paused container", http.StatusNoContent),
		},
		"/containers/{hostID}/{containerID}/kill": map[string]any{
			"post": op("Containers", "KillContainer", "Send a signal to a container", http.StatusNoContent),
		},
		"/containers/{hostID}/{containerID}/recreate": map[string]any{
			"post": op("Containers", "RecreateContainer", "Recreate a container with current config", http.StatusOK),
		},
		"/containers/{hostID}/{containerID}/logs": map[string]any{
			"get": op("Containers", "GetContainerLogs", "Get container log output", http.StatusOK),
		},
		"/containers/{hostID}/{containerID}/stats": map[string]any{
			"get": op("Containers", "GetContainerStats", "Get container resource usage statistics", http.StatusOK),
		},
		"/containers/{hostID}/{containerID}/exec": map[string]any{
			"post": op("Containers", "CreateExec", "Create an exec instance in a container", http.StatusOK),
		},
		"/containers/{hostID}/{containerID}/env": map[string]any{
			"get": op("Containers", "GetEnvVars", "Get container environment variables", http.StatusOK),
			"put": op("Containers", "UpdateEnvVars", "Update container environment variables", http.StatusOK),
		},
		"/containers/{hostID}/{containerID}/resources": map[string]any{
			"put": op("Containers", "UpdateResources", "Update container resource limits", http.StatusOK),
		},
		"/containers/{hostID}/{containerID}/browse": map[string]any{
			"get": op("Containers", "BrowseFilesystem", "Browse the container filesystem", http.StatusOK),
		},
		"/containers/{hostID}/{containerID}/export": map[string]any{
			"get": op("Containers", "ExportContainer", "Export container as a tar archive", http.StatusOK),
		},
		"/containers/{hostID}/{containerID}/commit": map[string]any{
			"post": op("Containers", "CommitContainer", "Create a new image from container changes", http.StatusOK),
		},
		"/containers/{hostID}/bulk/start": map[string]any{
			"post": op("Containers", "BulkStart", "Start multiple containers", http.StatusOK),
		},
		"/containers/{hostID}/bulk/stop": map[string]any{
			"post": op("Containers", "BulkStop", "Stop multiple containers", http.StatusOK),
		},
		"/containers/{hostID}/bulk/restart": map[string]any{
			"post": op("Containers", "BulkRestart", "Restart multiple containers", http.StatusOK),
		},
		"/containers/{hostID}/prune": map[string]any{
			"post": op("Containers", "PruneContainers", "Remove stopped containers", http.StatusOK),
		},

		// =====================================================================
		// Images (host-scoped)
		// =====================================================================
		"/images/{hostID}": map[string]any{
			"get": op("Images", "ListImages", "List all Docker images on a host", http.StatusOK),
		},
		"/images/{hostID}/dangling": map[string]any{
			"get": op("Images", "ListDanglingImages", "List dangling (untagged) images", http.StatusOK),
		},
		"/images/{hostID}/search": map[string]any{
			"get": op("Images", "SearchImages", "Search for images in registries", http.StatusOK),
		},
		"/images/{hostID}/{imageID}": map[string]any{
			"get":    op("Images", "GetImage", "Get image details", http.StatusOK),
			"delete": op("Images", "RemoveImage", "Remove a Docker image", http.StatusNoContent),
		},
		"/images/{hostID}/{imageID}/history": map[string]any{
			"get": op("Images", "GetImageHistory", "Get image layer history", http.StatusOK),
		},
		"/images/{hostID}/pull": map[string]any{
			"post": op("Images", "PullImage", "Pull an image from a registry", http.StatusOK),
		},
		"/images/{hostID}/build": map[string]any{
			"post": op("Images", "BuildImage", "Build an image from a Dockerfile", http.StatusOK),
		},
		"/images/{hostID}/prune": map[string]any{
			"post": op("Images", "PruneImages", "Remove unused images", http.StatusOK),
		},

		// =====================================================================
		// Volumes (host-scoped)
		// =====================================================================
		"/volumes/{hostID}": map[string]any{
			"get":  op("Volumes", "ListVolumes", "List all Docker volumes on a host", http.StatusOK),
			"post": op("Volumes", "CreateVolume", "Create a new Docker volume", http.StatusCreated),
		},
		"/volumes/{hostID}/{volumeName}": map[string]any{
			"get":    op("Volumes", "GetVolume", "Get volume details", http.StatusOK),
			"delete": op("Volumes", "RemoveVolume", "Remove a Docker volume", http.StatusNoContent),
		},
		"/volumes/{hostID}/prune": map[string]any{
			"post": op("Volumes", "PruneVolumes", "Remove unused volumes", http.StatusOK),
		},
		"/volumes/{hostID}/stats": map[string]any{
			"get": op("Volumes", "GetVolumeStats", "Get volume usage statistics", http.StatusOK),
		},
		"/volumes/{hostID}/{volumeName}/browse": map[string]any{
			"get": op("Volumes", "BrowseVolume", "Browse volume contents", http.StatusOK),
		},

		// =====================================================================
		// Networks (host-scoped)
		// =====================================================================
		"/networks/{hostID}": map[string]any{
			"get":  op("Networks", "ListNetworks", "List all Docker networks on a host", http.StatusOK),
			"post": op("Networks", "CreateNetwork", "Create a new Docker network", http.StatusCreated),
		},
		"/networks/{hostID}/{networkID}": map[string]any{
			"get":    op("Networks", "GetNetwork", "Get network details", http.StatusOK),
			"delete": op("Networks", "RemoveNetwork", "Remove a Docker network", http.StatusNoContent),
		},
		"/networks/{hostID}/{networkID}/connect": map[string]any{
			"post": op("Networks", "ConnectContainer", "Connect a container to a network", http.StatusOK),
		},
		"/networks/{hostID}/{networkID}/disconnect": map[string]any{
			"post": op("Networks", "DisconnectContainer", "Disconnect a container from a network", http.StatusOK),
		},
		"/networks/{hostID}/topology": map[string]any{
			"get": op("Networks", "GetTopology", "Get network topology visualization data", http.StatusOK),
		},
		"/networks/{hostID}/prune": map[string]any{
			"post": op("Networks", "PruneNetworks", "Remove unused networks", http.StatusOK),
		},

		// =====================================================================
		// Stacks
		// =====================================================================
		"/stacks": map[string]any{
			"get":  op("Stacks", "ListStacks", "List all Docker Compose stacks", http.StatusOK),
			"post": op("Stacks", "CreateStack", "Create a new stack", http.StatusCreated),
		},
		"/stacks/deploy": map[string]any{
			"post": op("Stacks", "DeployStack", "Deploy a Docker Compose stack", http.StatusOK),
		},
		"/stacks/validate": map[string]any{
			"post": op("Stacks", "ValidateCompose", "Validate a Docker Compose file", http.StatusOK),
		},
		"/stacks/{stackID}": map[string]any{
			"get":    op("Stacks", "GetStack", "Get stack details and services", http.StatusOK),
			"put":    op("Stacks", "UpdateStack", "Update stack configuration", http.StatusOK),
			"delete": op("Stacks", "RemoveStack", "Remove a stack and its resources", http.StatusNoContent),
		},
		"/stacks/{stackID}/redeploy": map[string]any{
			"post": op("Stacks", "RedeployStack", "Redeploy a stack", http.StatusOK),
		},
		"/stacks/{stackID}/start": map[string]any{
			"post": op("Stacks", "StartStack", "Start all stack services", http.StatusOK),
		},
		"/stacks/{stackID}/stop": map[string]any{
			"post": op("Stacks", "StopStack", "Stop all stack services", http.StatusOK),
		},
		"/stacks/{stackID}/restart": map[string]any{
			"post": op("Stacks", "RestartStack", "Restart all stack services", http.StatusOK),
		},
		"/stacks/{stackID}/compose": map[string]any{
			"get": op("Stacks", "GetComposeConfig", "Get the Compose configuration", http.StatusOK),
		},
		"/stacks/{stackID}/versions": map[string]any{
			"get":  op("Stacks", "ListVersions", "List version history", http.StatusOK),
			"post": op("Stacks", "CreateVersionSnapshot", "Create a version snapshot", http.StatusCreated),
		},
		"/stacks/{stackID}/dependencies": map[string]any{
			"get":  op("Stacks", "ListDependencies", "List stack dependencies", http.StatusOK),
			"post": op("Stacks", "AddDependency", "Add a stack dependency", http.StatusCreated),
		},

		// =====================================================================
		// Hosts
		// =====================================================================
		"/hosts": map[string]any{
			"get":  op("Hosts", "ListHosts", "List all managed hosts/nodes", http.StatusOK),
			"post": op("Hosts", "CreateHost", "Add a new host to manage", http.StatusCreated),
		},
		"/hosts/summaries": map[string]any{
			"get": op("Hosts", "ListSummaries", "List host summaries with status", http.StatusOK),
		},
		"/hosts/stats": map[string]any{
			"get": op("Hosts", "GetAggregateStats", "Get aggregate host statistics", http.StatusOK),
		},
		"/hosts/test": map[string]any{
			"post": op("Hosts", "TestConnection", "Test host connection before adding", http.StatusOK),
		},
		"/hosts/{hostID}": map[string]any{
			"get":    op("Hosts", "GetHost", "Get host details and status", http.StatusOK),
			"put":    op("Hosts", "UpdateHost", "Update host configuration", http.StatusOK),
			"delete": op("Hosts", "RemoveHost", "Remove a managed host", http.StatusNoContent),
		},
		"/hosts/{hostID}/reconnect": map[string]any{
			"post": op("Hosts", "ReconnectHost", "Reconnect to a host", http.StatusOK),
		},

		// =====================================================================
		// Backups
		// =====================================================================
		"/backups": map[string]any{
			"get":  op("Backups", "ListBackups", "List all backups with pagination", http.StatusOK),
			"post": op("Backups", "CreateBackup", "Create a new backup", http.StatusCreated),
		},
		"/backups/stats": map[string]any{
			"get": op("Backups", "GetStats", "Get backup statistics", http.StatusOK),
		},
		"/backups/storage": map[string]any{
			"get": op("Backups", "GetStorageInfo", "Get backup storage information", http.StatusOK),
		},
		"/backups/{backupID}": map[string]any{
			"get":    op("Backups", "GetBackup", "Get backup details", http.StatusOK),
			"delete": op("Backups", "DeleteBackup", "Delete a backup", http.StatusNoContent),
		},
		"/backups/{backupID}/restore": map[string]any{
			"post": op("Backups", "RestoreBackup", "Restore from a backup", http.StatusOK),
		},
		"/backups/{backupID}/verify": map[string]any{
			"post": op("Backups", "VerifyBackup", "Verify backup integrity", http.StatusOK),
		},
		"/backups/{backupID}/contents": map[string]any{
			"get": op("Backups", "ListContents", "List backup archive contents", http.StatusOK),
		},
		"/backups/{backupID}/download": map[string]any{
			"get": op("Backups", "DownloadBackup", "Download backup archive", http.StatusOK),
		},
		"/backups/schedules": map[string]any{
			"get":  op("Backups", "ListSchedules", "List backup schedules", http.StatusOK),
			"post": op("Backups", "CreateSchedule", "Create a backup schedule", http.StatusCreated),
		},
		"/backups/schedules/{scheduleID}": map[string]any{
			"get":    op("Backups", "GetSchedule", "Get schedule details", http.StatusOK),
			"put":    op("Backups", "UpdateSchedule", "Update a backup schedule", http.StatusOK),
			"delete": op("Backups", "DeleteSchedule", "Delete a backup schedule", http.StatusNoContent),
		},
		"/backups/schedules/{scheduleID}/run": map[string]any{
			"post": op("Backups", "RunScheduleNow", "Trigger a scheduled backup immediately", http.StatusOK),
		},

		// =====================================================================
		// Security
		// =====================================================================
		"/security/scans": map[string]any{
			"get": op("Security", "ListScans", "List security scans with pagination", http.StatusOK),
		},
		"/security/scans/{scanID}": map[string]any{
			"get":    op("Security", "GetScan", "Get scan details and vulnerabilities", http.StatusOK),
			"delete": op("Security", "DeleteScan", "Delete a scan record", http.StatusNoContent),
		},
		"/security/containers/{containerID}/scans": map[string]any{
			"get": op("Security", "GetContainerScans", "List scans for a container", http.StatusOK),
		},
		"/security/containers/{containerID}/scans/latest": map[string]any{
			"get": op("Security", "GetLatestScan", "Get the latest scan for a container", http.StatusOK),
		},
		"/security/hosts/{hostID}/scans": map[string]any{
			"get": op("Security", "GetHostScans", "List scans for a host", http.StatusOK),
		},
		"/security/hosts/{hostID}/summary": map[string]any{
			"get": op("Security", "GetHostSummary", "Get security summary for a host", http.StatusOK),
		},
		"/security/summary": map[string]any{
			"get": op("Security", "GetSummary", "Get overall security summary", http.StatusOK),
		},
		"/security/cleanup": map[string]any{
			"post": op("Security", "Cleanup", "Remove old scan records", http.StatusOK),
		},

		// =====================================================================
		// Config (variables + templates)
		// =====================================================================
		"/config/variables": map[string]any{
			"get":  op("Config", "ListVariables", "List configuration variables with pagination", http.StatusOK),
			"post": op("Config", "CreateVariable", "Create a new configuration variable", http.StatusCreated),
		},
		"/config/variables/{id}": map[string]any{
			"get":    op("Config", "GetVariable", "Get a configuration variable", http.StatusOK),
			"put":    op("Config", "UpdateVariable", "Update a configuration variable", http.StatusOK),
			"delete": op("Config", "DeleteVariable", "Delete a configuration variable", http.StatusNoContent),
		},
		"/config/variables/{id}/history": map[string]any{
			"get": op("Config", "GetVariableHistory", "Get variable change history", http.StatusOK),
		},
		"/config/variables/{id}/rollback": map[string]any{
			"post": op("Config", "RollbackVariable", "Rollback variable to a previous value", http.StatusOK),
		},
		"/config/variables/{id}/usage": map[string]any{
			"get": op("Config", "GetVariableUsage", "Get where a variable is used", http.StatusOK),
		},
		"/config/templates": map[string]any{
			"get":  op("Config", "ListTemplates", "List configuration templates", http.StatusOK),
			"post": op("Config", "CreateTemplate", "Create a configuration template", http.StatusCreated),
		},
		"/config/templates/{templateID}": map[string]any{
			"get":    op("Config", "GetTemplate", "Get a configuration template", http.StatusOK),
			"put":    op("Config", "UpdateTemplate", "Update a configuration template", http.StatusOK),
			"delete": op("Config", "DeleteTemplate", "Delete a configuration template", http.StatusNoContent),
		},
		"/config/export": map[string]any{
			"post": op("Config", "ExportConfig", "Export configuration as archive", http.StatusOK),
		},
		"/config/import": map[string]any{
			"post": op("Config", "ImportConfig", "Import configuration from archive", http.StatusOK),
		},

		// Config Sync
		"/config/sync": map[string]any{
			"post": op("ConfigSync", "SyncConfig", "Synchronize configuration to a container", http.StatusOK),
		},
		"/config/sync/preview": map[string]any{
			"post": op("ConfigSync", "PreviewSync", "Preview config changes before syncing", http.StatusOK),
		},
		"/config/sync/bulk": map[string]any{
			"post": op("ConfigSync", "BulkSyncConfig", "Synchronize configuration to multiple containers", http.StatusOK),
		},
		"/config/sync/outdated": map[string]any{
			"get": op("ConfigSync", "ListOutdatedSyncs", "List containers with outdated configuration", http.StatusOK),
		},
		"/config/sync/stats": map[string]any{
			"get": op("ConfigSync", "GetSyncStats", "Get configuration sync statistics", http.StatusOK),
		},
		"/config/sync/{hostID}/{containerID}": map[string]any{
			"get":    op("ConfigSync", "GetSyncStatus", "Get sync status for a container", http.StatusOK),
			"delete": op("ConfigSync", "RemoveSync", "Remove sync tracking for a container", http.StatusNoContent),
		},

		// =====================================================================
		// Settings (admin)
		// =====================================================================
		"/settings": map[string]any{
			"get": op("Settings", "GetSettings", "Get application settings (admin only)", http.StatusOK),
			"put": op("Settings", "UpdateSettings", "Update application settings (admin only)", http.StatusOK),
		},
		"/settings/ldap": map[string]any{
			"get": op("LDAP", "GetLDAPSettings", "Get LDAP configurations (Business+)", http.StatusOK),
			"put": op("LDAP", "UpdateLDAPSettings", "Create or update LDAP configuration (Business+)", http.StatusOK),
		},
		"/settings/ldap/test": map[string]any{
			"post": op("LDAP", "TestLDAPConnection", "Test LDAP connection (Business+)", http.StatusOK),
		},

		// =====================================================================
		// License (admin)
		// =====================================================================
		"/license": map[string]any{
			"get":    op("License", "GetLicense", "Get current license information (admin only)", http.StatusOK),
			"post":   op("License", "ActivateLicense", "Activate a license key (admin only)", http.StatusOK),
			"delete": op("License", "DeactivateLicense", "Deactivate license and revert to CE (admin only)", http.StatusOK),
		},
		"/license/status": map[string]any{
			"get": op("License", "GetLicenseStatus", "Get license status check", http.StatusOK),
		},

		// =====================================================================
		// Updates
		// =====================================================================
		"/updates": map[string]any{
			"get": op("Updates", "ListUpdates", "List available image updates with pagination", http.StatusOK),
		},
		"/updates/check": map[string]any{
			"post": op("Updates", "CheckUpdates", "Check for new image updates", http.StatusOK),
		},
		"/updates/check/{hostID}": map[string]any{
			"post": op("Updates", "CheckHostUpdates", "Check updates for a specific host", http.StatusOK),
		},
		"/updates/apply/{hostID}": map[string]any{
			"post": op("Updates", "ApplyUpdate", "Apply an image update on a host", http.StatusOK),
		},
		"/updates/rollback": map[string]any{
			"post": op("Updates", "RollbackUpdate", "Rollback an applied update", http.StatusOK),
		},
		"/updates/stats": map[string]any{
			"get": op("Updates", "GetStats", "Get update statistics", http.StatusOK),
		},
		"/updates/history/{hostID}": map[string]any{
			"get": op("Updates", "GetHistory", "Get update history for a host", http.StatusOK),
		},
		"/updates/policies": map[string]any{
			"get": op("Updates", "ListPolicies", "List update policies", http.StatusOK),
		},
		"/updates/policies/{hostID}": map[string]any{
			"get":  op("Updates", "ListHostPolicies", "List policies for a host", http.StatusOK),
			"post": op("Updates", "CreatePolicy", "Create an update policy", http.StatusCreated),
		},
		"/updates/webhooks/{hostID}": map[string]any{
			"get":  op("Updates", "ListWebhooks", "List update webhooks for a host", http.StatusOK),
			"post": op("Updates", "CreateWebhook", "Create an update webhook", http.StatusCreated),
		},

		// =====================================================================
		// Jobs
		// =====================================================================
		"/jobs": map[string]any{
			"get":  op("Jobs", "ListJobs", "List background jobs with pagination", http.StatusOK),
			"post": op("Jobs", "EnqueueJob", "Enqueue a new background job", http.StatusCreated),
		},
		"/jobs/stats": map[string]any{
			"get": op("Jobs", "GetStats", "Get job statistics", http.StatusOK),
		},
		"/jobs/{jobID}": map[string]any{
			"get":    op("Jobs", "GetJob", "Get job details and progress", http.StatusOK),
			"delete": op("Jobs", "CancelJob", "Cancel a running or pending job", http.StatusNoContent),
		},
		"/jobs/scheduled": map[string]any{
			"get":  op("Jobs", "ListScheduledJobs", "List scheduled (cron) jobs", http.StatusOK),
			"post": op("Jobs", "CreateScheduledJob", "Create a scheduled job", http.StatusCreated),
		},
		"/jobs/scheduled/{scheduledJobID}": map[string]any{
			"get":    op("Jobs", "GetScheduledJob", "Get scheduled job details", http.StatusOK),
			"put":    op("Jobs", "UpdateScheduledJob", "Update a scheduled job", http.StatusOK),
			"delete": op("Jobs", "DeleteScheduledJob", "Delete a scheduled job", http.StatusNoContent),
		},
		"/jobs/scheduled/{scheduledJobID}/run": map[string]any{
			"post": op("Jobs", "RunScheduledJobNow", "Trigger a scheduled job immediately", http.StatusOK),
		},

		// =====================================================================
		// Notifications
		// =====================================================================
		"/notifications/channels": map[string]any{
			"get":  op("Notifications", "ListChannels", "List notification channels", http.StatusOK),
			"post": op("Notifications", "RegisterChannel", "Register a notification channel", http.StatusCreated),
		},
		"/notifications/channels/{channelName}/test": map[string]any{
			"post": op("Notifications", "TestChannel", "Send a test notification to a channel", http.StatusOK),
		},
		"/notifications/channels/{channelName}": map[string]any{
			"delete": op("Notifications", "RemoveChannel", "Remove a notification channel", http.StatusNoContent),
		},
		"/notifications/send": map[string]any{
			"post": op("Notifications", "SendNotification", "Send a notification", http.StatusOK),
		},
		"/notifications/logs": map[string]any{
			"get": op("Notifications", "GetLogs", "Get notification delivery logs with pagination", http.StatusOK),
		},
		"/notifications/stats": map[string]any{
			"get": op("Notifications", "GetStats", "Get notification statistics", http.StatusOK),
		},
		"/notifications/throttle-stats": map[string]any{
			"get": op("Notifications", "GetThrottleStats", "Get throttle statistics", http.StatusOK),
		},
		"/notifications/throttle/reset": map[string]any{
			"post": op("Notifications", "ResetThrottle", "Reset notification throttle counters", http.StatusOK),
		},

		// =====================================================================
		// Users (admin)
		// =====================================================================
		"/users": map[string]any{
			"get":  op("Users", "ListUsers", "List all users with pagination (admin only)", http.StatusOK),
			"post": op("Users", "CreateUser", "Create a new user (admin only)", http.StatusCreated),
		},
		"/users/stats": map[string]any{
			"get": op("Users", "GetStats", "Get user statistics (admin only)", http.StatusOK),
		},
		"/users/{userID}": map[string]any{
			"get":    op("Users", "GetUser", "Get user details (admin only)", http.StatusOK),
			"put":    op("Users", "UpdateUser", "Update user details (admin only)", http.StatusOK),
			"delete": op("Users", "DeleteUser", "Delete a user (admin only)", http.StatusNoContent),
		},
		"/users/{userID}/activate": map[string]any{
			"post": op("Users", "ActivateUser", "Activate a user account", http.StatusOK),
		},
		"/users/{userID}/deactivate": map[string]any{
			"post": op("Users", "DeactivateUser", "Deactivate a user account", http.StatusOK),
		},
		"/users/{userID}/unlock": map[string]any{
			"post": op("Users", "UnlockUser", "Unlock a locked user account", http.StatusOK),
		},
		"/users/{userID}/api-keys": map[string]any{
			"get":  op("Users", "ListAPIKeys", "List API keys for a user", http.StatusOK),
			"post": op("Users", "CreateAPIKey", "Create an API key for a user", http.StatusCreated),
		},
		"/users/profile": map[string]any{
			"get": op("Users", "GetProfile", "Get own user profile", http.StatusOK),
			"put": op("Users", "UpdateProfile", "Update own user profile", http.StatusOK),
		},
		"/users/profile/api-keys": map[string]any{
			"get":  op("Users", "ListMyAPIKeys", "List own API keys", http.StatusOK),
			"post": op("Users", "CreateMyAPIKey", "Create an API key for self", http.StatusCreated),
		},

		// =====================================================================
		// Audit (admin)
		// =====================================================================
		"/audit": map[string]any{
			"get": op("Audit", "ListAuditLogs", "List audit log entries with pagination and filters", http.StatusOK),
		},
		"/audit/recent": map[string]any{
			"get": op("Audit", "GetRecent", "Get recent audit events", http.StatusOK),
		},
		"/audit/stats": map[string]any{
			"get": op("Audit", "GetStats", "Get audit statistics", http.StatusOK),
		},
		"/audit/user/{userID}": map[string]any{
			"get": op("Audit", "GetByUser", "Get audit events for a specific user", http.StatusOK),
		},
		"/audit/resource/{resourceType}/{resourceID}": map[string]any{
			"get": op("Audit", "GetByResource", "Get audit events for a specific resource", http.StatusOK),
		},
		"/audit/export/csv": map[string]any{
			"get": op("Audit", "ExportCSV", "Export audit logs as CSV (Business+)", http.StatusOK),
		},
		"/audit/export/pdf": map[string]any{
			"get": op("Audit", "ExportPDF", "Export audit logs as text report (Business+)", http.StatusOK),
		},

		// =====================================================================
		// Proxy (Caddy)
		// =====================================================================
		"/proxy/health": map[string]any{
			"get": op("Proxy", "GetHealth", "Get proxy server health status", http.StatusOK),
		},
		"/proxy/upstreams": map[string]any{
			"get": op("Proxy", "GetUpstreamStatus", "Get upstream status", http.StatusOK),
		},
		"/proxy/hosts": map[string]any{
			"get":  op("Proxy", "ListHosts", "List proxy hosts", http.StatusOK),
			"post": op("Proxy", "CreateHost", "Create a proxy host (operator+)", http.StatusCreated),
		},
		"/proxy/hosts/{id}": map[string]any{
			"get":    op("Proxy", "GetHost", "Get proxy host details", http.StatusOK),
			"put":    op("Proxy", "UpdateHost", "Update a proxy host (operator+)", http.StatusOK),
			"delete": op("Proxy", "DeleteHost", "Delete a proxy host (operator+)", http.StatusNoContent),
		},
		"/proxy/hosts/{id}/enable": map[string]any{
			"post": op("Proxy", "EnableHost", "Enable a proxy host (operator+)", http.StatusOK),
		},
		"/proxy/hosts/{id}/disable": map[string]any{
			"post": op("Proxy", "DisableHost", "Disable a proxy host (operator+)", http.StatusOK),
		},
		"/proxy/certificates": map[string]any{
			"get":  op("Proxy", "ListCertificates", "List TLS certificates", http.StatusOK),
			"post": op("Proxy", "UploadCertificate", "Upload a TLS certificate (operator+)", http.StatusCreated),
		},
		"/proxy/certificates/{id}": map[string]any{
			"delete": op("Proxy", "DeleteCertificate", "Delete a certificate (operator+)", http.StatusNoContent),
		},
		"/proxy/dns-providers": map[string]any{
			"get":  op("Proxy", "ListDNSProviders", "List DNS providers", http.StatusOK),
			"post": op("Proxy", "CreateDNSProvider", "Create a DNS provider (operator+)", http.StatusCreated),
		},
		"/proxy/dns-providers/supported": map[string]any{
			"get": op("Proxy", "GetSupportedDNSProviders", "List supported DNS provider types", http.StatusOK),
		},
		"/proxy/dns-providers/{id}": map[string]any{
			"delete": op("Proxy", "DeleteDNSProvider", "Delete a DNS provider (operator+)", http.StatusNoContent),
		},
		"/proxy/sync": map[string]any{
			"post": op("Proxy", "SyncToCaddy", "Sync proxy configuration to Caddy (operator+)", http.StatusOK),
		},
		"/proxy/audit-logs": map[string]any{
			"get": op("Proxy", "ListAuditLogs", "Get proxy audit logs with pagination", http.StatusOK),
		},

		// =====================================================================
		// NPM (Nginx Proxy Manager)
		// =====================================================================
		"/npm/connections": map[string]any{
			"post": op("NPM", "ConfigureConnection", "Configure NPM connection (operator+)", http.StatusCreated),
		},
		"/npm/connections/{hostID}": map[string]any{
			"get": op("NPM", "GetConnection", "Get NPM connection for a host", http.StatusOK),
		},
		"/npm/connections/{hostID}/test": map[string]any{
			"post": op("NPM", "TestConnection", "Test NPM connection", http.StatusOK),
		},
		"/npm/{hostID}/proxy-hosts": map[string]any{
			"get":  op("NPM", "ListProxyHosts", "List NPM proxy hosts", http.StatusOK),
			"post": op("NPM", "CreateProxyHost", "Create NPM proxy host (operator+)", http.StatusCreated),
		},
		"/npm/{hostID}/proxy-hosts/{proxyID}": map[string]any{
			"get":    op("NPM", "GetProxyHost", "Get NPM proxy host details", http.StatusOK),
			"put":    op("NPM", "UpdateProxyHost", "Update NPM proxy host (operator+)", http.StatusOK),
			"delete": op("NPM", "DeleteProxyHost", "Delete NPM proxy host (operator+)", http.StatusNoContent),
		},
		"/npm/{hostID}/certificates": map[string]any{
			"get": op("NPM", "ListCertificates", "List NPM certificates", http.StatusOK),
		},
		"/npm/{hostID}/certificates/letsencrypt": map[string]any{
			"post": op("NPM", "RequestLetsEncrypt", "Request Let's Encrypt certificate (operator+)", http.StatusOK),
		},
		"/npm/{hostID}/redirections": map[string]any{
			"get":  op("NPM", "ListRedirections", "List NPM redirections", http.StatusOK),
			"post": op("NPM", "CreateRedirection", "Create NPM redirection (operator+)", http.StatusCreated),
		},
		"/npm/{hostID}/access-lists": map[string]any{
			"get":  op("NPM", "ListAccessLists", "List NPM access lists", http.StatusOK),
			"post": op("NPM", "CreateAccessList", "Create NPM access list (operator+)", http.StatusCreated),
		},
		"/npm/{hostID}/audit-logs": map[string]any{
			"get": op("NPM", "ListAuditLogs", "Get NPM audit logs with pagination", http.StatusOK),
		},

		// =====================================================================
		// SSH
		// =====================================================================
		"/ssh/keys": map[string]any{
			"get":  op("SSH", "ListKeys", "List SSH keys", http.StatusOK),
			"post": op("SSH", "CreateKey", "Create an SSH key", http.StatusCreated),
		},
		"/ssh/keys/{id}": map[string]any{
			"get":    op("SSH", "GetKey", "Get SSH key details", http.StatusOK),
			"delete": op("SSH", "DeleteKey", "Delete an SSH key", http.StatusNoContent),
		},
		"/ssh/connections": map[string]any{
			"get":  op("SSH", "ListConnections", "List SSH connections", http.StatusOK),
			"post": op("SSH", "CreateConnection", "Create an SSH connection", http.StatusCreated),
		},
		"/ssh/connections/{id}": map[string]any{
			"get":    op("SSH", "GetConnection", "Get SSH connection details", http.StatusOK),
			"put":    op("SSH", "UpdateConnection", "Update an SSH connection", http.StatusOK),
			"delete": op("SSH", "DeleteConnection", "Delete an SSH connection", http.StatusNoContent),
		},
		"/ssh/connections/{id}/test": map[string]any{
			"post": op("SSH", "TestConnection", "Test an SSH connection", http.StatusOK),
		},
		"/ssh/connections/{id}/sessions": map[string]any{
			"get": op("SSH", "GetSessionHistory", "Get session history for a connection", http.StatusOK),
		},
		"/ssh/sessions/active": map[string]any{
			"get": op("SSH", "ListActiveSessions", "List active SSH sessions", http.StatusOK),
		},

		// =====================================================================
		// Registries (Business+)
		// =====================================================================
		"/registries": map[string]any{
			"get":  op("Registries", "ListRegistries", "List stored registries", http.StatusOK),
			"post": op("Registries", "CreateRegistry", "Create a new registry", http.StatusCreated),
		},
		"/registries/{registryID}": map[string]any{
			"put":    op("Registries", "UpdateRegistry", "Update a registry", http.StatusOK),
			"delete": op("Registries", "DeleteRegistry", "Delete a registry", http.StatusNoContent),
		},
		"/registries/{registryID}/repositories": map[string]any{
			"get": op("Registries", "ListRepositories", "List repositories in a registry", http.StatusOK),
		},
		"/registries/{registryID}/repositories/{repository}/tags": map[string]any{
			"get": op("Registries", "ListTags", "List tags for a repository", http.StatusOK),
		},
		"/registries/{registryID}/repositories/{repository}/tags/{reference}": map[string]any{
			"get": op("Registries", "GetManifest", "Get manifest for a specific tag", http.StatusOK),
		},

		// =====================================================================
		// Health (public, outside /api/v1)
		// =====================================================================
		"/health": map[string]any{
			"get": map[string]any{
				"tags":        []string{"System"},
				"operationId": "HealthCheck",
				"summary":     "Public health check endpoint (no auth required)",
				"security":    []map[string]any{},
				"responses": map[string]any{
					"200": map[string]any{"description": "Service is healthy"},
				},
			},
		},
	}
}

func (h *OpenAPIHandler) buildSchemas() map[string]any {
	return map[string]any{
		"Error": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"success": map[string]any{"type": "boolean", "example": false},
				"error": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"code":    map[string]any{"type": "string"},
						"message": map[string]any{"type": "string"},
					},
				},
			},
		},
		"PaginatedResponse": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"data":        map[string]any{"type": "array", "items": map[string]any{}},
				"total":       map[string]any{"type": "integer", "format": "int64"},
				"page":        map[string]any{"type": "integer"},
				"per_page":    map[string]any{"type": "integer"},
				"total_pages": map[string]any{"type": "integer"},
			},
		},
		"Container": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":      map[string]any{"type": "string"},
				"name":    map[string]any{"type": "string"},
				"image":   map[string]any{"type": "string"},
				"state":   map[string]any{"type": "string", "enum": []string{"running", "stopped", "paused", "restarting", "dead"}},
				"status":  map[string]any{"type": "string"},
				"created": map[string]any{"type": "string", "format": "date-time"},
			},
		},
		"Image": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":      map[string]any{"type": "string"},
				"tags":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"size":    map[string]any{"type": "integer", "format": "int64"},
				"created": map[string]any{"type": "string", "format": "date-time"},
			},
		},
		"Volume": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name":       map[string]any{"type": "string"},
				"driver":     map[string]any{"type": "string"},
				"mountpoint": map[string]any{"type": "string"},
				"created":    map[string]any{"type": "string", "format": "date-time"},
			},
		},
		"Network": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":     map[string]any{"type": "string"},
				"name":   map[string]any{"type": "string"},
				"driver": map[string]any{"type": "string"},
				"scope":  map[string]any{"type": "string"},
			},
		},
		"Stack": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name":     map[string]any{"type": "string"},
				"services": map[string]any{"type": "integer"},
				"status":   map[string]any{"type": "string"},
			},
		},
		"Host": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":     map[string]any{"type": "string", "format": "uuid"},
				"name":   map[string]any{"type": "string"},
				"url":    map[string]any{"type": "string"},
				"status": map[string]any{"type": "string"},
			},
		},
		"LDAPConfig": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":              map[string]any{"type": "string", "format": "uuid"},
				"name":            map[string]any{"type": "string"},
				"host":            map[string]any{"type": "string"},
				"port":            map[string]any{"type": "integer"},
				"use_tls":         map[string]any{"type": "boolean"},
				"start_tls":       map[string]any{"type": "boolean"},
				"skip_tls_verify": map[string]any{"type": "boolean"},
				"bind_dn":         map[string]any{"type": "string"},
				"base_dn":         map[string]any{"type": "string"},
				"user_filter":     map[string]any{"type": "string"},
				"username_attr":   map[string]any{"type": "string"},
				"email_attr":      map[string]any{"type": "string"},
				"default_role":    map[string]any{"type": "string"},
				"is_enabled":      map[string]any{"type": "boolean"},
			},
		},
		"LicenseInfo": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"edition":      map[string]any{"type": "string", "enum": []string{"ce", "biz", "ee"}},
				"edition_name": map[string]any{"type": "string"},
				"valid":        map[string]any{"type": "boolean"},
				"license_id":   map[string]any{"type": "string"},
				"expires_at":   map[string]any{"type": "string", "format": "date-time"},
				"features":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			},
		},
		"LoginRequest": map[string]any{
			"type":     "object",
			"required": []string{"username", "password"},
			"properties": map[string]any{
				"username": map[string]any{"type": "string"},
				"password": map[string]any{"type": "string", "format": "password"},
			},
		},
		"LoginResponse": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"token":         map[string]any{"type": "string"},
				"refresh_token": map[string]any{"type": "string"},
				"expires_at":    map[string]any{"type": "string", "format": "date-time"},
				"user": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"id":       map[string]any{"type": "string", "format": "uuid"},
						"username": map[string]any{"type": "string"},
						"email":    map[string]any{"type": "string"},
						"role":     map[string]any{"type": "string", "enum": []string{"admin", "operator", "viewer"}},
					},
				},
			},
		},
		"AuditLogEntry": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":            map[string]any{"type": "string", "format": "uuid"},
				"user_id":       map[string]any{"type": "string", "format": "uuid"},
				"action":        map[string]any{"type": "string"},
				"resource_type": map[string]any{"type": "string"},
				"resource_id":   map[string]any{"type": "string"},
				"ip_address":    map[string]any{"type": "string"},
				"created_at":    map[string]any{"type": "string", "format": "date-time"},
			},
		},
	}
}

// op creates a standard operation definition with authentication required.
func op(tag, opID, summary string, statusCode int) map[string]any {
	responses := map[string]any{
		strconv.Itoa(statusCode): map[string]any{"description": "Successful response"},
		"401":                    map[string]any{"description": "Unauthorized"},
		"500":                    map[string]any{"description": "Internal server error"},
	}

	return map[string]any{
		"tags":        []string{tag},
		"operationId": opID,
		"summary":     summary,
		"responses":   responses,
	}
}

// publicOp creates an operation definition for public endpoints (no auth required).
func publicOp(tag, opID, summary string) map[string]any {
	return map[string]any{
		"tags":        []string{tag},
		"operationId": opID,
		"summary":     summary,
		"security":    []map[string]any{},
		"responses": map[string]any{
			"200": map[string]any{"description": "Successful response"},
		},
	}
}
