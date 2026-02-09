// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/license"
)

// RegisterFrontendRoutes registers all web routes using Templ handlers.
func RegisterFrontendRoutes(r chi.Router, h *Handler, m *Middleware) {
	// Static files
	fileServer := http.FileServer(http.Dir("./web/static"))
	r.Handle("/static/*", http.StripPrefix("/static/", fileServer))

	// Favicon
	r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./web/static/favicon.ico")
	})

	// Public routes (no auth required)
	r.Group(func(r chi.Router) {
		r.Use(m.ThemeMiddleware)
		r.Use(SecureHeaders)

		// Auth pages
		r.Get("/login", h.LoginPageTempl)
		r.Post("/login", h.LoginSubmit)
		r.Get("/logout", h.Logout)

		// TOTP 2FA verification (during login)
		r.Get("/login/totp", h.TOTPVerifyPageTempl)
		r.Post("/login/totp", h.TOTPVerifySubmit)

		// Health check
		r.Get("/health", h.HealthCheck)

		// API Documentation (public)
		r.Get("/docs/api", h.OpenAPIDocsTempl)

		// Webhooks (public, validated by HMAC)
		r.Post("/webhooks/gitea", h.GiteaWebhookReceiver)

		// Prometheus metrics (public, for scraping)
		r.Get("/metrics", h.PrometheusMetrics)
	})

	// Protected routes (auth required)
	r.Group(func(r chi.Router) {
		r.Use(m.AuthRequired)
		r.Use(m.ResourceScopeMiddleware) // Compute user scope for team-based filtering
		r.Use(m.InjectCommonData)
		r.Use(m.FlashMiddleware)
		r.Use(m.CSRFMiddleware)
		r.Use(SecureHeaders)
		r.Use(NoCache)

		// Dashboard
		r.Get("/", h.DashboardTempl)
		r.Get("/dashboard", h.DashboardTempl)

		// Containers
		r.Route("/containers", func(r chi.Router) {
			// View operations - require container:view
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("container:view"))
				r.Get("/", h.ContainersTempl)
				r.Get("/{id}", h.ContainerDetailTempl)
				r.Get("/{id}/stats", h.ContainerStatsTempl)
				r.Get("/{id}/inspect", h.ContainerInspectTempl)
				r.Get("/{id}/files", h.ContainerFilesTempl)
				r.Get("/{id}/files/*", h.ContainerFilesTempl)
				r.Get("/{id}/files/api/browse", h.ContainerBrowseAPI)
				r.Get("/{id}/files/api/browse/*", h.ContainerBrowseAPI)
				r.Get("/{id}/files/api/file/*", h.ContainerReadFileAPI)
				r.Get("/{id}/files/api/download/*", h.ContainerDownloadFileAPI)
				r.Put("/{id}/files/api/file/*", h.ContainerWriteFileAPI)
				r.Delete("/{id}/files/api/file/*", h.ContainerDeleteFileAPI)
				r.Post("/{id}/files/api/mkdir/*", h.ContainerMkdirAPI)
			})

			// Settings - require container:create (modifying container config)
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("container:create"))
				r.Get("/{id}/settings", h.ContainerSettingsTempl)
				r.Post("/{id}/settings", h.ContainerSettingsUpdate)
				r.Get("/{id}/settings-summary", h.ContainerSettingsSummary)
			})

			// Logs - require container:logs
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("container:logs"))
				r.Get("/{id}/logs", h.ContainerLogsTempl)
			})

			// Exec - require container:exec
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("container:exec"))
				r.Get("/{id}/exec", h.ContainerExecTempl)
			})

			// Create - require container:create
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("container:create"))
				r.Get("/new", h.ContainerNewTempl)
				r.Post("/create", h.ContainerCreateSubmit)
			})

			// Start/restart - require container:start
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("container:start"))
				r.Post("/{id}/start", h.ContainerStart)
				r.Post("/{id}/restart", h.ContainerRestart)
				r.Post("/{id}/unpause", h.ContainerUnpause)
				r.Post("/bulk/start", h.ContainerBulkStart)
				r.Post("/bulk/restart", h.ContainerBulkRestart)
				r.Post("/bulk/unpause", h.ContainerBulkUnpause)
			})

			// Stop/pause - require container:stop
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("container:stop"))
				r.Post("/{id}/stop", h.ContainerStop)
				r.Post("/{id}/pause", h.ContainerPause)
				r.Post("/{id}/kill", h.ContainerKill)
				r.Post("/bulk/stop", h.ContainerBulkStop)
				r.Post("/bulk/pause", h.ContainerBulkPause)
				r.Post("/bulk/kill", h.ContainerBulkKill)
			})

			// Remove - require container:remove
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("container:remove"))
				r.Post("/{id}/remove", h.ContainerRemove)
				r.Post("/bulk/remove", h.ContainerBulkRemove)
			})

			// Rename - require container:create (or could be a separate permission)
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("container:create"))
				r.Post("/{id}/rename", h.ContainerRename)
			})
		})

		// Images
		r.Route("/images", func(r chi.Router) {
			// View - require image:view
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("image:view"))
				r.Get("/", h.ImagesTempl)
				r.Get("/{id}", h.ImageDetailTempl)
			})

			// Pull - require image:pull
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("image:pull"))
				r.Get("/pull", h.ImagePull)
				r.Post("/pull", h.ImagePullSubmit)
			})

			// Remove - require image:remove
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("image:remove"))
				r.Post("/{id}/remove", h.ImageRemove)
				r.Post("/prune", h.ImagesPrune)
			})
		})

		// Volumes
		r.Route("/volumes", func(r chi.Router) {
			// View - require volume:view
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("volume:view"))
				r.Get("/", h.VolumesTempl)
				r.Get("/{name}", h.VolumeDetailTempl)
				r.Get("/{name}/browse", h.VolumeBrowseAPI)
				r.Get("/{name}/browse/*", h.VolumeBrowseAPI)
			})

			// Create - require volume:create
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("volume:create"))
				r.Get("/new", h.VolumeNewTempl)
				r.Post("/create", h.VolumeCreate)
			})

			// Remove - require volume:remove
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("volume:remove"))
				r.Post("/{name}/remove", h.VolumeRemove)
				r.Post("/prune", h.VolumesPrune)
			})
		})

		// Networks
		r.Route("/networks", func(r chi.Router) {
			// View - require network:view
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("network:view"))
				r.Get("/", h.NetworksTempl)
				r.Get("/{id}", h.NetworkDetailTempl)
			})

			// Create - require network:create
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("network:create"))
				r.Get("/new", h.NetworkNewTempl)
				r.Post("/create", h.NetworkCreate)
				r.Post("/{id}/connect", h.NetworkConnect)
				r.Post("/{id}/disconnect", h.NetworkDisconnect)
			})

			// Remove - require network:remove
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("network:remove"))
				r.Post("/{id}/remove", h.NetworkRemove)
				r.Post("/prune", h.NetworksPrune)
			})
		})

		// Stacks
		r.Route("/stacks", func(r chi.Router) {
			// View - require stack:view
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("stack:view"))
				r.Get("/", h.StacksTempl)
				r.Get("/catalog", h.StackCatalogTempl)
				r.Get("/catalog/{slug}", h.StackCatalogDeployTempl)
				r.Get("/{name}", h.StackDetailTempl)
			})

			// Deploy - require stack:deploy
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("stack:deploy"))
				r.Get("/new", h.StackNewTempl)
				r.Post("/deploy", h.StackDeploy)
				r.Post("/catalog/{slug}/deploy", h.StackCatalogDeploySubmit)
			})

			// Update (start/stop/restart) - require stack:update
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("stack:update"))
				r.Post("/{name}/start", h.StackStart)
				r.Post("/{name}/stop", h.StackStop)
				r.Post("/{name}/restart", h.StackRestart)
			})

			// Remove - require stack:remove
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("stack:remove"))
				r.Post("/{name}/remove", h.StackRemove)
			})
		})

		// Security
		r.Route("/security", func(r chi.Router) {
			// View - require security:view
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("security:view"))
				r.Get("/", h.SecurityTempl)
				r.Get("/trends", h.SecurityTrendsTempl)
				r.Get("/report", h.SecurityReportTempl)
				r.Get("/container/{id}", h.SecurityContainerTempl)
			})

			// Scan - require security:scan
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("security:scan"))
				r.Post("/scan", h.SecurityScan)
				r.Post("/scan/{id}", h.SecurityScanContainer)
				r.Post("/issues/{id}/ignore", h.SecurityIssueIgnore)
				r.Post("/issues/{id}/resolve", h.SecurityIssueResolve)
			})
		})

		// Updates
		r.Route("/updates", func(r chi.Router) {
			r.Get("/", h.UpdatesTempl)
			r.Get("/check", h.UpdatesCheckTempl)
			r.Post("/check-all", h.UpdatesCheckTempl)
			r.Post("/apply-all", h.UpdateBatch)
			r.Post("/manual", h.UpdateManual)
			r.Get("/{id}/changelog", h.UpdateChangelog)
			r.Post("/{id}/apply", h.UpdateApplyTempl)
			r.Post("/{id}/rollback", h.UpdateRollbackTempl)
			r.Post("/batch", h.UpdateBatch)
		})

		// Backups
		r.Route("/backups", func(r chi.Router) {
			// View - require backup:view
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("backup:view"))
				r.Get("/", h.BackupsTempl)
				r.Get("/new", h.BackupNewTempl)
				r.Get("/schedules", h.BackupSchedulesTempl)
				r.Get("/{id}", h.BackupDetailTempl)
				r.Get("/{id}/download", h.BackupDownload)
			})

			// Create - require backup:create
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("backup:create"))
				r.Post("/create", h.BackupCreate)
				r.Post("/{id}/delete", h.BackupRemove)
				r.Post("/schedules", h.BackupScheduleCreate)
				r.Post("/schedules/{id}/delete", h.BackupScheduleDelete)
				r.Post("/schedules/{id}/run", h.BackupScheduleRun)
			})

			// Restore - require backup:restore
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("backup:restore"))
				r.Post("/{id}/restore", h.BackupRestore)
			})
		})

		// Config
		r.Route("/config", func(r chi.Router) {
			// View - require config:view
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("config:view"))
				r.Get("/", h.ConfigTempl)
				r.Get("/new", h.ConfigTempl)
				r.Get("/variables/{id}", h.ConfigTempl)
				r.Get("/audit", h.ConfigTempl)
				r.Get("/templates", h.ConfigTempl)
				r.Get("/templates/{id}", h.ConfigTempl)
				r.Get("/export", h.ConfigExport)
			})

			// Create - require config:create
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("config:create"))
				r.Post("/variables", h.ConfigVarCreate)
				r.Post("/templates", h.ConfigTemplateCreate)
				r.Post("/import", h.ConfigImport)
			})

			// Update - require config:update
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("config:update"))
				r.Post("/variables/{id}", h.ConfigVarUpdate)
				r.Post("/templates/{id}", h.ConfigTemplateUpdate)
				r.Post("/sync/{id}", h.ConfigSync)
			})

			// Remove - require config:remove
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("config:remove"))
				r.Post("/variables/{id}/delete", h.ConfigVarDelete)
				r.Delete("/variables/{id}", h.ConfigVarDelete)
			})
		})

		// Terminal Hub (multi-tab terminal)
		r.Route("/terminal", func(r chi.Router) {
			r.Get("/", h.TerminalHubTempl)
			r.Get("/picker", h.TerminalPickerTempl)
		})

		// Nodes (usulnet Docker Nodes) - renamed from Hosts
		r.Route("/nodes", func(r chi.Router) {
			// View - require host:view
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("host:view"))
				r.Get("/", h.HostsTempl)
				r.Get("/{id}", h.HostDetailTempl)
				r.Get("/{id}/terminal", h.HostTerminalTempl)
				r.Get("/{id}/files", h.HostFilesTempl)
				r.Get("/{id}/files/*", h.HostFilesTempl)
			})

			// Create - require host:create
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("host:create"))
				r.Get("/new", h.HostCreateFormTempl)
				r.Post("/create", h.HostCreateTempl)
				r.Post("/{id}/test", h.HostTest)
			})

			// Update - require host:update
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("host:update"))
				r.Get("/{id}/edit", h.HostEditFormTempl)
				r.Post("/{id}", h.HostUpdateTempl)
			})

			// Remove - require host:remove
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("host:remove"))
				r.Delete("/{id}", h.HostRemoveTempl)
			})

			// Deploy agent - require host:create (deploying is a privileged operation)
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("host:create"))
				r.Post("/{id}/deploy", h.AgentDeployTempl)
				r.Get("/{id}/deploy/{deployID}", h.AgentDeployStatusTempl)
			})
		})

		// Swarm Cluster Management (requires FeatureSwarm — disabled in CE)
		r.Route("/swarm", func(r chi.Router) {
			r.Use(h.requireFeature(license.FeatureSwarm))

			// View - require host:view
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("host:view"))
				r.Get("/", h.SwarmClusterTempl)
			})

			// Create/manage - require host:create (Swarm operations are privileged)
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("host:create"))
				r.Post("/init", h.SwarmInitTempl)
				r.Post("/leave", h.SwarmLeaveTempl)
				r.Delete("/nodes/{nodeID}", h.SwarmNodeRemoveTempl)
				r.Get("/services/new", h.SwarmServiceCreateFormTempl)
				r.Post("/services/create", h.SwarmServiceCreateTempl)
				r.Delete("/services/{serviceID}", h.SwarmServiceRemoveTempl)
				r.Post("/services/{serviceID}/scale", h.SwarmServiceScaleTempl)
				r.Post("/convert", h.SwarmConvertContainerTempl)
			})
		})

		// Host switcher (changes active host in session)
		r.Get("/switch-host/{id}", h.SwitchHost)

		// Legacy redirect: /hosts -> /nodes
		r.Get("/hosts", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/nodes", http.StatusMovedPermanently)
		})
		r.Get("/hosts/{id}", func(w http.ResponseWriter, r *http.Request) {
			id := chi.URLParam(r, "id")
			http.Redirect(w, r, "/nodes/"+id, http.StatusMovedPermanently)
		})

		// Proxy
		r.Route("/proxy", func(r chi.Router) {
			r.Get("/", h.ProxyTempl)
			r.Get("/setup", h.ProxySetupTempl)
			r.Post("/setup", h.ProxySetupSaveTempl)
			r.Post("/setup/delete", h.ProxySetupDeleteTempl)
			r.Post("/setup/test", h.ProxySetupTestTempl)
			r.Get("/new", h.ProxyNewTempl)
			r.Post("/hosts", h.ProxyHostCreateTempl)
			r.Post("/hosts/{id}", h.ProxyHostUpdateTempl)
			r.Delete("/hosts/{id}", h.ProxyHostDeleteTempl)
			r.Post("/hosts/{id}/enable", h.ProxyHostEnableTempl)
			r.Post("/hosts/{id}/disable", h.ProxyHostDisableTempl)
			r.Post("/sync", h.ProxySyncTempl)

			// Certificates
			r.Route("/certificates", func(r chi.Router) {
				r.Get("/", h.CertListTempl)
				r.Get("/new/letsencrypt", h.CertNewLETempl)
				r.Get("/new/custom", h.CertNewCustomTempl)
				r.Post("/letsencrypt", h.CertCreateLE)
				r.Post("/custom", h.CertCreateCustom)
				r.Get("/{id}", h.CertDetailTempl)
				r.Post("/{id}/renew", h.CertRenew)
				r.Delete("/{id}", h.CertDelete)
			})

			// Redirections
			r.Route("/redirections", func(r chi.Router) {
				r.Get("/", h.RedirListTempl)
				r.Get("/new", h.RedirNewTempl)
				r.Post("/", h.RedirCreate)
				r.Get("/{id}/edit", h.RedirEditTempl)
				r.Post("/{id}", h.RedirUpdate)
				r.Delete("/{id}", h.RedirDelete)
			})

			// Streams
			r.Route("/streams", func(r chi.Router) {
				r.Get("/", h.StreamListTempl)
				r.Get("/new", h.StreamNewTempl)
				r.Post("/", h.StreamCreate)
				r.Get("/{id}/edit", h.StreamEditTempl)
				r.Post("/{id}", h.StreamUpdate)
				r.Delete("/{id}", h.StreamDelete)
			})

			// Dead Hosts (404)
			r.Route("/dead-hosts", func(r chi.Router) {
				r.Get("/", h.DeadListTempl)
				r.Get("/new", h.DeadNewTempl)
				r.Post("/", h.DeadCreate)
				r.Delete("/{id}", h.DeadDelete)
			})

			// Access Lists
			r.Route("/access-lists", func(r chi.Router) {
				r.Get("/", h.ACLListTempl)
				r.Get("/new", h.ACLNewTempl)
				r.Post("/", h.ACLCreate)
				r.Get("/{id}/edit", h.ACLEditTempl)
				r.Post("/{id}", h.ACLUpdate)
				r.Delete("/{id}", h.ACLDelete)
			})

			// Audit Log
			r.Get("/audit", h.AuditListTempl)

			// Proxy host detail/edit (must be last - {id} is catch-all)
			r.Get("/{id}", h.ProxyDetailTempl)
			r.Get("/{id}/edit", h.ProxyEditTempl)
		})

		// S3 Storage
		r.Route("/storage", func(r chi.Router) {
			r.Get("/", h.StorageTempl)
			r.Post("/connections", h.StorageCreateConnection)
			r.Route("/{connID}", func(r chi.Router) {
				r.Post("/delete", h.StorageDeleteConnection)
				r.Post("/test", h.StorageTestConnection)
				r.Get("/buckets", h.StorageBucketsTempl)
				r.Post("/buckets", h.StorageCreateBucket)
				r.Get("/audit", h.StorageAuditTempl)
				r.Route("/buckets/{bucket}", func(r chi.Router) {
					r.Post("/delete", h.StorageDeleteBucket)
					r.Get("/browse", h.StorageBrowserTempl)
					r.Post("/upload", h.StorageUploadObject)
					r.Post("/delete-object", h.StorageDeleteObject)
					r.Post("/create-folder", h.StorageCreateFolder)
					r.Get("/download", h.StorageDownloadObject)
					r.Get("/presign-upload", h.StoragePresignUpload)
				})
			})
		})

		// Connections (SSH, Web Shortcuts, etc.)
		r.Route("/connections", func(r chi.Router) {
			// Main connections dashboard
			r.Get("/", h.ConnectionsTempl)

			// SSH Connections
			r.Route("/ssh", func(r chi.Router) {
				r.Get("/", h.SSHConnectionsTempl)
				r.Get("/new", h.SSHConnectionNewTempl)
				r.Post("/", h.SSHConnectionCreate)
				r.Get("/{id}", h.SSHConnectionDetailTempl)
				r.Post("/{id}", h.SSHConnectionUpdate)
				r.Delete("/{id}", h.SSHConnectionDelete)
				r.Post("/{id}/test", h.SSHConnectionTest)
				r.Get("/{id}/terminal", h.SSHConnectionTerminalTempl)

				// SFTP Browser
				r.Get("/{id}/files", h.SFTPBrowserTempl)
				r.Get("/{id}/files/list", h.SFTPListFiles)
				r.Post("/{id}/files/upload", h.SFTPUpload)
				r.Get("/{id}/files/download", h.SFTPDownload)
				r.Post("/{id}/files/delete", h.SFTPDelete)
				r.Post("/{id}/files/mkdir", h.SFTPMkdir)
				r.Post("/{id}/files/rename", h.SFTPRename)

				// SSH Tunnels
				r.Get("/{id}/tunnels", h.SSHTunnelsTempl)
				r.Post("/{id}/tunnels", h.SSHTunnelCreate)
				r.Post("/{id}/tunnels/{tunnelID}/toggle", h.SSHTunnelToggle)
				r.Delete("/{id}/tunnels/{tunnelID}", h.SSHTunnelDelete)
			})

			// RDP Connections
			r.Route("/rdp", func(r chi.Router) {
				r.Get("/", h.RDPConnectionsTempl)
				r.Get("/new", h.RDPConnectionNewTempl)
				r.Post("/", h.RDPConnectionCreate)
				r.Get("/{id}", h.RDPConnectionDetailTempl)
				r.Post("/{id}", h.RDPConnectionUpdate)
				r.Delete("/{id}", h.RDPConnectionDelete)
				r.Post("/{id}/test", h.RDPConnectionTest)
			})

			// SSH Keys
			r.Route("/keys", func(r chi.Router) {
				r.Get("/", h.SSHKeysTempl)
				r.Get("/new", h.SSHKeyNewTempl)
				r.Post("/", h.SSHKeyCreate)
				r.Get("/{id}", h.SSHKeyDetailTempl)
				r.Delete("/{id}", h.SSHKeyDelete)
				r.Get("/{id}/download", h.SSHKeyDownload)
			})

			// Web Shortcuts
			r.Route("/shortcuts", func(r chi.Router) {
				r.Get("/", h.ShortcutsTempl)
				r.Get("/new", h.ShortcutNewTempl)
				r.Post("/", h.ShortcutCreate)
				r.Get("/{id}/edit", h.ShortcutEditTempl)
				r.Post("/{id}", h.ShortcutUpdate)
				r.Delete("/{id}", h.ShortcutDelete)
			})

			// Database Connections
			r.Route("/database", func(r chi.Router) {
				r.Get("/", h.DatabaseConnectionsTempl)
				r.Post("/", h.DatabaseConnectionCreate)
				r.Get("/{id}", h.DatabaseBrowserTempl)
				r.Post("/{id}/test", h.DatabaseConnectionTest)
				r.Delete("/{id}", h.DatabaseConnectionDelete)
				r.Post("/{id}/write-mode", h.DatabaseWriteModeToggle)
				r.Get("/{id}/query", h.DatabaseQueryTempl)
				r.Post("/{id}/query", h.DatabaseQueryExecute)
			})

			// LDAP Connections (requires FeatureLDAP, disabled in CE)
			r.Route("/ldap", func(r chi.Router) {
				r.Use(h.requireFeature(license.FeatureLDAP))
				r.Get("/", h.LDAPConnectionsTempl)
				r.Post("/", h.LDAPConnectionCreate)
				r.Get("/{id}", h.LDAPBrowserTempl)
				r.Get("/{id}/settings", h.LDAPConnectionSettingsTempl)
				r.Post("/{id}/settings", h.LDAPConnectionSettingsUpdate)
				r.Post("/{id}/test", h.LDAPConnectionTest)
				r.Delete("/{id}", h.LDAPConnectionDelete)
				r.Post("/{id}/write-mode", h.LDAPWriteModeToggle)
				r.Get("/{id}/search", h.LDAPSearchTempl)
				r.Post("/{id}/search", h.LDAPSearchExecute)
			})
		})

		// WebSocket for SSH Terminal
		r.Get("/ws/ssh/{id}", h.WSSSHExec)

		// Gitea Integration (legacy routes - kept for backwards compatibility)
		r.Route("/integrations/gitea", func(r chi.Router) {
			r.Get("/", h.GiteaTempl)
			
			// Connection management
			r.Post("/connections", h.GiteaCreateConnection)
			r.Route("/connections/{id}", func(r chi.Router) {
				r.Post("/test", h.GiteaTestConnection)
				r.Post("/sync", h.GiteaSyncRepos)
				r.Post("/delete", h.GiteaDeleteConnection)
				r.Get("/templates", h.GiteaTemplates) // gitignore & license templates
			})
			
			// Repository creation (Tier 1)
			r.Post("/repos", h.GiteaCreateRepo)
			
			// Repository operations (Tier 1)
			r.Route("/repos/{id}", func(r chi.Router) {
				// Existing
				r.Get("/", h.GiteaRepoDetail)
				r.Get("/files", h.GiteaRepoFiles)
				r.Get("/file", h.GiteaFileContent)
				r.Post("/file", h.GiteaFileSave)
				
				// Tier 1: Repository management
				r.Post("/edit", h.GiteaEditRepo)
				r.Post("/delete", h.GiteaDeleteRepo)
				
				// Tier 1: Branches
				r.Get("/branches", h.GiteaListBranches)
				r.Post("/branches", h.GiteaCreateBranch)
				r.Delete("/branches/{name}", h.GiteaDeleteBranch)
				
				// Tier 1: Tags
				r.Get("/tags", h.GiteaListTags)
				r.Post("/tags", h.GiteaCreateTag)
				r.Delete("/tags/{name}", h.GiteaDeleteTag)
				
				// Tier 1: Commits & Diff
				r.Get("/commits", h.GiteaListCommitsFiltered)
				r.Get("/commits/{sha}", h.GiteaGetCommit)
				r.Get("/compare", h.GiteaCompare)
				r.Get("/diff", h.GiteaGetDiff)
				
				// Tier 2: Pull Requests
				r.Route("/pulls", func(r chi.Router) {
					r.Get("/", h.GiteaListPRs)
					r.Post("/", h.GiteaCreatePR)
					r.Get("/{number}", h.GiteaGetPR)
					r.Patch("/{number}", h.GiteaEditPR)
					r.Post("/{number}/merge", h.GiteaMergePR)
					r.Get("/{number}/diff", h.GiteaGetPRDiff)
					r.Get("/{number}/reviews", h.GiteaListPRReviews)
					r.Post("/{number}/reviews", h.GiteaCreatePRReview)
				})
				
				// Tier 2: Issues
				r.Route("/issues", func(r chi.Router) {
					r.Get("/", h.GiteaListIssues)
					r.Post("/", h.GiteaCreateIssue)
					r.Get("/{number}", h.GiteaGetIssue)
					r.Patch("/{number}", h.GiteaEditIssue)
					r.Get("/{number}/comments", h.GiteaListIssueComments)
					r.Post("/{number}/comments", h.GiteaCreateIssueComment)
					r.Delete("/comments/{commentId}", h.GiteaDeleteIssueComment)
				})
				
				// Tier 2: Labels & Milestones
				r.Get("/labels", h.GiteaListLabels)
				r.Get("/milestones", h.GiteaListMilestones)
				
				// Tier 2: Collaborators
				r.Route("/collaborators", func(r chi.Router) {
					r.Get("/", h.GiteaListCollaborators)
					r.Put("/{username}", h.GiteaAddCollaborator)
					r.Delete("/{username}", h.GiteaRemoveCollaborator)
					r.Get("/{username}/permission", h.GiteaGetCollaboratorPermission)
				})
				r.Get("/teams", h.GiteaListRepoTeams)
				
				// Tier 3: Webhooks
				r.Route("/hooks", func(r chi.Router) {
					r.Get("/", h.GiteaListHooks)
					r.Post("/", h.GiteaCreateHook)
					r.Get("/{hookId}", h.GiteaGetHook)
					r.Patch("/{hookId}", h.GiteaEditHook)
					r.Delete("/{hookId}", h.GiteaDeleteHook)
					r.Post("/{hookId}/test", h.GiteaTestHook)
				})
				
				// Tier 3: Deploy Keys
				r.Route("/keys", func(r chi.Router) {
					r.Get("/", h.GiteaListDeployKeys)
					r.Post("/", h.GiteaCreateDeployKey)
					r.Get("/{keyId}", h.GiteaGetDeployKey)
					r.Delete("/{keyId}", h.GiteaDeleteDeployKey)
				})
				
				// Tier 3: Releases
				r.Route("/releases", func(r chi.Router) {
					r.Get("/", h.GiteaListReleases)
					r.Post("/", h.GiteaCreateRelease)
					r.Get("/latest", h.GiteaGetLatestRelease)
					r.Get("/tags/{tag}", h.GiteaGetReleaseByTag)
					r.Get("/{releaseId}", h.GiteaGetRelease)
					r.Patch("/{releaseId}", h.GiteaEditRelease)
					r.Delete("/{releaseId}", h.GiteaDeleteRelease)
					r.Get("/{releaseId}/assets", h.GiteaListReleaseAssets)
					r.Delete("/{releaseId}/assets/{assetId}", h.GiteaDeleteReleaseAsset)
				})
				
				// Tier 3: Actions / CI
				r.Route("/actions", func(r chi.Router) {
					r.Get("/workflows", h.GiteaListWorkflows)
					r.Get("/runs", h.GiteaListActionRuns)
					r.Get("/runs/{runId}", h.GiteaGetActionRun)
					r.Get("/runs/{runId}/jobs", h.GiteaListActionJobs)
					r.Post("/runs/{runId}/cancel", h.GiteaCancelActionRun)
					r.Post("/runs/{runId}/rerun", h.GiteaRerunActionRun)
					r.Get("/jobs/{jobId}/logs", h.GiteaGetActionJobLogs)
				})
				
				// Tier 3: Commit Status (for CI integrations)
				r.Get("/commits/{sha}/status", h.GiteaGetCombinedStatus)
				r.Get("/commits/{sha}/statuses", h.GiteaListCommitStatuses)
				r.Post("/statuses/{sha}", h.GiteaCreateCommitStatus)
			})
		})

		// Unified Git Integration (supports Gitea, GitHub, GitLab)
		r.Route("/integrations/git", func(r chi.Router) {
			r.Get("/", h.GitListTempl) // Reuses GiteaTempl for now
			
			// Connection management (multi-provider)
			r.Post("/connections", h.GitCreateConnection)
			r.Route("/connections/{id}", func(r chi.Router) {
				r.Post("/test", h.GitTestConnection)
				r.Post("/sync", h.GitSyncRepos)
				r.Post("/delete", h.GitDeleteConnection)
				r.Get("/templates", h.GitTemplates)
			})
			
			// Repository operations (multi-provider)
			r.Post("/repos", h.GitCreateRepo)
			r.Route("/repos/{id}", func(r chi.Router) {
				r.Get("/", h.GitRepoDetail)
				r.Get("/files", h.GitRepoFiles)
				r.Get("/file", h.GitFileContent)
				r.Post("/file", h.GitFileSave)
				r.Post("/edit", h.GitEditRepo)
				r.Post("/delete", h.GitDeleteRepo)
				
				// Branches
				r.Get("/branches", h.GitListBranches)
				r.Post("/branches", h.GitCreateBranch)
				r.Delete("/branches/{name}", h.GitDeleteBranch)
				
				// Tags
				r.Get("/tags", h.GitListTags)
				
				// Commits
				r.Get("/commits", h.GitListCommits)
				r.Get("/commits/{sha}", h.GitGetCommit)
				
				// Pull Requests / Merge Requests
				r.Route("/pulls", func(r chi.Router) {
					r.Get("/", h.GitListPRs)
					r.Post("/", h.GitCreatePR)
					r.Get("/{number}", h.GitGetPR)
					r.Post("/{number}/merge", h.GitMergePR)
				})
				
				// Issues
				r.Route("/issues", func(r chi.Router) {
					r.Get("/", h.GitListIssues)
					r.Post("/", h.GitCreateIssue)
					r.Get("/{number}", h.GitGetIssue)
				})
				
				// Releases
				r.Get("/releases", h.GitListReleases)
				r.Get("/releases/latest", h.GitGetLatestRelease)
			})
		})

		// Editor (Monaco / Nvim)
		r.Route("/editor", func(r chi.Router) {
			r.Get("/", h.EditorHub)
			r.Get("/monaco", h.EditorMonaco)
			r.Get("/nvim", h.EditorNvim)
		})

		// Snippets API (user file storage for editor)
		r.Route("/api/snippets", func(r chi.Router) {
			r.Get("/", h.SnippetList)
			r.Post("/", h.SnippetCreate)
			r.Get("/paths", h.SnippetPaths)
			r.Get("/{id}", h.SnippetGet)
			r.Put("/{id}", h.SnippetUpdate)
			r.Delete("/{id}", h.SnippetDelete)
		})

		// Monitoring (metrics dashboard)
		r.Route("/monitoring", func(r chi.Router) {
			r.Get("/", h.MonitoringTempl)
			r.Get("/host", h.MonitoringHostPartial)
			r.Get("/containers", h.MonitoringContainersPartial)
			r.Get("/history", h.MonitoringHistoryJSON)
		})

		// Alerts
		r.Route("/alerts", func(r chi.Router) {
			r.Get("/", h.AlertsTempl)
			r.Post("/", h.AlertCreate)
			r.Get("/{id}", h.AlertEditTempl)
			r.Post("/{id}", h.AlertUpdate)
			r.Delete("/{id}", h.AlertDelete)
			r.Post("/{id}/enable", h.AlertEnable)
			r.Post("/{id}/disable", h.AlertDisable)
			r.Post("/events/{id}/ack", h.AlertEventAck)
			r.Post("/silences", h.AlertSilenceCreate)
			r.Delete("/silences/{id}", h.AlertSilenceDelete)
		})

		// Tools
		r.Route("/tools", func(r chi.Router) {
			// Command Cheat Sheet
			r.Get("/cheatsheet", h.CheatSheet)
			r.Post("/cheatsheet/custom", h.CheatSheetCustomCreate)
			r.Delete("/cheatsheet/custom/{id}", h.CheatSheetCustomDelete)

			// Ansible Inventory Browser
			r.Get("/ansible", h.AnsibleInventory)
			r.Post("/ansible/upload", h.AnsibleInventoryUpload)
			r.Post("/ansible/parse", h.AnsibleInventoryParse)
			r.Delete("/ansible/{id}", h.AnsibleInventoryDelete)

			// Network Packet Capture
			r.Get("/capture", h.PacketCapture)
			r.Get("/capture/{id}", h.PacketCaptureDetail)
			r.Post("/capture/start", h.PacketCaptureStart)
			r.Post("/capture/{id}/stop", h.PacketCaptureStop)
			r.Get("/capture/{id}/download", h.PacketCaptureDownload)
			r.Delete("/capture/{id}", h.PacketCaptureDelete)
		})

		// Topology
		r.Get("/topology", h.TopologyTempl)

		// Ports
		r.Get("/ports", h.PortsTempl)

		// Events
		r.Get("/events", h.EventsTempl)

		// Centralized Logs
		r.Get("/logs", h.LogsPageTempl)

		// Log Management
		r.Route("/logs/management", func(r chi.Router) {
			r.Get("/", h.LogManagement)
		})

		// Log Uploads
		r.Route("/logs/uploads", func(r chi.Router) {
			r.Post("/", h.LogUpload)
			r.Get("/{id}", h.LogUploadAnalyze)
			r.Delete("/{id}", h.LogUploadDelete)
		})

		// Log Search API
		r.Get("/api/logs/search", h.LogSearchAPI)

		// Notifications
		r.Route("/notifications", func(r chi.Router) {
			r.Get("/", h.NotificationsTempl)
			r.Post("/mark-all-read", h.NotificationsMarkAllRead)
			r.Post("/{id}/read", h.NotificationMarkRead)
			r.Delete("/{id}", h.NotificationDelete)
		})

		// Profile
		r.Route("/profile", func(r chi.Router) {
			r.Get("/", h.ProfileTempl)
			r.Post("/", h.UpdateProfile)
			r.Post("/password", h.UpdatePassword)
		})

		// Admin routes
		r.Group(func(r chi.Router) {
			r.Use(m.AdminRequired)

			// Teams
			r.Route("/teams", func(r chi.Router) {
				r.Get("/", h.TeamsTempl)
				r.Get("/new", h.TeamNewTempl)
				r.Post("/", h.TeamCreate)
				r.Get("/{id}", h.TeamDetailTempl)
				r.Get("/{id}/edit", h.TeamEditTempl)
				r.Post("/{id}", h.TeamUpdate)
				r.Delete("/{id}", h.TeamDelete)
				r.Post("/{id}/members", h.TeamAddMember)
				r.Delete("/{id}/members/{userID}", h.TeamRemoveMember)
				r.Post("/{id}/permissions", h.TeamGrantPermission)
				r.Delete("/{id}/permissions/{permID}", h.TeamRevokePermission)
			})

			// Users
			r.Route("/users", func(r chi.Router) {
				// View - require user:view
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("user:view"))
					r.Get("/", h.UsersTempl)
					r.Get("/{id}", h.UserEditTempl)
				})

				// Create - require user:create
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("user:create"))
					r.Get("/new", h.UserNewTempl)
					r.Post("/", h.UserCreate)
				})

				// Update - require user:update
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("user:update"))
					r.Post("/{id}", h.UserUpdate)
					r.Post("/{id}/enable", h.UserEnable)
					r.Post("/{id}/disable", h.UserDisable)
				})

				// Remove - require user:remove
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("user:remove"))
					r.Delete("/{id}", h.UserDelete)
				})
			})

			// Settings
			r.Route("/settings", func(r chi.Router) {
				// View - require settings:view
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("settings:view"))
					r.Get("/", h.SettingsTempl)
					// TOTP routes don't need special permissions (user's own 2FA)
					r.Get("/totp", h.TOTPSetupPageTempl)
				})

				// Update - require settings:update
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("settings:update"))
					r.Post("/", h.SettingsUpdate)
				})

				// TOTP setup (user's own 2FA - no special permission needed beyond auth)
				r.Post("/totp/verify", h.TOTPVerifySetupSubmit)
				r.Post("/totp/disable", h.TOTPDisableSubmit)
			})

			// OAuth Providers (Admin — requires FeatureOAuth, disabled in CE)
			r.Route("/admin/oauth", func(r chi.Router) {
				r.Use(h.requireFeature(license.FeatureOAuth))
				r.Get("/", h.OAuthProvidersTempl)
				r.Post("/", h.OAuthProviderCreate)
				r.Get("/{id}", h.OAuthProviderEditTempl)
				r.Post("/{id}", h.OAuthProviderUpdate)
				r.Delete("/{id}", h.OAuthProviderDelete)
				r.Post("/{id}/enable", h.OAuthProviderEnable)
				r.Post("/{id}/disable", h.OAuthProviderDisable)
			})

			// LDAP Providers (Admin — requires FeatureLDAP, disabled in CE)
			r.Route("/admin/ldap", func(r chi.Router) {
				r.Use(h.requireFeature(license.FeatureLDAP))
				r.Get("/", h.LDAPProvidersTempl)
				r.Post("/", h.LDAPProviderCreate)
				r.Get("/{id}", h.LDAPProviderEditTempl)
				r.Post("/{id}", h.LDAPProviderUpdate)
				r.Delete("/{id}", h.LDAPProviderDelete)
				r.Post("/{id}/enable", h.LDAPProviderEnable)
				r.Post("/{id}/disable", h.LDAPProviderDisable)
				r.Post("/{id}/test", h.LDAPProviderTest)
			})

			// Notification Channels (Admin)
			r.Route("/admin/notifications", func(r chi.Router) {
				r.Get("/channels", h.NotificationChannelsTempl)
				r.Post("/channels", h.NotificationChannelCreate)
				r.Delete("/channels/{name}", h.NotificationChannelDelete)
				r.Post("/channels/{name}/test", h.NotificationChannelTest)
			})

			// Roles (Admin)
			r.Route("/admin/roles", func(r chi.Router) {
				// View - require role:view
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("role:view"))
					r.Get("/", h.RolesTempl)
					r.Get("/{id}", h.RoleEditTempl)
				})

				// Create - require role:create
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("role:create"))
					r.Post("/", h.RoleCreate)
				})

				// Update - require role:update
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("role:update"))
					r.Post("/{id}", h.RoleUpdate)
					r.Post("/{id}/enable", h.RoleEnable)
					r.Post("/{id}/disable", h.RoleDisable)
				})

				// Remove - require role:remove
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("role:remove"))
					r.Delete("/{id}", h.RoleDelete)
				})
			})

			// Registries (Admin)
			r.Route("/registries", func(r chi.Router) {
				r.Get("/", h.RegistriesTempl)
				r.Post("/", h.RegistryCreate)
				r.Post("/{id}/update", h.RegistryUpdate)
				r.Post("/{id}/delete", h.RegistryDelete)
			})

			// Webhooks & Auto-Deploy (Admin)
			r.Route("/webhooks", func(r chi.Router) {
				r.Get("/", h.WebhooksTempl)
				r.Post("/", h.WebhookCreate)
				r.Post("/{id}/delete", h.WebhookDelete)
				r.Post("/autodeploy", h.AutoDeployCreate)
				r.Post("/autodeploy/{id}/delete", h.AutoDeployDelete)
			})

			// Runbooks (Admin)
			r.Route("/runbooks", func(r chi.Router) {
				r.Get("/", h.RunbooksTempl)
				r.Post("/", h.RunbookCreate)
				r.Post("/{id}/delete", h.RunbookDelete)
				r.Post("/{id}/execute", h.RunbookExecute)
			})

			// Jobs (Admin)
			r.Route("/jobs", func(r chi.Router) {
				r.Get("/", h.JobsTempl)
				r.Get("/{id}", h.JobDetailTempl)
				r.Post("/{id}/cancel", h.JobCancel)
				r.Post("/{id}/delete", h.JobDelete)
			})

			// License (Admin)
			r.Route("/license", func(r chi.Router) {
				r.Get("/", h.LicenseTempl)
				r.Post("/activate", h.LicenseActivate)
				r.Post("/deactivate", h.LicenseDeactivate)
			})
		})

		// WebSocket endpoints
		r.Route("/ws", func(r chi.Router) {
			r.Get("/logs/{id}", h.WSContainerLogs)
			r.Get("/exec/{id}", h.WSContainerExec)
			r.Get("/stats/{id}", h.WSContainerStats)
			r.Get("/host-exec/{id}", h.WSHostExec)
			r.Get("/events", h.WSEvents)
			r.Get("/jobs/{id}", h.WSJobProgress)
			r.Get("/capture/{id}", h.WSCapture)
			r.Get("/metrics", h.WSMetrics)
			r.Get("/editor/nvim", h.WSEditorNvim)
			r.Get("/monitoring/stats", h.WsMonitoringStats)
			r.Get("/monitoring/container/{id}", h.WsMonitoringContainer)
		})

		// Internal API for host filesystem browser (requires nsenter)
		r.Route("/api/v1/hosts/{hostID}", func(r chi.Router) {
			r.Get("/browse", h.APIHostBrowse)
			r.Get("/browse/*", h.APIHostBrowse)
			r.Get("/file/*", h.APIHostReadFile)
			r.Get("/download/*", h.APIHostDownloadFile)
			r.Post("/mkdir/*", h.APIHostMkdir)
			r.Delete("/file/*", h.APIHostDeleteFile)
		})

		// Terminal session history API
		r.Route("/api/v1/terminal", func(r chi.Router) {
			r.Get("/sessions", h.APITerminalSessionList)
			r.Get("/sessions/active", h.APITerminalSessionsActive)
			r.Get("/sessions/{id}", h.APITerminalSessionGet)
			r.Get("/sessions/target/{type}/{id}", h.APITerminalSessionsByTarget)
		})

		// HTMX Partials
		r.Route("/partials", func(r chi.Router) {
			r.Get("/stats", h.StatsPartial)
			r.Get("/containers", h.ContainersPartialTempl)
			r.Get("/container/{id}", h.ContainerRowPartial)
			r.Get("/images", h.ImagesPartial)
			r.Get("/events", h.EventsPartialTempl)
			r.Get("/notifications", h.NotificationsPartialTempl)
			r.Get("/search", h.SearchPartialTempl)
		})
	})
}
