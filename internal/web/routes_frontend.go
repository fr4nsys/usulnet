// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/license"
)

func init() {
	// Ensure correct MIME types on systems with incomplete /etc/mime.types
	// (e.g., Alpine Linux containers). Without this, Go's http.FileServer
	// may serve .js/.css/.woff2 as text/plain, which browsers reject when
	// X-Content-Type-Options: nosniff is set.
	mime.AddExtensionType(".js", "application/javascript")
	mime.AddExtensionType(".mjs", "application/javascript")
	mime.AddExtensionType(".css", "text/css")
	mime.AddExtensionType(".woff2", "font/woff2")
	mime.AddExtensionType(".woff", "font/woff")
	mime.AddExtensionType(".ttf", "font/ttf")
	mime.AddExtensionType(".svg", "image/svg+xml")
	mime.AddExtensionType(".json", "application/json")
	mime.AddExtensionType(".map", "application/json")
}

// noListFS wraps http.FileSystem to disable directory listing.
type noListFS struct{ http.FileSystem }

func (fs noListFS) Open(name string) (http.File, error) {
	f, err := fs.FileSystem.Open(name)
	if err != nil {
		return nil, err
	}
	stat, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if stat.IsDir() {
		return nil, os.ErrNotExist
	}
	return f, nil
}

// staticCacheHeaders adds Cache-Control headers for static assets.
func staticCacheHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.Contains(path, "/vendor/") || strings.HasSuffix(path, ".woff2") || strings.HasSuffix(path, ".ttf") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=86400")
		}
		next.ServeHTTP(w, r)
	})
}

// RegisterFrontendRoutes registers all web routes using Templ handlers.
// All routes are wrapped in a Group so that Use() calls do not conflict
// with routes already registered on the parent router (API routes).
func RegisterFrontendRoutes(r chi.Router, h *Handler, m *Middleware) {
	r.Group(func(r chi.Router) {
	// Panic recovery for all frontend routes
	r.Use(RecoverPanic(h))

	// Request ID for all frontend routes
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqID := r.Header.Get("X-Request-ID")
			if reqID == "" {
				reqID = fmt.Sprintf("%d", time.Now().UnixNano())
			}
			w.Header().Set("X-Request-ID", reqID)
			ctx := context.WithValue(r.Context(), ContextKeyRequestID, reqID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	// Static files
	fileServer := http.FileServer(noListFS{http.Dir("./web/static")})
	r.Handle("/static/*", staticCacheHeaders(http.StripPrefix("/static/", fileServer)))

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
		r.Post("/logout", h.Logout)

		// TOTP 2FA verification (during login)
		r.Get("/login/totp", h.TOTPVerifyPageTempl)
		r.Post("/login/totp", h.TOTPVerifySubmit)

		// LDAP login (redirect to main login with method hint)
		r.Get("/login/ldap", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/login?method=ldap", http.StatusSeeOther)
		})

		// OAuth SSO login
		r.Get("/login/oauth", h.OAuthLogin)
		r.Get("/auth/oauth/callback", h.OAuthCallbackHandler)

		// Health check
		r.Get("/health", h.HealthCheck)

		// API Documentation (public)
		r.Get("/docs/api", h.OpenAPIDocsTempl)

		// Webhooks (public, validated by HMAC)
		r.Post("/webhooks/gitea", h.GiteaWebhookReceiver)
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
		r.Use(MaxRequestBody(10 * 1024 * 1024)) // 10 MB body size limit

		// Dashboard
		r.Get("/", h.DashboardTempl)
		r.Get("/dashboard", h.DashboardTempl)

		// Infrastructure Overview (multi-node aggregate dashboard)
		r.Get("/overview", h.OverviewTempl)

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
			})

			// File write operations - require container:exec (writing inside containers is privileged)
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("container:exec"))
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
				r.Delete("/{id}", h.ImageRemove)
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
				r.Delete("/{name}", h.VolumeRemove)
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
				r.Delete("/{id}", h.NetworkRemove)
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

			// Update (start/stop/restart/edit) - require stack:update
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("stack:update"))
				r.Get("/{name}/edit", h.StackEditTempl)
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

		// Updates & Auto-Update
		r.Route("/updates", func(r chi.Router) {
			// View updates (operator+)
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("settings:view"))
				r.Get("/", h.UpdatesTempl)
				r.Get("/{id}/changelog", h.UpdateChangelog)
			})
			// Apply updates (settings:update)
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("settings:update"))
				r.Post("/check", h.UpdatesCheckTempl)
				r.Post("/check-all", h.UpdatesCheckTempl)
				r.Post("/apply-all", h.UpdateBatch)
				r.Post("/manual", h.UpdateManual)
				r.Post("/{id}/apply", h.UpdateApplyTempl)
				r.Post("/{id}/rollback", h.UpdateRollbackTempl)
				r.Post("/batch", h.UpdateBatch)
				r.Post("/policies", h.AutoUpdatePolicyCreate)
				r.Post("/policies/{id}/toggle", h.AutoUpdatePolicyToggle)
				r.Post("/policies/{id}/delete", h.AutoUpdatePolicyDelete)
			})
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

		// Terminal Hub (multi-tab terminal) - requires container:exec
		r.Route("/terminal", func(r chi.Router) {
			r.Use(m.RequirePermission("container:exec"))
			r.Get("/", h.TerminalHubTempl)
			r.Get("/picker", h.TerminalPickerTempl)
		})

		// Session Replay (Phase 7.2)
		r.Route("/session-replay", func(r chi.Router) {
			r.Use(m.RequirePermission("host:view"))
			r.Get("/{id}", h.SessionReplayPage)
			r.Get("/{id}/data", h.SessionReplayData)
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

		// Swarm Cluster Management (Enterprise/Business license required)
		r.Route("/swarm", func(r chi.Router) {
			r.Use(h.requireFeature(license.FeatureSwarm))

			// View - require host:view
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("host:view"))
				r.Get("/", h.SwarmClusterTempl)
				r.Get("/services/{serviceID}", func(w http.ResponseWriter, r *http.Request) {
					serviceID := chi.URLParam(r, "serviceID")
					http.Redirect(w, r, "/swarm?service="+serviceID, http.StatusSeeOther)
				})
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

		// Proxy (operator+ for mutations, viewer+ for reads)
		r.Route("/proxy", func(r chi.Router) {
			r.Use(m.RequirePermission("host:view"))
			r.Get("/", h.ProxyTempl)
			r.Get("/setup", h.ProxySetupTempl)

			// Operator+ for proxy mutations
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("host:update"))
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
			})

			// Certificates
			r.Route("/certificates", func(r chi.Router) {
				r.Get("/", h.CertListTempl)
				r.Get("/{id}", h.CertDetailTempl)
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("host:update"))
					r.Get("/new/letsencrypt", h.CertNewLETempl)
					r.Get("/new/custom", h.CertNewCustomTempl)
					r.Post("/letsencrypt", h.CertCreateLE)
					r.Post("/custom", h.CertCreateCustom)
					r.Post("/{id}/renew", h.CertRenew)
					r.Delete("/{id}", h.CertDelete)
				})
			})

			// Redirections
			r.Route("/redirections", func(r chi.Router) {
				r.Get("/", h.RedirListTempl)
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("host:update"))
					r.Get("/new", h.RedirNewTempl)
					r.Post("/", h.RedirCreate)
					r.Get("/{id}/edit", h.RedirEditTempl)
					r.Post("/{id}", h.RedirUpdate)
					r.Delete("/{id}", h.RedirDelete)
				})
			})

			// Streams
			r.Route("/streams", func(r chi.Router) {
				r.Get("/", h.StreamListTempl)
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("host:update"))
					r.Get("/new", h.StreamNewTempl)
					r.Post("/", h.StreamCreate)
					r.Get("/{id}/edit", h.StreamEditTempl)
					r.Post("/{id}", h.StreamUpdate)
					r.Delete("/{id}", h.StreamDelete)
				})
			})

			// Dead Hosts (404)
			r.Route("/dead-hosts", func(r chi.Router) {
				r.Get("/", h.DeadListTempl)
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("host:update"))
					r.Get("/new", h.DeadNewTempl)
					r.Post("/", h.DeadCreate)
					r.Delete("/{id}", h.DeadDelete)
				})
			})

			// Access Lists
			r.Route("/access-lists", func(r chi.Router) {
				r.Get("/", h.ACLListTempl)
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("host:update"))
					r.Get("/new", h.ACLNewTempl)
					r.Post("/", h.ACLCreate)
					r.Get("/{id}/edit", h.ACLEditTempl)
					r.Post("/{id}", h.ACLUpdate)
					r.Delete("/{id}", h.ACLDelete)
				})
			})

			// Audit Log
			r.Get("/audit", h.AuditListTempl)

			// Proxy host detail/edit (must be last - {id} is catch-all)
			r.Get("/{id}", h.ProxyDetailTempl)
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("host:update"))
				r.Get("/{id}/edit", h.ProxyEditTempl)
			})
		})

		// Storage (S3, Azure, GCS, B2, SFTP, Local)
		r.Route("/storage", func(r chi.Router) {
			r.Use(m.RequirePermission("backup:view"))
			r.Get("/", h.StorageTempl)

			// Mutations require backup:create
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("backup:create"))
				r.Post("/connections", h.StorageCreateConnection)
			})

			r.Route("/{connID}", func(r chi.Router) {
				r.Get("/buckets", h.StorageBucketsTempl)
				r.Get("/audit", h.StorageAuditTempl)

				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("backup:create"))
					r.Post("/update", h.StorageUpdateConnection)
					r.Post("/delete", h.StorageDeleteConnection)
					r.Post("/test", h.StorageTestConnection)
					r.Post("/buckets", h.StorageCreateBucket)
				})

				r.Route("/buckets/{bucket}", func(r chi.Router) {
					r.Get("/browse", h.StorageBrowserTempl)
					r.Get("/download", h.StorageDownloadObject)
					r.Get("/presign-upload", h.StoragePresignUpload)

					r.Group(func(r chi.Router) {
						r.Use(m.RequirePermission("backup:create"))
						r.Post("/delete", h.StorageDeleteBucket)
						r.Post("/upload", h.StorageUploadObject)
						r.Post("/delete-object", h.StorageDeleteObject)
						r.Post("/create-folder", h.StorageCreateFolder)
					})
				})
			})
		})

		// Connections (SSH, Web Shortcuts, etc.)
		r.Route("/connections", func(r chi.Router) {
			r.Use(m.RequirePermission("host:view"))
			// Main connections dashboard
			r.Get("/", h.ConnectionsTempl)

			// SSH Connections (optional service — gated by middleware)
			r.Route("/ssh", func(r chi.Router) {
				r.Use(h.requireServiceMiddleware(
					func() bool { return h.sshService != nil },
					"SSH Connections", "Enable SSH by configuring an encryption key (USULNET_ENCRYPTION_KEY)",
				))
				// Read-only (inherits host:view)
				r.Get("/", h.SSHConnectionsTempl)
				r.Get("/{id}", h.SSHConnectionDetailTempl)
				r.Get("/{id}/terminal", h.SSHConnectionTerminalTempl)
				r.Get("/{id}/tunnels", h.SSHTunnelsTempl)

				// SFTP Browser - read-only
				r.Get("/{id}/files", h.SFTPBrowserTempl)
				r.Get("/{id}/files/list", h.SFTPListFiles)
				r.Get("/{id}/files/download", h.SFTPDownload)

				// Mutations require host:update
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("host:update"))
					r.Get("/new", h.SSHConnectionNewTempl)
					r.Post("/", h.SSHConnectionCreate)
					r.Post("/{id}", h.SSHConnectionUpdate)
					r.Delete("/{id}", h.SSHConnectionDelete)
					r.Post("/{id}/test", h.SSHConnectionTest)
					r.Post("/{id}/duplicate", h.SSHConnectionDuplicate)

					// SFTP Browser - write operations
					r.Post("/{id}/files/upload", h.SFTPUpload)
					r.Post("/{id}/files/delete", h.SFTPDelete)
					r.Post("/{id}/files/mkdir", h.SFTPMkdir)
					r.Post("/{id}/files/rename", h.SFTPRename)

					// SSH Tunnels - mutations
					r.Post("/{id}/tunnels", h.SSHTunnelCreate)
					r.Post("/{id}/tunnels/{tunnelID}/toggle", h.SSHTunnelToggle)
					r.Delete("/{id}/tunnels/{tunnelID}", h.SSHTunnelDelete)
				})
			})

			// RDP Connections
			r.Route("/rdp", func(r chi.Router) {
				// Read-only (inherits host:view)
				r.Get("/", h.RDPConnectionsTempl)
				r.Get("/{id}", h.RDPConnectionDetailTempl)
				r.Get("/{id}/download", h.RDPConnectionDownload)
				r.Get("/{id}/session", h.RDPSessionTempl)

				// Mutations require host:update
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("host:update"))
					r.Get("/new", h.RDPConnectionNewTempl)
					r.Post("/", h.RDPConnectionCreate)
					r.Post("/{id}", h.RDPConnectionUpdate)
					r.Delete("/{id}", h.RDPConnectionDelete)
					r.Post("/{id}/test", h.RDPConnectionTest)
				})
			})

			// SSH Keys
			r.Route("/keys", func(r chi.Router) {
				// Read-only (inherits host:view)
				r.Get("/", h.SSHKeysTempl)
				r.Get("/{id}", h.SSHKeyDetailTempl)
				r.Get("/{id}/download", h.SSHKeyDownload)

				// Mutations require host:update
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("host:update"))
					r.Get("/new", h.SSHKeyNewTempl)
					r.Post("/", h.SSHKeyCreate)
					r.Delete("/{id}", h.SSHKeyDelete)
				})
			})

			// Web Shortcuts
			r.Route("/shortcuts", func(r chi.Router) {
				// Read-only (inherits host:view)
				r.Get("/", h.ShortcutsTempl)
				r.Get("/{id}/edit", h.ShortcutEditTempl)

				// Mutations require host:update
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("host:update"))
					r.Get("/new", h.ShortcutNewTempl)
					r.Post("/", h.ShortcutCreate)
					r.Post("/{id}", h.ShortcutUpdate)
					r.Delete("/{id}", h.ShortcutDelete)
				})
			})

			// Database Connections
			r.Route("/database", func(r chi.Router) {
				// Read-only: list and browse (inherits host:view)
				r.Get("/", h.DatabaseConnectionsTempl)
				r.Get("/{id}", h.DatabaseBrowserTempl)

				// Mutations and query execution require host:update
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("host:update"))
					r.Post("/", h.DatabaseConnectionCreate)
					r.Post("/{id}/test", h.DatabaseConnectionTest)
					r.Delete("/{id}", h.DatabaseConnectionDelete)
					r.Get("/{id}/query", h.DatabaseQueryTempl)
					r.Post("/{id}/query", h.DatabaseQueryExecute)
					r.Post("/{id}/write-mode", h.DatabaseWriteModeToggle)
				})
			})

			// LDAP Connections
			r.Route("/ldap", func(r chi.Router) {
				// Read-only: list and browse (inherits host:view)
				r.Get("/", h.LDAPConnectionsTempl)
				r.Get("/{id}", h.LDAPBrowserTempl)
				r.Get("/{id}/settings", h.LDAPConnectionSettingsTempl)

				// Mutations and search execution require host:update
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("host:update"))
					r.Post("/", h.LDAPConnectionCreate)
					r.Post("/{id}/settings", h.LDAPConnectionSettingsUpdate)
					r.Post("/{id}/test", h.LDAPConnectionTest)
					r.Delete("/{id}", h.LDAPConnectionDelete)
					r.Get("/{id}/search", h.LDAPSearchTempl)
					r.Post("/{id}/search", h.LDAPSearchExecute)
					r.Post("/{id}/write-mode", h.LDAPWriteModeToggle)
				})
			})
		})

		// WebSocket for SSH Terminal (requires host:update + rate limit)
		r.With(WebSocketRateLimit(), m.RequirePermission("host:update")).
			Get("/ws/ssh/{id}", h.WSSSHExec)

		// WebSocket for RDP Session (via guacd) (requires host:update + rate limit)
		r.With(WebSocketRateLimit(), m.RequirePermission("host:update")).
			Get("/ws/rdp/{id}", h.WSRDPExec)

		// Gitea Integration (legacy routes - kept for backwards compatibility)
		r.Route("/integrations/gitea", func(r chi.Router) {
			r.Use(m.RequirePermission("stack:view"))
			r.Get("/", h.GiteaTempl)

			// Connection management (mutations require stack:deploy)
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("stack:deploy"))
				r.Post("/connections", h.GiteaCreateConnection)
			})
			r.Route("/connections/{id}", func(r chi.Router) {
				r.Get("/templates", h.GiteaTemplates) // gitignore & license templates (read-only)
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("stack:deploy"))
					r.Post("/test", h.GiteaTestConnection)
					r.Post("/sync", h.GiteaSyncRepos)
					r.Post("/delete", h.GiteaDeleteConnection)
				})
			})

			// Repository creation (requires stack:deploy)
			r.With(m.RequirePermission("stack:deploy")).Post("/repos", h.GiteaCreateRepo)

			// Repository operations
			r.Route("/repos/{id}", func(r chi.Router) {
				// Read-only operations (stack:view inherited)
				r.Get("/", h.GiteaRepoDetail)
				r.Get("/files", h.GiteaRepoFiles)
				r.Get("/file", h.GiteaFileContent)
				r.Get("/branches", h.GiteaListBranches)
				r.Get("/tags", h.GiteaListTags)
				r.Get("/commits", h.GiteaListCommitsFiltered)
				r.Get("/commits/{sha}", h.GiteaGetCommit)
				r.Get("/compare", h.GiteaCompare)
				r.Get("/diff", h.GiteaGetDiff)

				// Mutation operations (require stack:deploy)
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("stack:deploy"))
					r.Post("/file", h.GiteaFileSave)
					r.Post("/edit", h.GiteaEditRepo)
					r.Post("/delete", h.GiteaDeleteRepo)
					r.Post("/branches", h.GiteaCreateBranch)
					r.Delete("/branches/{name}", h.GiteaDeleteBranch)
					r.Post("/tags", h.GiteaCreateTag)
					r.Delete("/tags/{name}", h.GiteaDeleteTag)
				})

				// Tier 2: Pull Requests
				r.Route("/pulls", func(r chi.Router) {
					r.Get("/", h.GiteaListPRs)
					r.Get("/{number}", h.GiteaGetPR)
					r.Get("/{number}/diff", h.GiteaGetPRDiff)
					r.Get("/{number}/reviews", h.GiteaListPRReviews)
					r.Group(func(r chi.Router) {
						r.Use(m.RequirePermission("stack:deploy"))
						r.Post("/", h.GiteaCreatePR)
						r.Patch("/{number}", h.GiteaEditPR)
						r.Post("/{number}/merge", h.GiteaMergePR)
						r.Post("/{number}/reviews", h.GiteaCreatePRReview)
					})
				})

				// Tier 2: Issues
				r.Route("/issues", func(r chi.Router) {
					r.Get("/", h.GiteaListIssues)
					r.Get("/{number}", h.GiteaGetIssue)
					r.Get("/{number}/comments", h.GiteaListIssueComments)
					r.Group(func(r chi.Router) {
						r.Use(m.RequirePermission("stack:deploy"))
						r.Post("/", h.GiteaCreateIssue)
						r.Patch("/{number}", h.GiteaEditIssue)
						r.Post("/{number}/comments", h.GiteaCreateIssueComment)
						r.Delete("/comments/{commentId}", h.GiteaDeleteIssueComment)
					})
				})

				// Tier 2: Labels & Milestones (read-only)
				r.Get("/labels", h.GiteaListLabels)
				r.Get("/milestones", h.GiteaListMilestones)

				// Tier 2: Collaborators
				r.Route("/collaborators", func(r chi.Router) {
					r.Get("/", h.GiteaListCollaborators)
					r.Get("/{username}/permission", h.GiteaGetCollaboratorPermission)
					r.Group(func(r chi.Router) {
						r.Use(m.RequirePermission("stack:deploy"))
						r.Put("/{username}", h.GiteaAddCollaborator)
						r.Delete("/{username}", h.GiteaRemoveCollaborator)
					})
				})
				r.Get("/teams", h.GiteaListRepoTeams)

				// Tier 3: Webhooks (all mutations require stack:deploy)
				r.Route("/hooks", func(r chi.Router) {
					r.Get("/", h.GiteaListHooks)
					r.Get("/{hookId}", h.GiteaGetHook)
					r.Group(func(r chi.Router) {
						r.Use(m.RequirePermission("stack:deploy"))
						r.Post("/", h.GiteaCreateHook)
						r.Patch("/{hookId}", h.GiteaEditHook)
						r.Delete("/{hookId}", h.GiteaDeleteHook)
						r.Post("/{hookId}/test", h.GiteaTestHook)
					})
				})

				// Tier 3: Deploy Keys (all mutations require stack:deploy)
				r.Route("/keys", func(r chi.Router) {
					r.Get("/", h.GiteaListDeployKeys)
					r.Get("/{keyId}", h.GiteaGetDeployKey)
					r.Group(func(r chi.Router) {
						r.Use(m.RequirePermission("stack:deploy"))
						r.Post("/", h.GiteaCreateDeployKey)
						r.Delete("/{keyId}", h.GiteaDeleteDeployKey)
					})
				})

				// Tier 3: Releases (all mutations require stack:deploy)
				r.Route("/releases", func(r chi.Router) {
					r.Get("/", h.GiteaListReleases)
					r.Get("/latest", h.GiteaGetLatestRelease)
					r.Get("/tags/{tag}", h.GiteaGetReleaseByTag)
					r.Get("/{releaseId}", h.GiteaGetRelease)
					r.Get("/{releaseId}/assets", h.GiteaListReleaseAssets)
					r.Group(func(r chi.Router) {
						r.Use(m.RequirePermission("stack:deploy"))
						r.Post("/", h.GiteaCreateRelease)
						r.Patch("/{releaseId}", h.GiteaEditRelease)
						r.Delete("/{releaseId}", h.GiteaDeleteRelease)
						r.Delete("/{releaseId}/assets/{assetId}", h.GiteaDeleteReleaseAsset)
					})
				})

				// Tier 3: Actions / CI
				r.Route("/actions", func(r chi.Router) {
					r.Get("/workflows", h.GiteaListWorkflows)
					r.Get("/runs", h.GiteaListActionRuns)
					r.Get("/runs/{runId}", h.GiteaGetActionRun)
					r.Get("/runs/{runId}/jobs", h.GiteaListActionJobs)
					r.Get("/jobs/{jobId}/logs", h.GiteaGetActionJobLogs)
					r.Group(func(r chi.Router) {
						r.Use(m.RequirePermission("stack:deploy"))
						r.Post("/runs/{runId}/cancel", h.GiteaCancelActionRun)
						r.Post("/runs/{runId}/rerun", h.GiteaRerunActionRun)
					})
				})

				// Tier 3: Commit Status (for CI integrations)
				r.Get("/commits/{sha}/status", h.GiteaGetCombinedStatus)
				r.Get("/commits/{sha}/statuses", h.GiteaListCommitStatuses)
				r.With(m.RequirePermission("stack:deploy")).
					Post("/statuses/{sha}", h.GiteaCreateCommitStatus)
			})
		})

		// Unified Git Integration (supports Gitea, GitHub, GitLab) - Business+ feature
		r.Route("/integrations/git", func(r chi.Router) {
			r.Use(m.RequirePermission("stack:view"))
			r.Use(h.requireFeature(license.FeatureGitSync))
			r.Get("/", h.GitListTempl) // Reuses GiteaTempl for now

			// Connection management (mutations require stack:deploy)
			r.Route("/connections/{id}", func(r chi.Router) {
				r.Get("/templates", h.GitTemplates)
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("stack:deploy"))
					r.Post("/test", h.GitTestConnection)
					r.Post("/sync", h.GitSyncRepos)
					r.Post("/delete", h.GitDeleteConnection)
				})
			})
			r.With(m.RequirePermission("stack:deploy")).Post("/connections", h.GitCreateConnection)

			// Repository operations (multi-provider)
			r.With(m.RequirePermission("stack:deploy")).Post("/repos", h.GitCreateRepo)
			r.Route("/repos/{id}", func(r chi.Router) {
				// Read-only
				r.Get("/", h.GitRepoDetail)
				r.Get("/files", h.GitRepoFiles)
				r.Get("/file", h.GitFileContent)
				r.Get("/branches", h.GitListBranches)
				r.Get("/tags", h.GitListTags)
				r.Get("/commits", h.GitListCommits)
				r.Get("/commits/{sha}", h.GitGetCommit)
				r.Get("/releases", h.GitListReleases)
				r.Get("/releases/latest", h.GitGetLatestRelease)

				// Mutations require stack:deploy
				r.Group(func(r chi.Router) {
					r.Use(m.RequirePermission("stack:deploy"))
					r.Post("/file", h.GitFileSave)
					r.Post("/edit", h.GitEditRepo)
					r.Post("/delete", h.GitDeleteRepo)
					r.Post("/branches", h.GitCreateBranch)
					r.Delete("/branches/{name}", h.GitDeleteBranch)
				})

				// Pull Requests / Merge Requests
				r.Route("/pulls", func(r chi.Router) {
					r.Get("/", h.GitListPRs)
					r.Get("/{number}", h.GitGetPR)
					r.Group(func(r chi.Router) {
						r.Use(m.RequirePermission("stack:deploy"))
						r.Post("/", h.GitCreatePR)
						r.Post("/{number}/merge", h.GitMergePR)
					})
				})

				// Issues
				r.Route("/issues", func(r chi.Router) {
					r.Get("/", h.GitListIssues)
					r.Get("/{number}", h.GitGetIssue)
					r.With(m.RequirePermission("stack:deploy")).Post("/", h.GitCreateIssue)
				})
			})
		})

		// Editor (Monaco / Nvim) - requires host:update (file editing is privileged)
		r.Route("/editor", func(r chi.Router) {
			r.Use(m.RequirePermission("host:update"))
			r.Get("/", h.EditorHub)
			r.Get("/monaco", h.EditorMonaco)
			r.Get("/nvim", h.EditorNvim)
		})

		// Snippets API (user file storage for editor) - requires host:update
		r.Route("/api/snippets", func(r chi.Router) {
			r.Use(m.RequirePermission("host:update"))
			r.Get("/", h.SnippetList)
			r.Post("/", h.SnippetCreate)
			r.Get("/paths", h.SnippetPaths)
			r.Get("/{id}", h.SnippetGet)
			r.Put("/{id}", h.SnippetUpdate)
			r.Delete("/{id}", h.SnippetDelete)
		})

		// Monitoring (metrics dashboard) - requires host:view
		r.Route("/monitoring", func(r chi.Router) {
			r.Use(m.RequirePermission("host:view"))
			r.Get("/", h.MonitoringPage)
			r.Get("/{id}", h.MonitoringContainerPage)
			r.Get("/host", redirect301("/partials/monitoring/host"))
			r.Get("/containers", redirect301("/partials/monitoring/containers"))
			r.Get("/history", redirect301("/partials/monitoring/history"))
		})

		// Alerts - requires security:view for reads, security:scan for mutations
		r.Route("/alerts", func(r chi.Router) {
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("security:view"))
				r.Get("/", h.AlertsTempl)
				r.Get("/{id}", h.AlertEditTempl)
			})
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("security:scan"))
				r.Post("/", h.AlertCreate)
				r.Post("/{id}", h.AlertUpdate)
				r.Delete("/{id}", h.AlertDelete)
				r.Post("/{id}/enable", h.AlertEnable)
				r.Post("/{id}/disable", h.AlertDisable)
				r.Post("/events/{id}/ack", h.AlertEventAck)
				r.Post("/silences", h.AlertSilenceCreate)
				r.Delete("/silences/{id}", h.AlertSilenceDelete)
			})
		})

		// Tools
		r.Route("/tools", func(r chi.Router) {
			// Command Cheat Sheet (any authenticated user)
			r.Get("/cheatsheet", h.CheatSheet)
			r.Post("/cheatsheet/custom", h.CheatSheetCustomCreate)
			r.Delete("/cheatsheet/custom/{id}", h.CheatSheetCustomDelete)

			// Ansible Inventory Browser — removed: stub handler that silently
			// discarded data. No database persistence, repository, or service
			// was ever implemented. Will be re-added when properly implemented.

			// Network Packet Capture (host:update - highly sensitive)
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("host:update"))
				r.Get("/capture", h.PacketCapture)
				r.Get("/capture/{id}", h.PacketCaptureDetail)
				r.Post("/capture/start", h.PacketCaptureStart)
				r.Post("/capture/{id}/stop", h.PacketCaptureStop)
				r.Get("/capture/{id}/download", h.PacketCaptureDownload)
				r.Get("/capture/{id}/analyze", h.PacketCaptureAnalyze)
				r.Delete("/capture/{id}", h.PacketCaptureDelete)
			})
		})

		// Topology (requires container:view — shows container relationships)
		r.With(m.RequirePermission("container:view")).Get("/topology", h.TopologyTempl)

		// Dependencies (full dependency graph — requires container:view)
		r.With(m.RequirePermission("container:view")).Get("/dependencies", h.DependenciesTempl)

		// Lifecycle Policies (automated resource cleanup) - requires settings:update
		r.Route("/lifecycle", func(r chi.Router) {
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("settings:view"))
				r.Get("/", h.LifecyclePoliciesTempl)
			})
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("settings:update"))
				r.Post("/policies", h.LifecyclePolicyCreate)
				r.Post("/policies/{id}/toggle", h.LifecyclePolicyToggle)
				r.Post("/policies/{id}/delete", h.LifecyclePolicyDelete)
				r.Post("/policies/{id}/execute", h.LifecyclePolicyExecute)
			})
		})

		// Resource Quotas (admin only)
		r.Route("/quotas", func(r chi.Router) {
			r.Use(m.AdminRequired)
			r.Get("/", h.QuotasTempl)
			r.Post("/", h.QuotaCreate)
			r.Post("/{id}/toggle", h.QuotaToggle)
			r.Post("/{id}/delete", h.QuotaDelete)
		})

		// GitOps Pipelines (automated deployment from Git) - Business+ feature
		r.Route("/gitops", func(r chi.Router) {
			r.Use(h.requireFeature(license.FeatureGitSync))
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("stack:view"))
				r.Get("/", h.GitOpsTempl)
			})
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("stack:deploy"))
				r.Post("/pipelines", h.GitOpsPipelineCreate)
				r.Post("/pipelines/{id}/toggle", h.GitOpsPipelineToggle)
				r.Post("/pipelines/{id}/delete", h.GitOpsPipelineDelete)
				r.Post("/pipelines/{id}/deploy", h.GitOpsPipelineDeploy)
			})
		})

		// Container Templates (reusable container configs) - requires container:create
		r.Route("/container-templates", func(r chi.Router) {
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("container:view"))
				r.Get("/", h.ContainerTemplatesTempl)
			})
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("container:create"))
				r.Post("/", h.ContainerTemplateCreate)
				r.Post("/{id}/deploy", h.ContainerTemplateDeploy)
				r.Post("/{id}/delete", h.ContainerTemplateDelete)
			})
		})

		// Maintenance Windows (admin only)
		r.Route("/maintenance", func(r chi.Router) {
			r.Use(m.AdminRequired)
			r.Get("/", h.MaintenanceTempl)
			r.Post("/", h.MaintenanceCreate)
			r.Post("/{id}/toggle", h.MaintenanceToggle)
			r.Post("/{id}/delete", h.MaintenanceDelete)
			r.Post("/{id}/execute", h.MaintenanceExecute)
		})

		// Compliance Policies (security & compliance) - requires security:view/scan
		r.Route("/compliance", func(r chi.Router) {
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("security:view"))
				r.Get("/", h.ComplianceTempl)
			})
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("security:scan"))
				r.Post("/policies", h.CompliancePolicyCreate)
				r.Post("/policies/{id}/toggle", h.CompliancePolicyToggle)
				r.Post("/policies/{id}/delete", h.CompliancePolicyDelete)
				r.Post("/scan", h.ComplianceScan)
				r.Post("/violations/{id}/acknowledge", h.ComplianceViolationAcknowledge)
				r.Post("/violations/{id}/resolve", h.ComplianceViolationResolve)
				r.Post("/violations/{id}/exempt", h.ComplianceViolationExempt)
			})
		})

		// Secret Management (admin only - highly sensitive)
		r.Route("/secrets", func(r chi.Router) {
			r.Use(m.AdminRequired)
			r.Get("/", h.SecretsTempl)
			r.Post("/", h.SecretCreate)
			r.Post("/{id}/delete", h.SecretDelete)
			r.Post("/{id}/rotate", h.SecretRotate)
		})

		// Vulnerability Management - requires security:view/scan
		r.Route("/vulnerabilities", func(r chi.Router) {
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("security:view"))
				r.Get("/", h.VulnMgmtTempl)
			})
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("security:scan"))
				r.Post("/scan", h.VulnScan)
				r.Post("/{id}/acknowledge", h.VulnAcknowledge)
				r.Post("/{id}/resolve", h.VulnResolve)
				r.Post("/{id}/accept", h.VulnAcceptRisk)
				r.Post("/{id}/assign", h.VulnAssign)
			})
		})

		// Vulnerability Management API — JSON endpoints for AJAX operations
		r.Route("/api/v1/vulnerabilities", func(r chi.Router) {
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("security:view"))
				r.Get("/dashboard", h.VulnDashboardAPI)
			})
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("security:scan"))
				r.Put("/{id}/assign", h.VulnAssignAPI)
				r.Put("/{id}/resolve", h.VulnResolveAPI)
			})
		})

		// Change Management Audit Trail (Phase 3 Enterprise)
		r.Route("/changes", func(r chi.Router) {
			r.Use(m.RequirePermission("audit:view"))
			r.Get("/", h.ChangesTempl)
			r.Get("/export/csv", h.ChangeExportCSV)
		})

		// Change Management API
		r.Route("/api/v1/changes", func(r chi.Router) {
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("audit:view"))
				r.Get("/", h.ChangeListAPI)
				r.Get("/stats", h.ChangeStatsAPI)
				r.Get("/{id}", h.ChangeDetailAPI)
				r.Get("/resource/{resourceType}/{resourceID}", h.ChangeResourceAPI)
			})
		})

		// Drift Detection (Phase 4 Enterprise)
		r.Route("/drift", func(r chi.Router) {
			r.Use(m.RequirePermission("audit:view"))
			r.Get("/", h.DriftTempl)
			r.Post("/{id}/accept", h.DriftAcceptAPI)
			r.Post("/{id}/remediate", h.DriftRemediateAPI)
		})

		// Drift Detection API
		r.Route("/api/v1/drift", func(r chi.Router) {
			r.Use(m.RequirePermission("audit:view"))
			r.Get("/", h.DriftTempl)
			r.Get("/stats", h.DriftStatsAPI)
			r.Get("/{id}", h.DriftDetailAPI)
		})

		// Resource Optimization (Phase 5 Enterprise)
		r.Route("/resource-optimization", func(r chi.Router) {
			r.Use(m.RequirePermission("audit:view"))
			r.Get("/", h.CostOptTempl)
			r.Post("/{id}/apply", h.CostOptApplyAPI)
			r.Post("/{id}/dismiss", h.CostOptDismissAPI)
		})

		// Resource Optimization API
		r.Route("/api/v1/resource-optimization", func(r chi.Router) {
			r.Use(m.RequirePermission("audit:view"))
			r.Get("/stats", h.CostOptStatsAPI)
		})

		// Access Control Audit (admin only)
		r.Route("/access-audit", func(r chi.Router) {
			r.Use(m.AdminRequired)
			r.Get("/", h.AccessAuditTempl)
			r.Post("/export", h.AccessAuditExport)
			r.Post("/sessions/{id}/revoke", h.AccessAuditSessionRevoke)
		})

		// Container Health Dashboard
		r.Group(func(r chi.Router) {
			r.Use(m.RequirePermission("container:view"))
			r.Get("/health-dashboard", h.HealthDashTempl)
		})

		// Bulk Operations (dedicated page) - requires container:start (container management)
		r.Route("/bulk-ops", func(r chi.Router) {
			r.Use(m.RequirePermission("container:view"))
			r.Get("/", h.BulkOpsTempl)
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("container:start"))
				r.Post("/action", h.BulkOpsAction)
			})
		})

		// Ports
		r.With(m.RequirePermission("container:view")).Get("/ports", h.PortsTempl)

		// Events
		r.With(m.RequirePermission("container:view")).Get("/events", h.EventsTempl)

		// Centralized Logs
		r.With(m.RequirePermission("container:view")).Get("/logs", h.LogsPageTempl)

		// Log Management (requires security:view)
		r.Route("/logs/management", func(r chi.Router) {
			r.Use(m.RequirePermission("security:view"))
			r.Get("/", h.LogManagement)
		})

		// Log Uploads (requires security:scan for mutations)
		r.Route("/logs/uploads", func(r chi.Router) {
			r.With(m.RequirePermission("security:view")).Get("/{id}", h.LogUploadAnalyze)
			r.Group(func(r chi.Router) {
				r.Use(m.RequirePermission("security:scan"))
				r.Post("/", h.LogUpload)
				r.Delete("/{id}", h.LogUploadDelete)
			})
		})

		// Log Search API
		r.With(m.RequirePermission("security:view")).Get("/api/logs/search", h.LogSearchAPI)

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
			r.Put("/preferences", h.UpdatePreferences)
			r.Put("/sidebar-prefs", h.UpdateSidebarPrefs)
			r.Post("/preferences/reset", h.ResetPreferences)
			r.Post("/theme", h.ToggleTheme)
			r.Post("/export", h.ExportUserData)
			r.Delete("/", h.DeleteAccount)
			r.Delete("/sessions", h.DeleteAllSessions)
			r.Delete("/sessions/{id}", h.DeleteSession)
		})

		// Admin routes
		r.Group(func(r chi.Router) {
			r.Use(m.AdminRequired)

			// Teams (optional service — gated by middleware)
			r.Route("/teams", func(r chi.Router) {
				r.Use(h.requireServiceMiddleware(
					func() bool { return h.services.Teams() != nil },
					"Teams", "Teams service is available when the application is fully initialized",
				))
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

			// Notification Channels (Admin, Business+ feature)
			r.Route("/admin/notifications", func(r chi.Router) {
				r.Use(h.requireFeature(license.FeatureMultiNotification))
				r.Get("/channels", h.NotificationChannelsTempl)
				r.Post("/channels", h.NotificationChannelCreate)
				r.Get("/channels/{name}/edit", h.NotificationChannelEditTempl)
				r.Post("/channels/{name}/delete", h.NotificationChannelDelete)
				r.Post("/channels/{name}/test", h.NotificationChannelTest)
			})

			// Roles (Admin, Business+ feature)
			r.Route("/admin/roles", func(r chi.Router) {
				r.Use(h.requireFeature(license.FeatureCustomRoles))
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
				// Registry browsing (Business+ feature)
				r.Group(func(r chi.Router) {
					r.Use(h.requireFeature(license.FeatureRegistryBrowsing))
					r.Get("/{id}/browse", h.RegistryBrowse)
					r.Get("/{id}/browse/repos/*", h.RegistryRepoTags)
					r.Get("/{id}/manifest", h.RegistryTagManifest)
				})
			})

			// Webhooks & Auto-Deploy (Admin)
			r.Route("/webhooks", func(r chi.Router) {
				r.Get("/", h.WebhooksTempl)
				r.Post("/", h.WebhookCreate)
				r.Post("/{id}/update", h.WebhookUpdate)
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
				r.Get("/scheduled", h.ScheduledJobsTempl)
				r.Post("/scheduled", h.ScheduledJobCreate)
				r.Post("/scheduled/{id}/delete", h.ScheduledJobDelete)
				r.Post("/scheduled/{id}/run", h.ScheduledJobRunNow)
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

		// About page (any authenticated user can view; backup/restore requires admin)
		r.Route("/about", func(r chi.Router) {
			r.Get("/", h.AboutTempl)
			r.With(m.AdminRequired).Post("/instance-backup", h.InstanceBackup)
			r.With(m.AdminRequired).Post("/instance-restore", h.InstanceRestore)
		})

		// WebSocket endpoints (with per-resource permissions)
		r.Route("/ws", func(r chi.Router) {
			r.Use(WebSocketRateLimit())
			r.With(m.RequirePermission("container:logs")).Get("/logs/{id}", h.WSContainerLogs)
			r.With(m.RequirePermission("container:exec")).Get("/exec/{id}", h.WSContainerExec)
			r.With(m.RequirePermission("container:view")).Get("/stats/{id}", h.WSContainerStats)
			r.With(m.RequirePermission("host:update")).Get("/host-exec/{id}", h.WSHostExec)
			r.With(m.RequirePermission("container:view")).Get("/events", h.WSEvents)
			r.With(m.RequirePermission("container:view")).Get("/jobs/{id}", h.WSJobProgress)
			r.With(m.RequirePermission("host:update")).Get("/capture/{id}", h.WSCapture)
			r.With(m.RequirePermission("container:view")).Get("/metrics", h.WSMetrics)
			r.With(m.RequirePermission("host:update")).Get("/editor/nvim", h.WSEditorNvim)
			r.With(m.RequirePermission("host:view")).Get("/monitoring/stats", h.WsMonitoringStats)
			r.With(m.RequirePermission("host:view")).Get("/monitoring/container/{id}", h.WsMonitoringContainer)
		})

		// Internal host filesystem browser endpoints (require nsenter).
		// Web layer mounts these under /hosts/{hostID}/fs/* so the
		// session-cookie + CSRF middleware applies. The previous mount
		// at /api/v1/hosts/{hostID}/* shadowed the JSON-API host CRUD
		// (chi's trie resolves the deeper Route() to this subtree),
		// silently breaking GET / PUT / DELETE /api/v1/hosts/{id} and
		// POST /api/v1/hosts/{id}/reconnect for any Bearer-token API
		// client. The fix mirrors PR #43's recon split: the canonical
		// JSON-API surface stays unchallenged under /api/v1/* and the
		// HTMX UI gets its own web-prefixed namespace.
		r.Route("/hosts/{hostID}/fs", func(r chi.Router) {
			r.Use(m.RequirePermission("host:update"))
			r.Get("/browse", h.APIHostBrowse)
			r.Get("/browse/*", h.APIHostBrowse)
			r.Get("/file/*", h.APIHostReadFile)
			r.Get("/download/*", h.APIHostDownloadFile)
			r.Post("/mkdir/*", h.APIHostMkdir)
			r.Delete("/file/*", h.APIHostDeleteFile)
		})

		// Terminal session history API (requires container:view — exposes session metadata)
		r.Route("/api/v1/terminal", func(r chi.Router) {
			r.Use(m.RequirePermission("container:view"))
			r.Get("/sessions", h.APITerminalSessionList)
			r.Get("/sessions/active", h.APITerminalSessionsActive)
			r.Get("/sessions/{id}", h.APITerminalSessionGet)
			r.Get("/sessions/target/{type}/{id}", h.APITerminalSessionsByTarget)
		})

		// ================================================================
		// Enterprise Feature Pages (HTML rendering)
		// ================================================================

		// OPA Policies page (Enterprise license)
		r.Group(func(r chi.Router) {
			r.Use(h.requireFeature(license.FeatureOPAPolicies))
			r.With(m.RequirePermission("security:view")).Get("/opa-policies", h.OPAPoliciesPageTempl)
		})

		// Runtime Security page (Enterprise license)
		r.Group(func(r chi.Router) {
			r.Use(h.requireFeature(license.FeatureRuntimeSecurity))
			r.With(m.RequirePermission("security:view")).Get("/runtime-security", h.RuntimeSecurityPageTempl)
		})

		// Image Signing page (Enterprise license)
		r.Group(func(r chi.Router) {
			r.Use(h.requireFeature(license.FeatureImageSigning))
			r.With(m.RequirePermission("image:view")).Get("/image-signing", h.ImageSigningPageTempl)
		})

		// Custom Dashboards page (Enterprise license)
		r.Group(func(r chi.Router) {
			r.Use(h.requireFeature(license.FeatureCustomDashboards))
			r.With(m.RequirePermission("host:view")).Get("/custom-dashboards", h.CustomDashboardsPageTempl)
		})

		// Git Sync page (Business+ license)
		r.Group(func(r chi.Router) {
			r.Use(h.requireFeature(license.FeatureGitSync))
			r.With(m.RequirePermission("stack:view")).Get("/git-sync", h.GitSyncPageTempl)
		})

		// Ephemeral Environments page (Enterprise license)
		r.Group(func(r chi.Router) {
			r.Use(h.requireFeature(license.FeatureEphemeralEnvs))
			r.With(m.RequirePermission("stack:view")).Get("/ephemeral-environments", h.EphemeralEnvsPageTempl)
		})

		// Manifest Builder page (Enterprise license)
		r.Group(func(r chi.Router) {
			r.Use(h.requireFeature(license.FeatureManifestBuilder))
			r.With(m.RequirePermission("stack:view")).Get("/manifest-builder", h.ManifestBuilderPageTempl)
		})

		// Compliance Frameworks page (Enterprise license)
		r.Group(func(r chi.Router) {
			r.Use(h.requireFeature(license.FeatureCompliance))
			r.With(m.RequirePermission("security:view")).Get("/compliance-frameworks", h.ComplianceFrameworksPageTempl)
		})

		// ================================================================
		// Enterprise Phase 2: Compliance, OPA, Logs, Image Signing, Runtime
		// ================================================================

		// Compliance frameworks (Enterprise license)
		r.Route("/api/v1/compliance", func(r chi.Router) {
			r.Use(h.requireFeature(license.FeatureCompliance))
			// Framework CRUD
			r.With(m.RequirePermission("security:view")).Get("/frameworks", h.ComplianceFrameworksTempl)
			r.With(m.RequirePermission("security:view")).Get("/frameworks/{id}/status", h.ComplianceFrameworkStatus)
			r.With(m.RequirePermission("security:view")).Get("/frameworks/{id}/controls", h.ComplianceFrameworkControls)
			r.With(m.RequirePermission("security:view")).Get("/frameworks/{id}/assessments", h.ComplianceFrameworkAssessments)
			r.With(m.RequirePermission("security:scan")).Post("/frameworks/{id}/assess", h.ComplianceFrameworkAssess)
			r.With(m.AdminRequired).Post("/frameworks/seed", h.ComplianceFrameworkSeed)
			// Controls
			r.With(m.RequirePermission("security:scan")).Put("/controls/{id}/status", h.ComplianceControlUpdateStatus)
			// Assessments & reports
			r.With(m.RequirePermission("security:view")).Get("/assessments/{assessmentId}/report", h.ComplianceFrameworkReport)
			r.With(m.RequirePermission("security:view")).Get("/assessments/{id}/evidence", h.ComplianceEvidenceList)
			r.With(m.RequirePermission("security:scan")).Post("/assessments/{id}/evidence", h.ComplianceEvidenceCreate)
		})

		// OPA policy engine (Enterprise license)
		r.Route("/api/v1/opa", func(r chi.Router) {
			r.Use(h.requireFeature(license.FeatureOPAPolicies))
			r.With(m.RequirePermission("security:view")).Get("/policies", h.OPAPoliciesJSON)
			r.With(m.RequirePermission("security:scan")).Post("/evaluate/container/{id}", h.OPAPolicyEvaluateContainer)
			r.With(m.AdminRequired).Post("/policies/seed", h.OPAPolicySeed)
		})

		// Log aggregation and search (Enterprise license)
		r.Route("/api/v1/logs", func(r chi.Router) {
			r.Use(h.requireFeature(license.FeatureLogAggregation))
			r.Use(m.RequirePermission("security:view"))
			r.Get("/search", h.LogSearchJSON)
			r.Get("/stats", h.LogStatsJSON)
		})

		// Image signing and verification (Enterprise license)
		r.Route("/api/v1/images/signing", func(r chi.Router) {
			r.Use(h.requireFeature(license.FeatureImageSigning))
			r.With(m.RequirePermission("image:view")).Get("/signatures", h.ImageSignaturesJSON)
			r.With(m.RequirePermission("image:view")).Get("/verify", h.ImageVerifyJSON)
			r.With(m.RequirePermission("image:view")).Get("/trust-policies", h.ImageTrustPoliciesJSON)
			r.With(m.AdminRequired).Post("/trust-policies/seed", h.ImageSignSeed)
		})

		// Runtime security (Enterprise license)
		r.Route("/api/v1/runtime-security", func(r chi.Router) {
			r.Use(h.requireFeature(license.FeatureRuntimeSecurity))
			r.With(m.RequirePermission("security:view")).Get("/events", h.RuntimeEventsJSON)
			r.With(m.RequirePermission("security:scan")).Post("/events/{id}/acknowledge", h.RuntimeEventAcknowledge)
			r.With(m.RequirePermission("security:view")).Get("/dashboard", h.RuntimeDashboardJSON)
			r.With(m.RequirePermission("security:view")).Get("/rules", h.RuntimeRulesJSON)
			r.With(m.AdminRequired).Post("/rules/seed", h.RuntimeSeedRules)
			r.With(m.RequirePermission("security:scan")).Post("/monitor", h.RuntimeMonitorAll)
		})

		// Dashboard layouts and widgets (Enterprise license)
		r.Route("/api/v1/dashboards", func(r chi.Router) {
			r.Use(h.requireFeature(license.FeatureCustomDashboards))
			r.Use(m.RequirePermission("host:view"))

			// Layouts
			r.Get("/layouts", h.DashboardLayoutsJSON)
			r.With(m.OperatorRequired).Post("/layouts", h.DashboardLayoutCreateJSON)
			r.Route("/layouts/{layoutID}", func(r chi.Router) {
				r.Get("/", h.DashboardLayoutGetJSON)
				r.With(m.OperatorRequired).Put("/", h.DashboardLayoutUpdateJSON)
				r.With(m.OperatorRequired).Delete("/", h.DashboardLayoutDeleteJSON)

				// Widgets within a layout
				r.Get("/widgets", h.DashboardWidgetsJSON)
				r.With(m.OperatorRequired).Post("/widgets", h.DashboardWidgetCreateJSON)
			})

			// Widget direct operations
			r.Route("/widgets/{widgetID}", func(r chi.Router) {
				r.Use(m.OperatorRequired)
				r.Put("/", h.DashboardWidgetUpdateJSON)
				r.Delete("/", h.DashboardWidgetDeleteJSON)
			})
		})

		// ================================================================
		// Phase 3: Market Expansion - GitOps
		// ================================================================

		// Bidirectional Git Sync
		r.Route("/api/v1/git-sync", func(r chi.Router) {
			r.Use(h.requireFeature(license.FeatureGitSync))
			r.Use(m.RequirePermission("stack:view"))
			r.Get("/configs", h.GitSyncConfigsJSON)
			r.With(m.OperatorRequired).Post("/configs", h.GitSyncConfigCreate)
			r.Get("/configs/{id}", h.GitSyncConfigGet)
			r.With(m.OperatorRequired).Delete("/configs/{id}", h.GitSyncConfigDelete)
			r.With(m.OperatorRequired).Post("/configs/{id}/toggle", h.GitSyncConfigToggle)
			r.With(m.OperatorRequired).Post("/configs/{id}/trigger", h.GitSyncTrigger)
			r.Get("/configs/{id}/events", h.GitSyncEventsJSON)
			r.Get("/configs/{id}/conflicts", h.GitSyncConflictsJSON)
			r.With(m.OperatorRequired).Post("/conflicts/{conflictId}/resolve", h.GitSyncConflictResolve)
			r.Get("/stats", h.GitSyncStatsJSON)
		})

		// Branch-based Ephemeral Environments
		r.Route("/api/v1/ephemeral", func(r chi.Router) {
			r.Use(h.requireFeature(license.FeatureEphemeralEnvs))
			r.Use(m.RequirePermission("container:view"))
			r.Get("/environments", h.EphemeralEnvsJSON)
			r.With(m.OperatorRequired).Post("/environments", h.EphemeralEnvCreate)
			r.Get("/environments/{id}", h.EphemeralEnvGet)
			r.With(m.OperatorRequired).Post("/environments/{id}/provision", h.EphemeralEnvProvision)
			r.With(m.OperatorRequired).Post("/environments/{id}/stop", h.EphemeralEnvStop)
			r.With(m.OperatorRequired).Delete("/environments/{id}", h.EphemeralEnvDestroy)
			r.With(m.OperatorRequired).Post("/environments/{id}/extend", h.EphemeralEnvExtendTTL)
			r.Get("/environments/{id}/logs", h.EphemeralEnvLogsJSON)
			r.Get("/dashboard", h.EphemeralEnvDashboardJSON)
		})

		// Visual GitOps Manifest Builder
		r.Route("/api/v1/manifests", func(r chi.Router) {
			r.Use(h.requireFeature(license.FeatureManifestBuilder))
			r.Use(m.RequirePermission("stack:view"))
			// Templates
			r.Get("/templates", h.ManifestTemplatesJSON)
			r.With(m.OperatorRequired).Post("/templates", h.ManifestTemplateCreate)
			r.Get("/templates/categories", h.ManifestTemplateCategoriesJSON)
			r.Get("/templates/{id}", h.ManifestTemplateGet)
			r.With(m.OperatorRequired).Delete("/templates/{id}", h.ManifestTemplateDelete)
			r.With(m.OperatorRequired).Post("/templates/{id}/render", h.ManifestTemplateRender)
			// Builder sessions
			r.Get("/sessions", h.ManifestSessionsJSON)
			r.With(m.OperatorRequired).Post("/sessions", h.ManifestSessionCreate)
			r.Get("/sessions/{id}", h.ManifestSessionGet)
			r.With(m.OperatorRequired).Put("/sessions/{id}", h.ManifestSessionUpdate)
			r.With(m.OperatorRequired).Delete("/sessions/{id}", h.ManifestSessionDelete)
			r.With(m.OperatorRequired).Post("/sessions/{id}/save", h.ManifestSessionSave)
			// Generation & validation
			r.With(m.OperatorRequired).Post("/generate", h.ManifestGenerateJSON)
			r.With(m.OperatorRequired).Post("/validate", h.ManifestValidateJSON)
			// Component library
			r.Get("/components", h.ManifestComponentsJSON)
			// Seed data
			r.With(m.AdminRequired).Post("/seed", h.ManifestSeedJSON)
		})

		// HTMX Partials — canonical prefix for all partial/fragment endpoints.
		// Monitoring partials moved here from /monitoring/* (INT-DTO-L1).
		r.Route("/partials", func(r chi.Router) {
			r.With(m.RequirePermission("container:view")).Get("/stats", h.StatsPartial)
			r.Get("/notifications", h.NotificationsPartialTempl)
			r.With(m.RequirePermission("container:view")).Get("/search", h.SearchPartialTempl)

			// Container/image/event partials require appropriate permissions
			r.With(m.RequirePermission("container:view")).Get("/containers", h.ContainersPartialTempl)
			r.With(m.RequirePermission("container:view")).Get("/container/{id}", h.ContainerRowPartial)
			r.With(m.RequirePermission("image:view")).Get("/images", h.ImagesPartial)
			r.With(m.RequirePermission("container:view")).Get("/events", h.EventsPartialTempl)

			// Monitoring partials (moved from /monitoring/*)
			r.Route("/monitoring", func(r chi.Router) {
				r.Use(m.RequirePermission("host:view"))
				r.Get("/host", h.MonitoringHostPartial)
				r.Get("/containers", h.MonitoringContainersPartial)
				r.Get("/history", h.MonitoringHistoryJSON)
			})
		})

		// Privacy & Recon (v26.5.0). Routes self-disable when the recon
		// feature flag is off; see internal/web/routes_recon.go.
		RegisterReconRoutes(r, h, m)
	})
	}) // end r.Group wrapper
}

// redirect301 returns a handler that issues a permanent redirect to the target path.
// Used for backward-compatible URL migration (e.g., moving HTMX partials).
func redirect301(target string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	}
}
