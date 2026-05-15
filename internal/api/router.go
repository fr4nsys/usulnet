// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/api/handlers"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
)

// RouterConfig contains configuration for setting up routes.
type RouterConfig struct {
	// JWTSecret is the secret for JWT token validation.
	JWTSecret string

	// CORSConfig is the CORS configuration.
	CORSConfig middleware.CORSConfig

	// RateLimitPerMinute is the rate limit for API requests.
	RateLimitPerMinute int

	// RequestTimeout is the timeout for HTTP requests.
	RequestTimeout time.Duration

	// LicenseProvider provides license information.
	LicenseProvider middleware.LicenseProvider

	// Logger for request logging.
	Logger middleware.RequestLogger

	// EnableDebugLogging enables verbose request logging.
	EnableDebugLogging bool

	// APIKeyAuth is an optional authenticator for API key-based authentication.
	APIKeyAuth middleware.APIKeyAuthenticator

	// MetricsEnabled controls whether the /metrics endpoint is registered.
	MetricsEnabled bool

	// MetricsPath is the URL path for the Prometheus metrics endpoint (default "/metrics").
	MetricsPath string

	// TokenValidator is an optional function for additional JWT validation
	// (e.g., checking if a token has been revoked via the Redis blacklist).
	TokenValidator middleware.TokenValidatorFunc

	// ReconEnabled toggles the recon / metadata route subtree. When
	// false, all /api/v1/recon/* and /api/v1/metadata/* requests
	// short-circuit with a 404 (module_disabled). See
	// docs/recon.md §7.4 and docs/v26.5/technical-notes.md.
	ReconEnabled bool

	// ReconAckChecker is consulted by the acknowledgement middleware
	// before any recon/metadata request is served. It is nil-safe:
	// a nil checker means "not acknowledged yet" and every gated
	// route returns 409 acknowledgement_required.
	ReconAckChecker middleware.ReconAckChecker
}

// DefaultRouterConfig returns a default router configuration.
func DefaultRouterConfig(jwtSecret string) RouterConfig {
	return RouterConfig{
		JWTSecret:          jwtSecret,
		CORSConfig:         middleware.DefaultCORSConfig(),
		RateLimitPerMinute: 100,
		RequestTimeout:     30 * time.Second,
		LicenseProvider:    nil, // Set by app.go with license.NewProvider()
		EnableDebugLogging: false,
		MetricsEnabled:     true,
		MetricsPath:        "/metrics",
	}
}

// Handlers contains all API handlers.
// All fields are optional - if nil, the corresponding routes won't be mounted.
type Handlers struct {
	System         *handlers.SystemHandler
	WebSocket      *handlers.WebSocketHandler
	Auth           *handlers.AuthHandler
	Container      *handlers.ContainerHandler
	Image          *handlers.ImageHandler
	Volume         *handlers.VolumeHandler
	Network        *handlers.NetworkHandler
	Stack          *handlers.StackHandler
	Host           *handlers.HostHandler
	User           *handlers.UserHandler
	Backup         *handlers.BackupHandler
	Security       *handlers.SecurityHandler
	Config         *handlers.ConfigHandler
	Update         *handlers.UpdateHandler
	Job            *handlers.JobsHandler
	Notification   *handlers.NotificationHandler
	Audit          *handlers.AuditHandler
	PasswordReset  *handlers.PasswordResetHandler
	Proxy          *handlers.ProxyHandler
	ProxyExtended  *handlers.ExtendedProxyHandler
	NPM            *handlers.NPMHandler
	SSH            *handlers.SSHHandler
	OpenAPI        *handlers.OpenAPIHandler
	Settings       *handlers.SettingsHandler
	License        *handlers.LicenseHandler
	Registry       *handlers.RegistryHandler
	Recon          *handlers.ReconHandler
	Metadata       *handlers.MetadataHandler
	Firewall       *handlers.FirewallHandler
	Crontab        *handlers.CrontabHandler
	BackupVerify   *handlers.BackupVerifyHandler
	Rollback       *handlers.RollbackHandler
	SSLObservatory *handlers.SSLObservatoryHandler
	DockerEngine   *handlers.DockerEngineHandler
	WireGuard      *handlers.WireGuardHandler
	ImageBuilder   *handlers.ImageBuilderHandler
	DNS            *handlers.DNSHandler
	Calendar       *handlers.CalendarHandler
	Marketplace    *handlers.MarketplaceHandler
}

// NewRouter creates a new chi router with all routes configured.
func NewRouter(config RouterConfig, h *Handlers) chi.Router {
	r := chi.NewRouter()

	// Apply configurable API rate limit globally.
	middleware.SetAPIRateLimitPerMinute(config.RateLimitPerMinute)

	// =========================================================================
	// Global Middleware (applied to all routes)
	// =========================================================================

	// Request ID (must be first)
	r.Use(middleware.RequestID)

	// Real IP extraction from proxy headers
	r.Use(middleware.RealIP)

	// Request logging
	if config.Logger != nil {
		if config.EnableDebugLogging {
			r.Use(middleware.DebugLogging(config.Logger))
		} else {
			r.Use(middleware.SimpleLogging(config.Logger))
		}
	}

	// Panic recovery
	r.Use(middleware.Recovery(middleware.RecoveryConfig{
		Logger:     config.Logger,
		PrintStack: true,
	}))

	// NOTE: chimiddleware.Timeout is NOT applied globally because it wraps
	// the ResponseWriter and removes http.Hijacker, breaking WebSocket upgrades.
	// Timeout is applied selectively to API routes below.

	// CORS
	r.Use(middleware.CORS(config.CORSConfig))

	// License context
	if config.LicenseProvider != nil {
		r.Use(middleware.License(middleware.LicenseConfig{
			Provider:     config.LicenseProvider,
			AddToContext: true,
		}))
	}

	// =========================================================================
	// Health Check Routes (no auth required)
	// =========================================================================

	if h.System != nil {
		r.Get("/health", h.System.Health)
		r.Get("/healthz", h.System.Liveness)
		r.Get("/ready", h.System.Readiness)
	}

	// OpenAPI specification (public)
	if h.OpenAPI != nil {
		r.Get("/api/v1/openapi.json", h.OpenAPI.Spec)
		r.Get("/api/docs", h.OpenAPI.Spec)
	}

	// =========================================================================
	// API Routes
	// =========================================================================

	r.Route("/api/v1", func(r chi.Router) {
		// Apply timeout only to API routes (not globally, to preserve http.Hijacker for WebSocket)
		r.Use(chimiddleware.Timeout(config.RequestTimeout))

		// -----------------------------------------------------------------
		// Public routes (no authentication)
		// -----------------------------------------------------------------
		r.Group(func(r chi.Router) {
			r.Use(middleware.AuthRateLimit())

			// Auth endpoints (login, refresh, logout are public;
			// handler applies RequireAuth internally for protected routes)
			if h.Auth != nil {
				r.Mount("/auth", h.Auth.Routes())
			}

			// Password reset endpoints (public)
			if h.PasswordReset != nil {
				r.Mount("/password-reset", h.PasswordReset.Routes())
			}

			// Public webhook trigger (auth via token in URL)
			if h.Update != nil {
				r.Post("/webhooks/update/{token}", h.Update.TriggerWebhook)
			}

			// Public version endpoint (no auth) — standard discovery surface,
			// matches /health/healthz and the public OpenAPI spec.
			if h.System != nil {
				r.Get("/system/version", h.System.Version)
			}
		})

		// -----------------------------------------------------------------
		// Authenticated routes
		// -----------------------------------------------------------------
		r.Group(func(r chi.Router) {
			// JWT + API Key Authentication
			r.Use(middleware.Auth(middleware.AuthConfig{
				Secret:         config.JWTSecret,
				TokenLookup:    "header:Authorization,query:token,cookie:auth_token",
				APIKeyAuth:     config.APIKeyAuth,
				TokenValidator: config.TokenValidator,
			}))

			// Standard API rate limiting
			r.Use(middleware.APIRateLimit())

			// =============================================================
			// System routes (viewer+)
			// =============================================================
			if h.System != nil {
				r.Route("/system", func(r chi.Router) {
					r.Use(middleware.RequireViewer)
					r.Get("/info", h.System.Info)
					r.Get("/health", h.System.Health)
					r.Get("/metrics", h.System.Metrics)
				})
			}

			// =============================================================
			// Docker resource routes (viewer+ at router level)
			//
			// Read routes are viewer+. Each handler enforces operator+
			// or admin+ on mutations internally via its own Routes().
			// =============================================================
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireViewer)

				if h.Container != nil {
					r.Mount("/containers", h.Container.Routes())
				}
				if h.Image != nil {
					r.Mount("/images", h.Image.Routes())
				}
				if h.Volume != nil {
					r.Mount("/volumes", h.Volume.Routes())
				}
				if h.Network != nil {
					r.Mount("/networks", h.Network.Routes())
				}
				if h.Stack != nil {
					r.Mount("/stacks", h.Stack.Routes())
				}
				if h.Host != nil {
					r.Mount("/hosts", h.Host.Routes())
				}
				if h.Backup != nil {
					r.Mount("/backups", h.Backup.Routes())
				}
				if h.Security != nil {
					r.Mount("/security", h.Security.Routes())
				}
				if h.Config != nil {
					r.Mount("/config", h.Config.Routes())
				}
				if h.Update != nil {
					r.Mount("/updates", h.Update.Routes())
				}
				if h.Job != nil {
					r.Mount("/jobs", h.Job.Routes())
				}
				if h.Notification != nil {
					r.Mount("/notifications", h.Notification.Routes())
				}
				if h.SSH != nil {
					r.Mount("/ssh", h.SSH.Routes())
				}
				if h.Registry != nil {
					r.Mount("/registries", h.Registry.Routes())
				}
			})

			// =============================================================
			// Proxy routes (viewer+ for viewing, operator+ for changes)
			// =============================================================
			if h.Proxy != nil {
				r.Route("/proxy", func(r chi.Router) {
					r.Use(middleware.RequireViewer)

					// Health & Status (viewer+)
					r.Get("/health", h.Proxy.GetHealth)
					r.Get("/upstreams", h.Proxy.GetUpstreamStatus)

					// Proxy Hosts
					r.Route("/hosts", func(r chi.Router) {
						r.Get("/", h.Proxy.ListHosts)
						r.Get("/{id}", h.Proxy.GetHost)

						// Operator+ for mutations
						r.Group(func(r chi.Router) {
							r.Use(middleware.RequireOperator)
							r.Post("/", h.Proxy.CreateHost)
							r.Put("/{id}", h.Proxy.UpdateHost)
							r.Delete("/{id}", h.Proxy.DeleteHost)
							r.Post("/{id}/enable", h.Proxy.EnableHost)
							r.Post("/{id}/disable", h.Proxy.DisableHost)
							r.Put("/{id}/headers", h.Proxy.SetHeaders)
						})
					})

					// Certificates
					r.Route("/certificates", func(r chi.Router) {
						r.Get("/", h.Proxy.ListCertificates)
						r.Group(func(r chi.Router) {
							r.Use(middleware.RequireOperator)
							r.Post("/", h.Proxy.UploadCertificate)
							r.Delete("/{id}", h.Proxy.DeleteCertificate)
						})
					})

					// DNS Providers
					r.Route("/dns-providers", func(r chi.Router) {
						r.Get("/", h.Proxy.ListDNSProviders)
						r.Get("/supported", h.Proxy.GetSupportedDNSProviders)
						r.Group(func(r chi.Router) {
							r.Use(middleware.RequireOperator)
							r.Post("/", h.Proxy.CreateDNSProvider)
							r.Delete("/{id}", h.Proxy.DeleteDNSProvider)
						})
					})

					// Sync & Audit (operator+)
					r.Group(func(r chi.Router) {
						r.Use(middleware.RequireOperator)
						r.Post("/sync", h.Proxy.SyncToCaddy)
						r.Get("/audit-logs", h.Proxy.ListAuditLogs)
					})

					// =========================================================
					// Extended proxy routes (v26.5.1 — ported from v26.2.7).
					// Access lists, dead hosts, locations, redirections,
					// streams. Streams against Caddy return 422 with a
					// clear "feature not supported" payload.
					// =========================================================
					if h.ProxyExtended != nil {
						r.Get("/support", h.ProxyExtended.GetSupportMatrix)

						// Access lists
						r.Route("/access-lists", func(r chi.Router) {
							r.Get("/", h.ProxyExtended.ListAccessLists)
							r.Get("/{id}", h.ProxyExtended.GetAccessList)
							r.Group(func(r chi.Router) {
								r.Use(middleware.RequireOperator)
								r.Post("/", h.ProxyExtended.CreateAccessList)
								r.Put("/{id}", h.ProxyExtended.UpdateAccessList)
								r.Delete("/{id}", h.ProxyExtended.DeleteAccessList)
							})
						})

						// Dead hosts (404 catch-alls)
						r.Route("/dead-hosts", func(r chi.Router) {
							r.Get("/", h.ProxyExtended.ListDeadHosts)
							r.Group(func(r chi.Router) {
								r.Use(middleware.RequireOperator)
								r.Post("/", h.ProxyExtended.CreateDeadHost)
								r.Delete("/{id}", h.ProxyExtended.DeleteDeadHost)
							})
						})

						// Locations (per-host path routes)
						r.Route("/hosts/{id}/locations", func(r chi.Router) {
							r.Get("/", h.ProxyExtended.ListLocations)
							r.Group(func(r chi.Router) {
								r.Use(middleware.RequireOperator)
								r.Put("/", h.ProxyExtended.SetLocations)
							})
						})

						// Redirections
						r.Route("/redirections", func(r chi.Router) {
							r.Get("/", h.ProxyExtended.ListRedirections)
							r.Group(func(r chi.Router) {
								r.Use(middleware.RequireOperator)
								r.Post("/", h.ProxyExtended.CreateRedirection)
								r.Put("/{id}", h.ProxyExtended.UpdateRedirection)
								r.Delete("/{id}", h.ProxyExtended.DeleteRedirection)
							})
						})

						// Streams (TCP/UDP — 422 against Caddy)
						r.Route("/streams", func(r chi.Router) {
							r.Get("/", h.ProxyExtended.ListStreams)
							r.Group(func(r chi.Router) {
								r.Use(middleware.RequireOperator)
								r.Post("/", h.ProxyExtended.CreateStream)
								r.Put("/{id}", h.ProxyExtended.UpdateStream)
								r.Delete("/{id}", h.ProxyExtended.DeleteStream)
							})
						})
					}
				})
			}

			// NPM routes (for Nginx Proxy Manager integration)
			if h.NPM != nil {
				r.Route("/npm", func(r chi.Router) {
					r.Use(middleware.RequireViewer)

					// Connection Management
					r.Route("/connections", func(r chi.Router) {
						r.Get("/{hostID}", h.NPM.GetConnection)
						r.Post("/{hostID}/test", h.NPM.TestConnection)

						r.Group(func(r chi.Router) {
							r.Use(middleware.RequireOperator)
							r.Post("/", h.NPM.ConfigureConnection)
							r.Put("/{id}", h.NPM.UpdateConnection)
							r.Delete("/{id}", h.NPM.DeleteConnection)
						})
					})

					// NPM Resources (per host)
					r.Route("/{hostID}", func(r chi.Router) {
						// Proxy Hosts
						r.Get("/proxy-hosts", h.NPM.ListProxyHosts)
						r.Get("/proxy-hosts/{proxyID}", h.NPM.GetProxyHost)
						r.Group(func(r chi.Router) {
							r.Use(middleware.RequireOperator)
							r.Post("/proxy-hosts", h.NPM.CreateProxyHost)
							r.Put("/proxy-hosts/{proxyID}", h.NPM.UpdateProxyHost)
							r.Delete("/proxy-hosts/{proxyID}", h.NPM.DeleteProxyHost)
							r.Post("/proxy-hosts/{proxyID}/enable", h.NPM.EnableProxyHost)
							r.Post("/proxy-hosts/{proxyID}/disable", h.NPM.DisableProxyHost)
						})

						// Certificates
						r.Get("/certificates", h.NPM.ListCertificates)
						r.Group(func(r chi.Router) {
							r.Use(middleware.RequireOperator)
							r.Post("/certificates/letsencrypt", h.NPM.RequestLetsEncryptCertificate)
							r.Delete("/certificates/{certID}", h.NPM.DeleteCertificate)
						})

						// Redirections
						r.Get("/redirections", h.NPM.ListRedirections)
						r.Group(func(r chi.Router) {
							r.Use(middleware.RequireOperator)
							r.Post("/redirections", h.NPM.CreateRedirection)
							r.Delete("/redirections/{redirID}", h.NPM.DeleteRedirection)
						})

						// Access Lists
						r.Get("/access-lists", h.NPM.ListAccessLists)
						r.Group(func(r chi.Router) {
							r.Use(middleware.RequireOperator)
							r.Post("/access-lists", h.NPM.CreateAccessList)
							r.Delete("/access-lists/{listID}", h.NPM.DeleteAccessList)
						})

						// Audit Logs
						r.Get("/audit-logs", h.NPM.ListAuditLogs)
					})
				})
			}

			// =============================================================
			// Firewall (v26.5.1 — ported from v26.2.7 as AGPL feature)
			//
			// The handler's Routes() enforces per-method RBAC: read
			// endpoints viewer+, mutations operator+, apply/sync admin.
			// Mounted at the top level (authenticated, no recon gate).
			// =============================================================
			if h.Firewall != nil {
				r.Mount("/firewall", h.Firewall.Routes())
			}

			// =============================================================
			// Crontab (v26.5.1 — ported from v26.2.7 as AGPL feature)
			//
			// REST CRUD for entries, paginated /executions, and a
			// WebSocket tail at /executions/tail. Per-method RBAC is
			// enforced inside the handler's Routes(): read viewer+,
			// mutations and run-now operator+.
			// =============================================================
			if h.Crontab != nil {
				r.Mount("/crontab", h.Crontab.Routes())
			}

			// =============================================================
			// Backup verification (v26.5.1 — ported from v26.2.7 as AGPL)
			//
			// REST: GET /runs, GET /runs/{id}, POST /run/{backup_id},
			// GET /backups/{backup_id}/runs, GET /stats, schedule CRUD.
			// Per-method RBAC inside Routes(): read viewer+, mutations
			// operator+.
			// =============================================================
			if h.BackupVerify != nil {
				r.Mount("/backup-verify", h.BackupVerify.Routes())
			}

			// =============================================================
			// Rollback (v26.5.1 — ported from v26.2.7 as AGPL feature)
			//
			// REST CRUD for policies, paginated /executions and /audit,
			// and a POST /policies/{id}/dry-run endpoint that previews
			// a fire without touching the live stack. Per-method RBAC
			// is enforced inside the handler's Routes(): read viewer+,
			// mutations and dry-run operator+.
			// =============================================================
			if h.Rollback != nil {
				r.Mount("/rollback", h.Rollback.Routes())
			}

			// =============================================================
			// SSL Observatory (v26.5.1 — ported from v26.2.7 as AGPL)
			//
			// REST CRUD for targets, paginated /scans, manual scan
			// trigger, and aggregate /stats + /expiring queries. The
			// handler's Routes() enforces per-method RBAC: read endpoints
			// viewer+, mutations operator+.
			// =============================================================
			if h.SSLObservatory != nil {
				r.Mount("/ssl", h.SSLObservatory.Routes())
			}

			// =============================================================
			// Docker engine config (v26.5.1 — ported from v26.2.7 as AGPL)
			//
			// REST: GET /config, PUT /config (validates → snapshots →
			// atomic write → SIGHUP → verify → rollback on failure),
			// GET /config/history, POST /config/restore/{snapshot_id}.
			// Per-method RBAC inside Routes(): read viewer+, mutations
			// admin (touches host daemon).
			// =============================================================
			if h.DockerEngine != nil {
				r.Mount("/docker-engine", h.DockerEngine.Routes())
			}

			// =============================================================
			// WireGuard mesh (v26.5.1 — ported from v26.2.7 as AGPL)
			//
			// REST: GET/POST/DELETE interfaces, GET/POST/DELETE peers,
			// one-time GET /peers/{id}/qr?token=… (5 min TTL), and a
			// mesh-link status feed at /mesh. Per-method RBAC inside
			// Routes(): read viewer+, mutations operator+, mesh push
			// admin (touches remote agents).
			// =============================================================
			if h.WireGuard != nil {
				r.Mount("/wireguard", h.WireGuard.Routes())
			}

			// =============================================================
			// Image Builder (v26.5.1 — ported from v26.2.7 as AGPL feature)
			//
			// REST: GET /builds, POST /builds, GET /builds/{id}, GET
			// /builds/{id}/log (WebSocket OR SSE), GET/POST/DELETE
			// /build-templates. Per-method RBAC inside Routes(): read
			// viewer+, mutations operator+. Live build logs come through
			// the redis pub/sub channel — see imagebuilder.LogChannel.
			// =============================================================
			if h.ImageBuilder != nil {
				r.Mount("/builds", h.ImageBuilder.Routes())
				r.Mount("/build-templates", h.ImageBuilder.TemplateRoutes())
			}

			// =============================================================
			// DNS provider plugins (v26.5.1 — session-10).
			//
			// Replaces the proxy module's ad-hoc DNS surface with a
			// dedicated subtree that hosts provider CRUD, record
			// management, ACME DNS-01 orders, and the capability
			// matrix. Same nil-safe pattern: when the encryptor is
			// unavailable, h.DNS is nil and the subtree is skipped;
			// every endpoint inside the handler also short-circuits
			// to 503 so the route mounting code stays simple.
			// =============================================================
			if h.DNS != nil {
				r.Mount("/dns", h.DNS.Routes())
			}

			// =============================================================
			// Calendar (v26.5.1 — ported from v26.2.7 as AGPL feature,
			// session-11)
			//
			// REST: GET /events?from=…&to=…, POST /events (manual entry),
			// GET/PUT/DELETE /events/{id}, GET /stats, GET /sources,
			// and GET /export.ics (RFC 5545). Read endpoints are
			// viewer+, mutations operator+.
			// =============================================================
			if h.Calendar != nil {
				r.Mount("/calendar", h.Calendar.Routes())
			}

			// =============================================================
			// Marketplace (v26.5.1 — ported from v26.2.7 as AGPL feature,
			// session-12). REST: GET /apps, GET /featured, GET /apps/{slug},
			// POST /apps/{slug}/install, GET /apps/{slug}/reviews,
			// GET /installations, GET/POST /installations/{id}/uninstall,
			// POST /reviews. Read endpoints viewer+, installs + reviews
			// operator+. Offline-first: zero outbound calls at runtime.
			// =============================================================
			if h.Marketplace != nil {
				r.Mount("/marketplace", h.Marketplace.Routes())
			}

			// =============================================================
			// Recon / metadata (v26.5.0)
			//
			// Chain: auth (above) -> feature flag -> acknowledgement
			// -> RBAC (per-route, inside each handler's Routes()).
			// The /_ack endpoint is mounted on a sibling branch that
			// skips the acknowledgement middleware so an admin can
			// record consent without first satisfying it.
			// =============================================================
			r.Group(func(r chi.Router) {
				r.Use(middleware.ReconFeatureFlag(config.ReconEnabled))

				// Acknowledgement endpoint — admin-only, no ack
				// middleware. Registered as an explicit route so we
				// can keep the mounted subtree (which would otherwise
				// claim the same /recon prefix) inside the gated
				// group below.
				if h.Recon != nil {
					r.With(middleware.RequireAdmin).Post("/recon/_ack", h.Recon.Acknowledge)
				}

				// Gated subtree: every recon/metadata route below
				// requires the legal-notice acknowledgement.
				r.Group(func(r chi.Router) {
					r.Use(middleware.ReconAcknowledgement(config.ReconAckChecker))
					if h.Recon != nil {
						r.Mount("/recon", h.Recon.Routes())
					}
					if h.Metadata != nil {
						r.Mount("/metadata", h.Metadata.Routes())
					}
				})
			})

			// =============================================================
			// Admin-only routes
			// =============================================================
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireAdmin)

				if h.User != nil {
					r.Mount("/users", h.User.Routes())
				}
				if h.Audit != nil {
					r.Mount("/audit", h.Audit.Routes())
				}

				// Settings (admin-only)
				if h.Settings != nil {
					h.Settings.SetLicenseProvider(config.LicenseProvider)
					r.Mount("/settings", h.Settings.Routes())
				} else {
					// Fallback placeholders if handler not initialized
					r.Route("/settings", func(r chi.Router) {
						r.Get("/", notImplemented)
						r.Put("/", notImplemented)
						r.Route("/ldap", func(r chi.Router) {
							r.Get("/", notImplemented)
							r.Put("/", notImplemented)
							r.Post("/test", notImplemented)
						})
					})
				}

				// License (admin-only)
				if h.License != nil {
					r.Mount("/license", h.License.Routes())
				} else {
					r.Route("/license", func(r chi.Router) {
						r.Get("/", notImplemented)
						r.Post("/", notImplemented)
						r.Delete("/", notImplemented)
					})
				}
			})
		})
	})

	// =========================================================================
	// API WebSocket routes (at /api/v1/ws, outside timeout to preserve http.Hijacker)
	// Note: Frontend WebSocket routes are at /ws (registered by routes_frontend.go)
	// Auth is applied here but timeout is NOT (to preserve http.Hijacker for WS upgrade).
	// =========================================================================
	if h.WebSocket != nil {
		r.Route("/api/v1/ws", func(r chi.Router) {
			// Apply authentication to WebSocket routes
			r.Use(middleware.Auth(middleware.AuthConfig{
				Secret:         config.JWTSecret,
				TokenLookup:    "header:Authorization,query:token,cookie:auth_token",
				APIKeyAuth:     config.APIKeyAuth,
				TokenValidator: config.TokenValidator,
			}))
			r.Use(middleware.RequireViewer)
			r.Use(middleware.WebSocketRateLimit())
			r.Mount("/", h.WebSocket.Routes())
		})
	}

	// =========================================================================
	// Prometheus metrics — behind admin auth
	// The authenticated endpoint at /api/v1/system/metrics (viewer+) also
	// serves metrics. This top-level endpoint requires admin for Prometheus
	// scrapers (configure bearer_token in scrape config).
	// =========================================================================
	if h.System != nil && config.MetricsEnabled {
		metricsPath := config.MetricsPath
		if metricsPath == "" {
			metricsPath = "/metrics"
		}
		r.Group(func(r chi.Router) {
			r.Use(middleware.Auth(middleware.AuthConfig{
				Secret:         config.JWTSecret,
				TokenLookup:    "header:Authorization,query:token",
				APIKeyAuth:     config.APIKeyAuth,
				TokenValidator: config.TokenValidator,
			}))
			r.Use(middleware.RequireAdmin)
			r.Get(metricsPath, h.System.Metrics)
		})
	}

	return r
}

// notImplemented is a placeholder handler for routes not yet implemented.
func notImplemented(w http.ResponseWriter, r *http.Request) {
	apierrors.WriteError(w, apierrors.NotImplemented(""))
}
