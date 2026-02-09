// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/fr4nsys/usulnet/internal/api/handlers"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/license"
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
	}
}

// Handlers contains all API handlers.
// All fields are optional - if nil, the corresponding routes won't be mounted.
type Handlers struct {
	System        *handlers.SystemHandler
	WebSocket     *handlers.WebSocketHandler
	Auth          *handlers.AuthHandler
	Container     *handlers.ContainerHandler
	Image         *handlers.ImageHandler
	Volume        *handlers.VolumeHandler
	Network       *handlers.NetworkHandler
	Stack         *handlers.StackHandler
	Host          *handlers.HostHandler
	User          *handlers.UserHandler
	Backup        *handlers.BackupHandler
	Security      *handlers.SecurityHandler
	Config        *handlers.ConfigHandler
	Update        *handlers.UpdateHandler
	Job           *handlers.JobsHandler
	Notification  *handlers.NotificationHandler
	Audit         *handlers.AuditHandler
	PasswordReset *handlers.PasswordResetHandler
	Proxy         *handlers.ProxyHandler
	NPM           *handlers.NPMHandler
	SSH           *handlers.SSHHandler
	OpenAPI       *handlers.OpenAPIHandler
}

// NewRouter creates a new chi router with all routes configured.
func NewRouter(config RouterConfig, h *Handlers) chi.Router {
	r := chi.NewRouter()

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

			// Public system info
			if h.System != nil {
				r.Get("/system/version", h.System.Version)
			}

			// Public webhook trigger (auth via token in URL)
			if h.Update != nil {
				r.Post("/webhooks/update/{token}", h.Update.TriggerWebhook)
			}
		})

		// -----------------------------------------------------------------
		// Authenticated routes
		// -----------------------------------------------------------------
		r.Group(func(r chi.Router) {
			// JWT + API Key Authentication
			r.Use(middleware.Auth(middleware.AuthConfig{
				Secret:      config.JWTSecret,
				TokenLookup: "header:Authorization,query:token,cookie:auth_token",
				APIKeyAuth:  config.APIKeyAuth,
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
			// Docker resource routes (viewer+)
			//
			// All authenticated users can access reads. Handlers may
			// enforce finer-grained RBAC internally via GetUserRole().
			// Per-method middleware can be layered in a future pass.
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
					})
					r.Get("/audit-logs", h.Proxy.ListAuditLogs)
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

				// Settings (placeholder until settings handler exists)
				r.Route("/settings", func(r chi.Router) {
					r.Get("/", notImplemented)
					r.Put("/", notImplemented)

					// LDAP settings require FeatureLDAP (Business+)
					r.Route("/ldap", func(r chi.Router) {
						if config.LicenseProvider != nil {
							r.Use(middleware.RequireFeature(config.LicenseProvider, license.FeatureLDAP))
						}
						r.Get("/", notImplemented)
						r.Put("/", notImplemented)
						r.Post("/test", notImplemented)
					})
				})

				// License
				r.Route("/license", func(r chi.Router) {
					r.Get("/", notImplemented)
					r.Post("/", notImplemented)
					r.Delete("/", notImplemented)
				})
			})
		})
	})

	// =========================================================================
	// API WebSocket routes (at /api/v1/ws, outside timeout to preserve http.Hijacker)
	// Note: Frontend WebSocket routes are at /ws (registered by routes_frontend.go)
	// =========================================================================
	if h.WebSocket != nil {
		r.Mount("/api/v1/ws", h.WebSocket.Routes())
	}

	// =========================================================================
	// Prometheus metrics (no auth for scraping)
	// =========================================================================
	if h.System != nil {
		r.Get("/metrics", h.System.Metrics)
	}

	return r
}

// notImplemented is a placeholder handler for routes not yet implemented.
func notImplemented(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"success":false,"error":{"code":"NOT_IMPLEMENTED","message":"This endpoint is not yet implemented"}}`))
}
