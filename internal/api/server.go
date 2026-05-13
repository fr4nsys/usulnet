// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package api provides the HTTP API server for usulnet.
package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/api/handlers"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
)

// ServerConfig contains configuration for the HTTP server.
type ServerConfig struct {
	// Host is the address to bind to (default: "0.0.0.0")
	Host string

	// Port is the HTTP port to listen on (default: 8080)
	Port int

	// HTTPSPort is the HTTPS port (default: 7443). Only used when TLSConfig is set.
	HTTPSPort int

	// TLSCert is the path to the TLS certificate file (legacy, use TLSConfig instead)
	TLSCert string

	// TLSKey is the path to the TLS key file (legacy, use TLSConfig instead)
	TLSKey string

	// TLSConfig is the pre-built TLS configuration for HTTPS. When set, the server
	// listens on both HTTP (Port) and HTTPS (HTTPSPort).
	TLSConfig *tls.Config

	// ReadTimeout is the maximum duration for reading the entire request.
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out writes of the response.
	WriteTimeout time.Duration

	// IdleTimeout is the maximum amount of time to wait for the next request.
	IdleTimeout time.Duration

	// MaxHeaderBytes controls the maximum number of bytes the server will read
	// parsing the request header's keys and values.
	MaxHeaderBytes int

	// ShutdownTimeout is the timeout for graceful shutdown.
	ShutdownTimeout time.Duration

	// RouterConfig contains configuration for the router.
	RouterConfig RouterConfig

	// Version information (injected at build time)
	Version   string
	Commit    string
	BuildTime string

	// RedirectHTTPS redirects all HTTP requests to HTTPS when TLS is configured.
	RedirectHTTPS bool

	// Logger for the server (also wired into RouterConfig.Logger)
	Logger middleware.RequestLogger

	// LicenseProvider for feature gating (also wired into RouterConfig.LicenseProvider)
	LicenseProvider middleware.LicenseProvider
}

// DefaultServerConfig returns a default server configuration.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Host:            "0.0.0.0",
		Port:            8080,
		ReadTimeout:     15 * time.Second,
		WriteTimeout:    60 * time.Second, // Longer for streaming endpoints
		IdleTimeout:     120 * time.Second,
		MaxHeaderBytes:  1 << 20, // 1 MB
		ShutdownTimeout: 30 * time.Second,
	}
}

// Server represents the HTTP API server.
type Server struct {
	config      ServerConfig
	router      chi.Router
	httpServer  *http.Server
	httpsServer *http.Server
	handlers    *Handlers
	logger      middleware.RequestLogger

	// Lifecycle
	mu       sync.Mutex
	running  bool
	shutdown chan struct{}
}

// NewServer creates a new API server with all dependencies injected via config.
func NewServer(config ServerConfig) *Server {
	// Wire logger and license provider into the router config
	if config.Logger != nil {
		config.RouterConfig.Logger = config.Logger
	}
	if config.LicenseProvider != nil {
		config.RouterConfig.LicenseProvider = config.LicenseProvider
	}

	version := config.Version
	if version == "" {
		version = "dev"
	}
	commit := config.Commit
	if commit == "" {
		commit = "unknown"
	}
	buildTime := config.BuildTime
	if buildTime == "" {
		buildTime = time.Now().Format(time.RFC3339)
	}

	s := &Server{
		config:   config,
		logger:   config.Logger,
		shutdown: make(chan struct{}),
	}

	// Initialize handlers with version info from config
	s.handlers = &Handlers{
		System:    handlers.NewSystemHandler(version, commit, buildTime, nil),
		WebSocket: nil, // Initialized when container service is available
	}

	return s
}

// RegisterLicenseProvider wires a license provider created after server init.
// This is the only late-binding dependency; all others are injected via ServerConfig.
func (s *Server) RegisterLicenseProvider(provider middleware.LicenseProvider) {
	s.config.RouterConfig.LicenseProvider = provider
}

// RegisterReconConfig wires the recon feature flag and acknowledgement
// store. Both are late-binding because the recon module is constructed
// after the API server but before Setup().
func (s *Server) RegisterReconConfig(enabled bool, ack middleware.ReconAckChecker) {
	s.config.RouterConfig.ReconEnabled = enabled
	s.config.RouterConfig.ReconAckChecker = ack
}

// RegisterHealthChecker registers a health checker component.
func (s *Server) RegisterHealthChecker(name string, checker handlers.HealthChecker) {
	s.handlers.System.RegisterHealthChecker(name, checker)
}

// Handlers returns the handlers for dependency injection.
func (s *Server) Handlers() *Handlers {
	return s.handlers
}

// Setup initializes the router and middleware.
// Call this after all dependencies are injected.
func (s *Server) Setup() {
	s.router = NewRouter(s.config.RouterConfig, s.handlers)
}

// Router returns the chi router for testing or custom modifications.
func (s *Server) Router() chi.Router {
	return s.router
}

// Start starts the HTTP server and optionally an HTTPS server.
func (s *Server) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("server already running")
	}
	s.running = true
	s.mu.Unlock()

	// Ensure router is set up
	if s.router == nil {
		s.Setup()
	}

	httpAddr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	// Determine HTTP handler: either the app router or an HTTPS redirect handler
	var httpHandler http.Handler = s.router
	if s.config.TLSConfig != nil && s.config.RedirectHTTPS {
		httpsPort := s.config.HTTPSPort
		if httpsPort == 0 {
			httpsPort = 7443
		}
		httpHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Preserve /health for container health checks over HTTP
			if r.URL.Path == "/health" || r.URL.Path == "/healthz" {
				s.router.ServeHTTP(w, r)
				return
			}
			host := r.Host
			// Strip port if present
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			target := fmt.Sprintf("https://%s:%d%s", host, httpsPort, r.URL.RequestURI())
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})
	}

	s.httpServer = &http.Server{
		Addr:              httpAddr,
		Handler:           httpHandler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       s.config.ReadTimeout,
		WriteTimeout:      s.config.WriteTimeout,
		IdleTimeout:       s.config.IdleTimeout,
		MaxHeaderBytes:    s.config.MaxHeaderBytes,
	}

	// Start HTTPS server if TLS is configured (dual-port mode)
	if s.config.TLSConfig != nil {
		httpsPort := s.config.HTTPSPort
		if httpsPort == 0 {
			httpsPort = 7443
		}
		httpsAddr := fmt.Sprintf("%s:%d", s.config.Host, httpsPort)

		s.httpsServer = &http.Server{
			Addr:              httpsAddr,
			Handler:           s.router,
			TLSConfig:         s.config.TLSConfig,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       s.config.ReadTimeout,
			WriteTimeout:      s.config.WriteTimeout,
			IdleTimeout:       s.config.IdleTimeout,
			MaxHeaderBytes:    s.config.MaxHeaderBytes,
		}

		httpsListener, err := tls.Listen("tcp", httpsAddr, s.config.TLSConfig)
		if err != nil {
			return fmt.Errorf("failed to create HTTPS listener: %w", err)
		}

		if s.logger != nil {
			s.logger.Info("Starting HTTPS server",
				"addr", httpsAddr,
				"protocol", "https",
			)
		}

		go func() {
			if err := s.httpsServer.Serve(httpsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				if s.logger != nil {
					s.logger.Error("HTTPS server error", "error", err)
				}
			}
		}()
	} else if s.config.TLSCert != "" && s.config.TLSKey != "" {
		// Legacy single-port TLS mode (TLSCert/TLSKey without TLSConfig)
		s.httpServer.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}
	}

	// Create HTTP listener
	httpListener, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return fmt.Errorf("failed to create HTTP listener: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("Starting HTTP server",
			"addr", httpAddr,
			"protocol", "http",
		)
	}

	// Start HTTP server (blocks)
	var serverErr error
	if s.config.TLSCert != "" && s.config.TLSKey != "" && s.config.TLSConfig == nil {
		// Legacy: single-port TLS
		serverErr = s.httpServer.ServeTLS(httpListener, s.config.TLSCert, s.config.TLSKey)
	} else {
		serverErr = s.httpServer.Serve(httpListener)
	}

	if serverErr != nil && !errors.Is(serverErr, http.ErrServerClosed) {
		return serverErr
	}

	return nil
}

// StartAsync starts the server in a goroutine and returns immediately.
func (s *Server) StartAsync() <-chan error {
	errChan := make(chan error, 1)
	go func() {
		if err := s.Start(); err != nil {
			errChan <- err
		}
		close(errChan)
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)
	return errChan
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	s.mu.Unlock()

	if s.logger != nil {
		s.logger.Info("Shutting down API server")
	}

	// Create shutdown context with timeout if none provided
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), s.config.ShutdownTimeout)
		defer cancel()
	}

	// Signal shutdown
	close(s.shutdown)

	// Gracefully shutdown HTTPS server first (if running)
	if s.httpsServer != nil {
		if err := s.httpsServer.Shutdown(ctx); err != nil {
			if s.logger != nil {
				s.logger.Error("Error shutting down HTTPS server", "error", err)
			}
		}
	}

	// Gracefully shutdown HTTP server
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			return fmt.Errorf("error shutting down server: %w", err)
		}
	}

	if s.logger != nil {
		s.logger.Info("API server stopped")
	}

	return nil
}

// IsRunning returns whether the server is currently running.
func (s *Server) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Addr returns the server's address.
func (s *Server) Addr() string {
	return fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
}

// ShutdownChan returns a channel that's closed when shutdown is initiated.
func (s *Server) ShutdownChan() <-chan struct{} {
	return s.shutdown
}

// ============================================================================
// Health check registration helpers
// ============================================================================

// RegisterDatabaseHealth registers a database health checker.
func (s *Server) RegisterDatabaseHealth(pingFn func(ctx context.Context) error) {
	s.RegisterHealthChecker("database", handlers.DatabaseHealthChecker(pingFn))
}

// RegisterRedisHealth registers a Redis health checker.
func (s *Server) RegisterRedisHealth(pingFn func(ctx context.Context) error) {
	s.RegisterHealthChecker("redis", handlers.RedisHealthChecker(pingFn))
}

// RegisterDockerHealth registers a Docker health checker.
func (s *Server) RegisterDockerHealth(pingFn func(ctx context.Context) error) {
	s.RegisterHealthChecker("docker", handlers.DockerHealthChecker(pingFn))
}

// RegisterNATSHealth registers a NATS health checker.
func (s *Server) RegisterNATSHealth(healthFn func(ctx context.Context) error) {
	s.RegisterHealthChecker("nats", handlers.NATSHealthChecker(healthFn))
}

// ============================================================================
// Testing helpers
// ============================================================================

// ServeHTTP implements http.Handler for testing.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.router == nil {
		s.Setup()
	}
	s.router.ServeHTTP(w, r)
}

// TestServer creates a server configured for testing.
func TestServer(jwtSecret string) *Server {
	config := DefaultServerConfig()
	config.RouterConfig = DefaultRouterConfig(jwtSecret)
	return NewServer(config)
}
