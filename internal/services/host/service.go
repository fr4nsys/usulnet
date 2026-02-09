// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package host provides host management services.
package host

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// Config contains host service configuration.
type Config struct {
	// HealthCheckInterval is how often to check host connectivity
	HealthCheckInterval time.Duration

	// StaleThreshold marks hosts offline after this duration without contact
	StaleThreshold time.Duration

	// MetricsRetention is how long to keep host metrics
	MetricsRetention time.Duration

	// DefaultTimeout for Docker operations
	DefaultTimeout time.Duration
}

// DefaultConfig returns default host service configuration.
func DefaultConfig() Config {
	return Config{
		HealthCheckInterval: 30 * time.Second,
		StaleThreshold:      2 * time.Minute,
		MetricsRetention:    7 * 24 * time.Hour, // 7 days
		DefaultTimeout:      30 * time.Second,
	}
}

// Service manages Docker hosts.
type Service struct {
	repo          *postgres.HostRepository
	clientPool    *docker.ClientPool
	cmdSender     docker.CommandSender // for agent proxy clients via NATS gateway
	encryptor     *crypto.AESEncryptor
	config        Config
	logger        *logger.Logger
	limitProvider license.LimitProvider

	proxyClients map[string]*docker.AgentProxyClient
	mu           sync.RWMutex
	stopCh       chan struct{}
	running      bool
}

// SetLimitProvider sets the license limit provider for resource cap enforcement.
func (s *Service) SetLimitProvider(lp license.LimitProvider) {
	s.limitProvider = lp
}

// NewService creates a new host service.
func NewService(
	repo *postgres.HostRepository,
	encryptor *crypto.AESEncryptor,
	config Config,
	log *logger.Logger,
) *Service {
	if log == nil {
		log = logger.Nop()
	}

	return &Service{
		repo:         repo,
		clientPool:   docker.NewClientPool(),
		encryptor:    encryptor,
		config:       config,
		logger:       log.Named("host"),
		proxyClients: make(map[string]*docker.AgentProxyClient),
		stopCh:       make(chan struct{}),
	}
}

// NewStandaloneService creates a host service for standalone mode without a database repository.
// Use RegisterClient to pre-register Docker clients.
func NewStandaloneService(config Config, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		repo:         nil,
		clientPool:   docker.NewClientPool(),
		config:       config,
		logger:       log.Named("host"),
		proxyClients: make(map[string]*docker.AgentProxyClient),
		stopCh:       make(chan struct{}),
	}
}

// SetCommandSender sets the gateway command sender for routing operations to remote agents.
// This must be called before agent-type hosts can be used.
func (s *Service) SetCommandSender(sender docker.CommandSender) {
	s.cmdSender = sender
	s.logger.Info("command sender configured for agent proxy support")
}

// SetRepository sets the host repository (for upgrading standalone to master mode).
func (s *Service) SetRepository(repo *postgres.HostRepository) {
	s.repo = repo
	s.logger.Info("host repository configured for database-backed host lookups")
}

// RegisterClient directly registers a Docker client in the pool for a given host ID.
// This bypasses the database and is used for standalone/local mode.
func (s *Service) RegisterClient(hostID string, client *docker.Client) {
	s.clientPool.Set(hostID, client)
	s.logger.Info("docker client registered", "host_id", hostID)
}

// ============================================================================
// Lifecycle
// ============================================================================

// Start starts background workers (health checks, metrics collection).
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.mu.Unlock()

	s.logger.Info("starting host service",
		"health_check_interval", s.config.HealthCheckInterval,
		"stale_threshold", s.config.StaleThreshold,
	)

	// Initialize connections for existing hosts
	go s.initializeConnections(ctx)

	// Start health check worker
	go s.healthCheckWorker(ctx)

	// Start metrics cleanup worker
	go s.metricsCleanupWorker(ctx)

	return nil
}

// Stop stops background workers.
func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	close(s.stopCh)
	s.running = false
	s.clientPool.CloseAll()
	s.logger.Info("host service stopped")
}

// initializeConnections connects to all known hosts on startup.
func (s *Service) initializeConnections(ctx context.Context) {
	if s.repo == nil {
		s.logger.Info("standalone mode - skipping host initialization from DB")
		return
	}
	hosts, err := s.repo.ListOnline(ctx)
	if err != nil {
		s.logger.Error("failed to list hosts for initialization", "error", err)
		return
	}

	s.logger.Info("initializing connections to hosts", "count", len(hosts))

	for _, host := range hosts {
		if err := s.connect(ctx, host); err != nil {
			s.logger.Warn("failed to connect to host on startup",
				"host", host.Name,
				"error", err,
			)
			// Mark as offline
			_ = s.repo.SetOffline(ctx, host.ID, err.Error())
		}
	}
}

// healthCheckWorker periodically checks host connectivity.
func (s *Service) healthCheckWorker(ctx context.Context) {
	ticker := time.NewTicker(s.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.performHealthChecks(ctx)
		}
	}
}

// performHealthChecks checks all hosts.
func (s *Service) performHealthChecks(ctx context.Context) {
	if s.repo == nil {
		// Standalone mode: just check pool connectivity
		results := s.clientPool.HealthCheck(ctx)
		for hostID, err := range results {
			if err != nil {
				s.logger.Warn("host health check failed", "host_id", hostID, "error", err)
			}
		}
		return
	}
	// Mark stale hosts as offline
	count, err := s.repo.MarkStaleHostsOffline(ctx, s.config.StaleThreshold)
	if err != nil {
		s.logger.Error("failed to mark stale hosts offline", "error", err)
	} else if count > 0 {
		s.logger.Info("marked stale hosts offline", "count", count)
	}

	// Check connectivity of all hosts in pool
	results := s.clientPool.HealthCheck(ctx)
	for hostID, err := range results {
		if err != nil {
			s.logger.Warn("host health check failed",
				"host_id", hostID,
				"error", err,
			)
			// Update status in DB
			id, _ := uuid.Parse(hostID)
			if id != uuid.Nil {
				_ = s.repo.SetOffline(ctx, id, err.Error())
			}
		}
	}
}

// metricsCleanupWorker periodically cleans up old metrics.
func (s *Service) metricsCleanupWorker(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			if s.repo == nil {
				continue
			}
			count, err := s.repo.DeleteOldMetrics(ctx, s.config.MetricsRetention)
			if err != nil {
				s.logger.Error("failed to delete old metrics", "error", err)
			} else if count > 0 {
				s.logger.Info("deleted old host metrics", "count", count)
			}
		}
	}
}

// ============================================================================
// CRUD Operations
// ============================================================================

// Create creates a new host and establishes connection.
func (s *Service) Create(ctx context.Context, input *models.CreateHostInput) (*models.Host, error) {
	// Enforce license node limit
	if s.limitProvider != nil {
		limit := s.limitProvider.GetLimits().MaxNodes
		if limit > 0 {
			stats, err := s.GetStats(ctx)
			if err == nil && stats.Total >= limit {
				return nil, apperrors.LimitExceeded("nodes", stats.Total, limit)
			}
		}
	}

	// Validate unique name
	exists, err := s.repo.ExistsByName(ctx, input.Name)
	if err != nil {
		return nil, fmt.Errorf("check name exists: %w", err)
	}
	if exists {
		return nil, apperrors.AlreadyExists("host with this name")
	}

	// Build host model
	host := &models.Host{
		ID:           uuid.New(),
		Name:         input.Name,
		DisplayName:  input.DisplayName,
		EndpointType: input.EndpointType,
		EndpointURL:  input.EndpointURL,
		TLSEnabled:   input.TLSEnabled,
		Status:       models.HostStatusConnecting,
		Labels:       models.JSONStringMap(input.Labels),
	}

	// Encrypt TLS credentials if provided
	if input.TLSEnabled {
		if input.TLSCACert != nil {
			encrypted, err := s.encryptor.EncryptString(*input.TLSCACert)
			if err != nil {
				return nil, fmt.Errorf("encrypt CA cert: %w", err)
			}
			host.TLSCACert = &encrypted
		}
		if input.TLSClientCert != nil {
			encrypted, err := s.encryptor.EncryptString(*input.TLSClientCert)
			if err != nil {
				return nil, fmt.Errorf("encrypt client cert: %w", err)
			}
			host.TLSClientCert = &encrypted
		}
		if input.TLSClientKey != nil {
			encrypted, err := s.encryptor.EncryptString(*input.TLSClientKey)
			if err != nil {
				return nil, fmt.Errorf("encrypt client key: %w", err)
			}
			host.TLSClientKey = &encrypted
		}
	}

	// For local endpoint, set default URL
	if input.EndpointType == models.EndpointLocal {
		url := "unix:///var/run/docker.sock"
		host.EndpointURL = &url
	}

	// Create in database
	if err := s.repo.CreateHost(ctx, host); err != nil {
		return nil, err
	}

	// Attempt to connect
	if err := s.connect(ctx, host); err != nil {
		// Update status to error but still return the host
		_ = s.repo.SetError(ctx, host.ID, err.Error())
		host.Status = models.HostStatusError
		msg := err.Error()
		host.StatusMessage = &msg
		s.logger.Warn("created host but failed to connect",
			"host", host.Name,
			"error", err,
		)
	} else {
		// Connection successful, sync Docker info
		if err := s.syncDockerInfo(ctx, host); err != nil {
			s.logger.Warn("failed to sync docker info",
				"host", host.Name,
				"error", err,
			)
		}
	}

	s.logger.Info("host created",
		"id", host.ID,
		"name", host.Name,
		"type", host.EndpointType,
	)

	return host, nil
}

// Get retrieves a host by ID.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*models.Host, error) {
	if s.repo != nil {
		return s.repo.GetByID(ctx, id)
	}

	// Standalone mode: build host info from client pool
	client, ok := s.clientPool.Get(id.String())
	if !ok {
		return nil, fmt.Errorf("host not found")
	}

	host := &models.Host{
		ID:           id,
		Name:         "local",
		EndpointType: models.EndpointLocal,
		Status:       models.HostStatusOnline,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Enrich with Docker info
	if info, err := client.Info(ctx); err == nil {
		host.DockerVersion = &info.ServerVersion
		host.OSType = &info.OSType
		host.Architecture = &info.Architecture
		host.TotalMemory = &info.MemTotal
		host.TotalCPUs = &info.NCPU
	}

	return host, nil
}

// GetByName retrieves a host by name.
func (s *Service) GetByName(ctx context.Context, name string) (*models.Host, error) {
	if s.repo == nil {
		return nil, fmt.Errorf("host repository not available (standalone mode)")
	}
	return s.repo.GetByName(ctx, name)
}

// Update updates a host.
func (s *Service) Update(ctx context.Context, id uuid.UUID, input *models.UpdateHostInput) (*models.Host, error) {
	host, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if input.DisplayName != nil {
		host.DisplayName = input.DisplayName
	}
	if input.EndpointURL != nil {
		host.EndpointURL = input.EndpointURL
	}
	if input.TLSEnabled != nil {
		host.TLSEnabled = *input.TLSEnabled
	}
	if input.Labels != nil {
		host.Labels = models.JSONStringMap(input.Labels)
	}

	// Update TLS credentials if provided
	if input.TLSCACert != nil {
		encrypted, err := s.encryptor.EncryptString(*input.TLSCACert)
		if err != nil {
			return nil, fmt.Errorf("encrypt CA cert: %w", err)
		}
		host.TLSCACert = &encrypted
	}
	if input.TLSClientCert != nil {
		encrypted, err := s.encryptor.EncryptString(*input.TLSClientCert)
		if err != nil {
			return nil, fmt.Errorf("encrypt client cert: %w", err)
		}
		host.TLSClientCert = &encrypted
	}
	if input.TLSClientKey != nil {
		encrypted, err := s.encryptor.EncryptString(*input.TLSClientKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt client key: %w", err)
		}
		host.TLSClientKey = &encrypted
	}

	// Save to database
	if err := s.repo.UpdateHost(ctx, host); err != nil {
		return nil, err
	}

	// Reconnect if connection settings changed
	if input.EndpointURL != nil || input.TLSEnabled != nil ||
		input.TLSCACert != nil || input.TLSClientCert != nil || input.TLSClientKey != nil {
		// Remove old connection
		s.clientPool.Remove(id.String())

		// Reconnect
		if err := s.connect(ctx, host); err != nil {
			_ = s.repo.SetError(ctx, host.ID, err.Error())
			host.Status = models.HostStatusError
		} else {
			_ = s.syncDockerInfo(ctx, host)
		}
	}

	s.logger.Info("host updated", "id", id, "name", host.Name)

	return host, nil
}

// Delete removes a host.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	host, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Remove from connection pool
	s.clientPool.Remove(id.String())

	// Delete from database
	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}

	s.logger.Info("host deleted", "id", id, "name", host.Name)

	return nil
}

// GenerateAgentToken creates a new random token for an agent host,
// stores its bcrypt hash, and returns the plain token (shown once to the user).
func (s *Service) GenerateAgentToken(ctx context.Context, hostID uuid.UUID) (string, error) {
	if s.repo == nil {
		return "", apperrors.New(apperrors.CodeNotFound, "host repository not available")
	}

	host, err := s.repo.GetByID(ctx, hostID)
	if err != nil {
		return "", err
	}
	if host.EndpointType != models.EndpointAgent {
		return "", apperrors.New(apperrors.CodeValidation, "agent tokens are only for agent-type hosts")
	}

	// Generate a secure random token (32 bytes = 64 hex chars, within bcrypt's 72-byte limit)
	tokenBytes := make([]byte, 32)
	if _, err := cryptorand.Read(tokenBytes); err != nil {
		return "", apperrors.Wrap(err, apperrors.CodeInternal, "failed to generate random token")
	}
	token := hex.EncodeToString(tokenBytes)

	// Store the bcrypt hash
	if err := s.repo.SetAgentToken(ctx, hostID, token); err != nil {
		return "", err
	}

	s.logger.Info("agent token generated", "host_id", hostID, "host_name", host.Name)
	return token, nil
}

// ============================================================================
// List Operations
// ============================================================================

// List retrieves hosts with pagination and filtering.
func (s *Service) List(ctx context.Context, opts postgres.HostListOptions) ([]*models.Host, int64, error) {
	if s.repo == nil {
		// Standalone mode: return hosts from client pool
		ids := s.clientPool.HostIDs()
		hosts := make([]*models.Host, 0, len(ids))
		for _, id := range ids {
			hostID, err := uuid.Parse(id)
			if err != nil {
				continue
			}
			hosts = append(hosts, &models.Host{
				ID:     hostID,
				Name:   "local",
				Status: models.HostStatusOnline,
			})
		}
		return hosts, int64(len(hosts)), nil
	}
	return s.repo.ListWithOptions(ctx, opts)
}

// ListSummaries retrieves host summaries with metrics.
func (s *Service) ListSummaries(ctx context.Context) ([]*models.HostSummary, error) {
	if s.repo != nil {
		summaries, err := s.repo.GetHostSummaries(ctx)
		if err != nil {
			return nil, err
		}
		// Enrich with live Docker data for online hosts
		for _, summary := range summaries {
			if summary.Status != models.HostStatusOnline {
				continue
			}
			client, ok := s.clientPool.Get(summary.ID.String())
			if !ok {
				continue
			}
			info, err := client.Info(ctx)
			if err != nil {
				continue
			}
			summary.ContainerCount = info.Containers
			summary.RunningCount = info.ContainersRunning
			if summary.DockerVersion == nil || *summary.DockerVersion == "" {
				summary.DockerVersion = &info.ServerVersion
			}
			if summary.TotalCPUs == nil || *summary.TotalCPUs == 0 {
				summary.TotalCPUs = &info.NCPU
			}
			if summary.TotalMemory == nil || *summary.TotalMemory == 0 {
				summary.TotalMemory = &info.MemTotal
			}
			if summary.OSType == nil || *summary.OSType == "" {
				summary.OSType = &info.OSType
			}
			if summary.Architecture == nil || *summary.Architecture == "" {
				summary.Architecture = &info.Architecture
			}
			now := time.Now()
			summary.LastSeenAt = &now
		}
		return summaries, nil
	}

	// Standalone mode: build summaries from Docker client pool
	var summaries []*models.HostSummary
	for _, hostID := range s.clientPool.HostIDs() {
		client, ok := s.clientPool.Get(hostID)
		if !ok {
			continue
		}

		parsedID, err := uuid.Parse(hostID)
		if err != nil {
			continue
		}

		summary := &models.HostSummary{
			Host: models.Host{
				ID:           parsedID,
				Name:         "local",
				EndpointType: models.EndpointLocal,
				Status:       models.HostStatusOnline,
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			},
		}

		// Enrich with Docker info
		if info, err := client.Info(ctx); err == nil {
			now := time.Now()
			summary.Host.DockerVersion = &info.ServerVersion
			summary.Host.OSType = &info.OSType
			summary.Host.Architecture = &info.Architecture
			summary.Host.TotalMemory = &info.MemTotal
			summary.Host.TotalCPUs = &info.NCPU
			summary.Host.LastSeenAt = &now
			summary.ContainerCount = info.Containers
			summary.RunningCount = info.ContainersRunning
			if info.Name != "" {
				summary.Host.Name = info.Name
				displayName := info.Name
				summary.Host.DisplayName = &displayName
			}
		}

		summaries = append(summaries, summary)
	}
	return summaries, nil
}

// GetStats retrieves host statistics.
func (s *Service) GetStats(ctx context.Context) (*postgres.HostStats, error) {
	if s.repo == nil {
		return &postgres.HostStats{}, nil
	}
	return s.repo.GetStats(ctx)
}

// ============================================================================
// Connection Management
// ============================================================================

// connect establishes a connection to a Docker host.
func (s *Service) connect(ctx context.Context, host *models.Host) error {
	opts, err := s.buildClientOptions(host)
	if err != nil {
		return fmt.Errorf("build client options: %w", err)
	}

	client, err := s.clientPool.GetOrCreate(ctx, host.ID.String(), opts)
	if err != nil {
		return fmt.Errorf("create docker client: %w", err)
	}

	// Verify connection
	if err := client.Ping(ctx); err != nil {
		s.clientPool.Remove(host.ID.String())
		return fmt.Errorf("ping docker: %w", err)
	}

	// Update status to online
	_ = s.repo.UpdateStatus(ctx, host.ID, string(models.HostStatusOnline), time.Now())

	return nil
}

// buildClientOptions builds Docker client options from host configuration.
func (s *Service) buildClientOptions(host *models.Host) (docker.ClientOptions, error) {
	opts := docker.ClientOptions{
		Timeout: s.config.DefaultTimeout,
	}

	// Set host URL
	switch host.EndpointType {
	case models.EndpointLocal:
		opts.Host = "unix:///var/run/docker.sock"
	case models.EndpointSocket:
		if host.EndpointURL != nil {
			opts.Host = *host.EndpointURL
		} else {
			opts.Host = "unix:///var/run/docker.sock"
		}
	case models.EndpointTCP:
		if host.EndpointURL == nil {
			return opts, fmt.Errorf("endpoint URL required for TCP connection")
		}
		opts.Host = *host.EndpointURL
	case models.EndpointAgent:
		// Agent connections are handled via NATS gateway, not direct Docker TCP.
		// The gateway dispatches commands to the remote agent which executes
		// them against its local Docker daemon. Direct Docker client connections
		// are not needed for agent-managed hosts.
		return opts, fmt.Errorf("agent host %s: use gateway command dispatch instead of direct Docker connection", host.Name)
	}

	// Configure TLS if enabled
	if host.TLSEnabled {
		tlsConfig := &docker.TLSConfig{}

		if host.TLSCACert != nil {
			decrypted, err := s.encryptor.DecryptString(*host.TLSCACert)
			if err != nil {
				return opts, fmt.Errorf("decrypt CA cert: %w", err)
			}
			tlsConfig.CACert = []byte(decrypted)
		}

		if host.TLSClientCert != nil {
			decrypted, err := s.encryptor.DecryptString(*host.TLSClientCert)
			if err != nil {
				return opts, fmt.Errorf("decrypt client cert: %w", err)
			}
			tlsConfig.ClientCert = []byte(decrypted)
		}

		if host.TLSClientKey != nil {
			decrypted, err := s.encryptor.DecryptString(*host.TLSClientKey)
			if err != nil {
				return opts, fmt.Errorf("decrypt client key: %w", err)
			}
			tlsConfig.ClientKey = []byte(decrypted)
		}

		opts.TLS = tlsConfig
	}

	return opts, nil
}

// GetClient retrieves a Docker client (direct or proxy) for a host.
// For agent-type hosts, returns an AgentProxyClient that routes via NATS gateway.
// For local/TCP/socket hosts, returns a direct Docker client.
func (s *Service) GetClient(ctx context.Context, hostID uuid.UUID) (docker.ClientAPI, error) {
	// Try to get direct client from pool
	if client, ok := s.clientPool.Get(hostID.String()); ok {
		if err := client.Ping(ctx); err == nil {
			return client, nil
		}
		s.clientPool.Remove(hostID.String())
	}

	// Check for cached proxy client (agent hosts)
	s.mu.RLock()
	if proxy, ok := s.proxyClients[hostID.String()]; ok {
		s.mu.RUnlock()
		return proxy, nil
	}
	s.mu.RUnlock()

	// In standalone mode (no repo), cannot reconnect
	if s.repo == nil {
		return nil, fmt.Errorf("docker client not available for host %s (standalone mode)", hostID)
	}

	// Look up host to determine type
	host, err := s.repo.GetByID(ctx, hostID)
	if err != nil {
		return nil, err
	}

	// For agent hosts, create a proxy client routed through NATS gateway
	if host.EndpointType == models.EndpointAgent {
		if s.cmdSender == nil {
			return nil, fmt.Errorf("gateway not available for agent host %q", host.Name)
		}
		proxy := docker.NewAgentProxyClient(s.cmdSender, hostID, s.logger)
		s.mu.Lock()
		s.proxyClients[hostID.String()] = proxy
		s.mu.Unlock()
		return proxy, nil
	}

	// For direct hosts, connect normally
	if err := s.connect(ctx, host); err != nil {
		return nil, err
	}

	client, _ := s.clientPool.Get(hostID.String())
	return client, nil
}

// Reconnect forces a reconnection to a host.
func (s *Service) Reconnect(ctx context.Context, id uuid.UUID) error {
	host, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Remove existing connection
	s.clientPool.Remove(id.String())

	// Update status
	_ = s.repo.UpdateStatus(ctx, id, string(models.HostStatusConnecting), time.Now())

	// Reconnect
	if err := s.connect(ctx, host); err != nil {
		_ = s.repo.SetError(ctx, id, err.Error())
		return err
	}

	// Sync Docker info
	if err := s.syncDockerInfo(ctx, host); err != nil {
		s.logger.Warn("failed to sync docker info after reconnect",
			"host", host.Name,
			"error", err,
		)
	}

	s.logger.Info("host reconnected", "id", id, "name", host.Name)

	return nil
}

// TestConnection tests connectivity to a host without saving.
func (s *Service) TestConnection(ctx context.Context, input *models.CreateHostInput) (*models.HostDockerInfo, error) {
	// Build temporary host for connection
	host := &models.Host{
		ID:           uuid.New(),
		Name:         "test-" + uuid.New().String()[:8],
		EndpointType: input.EndpointType,
		EndpointURL:  input.EndpointURL,
		TLSEnabled:   input.TLSEnabled,
	}

	// Set TLS certs (not encrypted for test)
	if input.TLSEnabled {
		host.TLSCACert = input.TLSCACert
		host.TLSClientCert = input.TLSClientCert
		host.TLSClientKey = input.TLSClientKey
	}

	// For local endpoint
	if input.EndpointType == models.EndpointLocal {
		url := "unix:///var/run/docker.sock"
		host.EndpointURL = &url
	}

	// Build options (without encryption)
	opts := docker.ClientOptions{
		Timeout: s.config.DefaultTimeout,
	}

	switch host.EndpointType {
	case models.EndpointLocal, models.EndpointSocket:
		if host.EndpointURL != nil {
			opts.Host = *host.EndpointURL
		} else {
			opts.Host = "unix:///var/run/docker.sock"
		}
	case models.EndpointTCP:
		if host.EndpointURL == nil {
			return nil, fmt.Errorf("endpoint URL required for TCP connection")
		}
		opts.Host = *host.EndpointURL
	}

	if host.TLSEnabled {
		opts.TLS = &docker.TLSConfig{}
		if host.TLSCACert != nil {
			opts.TLS.CACert = []byte(*host.TLSCACert)
		}
		if host.TLSClientCert != nil {
			opts.TLS.ClientCert = []byte(*host.TLSClientCert)
		}
		if host.TLSClientKey != nil {
			opts.TLS.ClientKey = []byte(*host.TLSClientKey)
		}
	}

	// Create temporary client
	client, err := docker.NewClient(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer client.Close()

	// Get Docker info
	info, err := client.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("get docker info: %w", err)
	}

	return dockerInfoToModel(info), nil
}

// dockerInfoToModel converts a docker.DockerInfo to models.HostDockerInfo.
func dockerInfoToModel(info *docker.DockerInfo) *models.HostDockerInfo {
	return &models.HostDockerInfo{
		ID:                info.ID,
		Name:              info.Name,
		ServerVersion:     info.ServerVersion,
		APIVersion:        info.APIVersion,
		OSType:            info.OSType,
		Architecture:      info.Architecture,
		KernelVersion:     info.KernelVersion,
		OperatingSystem:   info.OS,
		NCPU:              info.NCPU,
		MemTotal:          info.MemTotal,
		Containers:        info.Containers,
		ContainersRunning: info.ContainersRunning,
		ContainersPaused:  info.ContainersPaused,
		ContainersStopped: info.ContainersStopped,
		Images:            info.Images,
		DockerRootDir:     info.DockerRootDir,
		SwarmActive:       info.Swarm,
	}
}

// ============================================================================
// Docker Info Sync
// ============================================================================

// syncDockerInfo synchronizes Docker information for a host.
func (s *Service) syncDockerInfo(ctx context.Context, host *models.Host) error {
	client, ok := s.clientPool.Get(host.ID.String())
	if !ok {
		return fmt.Errorf("no client connection for host")
	}

	info, err := client.Info(ctx)
	if err != nil {
		return fmt.Errorf("get docker info: %w", err)
	}

	dockerInfo := dockerInfoToModel(info)

	if err := s.repo.UpdateDockerInfo(ctx, host.ID, dockerInfo); err != nil {
		return fmt.Errorf("update docker info: %w", err)
	}

	// Update local host object
	host.DockerVersion = &dockerInfo.ServerVersion
	host.OSType = &dockerInfo.OSType
	host.Architecture = &dockerInfo.Architecture
	host.TotalMemory = &dockerInfo.MemTotal
	host.TotalCPUs = &dockerInfo.NCPU
	host.Status = models.HostStatusOnline

	return nil
}

// GetDockerInfo retrieves current Docker info for a host.
func (s *Service) GetDockerInfo(ctx context.Context, hostID uuid.UUID) (*models.HostDockerInfo, error) {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	info, err := client.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("get docker info: %w", err)
	}

	return dockerInfoToModel(info), nil
}

// ============================================================================
// Status Management
// ============================================================================

// SetMaintenance puts a host in maintenance mode.
func (s *Service) SetMaintenance(ctx context.Context, id uuid.UUID, reason string) error {
	// Disconnect from pool (but keep in DB)
	s.clientPool.Remove(id.String())

	if err := s.repo.SetMaintenance(ctx, id, reason); err != nil {
		return err
	}

	s.logger.Info("host set to maintenance", "id", id, "reason", reason)
	return nil
}

// ClearMaintenance removes maintenance mode and reconnects.
func (s *Service) ClearMaintenance(ctx context.Context, id uuid.UUID) error {
	host, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Attempt to reconnect
	if err := s.connect(ctx, host); err != nil {
		_ = s.repo.SetError(ctx, id, err.Error())
		return err
	}

	// Sync Docker info
	_ = s.syncDockerInfo(ctx, host)

	s.logger.Info("host maintenance cleared", "id", id, "name", host.Name)
	return nil
}

// ============================================================================
// Metrics
// ============================================================================

// RecordMetrics records metrics for a host.
func (s *Service) RecordMetrics(ctx context.Context, metrics *models.HostMetrics) error {
	metrics.CollectedAt = time.Now().UTC()
	return s.repo.InsertMetrics(ctx, metrics)
}

// GetMetrics retrieves the latest metrics for a host.
func (s *Service) GetMetrics(ctx context.Context, hostID uuid.UUID) (*models.HostMetrics, error) {
	return s.repo.GetLatestMetrics(ctx, hostID)
}

// GetMetricsHistory retrieves metrics history for a host.
func (s *Service) GetMetricsHistory(ctx context.Context, hostID uuid.UUID, since time.Time, limit int) ([]*models.HostMetrics, error) {
	return s.repo.GetMetricsHistory(ctx, hostID, since, limit)
}

// ============================================================================
// Agent Operations (for future multi-host support)
// ============================================================================

// RegisterAgent registers a new agent-based host.
func (s *Service) RegisterAgent(ctx context.Context, reg *models.AgentRegistration, token string) (*models.Host, error) {
	// Check if agent already registered
	existingHost, err := s.repo.GetByAgentID(ctx, reg.AgentID)
	if err == nil {
		// Agent exists, validate token and update
		tokenHash := crypto.HashToken(token)
		if existingHost.AgentTokenHash != nil && *existingHost.AgentTokenHash != tokenHash {
			return nil, apperrors.Unauthorized("invalid agent token")
		}

		// Update host info
		existingHost.DockerVersion = &reg.DockerVersion
		existingHost.OSType = &reg.OSType
		existingHost.Architecture = &reg.Architecture
		existingHost.TotalMemory = &reg.TotalMemory
		existingHost.TotalCPUs = &reg.TotalCPUs
		existingHost.Status = models.HostStatusOnline

		_ = s.repo.UpdateDockerInfo(ctx, existingHost.ID, &models.HostDockerInfo{
			ServerVersion: reg.DockerVersion,
			OSType:        reg.OSType,
			Architecture:  reg.Architecture,
			MemTotal:      reg.TotalMemory,
			NCPU:          reg.TotalCPUs,
		})

		s.logger.Info("agent re-registered",
			"agent_id", reg.AgentID,
			"host", existingHost.Name,
		)

		return existingHost, nil
	}

	// Enforce license node limit (same check as Create)
	if s.limitProvider != nil {
		limit := s.limitProvider.GetLimits().MaxNodes
		if limit > 0 {
			stats, err := s.GetStats(ctx)
			if err == nil && stats.Total >= limit {
				return nil, apperrors.LimitExceeded("nodes", stats.Total, limit)
			}
		}
	}

	// New agent registration
	tokenHash := crypto.HashToken(token)
	host := &models.Host{
		ID:             uuid.New(),
		Name:           reg.HostName,
		EndpointType:   models.EndpointAgent,
		AgentID:        &reg.AgentID,
		AgentTokenHash: &tokenHash,
		Status:         models.HostStatusOnline,
		DockerVersion:  &reg.DockerVersion,
		OSType:         &reg.OSType,
		Architecture:   &reg.Architecture,
		TotalMemory:    &reg.TotalMemory,
		TotalCPUs:      &reg.TotalCPUs,
	}

	if err := s.repo.CreateHost(ctx, host); err != nil {
		return nil, err
	}

	s.logger.Info("new agent registered",
		"agent_id", reg.AgentID,
		"host", host.Name,
	)

	return host, nil
}

// ProcessHeartbeat processes an agent heartbeat.
func (s *Service) ProcessHeartbeat(ctx context.Context, heartbeat *models.AgentHeartbeat, tokenHash string) error {
	// Validate agent
	host, err := s.repo.ValidateAgentToken(ctx, heartbeat.AgentID, tokenHash)
	if err != nil {
		return err
	}

	// Update last seen
	if err := s.repo.UpdateLastSeen(ctx, host.ID); err != nil {
		return err
	}

	// Record metrics
	metrics := &models.HostMetrics{
		HostID:         host.ID,
		CPUPercent:     heartbeat.CPUPercent,
		MemoryPercent:  heartbeat.MemoryPercent,
		ContainerCount: heartbeat.ContainerCount,
		RunningCount:   heartbeat.RunningCount,
		CollectedAt:    heartbeat.Timestamp,
	}

	return s.repo.InsertMetrics(ctx, metrics)
}

// ============================================================================
// Utilities
// ============================================================================

// GetClientPool returns the client pool (for services that need direct access).
func (s *Service) GetClientPool() *docker.ClientPool {
	return s.clientPool
}

// IsOnline checks if a host is online.
func (s *Service) IsOnline(ctx context.Context, hostID uuid.UUID) bool {
	if client, ok := s.clientPool.Get(hostID.String()); ok {
		return client.Ping(ctx) == nil
	}
	return false
}

// GetOnlineHosts returns all online host IDs.
func (s *Service) GetOnlineHosts() []string {
	return s.clientPool.Hosts()
}
