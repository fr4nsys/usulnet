// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package proxy provides the reverse proxy management service.
// It stores configuration in PostgreSQL (source of truth) and pushes
// the full configuration to Caddy's admin API on each change.
package proxy

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/proxy/caddy"
)

// Config holds service configuration.
type Config struct {
	// CaddyAdminURL is the base URL of Caddy's admin API.
	CaddyAdminURL string
	// ACMEEmail is the email used for Let's Encrypt registration.
	ACMEEmail string
	// ListenHTTP is the Caddy listen address for HTTP (default ":80").
	ListenHTTP string
	// ListenHTTPS is the Caddy listen address for HTTPS (default ":443").
	ListenHTTPS string
	// DefaultHostID is the usulnet host ID used when not multi-host.
	DefaultHostID uuid.UUID
}

// Service manages reverse proxy configuration.
type Service struct {
	hosts    HostRepository
	headers  HeaderRepository
	certs    CertificateRepository
	dns      DNSProviderRepository
	audit    AuditLogRepository
	caddy    *caddy.Client
	enc      Encryptor
	cfg      Config
	logger   *logger.Logger

	// Sync mutex to prevent concurrent config pushes
	syncMu sync.Mutex
}

// NewService creates a new proxy service.
func NewService(
	hosts HostRepository,
	headers HeaderRepository,
	certs CertificateRepository,
	dns DNSProviderRepository,
	audit AuditLogRepository,
	enc Encryptor,
	cfg Config,
	log *logger.Logger,
) *Service {
	caddyCfg := caddy.Config{
		AdminURL: cfg.CaddyAdminURL,
		Timeout:  10 * time.Second,
	}

	return &Service{
		hosts:   hosts,
		headers: headers,
		certs:   certs,
		dns:     dns,
		audit:   audit,
		caddy:   caddy.NewClient(caddyCfg),
		enc:     enc,
		cfg:     cfg,
		logger:  log.Named("proxy"),
	}
}

// ============================================================================
// Proxy Host CRUD
// ============================================================================

// CreateHost creates a new proxy host and syncs to Caddy.
func (s *Service) CreateHost(ctx context.Context, input *models.CreateProxyHostInput, userID *uuid.UUID) (*models.ProxyHost, error) {
	h := &models.ProxyHost{
		ID:                  uuid.New(),
		HostID:              s.cfg.DefaultHostID,
		Name:                input.Name,
		Domains:             input.Domains,
		Enabled:             true,
		Status:              models.ProxyHostStatusPending,
		UpstreamScheme:      input.UpstreamScheme,
		UpstreamHost:        input.UpstreamHost,
		UpstreamPort:        input.UpstreamPort,
		UpstreamPath:        input.UpstreamPath,
		SSLMode:             input.SSLMode,
		SSLForceHTTPS:       input.SSLForceHTTPS,
		CertificateID:       input.CertificateID,
		DNSProviderID:       input.DNSProviderID,
		EnableWebSocket:     input.EnableWebSocket,
		EnableCompression:   input.EnableCompression,
		EnableHSTS:          input.EnableHSTS,
		EnableHTTP2:         input.EnableHTTP2,
		HealthCheckEnabled:  input.HealthCheckEnabled,
		HealthCheckPath:     input.HealthCheckPath,
		HealthCheckInterval: input.HealthCheckInterval,
		ContainerID:         input.ContainerID,
		ContainerName:       input.ContainerName,
		CreatedBy:           userID,
		UpdatedBy:           userID,
	}

	if err := s.hosts.Create(ctx, h); err != nil {
		return nil, fmt.Errorf("create proxy host: %w", err)
	}

	s.auditLog(ctx, h.HostID, userID, "create", "proxy_host", h.ID, h.Name, "")

	// Sync to Caddy
	if err := s.SyncToCaddy(ctx); err != nil {
		s.logger.Error("Failed to sync to Caddy after create", "host_id", h.ID, "error", err)
		_ = s.hosts.UpdateStatus(ctx, h.ID, models.ProxyHostStatusError, err.Error())
		return h, nil // Return host even if sync fails
	}

	_ = s.hosts.UpdateStatus(ctx, h.ID, models.ProxyHostStatusActive, "")
	h.Status = models.ProxyHostStatusActive
	return h, nil
}

// GetHost retrieves a proxy host by ID, including custom headers.
func (s *Service) GetHost(ctx context.Context, id uuid.UUID) (*models.ProxyHost, error) {
	h, err := s.hosts.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	headers, err := s.headers.ListByHost(ctx, id)
	if err != nil {
		s.logger.Error("Failed to load custom headers", "proxy_host_id", id, "error", err)
	} else {
		h.CustomHeaders = headers
	}

	return h, nil
}

// ListHosts returns all proxy hosts for the default host.
func (s *Service) ListHosts(ctx context.Context) ([]*models.ProxyHost, error) {
	return s.hosts.List(ctx, s.cfg.DefaultHostID, false)
}

// UpdateHost updates a proxy host and syncs to Caddy.
func (s *Service) UpdateHost(ctx context.Context, id uuid.UUID, input *models.UpdateProxyHostInput, userID *uuid.UUID) (*models.ProxyHost, error) {
	h, err := s.hosts.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Apply partial update
	if input.Name != nil {
		h.Name = *input.Name
	}
	if input.Domains != nil {
		h.Domains = input.Domains
	}
	if input.UpstreamScheme != nil {
		h.UpstreamScheme = *input.UpstreamScheme
	}
	if input.UpstreamHost != nil {
		h.UpstreamHost = *input.UpstreamHost
	}
	if input.UpstreamPort != nil {
		h.UpstreamPort = *input.UpstreamPort
	}
	if input.UpstreamPath != nil {
		h.UpstreamPath = *input.UpstreamPath
	}
	if input.SSLMode != nil {
		h.SSLMode = *input.SSLMode
	}
	if input.SSLForceHTTPS != nil {
		h.SSLForceHTTPS = *input.SSLForceHTTPS
	}
	if input.CertificateID != nil {
		h.CertificateID = input.CertificateID
	}
	if input.DNSProviderID != nil {
		h.DNSProviderID = input.DNSProviderID
	}
	if input.Enabled != nil {
		h.Enabled = *input.Enabled
	}
	if input.EnableWebSocket != nil {
		h.EnableWebSocket = *input.EnableWebSocket
	}
	if input.EnableCompression != nil {
		h.EnableCompression = *input.EnableCompression
	}
	if input.EnableHSTS != nil {
		h.EnableHSTS = *input.EnableHSTS
	}
	if input.EnableHTTP2 != nil {
		h.EnableHTTP2 = *input.EnableHTTP2
	}
	if input.HealthCheckEnabled != nil {
		h.HealthCheckEnabled = *input.HealthCheckEnabled
	}
	if input.HealthCheckPath != nil {
		h.HealthCheckPath = *input.HealthCheckPath
	}
	if input.HealthCheckInterval != nil {
		h.HealthCheckInterval = *input.HealthCheckInterval
	}

	h.UpdatedBy = userID

	if err := s.hosts.Update(ctx, h); err != nil {
		return nil, fmt.Errorf("update proxy host: %w", err)
	}

	s.auditLog(ctx, h.HostID, userID, "update", "proxy_host", h.ID, h.Name, "")

	if err := s.SyncToCaddy(ctx); err != nil {
		s.logger.Error("Failed to sync to Caddy after update", "host_id", h.ID, "error", err)
		_ = s.hosts.UpdateStatus(ctx, h.ID, models.ProxyHostStatusError, err.Error())
	} else {
		_ = s.hosts.UpdateStatus(ctx, h.ID, models.ProxyHostStatusActive, "")
	}

	return h, nil
}

// DeleteHost removes a proxy host and syncs to Caddy.
func (s *Service) DeleteHost(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	h, err := s.hosts.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Delete headers first (FK cascade should handle this, but be explicit)
	if err := s.headers.ReplaceForHost(ctx, id, nil); err != nil {
		s.logger.Error("Failed to delete headers for proxy host", "id", id, "error", err)
	}

	if err := s.hosts.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete proxy host: %w", err)
	}

	s.auditLog(ctx, h.HostID, userID, "delete", "proxy_host", h.ID, h.Name, "")

	if err := s.SyncToCaddy(ctx); err != nil {
		s.logger.Error("Failed to sync to Caddy after delete", "error", err)
		// Don't fail the delete if Caddy sync fails
	}

	return nil
}

// EnableHost enables a proxy host.
func (s *Service) EnableHost(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	enabled := true
	_, err := s.UpdateHost(ctx, id, &models.UpdateProxyHostInput{Enabled: &enabled}, userID)
	return err
}

// DisableHost disables a proxy host.
func (s *Service) DisableHost(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	disabled := false
	_, err := s.UpdateHost(ctx, id, &models.UpdateProxyHostInput{Enabled: &disabled}, userID)
	return err
}

// SetCustomHeaders replaces all custom headers for a proxy host and syncs.
func (s *Service) SetCustomHeaders(ctx context.Context, proxyHostID uuid.UUID, headers []models.ProxyHeader) error {
	if err := s.headers.ReplaceForHost(ctx, proxyHostID, headers); err != nil {
		return err
	}
	return s.SyncToCaddy(ctx)
}

// ============================================================================
// Certificates
// ============================================================================

// ListCertificates returns all certificates for the default host.
func (s *Service) ListCertificates(ctx context.Context) ([]*models.ProxyCertificate, error) {
	return s.certs.List(ctx, s.cfg.DefaultHostID)
}

// UploadCertificate stores a custom certificate.
func (s *Service) UploadCertificate(ctx context.Context, name string, domains []string, certPEM, keyPEM, chainPEM string, userID *uuid.UUID) (*models.ProxyCertificate, error) {
	// Encrypt the private key at rest
	encKey, err := s.enc.EncryptString(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("encrypt certificate key: %w", err)
	}

	c := &models.ProxyCertificate{
		ID:       uuid.New(),
		HostID:   s.cfg.DefaultHostID,
		Name:     name,
		Domains:  domains,
		Provider: "custom",
		CertPEM:  certPEM,
		KeyPEM:   encKey,
		ChainPEM: chainPEM,
	}

	if err := s.certs.Create(ctx, c); err != nil {
		return nil, err
	}

	s.auditLog(ctx, c.HostID, userID, "create", "certificate", c.ID, c.Name, "")
	return c, nil
}

// DeleteCertificate removes a certificate.
func (s *Service) DeleteCertificate(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	c, err := s.certs.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.certs.Delete(ctx, id); err != nil {
		return err
	}
	s.auditLog(ctx, c.HostID, userID, "delete", "certificate", c.ID, c.Name, "")
	return nil
}

// ============================================================================
// DNS Providers
// ============================================================================

// ListDNSProviders returns all DNS providers for the default host.
func (s *Service) ListDNSProviders(ctx context.Context) ([]*models.ProxyDNSProvider, error) {
	providers, err := s.dns.List(ctx, s.cfg.DefaultHostID)
	if err != nil {
		return nil, err
	}
	// Mask API tokens for display
	for _, p := range providers {
		p.APITokenHint = maskToken(p.APIToken)
		p.APIToken = "" // Never expose full token
	}
	return providers, nil
}

// CreateDNSProvider stores a new DNS provider with encrypted API token.
func (s *Service) CreateDNSProvider(ctx context.Context, name, provider, apiToken, zone string, propagation int, isDefault bool, userID *uuid.UUID) (*models.ProxyDNSProvider, error) {
	// Validate provider
	if _, ok := models.SupportedDNSProviders[provider]; !ok {
		return nil, fmt.Errorf("unsupported DNS provider: %s", provider)
	}

	encToken, err := s.enc.EncryptString(apiToken)
	if err != nil {
		return nil, fmt.Errorf("encrypt DNS API token: %w", err)
	}

	p := &models.ProxyDNSProvider{
		ID:          uuid.New(),
		HostID:      s.cfg.DefaultHostID,
		Name:        name,
		Provider:    provider,
		APIToken:    encToken,
		Zone:        zone,
		Propagation: propagation,
		IsDefault:   isDefault,
	}

	if err := s.dns.Create(ctx, p); err != nil {
		return nil, err
	}

	s.auditLog(ctx, p.HostID, userID, "create", "dns_provider", p.ID, p.Name, "")

	p.APITokenHint = maskToken(apiToken)
	p.APIToken = ""
	return p, nil
}

// DeleteDNSProvider removes a DNS provider.
func (s *Service) DeleteDNSProvider(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	p, err := s.dns.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.dns.Delete(ctx, id); err != nil {
		return err
	}
	s.auditLog(ctx, p.HostID, userID, "delete", "dns_provider", p.ID, p.Name, "")
	return nil
}

// ============================================================================
// Caddy Sync
// ============================================================================

// SyncToCaddy generates the full Caddy configuration from DB and pushes it.
// This is the core operation: DB → JSON config → POST /load.
func (s *Service) SyncToCaddy(ctx context.Context) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	// 1. Load all enabled hosts
	hosts, err := s.hosts.ListAll(ctx, true)
	if err != nil {
		return fmt.Errorf("list proxy hosts: %w", err)
	}

	// 2. Load custom headers for each host
	for _, h := range hosts {
		headers, err := s.headers.ListByHost(ctx, h.ID)
		if err != nil {
			s.logger.Error("Failed to load headers for host", "id", h.ID, "error", err)
			continue
		}
		h.CustomHeaders = headers
	}

	// 3. Load DNS providers (for DNS challenge hosts)
	dnsProviders := make(map[string]*models.ProxyDNSProvider)
	allDNS, err := s.dns.List(ctx, s.cfg.DefaultHostID)
	if err != nil {
		s.logger.Error("Failed to load DNS providers", "error", err)
	} else {
		for _, p := range allDNS {
			// Decrypt API token for Caddy config
			decrypted, err := s.enc.DecryptString(p.APIToken)
			if err != nil {
				s.logger.Error("Failed to decrypt DNS token", "provider_id", p.ID, "error", err)
				continue
			}
			p.APIToken = decrypted
			dnsProviders[p.ID.String()] = p
		}
	}

	// 4. Load custom certificates
	customCerts := make(map[string]*models.ProxyCertificate)
	allCerts, err := s.certs.List(ctx, s.cfg.DefaultHostID)
	if err != nil {
		s.logger.Error("Failed to load certificates", "error", err)
	} else {
		for _, c := range allCerts {
			// Decrypt private key for Caddy config
			if c.KeyPEM != "" {
				decrypted, err := s.enc.DecryptString(c.KeyPEM)
				if err != nil {
					s.logger.Error("Failed to decrypt cert key", "cert_id", c.ID, "error", err)
					continue
				}
				c.KeyPEM = decrypted
			}
			customCerts[c.ID.String()] = c
		}
	}

	// 5. Build Caddy config
	config := caddy.BuildConfig(hosts, dnsProviders, customCerts, s.cfg.ACMEEmail, s.cfg.ListenHTTP, s.cfg.ListenHTTPS)

	// 6. Push to Caddy
	if err := s.caddy.Load(ctx, config); err != nil {
		return fmt.Errorf("caddy load: %w", err)
	}

	s.logger.Info("Synced proxy configuration to Caddy", "host_count", len(hosts))

	// 7. Update status for all synced hosts
	for _, h := range hosts {
		_ = s.hosts.UpdateStatus(ctx, h.ID, models.ProxyHostStatusActive, "")
	}

	return nil
}

// CaddyHealthy checks if Caddy's admin API is reachable.
func (s *Service) CaddyHealthy(ctx context.Context) (bool, error) {
	return s.caddy.Healthy(ctx)
}

// UpstreamStatus returns the current health of all Caddy upstreams.
func (s *Service) UpstreamStatus(ctx context.Context) ([]caddy.UpstreamStatus, error) {
	return s.caddy.UpstreamStatus(ctx)
}

// ============================================================================
// Audit Log
// ============================================================================

// ListAuditLogs returns proxy audit log entries.
func (s *Service) ListAuditLogs(ctx context.Context, limit, offset int) ([]*models.ProxyAuditLog, int, error) {
	return s.audit.List(ctx, s.cfg.DefaultHostID, limit, offset)
}

// ============================================================================
// Auto-proxy from Docker containers
// ============================================================================

// AutoProxyFromLabels checks if a container has proxy labels and creates/updates
// a proxy host accordingly.
func (s *Service) AutoProxyFromLabels(ctx context.Context, containerID, containerName string, labels map[string]string) error {
	domain, ok := labels[models.LabelCaddyDomain]
	if !ok || domain == "" {
		return nil // No proxy label, skip
	}

	// Check if we already have a proxy for this container
	existing, err := s.hosts.GetByContainerID(ctx, containerID)
	if err != nil {
		return err
	}

	port := 80
	if p, ok := labels[models.LabelCaddyPort]; ok {
		fmt.Sscanf(p, "%d", &port)
	}

	sslMode := models.ProxySSLModeAuto
	if v, ok := labels[models.LabelCaddySSL]; ok && v == "false" {
		sslMode = models.ProxySSLModeNone
	}

	websocket := false
	if v, ok := labels[models.LabelCaddyWebsocket]; ok && v == "true" {
		websocket = true
	}

	if existing != nil {
		// Update existing
		name := containerName
		newDomains := []string{domain}
		newPort := port
		scheme := models.ProxyUpstreamHTTP
		_, err = s.UpdateHost(ctx, existing.ID, &models.UpdateProxyHostInput{
			Name:            &name,
			Domains:         newDomains,
			UpstreamHost:    &containerName,
			UpstreamPort:    &newPort,
			UpstreamScheme:  &scheme,
			SSLMode:         &sslMode,
			EnableWebSocket: &websocket,
		}, nil)
		return err
	}

	// Create new
	_, err = s.CreateHost(ctx, &models.CreateProxyHostInput{
		Name:              containerName,
		Domains:           []string{domain},
		UpstreamScheme:    models.ProxyUpstreamHTTP,
		UpstreamHost:      containerName,
		UpstreamPort:      port,
		SSLMode:           sslMode,
		SSLForceHTTPS:     sslMode != models.ProxySSLModeNone,
		EnableWebSocket:   websocket,
		EnableCompression: true,
		EnableHSTS:        sslMode != models.ProxySSLModeNone,
		EnableHTTP2:       true,
		ContainerID:       containerID,
		ContainerName:     containerName,
	}, nil)

	return err
}

// ============================================================================
// Helpers
// ============================================================================

func (s *Service) auditLog(ctx context.Context, hostID uuid.UUID, userID *uuid.UUID, action, resourceType string, resourceID uuid.UUID, resourceName, details string) {
	entry := &models.ProxyAuditLog{
		HostID:       hostID,
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		ResourceName: resourceName,
		Details:      details,
	}
	if err := s.audit.Create(ctx, entry); err != nil {
		s.logger.Error("Failed to write proxy audit log", "action", action, "error", err)
	}
}

func maskToken(token string) string {
	if len(token) <= 4 {
		return "****"
	}
	return "****" + token[len(token)-4:]
}
