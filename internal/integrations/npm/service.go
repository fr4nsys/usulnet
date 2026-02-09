// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package npm provides NPM integration services including auto-proxy.
package npm

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// ConnectionCreate is an alias for models.NPMConnectionCreate.
type ConnectionCreate = models.NPMConnectionCreate

// ConnectionUpdate is an alias for models.NPMConnectionUpdate.
type ConnectionUpdate = models.NPMConnectionUpdate

// Service provides NPM integration functionality.
type Service struct {
	npmConnRepo    *postgres.NPMConnectionRepository
	mappingRepo    *postgres.ContainerProxyMappingRepository
	auditRepo      *postgres.NPMAuditLogRepository
	encryptor      *crypto.AESEncryptor
	logger         *zap.Logger
	clients        map[string]*Client // hostID -> NPM client
}

// NewService creates a new NPM integration service.
func NewService(
	npmConnRepo *postgres.NPMConnectionRepository,
	mappingRepo *postgres.ContainerProxyMappingRepository,
	auditRepo *postgres.NPMAuditLogRepository,
	encryptor *crypto.AESEncryptor,
	logger *zap.Logger,
) *Service {
	return &Service{
		npmConnRepo: npmConnRepo,
		mappingRepo: mappingRepo,
		auditRepo:   auditRepo,
		encryptor:   encryptor,
		logger:      logger,
		clients:     make(map[string]*Client),
	}
}

// =============================================================================
// models.NPMConnection Management
// =============================================================================

// nullableStr returns a pointer to s, or nil if s is empty.
func nullableStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ConfigureConnection configures NPM connection for a Docker host.
func (s *Service) ConfigureConnection(ctx context.Context, hostID string, create *ConnectionCreate, userID string) (*models.NPMConnection, error) {
	// Encrypt password
	encryptedPassword, err := s.encryptor.EncryptString(create.AdminPassword)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to encrypt password")
	}

	// Check if connection already exists for this host (idempotent)
	existing, _ := s.npmConnRepo.GetByHostID(ctx, hostID)
	if existing != nil {
		// Update existing connection
		existing.BaseURL = strings.TrimSuffix(create.BaseURL, "/")
		existing.AdminEmail = create.AdminEmail
		existing.AdminPasswordEncrypted = encryptedPassword
		existing.IsEnabled = true
		existing.UpdatedAt = time.Now()
		existing.UpdatedBy = nullableStr(userID)

		// Test connection before saving
		client, err := s.createClient(existing)
		if err != nil {
			return nil, err
		}
		if err := client.Health(ctx); err != nil {
			return nil, errors.Wrap(err, errors.CodeNPMConnectionFailed, "failed to connect to NPM")
		}

		if err := s.npmConnRepo.Update(ctx, existing); err != nil {
			return nil, err
		}
		s.npmConnRepo.UpdateHealthStatus(ctx, existing.ID, models.NPMHealthStatusHealthy, "")
		s.clients[hostID] = client

		s.logger.Info("NPM connection updated (existing)",
			zap.String("host_id", hostID),
			zap.String("base_url", existing.BaseURL))
		return existing, nil
	}

	conn := &models.NPMConnection{
		ID:                     uuid.New().String(),
		HostID:                 hostID,
		BaseURL:                strings.TrimSuffix(create.BaseURL, "/"),
		AdminEmail:             create.AdminEmail,
		AdminPasswordEncrypted: encryptedPassword,
		IsEnabled:              true,
		HealthStatus:           models.NPMHealthStatusUnknown,
		CreatedAt:              time.Now(),
		UpdatedAt:              time.Now(),
		CreatedBy:              nullableStr(userID),
		UpdatedBy:              nullableStr(userID),
	}

	// Test connection before saving
	client, err := s.createClient(conn)
	if err != nil {
		return nil, err
	}

	if err := client.Health(ctx); err != nil {
		return nil, errors.Wrap(err, errors.CodeNPMConnectionFailed, "failed to connect to NPM")
	}

	// Save connection
	if err := s.npmConnRepo.Create(ctx, conn); err != nil {
		return nil, err
	}

	// Update health status
	s.npmConnRepo.UpdateHealthStatus(ctx, conn.ID, models.NPMHealthStatusHealthy, "")

	// Cache client
	s.clients[hostID] = client

	s.logger.Info("NPM connection configured",
		zap.String("host_id", hostID),
		zap.String("base_url", conn.BaseURL))

	return conn, nil
}

// GetConnection gets the NPM connection for a Docker host.
func (s *Service) GetConnection(ctx context.Context, hostID string) (*models.NPMConnection, error) {
	return s.npmConnRepo.GetByHostID(ctx, hostID)
}

// UpdateConnection updates the NPM connection for a Docker host.
func (s *Service) UpdateConnection(ctx context.Context, id string, update *ConnectionUpdate, userID string) (*models.NPMConnection, error) {
	conn, err := s.npmConnRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if update.BaseURL != nil {
		conn.BaseURL = strings.TrimSuffix(*update.BaseURL, "/")
	}
	if update.AdminEmail != nil {
		conn.AdminEmail = *update.AdminEmail
	}
	if update.AdminPassword != nil {
		encryptedPassword, err := s.encryptor.EncryptString(*update.AdminPassword)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to encrypt password")
		}
		conn.AdminPasswordEncrypted = encryptedPassword
	}
	if update.IsEnabled != nil {
		conn.IsEnabled = *update.IsEnabled
	}
	conn.UpdatedBy = nullableStr(userID)

	if err := s.npmConnRepo.Update(ctx, conn); err != nil {
		return nil, err
	}

	// Invalidate cached client
	delete(s.clients, conn.HostID)

	return conn, nil
}

// DeleteConnection deletes the NPM connection for a Docker host.
func (s *Service) DeleteConnection(ctx context.Context, id string) error {
	conn, err := s.npmConnRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if err := s.npmConnRepo.Delete(ctx, id); err != nil {
		return err
	}

	delete(s.clients, conn.HostID)
	return nil
}

// TestConnection tests the NPM connection.
func (s *Service) TestConnection(ctx context.Context, hostID string) error {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	if err := client.Health(ctx); err != nil {
		s.npmConnRepo.UpdateHealthStatus(ctx, hostID, models.NPMHealthStatusUnhealthy, err.Error())
		return err
	}

	s.npmConnRepo.UpdateHealthStatus(ctx, hostID, models.NPMHealthStatusHealthy, "")
	return nil
}

// GetClient returns the NPM client for a Docker host.
func (s *Service) GetClient(ctx context.Context, hostID string) (*Client, error) {
	// Check cache
	if client, ok := s.clients[hostID]; ok {
		return client, nil
	}

	// Load connection from DB
	conn, err := s.npmConnRepo.GetByHostID(ctx, hostID)
	if err != nil {
		return nil, err
	}

	if !conn.IsEnabled {
		return nil, errors.New(errors.CodeNPMNotConfigured, "NPM connection is disabled")
	}

	client, err := s.createClient(conn)
	if err != nil {
		return nil, err
	}

	s.clients[hostID] = client
	return client, nil
}

func (s *Service) createClient(conn *models.NPMConnection) (*Client, error) {
	// Decrypt password
	password, err := s.encryptor.DecryptString(conn.AdminPasswordEncrypted)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decrypt password")
	}

	return NewClient(&Config{
		BaseURL:  conn.BaseURL,
		Email:    conn.AdminEmail,
		Password: password,
	}, s.logger), nil
}

// =============================================================================
// Auto-Proxy
// =============================================================================

// ExtractProxyConfig extracts auto-proxy configuration from container labels.
func (s *Service) ExtractProxyConfig(containerInfo *container.InspectResponse) *models.AutoProxyConfig {
	labels := containerInfo.Config.Labels
	
	domain, ok := labels[models.LabelProxyDomain]
	if !ok || domain == "" {
		return nil // No auto-proxy configured
	}

	config := &models.AutoProxyConfig{
		ContainerID:   containerInfo.ID,
		ContainerName: strings.TrimPrefix(containerInfo.Name, "/"),
		Domain:        domain,
		Scheme:        "http",
		SSL:           true,
		SSLForced:     true,
		BlockExploits: true,
	}

	// Port (default: first exposed port)
	if portStr, ok := labels[models.LabelProxyPort]; ok {
		if port, err := strconv.Atoi(portStr); err == nil {
			config.Port = port
		}
	} else {
		// Find first exposed port
		for port := range containerInfo.Config.ExposedPorts {
			config.Port = port.Int()
			break
		}
	}

	// Scheme
	if scheme, ok := labels[models.LabelProxyScheme]; ok {
		config.Scheme = scheme
	}

	// SSL
	if ssl, ok := labels[models.LabelProxySSL]; ok {
		config.SSL = ssl == "true" || ssl == "1"
	}

	// SSL Forced
	if sslForced, ok := labels[models.LabelProxySSLForced]; ok {
		config.SSLForced = sslForced == "true" || sslForced == "1"
	}

	// WebSocket
	if ws, ok := labels[models.LabelProxyWebsocket]; ok {
		config.Websocket = ws == "true" || ws == "1"
	}

	// Block Exploits
	if block, ok := labels[models.LabelProxyBlockExploit]; ok {
		config.BlockExploits = block == "true" || block == "1"
	}

	return config
}

// CreateAutoProxy creates an NPM proxy host from container configuration.
func (s *Service) CreateAutoProxy(ctx context.Context, hostID string, config *models.AutoProxyConfig, userID string) (*ProxyHost, error) {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	// Check if mapping already exists
	existing, err := s.mappingRepo.GetByContainerID(ctx, hostID, config.ContainerID)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		// Update existing proxy host
		return s.UpdateAutoProxy(ctx, hostID, config, userID)
	}

	// Resolve container IP
	// In a real implementation, you'd get this from the Docker network
	forwardHost := config.ContainerName // Using container name as hostname (requires same Docker network)

	proxyHost := &ProxyHost{
		DomainNames:          []string{config.Domain},
		ForwardScheme:        config.Scheme,
		ForwardHost:          forwardHost,
		ForwardPort:          config.Port,
		SSLForced:            config.SSLForced,
		BlockExploits:        config.BlockExploits,
		AllowWebsocketUpgrade: config.Websocket,
		Enabled:              true,
		Meta: map[string]interface{}{
			"usulnet_auto_proxy": true,
			"container_id":       config.ContainerID,
			"container_name":     config.ContainerName,
		},
	}

	// Request certificate if SSL enabled
	if config.SSL {
		proxyHost.CertificateID = "new" // NPM will create Let's Encrypt cert
	}

	created, err := client.CreateProxyHost(ctx, proxyHost)
	if err != nil {
		return nil, err
	}

	// Save mapping
	mapping := &models.ContainerProxyMapping{
		ID:             uuid.New().String(),
		HostID:         hostID,
		ContainerID:    config.ContainerID,
		ContainerName:  config.ContainerName,
		NPMProxyHostID: created.ID,
		AutoCreated:    true,
		DomainSource:   "label",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	if err := s.mappingRepo.Create(ctx, mapping); err != nil {
		s.logger.Warn("failed to save container proxy mapping", zap.Error(err))
	}

	// Audit log
	s.logAudit(ctx, hostID, userID, models.NPMOperationCreate, models.NPMResourceProxyHost, created.ID, config.Domain, map[string]interface{}{
		"auto_proxy":      true,
		"container_id":    config.ContainerID,
		"container_name":  config.ContainerName,
	})

	s.logger.Info("auto-proxy created",
		zap.String("container", config.ContainerName),
		zap.String("domain", config.Domain),
		zap.Int("npm_id", created.ID))

	return created, nil
}

// UpdateAutoProxy updates an existing auto-proxy.
func (s *Service) UpdateAutoProxy(ctx context.Context, hostID string, config *models.AutoProxyConfig, userID string) (*ProxyHost, error) {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	mapping, err := s.mappingRepo.GetByContainerID(ctx, hostID, config.ContainerID)
	if err != nil {
		return nil, err
	}
	if mapping == nil {
		return s.CreateAutoProxy(ctx, hostID, config, userID)
	}

	forwardHost := config.ContainerName

	proxyHost := &ProxyHost{
		DomainNames:          []string{config.Domain},
		ForwardScheme:        config.Scheme,
		ForwardHost:          forwardHost,
		ForwardPort:          config.Port,
		SSLForced:            config.SSLForced,
		BlockExploits:        config.BlockExploits,
		AllowWebsocketUpgrade: config.Websocket,
		Enabled:              true,
		Meta: map[string]interface{}{
			"usulnet_auto_proxy": true,
			"container_id":       config.ContainerID,
			"container_name":     config.ContainerName,
		},
	}

	updated, err := client.UpdateProxyHost(ctx, mapping.NPMProxyHostID, proxyHost)
	if err != nil {
		return nil, err
	}

	s.logAudit(ctx, hostID, userID, models.NPMOperationUpdate, models.NPMResourceProxyHost, updated.ID, config.Domain, nil)

	return updated, nil
}

// DeleteAutoProxy deletes an auto-proxy when container is removed.
func (s *Service) DeleteAutoProxy(ctx context.Context, hostID, containerID string, userID string) error {
	mapping, err := s.mappingRepo.GetByContainerID(ctx, hostID, containerID)
	if err != nil {
		return err
	}
	if mapping == nil {
		return nil // No mapping exists
	}

	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	if err := client.DeleteProxyHost(ctx, mapping.NPMProxyHostID); err != nil {
		s.logger.Warn("failed to delete NPM proxy host", zap.Error(err))
		// Continue to delete mapping anyway
	}

	if err := s.mappingRepo.Delete(ctx, hostID, containerID); err != nil {
		return err
	}

	s.logAudit(ctx, hostID, userID, models.NPMOperationDelete, models.NPMResourceProxyHost, mapping.NPMProxyHostID, mapping.ContainerName, nil)

	s.logger.Info("auto-proxy deleted",
		zap.String("container_id", containerID),
		zap.Int("npm_id", mapping.NPMProxyHostID))

	return nil
}

// GetContainerMappings returns all container-proxy mappings for a host.
func (s *Service) GetContainerMappings(ctx context.Context, hostID string) ([]*models.ContainerProxyMapping, error) {
	return s.mappingRepo.ListByHost(ctx, hostID)
}

// =============================================================================
// Audit
// =============================================================================

func (s *Service) logAudit(ctx context.Context, hostID, userID, operation, resourceType string, resourceID int, resourceName string, details map[string]interface{}) {
	log := &models.NPMAuditLog{
		ID:           uuid.New().String(),
		HostID:       hostID,
		Operation:    operation,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		ResourceName: resourceName,
		Details:      details,
		CreatedAt:    time.Now(),
	}
	if userID != "" {
		log.UserID = &userID
	}

	if err := s.auditRepo.Create(ctx, log); err != nil {
		s.logger.Warn("failed to create audit log", zap.Error(err))
	}
}

// GetAuditLogs returns audit logs for a host.
func (s *Service) GetAuditLogs(ctx context.Context, hostID string, limit, offset int) ([]*models.NPMAuditLog, int, error) {
	logs, err := s.auditRepo.ListByHost(ctx, hostID, limit, offset)
	if err != nil {
		return nil, 0, err
	}

	total, err := s.auditRepo.CountByHost(ctx, hostID)
	if err != nil {
		return nil, 0, err
	}

	return logs, total, nil
}

// =============================================================================
// Client Wrapper Methods for API Handler
// =============================================================================

// CheckHealth checks if the NPM instance for a host is healthy.
func (s *Service) CheckHealth(ctx context.Context, hostID string) (bool, error) {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return false, err
	}
	if err := client.Health(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// ListProxyHosts returns all proxy hosts from NPM.
func (s *Service) ListProxyHosts(ctx context.Context, hostID string) ([]*ProxyHost, error) {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}
	return client.ListProxyHosts(ctx)
}

// GetProxyHost returns a proxy host by ID.
func (s *Service) GetProxyHost(ctx context.Context, hostID string, proxyID int) (*ProxyHost, error) {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}
	return client.GetProxyHost(ctx, proxyID)
}

// CreateProxyHost creates a new proxy host in NPM.
func (s *Service) CreateProxyHost(ctx context.Context, hostID string, host *ProxyHostCreate, userID string) (*ProxyHost, error) {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	ph := &ProxyHost{
		DomainNames:           host.DomainNames,
		ForwardScheme:         host.ForwardScheme,
		ForwardHost:           host.ForwardHost,
		ForwardPort:           host.ForwardPort,
		CachingEnabled:        host.CachingEnabled,
		BlockExploits:         host.BlockExploits,
		AllowWebsocketUpgrade: host.AllowWebsocket,
		HTTP2Support:          host.HTTP2Support,
		SSLForced:             host.SSLForced,
		HSTSEnabled:           host.HSTSEnabled,
		HSTSSubdomains:        host.HSTSSubdomains,
		CertificateID:         host.CertificateID,
		AccessListID:          host.AccessListID,
		AdvancedConfig:        host.AdvancedConfig,
		Enabled:               true,
	}

	result, err := client.CreateProxyHost(ctx, ph)
	if err != nil {
		return nil, err
	}

	s.logAudit(ctx, hostID, userID, models.NPMOperationCreate, models.NPMResourceProxyHost, result.ID, host.DomainNames[0], nil)
	return result, nil
}

// UpdateProxyHost updates a proxy host in NPM.
func (s *Service) UpdateProxyHost(ctx context.Context, hostID string, proxyID int, host *ProxyHostUpdate, userID string) (*ProxyHost, error) {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	existing, err := client.GetProxyHost(ctx, proxyID)
	if err != nil {
		return nil, err
	}

	if host.DomainNames != nil {
		existing.DomainNames = host.DomainNames
	}
	if host.ForwardScheme != nil {
		existing.ForwardScheme = *host.ForwardScheme
	}
	if host.ForwardHost != nil {
		existing.ForwardHost = *host.ForwardHost
	}
	if host.ForwardPort != nil {
		existing.ForwardPort = *host.ForwardPort
	}
	if host.SSLForced != nil {
		existing.SSLForced = *host.SSLForced
	}
	if host.CertificateID != nil {
		existing.CertificateID = host.CertificateID
	}
	if host.Enabled != nil {
		existing.Enabled = *host.Enabled
	}

	result, err := client.UpdateProxyHost(ctx, proxyID, existing)
	if err != nil {
		return nil, err
	}

	s.logAudit(ctx, hostID, userID, models.NPMOperationUpdate, models.NPMResourceProxyHost, proxyID, existing.DomainNames[0], nil)
	return result, nil
}

// DeleteProxyHost deletes a proxy host from NPM.
func (s *Service) DeleteProxyHost(ctx context.Context, hostID string, proxyID int, userID string) error {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	existing, _ := client.GetProxyHost(ctx, proxyID)
	name := ""
	if existing != nil && len(existing.DomainNames) > 0 {
		name = existing.DomainNames[0]
	}

	if err := client.DeleteProxyHost(ctx, proxyID); err != nil {
		return err
	}

	s.logAudit(ctx, hostID, userID, models.NPMOperationDelete, models.NPMResourceProxyHost, proxyID, name, nil)
	return nil
}

// EnableProxyHost enables a proxy host in NPM.
func (s *Service) EnableProxyHost(ctx context.Context, hostID string, proxyID int, userID string) error {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return err
	}
	if err := client.EnableProxyHost(ctx, proxyID); err != nil {
		return err
	}
	s.logAudit(ctx, hostID, userID, models.NPMOperationEnable, models.NPMResourceProxyHost, proxyID, "", nil)
	return nil
}

// DisableProxyHost disables a proxy host in NPM.
func (s *Service) DisableProxyHost(ctx context.Context, hostID string, proxyID int, userID string) error {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return err
	}
	if err := client.DisableProxyHost(ctx, proxyID); err != nil {
		return err
	}
	s.logAudit(ctx, hostID, userID, models.NPMOperationDisable, models.NPMResourceProxyHost, proxyID, "", nil)
	return nil
}

// ListCertificates returns all certificates from NPM.
func (s *Service) ListCertificates(ctx context.Context, hostID string) ([]*Certificate, error) {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}
	return client.ListCertificates(ctx)
}

// RequestLetsEncrypt requests a Let's Encrypt certificate.
func (s *Service) RequestLetsEncrypt(ctx context.Context, hostID string, domainNames []string, email string) (*Certificate, error) {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}
	req := &CertificateRequest{
		DomainNames:      domainNames,
		LetsencryptEmail: email,
		LetsencryptAgree: true,
	}
	return client.RequestLetsEncryptCertificate(ctx, req)
}

// DeleteCertificate deletes a certificate from NPM.
func (s *Service) DeleteCertificate(ctx context.Context, hostID string, certID int) error {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return err
	}
	return client.DeleteCertificate(ctx, certID)
}

// ListRedirections returns all redirections from NPM.
func (s *Service) ListRedirections(ctx context.Context, hostID string) ([]*RedirectionHost, error) {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}
	return client.ListRedirectionHosts(ctx)
}

// CreateRedirection creates a new redirection in NPM.
func (s *Service) CreateRedirection(ctx context.Context, hostID string, redir *RedirectionCreate, userID string) (*RedirectionHost, error) {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	rh := &RedirectionHost{
		DomainNames:       redir.DomainNames,
		ForwardScheme:     redir.ForwardScheme,
		ForwardDomainName: redir.ForwardDomain,
		ForwardHTTPCode:   redir.ForwardHTTPCode,
		PreservePath:      redir.PreservePath,
		SSLForced:         redir.SSLForced,
		CertificateID:     redir.CertificateID,
		Enabled:           true,
	}

	result, err := client.CreateRedirectionHost(ctx, rh)
	if err != nil {
		return nil, err
	}

	s.logAudit(ctx, hostID, userID, models.NPMOperationCreate, models.NPMResourceRedirection, result.ID, redir.DomainNames[0], nil)
	return result, nil
}

// DeleteRedirection deletes a redirection from NPM.
func (s *Service) DeleteRedirection(ctx context.Context, hostID string, redirID int, userID string) error {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return err
	}
	if err := client.DeleteRedirectionHost(ctx, redirID); err != nil {
		return err
	}
	s.logAudit(ctx, hostID, userID, models.NPMOperationDelete, models.NPMResourceRedirection, redirID, "", nil)
	return nil
}

// ListAccessLists returns all access lists from NPM.
func (s *Service) ListAccessLists(ctx context.Context, hostID string) ([]*AccessList, error) {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}
	return client.ListAccessLists(ctx)
}

// CreateAccessList creates a new access list in NPM.
func (s *Service) CreateAccessList(ctx context.Context, hostID string, list *AccessListCreate, userID string) (*AccessList, error) {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	al := &AccessList{
		Name:       list.Name,
		SatisfyAny: list.SatisfyAny,
		PassAuth:   list.PassAuth,
		Items:      list.Items,
		Clients:    list.Clients,
	}

	result, err := client.CreateAccessList(ctx, al)
	if err != nil {
		return nil, err
	}

	s.logAudit(ctx, hostID, userID, models.NPMOperationCreate, "access_list", result.ID, list.Name, nil)
	return result, nil
}

// DeleteAccessList deletes an access list from NPM.
func (s *Service) DeleteAccessList(ctx context.Context, hostID string, listID int, userID string) error {
	client, err := s.GetClient(ctx, hostID)
	if err != nil {
		return err
	}
	if err := client.DeleteAccessList(ctx, listID); err != nil {
		return err
	}
	s.logAudit(ctx, hostID, userID, models.NPMOperationDelete, "access_list", listID, "", nil)
	return nil
}

// ListAuditLogs returns NPM audit logs for a host.
func (s *Service) ListAuditLogs(ctx context.Context, hostID string, limit, offset int) ([]*models.NPMAuditLog, int, error) {
	return s.GetAuditLogs(ctx, hostID, limit, offset)
}

// =============================================================================
// Health Check Worker
// =============================================================================

// StartHealthCheckWorker starts a background worker to check NPM health.
// AutoConnect attempts to establish an NPM connection from config credentials.
// If a connection already exists for the hostID, it verifies/updates it.
// Returns true if connection is active and healthy.
func (s *Service) AutoConnect(ctx context.Context, hostID, baseURL, email, password, userID string) (bool, error) {
	if baseURL == "" || email == "" || password == "" {
		return false, nil // No credentials configured, skip silently
	}

	// Check if connection already exists
	existing, err := s.npmConnRepo.GetByHostID(ctx, hostID)
	if err != nil {
		s.logger.Warn("Failed to check existing NPM connection", zap.Error(err))
	}

	if existing != nil {
		// Connection exists - test it
		if err := s.TestConnection(ctx, hostID); err == nil {
			s.logger.Info("NPM auto-connect: existing connection is healthy",
				zap.String("host_id", hostID),
				zap.String("base_url", existing.BaseURL))
			return true, nil
		}

		// Existing connection unhealthy - update credentials
		s.logger.Info("NPM auto-connect: updating existing connection credentials",
			zap.String("host_id", hostID))
		pURL := &baseURL
		pEmail := &email
		pPwd := &password
		update := &ConnectionUpdate{
			BaseURL:       pURL,
			AdminEmail:    pEmail,
			AdminPassword: pPwd,
		}
		if _, err := s.UpdateConnection(ctx, existing.ID, update, userID); err != nil {
			s.logger.Warn("NPM auto-connect: failed to update credentials", zap.Error(err))
		}
		// Test again - if still fails, health check worker will retry
		if err := s.TestConnection(ctx, hostID); err != nil {
			s.logger.Warn("NPM auto-connect: connection unhealthy, health check worker will retry",
				zap.Error(err))
			return false, nil
		}
		return true, nil
	}

	// No existing connection - save to DB even if NPM is unreachable
	// Health check worker will retry periodically
	s.logger.Info("NPM auto-connect: creating connection from config",
		zap.String("host_id", hostID),
		zap.String("base_url", baseURL))

	encryptedPassword, err := s.encryptor.EncryptString(password)
	if err != nil {
		return false, errors.Wrap(err, errors.CodeInternal, "failed to encrypt password")
	}

	conn := &models.NPMConnection{
		ID:                     uuid.New().String(),
		HostID:                 hostID,
		BaseURL:                strings.TrimSuffix(baseURL, "/"),
		AdminEmail:             email,
		AdminPasswordEncrypted: encryptedPassword,
		IsEnabled:              true,
		HealthStatus:           models.NPMHealthStatusUnknown,
		CreatedAt:              time.Now(),
		UpdatedAt:              time.Now(),
		CreatedBy:              nullableStr(userID),
		UpdatedBy:              nullableStr(userID),
	}

	if err := s.npmConnRepo.Create(ctx, conn); err != nil {
		return false, errors.Wrap(err, errors.CodeInternal, "failed to save NPM connection")
	}

	// Try to connect - if fails, connection is saved and health check worker will retry
	client, err := s.createClient(conn)
	if err != nil {
		s.npmConnRepo.UpdateHealthStatus(ctx, conn.ID, models.NPMHealthStatusUnhealthy, err.Error())
		s.logger.Warn("NPM auto-connect: saved but unreachable, health check worker will retry",
			zap.Error(err))
		return false, nil
	}

	if err := client.Health(ctx); err != nil {
		s.npmConnRepo.UpdateHealthStatus(ctx, conn.ID, models.NPMHealthStatusUnhealthy, err.Error())
		s.logger.Warn("NPM auto-connect: saved but unhealthy, health check worker will retry",
			zap.Error(err))
		return false, nil
	}

	// Success - cache client
	s.npmConnRepo.UpdateHealthStatus(ctx, conn.ID, models.NPMHealthStatusHealthy, "")
	s.clients[hostID] = client

	s.logger.Info("NPM auto-connect: connection established successfully",
		zap.String("host_id", hostID),
		zap.String("base_url", baseURL))
	return true, nil
}

func (s *Service) StartHealthCheckWorker(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				s.checkAllConnections(ctx)
			}
		}
	}()

	s.logger.Info("NPM health check worker started", zap.Duration("interval", interval))
}

func (s *Service) checkAllConnections(ctx context.Context) {
	connections, err := s.npmConnRepo.List(ctx)
	if err != nil {
		s.logger.Error("failed to list NPM connections", zap.Error(err))
		return
	}

	for _, conn := range connections {
		if !conn.IsEnabled {
			continue
		}

		client, err := s.createClient(conn)
		if err != nil {
			s.npmConnRepo.UpdateHealthStatus(ctx, conn.ID, models.NPMHealthStatusUnhealthy, err.Error())
			// Invalidate cached client so GetClient rebuilds from DB next time
			delete(s.clients, conn.HostID)
			continue
		}

		if err := client.Health(ctx); err != nil {
			s.npmConnRepo.UpdateHealthStatus(ctx, conn.ID, models.NPMHealthStatusUnhealthy, err.Error())
			delete(s.clients, conn.HostID)
			s.logger.Warn("NPM health check failed",
				zap.String("host_id", conn.HostID),
				zap.Error(err))
		} else {
			s.npmConnRepo.UpdateHealthStatus(ctx, conn.ID, models.NPMHealthStatusHealthy, "")
			// Update cached client with fresh credentials from DB
			s.clients[conn.HostID] = client
		}
	}
}
