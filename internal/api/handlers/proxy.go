// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/proxy"
)

// ProxyHandler handles reverse proxy API endpoints.
type ProxyHandler struct {
	BaseHandler
	proxyService *proxy.Service
}

// NewProxyHandler creates a new proxy handler.
func NewProxyHandler(proxyService *proxy.Service, log *logger.Logger) *ProxyHandler {
	return &ProxyHandler{
		BaseHandler:  NewBaseHandler(log),
		proxyService: proxyService,
	}
}

// =============================================================================
// Proxy Hosts
// =============================================================================

// ListHosts returns all proxy hosts.
// GET /api/proxy/hosts
func (h *ProxyHandler) ListHosts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hosts, err := h.proxyService.ListHosts(ctx)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, hosts)
}

// GetHost returns a single proxy host by ID.
// GET /api/proxy/hosts/{id}
func (h *ProxyHandler) GetHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.BadRequest(w, "invalid proxy host ID")
		return
	}

	host, err := h.proxyService.GetHost(ctx, id)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, host)
}

// CreateProxyHostRequest is the request body for creating a proxy host.
type CreateProxyHostRequest struct {
	Name                string                     `json:"name"`
	Domains             []string                   `json:"domains"`
	UpstreamScheme      models.ProxyUpstreamScheme `json:"upstream_scheme"`
	UpstreamHost        string                     `json:"upstream_host"`
	UpstreamPort        int                        `json:"upstream_port"`
	UpstreamPath        string                     `json:"upstream_path,omitempty"`
	SSLMode             models.ProxySSLMode        `json:"ssl_mode"`
	SSLForceHTTPS       bool                       `json:"ssl_force_https"`
	CertificateID       *uuid.UUID                 `json:"certificate_id,omitempty"`
	DNSProviderID       *uuid.UUID                 `json:"dns_provider_id,omitempty"`
	EnableWebSocket     bool                       `json:"enable_websocket"`
	EnableCompression   bool                       `json:"enable_compression"`
	EnableHSTS          bool                       `json:"enable_hsts"`
	EnableHTTP2         bool                       `json:"enable_http2"`
	HealthCheckEnabled  bool                       `json:"health_check_enabled"`
	HealthCheckPath     string                     `json:"health_check_path,omitempty"`
	HealthCheckInterval int                        `json:"health_check_interval,omitempty"`
	ContainerID         string                     `json:"container_id,omitempty"`
	ContainerName       string                     `json:"container_name,omitempty"`
}

// CreateHost creates a new proxy host.
// POST /api/proxy/hosts
func (h *ProxyHandler) CreateHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateProxyHostRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.BadRequest(w, "invalid request body")
		return
	}

	// Validation
	if req.Name == "" {
		h.BadRequest(w, "name is required")
		return
	}
	if len(req.Domains) == 0 {
		h.BadRequest(w, "at least one domain is required")
		return
	}
	if req.UpstreamHost == "" {
		h.BadRequest(w, "upstream_host is required")
		return
	}
	if req.UpstreamPort <= 0 || req.UpstreamPort > 65535 {
		h.BadRequest(w, "upstream_port must be between 1 and 65535")
		return
	}

	userID, _ := h.GetUserID(r)

	input := &models.CreateProxyHostInput{
		Name:                req.Name,
		Domains:             req.Domains,
		UpstreamScheme:      req.UpstreamScheme,
		UpstreamHost:        req.UpstreamHost,
		UpstreamPort:        req.UpstreamPort,
		UpstreamPath:        req.UpstreamPath,
		SSLMode:             req.SSLMode,
		SSLForceHTTPS:       req.SSLForceHTTPS,
		CertificateID:       req.CertificateID,
		DNSProviderID:       req.DNSProviderID,
		EnableWebSocket:     req.EnableWebSocket,
		EnableCompression:   req.EnableCompression,
		EnableHSTS:          req.EnableHSTS,
		EnableHTTP2:         req.EnableHTTP2,
		HealthCheckEnabled:  req.HealthCheckEnabled,
		HealthCheckPath:     req.HealthCheckPath,
		HealthCheckInterval: req.HealthCheckInterval,
		ContainerID:         req.ContainerID,
		ContainerName:       req.ContainerName,
	}

	// Set defaults
	if input.UpstreamScheme == "" {
		input.UpstreamScheme = models.ProxyUpstreamHTTP
	}
	if input.SSLMode == "" {
		input.SSLMode = models.ProxySSLModeAuto
	}

	host, err := h.proxyService.CreateHost(ctx, input, &userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, host)
}

// UpdateProxyHostRequest is the request body for updating a proxy host.
type UpdateProxyHostRequest struct {
	Name                *string                     `json:"name,omitempty"`
	Domains             []string                    `json:"domains,omitempty"`
	UpstreamScheme      *models.ProxyUpstreamScheme `json:"upstream_scheme,omitempty"`
	UpstreamHost        *string                     `json:"upstream_host,omitempty"`
	UpstreamPort        *int                        `json:"upstream_port,omitempty"`
	UpstreamPath        *string                     `json:"upstream_path,omitempty"`
	SSLMode             *models.ProxySSLMode        `json:"ssl_mode,omitempty"`
	SSLForceHTTPS       *bool                       `json:"ssl_force_https,omitempty"`
	CertificateID       *uuid.UUID                  `json:"certificate_id,omitempty"`
	DNSProviderID       *uuid.UUID                  `json:"dns_provider_id,omitempty"`
	Enabled             *bool                       `json:"enabled,omitempty"`
	EnableWebSocket     *bool                       `json:"enable_websocket,omitempty"`
	EnableCompression   *bool                       `json:"enable_compression,omitempty"`
	EnableHSTS          *bool                       `json:"enable_hsts,omitempty"`
	EnableHTTP2         *bool                       `json:"enable_http2,omitempty"`
	HealthCheckEnabled  *bool                       `json:"health_check_enabled,omitempty"`
	HealthCheckPath     *string                     `json:"health_check_path,omitempty"`
	HealthCheckInterval *int                        `json:"health_check_interval,omitempty"`
}

// UpdateHost updates an existing proxy host.
// PUT /api/proxy/hosts/{id}
func (h *ProxyHandler) UpdateHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.BadRequest(w, "invalid proxy host ID")
		return
	}

	var req UpdateProxyHostRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.BadRequest(w, "invalid request body")
		return
	}

	userID, _ := h.GetUserID(r)

	input := &models.UpdateProxyHostInput{
		Name:                req.Name,
		Domains:             req.Domains,
		UpstreamScheme:      req.UpstreamScheme,
		UpstreamHost:        req.UpstreamHost,
		UpstreamPort:        req.UpstreamPort,
		UpstreamPath:        req.UpstreamPath,
		SSLMode:             req.SSLMode,
		SSLForceHTTPS:       req.SSLForceHTTPS,
		CertificateID:       req.CertificateID,
		DNSProviderID:       req.DNSProviderID,
		Enabled:             req.Enabled,
		EnableWebSocket:     req.EnableWebSocket,
		EnableCompression:   req.EnableCompression,
		EnableHSTS:          req.EnableHSTS,
		EnableHTTP2:         req.EnableHTTP2,
		HealthCheckEnabled:  req.HealthCheckEnabled,
		HealthCheckPath:     req.HealthCheckPath,
		HealthCheckInterval: req.HealthCheckInterval,
	}

	host, err := h.proxyService.UpdateHost(ctx, id, input, &userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, host)
}

// DeleteHost deletes a proxy host.
// DELETE /api/proxy/hosts/{id}
func (h *ProxyHandler) DeleteHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.BadRequest(w, "invalid proxy host ID")
		return
	}

	userID, _ := h.GetUserID(r)

	if err := h.proxyService.DeleteHost(ctx, id, &userID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// EnableHost enables a proxy host.
// POST /api/proxy/hosts/{id}/enable
func (h *ProxyHandler) EnableHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.BadRequest(w, "invalid proxy host ID")
		return
	}

	userID, _ := h.GetUserID(r)

	if err := h.proxyService.EnableHost(ctx, id, &userID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]string{"status": "enabled"})
}

// DisableHost disables a proxy host.
// POST /api/proxy/hosts/{id}/disable
func (h *ProxyHandler) DisableHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.BadRequest(w, "invalid proxy host ID")
		return
	}

	userID, _ := h.GetUserID(r)

	if err := h.proxyService.DisableHost(ctx, id, &userID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]string{"status": "disabled"})
}

// =============================================================================
// Custom Headers
// =============================================================================

// SetHeadersRequest is the request body for setting custom headers.
type SetHeadersRequest struct {
	Headers []models.ProxyHeader `json:"headers"`
}

// SetHeaders sets custom headers for a proxy host.
// PUT /api/proxy/hosts/{id}/headers
func (h *ProxyHandler) SetHeaders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.BadRequest(w, "invalid proxy host ID")
		return
	}

	var req SetHeadersRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.BadRequest(w, "invalid request body")
		return
	}

	// Set proxy host ID for each header
	for i := range req.Headers {
		req.Headers[i].ProxyHostID = id
		if req.Headers[i].ID == uuid.Nil {
			req.Headers[i].ID = uuid.New()
		}
	}

	if err := h.proxyService.SetCustomHeaders(ctx, id, req.Headers); err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]string{"status": "headers updated"})
}

// =============================================================================
// Certificates
// =============================================================================

// ListCertificates returns all certificates.
// GET /api/proxy/certificates
func (h *ProxyHandler) ListCertificates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	certs, err := h.proxyService.ListCertificates(ctx)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, certs)
}

// UploadCertificateRequest is the request body for uploading a certificate.
type UploadCertificateRequest struct {
	Name     string   `json:"name"`
	Domains  []string `json:"domains"`
	CertPEM  string   `json:"cert_pem"`
	KeyPEM   string   `json:"key_pem"`
	ChainPEM string   `json:"chain_pem,omitempty"`
}

// UploadCertificate uploads a custom certificate.
// POST /api/proxy/certificates
func (h *ProxyHandler) UploadCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req UploadCertificateRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.BadRequest(w, "invalid request body")
		return
	}

	if req.Name == "" {
		h.BadRequest(w, "name is required")
		return
	}
	if len(req.Domains) == 0 {
		h.BadRequest(w, "at least one domain is required")
		return
	}
	if req.CertPEM == "" || req.KeyPEM == "" {
		h.BadRequest(w, "cert_pem and key_pem are required")
		return
	}

	userID, _ := h.GetUserID(r)

	cert, err := h.proxyService.UploadCertificate(ctx, req.Name, req.Domains, req.CertPEM, req.KeyPEM, req.ChainPEM, &userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, cert)
}

// DeleteCertificate deletes a certificate.
// DELETE /api/proxy/certificates/{id}
func (h *ProxyHandler) DeleteCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.BadRequest(w, "invalid certificate ID")
		return
	}

	userID, _ := h.GetUserID(r)

	if err := h.proxyService.DeleteCertificate(ctx, id, &userID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// =============================================================================
// DNS Providers
// =============================================================================

// ListDNSProviders returns all DNS providers.
// GET /api/proxy/dns-providers
func (h *ProxyHandler) ListDNSProviders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	providers, err := h.proxyService.ListDNSProviders(ctx)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, providers)
}

// CreateDNSProviderRequest is the request body for creating a DNS provider.
type CreateDNSProviderRequest struct {
	Name        string `json:"name"`
	Provider    string `json:"provider"`
	APIToken    string `json:"api_token"`
	Zone        string `json:"zone,omitempty"`
	Propagation int    `json:"propagation,omitempty"`
	IsDefault   bool   `json:"is_default"`
}

// CreateDNSProvider creates a new DNS provider.
// POST /api/proxy/dns-providers
func (h *ProxyHandler) CreateDNSProvider(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateDNSProviderRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.BadRequest(w, "invalid request body")
		return
	}

	if req.Name == "" {
		h.BadRequest(w, "name is required")
		return
	}
	if req.Provider == "" {
		h.BadRequest(w, "provider is required")
		return
	}
	if req.APIToken == "" {
		h.BadRequest(w, "api_token is required")
		return
	}

	userID, _ := h.GetUserID(r)

	provider, err := h.proxyService.CreateDNSProvider(ctx, req.Name, req.Provider, req.APIToken, req.Zone, req.Propagation, req.IsDefault, &userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, provider)
}

// DeleteDNSProvider deletes a DNS provider.
// DELETE /api/proxy/dns-providers/{id}
func (h *ProxyHandler) DeleteDNSProvider(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.BadRequest(w, "invalid DNS provider ID")
		return
	}

	userID, _ := h.GetUserID(r)

	if err := h.proxyService.DeleteDNSProvider(ctx, id, &userID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// =============================================================================
// Health & Status
// =============================================================================

// ProxyHealthResponse is the response for proxy health checks.
type ProxyHealthResponse struct {
	Healthy bool   `json:"healthy"`
	Message string `json:"message,omitempty"`
}

// GetHealth returns the health status of the proxy backend (Caddy).
// GET /api/proxy/health
func (h *ProxyHandler) GetHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	healthy, err := h.proxyService.CaddyHealthy(ctx)
	if err != nil {
		h.OK(w, ProxyHealthResponse{Healthy: false, Message: err.Error()})
		return
	}

	h.OK(w, ProxyHealthResponse{Healthy: healthy})
}

// GetUpstreamStatus returns the health status of all upstreams.
// GET /api/proxy/upstreams
func (h *ProxyHandler) GetUpstreamStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	status, err := h.proxyService.UpstreamStatus(ctx)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, status)
}

// SyncToCaddy forces a sync to Caddy.
// POST /api/proxy/sync
func (h *ProxyHandler) SyncToCaddy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := h.proxyService.SyncToCaddy(ctx); err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]string{"status": "synced"})
}

// =============================================================================
// Audit Logs
// =============================================================================

// ListAuditLogs returns proxy audit logs.
// GET /api/proxy/audit-logs
func (h *ProxyHandler) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	pagination := h.GetPagination(r)

	logs, total, err := h.proxyService.ListAuditLogs(ctx, pagination.PerPage, pagination.Offset)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, NewPaginatedResponse(logs, int64(total), pagination))
}

// =============================================================================
// Supported Providers
// =============================================================================

// GetSupportedDNSProviders returns the list of supported DNS providers.
// GET /api/proxy/dns-providers/supported
func (h *ProxyHandler) GetSupportedDNSProviders(w http.ResponseWriter, r *http.Request) {
	// Return list of supported providers
	providers := make([]map[string]string, 0, len(models.SupportedDNSProviders))
	for name := range models.SupportedDNSProviders {
		providers = append(providers, map[string]string{
			"id":   name,
			"name": name,
		})
	}

	h.OK(w, providers)
}
