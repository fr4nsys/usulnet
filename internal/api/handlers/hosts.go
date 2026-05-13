// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/services/host"
)

// HostHandler handles host-related HTTP requests.
type HostHandler struct {
	BaseHandler
	hostService     *host.Service
	licenseProvider middleware.LicenseProvider
}

// NewHostHandler creates a new host handler.
func NewHostHandler(hostService *host.Service, log *logger.Logger) *HostHandler {
	return &HostHandler{
		BaseHandler: NewBaseHandler(log),
		hostService: hostService,
	}
}

// SetLicenseProvider sets the license provider for feature gating.
func (h *HostHandler) SetLicenseProvider(provider middleware.LicenseProvider) {
	h.licenseProvider = provider
}

// Routes returns the router for host endpoints.
func (h *HostHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Read-only routes (viewer+)
	r.Get("/", h.ListHosts)
	r.Get("/summaries", h.ListSummaries)
	r.Get("/stats", h.GetStats)

	// Operator+ for mutations
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireOperator)
		r.Post("/test", h.TestConnection)

		// Node creation enforces MaxNodes limit
		r.Group(func(r chi.Router) {
			if h.licenseProvider != nil {
				r.Use(middleware.RequireLimit(
					h.licenseProvider,
					"nodes",
					func(r *http.Request) int {
						stats, err := h.hostService.GetStats(r.Context())
						if err != nil {
							return 0
						}
						return stats.Total
					},
					func(l license.Limits) int { return l.MaxNodes },
				))
			}
			r.Post("/", h.CreateHost)
		})
	})

	r.Route("/{hostID}", func(r chi.Router) {
		// Read-only (viewer+)
		r.Get("/", h.GetHost)

		// Operator+ for mutations
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireOperator)
			r.Put("/", h.UpdateHost)
			r.Delete("/", h.DeleteHost)
			r.Post("/reconnect", h.Reconnect)
		})
	})

	return r
}

// ============================================================================
// Request/Response types
// ============================================================================

// CreateHostRequest represents a host creation request.
type CreateHostRequest struct {
	Name          string            `json:"name"`
	DisplayName   string            `json:"display_name,omitempty"`
	EndpointType  string            `json:"endpoint_type"`
	EndpointURL   string            `json:"endpoint_url,omitempty"`
	TLSEnabled    bool              `json:"tls_enabled,omitempty"`
	TLSCACert     string            `json:"tls_ca_cert,omitempty"`
	TLSClientCert string            `json:"tls_client_cert,omitempty"`
	TLSClientKey  string            `json:"tls_client_key,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
}

// UpdateHostRequest represents a host update request.
type UpdateHostRequest struct {
	DisplayName   *string           `json:"display_name,omitempty"`
	EndpointURL   *string           `json:"endpoint_url,omitempty"`
	TLSEnabled    *bool             `json:"tls_enabled,omitempty"`
	TLSCACert     *string           `json:"tls_ca_cert,omitempty"`
	TLSClientCert *string           `json:"tls_client_cert,omitempty"`
	TLSClientKey  *string           `json:"tls_client_key,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
}

// HostResponse represents a host in API responses.
type HostResponse struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	DisplayName   string            `json:"display_name,omitempty"`
	EndpointType  string            `json:"endpoint_type"`
	EndpointURL   string            `json:"endpoint_url,omitempty"`
	TLSEnabled    bool              `json:"tls_enabled"`
	Status        string            `json:"status"`
	StatusMessage string            `json:"status_message,omitempty"`
	LastSeenAt    string            `json:"last_seen_at,omitempty"`
	DockerVersion string            `json:"docker_version,omitempty"`
	OSType        string            `json:"os_type,omitempty"`
	Architecture  string            `json:"architecture,omitempty"`
	TotalMemory   int64             `json:"total_memory,omitempty"`
	TotalCPUs     int               `json:"total_cpus,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	CreatedAt     string            `json:"created_at"`
	UpdatedAt     string            `json:"updated_at"`
}

// HostSummaryResponse represents a host summary.
type HostSummaryResponse struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	DisplayName    string  `json:"display_name,omitempty"`
	Status         string  `json:"status"`
	ContainerCount int     `json:"container_count"`
	RunningCount   int     `json:"running_count"`
	CPUPercent     float64 `json:"cpu_percent"`
	MemoryPercent  float64 `json:"memory_percent"`
	DiskPercent    float64 `json:"disk_percent"`
}

// HostStatsResponse represents host statistics.
type HostStatsResponse struct {
	Total   int `json:"total"`
	Online  int `json:"online"`
	Offline int `json:"offline"`
	Error   int `json:"error"`
}

// TestConnectionResponse represents test connection result.
type TestConnectionResponse struct {
	Success       bool   `json:"success"`
	DockerVersion string `json:"docker_version,omitempty"`
	OSType        string `json:"os_type,omitempty"`
	Architecture  string `json:"architecture,omitempty"`
	TotalMemory   int64  `json:"total_memory,omitempty"`
	TotalCPUs     int    `json:"total_cpus,omitempty"`
	ErrorMessage  string `json:"error_message,omitempty"`
}

// ============================================================================
// Handlers
// ============================================================================

// ListHosts returns all hosts.
// GET /api/v1/hosts
func (h *HostHandler) ListHosts(w http.ResponseWriter, r *http.Request) {
	pagination := h.GetPagination(r)

	opts := postgres.HostListOptions{
		Limit:  pagination.PerPage,
		Offset: pagination.Offset,
	}

	// Optional filters
	if status := h.QueryParam(r, "status"); status != "" {
		opts.Status = status
	}
	if endpointType := h.QueryParam(r, "endpoint_type"); endpointType != "" {
		opts.EndpointType = endpointType
	}
	if search := h.QueryParam(r, "search"); search != "" {
		opts.Search = search
	}

	hosts, total, err := h.hostService.List(r.Context(), opts)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]HostResponse, len(hosts))
	for i, host := range hosts {
		resp[i] = toHostResponse(host)
	}

	h.OK(w, NewPaginatedResponse(resp, total, pagination))
}

// CreateHost creates a new host.
// POST /api/v1/hosts
func (h *HostHandler) CreateHost(w http.ResponseWriter, r *http.Request) {
	var req CreateHostRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Name == "" {
		h.BadRequest(w, "name is required")
		return
	}
	if req.EndpointType == "" {
		h.BadRequest(w, "endpoint_type is required")
		return
	}

	input := &models.CreateHostInput{
		Name:         req.Name,
		EndpointType: models.HostEndpointType(req.EndpointType),
		TLSEnabled:   req.TLSEnabled,
		Labels:       req.Labels,
	}

	if req.DisplayName != "" {
		input.DisplayName = &req.DisplayName
	}
	if req.EndpointURL != "" {
		input.EndpointURL = &req.EndpointURL
	}
	if req.TLSCACert != "" {
		input.TLSCACert = &req.TLSCACert
	}
	if req.TLSClientCert != "" {
		input.TLSClientCert = &req.TLSClientCert
	}
	if req.TLSClientKey != "" {
		input.TLSClientKey = &req.TLSClientKey
	}

	host, err := h.hostService.Create(r.Context(), input)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, toHostResponse(host))
}

// GetHost returns a specific host.
// GET /api/v1/hosts/{hostID}
func (h *HostHandler) GetHost(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	host, err := h.hostService.Get(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toHostResponse(host))
}

// UpdateHost updates a host.
// PUT /api/v1/hosts/{hostID}
func (h *HostHandler) UpdateHost(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req UpdateHostRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	input := &models.UpdateHostInput{
		DisplayName:   req.DisplayName,
		EndpointURL:   req.EndpointURL,
		TLSEnabled:    req.TLSEnabled,
		TLSCACert:     req.TLSCACert,
		TLSClientCert: req.TLSClientCert,
		TLSClientKey:  req.TLSClientKey,
		Labels:        req.Labels,
	}

	host, err := h.hostService.Update(r.Context(), hostID, input)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toHostResponse(host))
}

// DeleteHost deletes a host.
// DELETE /api/v1/hosts/{hostID}
func (h *HostHandler) DeleteHost(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.hostService.Delete(r.Context(), hostID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// Reconnect reconnects to a host.
// POST /api/v1/hosts/{hostID}/reconnect
func (h *HostHandler) Reconnect(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.hostService.Reconnect(r.Context(), hostID); err != nil {
		h.HandleError(w, err)
		return
	}

	// Return updated host
	host, err := h.hostService.Get(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toHostResponse(host))
}

// ListSummaries returns host summaries.
// GET /api/v1/hosts/summaries
func (h *HostHandler) ListSummaries(w http.ResponseWriter, r *http.Request) {
	summaries, err := h.hostService.ListSummaries(r.Context())
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]HostSummaryResponse, len(summaries))
	for i, s := range summaries {
		resp[i] = HostSummaryResponse{
			ID:             s.ID.String(),
			Name:           s.Name,
			Status:         string(s.Status),
			ContainerCount: s.ContainerCount,
			RunningCount:   s.RunningCount,
			CPUPercent:     s.CPUPercent,
			MemoryPercent:  s.MemoryPercent,
			DiskPercent:    s.DiskPercent,
		}
		if s.DisplayName != nil {
			resp[i].DisplayName = *s.DisplayName
		}
	}

	h.OK(w, resp)
}

// GetStats returns host statistics.
// GET /api/v1/hosts/stats
func (h *HostHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.hostService.GetStats(r.Context())
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, HostStatsResponse{
		Total:   stats.Total,
		Online:  stats.Online,
		Offline: stats.Offline,
		Error:   stats.Error,
	})
}

// TestConnection tests connection to a host.
// POST /api/v1/hosts/test
func (h *HostHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	var req CreateHostRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	input := &models.CreateHostInput{
		Name:         req.Name,
		EndpointType: models.HostEndpointType(req.EndpointType),
		TLSEnabled:   req.TLSEnabled,
	}

	if req.EndpointURL != "" {
		input.EndpointURL = &req.EndpointURL
	}
	if req.TLSCACert != "" {
		input.TLSCACert = &req.TLSCACert
	}
	if req.TLSClientCert != "" {
		input.TLSClientCert = &req.TLSClientCert
	}
	if req.TLSClientKey != "" {
		input.TLSClientKey = &req.TLSClientKey
	}

	info, err := h.hostService.TestConnection(r.Context(), input)
	if err != nil {
		h.OK(w, TestConnectionResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		})
		return
	}

	resp := TestConnectionResponse{
		Success: true,
	}
	if info != nil {
		resp.DockerVersion = info.ServerVersion
		resp.OSType = info.OSType
		resp.Architecture = info.Architecture
		resp.TotalMemory = info.MemTotal
		resp.TotalCPUs = info.NCPU
	}

	h.OK(w, resp)
}

// ============================================================================
// Helpers
// ============================================================================

func toHostResponse(host *models.Host) HostResponse {
	resp := HostResponse{
		ID:           host.ID.String(),
		Name:         host.Name,
		EndpointType: string(host.EndpointType),
		TLSEnabled:   host.TLSEnabled,
		Status:       string(host.Status),
		Labels:       host.Labels,
		CreatedAt:    host.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    host.UpdatedAt.Format(time.RFC3339),
	}

	if host.DisplayName != nil {
		resp.DisplayName = *host.DisplayName
	}
	if host.EndpointURL != nil {
		resp.EndpointURL = *host.EndpointURL
	}
	if host.StatusMessage != nil {
		resp.StatusMessage = *host.StatusMessage
	}
	if host.LastSeenAt != nil {
		resp.LastSeenAt = host.LastSeenAt.Format(time.RFC3339)
	}
	if host.DockerVersion != nil {
		resp.DockerVersion = *host.DockerVersion
	}
	if host.OSType != nil {
		resp.OSType = *host.OSType
	}
	if host.Architecture != nil {
		resp.Architecture = *host.Architecture
	}
	if host.TotalMemory != nil {
		resp.TotalMemory = *host.TotalMemory
	}
	if host.TotalCPUs != nil {
		resp.TotalCPUs = *host.TotalCPUs
	}

	return resp
}
