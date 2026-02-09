// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/integrations/npm"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// NPMHandler handles NPM (Nginx Proxy Manager) API endpoints.
type NPMHandler struct {
	BaseHandler
	npmService *npm.Service
}

// NewNPMHandler creates a new NPM handler.
func NewNPMHandler(npmService *npm.Service, log *logger.Logger) *NPMHandler {
	return &NPMHandler{
		BaseHandler: NewBaseHandler(log),
		npmService:  npmService,
	}
}

// =============================================================================
// Connection Management
// =============================================================================

// GetConnection returns the NPM connection for a host.
// GET /api/npm/connections/{hostID}
func (h *NPMHandler) GetConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := chi.URLParam(r, "hostID")

	if hostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}

	conn, err := h.npmService.GetConnection(ctx, hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if conn == nil {
		h.NotFound(w, "NPM connection")
		return
	}

	h.OK(w, conn)
}

// ConfigureConnectionRequest is the request body for configuring NPM connection.
type ConfigureConnectionRequest struct {
	HostID        string `json:"host_id"`
	BaseURL       string `json:"base_url"`
	AdminEmail    string `json:"admin_email"`
	AdminPassword string `json:"admin_password"`
}

// ConfigureConnection configures an NPM connection for a host.
// POST /api/npm/connections
func (h *NPMHandler) ConfigureConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req ConfigureConnectionRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.BadRequest(w, "invalid request body")
		return
	}

	if req.HostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}
	if req.BaseURL == "" {
		h.BadRequest(w, "base_url is required")
		return
	}
	if req.AdminEmail == "" {
		h.BadRequest(w, "admin_email is required")
		return
	}
	if req.AdminPassword == "" {
		h.BadRequest(w, "admin_password is required")
		return
	}

	userID, _ := h.GetUserID(r)

	input := &models.NPMConnectionCreate{
		HostID:        req.HostID,
		BaseURL:       req.BaseURL,
		AdminEmail:    req.AdminEmail,
		AdminPassword: req.AdminPassword,
	}

	conn, err := h.npmService.ConfigureConnection(ctx, req.HostID, input, userID.String())
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, conn)
}

// UpdateConnectionRequest is the request body for updating NPM connection.
type UpdateConnectionRequest struct {
	BaseURL       *string `json:"base_url,omitempty"`
	AdminEmail    *string `json:"admin_email,omitempty"`
	AdminPassword *string `json:"admin_password,omitempty"`
	IsEnabled     *bool   `json:"is_enabled,omitempty"`
}

// UpdateConnection updates an NPM connection.
// PUT /api/npm/connections/{id}
func (h *NPMHandler) UpdateConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connID := chi.URLParam(r, "id")

	if connID == "" {
		h.BadRequest(w, "connection id is required")
		return
	}

	var req UpdateConnectionRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.BadRequest(w, "invalid request body")
		return
	}

	userID, _ := h.GetUserID(r)

	input := &models.NPMConnectionUpdate{
		BaseURL:       req.BaseURL,
		AdminEmail:    req.AdminEmail,
		AdminPassword: req.AdminPassword,
		IsEnabled:     req.IsEnabled,
	}

	conn, err := h.npmService.UpdateConnection(ctx, connID, input, userID.String())
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, conn)
}

// DeleteConnection deletes an NPM connection.
// DELETE /api/npm/connections/{id}
func (h *NPMHandler) DeleteConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connID := chi.URLParam(r, "id")

	if connID == "" {
		h.BadRequest(w, "connection id is required")
		return
	}

	if err := h.npmService.DeleteConnection(ctx, connID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// TestConnection tests the NPM connection.
// POST /api/npm/connections/{hostID}/test
func (h *NPMHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := chi.URLParam(r, "hostID")

	if hostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}

	healthy, err := h.npmService.CheckHealth(ctx, hostID)
	if err != nil {
		h.OK(w, map[string]interface{}{
			"healthy": false,
			"error":   err.Error(),
		})
		return
	}

	h.OK(w, map[string]interface{}{
		"healthy": healthy,
	})
}

// =============================================================================
// Proxy Hosts
// =============================================================================

// ListProxyHosts returns all proxy hosts from NPM.
// GET /api/npm/{hostID}/proxy-hosts
func (h *NPMHandler) ListProxyHosts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := chi.URLParam(r, "hostID")

	if hostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}

	hosts, err := h.npmService.ListProxyHosts(ctx, hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, hosts)
}

// GetProxyHost returns a single proxy host from NPM.
// GET /api/npm/{hostID}/proxy-hosts/{proxyID}
func (h *NPMHandler) GetProxyHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := chi.URLParam(r, "hostID")
	proxyID := h.QueryParamInt(r, "proxyID", 0)

	if hostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}
	if proxyID == 0 {
		h.BadRequest(w, "proxy_id is required")
		return
	}

	host, err := h.npmService.GetProxyHost(ctx, hostID, proxyID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, host)
}

// CreateProxyHost creates a new proxy host in NPM.
// POST /api/npm/{hostID}/proxy-hosts
func (h *NPMHandler) CreateProxyHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := chi.URLParam(r, "hostID")

	if hostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}

	var req npm.ProxyHostCreate
	if err := h.ParseJSON(r, &req); err != nil {
		h.BadRequest(w, "invalid request body")
		return
	}

	userID, _ := h.GetUserID(r)

	host, err := h.npmService.CreateProxyHost(ctx, hostID, &req, userID.String())
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, host)
}

// UpdateProxyHost updates a proxy host in NPM.
// PUT /api/npm/{hostID}/proxy-hosts/{proxyID}
func (h *NPMHandler) UpdateProxyHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := chi.URLParam(r, "hostID")
	proxyID := h.URLParamInt(r, "proxyID", 0)

	if hostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}
	if proxyID == 0 {
		h.BadRequest(w, "proxy_id is required")
		return
	}

	var req npm.ProxyHostUpdate
	if err := h.ParseJSON(r, &req); err != nil {
		h.BadRequest(w, "invalid request body")
		return
	}

	userID, _ := h.GetUserID(r)

	host, err := h.npmService.UpdateProxyHost(ctx, hostID, proxyID, &req, userID.String())
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, host)
}

// DeleteProxyHost deletes a proxy host from NPM.
// DELETE /api/npm/{hostID}/proxy-hosts/{proxyID}
func (h *NPMHandler) DeleteProxyHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := chi.URLParam(r, "hostID")
	proxyID := h.URLParamInt(r, "proxyID", 0)

	if hostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}
	if proxyID == 0 {
		h.BadRequest(w, "proxy_id is required")
		return
	}

	userID, _ := h.GetUserID(r)

	if err := h.npmService.DeleteProxyHost(ctx, hostID, proxyID, userID.String()); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// EnableProxyHost enables a proxy host in NPM.
// POST /api/npm/{hostID}/proxy-hosts/{proxyID}/enable
func (h *NPMHandler) EnableProxyHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := chi.URLParam(r, "hostID")
	proxyID := h.URLParamInt(r, "proxyID", 0)

	if hostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}
	if proxyID == 0 {
		h.BadRequest(w, "proxy_id is required")
		return
	}

	userID, _ := h.GetUserID(r)

	if err := h.npmService.EnableProxyHost(ctx, hostID, proxyID, userID.String()); err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]string{"status": "enabled"})
}

// DisableProxyHost disables a proxy host in NPM.
// POST /api/npm/{hostID}/proxy-hosts/{proxyID}/disable
func (h *NPMHandler) DisableProxyHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := chi.URLParam(r, "hostID")
	proxyID := h.URLParamInt(r, "proxyID", 0)

	if hostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}
	if proxyID == 0 {
		h.BadRequest(w, "proxy_id is required")
		return
	}

	userID, _ := h.GetUserID(r)

	if err := h.npmService.DisableProxyHost(ctx, hostID, proxyID, userID.String()); err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]string{"status": "disabled"})
}

// =============================================================================
// Certificates
// =============================================================================

// ListCertificates returns all certificates from NPM.
// GET /api/npm/{hostID}/certificates
func (h *NPMHandler) ListCertificates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := chi.URLParam(r, "hostID")

	if hostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}

	certs, err := h.npmService.ListCertificates(ctx, hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, certs)
}

// RequestLetsEncryptCertificateRequest is the request body for requesting a Let's Encrypt certificate.
type RequestLetsEncryptCertificateRequest struct {
	DomainNames []string `json:"domain_names"`
	Email       string   `json:"email"`
}

// RequestLetsEncryptCertificate requests a new Let's Encrypt certificate in NPM.
// POST /api/npm/{hostID}/certificates/letsencrypt
func (h *NPMHandler) RequestLetsEncryptCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := chi.URLParam(r, "hostID")

	if hostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}

	var req RequestLetsEncryptCertificateRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.BadRequest(w, "invalid request body")
		return
	}

	if len(req.DomainNames) == 0 {
		h.BadRequest(w, "domain_names is required")
		return
	}
	if req.Email == "" {
		h.BadRequest(w, "email is required")
		return
	}

	cert, err := h.npmService.RequestLetsEncrypt(ctx, hostID, req.DomainNames, req.Email)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, cert)
}

// DeleteCertificate deletes a certificate from NPM.
// DELETE /api/npm/{hostID}/certificates/{certID}
func (h *NPMHandler) DeleteCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := chi.URLParam(r, "hostID")
	certID := h.URLParamInt(r, "certID", 0)

	if hostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}
	if certID == 0 {
		h.BadRequest(w, "cert_id is required")
		return
	}

	if err := h.npmService.DeleteCertificate(ctx, hostID, certID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// =============================================================================
// Redirections
// =============================================================================

// ListRedirections returns all redirections from NPM.
// GET /api/npm/{hostID}/redirections
func (h *NPMHandler) ListRedirections(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := chi.URLParam(r, "hostID")

	if hostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}

	redirections, err := h.npmService.ListRedirections(ctx, hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, redirections)
}

// CreateRedirection creates a new redirection in NPM.
// POST /api/npm/{hostID}/redirections
func (h *NPMHandler) CreateRedirection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := chi.URLParam(r, "hostID")

	if hostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}

	var req npm.RedirectionCreate
	if err := h.ParseJSON(r, &req); err != nil {
		h.BadRequest(w, "invalid request body")
		return
	}

	userID, _ := h.GetUserID(r)

	redir, err := h.npmService.CreateRedirection(ctx, hostID, &req, userID.String())
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, redir)
}

// DeleteRedirection deletes a redirection from NPM.
// DELETE /api/npm/{hostID}/redirections/{redirID}
func (h *NPMHandler) DeleteRedirection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := chi.URLParam(r, "hostID")
	redirID := h.URLParamInt(r, "redirID", 0)

	if hostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}
	if redirID == 0 {
		h.BadRequest(w, "redir_id is required")
		return
	}

	userID, _ := h.GetUserID(r)

	if err := h.npmService.DeleteRedirection(ctx, hostID, redirID, userID.String()); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// =============================================================================
// Access Lists
// =============================================================================

// ListAccessLists returns all access lists from NPM.
// GET /api/npm/{hostID}/access-lists
func (h *NPMHandler) ListAccessLists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := chi.URLParam(r, "hostID")

	if hostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}

	lists, err := h.npmService.ListAccessLists(ctx, hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, lists)
}

// CreateAccessList creates a new access list in NPM.
// POST /api/npm/{hostID}/access-lists
func (h *NPMHandler) CreateAccessList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := chi.URLParam(r, "hostID")

	if hostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}

	var req npm.AccessListCreate
	if err := h.ParseJSON(r, &req); err != nil {
		h.BadRequest(w, "invalid request body")
		return
	}

	userID, _ := h.GetUserID(r)

	list, err := h.npmService.CreateAccessList(ctx, hostID, &req, userID.String())
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, list)
}

// DeleteAccessList deletes an access list from NPM.
// DELETE /api/npm/{hostID}/access-lists/{listID}
func (h *NPMHandler) DeleteAccessList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := chi.URLParam(r, "hostID")
	listID := h.URLParamInt(r, "listID", 0)

	if hostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}
	if listID == 0 {
		h.BadRequest(w, "list_id is required")
		return
	}

	userID, _ := h.GetUserID(r)

	if err := h.npmService.DeleteAccessList(ctx, hostID, listID, userID.String()); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// =============================================================================
// Audit Logs
// =============================================================================

// ListAuditLogs returns NPM audit logs.
// GET /api/npm/{hostID}/audit-logs
func (h *NPMHandler) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := chi.URLParam(r, "hostID")

	if hostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}

	pagination := h.GetPagination(r)

	logs, total, err := h.npmService.ListAuditLogs(ctx, hostID, pagination.PerPage, pagination.Offset)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, NewPaginatedResponse(logs, int64(total), pagination))
}
