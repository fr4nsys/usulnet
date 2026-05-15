// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/models"
	proxysvc "github.com/fr4nsys/usulnet/internal/services/proxy"
)

// ExtendedProxyService is the service contract for the v26.5.1 extended
// proxy features (access lists, dead hosts, locations, redirections,
// streams). The shape mirrors the methods added to proxysvc.Service.
type ExtendedProxyService interface {
	ProxyService

	SupportMatrix() proxysvc.FeatureSupport

	// Access lists
	ListAccessLists(ctx context.Context) ([]*models.ProxyAccessList, error)
	GetAccessList(ctx context.Context, id uuid.UUID) (*models.ProxyAccessList, error)
	CreateAccessList(ctx context.Context, al *models.ProxyAccessList, userID *uuid.UUID) error
	UpdateAccessList(ctx context.Context, al *models.ProxyAccessList, userID *uuid.UUID) error
	DeleteAccessList(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error

	// Dead hosts
	ListDeadHosts(ctx context.Context) ([]*models.ProxyDeadHost, error)
	GetDeadHost(ctx context.Context, id uuid.UUID) (*models.ProxyDeadHost, error)
	CreateDeadHost(ctx context.Context, d *models.ProxyDeadHost, userID *uuid.UUID) error
	UpdateDeadHost(ctx context.Context, d *models.ProxyDeadHost, userID *uuid.UUID) error
	DeleteDeadHost(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error

	// Locations
	ListLocations(ctx context.Context, proxyHostID uuid.UUID) ([]models.ProxyLocation, error)
	SetLocations(ctx context.Context, proxyHostID uuid.UUID, locations []models.ProxyLocation, userID *uuid.UUID) error

	// Redirections
	ListRedirections(ctx context.Context) ([]*models.ProxyRedirection, error)
	GetRedirection(ctx context.Context, id uuid.UUID) (*models.ProxyRedirection, error)
	CreateRedirection(ctx context.Context, rd *models.ProxyRedirection, userID *uuid.UUID) error
	UpdateRedirection(ctx context.Context, rd *models.ProxyRedirection, userID *uuid.UUID) error
	DeleteRedirection(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error

	// Streams
	ListStreams(ctx context.Context) ([]*models.ProxyStream, error)
	GetStream(ctx context.Context, id uuid.UUID) (*models.ProxyStream, error)
	CreateStream(ctx context.Context, st *models.ProxyStream, userID *uuid.UUID) error
	UpdateStream(ctx context.Context, st *models.ProxyStream, userID *uuid.UUID) error
	DeleteStream(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error
}

// Compile-time check that *proxysvc.Service satisfies the contract.
var _ ExtendedProxyService = (*proxysvc.Service)(nil)

// ExtendedProxyHandler exposes the extended-proxy REST API.
type ExtendedProxyHandler struct {
	*ProxyHandler
	svc ExtendedProxyService
}

// NewExtendedProxyHandler creates an extended proxy handler that
// re-uses the base ProxyHandler for proxy-host routes and adds the
// access-list / dead-host / location / redirection / stream routes.
func NewExtendedProxyHandler(base *ProxyHandler, svc ExtendedProxyService) *ExtendedProxyHandler {
	return &ExtendedProxyHandler{ProxyHandler: base, svc: svc}
}

// HandleExtendedError maps proxy service errors to API responses.
// In particular, ErrFeatureNotSupported becomes a 422 with a clear
// message instead of a 500.
func (h *ExtendedProxyHandler) HandleExtendedError(w http.ResponseWriter, action string, err error) {
	if errors.Is(err, proxysvc.ErrFeatureNotSupported) {
		apierrors.WriteError(w, apierrors.FeatureNotSupported(fmt.Sprintf("%s: %s", action, err.Error())))
		return
	}
	h.HandleError(w, fmt.Errorf("%s: %w", action, err))
}

// ============================================================================
// Backend support matrix
// ============================================================================

// SupportMatrixResponse describes the active backend's extended-feature support.
type SupportMatrixResponse struct {
	Backend      string `json:"backend"`
	AccessLists  bool   `json:"access_lists"`
	DeadHosts    bool   `json:"dead_hosts"`
	Locations    bool   `json:"locations"`
	Redirections bool   `json:"redirections"`
	Streams      bool   `json:"streams"`
}

// GetSupportMatrix returns the extended-feature support matrix.
// GET /api/v1/proxy/support
func (h *ExtendedProxyHandler) GetSupportMatrix(w http.ResponseWriter, r *http.Request) {
	mode := ""
	if mb, ok := h.svc.(interface{ BackendMode() string }); ok {
		mode = mb.BackendMode()
	}
	m := h.svc.SupportMatrix()
	h.OK(w, SupportMatrixResponse{
		Backend:      mode,
		AccessLists:  m.AccessLists,
		DeadHosts:    m.DeadHosts,
		Locations:    m.Locations,
		Redirections: m.Redirections,
		Streams:      m.Streams,
	})
}

// ============================================================================
// Access Lists
// ============================================================================

// ListAccessLists returns all access lists.
// GET /api/v1/proxy/access-lists
func (h *ExtendedProxyHandler) ListAccessLists(w http.ResponseWriter, r *http.Request) {
	lists, err := h.svc.ListAccessLists(r.Context())
	if err != nil {
		h.HandleExtendedError(w, "list access lists", err)
		return
	}
	h.OK(w, lists)
}

// GetAccessList returns one access list by ID.
// GET /api/v1/proxy/access-lists/{id}
func (h *ExtendedProxyHandler) GetAccessList(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	al, err := h.svc.GetAccessList(r.Context(), id)
	if err != nil {
		h.HandleExtendedError(w, "get access list", err)
		return
	}
	h.OK(w, al)
}

// CreateAccessListRequest is the JSON body for creating an access list.
type CreateAccessListRequest struct {
	Name       string                         `json:"name" validate:"required,max=255"`
	SatisfyAny bool                           `json:"satisfy_any"`
	PassAuth   bool                           `json:"pass_auth"`
	Enabled    bool                           `json:"enabled"`
	Items      []models.ProxyAccessListAuth   `json:"items"`
	Clients    []models.ProxyAccessListClient `json:"clients"`
}

// CreateAccessList creates a new access list.
// POST /api/v1/proxy/access-lists
func (h *ExtendedProxyHandler) CreateAccessList(w http.ResponseWriter, r *http.Request) {
	var req CreateAccessListRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	userID, _ := h.GetUserID(r)
	al := &models.ProxyAccessList{
		Name:       req.Name,
		SatisfyAny: req.SatisfyAny,
		PassAuth:   req.PassAuth,
		Enabled:    req.Enabled,
		Items:      req.Items,
		Clients:    req.Clients,
	}
	if err := h.svc.CreateAccessList(r.Context(), al, &userID); err != nil {
		h.HandleExtendedError(w, "create access list", err)
		return
	}
	h.Created(w, al)
}

// UpdateAccessList replaces an access list's fields plus items/clients.
// PUT /api/v1/proxy/access-lists/{id}
func (h *ExtendedProxyHandler) UpdateAccessList(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	var req CreateAccessListRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	userID, _ := h.GetUserID(r)
	al := &models.ProxyAccessList{
		ID:         id,
		Name:       req.Name,
		SatisfyAny: req.SatisfyAny,
		PassAuth:   req.PassAuth,
		Enabled:    req.Enabled,
		Items:      req.Items,
		Clients:    req.Clients,
	}
	if err := h.svc.UpdateAccessList(r.Context(), al, &userID); err != nil {
		h.HandleExtendedError(w, "update access list", err)
		return
	}
	h.OK(w, al)
}

// DeleteAccessList removes an access list.
// DELETE /api/v1/proxy/access-lists/{id}
func (h *ExtendedProxyHandler) DeleteAccessList(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	userID, _ := h.GetUserID(r)
	if err := h.svc.DeleteAccessList(r.Context(), id, &userID); err != nil {
		h.HandleExtendedError(w, "delete access list", err)
		return
	}
	h.NoContent(w)
}

// ============================================================================
// Dead Hosts (read-only listing; create/delete optional)
// ============================================================================

// ListDeadHosts returns all dead hosts.
// GET /api/v1/proxy/dead-hosts
func (h *ExtendedProxyHandler) ListDeadHosts(w http.ResponseWriter, r *http.Request) {
	dead, err := h.svc.ListDeadHosts(r.Context())
	if err != nil {
		h.HandleExtendedError(w, "list dead hosts", err)
		return
	}
	h.OK(w, dead)
}

// DeadHostRequest is the JSON body for creating/updating a dead host.
type DeadHostRequest struct {
	Domains       []string            `json:"domains" validate:"required,min=1,dive,required"`
	SSLMode       models.ProxySSLMode `json:"ssl_mode"`
	SSLForceHTTPS bool                `json:"ssl_force_https"`
	CertificateID *uuid.UUID          `json:"certificate_id,omitempty"`
	Enabled       bool                `json:"enabled"`
}

// CreateDeadHost creates a new dead host.
// POST /api/v1/proxy/dead-hosts
func (h *ExtendedProxyHandler) CreateDeadHost(w http.ResponseWriter, r *http.Request) {
	var req DeadHostRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	userID, _ := h.GetUserID(r)
	d := &models.ProxyDeadHost{
		Domains:       req.Domains,
		SSLMode:       req.SSLMode,
		SSLForceHTTPS: req.SSLForceHTTPS,
		CertificateID: req.CertificateID,
		Enabled:       req.Enabled,
	}
	if d.SSLMode == "" {
		d.SSLMode = models.ProxySSLModeNone
	}
	if err := h.svc.CreateDeadHost(r.Context(), d, &userID); err != nil {
		h.HandleExtendedError(w, "create dead host", err)
		return
	}
	h.Created(w, d)
}

// DeleteDeadHost removes a dead host.
// DELETE /api/v1/proxy/dead-hosts/{id}
func (h *ExtendedProxyHandler) DeleteDeadHost(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	userID, _ := h.GetUserID(r)
	if err := h.svc.DeleteDeadHost(r.Context(), id, &userID); err != nil {
		h.HandleExtendedError(w, "delete dead host", err)
		return
	}
	h.NoContent(w)
}

// ============================================================================
// Locations
// ============================================================================

// ListLocations returns locations for a proxy host.
// GET /api/v1/proxy/hosts/{id}/locations
func (h *ExtendedProxyHandler) ListLocations(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	locs, err := h.svc.ListLocations(r.Context(), id)
	if err != nil {
		h.HandleExtendedError(w, "list locations", err)
		return
	}
	h.OK(w, locs)
}

// SetLocationsRequest is the JSON body for replacing host locations.
type SetLocationsRequest struct {
	Locations []models.ProxyLocation `json:"locations"`
}

// SetLocations replaces locations for a proxy host.
// PUT /api/v1/proxy/hosts/{id}/locations
func (h *ExtendedProxyHandler) SetLocations(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	var req SetLocationsRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	userID, _ := h.GetUserID(r)
	if err := h.svc.SetLocations(r.Context(), id, req.Locations, &userID); err != nil {
		h.HandleExtendedError(w, "set locations", err)
		return
	}
	h.OK(w, map[string]string{"status": "locations updated"})
}

// ============================================================================
// Redirections
// ============================================================================

// ListRedirections returns all redirections.
// GET /api/v1/proxy/redirections
func (h *ExtendedProxyHandler) ListRedirections(w http.ResponseWriter, r *http.Request) {
	rds, err := h.svc.ListRedirections(r.Context())
	if err != nil {
		h.HandleExtendedError(w, "list redirections", err)
		return
	}
	h.OK(w, rds)
}

// RedirectionRequest is the JSON body for creating/updating a redirection.
type RedirectionRequest struct {
	Domains         []string            `json:"domains" validate:"required,min=1,dive,required"`
	ForwardScheme   string              `json:"forward_scheme"`
	ForwardDomain   string              `json:"forward_domain" validate:"required"`
	ForwardHTTPCode int                 `json:"forward_http_code"`
	PreservePath    bool                `json:"preserve_path"`
	SSLMode         models.ProxySSLMode `json:"ssl_mode"`
	SSLForceHTTPS   bool                `json:"ssl_force_https"`
	CertificateID   *uuid.UUID          `json:"certificate_id,omitempty"`
	Enabled         bool                `json:"enabled"`
}

func (req RedirectionRequest) toModel() *models.ProxyRedirection {
	rd := &models.ProxyRedirection{
		Domains:         req.Domains,
		ForwardScheme:   req.ForwardScheme,
		ForwardDomain:   req.ForwardDomain,
		ForwardHTTPCode: req.ForwardHTTPCode,
		PreservePath:    req.PreservePath,
		SSLMode:         req.SSLMode,
		SSLForceHTTPS:   req.SSLForceHTTPS,
		CertificateID:   req.CertificateID,
		Enabled:         req.Enabled,
	}
	if rd.ForwardScheme == "" {
		rd.ForwardScheme = "https"
	}
	if rd.ForwardHTTPCode == 0 {
		rd.ForwardHTTPCode = 301
	}
	if rd.SSLMode == "" {
		rd.SSLMode = models.ProxySSLModeNone
	}
	return rd
}

// CreateRedirection creates a new redirection.
// POST /api/v1/proxy/redirections
func (h *ExtendedProxyHandler) CreateRedirection(w http.ResponseWriter, r *http.Request) {
	var req RedirectionRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	userID, _ := h.GetUserID(r)
	rd := req.toModel()
	if err := h.svc.CreateRedirection(r.Context(), rd, &userID); err != nil {
		h.HandleExtendedError(w, "create redirection", err)
		return
	}
	h.Created(w, rd)
}

// UpdateRedirection updates an existing redirection.
// PUT /api/v1/proxy/redirections/{id}
func (h *ExtendedProxyHandler) UpdateRedirection(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	var req RedirectionRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	userID, _ := h.GetUserID(r)
	rd := req.toModel()
	rd.ID = id
	if err := h.svc.UpdateRedirection(r.Context(), rd, &userID); err != nil {
		h.HandleExtendedError(w, "update redirection", err)
		return
	}
	h.OK(w, rd)
}

// DeleteRedirection removes a redirection.
// DELETE /api/v1/proxy/redirections/{id}
func (h *ExtendedProxyHandler) DeleteRedirection(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	userID, _ := h.GetUserID(r)
	if err := h.svc.DeleteRedirection(r.Context(), id, &userID); err != nil {
		h.HandleExtendedError(w, "delete redirection", err)
		return
	}
	h.NoContent(w)
}

// ============================================================================
// Streams (TCP/UDP — 422 against Caddy via ErrFeatureNotSupported)
// ============================================================================

// ListStreams returns all streams.
// GET /api/v1/proxy/streams
func (h *ExtendedProxyHandler) ListStreams(w http.ResponseWriter, r *http.Request) {
	streams, err := h.svc.ListStreams(r.Context())
	if err != nil {
		h.HandleExtendedError(w, "list streams", err)
		return
	}
	h.OK(w, streams)
}

// StreamRequest is the JSON body for creating/updating a stream.
type StreamRequest struct {
	IncomingPort   int    `json:"incoming_port" validate:"required,min=1,max=65535"`
	ForwardingHost string `json:"forwarding_host" validate:"required"`
	ForwardingPort int    `json:"forwarding_port" validate:"required,min=1,max=65535"`
	TCPForwarding  bool   `json:"tcp_forwarding"`
	UDPForwarding  bool   `json:"udp_forwarding"`
	Enabled        bool   `json:"enabled"`
}

func (req StreamRequest) toModel() *models.ProxyStream {
	return &models.ProxyStream{
		IncomingPort:   req.IncomingPort,
		ForwardingHost: req.ForwardingHost,
		ForwardingPort: req.ForwardingPort,
		TCPForwarding:  req.TCPForwarding,
		UDPForwarding:  req.UDPForwarding,
		Enabled:        req.Enabled,
	}
}

// CreateStream creates a new stream. Returns 422 with a clear message
// when the active backend cannot translate raw TCP/UDP forwarding
// (Caddy in v26.5.1).
// POST /api/v1/proxy/streams
func (h *ExtendedProxyHandler) CreateStream(w http.ResponseWriter, r *http.Request) {
	var req StreamRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	if !req.TCPForwarding && !req.UDPForwarding {
		h.BadRequest(w, "at least one of tcp_forwarding or udp_forwarding must be true")
		return
	}
	userID, _ := h.GetUserID(r)
	st := req.toModel()
	if err := h.svc.CreateStream(r.Context(), st, &userID); err != nil {
		h.HandleExtendedError(w, "create stream", err)
		return
	}
	h.Created(w, st)
}

// UpdateStream updates an existing stream.
// PUT /api/v1/proxy/streams/{id}
func (h *ExtendedProxyHandler) UpdateStream(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	var req StreamRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	if !req.TCPForwarding && !req.UDPForwarding {
		h.BadRequest(w, "at least one of tcp_forwarding or udp_forwarding must be true")
		return
	}
	userID, _ := h.GetUserID(r)
	st := req.toModel()
	st.ID = id
	if err := h.svc.UpdateStream(r.Context(), st, &userID); err != nil {
		h.HandleExtendedError(w, "update stream", err)
		return
	}
	h.OK(w, st)
}

// DeleteStream removes a stream.
// DELETE /api/v1/proxy/streams/{id}
func (h *ExtendedProxyHandler) DeleteStream(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	userID, _ := h.GetUserID(r)
	if err := h.svc.DeleteStream(r.Context(), id, &userID); err != nil {
		h.HandleExtendedError(w, "delete stream", err)
		return
	}
	h.NoContent(w)
}
