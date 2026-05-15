// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	wireguardsvc "github.com/fr4nsys/usulnet/internal/services/wireguard"
)

// WireGuardService is the narrow surface this handler depends on; the
// concrete service is *wireguard.Service. Declaring it here lets tests
// pass a mock without importing the live service.
//
// v26.2.7 had no API handler at all — the web handler called the
// concrete service directly. v26.5.1 introduces a proper REST surface.
type WireGuardService interface {
	ListInterfaces(ctx context.Context, hostID uuid.UUID) ([]*models.WireGuardInterface, error)
	GetInterface(ctx context.Context, id uuid.UUID) (*models.WireGuardInterface, error)
	CreateInterface(ctx context.Context, iface *models.WireGuardInterface) error
	UpdateInterface(ctx context.Context, iface *models.WireGuardInterface) error
	DeleteInterface(ctx context.Context, id uuid.UUID) error
	GetStats(ctx context.Context, hostID uuid.UUID) (*models.WireGuardStats, error)

	ListPeers(ctx context.Context, interfaceID uuid.UUID) ([]*models.WireGuardPeer, error)
	ListHostPeers(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.WireGuardPeer, int, error)
	GetPeer(ctx context.Context, id uuid.UUID) (*models.WireGuardPeer, error)
	CreatePeer(ctx context.Context, peer *models.WireGuardPeer, agentTargets []uuid.UUID) error
	UpdatePeer(ctx context.Context, peer *models.WireGuardPeer) error
	DeletePeer(ctx context.Context, id uuid.UUID) error
	DecryptPeerConfig(peer *models.WireGuardPeer) (string, error)

	ListMeshLinks(ctx context.Context, peerID uuid.UUID) ([]*models.WireGuardMeshLink, error)

	IssueQRToken(ctx context.Context, peerID uuid.UUID) (string, time.Time, error)
	ConsumeQRToken(token string, peerID uuid.UUID) error
}

// WireGuardHandler handles /api/v1/wireguard/* requests. svc may be
// nil — every handler then returns 503 service_unavailable so the
// route tree still mounts cleanly during early app boot.
type WireGuardHandler struct {
	BaseHandler
	svc      WireGuardService
	hostIDFn func(*http.Request) uuid.UUID
}

// NewWireGuardHandler creates a new WireGuard API handler.
func NewWireGuardHandler(svc WireGuardService, hostIDFn func(*http.Request) uuid.UUID, log *logger.Logger) *WireGuardHandler {
	return &WireGuardHandler{
		BaseHandler: NewBaseHandler(log),
		svc:         svc,
		hostIDFn:    hostIDFn,
	}
}

// Routes returns the chi router for /api/v1/wireguard.
// Read endpoints are viewer+, mutations are operator+, mesh propagation
// is admin (touches remote agents). The QR-issue endpoint is operator+
// (it produces a config that includes the peer's preshared key).
func (h *WireGuardHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Route("/interfaces", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.ListInterfaces)
		r.With(middleware.RequireOperator).Post("/", h.CreateInterface)
		r.With(middleware.RequireViewer).Get("/{id}", h.GetInterface)
		r.With(middleware.RequireOperator).Delete("/{id}", h.DeleteInterface)
		r.With(middleware.RequireViewer).Get("/{id}/peers", h.ListPeersForInterface)
	})

	r.Route("/peers", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.ListHostPeers)
		r.With(middleware.RequireOperator).Post("/", h.CreatePeer)
		r.With(middleware.RequireViewer).Get("/{id}", h.GetPeer)
		r.With(middleware.RequireOperator).Delete("/{id}", h.DeletePeer)
		r.With(middleware.RequireOperator).Post("/{id}/qr/issue", h.IssueQR)
		r.With(middleware.RequireViewer).Get("/{id}/qr", h.GetQR)
	})

	r.With(middleware.RequireViewer).Get("/mesh", h.ListMesh)
	r.With(middleware.RequireViewer).Get("/stats", h.Stats)

	return r
}

// ============================================================================
// DTOs
// ============================================================================

// CreateWireGuardInterfaceRequest is the body for POST /interfaces.
type CreateWireGuardInterfaceRequest struct {
	HostID      string `json:"host_id,omitempty" validate:"omitempty,uuid"`
	Name        string `json:"name,omitempty" validate:"omitempty,max=15"`
	DisplayName string `json:"display_name" validate:"required,min=1,max=255"`
	Description string `json:"description,omitempty" validate:"omitempty,max=1024"`
	ListenPort  int    `json:"listen_port,omitempty" validate:"omitempty,gte=1,lte=65535"`
	Address     string `json:"address" validate:"required,min=1,max=50"`
	DNS         string `json:"dns,omitempty" validate:"omitempty,max=255"`
	MTU         int    `json:"mtu,omitempty" validate:"omitempty,gte=576,lte=9000"`
	PostUp      string `json:"post_up,omitempty" validate:"omitempty,max=2048"`
	PostDown    string `json:"post_down,omitempty" validate:"omitempty,max=2048"`
}

// CreateWireGuardPeerRequest is the body for POST /peers.
type CreateWireGuardPeerRequest struct {
	InterfaceID         string   `json:"interface_id" validate:"required,uuid"`
	Name                string   `json:"name" validate:"required,min=1,max=255"`
	Description         string   `json:"description,omitempty" validate:"omitempty,max=1024"`
	AllowedIPs          string   `json:"allowed_ips,omitempty" validate:"omitempty,max=1024"`
	Endpoint            string   `json:"endpoint,omitempty" validate:"omitempty,max=255"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty" validate:"omitempty,gte=0,lte=65535"`
	PublicKey           string   `json:"public_key,omitempty" validate:"omitempty,max=44"`
	AgentTargets        []string `json:"agent_targets,omitempty"` // host_ids of agents that should apply this peer
}

// WireGuardInterfaceResponse is the API view of a WireGuard interface.
type WireGuardInterfaceResponse struct {
	ID            string  `json:"id"`
	HostID        string  `json:"host_id"`
	Name          string  `json:"name"`
	DisplayName   string  `json:"display_name"`
	Description   string  `json:"description,omitempty"`
	ListenPort    int     `json:"listen_port"`
	Address       string  `json:"address"`
	PublicKey     string  `json:"public_key"`
	DNS           string  `json:"dns,omitempty"`
	MTU           int     `json:"mtu,omitempty"`
	Enabled       bool    `json:"enabled"`
	Status        string  `json:"status"`
	PeerCount     int     `json:"peer_count"`
	LastHandshake *string `json:"last_handshake,omitempty"`
	TransferRx    int64   `json:"transfer_rx"`
	TransferTx    int64   `json:"transfer_tx"`
	CreatedBy     *string `json:"created_by,omitempty"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

// WireGuardPeerResponse is the API view of a WireGuard peer (never
// includes the preshared key or the rendered client config — those
// are only released via the one-time QR endpoint).
type WireGuardPeerResponse struct {
	ID                  string  `json:"id"`
	InterfaceID         string  `json:"interface_id"`
	HostID              string  `json:"host_id"`
	Name                string  `json:"name"`
	Description         string  `json:"description,omitempty"`
	PublicKey           string  `json:"public_key"`
	AllowedIPs          string  `json:"allowed_ips"`
	Endpoint            string  `json:"endpoint,omitempty"`
	PersistentKeepalive int     `json:"persistent_keepalive"`
	Enabled             bool    `json:"enabled"`
	LastHandshake       *string `json:"last_handshake,omitempty"`
	TransferRx          int64   `json:"transfer_rx"`
	TransferTx          int64   `json:"transfer_tx"`
	CreatedBy           *string `json:"created_by,omitempty"`
	CreatedAt           string  `json:"created_at"`
	UpdatedAt           string  `json:"updated_at"`
}

// WireGuardStatsResponse is the API view of aggregate stats.
type WireGuardStatsResponse struct {
	TotalInterfaces  int     `json:"total_interfaces"`
	ActiveInterfaces int     `json:"active_interfaces"`
	TotalPeers       int     `json:"total_peers"`
	ConnectedPeers   int     `json:"connected_peers"`
	TotalRx          int64   `json:"total_rx"`
	TotalTx          int64   `json:"total_tx"`
	LastActivity     *string `json:"last_activity,omitempty"`
}

// WireGuardMeshLinkResponse is the API view of a mesh-link row.
type WireGuardMeshLinkResponse struct {
	ID            string  `json:"id"`
	PeerID        string  `json:"peer_id"`
	AgentHostID   string  `json:"agent_host_id"`
	Status        string  `json:"status"`
	LastError     string  `json:"last_error,omitempty"`
	LastHandshake *string `json:"last_handshake,omitempty"`
	AppliedAt     *string `json:"applied_at,omitempty"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

// QRIssueResponse is the body of POST /peers/{id}/qr/issue.
type QRIssueResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	URL       string `json:"url"` // canonical URL to consume the token
}

// QRPayloadResponse is the body of GET /peers/{id}/qr?token=… It
// returns the cleartext peer config; the browser renders the QR with
// qrcodejs (already vendored under /static/vendor/qrcodejs).
type QRPayloadResponse struct {
	Config string `json:"config"`
}

// ============================================================================
// Handlers — Interfaces
// ============================================================================

// ListInterfaces handles GET /api/v1/wireguard/interfaces.
func (h *WireGuardHandler) ListInterfaces(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.wgServiceUnavailable(w)
		return
	}
	hostID, err := h.resolveWGHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	interfaces, err := h.svc.ListInterfaces(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	resp := make([]WireGuardInterfaceResponse, 0, len(interfaces))
	for _, iface := range interfaces {
		resp = append(resp, toWireGuardInterfaceResponse(iface))
	}
	h.OK(w, resp)
}

// GetInterface handles GET /api/v1/wireguard/interfaces/{id}.
func (h *WireGuardHandler) GetInterface(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.wgServiceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	iface, err := h.svc.GetInterface(r.Context(), id)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	h.OK(w, toWireGuardInterfaceResponse(iface))
}

// CreateInterface handles POST /api/v1/wireguard/interfaces.
func (h *WireGuardHandler) CreateInterface(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.wgServiceUnavailable(w)
		return
	}
	var req CreateWireGuardInterfaceRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	hostID, err := h.resolveWGHostIDFromBody(r, req.HostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	actor, _ := h.GetUserID(r)

	iface := &models.WireGuardInterface{
		HostID:      hostID,
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Description: req.Description,
		ListenPort:  req.ListenPort,
		Address:     req.Address,
		DNS:         req.DNS,
		MTU:         req.MTU,
		PostUp:      req.PostUp,
		PostDown:    req.PostDown,
		Enabled:     true,
		CreatedBy:   nilableUUID(actor),
	}
	if err := h.svc.CreateInterface(r.Context(), iface); err != nil {
		h.HandleError(w, mapWireGuardError(err))
		return
	}
	h.Created(w, toWireGuardInterfaceResponse(iface))
}

// DeleteInterface handles DELETE /api/v1/wireguard/interfaces/{id}.
func (h *WireGuardHandler) DeleteInterface(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.wgServiceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	if err := h.svc.DeleteInterface(r.Context(), id); err != nil {
		h.HandleError(w, err)
		return
	}
	h.NoContent(w)
}

// ListPeersForInterface handles GET /interfaces/{id}/peers.
func (h *WireGuardHandler) ListPeersForInterface(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.wgServiceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	peers, err := h.svc.ListPeers(r.Context(), id)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	resp := make([]WireGuardPeerResponse, 0, len(peers))
	for _, p := range peers {
		resp = append(resp, toWireGuardPeerResponse(p))
	}
	h.OK(w, resp)
}

// ============================================================================
// Handlers — Peers
// ============================================================================

// ListHostPeers handles GET /api/v1/wireguard/peers.
func (h *WireGuardHandler) ListHostPeers(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.wgServiceUnavailable(w)
		return
	}
	hostID, err := h.resolveWGHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	pagination := h.GetPagination(r)
	peers, total, err := h.svc.ListHostPeers(r.Context(), hostID, pagination.PerPage, pagination.Offset)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	resp := make([]WireGuardPeerResponse, 0, len(peers))
	for _, p := range peers {
		resp = append(resp, toWireGuardPeerResponse(p))
	}
	h.OK(w, map[string]any{
		"peers":  resp,
		"total":  total,
		"limit":  pagination.PerPage,
		"offset": pagination.Offset,
	})
}

// GetPeer handles GET /api/v1/wireguard/peers/{id}.
func (h *WireGuardHandler) GetPeer(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.wgServiceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	peer, err := h.svc.GetPeer(r.Context(), id)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	h.OK(w, toWireGuardPeerResponse(peer))
}

// CreatePeer handles POST /api/v1/wireguard/peers.
func (h *WireGuardHandler) CreatePeer(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.wgServiceUnavailable(w)
		return
	}
	var req CreateWireGuardPeerRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	ifaceID, err := uuid.Parse(req.InterfaceID)
	if err != nil {
		h.HandleError(w, apierrors.InvalidInput("invalid interface_id format"))
		return
	}

	iface, err := h.svc.GetInterface(r.Context(), ifaceID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	actor, _ := h.GetUserID(r)
	agentTargets := make([]uuid.UUID, 0, len(req.AgentTargets))
	for _, raw := range req.AgentTargets {
		id, parseErr := uuid.Parse(raw)
		if parseErr != nil {
			h.HandleError(w, apierrors.InvalidInput("invalid agent_targets entry: "+raw))
			return
		}
		agentTargets = append(agentTargets, id)
	}

	peer := &models.WireGuardPeer{
		InterfaceID:         ifaceID,
		HostID:              iface.HostID,
		Name:                req.Name,
		Description:         req.Description,
		AllowedIPs:          req.AllowedIPs,
		Endpoint:            req.Endpoint,
		PersistentKeepalive: req.PersistentKeepalive,
		PublicKey:           req.PublicKey,
		Enabled:             true,
		CreatedBy:           nilableUUID(actor),
	}
	if err := h.svc.CreatePeer(r.Context(), peer, agentTargets); err != nil {
		h.HandleError(w, mapWireGuardError(err))
		return
	}
	h.Created(w, toWireGuardPeerResponse(peer))
}

// DeletePeer handles DELETE /api/v1/wireguard/peers/{id}.
func (h *WireGuardHandler) DeletePeer(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.wgServiceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	if err := h.svc.DeletePeer(r.Context(), id); err != nil {
		h.HandleError(w, err)
		return
	}
	h.NoContent(w)
}

// ============================================================================
// Handlers — One-time QR
// ============================================================================

// IssueQR handles POST /api/v1/wireguard/peers/{id}/qr/issue.
// The response contains a single-use token (5 min TTL) and the URL to
// fetch the rendered config.
func (h *WireGuardHandler) IssueQR(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.wgServiceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	token, exp, err := h.svc.IssueQRToken(r.Context(), id)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	h.OK(w, QRIssueResponse{
		Token:     token,
		ExpiresAt: exp.Format(time.RFC3339),
		URL:       "/api/v1/wireguard/peers/" + id.String() + "/qr?token=" + token,
	})
}

// GetQR handles GET /api/v1/wireguard/peers/{id}/qr?token=… The token
// is single-use and validated server-side; on success the cleartext
// peer config is returned exactly once.
func (h *WireGuardHandler) GetQR(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.wgServiceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	token := h.QueryParam(r, "token")
	if token == "" {
		h.HandleError(w, apierrors.InvalidInput("token query parameter is required"))
		return
	}
	if err := h.svc.ConsumeQRToken(token, id); err != nil {
		h.HandleError(w, mapWireGuardError(err))
		return
	}
	peer, err := h.svc.GetPeer(r.Context(), id)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	cfg, err := h.svc.DecryptPeerConfig(peer)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	h.OK(w, QRPayloadResponse{Config: cfg})
}

// ============================================================================
// Handlers — Mesh / Stats
// ============================================================================

// ListMesh handles GET /api/v1/wireguard/mesh.
func (h *WireGuardHandler) ListMesh(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.wgServiceUnavailable(w)
		return
	}
	var peerID uuid.UUID
	if q := h.QueryParam(r, "peer_id"); q != "" {
		id, parseErr := uuid.Parse(q)
		if parseErr != nil {
			h.HandleError(w, apierrors.InvalidInput("invalid peer_id format"))
			return
		}
		peerID = id
	}
	links, err := h.svc.ListMeshLinks(r.Context(), peerID)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	resp := make([]WireGuardMeshLinkResponse, 0, len(links))
	for _, l := range links {
		resp = append(resp, toWireGuardMeshLinkResponse(l))
	}
	h.OK(w, resp)
}

// Stats handles GET /api/v1/wireguard/stats.
func (h *WireGuardHandler) Stats(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.wgServiceUnavailable(w)
		return
	}
	hostID, err := h.resolveWGHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	stats, err := h.svc.GetStats(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	resp := WireGuardStatsResponse{
		TotalInterfaces:  stats.TotalInterfaces,
		ActiveInterfaces: stats.ActiveInterfaces,
		TotalPeers:       stats.TotalPeers,
		ConnectedPeers:   stats.ConnectedPeers,
		TotalRx:          stats.TotalRx,
		TotalTx:          stats.TotalTx,
	}
	if stats.LastActivity != nil {
		v := stats.LastActivity.Format(time.RFC3339)
		resp.LastActivity = &v
	}
	h.OK(w, resp)
}

// ============================================================================
// Helpers
// ============================================================================

// resolveWGHostID returns the active host UUID for the request. Tries
// the injected hostIDFn, then ?host_id=, then X-Host-ID.
func (h *WireGuardHandler) resolveWGHostID(r *http.Request) (uuid.UUID, error) {
	if h.hostIDFn != nil {
		if id := h.hostIDFn(r); id != uuid.Nil {
			return id, nil
		}
	}
	if q := h.QueryParam(r, "host_id"); q != "" {
		id, err := uuid.Parse(q)
		if err != nil {
			return uuid.Nil, apierrors.InvalidInput("invalid host_id format")
		}
		return id, nil
	}
	if hdr := r.Header.Get("X-Host-ID"); hdr != "" {
		id, err := uuid.Parse(hdr)
		if err != nil {
			return uuid.Nil, apierrors.InvalidInput("invalid X-Host-ID format")
		}
		return id, nil
	}
	return uuid.Nil, apierrors.MissingField("host_id")
}

// resolveWGHostIDFromBody is the create-path variant — the host can be
// passed in the request body.
func (h *WireGuardHandler) resolveWGHostIDFromBody(r *http.Request, bodyHostID string) (uuid.UUID, error) {
	if bodyHostID != "" {
		id, err := uuid.Parse(bodyHostID)
		if err != nil {
			return uuid.Nil, apierrors.InvalidInput("invalid host_id format")
		}
		return id, nil
	}
	return h.resolveWGHostID(r)
}

// wgServiceUnavailable writes a 503 with code SERVICE_UNAVAILABLE.
func (h *WireGuardHandler) wgServiceUnavailable(w http.ResponseWriter) {
	apierrors.WriteError(w, apierrors.ServiceUnavailable("wireguard service is not configured"))
}

// mapWireGuardError translates package-level errors into typed APIErrors.
func mapWireGuardError(err error) error {
	switch {
	case errors.Is(err, wireguardsvc.ErrInvalidInput):
		return apierrors.InvalidInput(err.Error())
	case errors.Is(err, wireguardsvc.ErrSenderNotConfigured):
		return apierrors.ServiceUnavailable("wireguard agent transport is not configured")
	case errors.Is(err, wireguardsvc.ErrEncryptorNotConfigured):
		return apierrors.ServiceUnavailable("wireguard encryption is not configured")
	case errors.Is(err, wireguardsvc.ErrQRTokenExpired):
		return apierrors.InvalidInput("qr token is expired or already consumed")
	}
	return err
}

func toWireGuardInterfaceResponse(i *models.WireGuardInterface) WireGuardInterfaceResponse {
	resp := WireGuardInterfaceResponse{
		ID:          i.ID.String(),
		HostID:      i.HostID.String(),
		Name:        i.Name,
		DisplayName: i.DisplayName,
		Description: i.Description,
		ListenPort:  i.ListenPort,
		Address:     i.Address,
		PublicKey:   i.PublicKey,
		DNS:         i.DNS,
		MTU:         i.MTU,
		Enabled:     i.Enabled,
		Status:      string(i.Status),
		PeerCount:   i.PeerCount,
		TransferRx:  i.TransferRx,
		TransferTx:  i.TransferTx,
		CreatedAt:   i.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   i.UpdatedAt.Format(time.RFC3339),
	}
	if i.LastHandshake != nil {
		v := i.LastHandshake.Format(time.RFC3339)
		resp.LastHandshake = &v
	}
	if i.CreatedBy != nil {
		v := i.CreatedBy.String()
		resp.CreatedBy = &v
	}
	return resp
}

func toWireGuardPeerResponse(p *models.WireGuardPeer) WireGuardPeerResponse {
	resp := WireGuardPeerResponse{
		ID:                  p.ID.String(),
		InterfaceID:         p.InterfaceID.String(),
		HostID:              p.HostID.String(),
		Name:                p.Name,
		Description:         p.Description,
		PublicKey:           p.PublicKey,
		AllowedIPs:          p.AllowedIPs,
		Endpoint:            p.Endpoint,
		PersistentKeepalive: p.PersistentKeepalive,
		Enabled:             p.Enabled,
		TransferRx:          p.TransferRx,
		TransferTx:          p.TransferTx,
		CreatedAt:           p.CreatedAt.Format(time.RFC3339),
		UpdatedAt:           p.UpdatedAt.Format(time.RFC3339),
	}
	if p.LastHandshake != nil {
		v := p.LastHandshake.Format(time.RFC3339)
		resp.LastHandshake = &v
	}
	if p.CreatedBy != nil {
		v := p.CreatedBy.String()
		resp.CreatedBy = &v
	}
	return resp
}

func toWireGuardMeshLinkResponse(l *models.WireGuardMeshLink) WireGuardMeshLinkResponse {
	resp := WireGuardMeshLinkResponse{
		ID:          l.ID.String(),
		PeerID:      l.PeerID.String(),
		AgentHostID: l.AgentHostID.String(),
		Status:      string(l.Status),
		LastError:   l.LastError,
		CreatedAt:   l.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   l.UpdatedAt.Format(time.RFC3339),
	}
	if l.LastHandshake != nil {
		v := l.LastHandshake.Format(time.RFC3339)
		resp.LastHandshake = &v
	}
	if l.AppliedAt != nil {
		v := l.AppliedAt.Format(time.RFC3339)
		resp.AppliedAt = &v
	}
	return resp
}
