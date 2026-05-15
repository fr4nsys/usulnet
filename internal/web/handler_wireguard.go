// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	wireguardsvc "github.com/fr4nsys/usulnet/internal/services/wireguard"
	wgtpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/wireguard"
)

// requireWireGuardSvc returns the WireGuard service or renders a
// "not configured" error. Centralized so every handler has the
// identical degradation path when wireguard wiring is missing
// (e.g. encryption key not set, or migration 055 not applied).
func (h *Handler) requireWireGuardSvc(w http.ResponseWriter, r *http.Request) *wireguardsvc.Service {
	if reg, ok := h.services.(*ServiceRegistry); ok && reg.wireguardSvc != nil {
		return reg.wireguardSvc
	}
	h.RenderErrorTempl(w, r, http.StatusServiceUnavailable,
		"WireGuard Not Configured",
		"The WireGuard manager is not enabled in this build (typically because the data encryption key is not set).")
	return nil
}

// getWGHostID resolves the active host ID for WireGuard operations.
func (h *Handler) getWGHostID(r *http.Request) uuid.UUID {
	if reg, ok := h.services.(*ServiceRegistry); ok {
		return resolveHostID(r.Context(), reg.defaultHostID)
	}
	return uuid.Nil
}

// wireguardUserUUID returns a *uuid.UUID for the requesting user.
func (h *Handler) wireguardUserUUID(r *http.Request) *uuid.UUID {
	user := h.getUserData(r)
	if user == nil || user.ID == "" {
		return nil
	}
	id, err := uuid.Parse(user.ID)
	if err != nil {
		return nil
	}
	return &id
}

// wgProbeMessage returns a single-line warning string when the local
// host is missing the `wg` or `wg-quick` binary. Empty when both are
// present.
func (h *Handler) wgProbeMessage() string {
	if reg, ok := h.services.(*ServiceRegistry); ok {
		switch {
		case !reg.wgProbe.WGAvailable && !reg.wgProbe.WGQuickAvailable:
			return "wg and wg-quick are not installed on this host. Container deployments need NET_ADMIN + /sys/class/net to bring interfaces up."
		case !reg.wgProbe.WGAvailable:
			return "wg userspace binary not found. Install wireguard-tools."
		case !reg.wgProbe.WGQuickAvailable:
			return "wg-quick is not installed. wg-quick is required for interface lifecycle (up/down)."
		}
	}
	return ""
}

// ============================================================================
// Interface list
// ============================================================================

// WireGuardListTempl renders the WireGuard interfaces list page.
func (h *Handler) WireGuardListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireWireGuardSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getWGHostID(r)
	pageData := h.prepareTemplPageData(r, "WireGuard VPN", "wireguard")

	interfaces, err := svc.ListInterfaces(ctx, hostID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load interfaces: "+err.Error())
		return
	}

	stats, _ := svc.GetStats(ctx, hostID)

	views := make([]wgtpl.InterfaceView, 0, len(interfaces))
	for _, iface := range interfaces {
		views = append(views, wgInterfaceToView(iface))
	}

	statsView := wgtpl.StatsView{}
	if stats != nil {
		statsView.TotalInterfaces = stats.TotalInterfaces
		statsView.ActiveInterfaces = stats.ActiveInterfaces
		statsView.TotalPeers = stats.TotalPeers
		statsView.ConnectedPeers = stats.ConnectedPeers
		statsView.TotalRx = formatBytes(stats.TotalRx)
		statsView.TotalTx = formatBytes(stats.TotalTx)
	}

	h.renderTempl(w, r, wgtpl.List(wgtpl.ListData{
		PageData:     pageData,
		Interfaces:   views,
		Stats:        statsView,
		ProbeMessage: h.wgProbeMessage(),
	}))
}

// ============================================================================
// Interface detail
// ============================================================================

// WireGuardDetailTempl renders an interface detail page with its peers.
func (h *Handler) WireGuardDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireWireGuardSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "WireGuard Interface", "wireguard")

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "")
		return
	}

	iface, err := svc.GetInterface(ctx, id)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Interface not found.")
		return
	}

	peers, err := svc.ListPeers(ctx, id)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load peers: "+err.Error())
		return
	}

	peerViews := make([]wgtpl.PeerView, 0, len(peers))
	for _, p := range peers {
		peerViews = append(peerViews, wgPeerToView(p))
	}

	h.renderTempl(w, r, wgtpl.Detail(wgtpl.DetailData{
		PageData:  pageData,
		Interface: wgInterfaceToView(iface),
		Peers:     peerViews,
	}))
}

// ============================================================================
// New interface
// ============================================================================

// WireGuardNewTempl renders the new-interface form.
func (h *Handler) WireGuardNewTempl(w http.ResponseWriter, r *http.Request) {
	if svc := h.requireWireGuardSvc(w, r); svc == nil {
		return
	}
	pageData := h.prepareTemplPageData(r, "New WireGuard Interface", "wireguard")
	h.renderTempl(w, r, wgtpl.New(wgtpl.NewData{PageData: pageData}))
}

// WireGuardCreateTempl handles POST /wireguard — creates a new interface.
func (h *Handler) WireGuardCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireWireGuardSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/wireguard", http.StatusSeeOther)
		return
	}

	hostID := h.getWGHostID(r)
	port := 51820
	if p, err := strconv.Atoi(r.FormValue("listen_port")); err == nil && p > 0 {
		port = p
	}
	mtu := 1420
	if m, err := strconv.Atoi(r.FormValue("mtu")); err == nil && m > 0 {
		mtu = m
	}

	iface := &models.WireGuardInterface{
		HostID:      hostID,
		Name:        r.FormValue("name"),
		DisplayName: r.FormValue("display_name"),
		Description: r.FormValue("description"),
		ListenPort:  port,
		Address:     r.FormValue("address"),
		DNS:         r.FormValue("dns"),
		MTU:         mtu,
		PostUp:      r.FormValue("post_up"),
		PostDown:    r.FormValue("post_down"),
		Enabled:     true,
		CreatedBy:   h.wireguardUserUUID(r),
	}

	if err := svc.CreateInterface(r.Context(), iface); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to create interface: "+err.Error())
		return
	}
	http.Redirect(w, r, "/wireguard/"+iface.ID.String(), http.StatusSeeOther)
}

// WireGuardDeleteTempl deletes an interface (and cascade-deletes peers).
func (h *Handler) WireGuardDeleteTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireWireGuardSvc(w, r)
	if svc == nil {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Redirect(w, r, "/wireguard", http.StatusSeeOther)
		return
	}
	if err := svc.DeleteInterface(r.Context(), id); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to delete interface: "+err.Error())
		return
	}
	http.Redirect(w, r, "/wireguard", http.StatusSeeOther)
}

// ============================================================================
// Peer list / detail / new / delete
// ============================================================================

// WireGuardPeerListTempl renders the global peer list.
func (h *Handler) WireGuardPeerListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireWireGuardSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getWGHostID(r)
	pageData := h.prepareTemplPageData(r, "WireGuard Peers", "wireguard")

	peers, total, err := svc.ListHostPeers(ctx, hostID, 100, 0)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load peers: "+err.Error())
		return
	}

	views := make([]wgtpl.PeerView, 0, len(peers))
	for _, p := range peers {
		views = append(views, wgPeerToView(p))
	}
	h.renderTempl(w, r, wgtpl.PeerList(wgtpl.PeerListData{
		PageData: pageData,
		Peers:    views,
		Total:    total,
	}))
}

// WireGuardPeerNewTempl renders the new-peer form.
func (h *Handler) WireGuardPeerNewTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireWireGuardSvc(w, r)
	if svc == nil {
		return
	}

	ifaceID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Redirect(w, r, "/wireguard", http.StatusSeeOther)
		return
	}

	iface, err := svc.GetInterface(r.Context(), ifaceID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Interface not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Add Peer", "wireguard")
	h.renderTempl(w, r, wgtpl.PeerNew(wgtpl.PeerNewData{
		PageData:      pageData,
		InterfaceID:   ifaceID.String(),
		InterfaceName: iface.DisplayName,
		Agents:        h.wgAgentTargets(r),
	}))
}

// WireGuardPeerCreateTempl handles POST /wireguard/{id}/peers.
func (h *Handler) WireGuardPeerCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireWireGuardSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/wireguard", http.StatusSeeOther)
		return
	}

	ifaceID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Redirect(w, r, "/wireguard", http.StatusSeeOther)
		return
	}

	iface, err := svc.GetInterface(r.Context(), ifaceID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Interface not found.")
		return
	}

	keepalive := 25
	if k, err := strconv.Atoi(r.FormValue("persistent_keepalive")); err == nil {
		keepalive = k
	}

	agentTargets := make([]uuid.UUID, 0)
	for _, raw := range r.Form["agent_targets"] {
		if raw == "" {
			continue
		}
		id, parseErr := uuid.Parse(raw)
		if parseErr != nil {
			continue
		}
		agentTargets = append(agentTargets, id)
	}

	peer := &models.WireGuardPeer{
		InterfaceID:         ifaceID,
		HostID:              iface.HostID,
		Name:                r.FormValue("name"),
		Description:         r.FormValue("description"),
		PublicKey:           r.FormValue("public_key"),
		AllowedIPs:          r.FormValue("allowed_ips"),
		Endpoint:            r.FormValue("endpoint"),
		PersistentKeepalive: keepalive,
		Enabled:             true,
		CreatedBy:           h.wireguardUserUUID(r),
	}

	if err := svc.CreatePeer(r.Context(), peer, agentTargets); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to create peer: "+err.Error())
		return
	}

	http.Redirect(w, r, "/wireguard/peers/"+peer.ID.String(), http.StatusSeeOther)
}

// WireGuardPeerDetailTempl renders a peer detail page with the
// one-time QR widget and (in mesh mode) the propagation status.
func (h *Handler) WireGuardPeerDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireWireGuardSvc(w, r)
	if svc == nil {
		return
	}

	peerID, err := uuid.Parse(chi.URLParam(r, "peerID"))
	if err != nil {
		http.Redirect(w, r, "/wireguard/peers", http.StatusSeeOther)
		return
	}

	peer, err := svc.GetPeer(r.Context(), peerID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Peer not found.")
		return
	}

	links, _ := svc.ListMeshLinks(r.Context(), peerID)
	linkViews := make([]wgtpl.MeshLinkView, 0, len(links))
	for _, l := range links {
		linkViews = append(linkViews, wgMeshLinkToView(l, peer.Name))
	}

	pageData := h.prepareTemplPageData(r, "Peer: "+peer.Name, "wireguard")
	h.renderTempl(w, r, wgtpl.PeerDetail(wgtpl.PeerDetailData{
		PageData:  pageData,
		Peer:      wgPeerToView(peer),
		MeshLinks: linkViews,
	}))
}

// WireGuardPeerDeleteTempl deletes a peer.
func (h *Handler) WireGuardPeerDeleteTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireWireGuardSvc(w, r)
	if svc == nil {
		return
	}
	peerID, err := uuid.Parse(chi.URLParam(r, "peerID"))
	if err != nil {
		http.Redirect(w, r, "/wireguard", http.StatusSeeOther)
		return
	}
	_ = svc.DeletePeer(r.Context(), peerID)
	http.Redirect(w, r, "/wireguard", http.StatusSeeOther)
}

// ============================================================================
// Mesh status
// ============================================================================

// WireGuardMeshTempl renders the mesh-status page (all peer×agent rows).
func (h *Handler) WireGuardMeshTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireWireGuardSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "WireGuard Mesh", "wireguard")

	links, err := svc.ListMeshLinks(ctx, uuid.Nil)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load mesh links: "+err.Error())
		return
	}

	agentSet := make(map[uuid.UUID]struct{})
	views := make([]wgtpl.MeshLinkView, 0, len(links))
	var applied, pending, failed int
	for _, l := range links {
		// Try to enrich with peer name when cheap (single round-trip
		// per peer is acceptable for the typical < 100 row workload).
		name := ""
		if peer, gErr := svc.GetPeer(ctx, l.PeerID); gErr == nil {
			name = peer.Name
		}
		views = append(views, wgMeshLinkToView(l, name))
		agentSet[l.AgentHostID] = struct{}{}
		switch l.Status {
		case models.WGMeshLinkApplied:
			applied++
		case models.WGMeshLinkPending:
			pending++
		case models.WGMeshLinkFailed:
			failed++
		}
	}

	msg := ""
	if len(links) == 0 {
		msg = "No mesh links recorded yet. Mesh propagation requires master/agent mode; in standalone mode this page is empty."
	}

	h.renderTempl(w, r, wgtpl.Mesh(wgtpl.MeshData{
		PageData:      pageData,
		Links:         views,
		StandaloneMsg: msg,
		AgentCount:    len(agentSet),
		AppliedCount:  applied,
		PendingCount:  pending,
		FailedCount:   failed,
	}))
}

// ============================================================================
// View helpers
// ============================================================================

// wgAgentTargets returns the list of hosts the operator can push peer
// entries to. In standalone mode (no host service or no remote hosts)
// the list is empty and the form hides the propagation checkboxes.
//
// We deliberately do NOT include the master's own default host — the
// peer entry is already applied via the in-process service.
func (h *Handler) wgAgentTargets(r *http.Request) []wgtpl.AgentTarget {
	reg, ok := h.services.(*ServiceRegistry)
	if !ok || reg.hostSvc == nil {
		return nil
	}
	hosts, err := reg.hostSvc.ListSummaries(r.Context())
	if err != nil {
		return nil
	}
	targets := make([]wgtpl.AgentTarget, 0, len(hosts))
	for _, host := range hosts {
		if host.ID == reg.defaultHostID {
			continue
		}
		targets = append(targets, wgtpl.AgentTarget{
			HostID:   host.ID.String(),
			Hostname: host.Name,
		})
	}
	return targets
}

func wgInterfaceToView(iface *models.WireGuardInterface) wgtpl.InterfaceView {
	return wgtpl.InterfaceView{
		ID:          iface.ID.String(),
		Name:        iface.Name,
		DisplayName: iface.DisplayName,
		Address:     iface.Address,
		ListenPort:  iface.ListenPort,
		PublicKey:   iface.PublicKey,
		Status:      string(iface.Status),
		PeerCount:   iface.PeerCount,
		TransferRx:  formatBytes(iface.TransferRx),
		TransferTx:  formatBytes(iface.TransferTx),
		CreatedAt:   iface.CreatedAt.Format("2006-01-02 15:04"),
	}
}

func wgPeerToView(p *models.WireGuardPeer) wgtpl.PeerView {
	v := wgtpl.PeerView{
		ID:                  p.ID.String(),
		Name:                p.Name,
		PublicKey:           p.PublicKey,
		AllowedIPs:          p.AllowedIPs,
		Endpoint:            p.Endpoint,
		PersistentKeepalive: p.PersistentKeepalive,
		Enabled:             p.Enabled,
		TransferRx:          formatBytes(p.TransferRx),
		TransferTx:          formatBytes(p.TransferTx),
		CreatedAt:           p.CreatedAt.Format("2006-01-02 15:04"),
	}
	if p.LastHandshake != nil {
		v.LastHandshake = p.LastHandshake.Format("2006-01-02 15:04:05")
	}
	return v
}

func wgMeshLinkToView(l *models.WireGuardMeshLink, peerName string) wgtpl.MeshLinkView {
	v := wgtpl.MeshLinkView{
		PeerID:      l.PeerID.String(),
		PeerName:    peerName,
		AgentHostID: l.AgentHostID.String(),
		Status:      string(l.Status),
		LastError:   l.LastError,
		UpdatedAt:   l.UpdatedAt.Format("2006-01-02 15:04:05"),
	}
	if l.LastHandshake != nil {
		v.LastHandshake = l.LastHandshake.Format("2006-01-02 15:04:05")
	}
	if l.AppliedAt != nil {
		v.AppliedAt = l.AppliedAt.Format("2006-01-02 15:04:05")
	}
	return v
}
