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
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/network"
)

// NetworkHandler handles network-related HTTP requests.
type NetworkHandler struct {
	BaseHandler
	networkService *network.Service
}

// NewNetworkHandler creates a new network handler.
func NewNetworkHandler(networkService *network.Service, log *logger.Logger) *NetworkHandler {
	return &NetworkHandler{
		BaseHandler:    NewBaseHandler(log),
		networkService: networkService,
	}
}

// Routes returns the router for network endpoints.
func (h *NetworkHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Route("/{hostID}", func(r chi.Router) {
		// Read-only (viewer+)
		r.Get("/", h.ListNetworks)
		r.Get("/stats", h.GetStats)
		r.Get("/topology", h.GetTopology)
		r.Get("/dns", h.ListDNSConfigs)
		r.Get("/subnets/conflicts", h.GetSubnetConflicts)
		r.Get("/isolation", h.GetIsolationAnalysis)
		r.Get("/ports", h.GetHostPortMap)
		r.Get("/ports/conflicts", h.GetPortConflicts)
		r.Get("/traffic", h.GetTrafficFlow)

		// Operator+ for mutations
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireOperator)
			r.Post("/", h.CreateNetwork)
			r.Post("/prune", h.PruneNetworks)
			r.Post("/dns/validate", h.ValidateSubnet)
			r.Post("/ports/suggest", h.SuggestPorts)
		})

		r.Route("/{networkID}", func(r chi.Router) {
			// Read-only (viewer+)
			r.Get("/", h.GetNetwork)
			r.Get("/containers", h.GetContainers)
			r.Get("/dns", h.GetDNSConfig)
			r.Get("/isolation", h.GetNetworkIsolation)

			// Operator+ for mutations
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireOperator)
				r.Delete("/", h.DeleteNetwork)
				r.Post("/connect", h.ConnectContainer)
				r.Post("/disconnect", h.DisconnectContainer)
				r.Put("/dns", h.SetDNSConfig)
			})
		})
	})

	return r
}

// ============================================================================
// Request/Response types
// ============================================================================

// CreateNetworkRequest represents a network creation request.
type CreateNetworkRequest struct {
	Name       string              `json:"name"`
	Driver     string              `json:"driver,omitempty"`
	Internal   bool                `json:"internal,omitempty"`
	Attachable bool                `json:"attachable,omitempty"`
	Ingress    bool                `json:"ingress,omitempty"`
	EnableIPv6 bool                `json:"enable_ipv6,omitempty"`
	IPAM       *NetworkIPAMRequest `json:"ipam,omitempty"`
	Options    map[string]string   `json:"options,omitempty"`
	Labels     map[string]string   `json:"labels,omitempty"`
}

// NetworkIPAMRequest represents IPAM configuration.
type NetworkIPAMRequest struct {
	Driver  string              `json:"driver,omitempty"`
	Config  []IPAMConfigRequest `json:"config,omitempty"`
	Options map[string]string   `json:"options,omitempty"`
}

// IPAMConfigRequest represents IPAM pool configuration.
type IPAMConfigRequest struct {
	Subnet     string            `json:"subnet,omitempty"`
	IPRange    string            `json:"ip_range,omitempty"`
	Gateway    string            `json:"gateway,omitempty"`
	AuxAddress map[string]string `json:"aux_address,omitempty"`
}

// ConnectRequest represents a container connect request.
type ConnectRequest struct {
	ContainerID string   `json:"container_id"`
	Aliases     []string `json:"aliases,omitempty"`
}

// DisconnectRequest represents a container disconnect request.
type DisconnectRequest struct {
	ContainerID string `json:"container_id"`
	Force       bool   `json:"force,omitempty"`
}

// NetworkResponse represents a network in API responses.
type NetworkResponse struct {
	ID         string                           `json:"id"`
	HostID     string                           `json:"host_id"`
	Name       string                           `json:"name"`
	Driver     string                           `json:"driver"`
	Scope      string                           `json:"scope"`
	EnableIPv6 bool                             `json:"enable_ipv6"`
	Internal   bool                             `json:"internal"`
	Attachable bool                             `json:"attachable"`
	Ingress    bool                             `json:"ingress"`
	IPAM       NetworkIPAMResponse              `json:"ipam"`
	Options    map[string]string                `json:"options,omitempty"`
	Labels     map[string]string                `json:"labels,omitempty"`
	Containers map[string]ContainerInfoResponse `json:"containers,omitempty"`
	CreatedAt  string                           `json:"created_at"`
	SyncedAt   string                           `json:"synced_at"`
}

// NetworkIPAMResponse represents IPAM configuration.
type NetworkIPAMResponse struct {
	Driver  string               `json:"driver,omitempty"`
	Config  []IPAMConfigResponse `json:"config,omitempty"`
	Options map[string]string    `json:"options,omitempty"`
}

// IPAMConfigResponse represents IPAM pool configuration.
type IPAMConfigResponse struct {
	Subnet     string            `json:"subnet,omitempty"`
	IPRange    string            `json:"ip_range,omitempty"`
	Gateway    string            `json:"gateway,omitempty"`
	AuxAddress map[string]string `json:"aux_address,omitempty"`
}

// ContainerInfoResponse represents container info in a network.
type ContainerInfoResponse struct {
	Name        string `json:"name"`
	EndpointID  string `json:"endpoint_id"`
	MacAddress  string `json:"mac_address"`
	IPv4Address string `json:"ipv4_address"`
	IPv6Address string `json:"ipv6_address,omitempty"`
}

// NetworkStatsResponse represents network statistics.
type NetworkStatsResponse struct {
	Total      int `json:"total"`
	Bridge     int `json:"bridge"`
	Host       int `json:"host"`
	Overlay    int `json:"overlay"`
	Macvlan    int `json:"macvlan"`
	None       int `json:"none"`
	Custom     int `json:"custom"`
	Internal   int `json:"internal"`
	Attachable int `json:"attachable"`
}

// PruneNetworksResponse represents prune result.
type PruneNetworksResponse struct {
	NetworksDeleted []string `json:"networks_deleted"`
}

// DNSConfigRequest represents DNS configuration input.
type DNSConfigRequest struct {
	Servers []string `json:"servers,omitempty"`
	Search  []string `json:"search,omitempty"`
	Options []string `json:"options,omitempty"`
}

// DNSConfigResponse represents DNS configuration output.
type DNSConfigResponse struct {
	NetworkID   string   `json:"network_id"`
	NetworkName string   `json:"network_name"`
	Servers     []string `json:"servers,omitempty"`
	Search      []string `json:"search,omitempty"`
	Options     []string `json:"options,omitempty"`
}

// ValidateSubnetRequest represents subnet validation input.
type ValidateSubnetRequest struct {
	Subnet string `json:"subnet"`
}

// ValidateSubnetResponse represents subnet validation output.
type ValidateSubnetResponse struct {
	Valid     bool                     `json:"valid"`
	Subnet    string                   `json:"subnet"`
	Conflicts []SubnetConflictResponse `json:"conflicts,omitempty"`
}

// SubnetConflictResponse represents a subnet conflict.
type SubnetConflictResponse struct {
	Network1ID     string `json:"network1_id"`
	Network1Name   string `json:"network1_name"`
	Network1Subnet string `json:"network1_subnet"`
	Network2ID     string `json:"network2_id"`
	Network2Name   string `json:"network2_name"`
	Network2Subnet string `json:"network2_subnet"`
	ConflictType   string `json:"conflict_type"`
	Description    string `json:"description"`
}

// SubnetAnalysisResponse represents subnet analysis output.
type SubnetAnalysisResponse struct {
	TotalNetworks   int                      `json:"total_networks"`
	TotalSubnets    int                      `json:"total_subnets"`
	Conflicts       []SubnetConflictResponse `json:"conflicts,omitempty"`
	Warnings        []string                 `json:"warnings,omitempty"`
	AvailableRanges []string                 `json:"available_ranges,omitempty"`
}

// IsolationAnalysisResponse represents network isolation analysis output.
type IsolationAnalysisResponse struct {
	NetworkID         string                 `json:"network_id"`
	NetworkName       string                 `json:"network_name"`
	IsIsolated        bool                   `json:"is_isolated"`
	IsInternal        bool                   `json:"is_internal"`
	HasExternalAccess bool                   `json:"has_external_access"`
	ConnectedNetworks []string               `json:"connected_networks,omitempty"`
	SharedContainers  []string               `json:"shared_containers,omitempty"`
	IsolationScore    int                    `json:"isolation_score"`
	Recommendations   []string               `json:"recommendations,omitempty"`
	SecurityRisks     []SecurityRiskResponse `json:"security_risks,omitempty"`
}

// SecurityRiskResponse represents a security risk.
type SecurityRiskResponse struct {
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Mitigation  string `json:"mitigation"`
}

// PortSuggestionRequest represents port suggestion input.
type PortSuggestionRequest struct {
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol,omitempty"`
}

// PortSuggestionResponse represents port suggestion output.
type PortSuggestionResponse struct {
	RequestedPort  uint16   `json:"requested_port"`
	ConflictsWith  string   `json:"conflicts_with,omitempty"`
	SuggestedPorts []uint16 `json:"suggested_ports"`
	PortRange      string   `json:"port_range,omitempty"`
	Reason         string   `json:"reason,omitempty"`
}

// NetworkPortMappingResponse represents a port mapping in network context.
type NetworkPortMappingResponse struct {
	HostPort       uint16 `json:"host_port"`
	ContainerPort  uint16 `json:"container_port"`
	Protocol       string `json:"protocol"`
	HostIP         string `json:"host_ip"`
	ContainerID    string `json:"container_id"`
	ContainerName  string `json:"container_name"`
	ContainerImage string `json:"container_image,omitempty"`
	IsWellKnown    bool   `json:"is_well_known"`
	ServiceName    string `json:"service_name,omitempty"`
}

// HostPortMapResponse represents port map for a host.
type HostPortMapResponse struct {
	HostID      string                       `json:"host_id"`
	TotalPorts  int                          `json:"total_ports"`
	UsedPorts   int                          `json:"used_ports"`
	Ports       []NetworkPortMappingResponse `json:"ports"`
	ByProtocol  map[string]int               `json:"by_protocol"`
	ByContainer map[string]int               `json:"by_container"`
}

// PortConflictResponse represents a port conflict.
type PortConflictResponse struct {
	Port        uint16   `json:"port"`
	Protocol    string   `json:"protocol"`
	HostIP      string   `json:"host_ip"`
	Containers  []string `json:"containers"`
	Description string   `json:"description"`
}

// TrafficFlowResponse represents traffic flow analysis output.
type TrafficFlowResponse struct {
	HostID      string                        `json:"host_id"`
	CapturedAt  string                        `json:"captured_at"`
	Connections []ContainerConnectionResponse `json:"connections,omitempty"`
	Summary     TrafficSummaryResponse        `json:"summary"`
}

// ContainerConnectionResponse represents a container connection.
type ContainerConnectionResponse struct {
	SourceContainerID   string `json:"source_container_id,omitempty"`
	SourceContainerName string `json:"source_container_name,omitempty"`
	SourceIP            string `json:"source_ip,omitempty"`
	SourcePort          uint16 `json:"source_port,omitempty"`
	DestContainerID     string `json:"dest_container_id,omitempty"`
	DestContainerName   string `json:"dest_container_name,omitempty"`
	DestIP              string `json:"dest_ip,omitempty"`
	DestPort            uint16 `json:"dest_port,omitempty"`
	Protocol            string `json:"protocol"`
	State               string `json:"state,omitempty"`
	BytesSent           uint64 `json:"bytes_sent,omitempty"`
	BytesReceived       uint64 `json:"bytes_received,omitempty"`
	NetworkID           string `json:"network_id,omitempty"`
	NetworkName         string `json:"network_name,omitempty"`
}

// TrafficSummaryResponse represents traffic summary.
type TrafficSummaryResponse struct {
	TotalConnections    int    `json:"total_connections"`
	InternalConnections int    `json:"internal_connections"`
	ExternalConnections int    `json:"external_connections"`
	TCPConnections      int    `json:"tcp_connections"`
	UDPConnections      int    `json:"udp_connections"`
	TotalBytesSent      uint64 `json:"total_bytes_sent"`
	TotalBytesReceived  uint64 `json:"total_bytes_received"`
}

// ============================================================================
// Handlers
// ============================================================================

// ListNetworks returns all networks for a host.
// GET /api/v1/networks/{hostID}
func (h *NetworkHandler) ListNetworks(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	// Check for driver filter
	driver := h.QueryParam(r, "driver")

	var networks []*models.Network
	if driver != "" {
		networks, err = h.networkService.ListByDriver(r.Context(), hostID, driver)
	} else {
		networks, err = h.networkService.List(r.Context(), hostID)
	}
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]NetworkResponse, len(networks))
	for i, n := range networks {
		resp[i] = toNetworkResponse(n)
	}

	h.OK(w, resp)
}

// CreateNetwork creates a new network.
// POST /api/v1/networks/{hostID}
func (h *NetworkHandler) CreateNetwork(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req CreateNetworkRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Name == "" {
		h.BadRequest(w, "name is required")
		return
	}

	input := &models.CreateNetworkInput{
		Name:       req.Name,
		Driver:     req.Driver,
		Internal:   req.Internal,
		Attachable: req.Attachable,
		Ingress:    req.Ingress,
		EnableIPv6: req.EnableIPv6,
		Options:    req.Options,
		Labels:     req.Labels,
	}

	if req.IPAM != nil {
		input.IPAM = &models.NetworkIPAMInput{
			Driver:  req.IPAM.Driver,
			Options: req.IPAM.Options,
		}
		if len(req.IPAM.Config) > 0 {
			input.IPAM.Config = make([]models.IPAMConfigInput, len(req.IPAM.Config))
			for i, c := range req.IPAM.Config {
				input.IPAM.Config[i] = models.IPAMConfigInput{
					Subnet:     c.Subnet,
					IPRange:    c.IPRange,
					Gateway:    c.Gateway,
					AuxAddress: c.AuxAddress,
				}
			}
		}
	}

	net, err := h.networkService.Create(r.Context(), hostID, input)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, toNetworkResponse(net))
}

// GetNetwork returns a specific network.
// GET /api/v1/networks/{hostID}/{networkID}
func (h *NetworkHandler) GetNetwork(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	networkID := h.URLParam(r, "networkID")
	if networkID == "" {
		h.BadRequest(w, "networkID is required")
		return
	}

	net, err := h.networkService.Get(r.Context(), hostID, networkID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toNetworkResponse(net))
}

// DeleteNetwork deletes a network.
// DELETE /api/v1/networks/{hostID}/{networkID}
func (h *NetworkHandler) DeleteNetwork(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	networkID := h.URLParam(r, "networkID")
	if networkID == "" {
		h.BadRequest(w, "networkID is required")
		return
	}

	if err := h.networkService.Delete(r.Context(), hostID, networkID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// GetContainers returns containers connected to a network.
// GET /api/v1/networks/{hostID}/{networkID}/containers
func (h *NetworkHandler) GetContainers(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	networkID := h.URLParam(r, "networkID")
	if networkID == "" {
		h.BadRequest(w, "networkID is required")
		return
	}

	containers, err := h.networkService.GetContainers(r.Context(), hostID, networkID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]ContainerInfoResponse, len(containers))
	for i, c := range containers {
		resp[i] = ContainerInfoResponse{
			Name:        c.Name,
			EndpointID:  c.EndpointID,
			MacAddress:  c.MacAddress,
			IPv4Address: c.IPv4Address,
			IPv6Address: c.IPv6Address,
		}
	}

	h.OK(w, resp)
}

// ConnectContainer connects a container to a network.
// POST /api/v1/networks/{hostID}/{networkID}/connect
func (h *NetworkHandler) ConnectContainer(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	networkID := h.URLParam(r, "networkID")
	if networkID == "" {
		h.BadRequest(w, "networkID is required")
		return
	}

	var req ConnectRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.ContainerID == "" {
		h.BadRequest(w, "container_id is required")
		return
	}

	if err := h.networkService.Connect(r.Context(), hostID, networkID, req.ContainerID, req.Aliases); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// DisconnectContainer disconnects a container from a network.
// POST /api/v1/networks/{hostID}/{networkID}/disconnect
func (h *NetworkHandler) DisconnectContainer(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	networkID := h.URLParam(r, "networkID")
	if networkID == "" {
		h.BadRequest(w, "networkID is required")
		return
	}

	var req DisconnectRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.ContainerID == "" {
		h.BadRequest(w, "container_id is required")
		return
	}

	if err := h.networkService.Disconnect(r.Context(), hostID, networkID, req.ContainerID, req.Force); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// GetStats returns network statistics.
// GET /api/v1/networks/{hostID}/stats
func (h *NetworkHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	stats, err := h.networkService.GetStats(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, NetworkStatsResponse{
		Total:      stats.Total,
		Bridge:     stats.Bridge,
		Host:       stats.Host,
		Overlay:    stats.Overlay,
		Macvlan:    stats.Macvlan,
		None:       stats.None,
		Custom:     stats.Custom,
		Internal:   stats.Internal,
		Attachable: stats.Attachable,
	})
}

// GetTopology returns network topology.
// GET /api/v1/networks/{hostID}/topology
func (h *NetworkHandler) GetTopology(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	topology, err := h.networkService.GetTopology(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, topology)
}

// PruneNetworks removes unused networks.
// POST /api/v1/networks/{hostID}/prune
func (h *NetworkHandler) PruneNetworks(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	result, err := h.networkService.Prune(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, PruneNetworksResponse{
		NetworksDeleted: result.ItemsDeleted,
	})
}

// ============================================================================
// DNS Configuration Handlers
// ============================================================================

// ListDNSConfigs returns DNS configurations for all networks on a host.
// GET /api/v1/networks/{hostID}/dns
func (h *NetworkHandler) ListDNSConfigs(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	configs, err := h.networkService.ListNetworksWithDNS(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]DNSConfigResponse, len(configs))
	for i, c := range configs {
		resp[i] = DNSConfigResponse{
			NetworkID:   c.NetworkID,
			NetworkName: c.NetworkName,
			Servers:     c.Servers,
			Search:      c.Search,
			Options:     c.Options,
		}
	}

	h.OK(w, resp)
}

// GetDNSConfig returns DNS configuration for a specific network.
// GET /api/v1/networks/{hostID}/{networkID}/dns
func (h *NetworkHandler) GetDNSConfig(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	networkID := h.URLParam(r, "networkID")
	if networkID == "" {
		h.BadRequest(w, "networkID is required")
		return
	}

	config, err := h.networkService.GetDNSConfig(r.Context(), hostID, networkID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, DNSConfigResponse{
		NetworkID:   config.NetworkID,
		NetworkName: config.NetworkName,
		Servers:     config.Servers,
		Search:      config.Search,
		Options:     config.Options,
	})
}

// SetDNSConfig sets DNS configuration for a network.
// PUT /api/v1/networks/{hostID}/{networkID}/dns
func (h *NetworkHandler) SetDNSConfig(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	networkID := h.URLParam(r, "networkID")
	if networkID == "" {
		h.BadRequest(w, "networkID is required")
		return
	}

	var req DNSConfigRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	input := &models.SetDNSConfigInput{
		Servers: req.Servers,
		Search:  req.Search,
		Options: req.Options,
	}

	config, err := h.networkService.SetDNSConfig(r.Context(), hostID, networkID, input)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, DNSConfigResponse{
		NetworkID:   config.NetworkID,
		NetworkName: config.NetworkName,
		Servers:     config.Servers,
		Search:      config.Search,
		Options:     config.Options,
	})
}

// ============================================================================
// Subnet Analysis Handlers
// ============================================================================

// ValidateSubnet validates a proposed subnet against existing networks.
// POST /api/v1/networks/{hostID}/dns/validate
func (h *NetworkHandler) ValidateSubnet(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req ValidateSubnetRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Subnet == "" {
		h.BadRequest(w, "subnet is required")
		return
	}

	valid, conflicts, err := h.networkService.ValidateNewSubnet(r.Context(), hostID, req.Subnet)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := ValidateSubnetResponse{
		Valid:  valid,
		Subnet: req.Subnet,
	}

	for _, c := range conflicts {
		resp.Conflicts = append(resp.Conflicts, SubnetConflictResponse{
			Network1ID:     c.Network1ID,
			Network1Name:   c.Network1Name,
			Network1Subnet: c.Network1Subnet,
			Network2ID:     c.Network2ID,
			Network2Name:   c.Network2Name,
			Network2Subnet: c.Network2Subnet,
			ConflictType:   c.ConflictType,
			Description:    c.Description,
		})
	}

	h.OK(w, resp)
}

// GetSubnetConflicts returns all subnet conflicts on a host.
// GET /api/v1/networks/{hostID}/subnets/conflicts
func (h *NetworkHandler) GetSubnetConflicts(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	analysis, err := h.networkService.DetectSubnetConflicts(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := SubnetAnalysisResponse{
		TotalNetworks:   analysis.TotalNetworks,
		TotalSubnets:    analysis.TotalSubnets,
		Warnings:        analysis.Warnings,
		AvailableRanges: analysis.AvailableRanges,
	}

	for _, c := range analysis.Conflicts {
		resp.Conflicts = append(resp.Conflicts, SubnetConflictResponse{
			Network1ID:     c.Network1ID,
			Network1Name:   c.Network1Name,
			Network1Subnet: c.Network1Subnet,
			Network2ID:     c.Network2ID,
			Network2Name:   c.Network2Name,
			Network2Subnet: c.Network2Subnet,
			ConflictType:   c.ConflictType,
			Description:    c.Description,
		})
	}

	h.OK(w, resp)
}

// ============================================================================
// Isolation Analysis Handlers
// ============================================================================

// GetIsolationAnalysis returns isolation analysis for all networks on a host.
// GET /api/v1/networks/{hostID}/isolation
func (h *NetworkHandler) GetIsolationAnalysis(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	analyses, err := h.networkService.AnalyzeAllIsolation(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]IsolationAnalysisResponse, len(analyses))
	for i, a := range analyses {
		resp[i] = toIsolationResponse(a)
	}

	h.OK(w, resp)
}

// GetNetworkIsolation returns isolation analysis for a specific network.
// GET /api/v1/networks/{hostID}/{networkID}/isolation
func (h *NetworkHandler) GetNetworkIsolation(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	networkID := h.URLParam(r, "networkID")
	if networkID == "" {
		h.BadRequest(w, "networkID is required")
		return
	}

	analysis, err := h.networkService.AnalyzeIsolation(r.Context(), hostID, networkID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toIsolationResponse(analysis))
}

func toIsolationResponse(a *models.NetworkIsolationAnalysis) IsolationAnalysisResponse {
	resp := IsolationAnalysisResponse{
		NetworkID:         a.NetworkID,
		NetworkName:       a.NetworkName,
		IsIsolated:        a.IsIsolated,
		IsInternal:        a.IsInternal,
		HasExternalAccess: a.HasExternalAccess,
		ConnectedNetworks: a.ConnectedNetworks,
		SharedContainers:  a.SharedContainers,
		IsolationScore:    a.IsolationScore,
		Recommendations:   a.Recommendations,
	}

	for _, r := range a.SecurityRisks {
		resp.SecurityRisks = append(resp.SecurityRisks, SecurityRiskResponse{
			Severity:    r.Severity,
			Category:    r.Category,
			Description: r.Description,
			Mitigation:  r.Mitigation,
		})
	}

	return resp
}

// ============================================================================
// Traffic Flow Handlers
// ============================================================================

// GetTrafficFlow returns traffic flow analysis for a host.
// GET /api/v1/networks/{hostID}/traffic
func (h *NetworkHandler) GetTrafficFlow(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	analysis, err := h.networkService.GetTrafficFlow(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := TrafficFlowResponse{
		HostID:     analysis.HostID,
		CapturedAt: analysis.CapturedAt,
		Summary: TrafficSummaryResponse{
			TotalConnections:    analysis.Summary.TotalConnections,
			InternalConnections: analysis.Summary.InternalConnections,
			ExternalConnections: analysis.Summary.ExternalConnections,
			TCPConnections:      analysis.Summary.TCPConnections,
			UDPConnections:      analysis.Summary.UDPConnections,
			TotalBytesSent:      analysis.Summary.TotalBytesSent,
			TotalBytesReceived:  analysis.Summary.TotalBytesReceived,
		},
	}

	for _, c := range analysis.Connections {
		resp.Connections = append(resp.Connections, ContainerConnectionResponse{
			SourceContainerID:   c.SourceContainerID,
			SourceContainerName: c.SourceContainerName,
			SourceIP:            c.SourceIP,
			SourcePort:          c.SourcePort,
			DestContainerID:     c.DestContainerID,
			DestContainerName:   c.DestContainerName,
			DestIP:              c.DestIP,
			DestPort:            c.DestPort,
			Protocol:            c.Protocol,
			State:               c.State,
			BytesSent:           c.BytesSent,
			BytesReceived:       c.BytesReceived,
			NetworkID:           c.NetworkID,
			NetworkName:         c.NetworkName,
		})
	}

	h.OK(w, resp)
}

// ============================================================================
// Port Analysis Handlers
// ============================================================================

// GetHostPortMap returns all port mappings on a host.
// GET /api/v1/networks/{hostID}/ports
func (h *NetworkHandler) GetHostPortMap(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	portMap, err := h.networkService.GetHostPortMap(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := HostPortMapResponse{
		HostID:      portMap.HostID,
		TotalPorts:  portMap.TotalPorts,
		UsedPorts:   portMap.UsedPorts,
		ByProtocol:  portMap.ByProtocol,
		ByContainer: portMap.ByContainer,
	}

	for _, p := range portMap.Ports {
		resp.Ports = append(resp.Ports, NetworkPortMappingResponse{
			HostPort:       p.HostPort,
			ContainerPort:  p.ContainerPort,
			Protocol:       p.Protocol,
			HostIP:         p.HostIP,
			ContainerID:    p.ContainerID,
			ContainerName:  p.ContainerName,
			ContainerImage: p.ContainerImage,
			IsWellKnown:    p.IsWellKnown,
			ServiceName:    p.ServiceName,
		})
	}

	h.OK(w, resp)
}

// GetPortConflicts returns port conflicts on a host.
// GET /api/v1/networks/{hostID}/ports/conflicts
func (h *NetworkHandler) GetPortConflicts(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	conflicts, err := h.networkService.AnalyzePortConflicts(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]PortConflictResponse, len(conflicts))
	for i, c := range conflicts {
		resp[i] = PortConflictResponse{
			Port:        c.Port,
			Protocol:    c.Protocol,
			HostIP:      c.HostIP,
			Containers:  c.Containers,
			Description: c.Description,
		}
	}

	h.OK(w, resp)
}

// SuggestPorts suggests alternative ports when a requested port is in use.
// POST /api/v1/networks/{hostID}/ports/suggest
func (h *NetworkHandler) SuggestPorts(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req PortSuggestionRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Port == 0 {
		h.BadRequest(w, "port is required")
		return
	}

	if req.Protocol == "" {
		req.Protocol = "tcp"
	}

	suggestion, err := h.networkService.SuggestAlternativePorts(r.Context(), hostID, req.Port, req.Protocol)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, PortSuggestionResponse{
		RequestedPort:  suggestion.RequestedPort,
		ConflictsWith:  suggestion.ConflictsWith,
		SuggestedPorts: suggestion.SuggestedPorts,
		PortRange:      suggestion.PortRange,
		Reason:         suggestion.Reason,
	})
}

// ============================================================================
// Helpers
// ============================================================================

func toNetworkResponse(n *models.Network) NetworkResponse {
	resp := NetworkResponse{
		ID:         n.ID,
		HostID:     n.HostID.String(),
		Name:       n.Name,
		Driver:     n.Driver,
		Scope:      string(n.Scope),
		EnableIPv6: n.EnableIPv6,
		Internal:   n.Internal,
		Attachable: n.Attachable,
		Ingress:    n.Ingress,
		Options:    n.Options,
		Labels:     n.Labels,
		CreatedAt:  n.CreatedAt.Format(time.RFC3339),
		SyncedAt:   n.SyncedAt.Format(time.RFC3339),
	}

	// IPAM
	resp.IPAM = NetworkIPAMResponse{
		Driver:  n.IPAM.Driver,
		Options: n.IPAM.Options,
	}
	if len(n.IPAM.Config) > 0 {
		resp.IPAM.Config = make([]IPAMConfigResponse, len(n.IPAM.Config))
		for i, c := range n.IPAM.Config {
			resp.IPAM.Config[i] = IPAMConfigResponse{
				Subnet:     c.Subnet,
				IPRange:    c.IPRange,
				Gateway:    c.Gateway,
				AuxAddress: c.AuxAddress,
			}
		}
	}

	// Containers
	if len(n.Containers) > 0 {
		resp.Containers = make(map[string]ContainerInfoResponse)
		for id, c := range n.Containers {
			resp.Containers[id] = ContainerInfoResponse{
				Name:        c.Name,
				EndpointID:  c.EndpointID,
				MacAddress:  c.MacAddress,
				IPv4Address: c.IPv4Address,
				IPv6Address: c.IPv6Address,
			}
		}
	}

	return resp
}
