// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// NetworkScope represents the scope of a network
type NetworkScope string

const (
	NetworkScopeLocal  NetworkScope = "local"
	NetworkScopeSwarm  NetworkScope = "swarm"
	NetworkScopeGlobal NetworkScope = "global"
)

// NetworkDriver represents network driver types
const (
	NetworkDriverBridge  = "bridge"
	NetworkDriverHost    = "host"
	NetworkDriverOverlay = "overlay"
	NetworkDriverMacvlan = "macvlan"
	NetworkDriverIPvlan  = "ipvlan"
	NetworkDriverNone    = "none"
)

// Network represents a Docker network (cached state)
type Network struct {
	ID         string                          `json:"id" db:"id"`
	HostID     uuid.UUID                       `json:"host_id" db:"host_id"`
	Name       string                          `json:"name" db:"name"`
	Driver     string                          `json:"driver" db:"driver"`
	Scope      NetworkScope                    `json:"scope" db:"scope"`
	EnableIPv6 bool                            `json:"enable_ipv6" db:"enable_ipv6"`
	Internal   bool                            `json:"internal" db:"internal"`
	Attachable bool                            `json:"attachable" db:"attachable"`
	Ingress    bool                            `json:"ingress" db:"ingress"`
	IPAM       NetworkIPAM                     `json:"ipam" db:"ipam"`
	Options    map[string]string               `json:"options,omitempty" db:"options"`
	Labels     map[string]string               `json:"labels,omitempty" db:"labels"`
	Containers map[string]NetworkContainerInfo `json:"containers,omitempty" db:"-"` // Not persisted
	CreatedAt  time.Time                       `json:"created_at" db:"created_at"`
	SyncedAt   time.Time                       `json:"synced_at" db:"synced_at"`
}

// IsSystem returns true if network is a system network (bridge, host, none)
func (n *Network) IsSystem() bool {
	return n.Name == "bridge" || n.Name == "host" || n.Name == "none"
}

// IsBridge returns true if network uses bridge driver
func (n *Network) IsBridge() bool {
	return n.Driver == NetworkDriverBridge
}

// IsOverlay returns true if network uses overlay driver
func (n *Network) IsOverlay() bool {
	return n.Driver == NetworkDriverOverlay
}

// ContainerCount returns the number of connected containers
func (n *Network) ContainerCount() int {
	return len(n.Containers)
}

// NetworkIPAM represents IPAM configuration
type NetworkIPAM struct {
	Driver  string            `json:"driver,omitempty"`
	Config  []IPAMConfig      `json:"config,omitempty"`
	Options map[string]string `json:"options,omitempty"`
}

// IPAMConfig represents IPAM pool configuration
type IPAMConfig struct {
	Subnet     string            `json:"subnet,omitempty"`
	IPRange    string            `json:"ip_range,omitempty"`
	Gateway    string            `json:"gateway,omitempty"`
	AuxAddress map[string]string `json:"aux_address,omitempty"`
}

// NetworkContainerInfo represents container info in a network
type NetworkContainerInfo struct {
	Name        string `json:"name"`
	EndpointID  string `json:"endpoint_id"`
	MacAddress  string `json:"mac_address"`
	IPv4Address string `json:"ipv4_address"`
	IPv6Address string `json:"ipv6_address,omitempty"`
}

// NetworkInspect represents detailed network information
type NetworkInspect struct {
	Network
	ConfigFrom ConfigReference        `json:"config_from,omitempty"`
	ConfigOnly bool                   `json:"config_only"`
	Peers      []PeerInfo             `json:"peers,omitempty"`
	Services   map[string]ServiceInfo `json:"services,omitempty"`
}

// ConfigReference represents a network config reference
type ConfigReference struct {
	Network string `json:"network"`
}

// PeerInfo represents peer information (Swarm)
type PeerInfo struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}

// ServiceInfo represents service info in a network
type ServiceInfo struct {
	VIP          string   `json:"vip,omitempty"`
	Ports        []string `json:"ports,omitempty"`
	LocalLBIndex int      `json:"local_lb_index"`
	Tasks        []Task   `json:"tasks,omitempty"`
}

// Task represents a Swarm task
type Task struct {
	Name       string            `json:"name"`
	EndpointID string            `json:"endpoint_id"`
	EndpointIP string            `json:"endpoint_ip"`
	Info       map[string]string `json:"info,omitempty"`
}

// CreateNetworkInput represents input for creating a network
type CreateNetworkInput struct {
	Name       string            `json:"name" validate:"required,min=1,max=255"`
	Driver     string            `json:"driver,omitempty"`
	Internal   bool              `json:"internal,omitempty"`
	Attachable bool              `json:"attachable,omitempty"`
	Ingress    bool              `json:"ingress,omitempty"`
	EnableIPv6 bool              `json:"enable_ipv6,omitempty"`
	IPAM       *NetworkIPAMInput `json:"ipam,omitempty"`
	Options    map[string]string `json:"options,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// NetworkIPAMInput represents IPAM input configuration
type NetworkIPAMInput struct {
	Driver  string            `json:"driver,omitempty"`
	Config  []IPAMConfigInput `json:"config,omitempty"`
	Options map[string]string `json:"options,omitempty"`
}

// IPAMConfigInput represents IPAM pool input
type IPAMConfigInput struct {
	Subnet     string            `json:"subnet,omitempty"`
	IPRange    string            `json:"ip_range,omitempty"`
	Gateway    string            `json:"gateway,omitempty"`
	AuxAddress map[string]string `json:"aux_address,omitempty"`
}

// ConnectNetworkInput represents input for connecting a container to a network
type ConnectNetworkInput struct {
	ContainerID    string               `json:"container_id" validate:"required"`
	EndpointConfig *EndpointConfigInput `json:"endpoint_config,omitempty"`
}

// EndpointConfigInput represents endpoint configuration input
type EndpointConfigInput struct {
	IPAMConfig *IPAMEndpointConfig `json:"ipam_config,omitempty"`
	Aliases    []string            `json:"aliases,omitempty"`
	DriverOpts map[string]string   `json:"driver_opts,omitempty"`
}

// IPAMEndpointConfig represents IPAM endpoint configuration
type IPAMEndpointConfig struct {
	IPv4Address  string   `json:"ipv4_address,omitempty"`
	IPv6Address  string   `json:"ipv6_address,omitempty"`
	LinkLocalIPs []string `json:"link_local_ips,omitempty"`
}

// DisconnectNetworkInput represents input for disconnecting a container
type DisconnectNetworkInput struct {
	ContainerID string `json:"container_id" validate:"required"`
	Force       bool   `json:"force,omitempty"`
}

// NetworkListOptions represents options for listing networks
type NetworkListOptions struct {
	Filters map[string][]string `json:"filters,omitempty"`
}

// NetworkPruneReport represents network prune result
type NetworkPruneReport struct {
	NetworksDeleted []string `json:"networks_deleted,omitempty"`
}

// NetworkTopology represents the network topology for visualization
type NetworkTopology struct {
	Networks   []NetworkNode   `json:"networks"`
	Containers []ContainerNode `json:"containers"`
	Edges      []TopologyEdge  `json:"edges"`
}

// NetworkNode represents a network in the topology
type NetworkNode struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Driver   string `json:"driver"`
	Subnet   string `json:"subnet,omitempty"`
	Internal bool   `json:"internal"`
}

// ContainerNode represents a container in the topology
type ContainerNode struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Image string `json:"image"`
	State string `json:"state"`
}

// TopologyEdge represents a connection between container and network
type TopologyEdge struct {
	Source     string `json:"source"` // Container ID
	Target     string `json:"target"` // Network ID
	IPAddress  string `json:"ip_address"`
	MacAddress string `json:"mac_address,omitempty"`
}

// PortAnalysis represents port security analysis for a network
type PortAnalysis struct {
	NetworkID    string         `json:"network_id"`
	NetworkName  string         `json:"network_name"`
	ExposedPorts []ExposedPort  `json:"exposed_ports"`
	Conflicts    []PortConflict `json:"conflicts"`
	Warnings     []PortWarning  `json:"warnings"`
}

// ExposedPort represents an exposed port
type ExposedPort struct {
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	ContainerPort uint16 `json:"container_port"`
	HostPort      uint16 `json:"host_port"`
	HostIP        string `json:"host_ip"`
	Protocol      string `json:"protocol"`
}

// PortConflict represents a port conflict
type PortConflict struct {
	Port        uint16   `json:"port"`
	Protocol    string   `json:"protocol"`
	HostIP      string   `json:"host_ip"`
	Containers  []string `json:"containers"`
	Description string   `json:"description"`
}

// PortWarning represents a port security warning
type PortWarning struct {
	ContainerID    string `json:"container_id"`
	ContainerName  string `json:"container_name"`
	Port           uint16 `json:"port"`
	Protocol       string `json:"protocol"`
	Severity       string `json:"severity"` // low, medium, high, critical
	Message        string `json:"message"`
	Recommendation string `json:"recommendation"`
}

// NetworkStats holds network statistics.
type NetworkStats struct {
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

// ============================================================================
// DNS Configuration
// ============================================================================

// NetworkDNSConfig represents custom DNS configuration for a network
type NetworkDNSConfig struct {
	NetworkID   string   `json:"network_id"`
	NetworkName string   `json:"network_name"`
	Servers     []string `json:"servers,omitempty"` // DNS server IPs (e.g., ["8.8.8.8", "8.8.4.4"])
	Search      []string `json:"search,omitempty"`  // DNS search domains (e.g., ["example.com"])
	Options     []string `json:"options,omitempty"` // DNS options (e.g., ["ndots:2", "timeout:5"])
}

// Label keys for storing DNS configuration in network labels
const (
	LabelDNSServers = "usulnet.dns.servers" // Comma-separated DNS servers
	LabelDNSSearch  = "usulnet.dns.search"  // Comma-separated search domains
	LabelDNSOptions = "usulnet.dns.options" // Comma-separated DNS options
)

// SetDNSConfigInput represents input for setting DNS configuration on a network
type SetDNSConfigInput struct {
	Servers []string `json:"servers,omitempty" validate:"dive,ip"`
	Search  []string `json:"search,omitempty" validate:"dive,hostname"`
	Options []string `json:"options,omitempty"`
}

// ============================================================================
// Subnet Conflict Detection
// ============================================================================

// SubnetConflict represents a conflict between network subnets
type SubnetConflict struct {
	Network1ID     string `json:"network1_id"`
	Network1Name   string `json:"network1_name"`
	Network1Subnet string `json:"network1_subnet"`
	Network2ID     string `json:"network2_id"`
	Network2Name   string `json:"network2_name"`
	Network2Subnet string `json:"network2_subnet"`
	ConflictType   string `json:"conflict_type"` // overlap, identical, contains
	Description    string `json:"description"`
}

// SubnetAnalysis represents subnet analysis for a host
type SubnetAnalysis struct {
	TotalNetworks   int              `json:"total_networks"`
	TotalSubnets    int              `json:"total_subnets"`
	Conflicts       []SubnetConflict `json:"conflicts,omitempty"`
	Warnings        []string         `json:"warnings,omitempty"`
	AvailableRanges []string         `json:"available_ranges,omitempty"` // Suggested available CIDR ranges
}

// ============================================================================
// Network Isolation Analysis
// ============================================================================

// NetworkIsolationAnalysis represents isolation analysis for networks
type NetworkIsolationAnalysis struct {
	NetworkID         string                `json:"network_id"`
	NetworkName       string                `json:"network_name"`
	IsIsolated        bool                  `json:"is_isolated"`
	IsInternal        bool                  `json:"is_internal"`
	HasExternalAccess bool                  `json:"has_external_access"`
	ConnectedNetworks []string              `json:"connected_networks,omitempty"` // Networks sharing containers
	SharedContainers  []string              `json:"shared_containers,omitempty"`  // Containers on multiple networks
	IsolationScore    int                   `json:"isolation_score"`              // 0-100, higher = more isolated
	Recommendations   []string              `json:"recommendations,omitempty"`
	SecurityRisks     []NetworkSecurityRisk `json:"security_risks,omitempty"`
}

// NetworkSecurityRisk represents a security risk finding
type NetworkSecurityRisk struct {
	Severity    string `json:"severity"` // low, medium, high, critical
	Category    string `json:"category"` // exposure, isolation, configuration
	Description string `json:"description"`
	Mitigation  string `json:"mitigation"`
}

// ============================================================================
// Traffic Flow Analysis
// ============================================================================

// TrafficFlowAnalysis represents network traffic flow analysis
type TrafficFlowAnalysis struct {
	HostID      string                `json:"host_id"`
	CapturedAt  string                `json:"captured_at"`
	Connections []ContainerConnection `json:"connections,omitempty"`
	Summary     TrafficSummary        `json:"summary"`
}

// ContainerConnection represents a connection between containers
type ContainerConnection struct {
	SourceContainerID   string `json:"source_container_id"`
	SourceContainerName string `json:"source_container_name"`
	SourceIP            string `json:"source_ip"`
	SourcePort          uint16 `json:"source_port"`
	DestContainerID     string `json:"dest_container_id,omitempty"`
	DestContainerName   string `json:"dest_container_name,omitempty"`
	DestIP              string `json:"dest_ip"`
	DestPort            uint16 `json:"dest_port"`
	Protocol            string `json:"protocol"` // tcp, udp, icmp
	State               string `json:"state"`    // established, time_wait, etc.
	BytesSent           uint64 `json:"bytes_sent"`
	BytesReceived       uint64 `json:"bytes_received"`
	NetworkID           string `json:"network_id,omitempty"`
	NetworkName         string `json:"network_name,omitempty"`
}

// TrafficSummary represents a summary of traffic flow
type TrafficSummary struct {
	TotalConnections    int    `json:"total_connections"`
	InternalConnections int    `json:"internal_connections"` // Container to container
	ExternalConnections int    `json:"external_connections"` // To/from external IPs
	TCPConnections      int    `json:"tcp_connections"`
	UDPConnections      int    `json:"udp_connections"`
	TotalBytesSent      uint64 `json:"total_bytes_sent"`
	TotalBytesReceived  uint64 `json:"total_bytes_received"`
}

// ============================================================================
// Port Analysis
// ============================================================================

// PortSuggestion represents a port suggestion when conflicts occur
type PortSuggestion struct {
	RequestedPort  uint16   `json:"requested_port"`
	ConflictsWith  string   `json:"conflicts_with,omitempty"` // Container name using the port
	SuggestedPorts []uint16 `json:"suggested_ports"`          // Available alternative ports
	PortRange      string   `json:"port_range,omitempty"`     // e.g., "8080-8090"
	Reason         string   `json:"reason"`
}

// HostPortMap represents port usage on a host
type HostPortMap struct {
	HostID      string             `json:"host_id"`
	HostName    string             `json:"host_name"`
	TotalPorts  int                `json:"total_ports"`
	UsedPorts   int                `json:"used_ports"`
	Ports       []HostPortMapping  `json:"ports"`
	ByProtocol  map[string]int     `json:"by_protocol"`  // tcp/udp counts
	ByContainer map[string]int     `json:"by_container"` // Container -> port count
}

// HostPortMapping represents a single port mapping on a host
type HostPortMapping struct {
	HostPort       uint16 `json:"host_port"`
	ContainerPort  uint16 `json:"container_port"`
	Protocol       string `json:"protocol"`
	HostIP         string `json:"host_ip"`
	ContainerID    string `json:"container_id"`
	ContainerName  string `json:"container_name"`
	ContainerImage string `json:"container_image,omitempty"`
	IsWellKnown    bool   `json:"is_well_known"`          // Port < 1024
	ServiceName    string `json:"service_name,omitempty"` // e.g., "HTTP", "SSH", "MySQL"
}
