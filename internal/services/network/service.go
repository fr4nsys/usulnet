// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package network provides Docker network management services.
package network

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	hostservice "github.com/fr4nsys/usulnet/internal/services/host"
)

// Service provides Docker network management operations.
type Service struct {
	hostService *hostservice.Service
	logger      *logger.Logger
}

// NewService creates a new network service.
func NewService(hostService *hostservice.Service, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		hostService: hostService,
		logger:      log,
	}
}

// subnetInfo holds subnet information for conflict detection.
type subnetInfo struct {
	networkID   string
	networkName string
	subnet      string
	ipNet       *net.IPNet
}

// List returns all networks on a host.
func (s *Service) List(ctx context.Context, hostID uuid.UUID) ([]*models.Network, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	networks, err := client.NetworkList(ctx, docker.NetworkListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list networks: %w", err)
	}

	result := make([]*models.Network, 0, len(networks))
	for _, n := range networks {
		// Inspect each network to get container information
		// (NetworkList doesn't include containers)
		detailed, inspectErr := client.NetworkGet(ctx, n.ID)
		if inspectErr == nil {
			result = append(result, s.dockerToModel(detailed, hostID))
		} else {
			result = append(result, s.dockerToModel(&n, hostID))
		}
	}
	return result, nil
}

// ListByDriver returns networks using a specific driver.
func (s *Service) ListByDriver(ctx context.Context, hostID uuid.UUID, driver string) ([]*models.Network, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	networks, err := client.NetworkList(ctx, docker.NetworkListOptions{
		Filters: map[string][]string{"driver": {driver}},
	})
	if err != nil {
		return nil, fmt.Errorf("list networks by driver: %w", err)
	}

	result := make([]*models.Network, 0, len(networks))
	for _, n := range networks {
		result = append(result, s.dockerToModel(&n, hostID))
	}
	return result, nil
}

// ListByLabel returns networks with specific labels.
func (s *Service) ListByLabel(ctx context.Context, hostID uuid.UUID, labels map[string]string) ([]*models.Network, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	labelFilters := make([]string, 0, len(labels))
	for k, v := range labels {
		labelFilters = append(labelFilters, fmt.Sprintf("%s=%s", k, v))
	}

	networks, err := client.NetworkList(ctx, docker.NetworkListOptions{
		Filters: map[string][]string{"label": labelFilters},
	})
	if err != nil {
		return nil, fmt.Errorf("list networks by label: %w", err)
	}

	result := make([]*models.Network, 0, len(networks))
	for _, n := range networks {
		result = append(result, s.dockerToModel(&n, hostID))
	}
	return result, nil
}

// Get returns a specific network by ID.
func (s *Service) Get(ctx context.Context, hostID uuid.UUID, networkID string) (*models.Network, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	net, err := client.NetworkGet(ctx, networkID)
	if err != nil {
		return nil, fmt.Errorf("get network: %w", err)
	}

	return s.dockerToModel(net, hostID), nil
}

// GetByName returns a network by name.
func (s *Service) GetByName(ctx context.Context, hostID uuid.UUID, name string) (*models.Network, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	net, err := client.NetworkGetByName(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("get network by name: %w", err)
	}

	return s.dockerToModel(net, hostID), nil
}

// ListUserDefined returns user-defined (non-system) networks.
func (s *Service) ListUserDefined(ctx context.Context, hostID uuid.UUID) ([]*models.Network, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	networks, err := client.NetworkList(ctx, docker.NetworkListOptions{
		Filters: map[string][]string{"type": {"custom"}},
	})
	if err != nil {
		return nil, fmt.Errorf("list user-defined networks: %w", err)
	}

	result := make([]*models.Network, 0)
	for _, n := range networks {
		if n.Name == "bridge" || n.Name == "host" || n.Name == "none" {
			continue
		}
		result = append(result, s.dockerToModel(&n, hostID))
	}
	return result, nil
}

// Create creates a new network.
func (s *Service) Create(ctx context.Context, hostID uuid.UUID, input *models.CreateNetworkInput) (*models.Network, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	opts := docker.NetworkCreateOptions{
		Name:       input.Name,
		Driver:     input.Driver,
		Internal:   input.Internal,
		Attachable: input.Attachable,
		EnableIPv6: input.EnableIPv6,
		Labels:     input.Labels,
		Options:    input.Options,
	}

	// Configure IPAM if provided
	if input.IPAM != nil && len(input.IPAM.Config) > 0 {
		opts.IPAM = &docker.IPAMConfig{
			Driver:  input.IPAM.Driver,
			Options: input.IPAM.Options,
		}
		for _, cfg := range input.IPAM.Config {
			opts.IPAM.Config = append(opts.IPAM.Config, docker.IPAMPoolConfig{
				Subnet:     cfg.Subnet,
				Gateway:    cfg.Gateway,
				IPRange:    cfg.IPRange,
				AuxAddress: cfg.AuxAddress,
			})
		}
	}

	net, err := client.NetworkCreate(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("create network: %w", err)
	}

	s.logger.Info("network created", "name", net.Name, "driver", net.Driver)
	return s.dockerToModel(net, hostID), nil
}

// Delete removes a network.
func (s *Service) Delete(ctx context.Context, hostID uuid.UUID, networkID string) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	if err := client.NetworkRemove(ctx, networkID); err != nil {
		return fmt.Errorf("remove network: %w", err)
	}

	s.logger.Info("network removed", "network", networkID)
	return nil
}

// Connect connects a container to a network.
func (s *Service) Connect(ctx context.Context, hostID uuid.UUID, networkID, containerID string, aliases []string) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	opts := docker.NetworkConnectOptions{
		ContainerID: containerID,
		Aliases:     aliases,
	}

	if err := client.NetworkConnect(ctx, networkID, opts); err != nil {
		return fmt.Errorf("connect to network: %w", err)
	}

	s.logger.Info("container connected to network", "container", containerID, "network", networkID)
	return nil
}

// Disconnect disconnects a container from a network.
func (s *Service) Disconnect(ctx context.Context, hostID uuid.UUID, networkID, containerID string, force bool) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	if err := client.NetworkDisconnect(ctx, networkID, containerID, force); err != nil {
		return fmt.Errorf("disconnect from network: %w", err)
	}

	s.logger.Info("container disconnected from network", "container", containerID, "network", networkID)
	return nil
}

// Prune removes unused networks.
func (s *Service) Prune(ctx context.Context, hostID uuid.UUID) (*models.PruneResult, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	networkNames, err := client.NetworkPrune(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("prune networks: %w", err)
	}

	s.logger.Info("networks pruned", "count", len(networkNames))
	return &models.PruneResult{
		ItemsDeleted: networkNames,
	}, nil
}

// Exists checks if a network exists.
func (s *Service) Exists(ctx context.Context, hostID uuid.UUID, networkID string) (bool, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return false, err
	}
	return client.NetworkExists(ctx, networkID)
}

// GetContainers returns containers connected to a network.
func (s *Service) GetContainers(ctx context.Context, hostID uuid.UUID, networkID string) ([]docker.NetworkContainer, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}
	net, err := client.NetworkGet(ctx, networkID)
	if err != nil {
		return nil, err
	}
	result := make([]docker.NetworkContainer, 0, len(net.Containers))
	for _, c := range net.Containers {
		result = append(result, c)
	}
	return result, nil
}

// GetTopology returns network topology (network -> containers mapping).
func (s *Service) GetTopology(ctx context.Context, hostID uuid.UUID) (map[string][]string, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}
	return client.NetworkTopology(ctx)
}

// GetStats retrieves network statistics for a host.
func (s *Service) GetStats(ctx context.Context, hostID uuid.UUID) (*models.NetworkStats, error) {
	networks, err := s.List(ctx, hostID)
	if err != nil {
		return nil, err
	}

	stats := &models.NetworkStats{
		Total: len(networks),
	}

	for _, n := range networks {
		switch n.Driver {
		case "bridge":
			stats.Bridge++
		case "host":
			stats.Host++
		case "overlay":
			stats.Overlay++
		case "macvlan":
			stats.Macvlan++
		case "null":
			stats.None++
		default:
			stats.Custom++
		}
		if n.Internal {
			stats.Internal++
		}
		if n.Attachable {
			stats.Attachable++
		}
	}

	return stats, nil
}

// ValidateSubnet validates a subnet CIDR.
func ValidateSubnet(subnet string) error {
	if subnet == "" {
		return nil
	}
	_, _, err := net.ParseCIDR(subnet)
	if err != nil {
		return fmt.Errorf("invalid subnet CIDR: %w", err)
	}
	return nil
}

// ValidateGateway validates a gateway IP against a subnet.
func ValidateGateway(gateway, subnet string) error {
	if gateway == "" {
		return nil
	}
	gwIP := net.ParseIP(gateway)
	if gwIP == nil {
		return fmt.Errorf("invalid gateway IP: %s", gateway)
	}
	if subnet != "" {
		_, ipNet, err := net.ParseCIDR(subnet)
		if err != nil {
			return fmt.Errorf("invalid subnet CIDR: %w", err)
		}
		if !ipNet.Contains(gwIP) {
			return fmt.Errorf("gateway %s is not within subnet %s", gateway, subnet)
		}
	}
	return nil
}

// ============================================================================
// DNS Configuration
// ============================================================================

// GetDNSConfig retrieves DNS configuration for a network
func (s *Service) GetDNSConfig(ctx context.Context, hostID uuid.UUID, networkID string) (*models.NetworkDNSConfig, error) {
	net, err := s.Get(ctx, hostID, networkID)
	if err != nil {
		return nil, err
	}

	config := &models.NetworkDNSConfig{
		NetworkID:   net.ID,
		NetworkName: net.Name,
	}

	// Parse DNS configuration from labels
	if servers, ok := net.Labels[models.LabelDNSServers]; ok && servers != "" {
		config.Servers = strings.Split(servers, ",")
	}
	if search, ok := net.Labels[models.LabelDNSSearch]; ok && search != "" {
		config.Search = strings.Split(search, ",")
	}
	if options, ok := net.Labels[models.LabelDNSOptions]; ok && options != "" {
		config.Options = strings.Split(options, ",")
	}

	return config, nil
}

// SetDNSConfig sets DNS configuration for a network by updating its labels
// Note: Docker doesn't support updating network labels directly, so this creates
// a recommendation for new containers or requires network recreation
func (s *Service) SetDNSConfig(ctx context.Context, hostID uuid.UUID, networkID string, input *models.SetDNSConfigInput) (*models.NetworkDNSConfig, error) {
	network, err := s.Get(ctx, hostID, networkID)
	if err != nil {
		return nil, err
	}

	// Validate DNS servers
	for _, server := range input.Servers {
		if ip := net.ParseIP(server); ip == nil {
			return nil, fmt.Errorf("invalid DNS server IP: %s", server)
		}
	}

	// Since Docker doesn't support updating network labels, we store the config
	// in memory/database for reference. The actual DNS must be applied when
	// creating/connecting containers.
	s.logger.Info("DNS config set for network",
		"network_id", networkID,
		"network_name", network.Name,
		"servers", input.Servers,
		"search", input.Search,
	)

	return &models.NetworkDNSConfig{
		NetworkID:   network.ID,
		NetworkName: network.Name,
		Servers:     input.Servers,
		Search:      input.Search,
		Options:     input.Options,
	}, nil
}

// CreateWithDNS creates a network with DNS configuration stored in labels
func (s *Service) CreateWithDNS(ctx context.Context, hostID uuid.UUID, input *models.CreateNetworkInput, dns *models.SetDNSConfigInput) (*models.Network, error) {
	// Add DNS configuration to labels
	if input.Labels == nil {
		input.Labels = make(map[string]string)
	}

	if dns != nil {
		if len(dns.Servers) > 0 {
			input.Labels[models.LabelDNSServers] = strings.Join(dns.Servers, ",")
		}
		if len(dns.Search) > 0 {
			input.Labels[models.LabelDNSSearch] = strings.Join(dns.Search, ",")
		}
		if len(dns.Options) > 0 {
			input.Labels[models.LabelDNSOptions] = strings.Join(dns.Options, ",")
		}
	}

	return s.Create(ctx, hostID, input)
}

// ListNetworksWithDNS returns networks with their DNS configurations
func (s *Service) ListNetworksWithDNS(ctx context.Context, hostID uuid.UUID) ([]*models.NetworkDNSConfig, error) {
	networks, err := s.List(ctx, hostID)
	if err != nil {
		return nil, err
	}

	configs := make([]*models.NetworkDNSConfig, 0, len(networks))
	for _, net := range networks {
		config := &models.NetworkDNSConfig{
			NetworkID:   net.ID,
			NetworkName: net.Name,
		}

		// Parse DNS configuration from labels
		if servers, ok := net.Labels[models.LabelDNSServers]; ok && servers != "" {
			config.Servers = strings.Split(servers, ",")
		}
		if search, ok := net.Labels[models.LabelDNSSearch]; ok && search != "" {
			config.Search = strings.Split(search, ",")
		}
		if options, ok := net.Labels[models.LabelDNSOptions]; ok && options != "" {
			config.Options = strings.Split(options, ",")
		}

		// Only include networks with DNS configuration
		if len(config.Servers) > 0 || len(config.Search) > 0 || len(config.Options) > 0 {
			configs = append(configs, config)
		}
	}

	return configs, nil
}

// ============================================================================
// Subnet Conflict Detection
// ============================================================================

// DetectSubnetConflicts analyzes all networks on a host for subnet conflicts
func (s *Service) DetectSubnetConflicts(ctx context.Context, hostID uuid.UUID) (*models.SubnetAnalysis, error) {
	networks, err := s.List(ctx, hostID)
	if err != nil {
		return nil, err
	}

	analysis := &models.SubnetAnalysis{
		TotalNetworks: len(networks),
	}

	// Collect all subnets
	var subnets []subnetInfo
	for _, n := range networks {
		for _, cfg := range n.IPAM.Config {
			if cfg.Subnet != "" {
				_, ipNet, err := net.ParseCIDR(cfg.Subnet)
				if err != nil {
					analysis.Warnings = append(analysis.Warnings,
						fmt.Sprintf("Invalid subnet in network %s: %s", n.Name, cfg.Subnet))
					continue
				}
				subnets = append(subnets, subnetInfo{
					networkID:   n.ID,
					networkName: n.Name,
					subnet:      cfg.Subnet,
					ipNet:       ipNet,
				})
			}
		}
	}

	analysis.TotalSubnets = len(subnets)

	// Check for conflicts between all pairs
	for i := 0; i < len(subnets); i++ {
		for j := i + 1; j < len(subnets); j++ {
			s1 := subnets[i]
			s2 := subnets[j]

			conflict := s.checkSubnetConflict(s1.ipNet, s2.ipNet)
			if conflict != "" {
				analysis.Conflicts = append(analysis.Conflicts, models.SubnetConflict{
					Network1ID:     s1.networkID,
					Network1Name:   s1.networkName,
					Network1Subnet: s1.subnet,
					Network2ID:     s2.networkID,
					Network2Name:   s2.networkName,
					Network2Subnet: s2.subnet,
					ConflictType:   conflict,
					Description:    s.describeConflict(conflict, s1.subnet, s2.subnet),
				})
			}
		}
	}

	// Suggest available ranges
	analysis.AvailableRanges = s.suggestAvailableRanges(subnets)

	return analysis, nil
}

// checkSubnetConflict checks if two subnets conflict
func (s *Service) checkSubnetConflict(net1, net2 *net.IPNet) string {
	// Check if net1 contains net2's network address
	if net1.Contains(net2.IP) {
		if net1.String() == net2.String() {
			return "identical"
		}
		return "contains"
	}

	// Check if net2 contains net1's network address
	if net2.Contains(net1.IP) {
		return "contains"
	}

	// Check for overlap by checking if either contains the broadcast of the other
	// Get last IP of net1
	last1 := lastIP(net1)
	if net2.Contains(last1) {
		return "overlap"
	}

	last2 := lastIP(net2)
	if net1.Contains(last2) {
		return "overlap"
	}

	return ""
}

// lastIP returns the last IP address in a subnet
func lastIP(ipNet *net.IPNet) net.IP {
	ip := make(net.IP, len(ipNet.IP))
	copy(ip, ipNet.IP)
	for i := range ip {
		ip[i] |= ^ipNet.Mask[i]
	}
	return ip
}

// describeConflict provides a human-readable description of the conflict
func (s *Service) describeConflict(conflictType, subnet1, subnet2 string) string {
	switch conflictType {
	case "identical":
		return fmt.Sprintf("Subnets %s and %s are identical", subnet1, subnet2)
	case "contains":
		return fmt.Sprintf("Subnet ranges %s and %s overlap (one contains the other)", subnet1, subnet2)
	case "overlap":
		return fmt.Sprintf("Subnet ranges %s and %s partially overlap", subnet1, subnet2)
	default:
		return "Unknown conflict type"
	}
}

// suggestAvailableRanges suggests available subnet ranges
func (s *Service) suggestAvailableRanges(used []subnetInfo) []string {
	// Common private ranges to suggest
	suggestions := []string{}

	// Check common ranges
	commonRanges := []string{
		"172.18.0.0/16",
		"172.19.0.0/16",
		"172.20.0.0/16",
		"172.21.0.0/16",
		"172.22.0.0/16",
		"10.0.0.0/16",
		"10.1.0.0/16",
		"10.2.0.0/16",
		"192.168.100.0/24",
		"192.168.200.0/24",
	}

	for _, cidr := range commonRanges {
		_, candidateNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		isAvailable := true
		for _, u := range used {
			if s.checkSubnetConflict(candidateNet, u.ipNet) != "" {
				isAvailable = false
				break
			}
		}

		if isAvailable {
			suggestions = append(suggestions, cidr)
			if len(suggestions) >= 5 {
				break
			}
		}
	}

	return suggestions
}

// ValidateNewSubnet checks if a proposed subnet conflicts with existing networks
func (s *Service) ValidateNewSubnet(ctx context.Context, hostID uuid.UUID, proposedSubnet string) (bool, []models.SubnetConflict, error) {
	_, proposedNet, err := net.ParseCIDR(proposedSubnet)
	if err != nil {
		return false, nil, fmt.Errorf("invalid subnet CIDR: %w", err)
	}

	networks, err := s.List(ctx, hostID)
	if err != nil {
		return false, nil, err
	}

	var conflicts []models.SubnetConflict
	for _, n := range networks {
		for _, cfg := range n.IPAM.Config {
			if cfg.Subnet == "" {
				continue
			}
			_, existingNet, err := net.ParseCIDR(cfg.Subnet)
			if err != nil {
				continue
			}

			conflictType := s.checkSubnetConflict(proposedNet, existingNet)
			if conflictType != "" {
				conflicts = append(conflicts, models.SubnetConflict{
					Network1ID:     "proposed",
					Network1Name:   "proposed",
					Network1Subnet: proposedSubnet,
					Network2ID:     n.ID,
					Network2Name:   n.Name,
					Network2Subnet: cfg.Subnet,
					ConflictType:   conflictType,
					Description:    s.describeConflict(conflictType, proposedSubnet, cfg.Subnet),
				})
			}
		}
	}

	return len(conflicts) == 0, conflicts, nil
}

// ============================================================================
// Network Isolation Analysis
// ============================================================================

// AnalyzeIsolation analyzes network isolation for a specific network
func (s *Service) AnalyzeIsolation(ctx context.Context, hostID uuid.UUID, networkID string) (*models.NetworkIsolationAnalysis, error) {
	net, err := s.Get(ctx, hostID, networkID)
	if err != nil {
		return nil, err
	}

	analysis := &models.NetworkIsolationAnalysis{
		NetworkID:   net.ID,
		NetworkName: net.Name,
		IsInternal:  net.Internal,
	}

	// Get all networks and their containers
	allNetworks, err := s.List(ctx, hostID)
	if err != nil {
		return nil, err
	}

	// Build container -> networks map
	containerNetworks := make(map[string][]string) // containerID -> []networkName
	for _, n := range allNetworks {
		for containerID := range n.Containers {
			containerNetworks[containerID] = append(containerNetworks[containerID], n.Name)
		}
	}

	// Find containers on this network that are also on other networks
	connectedNetworks := make(map[string]bool)
	for containerID := range net.Containers {
		networks := containerNetworks[containerID]
		if len(networks) > 1 {
			analysis.SharedContainers = append(analysis.SharedContainers, net.Containers[containerID].Name)
			for _, netName := range networks {
				if netName != net.Name {
					connectedNetworks[netName] = true
				}
			}
		}
	}

	for netName := range connectedNetworks {
		analysis.ConnectedNetworks = append(analysis.ConnectedNetworks, netName)
	}

	// Calculate isolation score
	analysis.IsIsolated = len(analysis.ConnectedNetworks) == 0 && net.Internal
	analysis.HasExternalAccess = !net.Internal

	// Score calculation: higher = more isolated
	score := 100
	if !net.Internal {
		score -= 30 // External access reduces isolation
	}
	score -= len(analysis.ConnectedNetworks) * 10 // Each connected network reduces score
	score -= len(analysis.SharedContainers) * 5   // Each shared container reduces score
	if score < 0 {
		score = 0
	}
	analysis.IsolationScore = score

	// Add recommendations
	if !net.Internal && len(net.Containers) > 0 {
		hasWebService := false
		for _, c := range net.Containers {
			if strings.Contains(strings.ToLower(c.Name), "web") ||
				strings.Contains(strings.ToLower(c.Name), "nginx") ||
				strings.Contains(strings.ToLower(c.Name), "frontend") {
				hasWebService = true
				break
			}
		}
		if !hasWebService {
			analysis.Recommendations = append(analysis.Recommendations,
				"Consider making this network internal if no external access is needed")
		}
	}

	if len(analysis.SharedContainers) > 3 {
		analysis.Recommendations = append(analysis.Recommendations,
			"Many containers span multiple networks - consider reviewing network segmentation")
	}

	// Security risks
	if !net.Internal && net.Driver == "bridge" {
		analysis.SecurityRisks = append(analysis.SecurityRisks, models.NetworkSecurityRisk{
			Severity:    "medium",
			Category:    "exposure",
			Description: "Network allows external access with bridge driver",
			Mitigation:  "Use internal=true for backend services, or use a dedicated ingress network",
		})
	}

	if len(analysis.ConnectedNetworks) > 0 && !net.Internal {
		analysis.SecurityRisks = append(analysis.SecurityRisks, models.NetworkSecurityRisk{
			Severity:    "low",
			Category:    "isolation",
			Description: fmt.Sprintf("Network shares %d containers with other networks", len(analysis.SharedContainers)),
			Mitigation:  "Review if container multi-homing is necessary for the workload",
		})
	}

	return analysis, nil
}

// AnalyzeAllIsolation analyzes isolation for all networks on a host
func (s *Service) AnalyzeAllIsolation(ctx context.Context, hostID uuid.UUID) ([]*models.NetworkIsolationAnalysis, error) {
	networks, err := s.List(ctx, hostID)
	if err != nil {
		return nil, err
	}

	analyses := make([]*models.NetworkIsolationAnalysis, 0, len(networks))
	for _, net := range networks {
		// Skip default Docker networks
		if net.Name == "bridge" || net.Name == "host" || net.Name == "none" {
			continue
		}

		analysis, err := s.AnalyzeIsolation(ctx, hostID, net.ID)
		if err != nil {
			s.logger.Warn("failed to analyze network isolation", "network", net.Name, "error", err)
			continue
		}
		analyses = append(analyses, analysis)
	}

	return analyses, nil
}

// ============================================================================
// Port Analysis and Suggestions
// ============================================================================

// GetHostPortMap returns a complete map of all port bindings on a host
func (s *Service) GetHostPortMap(ctx context.Context, hostID uuid.UUID) (*models.HostPortMap, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	containers, err := client.ContainerList(ctx, docker.ContainerListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	portMap := &models.HostPortMap{
		HostID:      hostID.String(),
		ByProtocol:  make(map[string]int),
		ByContainer: make(map[string]int),
	}

	for _, c := range containers {
		containerName := c.Name
		if strings.HasPrefix(containerName, "/") {
			containerName = containerName[1:]
		}

		for _, port := range c.Ports {
			if port.PublicPort == 0 {
				continue // Not exposed
			}

			mapping := models.HostPortMapping{
				HostPort:       port.PublicPort,
				ContainerPort:  port.PrivatePort,
				Protocol:       port.Type,
				HostIP:         port.IP,
				ContainerID:    c.ID,
				ContainerName:  containerName,
				ContainerImage: c.Image,
				IsWellKnown:    port.PublicPort < 1024,
				ServiceName:    getServiceName(port.PublicPort, port.Type),
			}

			portMap.Ports = append(portMap.Ports, mapping)
			portMap.ByProtocol[port.Type]++
			portMap.ByContainer[containerName]++
			portMap.UsedPorts++
		}
	}

	portMap.TotalPorts = portMap.UsedPorts

	return portMap, nil
}

// SuggestAlternativePorts returns port suggestions when a requested port conflicts
func (s *Service) SuggestAlternativePorts(ctx context.Context, hostID uuid.UUID, requestedPort uint16, protocol string) (*models.PortSuggestion, error) {
	portMap, err := s.GetHostPortMap(ctx, hostID)
	if err != nil {
		return nil, err
	}

	suggestion := &models.PortSuggestion{
		RequestedPort: requestedPort,
	}

	// Check if port is in use
	usedPorts := make(map[uint16]string) // port -> container name
	for _, p := range portMap.Ports {
		if p.Protocol == protocol || protocol == "" {
			usedPorts[p.HostPort] = p.ContainerName
		}
	}

	if containerName, inUse := usedPorts[requestedPort]; inUse {
		suggestion.ConflictsWith = containerName
		suggestion.Reason = fmt.Sprintf("Port %d/%s is already in use by container '%s'", requestedPort, protocol, containerName)
	}

	// Find alternative ports
	alternatives := []uint16{}

	// Strategy 1: Try ports around the requested port
	for offset := uint16(1); offset <= 100 && len(alternatives) < 5; offset++ {
		// Try above
		candidate := requestedPort + offset
		if candidate <= 65535 && !isReservedPort(candidate) {
			if _, used := usedPorts[candidate]; !used {
				alternatives = append(alternatives, candidate)
			}
		}
		// Try below
		if requestedPort > offset {
			candidate = requestedPort - offset
			if candidate > 0 && !isReservedPort(candidate) {
				if _, used := usedPorts[candidate]; !used {
					alternatives = append(alternatives, candidate)
				}
			}
		}
	}

	// Strategy 2: If still need more, try common alternative ports
	if len(alternatives) < 3 {
		commonAlternatives := getCommonAlternatives(requestedPort)
		for _, alt := range commonAlternatives {
			if _, used := usedPorts[alt]; !used {
				// Avoid duplicates
				found := false
				for _, existing := range alternatives {
					if existing == alt {
						found = true
						break
					}
				}
				if !found {
					alternatives = append(alternatives, alt)
				}
			}
		}
	}

	// Limit to 5 suggestions
	if len(alternatives) > 5 {
		alternatives = alternatives[:5]
	}

	suggestion.SuggestedPorts = alternatives

	// Find available range
	suggestion.PortRange = s.findAvailableRange(usedPorts, requestedPort)

	return suggestion, nil
}

// findAvailableRange finds a contiguous range of available ports near the requested port
func (s *Service) findAvailableRange(usedPorts map[uint16]string, near uint16) string {
	start := near
	end := near

	// Expand upward
	for {
		if end >= 65535 {
			break
		}
		if _, used := usedPorts[end+1]; used {
			break
		}
		end++
		if end-start >= 10 {
			break
		}
	}

	// Expand downward
	for {
		if start <= 1024 {
			break
		}
		if _, used := usedPorts[start-1]; used {
			break
		}
		start--
		if end-start >= 10 {
			break
		}
	}

	if end > start {
		return fmt.Sprintf("%d-%d", start, end)
	}
	return ""
}

// getServiceName returns a human-readable service name for common ports
func getServiceName(port uint16, protocol string) string {
	services := map[uint16]string{
		20:    "FTP Data",
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		143:   "IMAP",
		443:   "HTTPS",
		465:   "SMTPS",
		587:   "SMTP Submission",
		993:   "IMAPS",
		995:   "POP3S",
		1433:  "MSSQL",
		1521:  "Oracle",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		5672:  "AMQP",
		6379:  "Redis",
		8080:  "HTTP Alt",
		8443:  "HTTPS Alt",
		9000:  "PHP-FPM",
		9200:  "Elasticsearch",
		9300:  "Elasticsearch Cluster",
		27017: "MongoDB",
	}

	if name, ok := services[port]; ok {
		return name
	}
	return ""
}

// isReservedPort checks if a port should not be suggested
func isReservedPort(port uint16) bool {
	// Reserved system ports (0-1023) and some commonly reserved ports
	reserved := map[uint16]bool{
		0: true, 1: true,
	}
	return port < 1024 || reserved[port]
}

// getCommonAlternatives returns common alternative ports for a given port
func getCommonAlternatives(port uint16) []uint16 {
	// Common alternatives based on typical port patterns
	switch {
	case port == 80:
		return []uint16{8080, 8000, 8888, 9080}
	case port == 443:
		return []uint16{8443, 4443, 9443}
	case port == 3000:
		return []uint16{3001, 3002, 3003, 3004}
	case port == 5000:
		return []uint16{5001, 5002, 5003}
	case port == 8080:
		return []uint16{8081, 8082, 8888, 9080}
	case port >= 3000 && port < 4000:
		return []uint16{port + 1, port + 2, port + 10, port + 100}
	case port >= 8000 && port < 9000:
		return []uint16{port + 1, port + 2, port + 10, port + 100}
	default:
		return []uint16{port + 1, port + 10, port + 100}
	}
}

// ============================================================================
// Traffic Flow Analysis
// ============================================================================

// GetTrafficFlow analyzes network traffic between containers using Docker network information
// Note: Full conntrack analysis requires host-level access which may not be available
func (s *Service) GetTrafficFlow(ctx context.Context, hostID uuid.UUID) (*models.TrafficFlowAnalysis, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	// Get all containers with their network settings
	containers, err := client.ContainerList(ctx, docker.ContainerListOptions{All: false}) // Only running
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	// Build container IP map
	containerByIP := make(map[string]docker.Container)
	for _, c := range containers {
		for _, net := range c.Networks {
			if net.IPAddress != "" {
				containerByIP[net.IPAddress] = c
			}
		}
	}

	analysis := &models.TrafficFlowAnalysis{
		HostID:     hostID.String(),
		CapturedAt: time.Now().Format(time.RFC3339),
	}

	// Analyze connections based on exposed ports and network topology
	// This is a simplified analysis based on Docker network information
	// Full conntrack would require privileged access to the host
	networks, err := s.List(ctx, hostID)
	if err != nil {
		return nil, err
	}

	for _, net := range networks {
		if len(net.Containers) < 2 {
			continue // No potential inter-container communication
		}

		// Containers on the same network can potentially communicate
		containerList := make([]models.NetworkContainerInfo, 0, len(net.Containers))
		for _, c := range net.Containers {
			containerList = append(containerList, c)
		}

		// Create potential connection entries
		for i := 0; i < len(containerList); i++ {
			for j := i + 1; j < len(containerList); j++ {
				c1 := containerList[i]
				c2 := containerList[j]

				// Record bidirectional potential connections
				analysis.Connections = append(analysis.Connections, models.ContainerConnection{
					SourceContainerName: c1.Name,
					SourceIP:            c1.IPv4Address,
					DestContainerName:   c2.Name,
					DestIP:              c2.IPv4Address,
					Protocol:            "tcp",
					State:               "potential",
					NetworkID:           net.ID,
					NetworkName:         net.Name,
				})
			}
		}
	}

	// Calculate summary
	analysis.Summary = models.TrafficSummary{
		TotalConnections:    len(analysis.Connections),
		InternalConnections: len(analysis.Connections), // All are internal in this simplified analysis
	}

	return analysis, nil
}

// GetContainerConnections returns active connections for a specific container
// This uses Docker exec to run netstat/ss inside the container
func (s *Service) GetContainerConnections(ctx context.Context, hostID uuid.UUID, containerID string) ([]models.ContainerConnection, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	// Try to get active connections by executing ss or netstat inside the container
	// This requires the container to have these tools installed
	result, err := client.ContainerExec(ctx, containerID, []string{"sh", "-c", "ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null || echo 'no-tools'"}, docker.DefaultExecOptions())
	if err != nil {
		// If exec fails, return empty list (container might not support exec)
		s.logger.Debug("failed to exec in container for connections", "container", containerID, "error", err)
		return []models.ContainerConnection{}, nil
	}

	if strings.Contains(result.Stdout, "no-tools") {
		return []models.ContainerConnection{}, nil
	}

	connections := s.parseConnectionsOutput(result.Stdout, containerID)
	return connections, nil
}

// parseConnectionsOutput parses ss/netstat output into connection structs
func (s *Service) parseConnectionsOutput(output, containerID string) []models.ContainerConnection {
	var connections []models.ContainerConnection

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "State") || strings.HasPrefix(line, "Netid") {
			continue
		}

		// Parse ss output format: State Recv-Q Send-Q Local:Port Peer:Port Process
		// Parse netstat output: Proto Recv-Q Send-Q Local:Port Foreign:Port State
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		var conn models.ContainerConnection
		conn.SourceContainerID = containerID

		// Determine format and parse
		if fields[0] == "tcp" || fields[0] == "udp" || fields[0] == "tcp6" || fields[0] == "udp6" {
			// netstat format
			conn.Protocol = strings.TrimSuffix(fields[0], "6")
			localAddr := fields[3]
			remoteAddr := fields[4]
			if len(fields) > 5 {
				conn.State = fields[5]
			}

			// Parse addresses
			if parts := strings.Split(localAddr, ":"); len(parts) >= 2 {
				conn.SourceIP = strings.Join(parts[:len(parts)-1], ":")
				fmt.Sscanf(parts[len(parts)-1], "%d", &conn.SourcePort)
			}
			if parts := strings.Split(remoteAddr, ":"); len(parts) >= 2 {
				conn.DestIP = strings.Join(parts[:len(parts)-1], ":")
				fmt.Sscanf(parts[len(parts)-1], "%d", &conn.DestPort)
			}
		} else {
			// ss format
			conn.State = fields[0]
			conn.Protocol = "tcp"
			if len(fields) > 4 {
				localAddr := fields[3]
				remoteAddr := fields[4]

				if parts := strings.Split(localAddr, ":"); len(parts) >= 2 {
					conn.SourceIP = strings.Join(parts[:len(parts)-1], ":")
					fmt.Sscanf(parts[len(parts)-1], "%d", &conn.SourcePort)
				}
				if parts := strings.Split(remoteAddr, ":"); len(parts) >= 2 {
					conn.DestIP = strings.Join(parts[:len(parts)-1], ":")
					fmt.Sscanf(parts[len(parts)-1], "%d", &conn.DestPort)
				}
			}
		}

		if conn.DestIP != "" && conn.DestIP != "0.0.0.0" && conn.DestIP != "*" {
			connections = append(connections, conn)
		}
	}

	return connections
}

// AnalyzePortConflicts analyzes all port bindings and identifies conflicts
func (s *Service) AnalyzePortConflicts(ctx context.Context, hostID uuid.UUID) ([]models.PortConflict, error) {
	portMap, err := s.GetHostPortMap(ctx, hostID)
	if err != nil {
		return nil, err
	}

	// Group ports by host:port:protocol
	portUsers := make(map[string][]string) // "ip:port:proto" -> []container names
	for _, p := range portMap.Ports {
		key := fmt.Sprintf("%s:%d:%s", p.HostIP, p.HostPort, p.Protocol)
		portUsers[key] = append(portUsers[key], p.ContainerName)
	}

	var conflicts []models.PortConflict
	for key, containers := range portUsers {
		if len(containers) > 1 {
			parts := strings.Split(key, ":")
			var port uint16
			fmt.Sscanf(parts[1], "%d", &port)

			conflicts = append(conflicts, models.PortConflict{
				Port:        port,
				Protocol:    parts[2],
				HostIP:      parts[0],
				Containers:  containers,
				Description: fmt.Sprintf("Port %s is bound by multiple containers: %s", key, strings.Join(containers, ", ")),
			})
		}
	}

	return conflicts, nil
}

// dockerToModel converts a Docker network to our model.
func (s *Service) dockerToModel(n *docker.Network, hostID uuid.UUID) *models.Network {
	net := &models.Network{
		ID:         n.ID,
		HostID:     hostID,
		Name:       n.Name,
		Driver:     n.Driver,
		Scope:      models.NetworkScope(n.Scope),
		EnableIPv6: n.EnableIPv6,
		Internal:   n.Internal,
		Attachable: n.Attachable,
		Ingress:    n.Ingress,
		Options:    n.Options,
		Labels:     n.Labels,
		CreatedAt:  n.Created,
	}

	// Convert IPAM config
	if len(n.IPAM.Config) > 0 {
		net.IPAM = models.NetworkIPAM{
			Driver: n.IPAM.Driver,
		}
		for _, cfg := range n.IPAM.Config {
			net.IPAM.Config = append(net.IPAM.Config, models.IPAMConfig{
				Subnet:     cfg.Subnet,
				Gateway:    cfg.Gateway,
				IPRange:    cfg.IPRange,
				AuxAddress: cfg.AuxAddress,
			})
		}
	}

	// Convert containers
	if len(n.Containers) > 0 {
		net.Containers = make(map[string]models.NetworkContainerInfo)
		for id, c := range n.Containers {
			name := c.Name
			if strings.HasPrefix(name, "/") {
				name = name[1:]
			}
			net.Containers[id] = models.NetworkContainerInfo{
				Name:        name,
				EndpointID:  c.EndpointID,
				MacAddress:  c.MacAddress,
				IPv4Address: c.IPv4Address,
				IPv6Address: c.IPv6Address,
			}
		}
	}

	return net
}
