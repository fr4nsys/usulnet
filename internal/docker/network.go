// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package docker

import (
	"context"

	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"

	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// NetworkListOptions specifies options for listing networks
type NetworkListOptions struct {
	// Filters to apply (e.g., {"driver": ["bridge"], "scope": ["local"]})
	Filters map[string][]string
}

// NetworkCreateOptions specifies options for creating networks
type NetworkCreateOptions struct {
	// Name is the network name
	Name string

	// Driver is the network driver (bridge, overlay, macvlan, etc.)
	Driver string

	// Internal restricts external access to the network
	Internal bool

	// Attachable enables manual container attachment (for overlay networks)
	Attachable bool

	// EnableIPv6 enables IPv6 networking
	EnableIPv6 bool

	// IPAM specifies IP Address Management configuration
	IPAM *IPAMConfig

	// Options are driver-specific options
	Options map[string]string

	// Labels are metadata labels
	Labels map[string]string
}

// NetworkConnectOptions specifies options for connecting containers to networks
type NetworkConnectOptions struct {
	// ContainerID is the container to connect
	ContainerID string

	// Aliases are DNS aliases for the container on this network
	Aliases []string

	// IPAddress is the IPv4 address to assign (empty for DHCP)
	IPAddress string

	// IPv6Address is the IPv6 address to assign (empty for auto)
	IPv6Address string

	// Links are legacy container links
	Links []string
}

// NetworkList returns a list of networks
func (c *Client) NetworkList(ctx context.Context, opts NetworkListOptions) ([]Network, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	// Build filters
	f := filters.NewArgs()
	for key, values := range opts.Filters {
		for _, v := range values {
			f.Add(key, v)
		}
	}

	listOpts := network.ListOptions{
		Filters: f,
	}

	networks, err := c.cli.NetworkList(ctx, listOpts)
	if err != nil {
		log.Error("Failed to list networks", "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to list networks")
	}

	result := make([]Network, len(networks))
	for i, net := range networks {
		result[i] = NetworkFromResource(net)
	}

	log.Debug("Listed networks", "count", len(result))
	return result, nil
}

// NetworkGet returns detailed information about a network
func (c *Client) NetworkGet(ctx context.Context, networkID string) (*Network, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	net, err := c.cli.NetworkInspect(ctx, networkID, network.InspectOptions{
		Verbose: true,
	})
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, errors.New(errors.CodeNetworkNotFound, "network not found").
				WithDetail("network_id", networkID)
		}
		log.Error("Failed to inspect network", "network_id", networkID, "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to inspect network")
	}

	result := NetworkFromDocker(net)
	return &result, nil
}

// NetworkCreate creates a new network
func (c *Client) NetworkCreate(ctx context.Context, opts NetworkCreateOptions) (*Network, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	createOpts := network.CreateOptions{
		Driver:     opts.Driver,
		Internal:   opts.Internal,
		Attachable: opts.Attachable,
		EnableIPv6: &opts.EnableIPv6,
		Options:    opts.Options,
		Labels:     opts.Labels,
	}

	// Set default driver if not specified
	if createOpts.Driver == "" {
		createOpts.Driver = "bridge"
	}

	// Configure IPAM if specified
	if opts.IPAM != nil {
		createOpts.IPAM = &network.IPAM{
			Driver:  opts.IPAM.Driver,
			Options: opts.IPAM.Options,
		}
		for _, cfg := range opts.IPAM.Config {
			createOpts.IPAM.Config = append(createOpts.IPAM.Config, network.IPAMConfig{
				Subnet:     cfg.Subnet,
				IPRange:    cfg.IPRange,
				Gateway:    cfg.Gateway,
				AuxAddress: cfg.AuxAddress,
			})
		}
	}

	resp, err := c.cli.NetworkCreate(ctx, opts.Name, createOpts)
	if err != nil {
		log.Error("Failed to create network", "name", opts.Name, "driver", opts.Driver, "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to create network")
	}

	// Log warnings if any
	if resp.Warning != "" {
		log.Warn("Network creation warning", "network_id", resp.ID, "warning", resp.Warning)
	}

	log.Info("Network created", "network_id", resp.ID, "name", opts.Name, "driver", opts.Driver)

	// Return the created network
	return c.NetworkGet(ctx, resp.ID)
}

// NetworkRemove removes a network
func (c *Client) NetworkRemove(ctx context.Context, networkID string) error {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	if err := c.cli.NetworkRemove(ctx, networkID); err != nil {
		if client.IsErrNotFound(err) {
			return errors.New(errors.CodeNetworkNotFound, "network not found").
				WithDetail("network_id", networkID)
		}
		log.Error("Failed to remove network", "network_id", networkID, "error", err)
		return errors.Wrap(err, errors.CodeInternal, "failed to remove network")
	}

	log.Info("Network removed", "network_id", networkID)
	return nil
}

// NetworkConnect connects a container to a network
func (c *Client) NetworkConnect(ctx context.Context, networkID string, opts NetworkConnectOptions) error {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	endpointConfig := &network.EndpointSettings{
		Aliases: opts.Aliases,
		Links:   opts.Links,
	}

	// Set IP configuration if specified
	if opts.IPAddress != "" || opts.IPv6Address != "" {
		endpointConfig.IPAMConfig = &network.EndpointIPAMConfig{
			IPv4Address: opts.IPAddress,
			IPv6Address: opts.IPv6Address,
		}
	}

	if err := c.cli.NetworkConnect(ctx, networkID, opts.ContainerID, endpointConfig); err != nil {
		if client.IsErrNotFound(err) {
			return errors.New(errors.CodeNetworkNotFound, "network or container not found").
				WithDetail("network_id", networkID).
				WithDetail("container_id", opts.ContainerID)
		}
		log.Error("Failed to connect container to network",
			"network_id", networkID,
			"container_id", opts.ContainerID,
			"error", err)
		return errors.Wrap(err, errors.CodeInternal, "failed to connect container to network")
	}

	log.Info("Container connected to network",
		"network_id", networkID,
		"container_id", opts.ContainerID)
	return nil
}

// NetworkDisconnect disconnects a container from a network
func (c *Client) NetworkDisconnect(ctx context.Context, networkID, containerID string, force bool) error {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	if err := c.cli.NetworkDisconnect(ctx, networkID, containerID, force); err != nil {
		if client.IsErrNotFound(err) {
			return errors.New(errors.CodeNetworkNotFound, "network or container not found").
				WithDetail("network_id", networkID).
				WithDetail("container_id", containerID)
		}
		log.Error("Failed to disconnect container from network",
			"network_id", networkID,
			"container_id", containerID,
			"error", err)
		return errors.Wrap(err, errors.CodeInternal, "failed to disconnect container from network")
	}

	log.Info("Container disconnected from network",
		"network_id", networkID,
		"container_id", containerID)
	return nil
}

// NetworkPrune removes unused networks
func (c *Client) NetworkPrune(ctx context.Context, pruneFilters map[string][]string) ([]string, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	f := filters.NewArgs()
	for key, values := range pruneFilters {
		for _, v := range values {
			f.Add(key, v)
		}
	}

	report, err := c.cli.NetworksPrune(ctx, f)
	if err != nil {
		log.Error("Failed to prune networks", "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to prune networks")
	}

	log.Info("Networks pruned", "deleted", len(report.NetworksDeleted))
	return report.NetworksDeleted, nil
}

// NetworkExists checks if a network exists
func (c *Client) NetworkExists(ctx context.Context, networkID string) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return false, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	_, err := c.cli.NetworkInspect(ctx, networkID, network.InspectOptions{})
	if err != nil {
		if client.IsErrNotFound(err) {
			return false, nil
		}
		return false, errors.Wrap(err, errors.CodeInternal, "failed to check network existence")
	}

	return true, nil
}

// NetworkContainers returns a list of containers connected to a network
func (c *Client) NetworkContainers(ctx context.Context, networkID string) ([]NetworkContainer, error) {
	net, err := c.NetworkGet(ctx, networkID)
	if err != nil {
		return nil, err
	}

	result := make([]NetworkContainer, 0, len(net.Containers))
	for _, container := range net.Containers {
		result = append(result, container)
	}

	return result, nil
}

// NetworkListByDriver returns networks using a specific driver
func (c *Client) NetworkListByDriver(ctx context.Context, driver string) ([]Network, error) {
	return c.NetworkList(ctx, NetworkListOptions{
		Filters: map[string][]string{
			"driver": {driver},
		},
	})
}

// NetworkListByLabel returns networks matching specific labels
func (c *Client) NetworkListByLabel(ctx context.Context, labels map[string]string) ([]Network, error) {
	filters := make(map[string][]string)
	for key, value := range labels {
		filters["label"] = append(filters["label"], key+"="+value)
	}

	return c.NetworkList(ctx, NetworkListOptions{Filters: filters})
}

// NetworkListByScope returns networks with the specified scope (local, swarm, global)
func (c *Client) NetworkListByScope(ctx context.Context, scope string) ([]Network, error) {
	return c.NetworkList(ctx, NetworkListOptions{
		Filters: map[string][]string{
			"scope": {scope},
		},
	})
}

// NetworkGetByName returns a network by its name
func (c *Client) NetworkGetByName(ctx context.Context, name string) (*Network, error) {
	networks, err := c.NetworkList(ctx, NetworkListOptions{
		Filters: map[string][]string{
			"name": {name},
		},
	})
	if err != nil {
		return nil, err
	}

	// Find exact match (Docker filter is a prefix match)
	for _, net := range networks {
		if net.Name == name {
			return &net, nil
		}
	}

	return nil, errors.New(errors.CodeNetworkNotFound, "network not found").
		WithDetail("name", name)
}

// NetworkTopology returns a map of network connectivity
// Key: network name, Value: list of connected container names
func (c *Client) NetworkTopology(ctx context.Context) (map[string][]string, error) {
	networks, err := c.NetworkList(ctx, NetworkListOptions{})
	if err != nil {
		return nil, err
	}

	topology := make(map[string][]string)

	for _, net := range networks {
		// Get full network info with containers
		fullNet, err := c.NetworkGet(ctx, net.ID)
		if err != nil {
			// Skip networks we can't inspect
			continue
		}

		var containerNames []string
		for _, container := range fullNet.Containers {
			containerNames = append(containerNames, container.Name)
		}

		topology[fullNet.Name] = containerNames
	}

	return topology, nil
}

// SystemPruneNetworks is an alias for NetworkPrune with no filters
func (c *Client) SystemPruneNetworks(ctx context.Context) ([]string, error) {
	return c.NetworkPrune(ctx, nil)
}

// IsDefaultNetwork checks if a network is a Docker default network
func IsDefaultNetwork(name string) bool {
	defaults := map[string]bool{
		"bridge": true,
		"host":   true,
		"none":   true,
	}
	return defaults[name]
}

// NetworkAnalysis contains analysis results for a network
type NetworkAnalysis struct {
	Network           Network
	ContainerCount    int
	IsDefault         bool
	IsInternal        bool
	HasIPv6           bool
	AvailableIPs      int
	UsedIPs           int
	Warnings          []string
	Recommendations   []string
}

// AnalyzeNetwork performs a basic analysis of a network
func (c *Client) AnalyzeNetwork(ctx context.Context, networkID string) (*NetworkAnalysis, error) {
	net, err := c.NetworkGet(ctx, networkID)
	if err != nil {
		return nil, err
	}

	analysis := &NetworkAnalysis{
		Network:        *net,
		ContainerCount: len(net.Containers),
		IsDefault:      IsDefaultNetwork(net.Name),
		IsInternal:     net.Internal,
		HasIPv6:        net.EnableIPv6,
	}

	// Add warnings and recommendations
	if net.Driver == "host" {
		analysis.Warnings = append(analysis.Warnings, "Host network mode bypasses Docker network isolation")
	}

	if !net.Internal && net.Driver == "bridge" && len(net.Containers) > 0 {
		analysis.Recommendations = append(analysis.Recommendations,
			"Consider using internal=true for backend services that don't need external access")
	}

	if len(net.Containers) == 0 && !analysis.IsDefault {
		analysis.Recommendations = append(analysis.Recommendations,
			"Network has no connected containers - consider removing if unused")
	}

	return analysis, nil
}
