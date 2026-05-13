// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package docker

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/swarm"

	"github.com/fr4nsys/usulnet/internal/pkg/errors"
)

// ============================================================================
// Swarm Cluster Operations
// ============================================================================

// SwarmInit initializes a new Swarm cluster, making this node the manager.
func (c *Client) SwarmInit(ctx context.Context, listenAddr, advertiseAddr string, forceNewCluster bool) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return "", errors.New(errors.CodeDockerConnection, "client is closed")
	}

	if listenAddr == "" {
		listenAddr = "0.0.0.0:2377"
	}

	nodeID, err := c.cli.SwarmInit(ctx, swarm.InitRequest{
		ListenAddr:      listenAddr,
		AdvertiseAddr:   advertiseAddr,
		ForceNewCluster: forceNewCluster,
	})
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "failed to initialize Swarm")
	}

	return nodeID, nil
}

// SwarmJoin joins this node to an existing Swarm cluster.
func (c *Client) SwarmJoin(ctx context.Context, remoteAddr, joinToken, listenAddr string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	if listenAddr == "" {
		listenAddr = "0.0.0.0:2377"
	}

	return c.cli.SwarmJoin(ctx, swarm.JoinRequest{
		ListenAddr:  listenAddr,
		RemoteAddrs: []string{remoteAddr},
		JoinToken:   joinToken,
	})
}

// SwarmLeave makes this node leave the Swarm.
func (c *Client) SwarmLeave(ctx context.Context, force bool) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	return c.cli.SwarmLeave(ctx, force)
}

// SwarmInspect returns the current Swarm cluster state.
func (c *Client) SwarmInspect(ctx context.Context) (*SwarmClusterState, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	info, err := c.cli.Info(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDockerConnection, "failed to get Docker info")
	}

	state := &SwarmClusterState{
		Active:         info.Swarm.LocalNodeState == swarm.LocalNodeStateActive,
		NodeID:         info.Swarm.NodeID,
		NodeAddr:       info.Swarm.NodeAddr,
		IsManager:      info.Swarm.ControlAvailable,
		Managers:       info.Swarm.Managers,
		Nodes:          info.Swarm.Nodes,
		LocalNodeState: string(info.Swarm.LocalNodeState),
		Error:          info.Swarm.Error,
	}

	if state.Active && info.Swarm.Cluster != nil {
		state.ClusterID = info.Swarm.Cluster.ID
	}

	return state, nil
}

// SwarmGetJoinTokens retrieves the worker and manager join tokens.
func (c *Client) SwarmGetJoinTokens(ctx context.Context) (workerToken, managerToken string, err error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return "", "", errors.New(errors.CodeDockerConnection, "client is closed")
	}

	sw, err := c.cli.SwarmInspect(ctx)
	if err != nil {
		return "", "", errors.Wrap(err, errors.CodeInternal, "failed to inspect Swarm")
	}

	return sw.JoinTokens.Worker, sw.JoinTokens.Manager, nil
}

// ============================================================================
// Swarm Node Operations
// ============================================================================

// SwarmNodeList lists all nodes in the Swarm cluster.
func (c *Client) SwarmNodeList(ctx context.Context) ([]SwarmNodeInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	nodes, err := c.cli.NodeList(ctx, types.NodeListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to list Swarm nodes")
	}

	result := make([]SwarmNodeInfo, 0, len(nodes))
	for _, n := range nodes {
		info := SwarmNodeInfo{
			ID:            n.ID,
			Hostname:      n.Description.Hostname,
			Role:          string(n.Spec.Role),
			Status:        string(n.Status.State),
			Availability:  string(n.Spec.Availability),
			EngineVersion: n.Description.Engine.EngineVersion,
			Address:       n.Status.Addr,
			NCPU:          n.Description.Resources.NanoCPUs / 1e9,
			MemoryBytes:   n.Description.Resources.MemoryBytes,
			OS:            n.Description.Platform.OS,
			Architecture:  n.Description.Platform.Architecture,
		}

		if n.ManagerStatus != nil {
			info.IsLeader = n.ManagerStatus.Leader
		}

		result = append(result, info)
	}

	return result, nil
}

// SwarmNodeRemove removes a node from the Swarm.
func (c *Client) SwarmNodeRemove(ctx context.Context, nodeID string, force bool) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	return c.cli.NodeRemove(ctx, nodeID, types.NodeRemoveOptions{Force: force})
}

// ============================================================================
// Swarm Service Operations
// ============================================================================

// SwarmServiceCreate creates a new Swarm service.
func (c *Client) SwarmServiceCreate(ctx context.Context, opts SwarmServiceCreateOptions) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return "", errors.New(errors.CodeDockerConnection, "client is closed")
	}

	// Build port configs
	var ports []swarm.PortConfig
	for _, p := range opts.Ports {
		ports = append(ports, swarm.PortConfig{
			Protocol:      swarm.PortConfigProtocol(p.Protocol),
			TargetPort:    p.TargetPort,
			PublishedPort: p.PublishedPort,
			PublishMode:   swarm.PortConfigPublishMode(p.PublishMode),
		})
	}

	// Build mount configs
	var mounts []mount.Mount
	for _, m := range opts.Mounts {
		mounts = append(mounts, mount.Mount{
			Type:     mount.Type(m.Type),
			Source:   m.Source,
			Target:   m.Target,
			ReadOnly: m.ReadOnly,
		})
	}

	// Build placement constraints
	var placement *swarm.Placement
	if len(opts.Constraints) > 0 {
		placement = &swarm.Placement{
			Constraints: opts.Constraints,
		}
	}

	replicas := opts.Replicas
	spec := swarm.ServiceSpec{
		Annotations: swarm.Annotations{
			Name:   opts.Name,
			Labels: opts.Labels,
		},
		TaskTemplate: swarm.TaskSpec{
			ContainerSpec: &swarm.ContainerSpec{
				Image:   opts.Image,
				Command: opts.Command,
				Env:     opts.Env,
				Mounts:  mounts,
			},
			Placement: placement,
		},
		Mode: swarm.ServiceMode{
			Replicated: &swarm.ReplicatedService{
				Replicas: &replicas,
			},
		},
		EndpointSpec: &swarm.EndpointSpec{
			Ports: ports,
		},
	}

	resp, err := c.cli.ServiceCreate(ctx, spec, types.ServiceCreateOptions{})
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "failed to create Swarm service")
	}

	return resp.ID, nil
}

// SwarmServiceList lists all Swarm services.
func (c *Client) SwarmServiceList(ctx context.Context) ([]SwarmServiceInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	services, err := c.cli.ServiceList(ctx, types.ServiceListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to list Swarm services")
	}

	// Get tasks to count running replicas
	tasks, taskErr := c.cli.TaskList(ctx, types.TaskListOptions{})
	taskMap := make(map[string]uint64) // serviceID -> running count
	if taskErr == nil {
		for _, t := range tasks {
			if t.Status.State == swarm.TaskStateRunning {
				taskMap[t.ServiceID]++
			}
		}
	}

	result := make([]SwarmServiceInfo, 0, len(services))
	for _, s := range services {
		info := SwarmServiceInfo{
			ID:        s.ID,
			Name:      s.Spec.Name,
			Labels:    s.Spec.Labels,
			CreatedAt: s.CreatedAt,
			UpdatedAt: s.UpdatedAt,
		}

		// Image
		if s.Spec.TaskTemplate.ContainerSpec != nil {
			info.Image = s.Spec.TaskTemplate.ContainerSpec.Image
		}

		// Mode and replicas
		if s.Spec.Mode.Replicated != nil && s.Spec.Mode.Replicated.Replicas != nil {
			info.Mode = "replicated"
			info.ReplicasDesired = *s.Spec.Mode.Replicated.Replicas
		} else if s.Spec.Mode.Global != nil {
			info.Mode = "global"
		}
		info.ReplicasRunning = taskMap[s.ID]

		// Ports
		if s.Endpoint.Ports != nil {
			for _, p := range s.Endpoint.Ports {
				info.Ports = append(info.Ports, SwarmPortConfig{
					Protocol:      string(p.Protocol),
					TargetPort:    p.TargetPort,
					PublishedPort: p.PublishedPort,
					PublishMode:   string(p.PublishMode),
				})
			}
		}

		result = append(result, info)
	}

	return result, nil
}

// SwarmServiceGet returns details of a specific Swarm service.
func (c *Client) SwarmServiceGet(ctx context.Context, serviceID string) (*SwarmServiceInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	s, _, err := c.cli.ServiceInspectWithRaw(ctx, serviceID, types.ServiceInspectOptions{})
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, fmt.Sprintf("service %s not found", serviceID))
	}

	info := &SwarmServiceInfo{
		ID:        s.ID,
		Name:      s.Spec.Name,
		Labels:    s.Spec.Labels,
		CreatedAt: s.CreatedAt,
		UpdatedAt: s.UpdatedAt,
	}

	if s.Spec.TaskTemplate.ContainerSpec != nil {
		info.Image = s.Spec.TaskTemplate.ContainerSpec.Image
	}

	if s.Spec.Mode.Replicated != nil && s.Spec.Mode.Replicated.Replicas != nil {
		info.Mode = "replicated"
		info.ReplicasDesired = *s.Spec.Mode.Replicated.Replicas
	} else if s.Spec.Mode.Global != nil {
		info.Mode = "global"
	}

	// Count running tasks
	tasks, taskErr := c.cli.TaskList(ctx, types.TaskListOptions{
		Filters: filters.NewArgs(filters.Arg("service", serviceID)),
	})
	if taskErr == nil {
		for _, t := range tasks {
			if t.Status.State == swarm.TaskStateRunning {
				info.ReplicasRunning++
			}
		}
	}

	if s.Endpoint.Ports != nil {
		for _, p := range s.Endpoint.Ports {
			info.Ports = append(info.Ports, SwarmPortConfig{
				Protocol:      string(p.Protocol),
				TargetPort:    p.TargetPort,
				PublishedPort: p.PublishedPort,
				PublishMode:   string(p.PublishMode),
			})
		}
	}

	return info, nil
}

// SwarmServiceRemove removes a Swarm service.
func (c *Client) SwarmServiceRemove(ctx context.Context, serviceID string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	return c.cli.ServiceRemove(ctx, serviceID)
}

// SwarmServiceScale scales a Swarm service to the desired number of replicas.
func (c *Client) SwarmServiceScale(ctx context.Context, serviceID string, replicas uint64) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	s, _, err := c.cli.ServiceInspectWithRaw(ctx, serviceID, types.ServiceInspectOptions{})
	if err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "service not found")
	}

	if s.Spec.Mode.Replicated == nil {
		return errors.New(errors.CodeValidation, "cannot scale a global service")
	}

	s.Spec.Mode.Replicated.Replicas = &replicas

	_, err = c.cli.ServiceUpdate(ctx, serviceID, s.Version, s.Spec, types.ServiceUpdateOptions{})
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to scale service")
	}

	return nil
}

// SwarmServiceUpdate updates an existing Swarm service.
func (c *Client) SwarmServiceUpdate(ctx context.Context, serviceID string, opts SwarmServiceUpdateOptions) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	s, _, err := c.cli.ServiceInspectWithRaw(ctx, serviceID, types.ServiceInspectOptions{})
	if err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "service not found")
	}

	// Apply updates
	if opts.Image != nil && s.Spec.TaskTemplate.ContainerSpec != nil {
		s.Spec.TaskTemplate.ContainerSpec.Image = *opts.Image
	}
	if opts.Replicas != nil && s.Spec.Mode.Replicated != nil {
		s.Spec.Mode.Replicated.Replicas = opts.Replicas
	}
	if opts.Env != nil && s.Spec.TaskTemplate.ContainerSpec != nil {
		s.Spec.TaskTemplate.ContainerSpec.Env = opts.Env
	}
	if opts.Labels != nil {
		s.Spec.Labels = opts.Labels
	}
	if opts.Ports != nil {
		var ports []swarm.PortConfig
		for _, p := range opts.Ports {
			ports = append(ports, swarm.PortConfig{
				Protocol:      swarm.PortConfigProtocol(p.Protocol),
				TargetPort:    p.TargetPort,
				PublishedPort: p.PublishedPort,
				PublishMode:   swarm.PortConfigPublishMode(p.PublishMode),
			})
		}
		s.Spec.EndpointSpec = &swarm.EndpointSpec{Ports: ports}
	}

	_, err = c.cli.ServiceUpdate(ctx, serviceID, s.Version, s.Spec, types.ServiceUpdateOptions{})
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to update service")
	}

	return nil
}

// ============================================================================
// Swarm Task Operations
// ============================================================================

// SwarmTaskList lists tasks for a specific service.
func (c *Client) SwarmTaskList(ctx context.Context, serviceID string) ([]SwarmTaskInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	tasks, err := c.cli.TaskList(ctx, types.TaskListOptions{
		Filters: filters.NewArgs(filters.Arg("service", serviceID)),
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to list tasks")
	}

	// Get node list for hostname resolution
	nodeMap := make(map[string]string)
	if nodes, nodeErr := c.cli.NodeList(ctx, types.NodeListOptions{}); nodeErr == nil {
		for _, n := range nodes {
			nodeMap[n.ID] = n.Description.Hostname
		}
	}

	result := make([]SwarmTaskInfo, 0, len(tasks))
	for _, t := range tasks {
		info := SwarmTaskInfo{
			ID:           t.ID,
			ServiceID:    t.ServiceID,
			NodeID:       t.NodeID,
			NodeHostname: nodeMap[t.NodeID],
			Status:       string(t.Status.State),
			DesiredState: string(t.DesiredState),
			Error:        t.Status.Err,
			CreatedAt:    t.CreatedAt,
			UpdatedAt:    t.UpdatedAt,
		}

		if t.Status.ContainerStatus != nil {
			info.ContainerID = t.Status.ContainerStatus.ContainerID
		}
		if t.Spec.ContainerSpec != nil {
			info.Image = t.Spec.ContainerSpec.Image
		}

		result = append(result, info)
	}

	return result, nil
}

