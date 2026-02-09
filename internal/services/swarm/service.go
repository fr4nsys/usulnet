// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package swarm provides Swarm cluster management for usulnet.
// It wraps Docker SDK Swarm operations with business logic for
// initializing clusters, joining nodes, and managing HA services.
package swarm

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	hostsvc "github.com/fr4nsys/usulnet/internal/services/host"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Service manages Docker Swarm operations through the host service.
type Service struct {
	hostService *hostsvc.Service
	logger      *logger.Logger
	mu          sync.RWMutex
}

// NewService creates a new Swarm service.
func NewService(hostService *hostsvc.Service, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		hostService: hostService,
		logger:      log.Named("swarm"),
	}
}

// ============================================================================
// Cluster Operations
// ============================================================================

// GetClusterInfo returns the current Swarm cluster state from the local Docker host.
func (s *Service) GetClusterInfo(ctx context.Context, hostID uuid.UUID) (*models.SwarmClusterInfo, error) {
	client, err := s.getClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	state, err := client.SwarmInspect(ctx)
	if err != nil {
		return nil, fmt.Errorf("inspect swarm: %w", err)
	}

	info := &models.SwarmClusterInfo{
		Active:       state.Active,
		ClusterID:    state.ClusterID,
		ManagerAddr:  state.NodeAddr,
	}

	if !state.Active {
		return info, nil
	}

	// Get join tokens if we're a manager
	if state.IsManager {
		workerToken, managerToken, tokenErr := client.SwarmGetJoinTokens(ctx)
		if tokenErr == nil {
			info.JoinTokenWorker = workerToken
			info.JoinTokenManager = managerToken
		}
	}

	// Get node list
	nodes, nodeErr := client.SwarmNodeList(ctx)
	if nodeErr == nil {
		for _, n := range nodes {
			info.TotalNodes++
			if n.Role == "manager" {
				info.ManagerNodes++
			} else {
				info.WorkerNodes++
			}
			info.Nodes = append(info.Nodes, models.SwarmNode{
				ID:            n.ID,
				Hostname:      n.Hostname,
				Role:          n.Role,
				Status:        n.Status,
				Availability:  n.Availability,
				EngineVersion: n.EngineVersion,
				Address:       n.Address,
				IsLeader:      n.IsLeader,
				NCPU:          n.NCPU,
				MemoryBytes:   n.MemoryBytes,
				OS:            n.OS,
				Architecture:  n.Architecture,
			})
		}
	}

	// Get service count
	services, svcErr := client.SwarmServiceList(ctx)
	if svcErr == nil {
		info.ServiceCount = len(services)
	}

	return info, nil
}

// InitSwarm initializes a new Swarm cluster on the specified host.
func (s *Service) InitSwarm(ctx context.Context, hostID uuid.UUID, input *models.SwarmInitInput) (*models.SwarmClusterInfo, error) {
	client, err := s.getClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	listenAddr := input.ListenAddr
	if listenAddr == "" {
		listenAddr = "0.0.0.0:2377"
	}

	nodeID, err := client.SwarmInit(ctx, listenAddr, input.AdvertiseAddr, input.ForceNewCluster)
	if err != nil {
		return nil, fmt.Errorf("init swarm: %w", err)
	}

	s.logger.Info("Swarm initialized",
		"host_id", hostID,
		"node_id", nodeID,
		"advertise_addr", input.AdvertiseAddr,
	)

	// Return full cluster info
	return s.GetClusterInfo(ctx, hostID)
}

// LeaveSwarm makes the specified host leave the Swarm cluster.
func (s *Service) LeaveSwarm(ctx context.Context, hostID uuid.UUID, force bool) error {
	client, err := s.getClient(ctx, hostID)
	if err != nil {
		return err
	}

	if err := client.SwarmLeave(ctx, force); err != nil {
		return fmt.Errorf("leave swarm: %w", err)
	}

	s.logger.Info("Host left Swarm", "host_id", hostID, "force", force)
	return nil
}

// ============================================================================
// Node Operations
// ============================================================================

// ListNodes returns all nodes in the Swarm cluster.
func (s *Service) ListNodes(ctx context.Context, hostID uuid.UUID) ([]models.SwarmNode, error) {
	client, err := s.getClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	nodes, err := client.SwarmNodeList(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}

	result := make([]models.SwarmNode, 0, len(nodes))
	for _, n := range nodes {
		result = append(result, models.SwarmNode{
			ID:            n.ID,
			Hostname:      n.Hostname,
			Role:          n.Role,
			Status:        n.Status,
			Availability:  n.Availability,
			EngineVersion: n.EngineVersion,
			Address:       n.Address,
			IsLeader:      n.IsLeader,
			NCPU:          n.NCPU,
			MemoryBytes:   n.MemoryBytes,
			OS:            n.OS,
			Architecture:  n.Architecture,
		})
	}

	return result, nil
}

// RemoveNode removes a node from the Swarm cluster.
func (s *Service) RemoveNode(ctx context.Context, hostID uuid.UUID, nodeID string, force bool) error {
	client, err := s.getClient(ctx, hostID)
	if err != nil {
		return err
	}

	if err := client.SwarmNodeRemove(ctx, nodeID, force); err != nil {
		return fmt.Errorf("remove node: %w", err)
	}

	s.logger.Info("Node removed from Swarm", "node_id", nodeID, "force", force)
	return nil
}

// ============================================================================
// Service Operations
// ============================================================================

// ListServices returns all Swarm services.
func (s *Service) ListServices(ctx context.Context, hostID uuid.UUID) ([]docker.SwarmServiceInfo, error) {
	client, err := s.getClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	services, err := client.SwarmServiceList(ctx)
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}

	return services, nil
}

// GetService returns details of a specific Swarm service.
func (s *Service) GetService(ctx context.Context, hostID uuid.UUID, serviceID string) (*docker.SwarmServiceInfo, error) {
	client, err := s.getClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	svc, err := client.SwarmServiceGet(ctx, serviceID)
	if err != nil {
		return nil, fmt.Errorf("get service: %w", err)
	}

	return svc, nil
}

// CreateService creates a new Swarm service.
func (s *Service) CreateService(ctx context.Context, hostID uuid.UUID, input *models.CreateSwarmServiceInput) (string, error) {
	client, err := s.getClient(ctx, hostID)
	if err != nil {
		return "", err
	}

	opts := docker.SwarmServiceCreateOptions{
		Name:        input.Name,
		Image:       input.Image,
		Replicas:    uint64(input.Replicas),
		Env:         input.Env,
		Labels:      input.Labels,
		Constraints: input.Constraints,
		Command:     input.Command,
	}

	for _, p := range input.Ports {
		opts.Ports = append(opts.Ports, docker.SwarmPortConfig{
			Protocol:      p.Protocol,
			TargetPort:    p.TargetPort,
			PublishedPort: p.PublishedPort,
			PublishMode:   p.PublishMode,
		})
	}

	serviceID, err := client.SwarmServiceCreate(ctx, opts)
	if err != nil {
		return "", fmt.Errorf("create service: %w", err)
	}

	s.logger.Info("Swarm service created",
		"service_id", serviceID,
		"name", input.Name,
		"image", input.Image,
		"replicas", input.Replicas,
	)

	return serviceID, nil
}

// RemoveService removes a Swarm service.
func (s *Service) RemoveService(ctx context.Context, hostID uuid.UUID, serviceID string) error {
	client, err := s.getClient(ctx, hostID)
	if err != nil {
		return err
	}

	if err := client.SwarmServiceRemove(ctx, serviceID); err != nil {
		return fmt.Errorf("remove service: %w", err)
	}

	s.logger.Info("Swarm service removed", "service_id", serviceID)
	return nil
}

// ScaleService scales a Swarm service to the desired number of replicas.
func (s *Service) ScaleService(ctx context.Context, hostID uuid.UUID, serviceID string, replicas int) error {
	client, err := s.getClient(ctx, hostID)
	if err != nil {
		return err
	}

	if err := client.SwarmServiceScale(ctx, serviceID, uint64(replicas)); err != nil {
		return fmt.Errorf("scale service: %w", err)
	}

	s.logger.Info("Swarm service scaled", "service_id", serviceID, "replicas", replicas)
	return nil
}

// ListTasks returns all tasks for a specific service.
func (s *Service) ListTasks(ctx context.Context, hostID uuid.UUID, serviceID string) ([]docker.SwarmTaskInfo, error) {
	client, err := s.getClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	tasks, err := client.SwarmTaskList(ctx, serviceID)
	if err != nil {
		return nil, fmt.Errorf("list tasks: %w", err)
	}

	return tasks, nil
}

// ============================================================================
// Container → Service Conversion
// ============================================================================

// ConvertContainerToService converts a running container to a Swarm service with replicas.
func (s *Service) ConvertContainerToService(ctx context.Context, hostID uuid.UUID, input *models.ConvertToServiceInput) (string, error) {
	client, err := s.getClient(ctx, hostID)
	if err != nil {
		return "", err
	}

	// Get container details
	details, err := client.ContainerGet(ctx, input.ContainerID)
	if err != nil {
		return "", fmt.Errorf("get container: %w", err)
	}

	// Build service name
	serviceName := input.ServiceName
	if serviceName == "" {
		serviceName = details.Name
		// Remove leading "/" from Docker container names
		if len(serviceName) > 0 && serviceName[0] == '/' {
			serviceName = serviceName[1:]
		}
	}

	// Build port configs from container
	var ports []docker.SwarmPortConfig
	for _, p := range details.Ports {
		if p.PublicPort > 0 {
			ports = append(ports, docker.SwarmPortConfig{
				Protocol:      p.Type,
				TargetPort:    uint32(p.PrivatePort),
				PublishedPort: uint32(p.PublicPort),
				PublishMode:   "ingress",
			})
		}
	}

	// Build env from container config
	var env []string
	if details.Config != nil {
		env = details.Config.Env
	}

	// Create the service
	replicas := uint64(input.Replicas)
	if replicas == 0 {
		replicas = 1
	}

	opts := docker.SwarmServiceCreateOptions{
		Name:     serviceName,
		Image:    details.Image,
		Replicas: replicas,
		Env:      env,
		Ports:    ports,
		Labels: map[string]string{
			"usulnet.source":       "container-conversion",
			"usulnet.container_id": input.ContainerID,
		},
	}

	serviceID, err := client.SwarmServiceCreate(ctx, opts)
	if err != nil {
		return "", fmt.Errorf("create service from container: %w", err)
	}

	s.logger.Info("Container converted to Swarm service",
		"container_id", input.ContainerID,
		"container_name", details.Name,
		"service_id", serviceID,
		"service_name", serviceName,
		"replicas", replicas,
	)

	return serviceID, nil
}

// ============================================================================
// Helpers
// ============================================================================

func (s *Service) getClient(ctx context.Context, hostID uuid.UUID) (docker.ClientAPI, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, fmt.Errorf("get docker client for host %s: %w", hostID, err)
	}
	return client, nil
}
