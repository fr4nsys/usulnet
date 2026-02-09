// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// SwarmRole represents a node's role in the Swarm cluster
type SwarmRole string

const (
	SwarmRoleManager SwarmRole = "manager"
	SwarmRoleWorker  SwarmRole = "worker"
)

// SwarmServiceMode represents how a service is distributed
type SwarmServiceMode string

const (
	SwarmServiceModeReplicated SwarmServiceMode = "replicated"
	SwarmServiceModeGlobal     SwarmServiceMode = "global"
)

// SwarmServiceStatus represents the status of a swarm service
type SwarmServiceStatus string

const (
	SwarmServiceRunning    SwarmServiceStatus = "running"
	SwarmServiceConverging SwarmServiceStatus = "converging"
	SwarmServicePaused     SwarmServiceStatus = "paused"
	SwarmServiceRemoved    SwarmServiceStatus = "removed"
)

// SwarmClusterInfo represents the overall Swarm cluster state
type SwarmClusterInfo struct {
	Active        bool          `json:"active"`
	ClusterID     string        `json:"cluster_id,omitempty"`
	ManagerNodes  int           `json:"manager_nodes"`
	WorkerNodes   int           `json:"worker_nodes"`
	TotalNodes    int           `json:"total_nodes"`
	ServiceCount  int           `json:"service_count"`
	TaskCount     int           `json:"task_count"`
	JoinTokenWorker  string     `json:"join_token_worker,omitempty"`
	JoinTokenManager string     `json:"join_token_manager,omitempty"`
	ManagerAddr   string        `json:"manager_addr,omitempty"`
	Nodes         []SwarmNode   `json:"nodes,omitempty"`
}

// SwarmNode represents a node in the Swarm cluster
type SwarmNode struct {
	ID           string `json:"id"`
	Hostname     string `json:"hostname"`
	Role         string `json:"role"`          // manager, worker
	Status       string `json:"status"`        // ready, down, disconnected
	Availability string `json:"availability"`  // active, pause, drain
	EngineVersion string `json:"engine_version"`
	Address      string `json:"address"`
	ManagerAddr  string `json:"manager_addr,omitempty"`
	IsLeader     bool   `json:"is_leader"`
	NCPU         int64  `json:"ncpu"`
	MemoryBytes  int64  `json:"memory_bytes"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

// SwarmService represents a Docker Swarm service tracked by usulnet
type SwarmService struct {
	ID                uuid.UUID          `json:"id" db:"id"`
	DockerServiceID   string             `json:"docker_service_id" db:"docker_service_id"`
	Name              string             `json:"name" db:"name"`
	Image             string             `json:"image" db:"image"`
	ReplicasDesired   int                `json:"replicas_desired" db:"replicas_desired"`
	ReplicasRunning   int                `json:"replicas_running" db:"replicas_running"`
	Mode              SwarmServiceMode   `json:"mode" db:"mode"`
	Status            SwarmServiceStatus `json:"status" db:"status"`
	SourceContainerID *string            `json:"source_container_id,omitempty" db:"source_container_id"`
	Ports             []SwarmPort        `json:"ports" db:"-"`
	Env               []string           `json:"env" db:"-"`
	Labels            map[string]string  `json:"labels" db:"-"`
	Constraints       []string           `json:"constraints" db:"-"`
	CreatedAt         time.Time          `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at" db:"updated_at"`

	// Populated at runtime, not stored in DB
	Tasks []SwarmTask `json:"tasks,omitempty" db:"-"`
}

// SwarmPort represents a published port for a Swarm service
type SwarmPort struct {
	Protocol      string `json:"protocol"`       // tcp, udp
	TargetPort    uint32 `json:"target_port"`
	PublishedPort uint32 `json:"published_port"`
	PublishMode   string `json:"publish_mode"`   // ingress, host
}

// SwarmTask represents a running instance of a Swarm service
type SwarmTask struct {
	ID          string    `json:"id"`
	ServiceID   string    `json:"service_id"`
	NodeID      string    `json:"node_id"`
	NodeHostname string   `json:"node_hostname,omitempty"`
	Status      string    `json:"status"`        // running, shutdown, failed, pending, etc.
	DesiredState string   `json:"desired_state"` // running, shutdown
	ContainerID string    `json:"container_id,omitempty"`
	Image       string    `json:"image"`
	Error       string    `json:"error,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CreateSwarmServiceInput represents input for creating a Swarm service
type CreateSwarmServiceInput struct {
	Name        string            `json:"name" validate:"required,min=1,max=100"`
	Image       string            `json:"image" validate:"required"`
	Replicas    int               `json:"replicas" validate:"min=1,max=100"`
	Ports       []SwarmPort       `json:"ports,omitempty"`
	Env         []string          `json:"env,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Constraints []string          `json:"constraints,omitempty"`
	Command     []string          `json:"command,omitempty"`
}

// ScaleSwarmServiceInput represents input for scaling a service
type ScaleSwarmServiceInput struct {
	Replicas int `json:"replicas" validate:"min=0,max=100"`
}

// SwarmInitInput represents input for initializing Swarm
type SwarmInitInput struct {
	AdvertiseAddr string `json:"advertise_addr"` // e.g., "192.168.1.10:2377"
	ListenAddr    string `json:"listen_addr"`    // e.g., "0.0.0.0:2377"
	ForceNewCluster bool `json:"force_new_cluster"`
}

// SwarmJoinInput represents input for joining a Swarm
type SwarmJoinInput struct {
	RemoteAddr string `json:"remote_addr" validate:"required"` // Manager address
	JoinToken  string `json:"join_token" validate:"required"`
	ListenAddr string `json:"listen_addr"`
}

// ConvertToServiceInput represents input for converting a container to a Swarm service
type ConvertToServiceInput struct {
	ContainerID string `json:"container_id" validate:"required"`
	Replicas    int    `json:"replicas" validate:"min=1,max=100"`
	ServiceName string `json:"service_name,omitempty"`
}
