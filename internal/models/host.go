// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// JSONStringMap is a map[string]string that implements sql.Scanner and driver.Valuer
// for proper JSONB column scanning with sqlx.
type JSONStringMap map[string]string

// Scan implements the sql.Scanner interface for reading JSONB from PostgreSQL.
func (m *JSONStringMap) Scan(value interface{}) error {
	if value == nil {
		*m = nil
		return nil
	}

	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("JSONStringMap.Scan: unsupported type %T", value)
	}

	result := make(map[string]string)
	if err := json.Unmarshal(bytes, &result); err != nil {
		return fmt.Errorf("JSONStringMap.Scan: %w", err)
	}
	*m = result
	return nil
}

// Value implements the driver.Valuer interface for writing JSONB to PostgreSQL.
// Returns string (not []byte) because pgx treats []byte as bytea, not as JSON text.
func (m JSONStringMap) Value() (driver.Value, error) {
	if m == nil {
		return "{}", nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

// HostEndpointType represents how to connect to a Docker host
type HostEndpointType string

const (
	EndpointLocal  HostEndpointType = "local"  // Local Docker socket
	EndpointSocket HostEndpointType = "socket" // Remote socket via SSH
	EndpointTCP    HostEndpointType = "tcp"    // TCP with TLS
	EndpointAgent  HostEndpointType = "agent"  // Via usulnet agent
)

// HostStatus represents the current status of a host
type HostStatus string

const (
	HostStatusOnline       HostStatus = "online"
	HostStatusOffline      HostStatus = "offline"
	HostStatusConnecting   HostStatus = "connecting"
	HostStatusError        HostStatus = "error"
	HostStatusMaintenance  HostStatus = "maintenance"
	HostStatusUnknown      HostStatus = "unknown"
)

// HostInfo contains minimal host information needed by the gateway.
type HostInfo struct {
	ID     uuid.UUID
	Name   string
	Status string
}

// Host represents a Docker host
type Host struct {
	ID             uuid.UUID        `json:"id" db:"id"`
	Name           string           `json:"name" db:"name"`
	DisplayName    *string          `json:"display_name,omitempty" db:"display_name"`
	EndpointType   HostEndpointType `json:"endpoint_type" db:"endpoint_type"`
	EndpointURL    *string          `json:"endpoint_url,omitempty" db:"endpoint_url"`
	AgentID        *uuid.UUID       `json:"agent_id,omitempty" db:"agent_id"`
	AgentTokenHash *string          `json:"-" db:"agent_token_hash"`
	TLSEnabled     bool             `json:"tls_enabled" db:"tls_enabled"`
	TLSCACert      *string          `json:"-" db:"tls_ca_cert"`
	TLSClientCert  *string          `json:"-" db:"tls_client_cert"`
	TLSClientKey   *string          `json:"-" db:"tls_client_key"`
	Status         HostStatus       `json:"status" db:"status"`
	StatusMessage  *string          `json:"status_message,omitempty" db:"status_message"`
	LastSeenAt     *time.Time       `json:"last_seen_at,omitempty" db:"last_seen_at"`
	DockerVersion  *string          `json:"docker_version,omitempty" db:"docker_version"`
	OSType         *string          `json:"os_type,omitempty" db:"os_type"`
	Architecture   *string          `json:"architecture,omitempty" db:"architecture"`
	TotalMemory    *int64           `json:"total_memory,omitempty" db:"total_memory"`
	TotalCPUs      *int             `json:"total_cpus,omitempty" db:"total_cpus"`
	Labels         JSONStringMap     `json:"labels,omitempty" db:"labels"`
	CreatedAt      time.Time        `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at" db:"updated_at"`
}

// IsOnline returns true if host is online
func (h *Host) IsOnline() bool {
	return h.Status == HostStatusOnline
}

// IsAgent returns true if this is an agent-based host
func (h *Host) IsAgent() bool {
	return h.EndpointType == EndpointAgent
}

// CreateHostInput represents input for creating a host
type CreateHostInput struct {
	Name         string           `json:"name" validate:"required,min=1,max=100"`
	DisplayName  *string          `json:"display_name,omitempty" validate:"omitempty,max=200"`
	EndpointType HostEndpointType `json:"endpoint_type" validate:"required,oneof=local socket tcp agent"`
	EndpointURL  *string          `json:"endpoint_url,omitempty" validate:"omitempty,url"`
	TLSEnabled   bool             `json:"tls_enabled"`
	TLSCACert    *string          `json:"tls_ca_cert,omitempty"`
	TLSClientCert *string         `json:"tls_client_cert,omitempty"`
	TLSClientKey *string          `json:"tls_client_key,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
}

// UpdateHostInput represents input for updating a host
type UpdateHostInput struct {
	DisplayName   *string            `json:"display_name,omitempty" validate:"omitempty,max=200"`
	EndpointURL   *string            `json:"endpoint_url,omitempty" validate:"omitempty,url"`
	TLSEnabled    *bool              `json:"tls_enabled,omitempty"`
	TLSCACert     *string            `json:"tls_ca_cert,omitempty"`
	TLSClientCert *string            `json:"tls_client_cert,omitempty"`
	TLSClientKey  *string            `json:"tls_client_key,omitempty"`
	Labels        map[string]string  `json:"labels,omitempty"`
}

// HostMetrics represents host-level metrics
type HostMetrics struct {
	ID             int64     `json:"id" db:"id"`
	HostID         uuid.UUID `json:"host_id" db:"host_id"`
	CPUPercent     float64   `json:"cpu_percent" db:"cpu_percent"`
	MemoryUsed     int64     `json:"memory_used" db:"memory_used"`
	MemoryTotal    int64     `json:"memory_total" db:"memory_total"`
	MemoryPercent  float64   `json:"memory_percent" db:"memory_percent"`
	DiskUsed       int64     `json:"disk_used" db:"disk_used"`
	DiskTotal      int64     `json:"disk_total" db:"disk_total"`
	DiskPercent    float64   `json:"disk_percent" db:"disk_percent"`
	NetworkRxBytes int64     `json:"network_rx_bytes" db:"network_rx_bytes"`
	NetworkTxBytes int64     `json:"network_tx_bytes" db:"network_tx_bytes"`
	ContainerCount int       `json:"container_count" db:"container_count"`
	RunningCount   int       `json:"running_count" db:"running_count"`
	CollectedAt    time.Time `json:"collected_at" db:"collected_at"`
}

// HostSummary provides a summary view of a host
type HostSummary struct {
	Host
	ContainerCount int     `json:"container_count"`
	RunningCount   int     `json:"running_count"`
	CPUPercent     float64 `json:"cpu_percent"`
	MemoryPercent  float64 `json:"memory_percent"`
	DiskPercent    float64 `json:"disk_percent"`
}

// AgentRegistration represents an agent registration request
type AgentRegistration struct {
	AgentID      uuid.UUID `json:"agent_id"`
	HostName     string    `json:"host_name"`
	Version      string    `json:"version"`
	DockerVersion string   `json:"docker_version"`
	OSType       string    `json:"os_type"`
	Architecture string    `json:"architecture"`
	TotalMemory  int64     `json:"total_memory"`
	TotalCPUs    int       `json:"total_cpus"`
}

// AgentHeartbeat represents an agent heartbeat
type AgentHeartbeat struct {
	AgentID        uuid.UUID `json:"agent_id"`
	Timestamp      time.Time `json:"timestamp"`
	CPUPercent     float64   `json:"cpu_percent"`
	MemoryPercent  float64   `json:"memory_percent"`
	ContainerCount int       `json:"container_count"`
	RunningCount   int       `json:"running_count"`
}

// HostDockerInfo represents Docker daemon information
type HostDockerInfo struct {
	ID                 string            `json:"id"`
	Name               string            `json:"name"`
	ServerVersion      string            `json:"server_version"`
	APIVersion         string            `json:"api_version"`
	OSType             string            `json:"os_type"`
	Architecture       string            `json:"architecture"`
	KernelVersion      string            `json:"kernel_version"`
	OperatingSystem    string            `json:"operating_system"`
	NCPU               int               `json:"ncpu"`
	MemTotal           int64             `json:"mem_total"`
	Containers         int               `json:"containers"`
	ContainersRunning  int               `json:"containers_running"`
	ContainersPaused   int               `json:"containers_paused"`
	ContainersStopped  int               `json:"containers_stopped"`
	Images             int               `json:"images"`
	DockerRootDir      string            `json:"docker_root_dir"`
	StorageDriver      string            `json:"storage_driver"`
	LoggingDriver      string            `json:"logging_driver"`
	CgroupDriver       string            `json:"cgroup_driver"`
	CgroupVersion      string            `json:"cgroup_version"`
	DefaultRuntime     string            `json:"default_runtime"`
	SecurityOptions    []string          `json:"security_options,omitempty"`
	IndexServerAddress string            `json:"index_server_address"`
	RegistryConfig     map[string]any    `json:"registry_config,omitempty"`
	Labels             []string          `json:"labels,omitempty"`
	RuntimeNames       []string          `json:"runtime_names,omitempty"`
	Runtimes           map[string]any    `json:"runtimes,omitempty"`
	Swarm              *SwarmInfo        `json:"swarm,omitempty"`
	SwarmActive        bool              `json:"swarm_active"`
	Plugins            map[string][]string `json:"plugins,omitempty"`
}

// SwarmInfo represents Swarm information
type SwarmInfo struct {
	NodeID           string `json:"node_id"`
	NodeAddr         string `json:"node_addr"`
	LocalNodeState   string `json:"local_node_state"`
	ControlAvailable bool   `json:"control_available"`
	Error            string `json:"error,omitempty"`
	ClusterID        string `json:"cluster_id,omitempty"`
	Managers         int    `json:"managers"`
	Nodes            int    `json:"nodes"`
}
