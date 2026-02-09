// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// ContainerState represents the state of a container
type ContainerState string

const (
	ContainerStateCreated    ContainerState = "created"
	ContainerStateRunning    ContainerState = "running"
	ContainerStatePaused     ContainerState = "paused"
	ContainerStateRestarting ContainerState = "restarting"
	ContainerStateRemoving   ContainerState = "removing"
	ContainerStateExited     ContainerState = "exited"
	ContainerStateDead       ContainerState = "dead"
)

// Container represents a Docker container (cached state)
type Container struct {
	ID              string           `json:"id" db:"id"`
	HostID          uuid.UUID        `json:"host_id" db:"host_id"`
	Name            string           `json:"name" db:"name"`
	Image           string           `json:"image" db:"image"`
	ImageID         *string          `json:"image_id,omitempty" db:"image_id"`
	Status          string           `json:"status" db:"status"` // Human readable status
	State           ContainerState   `json:"state" db:"state"`
	CreatedAtDocker *time.Time       `json:"created_at_docker,omitempty" db:"created_at_docker"`
	StartedAt       *time.Time       `json:"started_at,omitempty" db:"started_at"`
	FinishedAt      *time.Time       `json:"finished_at,omitempty" db:"finished_at"`
	Ports           []PortMapping    `json:"ports,omitempty" db:"ports"`
	Labels          map[string]string `json:"labels,omitempty" db:"labels"`
	EnvVars         []string         `json:"env_vars,omitempty" db:"env_vars"` // Variable names only, not values
	Mounts          []MountPoint     `json:"mounts,omitempty" db:"mounts"`
	Networks        []NetworkAttachment `json:"networks,omitempty" db:"networks"`
	RestartPolicy   *string          `json:"restart_policy,omitempty" db:"restart_policy"`
	CurrentVersion  *string          `json:"current_version,omitempty" db:"current_version"`
	LatestVersion   *string          `json:"latest_version,omitempty" db:"latest_version"`
	UpdateAvailable bool             `json:"update_available" db:"update_available"`
	SecurityScore   int              `json:"security_score" db:"security_score"`
	SecurityGrade   string           `json:"security_grade" db:"security_grade"`
	LastScannedAt   *time.Time       `json:"last_scanned_at,omitempty" db:"last_scanned_at"`
	SyncedAt        time.Time        `json:"synced_at" db:"synced_at"`
	CreatedAt       time.Time        `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at" db:"updated_at"`
}

// IsRunning returns true if container is running
func (c *Container) IsRunning() bool {
	return c.State == ContainerStateRunning
}

// NeedsSecurityScan returns true if security scan is needed
func (c *Container) NeedsSecurityScan(interval time.Duration) bool {
	if c.LastScannedAt == nil {
		return true
	}
	return time.Since(*c.LastScannedAt) > interval
}

// PortMapping represents a port mapping
type PortMapping struct {
	PrivatePort uint16 `json:"private_port"`
	PublicPort  uint16 `json:"public_port,omitempty"`
	Type        string `json:"type"` // tcp, udp
	IP          string `json:"ip,omitempty"`
}

// MountPoint represents a volume mount
type MountPoint struct {
	Type        string `json:"type"` // bind, volume, tmpfs
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode,omitempty"` // rw, ro
	RW          bool   `json:"rw"`
	Propagation string `json:"propagation,omitempty"`
}

// NetworkAttachment represents container network attachment
type NetworkAttachment struct {
	NetworkID   string   `json:"network_id"`
	NetworkName string   `json:"network_name"`
	IPAddress   string   `json:"ip_address,omitempty"`
	Gateway     string   `json:"gateway,omitempty"`
	MacAddress  string   `json:"mac_address,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
}

// ContainerStats represents container resource usage
type ContainerStats struct {
	ID             int64     `json:"id" db:"id"`
	ContainerID    string    `json:"container_id" db:"container_id"`
	HostID         uuid.UUID `json:"host_id" db:"host_id"`
	CPUPercent     float64   `json:"cpu_percent" db:"cpu_percent"`
	MemoryUsage    int64     `json:"memory_usage" db:"memory_usage"`
	MemoryLimit    int64     `json:"memory_limit" db:"memory_limit"`
	MemoryPercent  float64   `json:"memory_percent" db:"memory_percent"`
	NetworkRxBytes int64     `json:"network_rx_bytes" db:"network_rx_bytes"`
	NetworkTxBytes int64     `json:"network_tx_bytes" db:"network_tx_bytes"`
	BlockRead      int64     `json:"block_read" db:"block_read"`
	BlockWrite     int64     `json:"block_write" db:"block_write"`
	PIDs           int       `json:"pids" db:"pids"`
	CollectedAt    time.Time `json:"collected_at" db:"collected_at"`
}

// ContainerLogEntry represents a log entry
type ContainerLogEntry struct {
	ID          int64     `json:"id" db:"id"`
	ContainerID string    `json:"container_id" db:"container_id"`
	HostID      uuid.UUID `json:"host_id" db:"host_id"`
	Stream      string    `json:"stream" db:"stream"` // stdout, stderr
	Message     string    `json:"message" db:"message"`
	Timestamp   time.Time `json:"timestamp" db:"timestamp"`
}

// ContainerAction represents a container action request
type ContainerAction string

const (
	ActionStart   ContainerAction = "start"
	ActionStop    ContainerAction = "stop"
	ActionRestart ContainerAction = "restart"
	ActionPause   ContainerAction = "pause"
	ActionUnpause ContainerAction = "unpause"
	ActionKill    ContainerAction = "kill"
	ActionRemove  ContainerAction = "remove"
)

// ContainerActionInput represents input for container action
type ContainerActionInput struct {
	Action  ContainerAction `json:"action" validate:"required,oneof=start stop restart pause unpause kill remove"`
	Signal  *string         `json:"signal,omitempty"` // For kill action
	Timeout *int            `json:"timeout,omitempty"` // For stop action
	Force   bool            `json:"force,omitempty"` // For remove action
}

// CreateContainerInput represents input for creating a container
type CreateContainerInput struct {
	Name          string            `json:"name" validate:"required,docker_container_name"`
	Image         string            `json:"image" validate:"required,docker_image"`
	Cmd           []string          `json:"cmd,omitempty"`
	Entrypoint    []string          `json:"entrypoint,omitempty"`
	Env           map[string]string `json:"env,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	Ports         []PortBinding     `json:"ports,omitempty"`
	Volumes       []VolumeBinding   `json:"volumes,omitempty"`
	Networks      []string          `json:"networks,omitempty"`
	RestartPolicy string            `json:"restart_policy,omitempty" validate:"omitempty,oneof=no always unless-stopped on-failure"`
	Hostname      string            `json:"hostname,omitempty"`
	User          string            `json:"user,omitempty"`
	WorkingDir    string            `json:"working_dir,omitempty"`
	Privileged    bool              `json:"privileged,omitempty"`
	CapAdd        []string          `json:"cap_add,omitempty"`
	CapDrop       []string          `json:"cap_drop,omitempty"`
	MemoryLimit   int64             `json:"memory_limit,omitempty"`
	CPUShares     int64             `json:"cpu_shares,omitempty"`
	CPUQuota      int64             `json:"cpu_quota,omitempty"`
	AutoRemove    bool              `json:"auto_remove,omitempty"`
	ReadOnly      bool              `json:"read_only,omitempty"`
}

// PortBinding represents a port binding configuration
type PortBinding struct {
	ContainerPort uint16 `json:"container_port" validate:"required,port"`
	HostPort      uint16 `json:"host_port,omitempty" validate:"omitempty,port"`
	HostIP        string `json:"host_ip,omitempty"`
	Protocol      string `json:"protocol,omitempty" validate:"omitempty,oneof=tcp udp"`
}

// VolumeBinding represents a volume binding configuration
type VolumeBinding struct {
	Source      string `json:"source" validate:"required"`
	Destination string `json:"destination" validate:"required"`
	ReadOnly    bool   `json:"read_only,omitempty"`
	Type        string `json:"type,omitempty" validate:"omitempty,oneof=bind volume tmpfs"`
}

// ContainerInspect represents detailed container information
type ContainerInspect struct {
	Container
	Config       ContainerConfig       `json:"config"`
	HostConfig   ContainerHostConfig   `json:"host_config"`
	NetworkSettings NetworkSettings    `json:"network_settings"`
	GraphDriver  GraphDriverData       `json:"graph_driver"`
}

// ContainerConfig represents container configuration
type ContainerConfig struct {
	Hostname     string            `json:"hostname"`
	Domainname   string            `json:"domainname"`
	User         string            `json:"user"`
	AttachStdin  bool              `json:"attach_stdin"`
	AttachStdout bool              `json:"attach_stdout"`
	AttachStderr bool              `json:"attach_stderr"`
	Tty          bool              `json:"tty"`
	OpenStdin    bool              `json:"open_stdin"`
	StdinOnce    bool              `json:"stdin_once"`
	Env          []string          `json:"env"`
	Cmd          []string          `json:"cmd"`
	Entrypoint   []string          `json:"entrypoint"`
	Image        string            `json:"image"`
	Labels       map[string]string `json:"labels"`
	WorkingDir   string            `json:"working_dir"`
	Healthcheck  *HealthConfig     `json:"healthcheck,omitempty"`
}

// HealthConfig represents container health check configuration
type HealthConfig struct {
	Test        []string      `json:"test"`
	Interval    time.Duration `json:"interval"`
	Timeout     time.Duration `json:"timeout"`
	Retries     int           `json:"retries"`
	StartPeriod time.Duration `json:"start_period"`
}

// ContainerHostConfig represents container host configuration
type ContainerHostConfig struct {
	Binds           []string               `json:"binds"`
	NetworkMode     string                 `json:"network_mode"`
	PortBindings    map[string][]PortBinding `json:"port_bindings"`
	RestartPolicy   RestartPolicyConfig    `json:"restart_policy"`
	AutoRemove      bool                   `json:"auto_remove"`
	Privileged      bool                   `json:"privileged"`
	ReadonlyRootfs  bool                   `json:"readonly_rootfs"`
	CapAdd          []string               `json:"cap_add"`
	CapDrop         []string               `json:"cap_drop"`
	Memory          int64                  `json:"memory"`
	MemorySwap      int64                  `json:"memory_swap"`
	CPUShares       int64                  `json:"cpu_shares"`
	CPUQuota        int64                  `json:"cpu_quota"`
	CPUPeriod       int64                  `json:"cpu_period"`
	PidMode         string                 `json:"pid_mode"`
	IpcMode         string                 `json:"ipc_mode"`
	UTSMode         string                 `json:"uts_mode"`
	SecurityOpt     []string               `json:"security_opt"`
}

// RestartPolicyConfig represents restart policy
type RestartPolicyConfig struct {
	Name              string `json:"name"` // no, always, unless-stopped, on-failure
	MaximumRetryCount int    `json:"maximum_retry_count"`
}

// NetworkSettings represents container network settings
type NetworkSettings struct {
	Bridge                 string                        `json:"bridge"`
	SandboxID              string                        `json:"sandbox_id"`
	HairpinMode            bool                          `json:"hairpin_mode"`
	LinkLocalIPv6Address   string                        `json:"link_local_ipv6_address"`
	LinkLocalIPv6PrefixLen int                           `json:"link_local_ipv6_prefix_len"`
	Ports                  map[string][]PortBinding      `json:"ports"`
	SandboxKey             string                        `json:"sandbox_key"`
	Networks               map[string]EndpointSettings   `json:"networks"`
}

// EndpointSettings represents network endpoint settings
type EndpointSettings struct {
	NetworkID           string   `json:"network_id"`
	EndpointID          string   `json:"endpoint_id"`
	Gateway             string   `json:"gateway"`
	IPAddress           string   `json:"ip_address"`
	IPPrefixLen         int      `json:"ip_prefix_len"`
	IPv6Gateway         string   `json:"ipv6_gateway"`
	GlobalIPv6Address   string   `json:"global_ipv6_address"`
	GlobalIPv6PrefixLen int      `json:"global_ipv6_prefix_len"`
	MacAddress          string   `json:"mac_address"`
	Aliases             []string `json:"aliases"`
}

// GraphDriverData represents graph driver data
type GraphDriverData struct {
	Name string            `json:"name"`
	Data map[string]string `json:"data"`
}

// ContainerListOptions represents options for listing containers
type ContainerListOptions struct {
	All     bool              `json:"all"`
	Limit   int               `json:"limit"`
	Filters map[string][]string `json:"filters"`
}

// ContainerExecInput represents input for exec command
type ContainerExecInput struct {
	Cmd          []string `json:"cmd" validate:"required"`
	AttachStdin  bool     `json:"attach_stdin"`
	AttachStdout bool     `json:"attach_stdout"`
	AttachStderr bool     `json:"attach_stderr"`
	Tty          bool     `json:"tty"`
	User         string   `json:"user,omitempty"`
	WorkingDir   string   `json:"working_dir,omitempty"`
	Privileged   bool     `json:"privileged"`
}

// ContainerPort represents a port mapping for container creation.
type ContainerPort struct {
	ContainerPort uint16 `json:"container_port"`
	HostPort      uint16 `json:"host_port,omitempty"`
	Protocol      string `json:"protocol,omitempty"` // tcp, udp
	HostIP        string `json:"host_ip,omitempty"`
}

// ContainerMount represents a volume mount for container creation.
type ContainerMount struct {
	Source      string `json:"source"`
	Target      string `json:"target"`
	Type        string `json:"type,omitempty"` // bind, volume, tmpfs
	ReadOnly    bool   `json:"read_only,omitempty"`
	Consistency string `json:"consistency,omitempty"`
}

// PruneResult represents the result of a prune operation.
type PruneResult struct {
	ItemsDeleted   []string `json:"items_deleted"`
	SpaceReclaimed int64    `json:"space_reclaimed"`
}

// ContainerPathStat represents file stat information from a container.
type ContainerPathStat struct {
	Name       string    `json:"name"`
	Size       int64     `json:"size"`
	Mode       uint32    `json:"mode"`
	Mtime      time.Time `json:"mtime"`
	LinkTarget string    `json:"link_target,omitempty"`
}
