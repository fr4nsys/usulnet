// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package protocol defines command types for Gateway-Agent communication.
package protocol

import (
	"time"
)

// CommandType identifies the type of command to execute.
type CommandType string

// Container commands
const (
	CmdContainerList       CommandType = "container.list"
	CmdContainerInspect    CommandType = "container.inspect"
	CmdContainerStart      CommandType = "container.start"
	CmdContainerStop       CommandType = "container.stop"
	CmdContainerRestart    CommandType = "container.restart"
	CmdContainerKill       CommandType = "container.kill"
	CmdContainerPause      CommandType = "container.pause"
	CmdContainerUnpause    CommandType = "container.unpause"
	CmdContainerRemove     CommandType = "container.remove"
	CmdContainerCreate     CommandType = "container.create"
	CmdContainerRename     CommandType = "container.rename"
	CmdContainerLogs       CommandType = "container.logs"
	CmdContainerStats      CommandType = "container.stats"
	CmdContainerExec       CommandType = "container.exec"
	CmdContainerTop        CommandType = "container.top"
	CmdContainerRecreate   CommandType = "container.recreate"
	CmdContainerUpdate     CommandType = "container.update"
)

// Image commands
const (
	CmdImageList    CommandType = "image.list"
	CmdImageInspect CommandType = "image.inspect"
	CmdImagePull    CommandType = "image.pull"
	CmdImageRemove  CommandType = "image.remove"
	CmdImageTag     CommandType = "image.tag"
	CmdImagePrune   CommandType = "image.prune"
	CmdImageHistory CommandType = "image.history"
	CmdImageSearch  CommandType = "image.search"
)

// Volume commands
const (
	CmdVolumeList    CommandType = "volume.list"
	CmdVolumeInspect CommandType = "volume.inspect"
	CmdVolumeCreate  CommandType = "volume.create"
	CmdVolumeRemove  CommandType = "volume.remove"
	CmdVolumePrune   CommandType = "volume.prune"
)

// Network commands
const (
	CmdNetworkList       CommandType = "network.list"
	CmdNetworkInspect    CommandType = "network.inspect"
	CmdNetworkCreate     CommandType = "network.create"
	CmdNetworkRemove     CommandType = "network.remove"
	CmdNetworkConnect    CommandType = "network.connect"
	CmdNetworkDisconnect CommandType = "network.disconnect"
	CmdNetworkPrune      CommandType = "network.prune"
)

// Stack/Compose commands
const (
	CmdStackList    CommandType = "stack.list"
	CmdStackDeploy  CommandType = "stack.deploy"
	CmdStackRemove  CommandType = "stack.remove"
	CmdStackStart   CommandType = "stack.start"
	CmdStackStop    CommandType = "stack.stop"
	CmdStackRestart CommandType = "stack.restart"
	CmdStackLogs    CommandType = "stack.logs"
)

// System commands
const (
	CmdSystemInfo      CommandType = "system.info"
	CmdSystemVersion   CommandType = "system.version"
	CmdSystemDf        CommandType = "system.df"
	CmdSystemPing      CommandType = "system.ping"
	CmdSystemEvents    CommandType = "system.events"
	CmdSystemPrune     CommandType = "system.prune"
)

// Backup commands
const (
	CmdBackupVolume   CommandType = "backup.volume"
	CmdBackupRestore  CommandType = "backup.restore"
	CmdBackupList     CommandType = "backup.list"
	CmdBackupDownload CommandType = "backup.download"
)

// Security commands
const (
	CmdSecurityScan      CommandType = "security.scan"
	CmdSecurityScanImage CommandType = "security.scan_image"
)

// Update commands
const (
	CmdUpdateCheck   CommandType = "update.check"
	CmdUpdateApply   CommandType = "update.apply"
	CmdUpdateRollback CommandType = "update.rollback"
)

// Exec commands
const (
	CmdExecRun    CommandType = "exec.run"
	CmdExecResize CommandType = "exec.resize"
)

// Agent control commands
const (
	CmdAgentDisconnect CommandType = "agent.disconnect"
	CmdAgentReconnect  CommandType = "agent.reconnect"
	CmdAgentReload     CommandType = "agent.reload"
	CmdAgentRestart    CommandType = "agent.restart"
	CmdAgentConfigure  CommandType = "agent.configure"
)

// CommandPriority defines execution priority.
type CommandPriority int

const (
	PriorityLow      CommandPriority = 0
	PriorityNormal   CommandPriority = 1
	PriorityHigh     CommandPriority = 2
	PriorityCritical CommandPriority = 3
)

// Command represents a command to be executed by an agent.
type Command struct {
	ID          string          `json:"id"`
	Type        CommandType     `json:"type"`
	HostID      string          `json:"host_id"`
	Priority    CommandPriority `json:"priority"`
	Timeout     time.Duration   `json:"timeout"`
	ReplyTo     string          `json:"reply_to"`
	CreatedAt   time.Time       `json:"created_at"`
	CreatedBy   string          `json:"created_by,omitempty"`
	Params      CommandParams   `json:"params"`
	Retries     int             `json:"retries,omitempty"`
	MaxRetries  int             `json:"max_retries,omitempty"`
	Idempotent  bool            `json:"idempotent,omitempty"`
}

// CommandParams contains command-specific parameters.
type CommandParams struct {
	// Container params
	ContainerID   string            `json:"container_id,omitempty"`
	ContainerName string            `json:"container_name,omitempty"`
	Signal        string            `json:"signal,omitempty"`
	Force         bool              `json:"force,omitempty"`
	RemoveVolumes bool              `json:"remove_volumes,omitempty"`
	StopTimeout   *int              `json:"stop_timeout,omitempty"`
	
	// Image params
	ImageRef      string            `json:"image_ref,omitempty"`
	Tag           string            `json:"tag,omitempty"`
	Platform      string            `json:"platform,omitempty"`
	RegistryAuth  string            `json:"registry_auth,omitempty"` // Base64-encoded JSON credentials for private registries
	
	// Volume params
	VolumeID      string            `json:"volume_id,omitempty"`
	VolumeName    string            `json:"volume_name,omitempty"`
	Driver        string            `json:"driver,omitempty"`
	DriverOpts    map[string]string `json:"driver_opts,omitempty"`
	
	// Network params
	NetworkID     string            `json:"network_id,omitempty"`
	NetworkName   string            `json:"network_name,omitempty"`
	Subnet        string            `json:"subnet,omitempty"`
	Gateway       string            `json:"gateway,omitempty"`
	Internal      bool              `json:"internal,omitempty"`
	Attachable    bool              `json:"attachable,omitempty"`
	EndpointID    string            `json:"endpoint_id,omitempty"`
	IPAddress     string            `json:"ip_address,omitempty"`
	Aliases       []string          `json:"aliases,omitempty"`
	
	// Stack params
	StackName     string            `json:"stack_name,omitempty"`
	ComposeFile   string            `json:"compose_file,omitempty"`
	EnvVars       map[string]string `json:"env_vars,omitempty"`
	
	// Logs params
	Follow        bool              `json:"follow,omitempty"`
	Tail          string            `json:"tail,omitempty"`
	Since         string            `json:"since,omitempty"`
	Until         string            `json:"until,omitempty"`
	Timestamps    bool              `json:"timestamps,omitempty"`
	Details       bool              `json:"details,omitempty"`
	
	// Exec params
	Cmd           []string          `json:"cmd,omitempty"`
	WorkingDir    string            `json:"working_dir,omitempty"`
	Env           []string          `json:"env,omitempty"`
	User          string            `json:"user,omitempty"`
	Tty           bool              `json:"tty,omitempty"`
	AttachStdin   bool              `json:"attach_stdin,omitempty"`
	AttachStdout  bool              `json:"attach_stdout,omitempty"`
	AttachStderr  bool              `json:"attach_stderr,omitempty"`
	Privileged    bool              `json:"privileged,omitempty"`
	
	// Create/Update params
	Config        interface{}       `json:"config,omitempty"`
	HostConfig    interface{}       `json:"host_config,omitempty"`
	NetworkConfig interface{}       `json:"network_config,omitempty"`
	
	// Backup params
	BackupPath    string            `json:"backup_path,omitempty"`
	BackupID      string            `json:"backup_id,omitempty"`
	Compress      bool              `json:"compress,omitempty"`
	
	// Prune params
	PruneFilters  map[string][]string `json:"prune_filters,omitempty"`
	PruneAll      bool              `json:"prune_all,omitempty"`
	
	// Generic filters
	Filters       map[string][]string `json:"filters,omitempty"`
	All           bool              `json:"all,omitempty"`
	Limit         int               `json:"limit,omitempty"`
}

// CommandStatus represents the status of a command execution.
type CommandStatus string

const (
	CommandStatusPending   CommandStatus = "pending"
	CommandStatusRunning   CommandStatus = "running"
	CommandStatusCompleted CommandStatus = "completed"
	CommandStatusFailed    CommandStatus = "failed"
	CommandStatusTimeout   CommandStatus = "timeout"
	CommandStatusCancelled CommandStatus = "cancelled"
)

// CommandResult contains the result of a command execution.
type CommandResult struct {
	CommandID   string        `json:"command_id"`
	Status      CommandStatus `json:"status"`
	StartedAt   time.Time     `json:"started_at"`
	CompletedAt time.Time     `json:"completed_at"`
	Duration    time.Duration `json:"duration"`
	Data        interface{}   `json:"data,omitempty"`
	Error       *CommandError `json:"error,omitempty"`
	Warnings    []string      `json:"warnings,omitempty"`
	Retried     int           `json:"retried,omitempty"`
}

// CommandError represents an error during command execution.
type CommandError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
	// Original error from Docker SDK if applicable
	DockerError string `json:"docker_error,omitempty"`
}

func (e *CommandError) Error() string {
	if e.DockerError != "" {
		return e.Code + ": " + e.Message + " (docker: " + e.DockerError + ")"
	}
	return e.Code + ": " + e.Message
}

// NewCommandResult creates a successful command result.
func NewCommandResult(cmdID string, data interface{}) *CommandResult {
	return &CommandResult{
		CommandID:   cmdID,
		Status:      CommandStatusCompleted,
		CompletedAt: time.Now().UTC(),
		Data:        data,
	}
}

// NewCommandResultError creates a failed command result.
func NewCommandResultError(cmdID string, err *CommandError) *CommandResult {
	return &CommandResult{
		CommandID:   cmdID,
		Status:      CommandStatusFailed,
		CompletedAt: time.Now().UTC(),
		Error:       err,
	}
}

// DefaultTimeout returns the default timeout for a command type.
func DefaultTimeout(cmdType CommandType) time.Duration {
	switch cmdType {
	case CmdImagePull:
		return 10 * time.Minute
	case CmdStackDeploy:
		return 5 * time.Minute
	case CmdContainerLogs, CmdStackLogs:
		return 30 * time.Second
	case CmdBackupVolume, CmdBackupRestore:
		return 30 * time.Minute
	case CmdSecurityScan, CmdSecurityScanImage:
		return 10 * time.Minute
	case CmdUpdateApply:
		return 15 * time.Minute
	case CmdSystemPrune, CmdImagePrune, CmdVolumePrune, CmdNetworkPrune:
		return 5 * time.Minute
	default:
		return 30 * time.Second
	}
}

// IsIdempotent returns true if the command type is safe to retry.
func IsIdempotent(cmdType CommandType) bool {
	switch cmdType {
	case CmdContainerList, CmdContainerInspect, CmdContainerLogs, CmdContainerStats, CmdContainerTop,
		CmdImageList, CmdImageInspect, CmdImageHistory, CmdImageSearch,
		CmdVolumeList, CmdVolumeInspect,
		CmdNetworkList, CmdNetworkInspect,
		CmdStackList, CmdStackLogs,
		CmdSystemInfo, CmdSystemVersion, CmdSystemDf, CmdSystemPing,
		CmdBackupList,
		CmdUpdateCheck:
		return true
	default:
		return false
	}
}

// IsDestructive returns true if the command could cause data loss.
func IsDestructive(cmdType CommandType) bool {
	switch cmdType {
	case CmdContainerRemove, CmdContainerKill,
		CmdImageRemove, CmdImagePrune,
		CmdVolumeRemove, CmdVolumePrune,
		CmdNetworkRemove, CmdNetworkPrune,
		CmdStackRemove,
		CmdSystemPrune:
		return true
	default:
		return false
	}
}
