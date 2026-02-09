// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// StackStatus represents the status of a stack
type StackStatus string

const (
	StackStatusActive   StackStatus = "active"
	StackStatusInactive StackStatus = "inactive"
	StackStatusPartial  StackStatus = "partial" // Some containers running
	StackStatusError    StackStatus = "error"
	StackStatusUnknown  StackStatus = "unknown"
)

// StackType represents the type of stack
type StackType string

const (
	StackTypeCompose StackType = "compose"
	StackTypeSwarm   StackType = "swarm"
)

// Stack represents a docker-compose or swarm stack
type Stack struct {
	ID              uuid.UUID         `json:"id" db:"id"`
	HostID          uuid.UUID         `json:"host_id" db:"host_id"`
	Name            string            `json:"name" db:"name"`
	Type            StackType         `json:"type" db:"type"`
	Status          StackStatus       `json:"status" db:"status"`
	ProjectDir      string            `json:"project_dir" db:"project_dir"`
	ComposeFile     string            `json:"compose_file" db:"compose_file"` // YAML content
	EnvFile         *string           `json:"env_file,omitempty" db:"env_file"`
	Variables       map[string]string `json:"variables,omitempty" db:"variables"` // Interpolation vars
	Services        []StackService    `json:"services,omitempty" db:"-"`
	ServiceCount    int               `json:"service_count" db:"service_count"`
	RunningCount    int               `json:"running_count" db:"running_count"`
	GitRepo         *string           `json:"git_repo,omitempty" db:"git_repo"`
	GitBranch       *string           `json:"git_branch,omitempty" db:"git_branch"`
	GitCommit       *string           `json:"git_commit,omitempty" db:"git_commit"`
	LastDeployedAt  *time.Time        `json:"last_deployed_at,omitempty" db:"last_deployed_at"`
	LastDeployedBy  *uuid.UUID        `json:"last_deployed_by,omitempty" db:"last_deployed_by"`
	CreatedAt       time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at" db:"updated_at"`
}

// IsRunning returns true if all services are running
func (s *Stack) IsRunning() bool {
	return s.Status == StackStatusActive && s.RunningCount == s.ServiceCount
}

// IsPartiallyRunning returns true if some services are running
func (s *Stack) IsPartiallyRunning() bool {
	return s.Status == StackStatusPartial || (s.RunningCount > 0 && s.RunningCount < s.ServiceCount)
}

// IsStopped returns true if no services are running
func (s *Stack) IsStopped() bool {
	return s.RunningCount == 0
}

// IsFromGit returns true if stack is from a Git repository
func (s *Stack) IsFromGit() bool {
	return s.GitRepo != nil && *s.GitRepo != ""
}

// StackService represents a service in a stack
type StackService struct {
	Name           string          `json:"name"`
	Image          string          `json:"image"`
	ContainerID    *string         `json:"container_id,omitempty"`
	ContainerName  *string         `json:"container_name,omitempty"`
	Status         string          `json:"status"`
	State          ContainerState  `json:"state"`
	Replicas       int             `json:"replicas"`
	RunningReplicas int            `json:"running_replicas"`
	Ports          []PortMapping   `json:"ports,omitempty"`
	Volumes        []string        `json:"volumes,omitempty"`
	Networks       []string        `json:"networks,omitempty"`
	DependsOn      []string        `json:"depends_on,omitempty"`
	HealthStatus   *string         `json:"health_status,omitempty"`
}

// CreateStackInput represents input for creating a stack
type CreateStackInput struct {
	Name         string            `json:"name" validate:"required,min=1,max=100"`
	ComposeFile  string            `json:"compose_file" validate:"required"`
	EnvFile      *string           `json:"env_file,omitempty"`
	Variables    map[string]string `json:"variables,omitempty"`
	ProjectDir   string            `json:"project_dir,omitempty"`
	AutoStart    bool              `json:"auto_start,omitempty"`
}

// CreateStackFromGitInput represents input for creating a stack from Git
type CreateStackFromGitInput struct {
	Name          string            `json:"name" validate:"required,min=1,max=100"`
	GitRepo       string            `json:"git_repo" validate:"required,url"`
	GitBranch     string            `json:"git_branch,omitempty"`
	GitUsername   *string           `json:"git_username,omitempty"`
	GitPassword   *string           `json:"git_password,omitempty"`
	ComposeFile   string            `json:"compose_file,omitempty"` // Path in repo
	Variables     map[string]string `json:"variables,omitempty"`
	AutoStart     bool              `json:"auto_start,omitempty"`
}

// UpdateStackInput represents input for updating a stack
type UpdateStackInput struct {
	ComposeFile  *string           `json:"compose_file,omitempty"`
	EnvFile      *string           `json:"env_file,omitempty"`
	Variables    map[string]string `json:"variables,omitempty"`
}

// StackActionInput represents input for stack actions
type StackActionInput struct {
	Action  StackAction `json:"action" validate:"required,oneof=start stop restart pull recreate"`
	Timeout *int        `json:"timeout,omitempty"`
}

// StackAction represents a stack action
type StackAction string

const (
	StackActionStart    StackAction = "start"
	StackActionStop     StackAction = "stop"
	StackActionRestart  StackAction = "restart"
	StackActionPull     StackAction = "pull"
	StackActionRecreate StackAction = "recreate"
)

// StackDeployOptions represents options for deploying a stack
type StackDeployOptions struct {
	Prune            bool     `json:"prune,omitempty"`
	RemoveOrphans    bool     `json:"remove_orphans,omitempty"`
	ForceRecreate    bool     `json:"force_recreate,omitempty"`
	NoBuild          bool     `json:"no_build,omitempty"`
	NoStart          bool     `json:"no_start,omitempty"`
	QuietPull        bool     `json:"quiet_pull,omitempty"`
	Wait             bool     `json:"wait,omitempty"`
	WaitTimeout      *int     `json:"wait_timeout,omitempty"`
	Services         []string `json:"services,omitempty"` // Specific services to deploy
}

// StackLog represents a stack operation log
type StackLog struct {
	ID          int64     `json:"id" db:"id"`
	StackID     uuid.UUID `json:"stack_id" db:"stack_id"`
	Operation   string    `json:"operation" db:"operation"`
	Status      string    `json:"status" db:"status"` // running, success, failed
	Output      string    `json:"output" db:"output"`
	ErrorMsg    *string   `json:"error_msg,omitempty" db:"error_msg"`
	UserID      *uuid.UUID `json:"user_id,omitempty" db:"user_id"`
	StartedAt   time.Time `json:"started_at" db:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty" db:"completed_at"`
}

// ComposeConfig represents parsed docker-compose configuration
type ComposeConfig struct {
	Version  string                    `json:"version,omitempty"`
	Services map[string]ComposeService `json:"services"`
	Networks map[string]ComposeNetwork `json:"networks,omitempty"`
	Volumes  map[string]ComposeVolume  `json:"volumes,omitempty"`
	Secrets  map[string]ComposeSecret  `json:"secrets,omitempty"`
	Configs  map[string]ComposeConfig_ `json:"configs,omitempty"`
}

// ComposeService represents a service in docker-compose
type ComposeService struct {
	Image         string            `json:"image,omitempty"`
	Build         *ComposeBuild     `json:"build,omitempty"`
	Command       interface{}       `json:"command,omitempty"` // string or []string
	Entrypoint    interface{}       `json:"entrypoint,omitempty"`
	Environment   interface{}       `json:"environment,omitempty"` // map or []string
	EnvFile       interface{}       `json:"env_file,omitempty"` // string or []string
	Ports         []interface{}     `json:"ports,omitempty"`
	Volumes       []interface{}     `json:"volumes,omitempty"`
	Networks      interface{}       `json:"networks,omitempty"`
	DependsOn     interface{}       `json:"depends_on,omitempty"`
	Restart       string            `json:"restart,omitempty"`
	Labels        interface{}       `json:"labels,omitempty"`
	Healthcheck   *ComposeHealthcheck `json:"healthcheck,omitempty"`
	Deploy        *ComposeDeploy    `json:"deploy,omitempty"`
	Logging       *ComposeLogging   `json:"logging,omitempty"`
	Hostname      string            `json:"hostname,omitempty"`
	ContainerName string            `json:"container_name,omitempty"`
	User          string            `json:"user,omitempty"`
	WorkingDir    string            `json:"working_dir,omitempty"`
	Privileged    bool              `json:"privileged,omitempty"`
	CapAdd        []string          `json:"cap_add,omitempty"`
	CapDrop       []string          `json:"cap_drop,omitempty"`
	SecurityOpt   []string          `json:"security_opt,omitempty"`
	Ulimits       interface{}       `json:"ulimits,omitempty"`
	Sysctls       interface{}       `json:"sysctls,omitempty"`
	ExtraHosts    []string          `json:"extra_hosts,omitempty"`
	Dns           interface{}       `json:"dns,omitempty"`
	DnsSearch     interface{}       `json:"dns_search,omitempty"`
	Tmpfs         interface{}       `json:"tmpfs,omitempty"`
	StdinOpen     bool              `json:"stdin_open,omitempty"`
	Tty           bool              `json:"tty,omitempty"`
	StopSignal    string            `json:"stop_signal,omitempty"`
	StopGracePeriod string          `json:"stop_grace_period,omitempty"`
	Secrets       []interface{}     `json:"secrets,omitempty"`
	Configs       []interface{}     `json:"configs,omitempty"`
}

// ComposeBuild represents build configuration
type ComposeBuild struct {
	Context    string            `json:"context,omitempty"`
	Dockerfile string            `json:"dockerfile,omitempty"`
	Args       interface{}       `json:"args,omitempty"`
	Target     string            `json:"target,omitempty"`
	CacheFrom  []string          `json:"cache_from,omitempty"`
	Labels     interface{}       `json:"labels,omitempty"`
	Network    string            `json:"network,omitempty"`
}

// ComposeHealthcheck represents healthcheck configuration
type ComposeHealthcheck struct {
	Test        interface{} `json:"test,omitempty"`
	Interval    string      `json:"interval,omitempty"`
	Timeout     string      `json:"timeout,omitempty"`
	Retries     int         `json:"retries,omitempty"`
	StartPeriod string      `json:"start_period,omitempty"`
	Disable     bool        `json:"disable,omitempty"`
}

// ComposeDeploy represents deploy configuration (Swarm)
type ComposeDeploy struct {
	Mode           string                 `json:"mode,omitempty"`
	Replicas       *int                   `json:"replicas,omitempty"`
	Labels         interface{}            `json:"labels,omitempty"`
	UpdateConfig   *ComposeUpdateConfig   `json:"update_config,omitempty"`
	RollbackConfig *ComposeUpdateConfig   `json:"rollback_config,omitempty"`
	Resources      *ComposeResources      `json:"resources,omitempty"`
	RestartPolicy  *ComposeRestartPolicy  `json:"restart_policy,omitempty"`
	Placement      *ComposePlacement      `json:"placement,omitempty"`
	EndpointMode   string                 `json:"endpoint_mode,omitempty"`
}

// ComposeUpdateConfig represents update configuration
type ComposeUpdateConfig struct {
	Parallelism   *int   `json:"parallelism,omitempty"`
	Delay         string `json:"delay,omitempty"`
	FailureAction string `json:"failure_action,omitempty"`
	Monitor       string `json:"monitor,omitempty"`
	MaxFailureRatio string `json:"max_failure_ratio,omitempty"`
	Order         string `json:"order,omitempty"`
}

// ComposeResources represents resource constraints
type ComposeResources struct {
	Limits       *ComposeResourceLimit `json:"limits,omitempty"`
	Reservations *ComposeResourceLimit `json:"reservations,omitempty"`
}

// ComposeResourceLimit represents resource limits
type ComposeResourceLimit struct {
	Cpus    string `json:"cpus,omitempty"`
	Memory  string `json:"memory,omitempty"`
	Pids    int64  `json:"pids,omitempty"`
}

// ComposeRestartPolicy represents restart policy
type ComposeRestartPolicy struct {
	Condition   string `json:"condition,omitempty"`
	Delay       string `json:"delay,omitempty"`
	MaxAttempts *int   `json:"max_attempts,omitempty"`
	Window      string `json:"window,omitempty"`
}

// ComposePlacement represents placement constraints
type ComposePlacement struct {
	Constraints []string               `json:"constraints,omitempty"`
	Preferences []ComposePlacementPref `json:"preferences,omitempty"`
	MaxReplicas int64                  `json:"max_replicas_per_node,omitempty"`
}

// ComposePlacementPref represents placement preferences
type ComposePlacementPref struct {
	Spread string `json:"spread,omitempty"`
}

// ComposeLogging represents logging configuration
type ComposeLogging struct {
	Driver  string            `json:"driver,omitempty"`
	Options map[string]string `json:"options,omitempty"`
}

// ComposeNetwork represents a network in docker-compose
type ComposeNetwork struct {
	Driver     string            `json:"driver,omitempty"`
	DriverOpts map[string]string `json:"driver_opts,omitempty"`
	Ipam       *ComposeIPAM      `json:"ipam,omitempty"`
	External   interface{}       `json:"external,omitempty"`
	Internal   bool              `json:"internal,omitempty"`
	Attachable bool              `json:"attachable,omitempty"`
	Labels     interface{}       `json:"labels,omitempty"`
	Name       string            `json:"name,omitempty"`
}

// ComposeIPAM represents IPAM configuration
type ComposeIPAM struct {
	Driver string              `json:"driver,omitempty"`
	Config []ComposeIPAMConfig `json:"config,omitempty"`
}

// ComposeIPAMConfig represents IPAM pool configuration
type ComposeIPAMConfig struct {
	Subnet  string `json:"subnet,omitempty"`
	Gateway string `json:"gateway,omitempty"`
}

// ComposeVolume represents a volume in docker-compose
type ComposeVolume struct {
	Driver     string            `json:"driver,omitempty"`
	DriverOpts map[string]string `json:"driver_opts,omitempty"`
	External   interface{}       `json:"external,omitempty"`
	Labels     interface{}       `json:"labels,omitempty"`
	Name       string            `json:"name,omitempty"`
}

// ComposeSecret represents a secret in docker-compose
type ComposeSecret struct {
	File     string `json:"file,omitempty"`
	External interface{} `json:"external,omitempty"`
	Name     string `json:"name,omitempty"`
}

// ComposeConfig_ represents a config in docker-compose
type ComposeConfig_ struct {
	File     string      `json:"file,omitempty"`
	External interface{} `json:"external,omitempty"`
	Name     string      `json:"name,omitempty"`
}

// StackDeployHistory represents a deployment history record.
type StackDeployHistory struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	StackID      uuid.UUID  `json:"stack_id" db:"stack_id"`
	Status       string     `json:"status" db:"status"`
	Output       string     `json:"output" db:"output"`
	ErrorMessage string     `json:"error_message" db:"error_message"`
	StartedAt    time.Time  `json:"started_at" db:"started_at"`
	FinishedAt   *time.Time `json:"finished_at,omitempty" db:"finished_at"`
	TriggeredBy  string     `json:"triggered_by" db:"triggered_by"`
}

// StackVersion represents a historical version of a stack's compose file.
type StackVersion struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	StackID      uuid.UUID  `json:"stack_id" db:"stack_id"`
	Version      int        `json:"version" db:"version"`
	ComposeFile  string     `json:"compose_file" db:"compose_file"`
	EnvFile      *string    `json:"env_file,omitempty" db:"env_file"`
	Comment      string     `json:"comment" db:"comment"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	DeployedAt   *time.Time `json:"deployed_at,omitempty" db:"deployed_at"`
	IsDeployed   bool       `json:"is_deployed" db:"is_deployed"`
}

// StackVersionDiff represents a diff between two versions.
type StackVersionDiff struct {
	FromVersion   int               `json:"from_version"`
	ToVersion     int               `json:"to_version"`
	ComposeChanges []DiffLine       `json:"compose_changes"`
	EnvChanges     []DiffLine       `json:"env_changes,omitempty"`
	Summary       DiffSummary       `json:"summary"`
}

// DiffLine represents a single line in a diff.
type DiffLine struct {
	Type    DiffLineType `json:"type"` // "add", "remove", "context"
	Content string       `json:"content"`
	OldLine int          `json:"old_line,omitempty"`
	NewLine int          `json:"new_line,omitempty"`
}

// DiffLineType represents the type of diff line.
type DiffLineType string

const (
	DiffLineAdd     DiffLineType = "add"
	DiffLineRemove  DiffLineType = "remove"
	DiffLineContext DiffLineType = "context"
)

// DiffSummary summarizes changes in a diff.
type DiffSummary struct {
	LinesAdded    int      `json:"lines_added"`
	LinesRemoved  int      `json:"lines_removed"`
	ServicesAdded []string `json:"services_added,omitempty"`
	ServicesRemoved []string `json:"services_removed,omitempty"`
	ServicesModified []string `json:"services_modified,omitempty"`
}

// StackEnvironment represents environment variables for a stack with inheritance support.
type StackEnvironment struct {
	ID          uuid.UUID         `json:"id" db:"id"`
	StackID     uuid.UUID         `json:"stack_id" db:"stack_id"`
	Name        string            `json:"name" db:"name"` // e.g., "development", "production"
	Variables   map[string]string `json:"variables" db:"variables"`
	ParentID    *uuid.UUID        `json:"parent_id,omitempty" db:"parent_id"` // For inheritance
	IsDefault   bool              `json:"is_default" db:"is_default"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
}

// ResolvedEnvironment returns variables with inheritance applied.
func (e *StackEnvironment) ResolvedEnvironment(parent *StackEnvironment) map[string]string {
	result := make(map[string]string)
	if parent != nil {
		for k, v := range parent.Variables {
			result[k] = v
		}
	}
	for k, v := range e.Variables {
		result[k] = v
	}
	return result
}

// StackDependency represents a dependency between stacks.
type StackDependency struct {
	ID             uuid.UUID `json:"id" db:"id"`
	StackID        uuid.UUID `json:"stack_id" db:"stack_id"`
	DependsOnID    uuid.UUID `json:"depends_on_id" db:"depends_on_id"`
	DependsOnName  string    `json:"depends_on_name" db:"depends_on_name"` // Denormalized for display
	Condition      string    `json:"condition" db:"condition"` // "started", "healthy", "completed"
	Optional       bool      `json:"optional" db:"optional"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

// StackDependencyCondition represents the condition for a dependency.
type StackDependencyCondition string

const (
	DependencyConditionStarted   StackDependencyCondition = "started"
	DependencyConditionHealthy   StackDependencyCondition = "healthy"
	DependencyConditionCompleted StackDependencyCondition = "completed"
)
