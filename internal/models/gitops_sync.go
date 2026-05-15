// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// Bidirectional Git Sync
// ============================================================================

// SyncDirection indicates the direction of git sync.
type SyncDirection string

const (
	SyncDirectionToGit         SyncDirection = "to_git"
	SyncDirectionFromGit       SyncDirection = "from_git"
	SyncDirectionBidirectional SyncDirection = "bidirectional"
)

// ConflictStrategy determines how sync conflicts are resolved.
type ConflictStrategy string

const (
	ConflictStrategyManual    ConflictStrategy = "manual"
	ConflictStrategyPreferGit ConflictStrategy = "prefer_git"
	ConflictStrategyPreferUI  ConflictStrategy = "prefer_ui"
)

// ConflictResolution is the outcome for a sync conflict.
type ConflictResolution string

const (
	ConflictResolutionPending   ConflictResolution = "pending"
	ConflictResolutionUseGit    ConflictResolution = "use_git"
	ConflictResolutionUseUI     ConflictResolution = "use_ui"
	ConflictResolutionMerged    ConflictResolution = "merged"
	ConflictResolutionDismissed ConflictResolution = "dismissed"
)

// GitSyncConfig represents a bidirectional sync configuration between usulnet UI and a Git repository.
type GitSyncConfig struct {
	ID                    uuid.UUID        `db:"id" json:"id"`
	ConnectionID          uuid.UUID        `db:"connection_id" json:"connection_id"`
	RepositoryID          uuid.UUID        `db:"repository_id" json:"repository_id"`
	Name                  string           `db:"name" json:"name"`
	RepoFullName          string           `db:"repo_full_name" json:"repo_full_name"`
	SyncDirection         SyncDirection    `db:"sync_direction" json:"sync_direction"`
	TargetPath            string           `db:"target_path" json:"target_path"`
	StackName             string           `db:"stack_name" json:"stack_name"`
	FilePattern           string           `db:"file_pattern" json:"file_pattern"`
	Branch                string           `db:"branch" json:"branch"`
	AutoCommit            bool             `db:"auto_commit" json:"auto_commit"`
	AutoDeploy            bool             `db:"auto_deploy" json:"auto_deploy"`
	CommitMessageTemplate string           `db:"commit_message_template" json:"commit_message_template"`
	ConflictStrategy      ConflictStrategy `db:"conflict_strategy" json:"conflict_strategy"`
	IsEnabled             bool             `db:"is_enabled" json:"is_enabled"`
	LastSyncAt            *time.Time       `db:"last_sync_at" json:"last_sync_at,omitempty"`
	LastSyncStatus        string           `db:"last_sync_status" json:"last_sync_status"`
	LastSyncError         string           `db:"last_sync_error" json:"last_sync_error"`
	SyncCount             int              `db:"sync_count" json:"sync_count"`
	CreatedBy             *uuid.UUID       `db:"created_by" json:"created_by,omitempty"`
	CreatedAt             time.Time        `db:"created_at" json:"created_at"`
	UpdatedAt             time.Time        `db:"updated_at" json:"updated_at"`
}

// GitSyncEvent represents a single sync operation event.
type GitSyncEvent struct {
	ID            uuid.UUID       `db:"id" json:"id"`
	ConfigID      uuid.UUID       `db:"config_id" json:"config_id"`
	Direction     SyncDirection   `db:"direction" json:"direction"`
	EventType     string          `db:"event_type" json:"event_type"` // commit_pushed, file_updated, conflict_detected, deploy_triggered
	Status        string          `db:"status" json:"status"`         // pending, success, failed, conflict
	CommitSHA     string          `db:"commit_sha" json:"commit_sha"`
	CommitMessage string          `db:"commit_message" json:"commit_message"`
	FilesChanged  json.RawMessage `db:"files_changed" json:"files_changed"`
	DiffSummary   string          `db:"diff_summary" json:"diff_summary"`
	ErrorMessage  string          `db:"error_message" json:"error_message"`
	Metadata      json.RawMessage `db:"metadata" json:"metadata"`
	CreatedAt     time.Time       `db:"created_at" json:"created_at"`
}

// Sync event types
const (
	SyncEventCommitPushed     = "commit_pushed"
	SyncEventFileUpdated      = "file_updated"
	SyncEventConflictDetected = "conflict_detected"
	SyncEventDeployTriggered  = "deploy_triggered"
	SyncEventSyncFailed       = "sync_failed"
)

// GitSyncConflict represents a conflict detected during bidirectional sync.
type GitSyncConflict struct {
	ID            uuid.UUID          `db:"id" json:"id"`
	ConfigID      uuid.UUID          `db:"config_id" json:"config_id"`
	EventID       *uuid.UUID         `db:"event_id" json:"event_id,omitempty"`
	FilePath      string             `db:"file_path" json:"file_path"`
	GitContent    string             `db:"git_content" json:"git_content"`
	UIContent     string             `db:"ui_content" json:"ui_content"`
	BaseContent   string             `db:"base_content" json:"base_content"`
	Resolution    ConflictResolution `db:"resolution" json:"resolution"`
	ResolvedBy    *uuid.UUID         `db:"resolved_by" json:"resolved_by,omitempty"`
	ResolvedAt    *time.Time         `db:"resolved_at" json:"resolved_at,omitempty"`
	MergedContent *string            `db:"merged_content" json:"merged_content,omitempty"`
	CreatedAt     time.Time          `db:"created_at" json:"created_at"`
}

// ============================================================================
// Ephemeral Environments
// ============================================================================

// EphemeralEnvironmentStatus represents the status of an ephemeral environment.
type EphemeralEnvironmentStatus string

const (
	EphemeralStatusPending      EphemeralEnvironmentStatus = "pending"
	EphemeralStatusProvisioning EphemeralEnvironmentStatus = "provisioning"
	EphemeralStatusRunning      EphemeralEnvironmentStatus = "running"
	EphemeralStatusStopping     EphemeralEnvironmentStatus = "stopping"
	EphemeralStatusStopped      EphemeralEnvironmentStatus = "stopped"
	EphemeralStatusFailed       EphemeralEnvironmentStatus = "failed"
	EphemeralStatusExpired      EphemeralEnvironmentStatus = "expired"
)

// EphemeralEnvironment represents a branch-based ephemeral environment.
type EphemeralEnvironment struct {
	ID             uuid.UUID                  `db:"id" json:"id"`
	Name           string                     `db:"name" json:"name"`
	ConnectionID   *uuid.UUID                 `db:"connection_id" json:"connection_id,omitempty"`
	RepositoryID   *uuid.UUID                 `db:"repository_id" json:"repository_id,omitempty"`
	Branch         string                     `db:"branch" json:"branch"`
	RepoFullName   string                     `db:"repo_full_name" json:"repo_full_name"`
	CommitSHA      string                     `db:"commit_sha" json:"commit_sha"`
	StackName      string                     `db:"stack_name" json:"stack_name"`
	ComposeFile    string                     `db:"compose_file" json:"compose_file"`
	Environment    json.RawMessage            `db:"environment" json:"environment"`
	PortMappings   json.RawMessage            `db:"port_mappings" json:"port_mappings"`
	Status         EphemeralEnvironmentStatus `db:"status" json:"status"`
	URL            string                     `db:"url" json:"url"`
	TTLMinutes     int                        `db:"ttl_minutes" json:"ttl_minutes"`
	AutoDestroy    bool                       `db:"auto_destroy" json:"auto_destroy"`
	ExpiresAt      *time.Time                 `db:"expires_at" json:"expires_at,omitempty"`
	StartedAt      *time.Time                 `db:"started_at" json:"started_at,omitempty"`
	StoppedAt      *time.Time                 `db:"stopped_at" json:"stopped_at,omitempty"`
	ErrorMessage   string                     `db:"error_message" json:"error_message"`
	ResourceLimits json.RawMessage            `db:"resource_limits" json:"resource_limits"`
	Labels         json.RawMessage            `db:"labels" json:"labels"`
	CreatedBy      *uuid.UUID                 `db:"created_by" json:"created_by,omitempty"`
	CreatedAt      time.Time                  `db:"created_at" json:"created_at"`
	UpdatedAt      time.Time                  `db:"updated_at" json:"updated_at"`
}

// EphemeralEnvironmentLog is a log entry from an ephemeral environment lifecycle.
type EphemeralEnvironmentLog struct {
	ID            uuid.UUID       `db:"id" json:"id"`
	EnvironmentID uuid.UUID       `db:"environment_id" json:"environment_id"`
	Phase         string          `db:"phase" json:"phase"` // provision, deploy, healthcheck, destroy
	Message       string          `db:"message" json:"message"`
	Level         string          `db:"level" json:"level"` // info, warn, error
	Metadata      json.RawMessage `db:"metadata" json:"metadata"`
	CreatedAt     time.Time       `db:"created_at" json:"created_at"`
}

// EphemeralEnvListOptions holds filters for listing ephemeral environments.
type EphemeralEnvListOptions struct {
	Status       string `json:"status,omitempty"`
	Branch       string `json:"branch,omitempty"`
	RepositoryID string `json:"repository_id,omitempty"`
	Limit        int    `json:"limit,omitempty"`
	Offset       int    `json:"offset,omitempty"`
}

// ============================================================================
// Manifest Builder
// ============================================================================

// ManifestFormat represents the output format of a manifest.
type ManifestFormat string

const (
	ManifestFormatCompose    ManifestFormat = "compose"
	ManifestFormatKubernetes ManifestFormat = "kubernetes"
	ManifestFormatSwarm      ManifestFormat = "swarm"
)

// ManifestTemplate represents a saved manifest template/blueprint.
type ManifestTemplate struct {
	ID          uuid.UUID       `db:"id" json:"id"`
	Name        string          `db:"name" json:"name"`
	Description string          `db:"description" json:"description"`
	Format      ManifestFormat  `db:"format" json:"format"`
	Category    string          `db:"category" json:"category"`
	Icon        string          `db:"icon" json:"icon"`
	Version     string          `db:"version" json:"version"`
	Content     string          `db:"content" json:"content"`
	Variables   json.RawMessage `db:"variables" json:"variables"`
	IsPublic    bool            `db:"is_public" json:"is_public"`
	IsBuiltin   bool            `db:"is_builtin" json:"is_builtin"`
	UsageCount  int             `db:"usage_count" json:"usage_count"`
	Tags        json.RawMessage `db:"tags" json:"tags"`
	CreatedBy   *uuid.UUID      `db:"created_by" json:"created_by,omitempty"`
	CreatedAt   time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time       `db:"updated_at" json:"updated_at"`
}

// ManifestTemplateVariable represents a template variable definition.
type ManifestTemplateVariable struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"` // string, number, boolean, select
	Default     string   `json:"default"`
	Description string   `json:"description"`
	Required    bool     `json:"required"`
	Options     []string `json:"options,omitempty"` // for select type
}

// ManifestBuilderSession represents an active or saved manifest builder session.
type ManifestBuilderSession struct {
	ID                uuid.UUID       `db:"id" json:"id"`
	Name              string          `db:"name" json:"name"`
	UserID            uuid.UUID       `db:"user_id" json:"user_id"`
	TemplateID        *uuid.UUID      `db:"template_id" json:"template_id,omitempty"`
	Format            ManifestFormat  `db:"format" json:"format"`
	CanvasState       json.RawMessage `db:"canvas_state" json:"canvas_state"`
	Services          json.RawMessage `db:"services" json:"services"`
	Networks          json.RawMessage `db:"networks" json:"networks"`
	Volumes           json.RawMessage `db:"volumes" json:"volumes"`
	GeneratedManifest string          `db:"generated_manifest" json:"generated_manifest"`
	ValidationErrors  json.RawMessage `db:"validation_errors" json:"validation_errors"`
	IsSaved           bool            `db:"is_saved" json:"is_saved"`
	LastGitPushAt     *time.Time      `db:"last_git_push_at" json:"last_git_push_at,omitempty"`
	LastDeployAt      *time.Time      `db:"last_deploy_at" json:"last_deploy_at,omitempty"`
	CreatedAt         time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt         time.Time       `db:"updated_at" json:"updated_at"`
}

// ManifestServiceBlock represents a service definition in the visual builder.
type ManifestServiceBlock struct {
	Name        string              `json:"name"`
	Image       string              `json:"image"`
	Tag         string              `json:"tag"`
	Ports       []GitOpsPortMapping `json:"ports"`
	Volumes     []VolumeMount       `json:"volumes"`
	Environment map[string]string   `json:"environment"`
	Command     string              `json:"command,omitempty"`
	Restart     string              `json:"restart"`
	HealthCheck *HealthCheckDef     `json:"health_check,omitempty"`
	DependsOn   []string            `json:"depends_on,omitempty"`
	Networks    []string            `json:"networks,omitempty"`
	Deploy      *DeployConfig       `json:"deploy,omitempty"`
	Labels      map[string]string   `json:"labels,omitempty"`
	// Canvas positioning
	PositionX int `json:"position_x"`
	PositionY int `json:"position_y"`
}

// GitOpsPortMapping is a container port mapping for GitOps manifests.
type GitOpsPortMapping struct {
	Host      int    `json:"host"`
	Container int    `json:"container"`
	Protocol  string `json:"protocol"` // tcp, udp
}

// VolumeMount is a volume mount definition.
type VolumeMount struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
	Type     string `json:"type"` // volume, bind, tmpfs
}

// HealthCheckDef is a container health check definition.
type HealthCheckDef struct {
	Test        string `json:"test"`
	Interval    string `json:"interval"`
	Timeout     string `json:"timeout"`
	Retries     int    `json:"retries"`
	StartPeriod string `json:"start_period"`
}

// DeployConfig is Swarm/K8s deploy configuration.
type DeployConfig struct {
	Replicas       int    `json:"replicas"`
	CPULimit       string `json:"cpu_limit"`
	MemLimit       string `json:"mem_limit"`
	CPUReservation string `json:"cpu_reservation"`
	MemReservation string `json:"mem_reservation"`
}

// ManifestBuilderComponent represents a reusable service block in the library.
type ManifestBuilderComponent struct {
	ID            uuid.UUID       `db:"id" json:"id"`
	Name          string          `db:"name" json:"name"`
	Description   string          `db:"description" json:"description"`
	Category      string          `db:"category" json:"category"`
	Icon          string          `db:"icon" json:"icon"`
	DefaultConfig json.RawMessage `db:"default_config" json:"default_config"`
	Ports         json.RawMessage `db:"ports" json:"ports"`
	Volumes       json.RawMessage `db:"volumes" json:"volumes"`
	Environment   json.RawMessage `db:"environment" json:"environment"`
	HealthCheck   json.RawMessage `db:"health_check" json:"health_check"`
	DependsOn     json.RawMessage `db:"depends_on" json:"depends_on"`
	IsBuiltin     bool            `db:"is_builtin" json:"is_builtin"`
	CreatedBy     *uuid.UUID      `db:"created_by" json:"created_by,omitempty"`
	CreatedAt     time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time       `db:"updated_at" json:"updated_at"`
}

// ManifestValidationError represents a validation error in a manifest.
type ManifestValidationError struct {
	Service  string `json:"service,omitempty"`
	Field    string `json:"field"`
	Message  string `json:"message"`
	Severity string `json:"severity"` // error, warning, info
}
