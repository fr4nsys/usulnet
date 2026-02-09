// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// JobStatus represents the status of a job
type JobStatus string

const (
	JobStatusPending   JobStatus = "pending"
	JobStatusQueued    JobStatus = "queued"
	JobStatusRunning   JobStatus = "running"
	JobStatusCompleted JobStatus = "completed"
	JobStatusFailed    JobStatus = "failed"
	JobStatusCancelled JobStatus = "cancelled"
	JobStatusRetrying  JobStatus = "retrying"
)

// JobType represents the type of job
type JobType string

const (
	JobTypeSecurityScan      JobType = "security_scan"
	JobTypeUpdateCheck       JobType = "update_check"
	JobTypeContainerUpdate   JobType = "container_update"
	JobTypeBackupCreate      JobType = "backup_create"
	JobTypeBackupRestore     JobType = "backup_restore"
	JobTypeConfigSync        JobType = "config_sync"
	JobTypeImagePull         JobType = "image_pull"
	JobTypeImagePrune        JobType = "image_prune"
	JobTypeVolumePrune       JobType = "volume_prune"
	JobTypeNetworkPrune      JobType = "network_prune"
	JobTypeStackDeploy       JobType = "stack_deploy"
	JobTypeNPMSync           JobType = "npm_sync"
	JobTypeHostInventory     JobType = "host_inventory"
	JobTypeMetricsCollection JobType = "metrics_collection"
	JobTypeCleanup           JobType = "cleanup"
	JobTypeRetention         JobType = "retention"
)

// JobPriority represents job priority
type JobPriority int

const (
	JobPriorityLow      JobPriority = 1
	JobPriorityNormal   JobPriority = 5
	JobPriorityHigh     JobPriority = 10
	JobPriorityCritical JobPriority = 20
)

// Job represents a background job
type Job struct {
	ID            uuid.UUID       `json:"id" db:"id"`
	Type          JobType         `json:"type" db:"type"`
	Status        JobStatus       `json:"status" db:"status"`
	Priority      JobPriority     `json:"priority" db:"priority"`
	HostID        *uuid.UUID      `json:"host_id,omitempty" db:"host_id"`
	TargetID      *string         `json:"target_id,omitempty" db:"target_id"`
	TargetName    *string         `json:"target_name,omitempty" db:"target_name"`
	Payload       json.RawMessage `json:"payload,omitempty" db:"payload"`
	Result        json.RawMessage `json:"result,omitempty" db:"result"`
	ErrorMessage  *string         `json:"error_message,omitempty" db:"error_message"`
	Progress      int             `json:"progress" db:"progress"` // 0-100
	ProgressMessage *string       `json:"progress_message,omitempty" db:"progress_message"`
	Attempts      int             `json:"attempts" db:"attempts"`
	MaxAttempts   int             `json:"max_attempts" db:"max_attempts"`
	ScheduledAt   *time.Time      `json:"scheduled_at,omitempty" db:"scheduled_at"`
	StartedAt     *time.Time      `json:"started_at,omitempty" db:"started_at"`
	CompletedAt   *time.Time      `json:"completed_at,omitempty" db:"completed_at"`
	CreatedBy     *uuid.UUID      `json:"created_by,omitempty" db:"created_by"`
	CreatedAt     time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at" db:"updated_at"`
}

// IsFinished returns true if job is in a terminal state
func (j *Job) IsFinished() bool {
	return j.Status == JobStatusCompleted || j.Status == JobStatusFailed || j.Status == JobStatusCancelled
}

// CanRetry returns true if job can be retried
func (j *Job) CanRetry() bool {
	return j.Status == JobStatusFailed && j.Attempts < j.MaxAttempts
}

// Duration returns the job duration
func (j *Job) Duration() time.Duration {
	if j.StartedAt == nil {
		return 0
	}
	endTime := j.CompletedAt
	if endTime == nil {
		now := time.Now()
		endTime = &now
	}
	return endTime.Sub(*j.StartedAt)
}

// GetPayload unmarshals the payload into the provided struct
func (j *Job) GetPayload(v interface{}) error {
	if j.Payload == nil {
		return nil
	}
	return json.Unmarshal(j.Payload, v)
}

// SetPayload marshals the provided struct into the payload
func (j *Job) SetPayload(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	j.Payload = data
	return nil
}

// GetResult unmarshals the result into the provided struct
func (j *Job) GetResult(v interface{}) error {
	if j.Result == nil {
		return nil
	}
	return json.Unmarshal(j.Result, v)
}

// SetResult marshals the provided struct into the result
func (j *Job) SetResult(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	j.Result = data
	return nil
}

// CreateJobInput represents input for creating a job
type CreateJobInput struct {
	Type        JobType     `json:"type" validate:"required"`
	HostID      *uuid.UUID  `json:"host_id,omitempty"`
	TargetID    *string     `json:"target_id,omitempty"`
	TargetName  *string     `json:"target_name,omitempty"`
	Payload     interface{} `json:"payload,omitempty"`
	Priority    JobPriority `json:"priority,omitempty"`
	MaxAttempts int         `json:"max_attempts,omitempty"`
	ScheduledAt *time.Time  `json:"scheduled_at,omitempty"`
}

// JobListOptions represents options for listing jobs
type JobListOptions struct {
	Type     *JobType   `json:"type,omitempty"`
	Status   *JobStatus `json:"status,omitempty"`
	HostID   *uuid.UUID `json:"host_id,omitempty"`
	TargetID *string    `json:"target_id,omitempty"`
	Before   *time.Time `json:"before,omitempty"`
	After    *time.Time `json:"after,omitempty"`
	Limit    int        `json:"limit,omitempty"`
	Offset   int        `json:"offset,omitempty"`
}

// ScheduledJob represents a scheduled/recurring job
type ScheduledJob struct {
	ID          uuid.UUID   `json:"id" db:"id"`
	Name        string      `json:"name" db:"name"`
	Type        JobType     `json:"type" db:"type"`
	Schedule    string      `json:"schedule" db:"schedule"` // Cron expression
	HostID      *uuid.UUID  `json:"host_id,omitempty" db:"host_id"`
	TargetID    *string     `json:"target_id,omitempty" db:"target_id"`
	TargetName  *string     `json:"target_name,omitempty" db:"target_name"`
	Payload     json.RawMessage `json:"payload,omitempty" db:"payload"`
	Priority    JobPriority `json:"priority" db:"priority"`
	MaxAttempts int         `json:"max_attempts" db:"max_attempts"`
	IsEnabled   bool        `json:"is_enabled" db:"is_enabled"`
	LastRunAt   *time.Time  `json:"last_run_at,omitempty" db:"last_run_at"`
	LastRunStatus *JobStatus `json:"last_run_status,omitempty" db:"last_run_status"`
	NextRunAt   *time.Time  `json:"next_run_at,omitempty" db:"next_run_at"`
	RunCount    int64       `json:"run_count" db:"run_count"`
	FailCount   int64       `json:"fail_count" db:"fail_count"`
	CreatedBy   *uuid.UUID  `json:"created_by,omitempty" db:"created_by"`
	CreatedAt   time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at" db:"updated_at"`
}

// CreateScheduledJobInput represents input for creating a scheduled job
type CreateScheduledJobInput struct {
	Name        string      `json:"name" validate:"required,min=1,max=100"`
	Type        JobType     `json:"type" validate:"required"`
	Schedule    string      `json:"schedule" validate:"required,cron"`
	HostID      *uuid.UUID  `json:"host_id,omitempty"`
	TargetID    *string     `json:"target_id,omitempty"`
	TargetName  *string     `json:"target_name,omitempty"`
	Payload     interface{} `json:"payload,omitempty"`
	Priority    JobPriority `json:"priority,omitempty"`
	MaxAttempts int         `json:"max_attempts,omitempty"`
	IsEnabled   bool        `json:"is_enabled,omitempty"`
}

// UpdateScheduledJobInput represents input for updating a scheduled job
type UpdateScheduledJobInput struct {
	Name        *string      `json:"name,omitempty" validate:"omitempty,min=1,max=100"`
	Schedule    *string      `json:"schedule,omitempty" validate:"omitempty,cron"`
	Payload     interface{}  `json:"payload,omitempty"`
	Priority    *JobPriority `json:"priority,omitempty"`
	MaxAttempts *int         `json:"max_attempts,omitempty"`
	IsEnabled   *bool        `json:"is_enabled,omitempty"`
}

// JobProgress represents job progress update
type JobProgress struct {
	JobID   uuid.UUID `json:"job_id"`
	Progress int      `json:"progress"` // 0-100
	Message string   `json:"message,omitempty"`
}

// JobEvent represents a job event for real-time updates
type JobEvent struct {
	JobID     uuid.UUID   `json:"job_id"`
	Type      string      `json:"type"` // created, started, progress, completed, failed, cancelled
	Status    JobStatus   `json:"status"`
	Progress  int         `json:"progress,omitempty"`
	Message   string      `json:"message,omitempty"`
	Error     string      `json:"error,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// JobStats represents job statistics
type JobStats struct {
	TotalJobs     int64          `json:"total_jobs"`
	PendingJobs   int64          `json:"pending_jobs"`
	RunningJobs   int64          `json:"running_jobs"`
	CompletedJobs int64          `json:"completed_jobs"`
	FailedJobs    int64          `json:"failed_jobs"`
	ByType        map[string]int64 `json:"by_type"`
	AvgDuration   time.Duration  `json:"avg_duration"`
	SuccessRate   float64        `json:"success_rate"`
}

// Payloads for specific job types

// SecurityScanPayload represents payload for security scan job
type SecurityScanPayload struct {
	ContainerID string `json:"container_id,omitempty"`
	IncludeCVE  bool   `json:"include_cve"`
	ScanAll     bool   `json:"scan_all"`
}

// UpdateCheckPayload represents payload for update check job
type UpdateCheckPayload struct {
	ContainerID string `json:"container_id,omitempty"`
	CheckAll    bool   `json:"check_all"`
}

// ContainerUpdatePayload represents payload for container update job
type ContainerUpdatePayload struct {
	ContainerID   string `json:"container_id"`
	TargetVersion string `json:"target_version,omitempty"`
	CreateBackup  bool   `json:"create_backup"`
	AutoRollback  bool   `json:"auto_rollback"`
}

// BackupPayload represents payload for backup job
type BackupPayload struct {
	Type          string `json:"type"` // volume, container, stack
	TargetID      string `json:"target_id"`
	Compression   string `json:"compression"`
	Encrypted     bool   `json:"encrypted"`
	RetentionDays int    `json:"retention_days,omitempty"`
}

// ImagePullPayload represents payload for image pull job
type ImagePullPayload struct {
	Image        string `json:"image"`
	Tag          string `json:"tag,omitempty"`
	Platform     string `json:"platform,omitempty"`
	RegistryAuth string `json:"registry_auth,omitempty"`
}

// StackDeployPayload represents payload for stack deploy job
type StackDeployPayload struct {
	StackID       uuid.UUID         `json:"stack_id"`
	ComposeFile   string            `json:"compose_file,omitempty"`
	Variables     map[string]string `json:"variables,omitempty"`
	Prune         bool              `json:"prune"`
	ForceRecreate bool              `json:"force_recreate"`
}
