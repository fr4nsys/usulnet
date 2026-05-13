// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// UpdateStatus represents the status of an update operation
type UpdateStatus string

const (
	UpdateStatusPending      UpdateStatus = "pending"
	UpdateStatusChecking     UpdateStatus = "checking"
	UpdateStatusAvailable    UpdateStatus = "available"
	UpdateStatusPulling      UpdateStatus = "pulling"
	UpdateStatusBackingUp    UpdateStatus = "backing_up"
	UpdateStatusUpdating     UpdateStatus = "updating"
	UpdateStatusHealthCheck  UpdateStatus = "health_check"
	UpdateStatusCompleted    UpdateStatus = "completed"
	UpdateStatusFailed       UpdateStatus = "failed"
	UpdateStatusRolledBack   UpdateStatus = "rolled_back"
	UpdateStatusSkipped      UpdateStatus = "skipped"
)

// IsTerminal returns true if the status is a terminal state
func (s UpdateStatus) IsTerminal() bool {
	return s == UpdateStatusCompleted ||
		s == UpdateStatusFailed ||
		s == UpdateStatusRolledBack ||
		s == UpdateStatusSkipped
}

// IsSuccess returns true if the update completed successfully
func (s UpdateStatus) IsSuccess() bool {
	return s == UpdateStatusCompleted
}

// UpdateTrigger represents what triggered the update
type UpdateTrigger string

const (
	UpdateTriggerManual    UpdateTrigger = "manual"
	UpdateTriggerScheduled UpdateTrigger = "scheduled"
	UpdateTriggerWebhook   UpdateTrigger = "webhook"
	UpdateTriggerWatchtower UpdateTrigger = "watchtower"
	UpdateTriggerAutomatic UpdateTrigger = "automatic"
)

// UpdateType represents the type of update target
type UpdateType string

const (
	UpdateTypeContainer UpdateType = "container"
	UpdateTypeStack     UpdateType = "stack"
	UpdateTypeService   UpdateType = "service" // Swarm service
)

// Update represents an update operation record
type Update struct {
	ID              uuid.UUID     `json:"id" db:"id"`
	HostID          uuid.UUID     `json:"host_id" db:"host_id"`
	Type            UpdateType    `json:"type" db:"type"`
	TargetID        string        `json:"target_id" db:"target_id"` // Container ID or Stack ID
	TargetName      string        `json:"target_name" db:"target_name"`
	Image           string        `json:"image" db:"image"`
	FromVersion     string        `json:"from_version" db:"from_version"`
	ToVersion       string        `json:"to_version" db:"to_version"`
	FromDigest      *string       `json:"from_digest,omitempty" db:"from_digest"`
	ToDigest        *string       `json:"to_digest,omitempty" db:"to_digest"`
	Status          UpdateStatus  `json:"status" db:"status"`
	Trigger         UpdateTrigger `json:"trigger" db:"trigger"`
	BackupID        *uuid.UUID    `json:"backup_id,omitempty" db:"backup_id"`
	ChangelogURL    *string       `json:"changelog_url,omitempty" db:"changelog_url"`
	ChangelogBody   *string       `json:"changelog_body,omitempty" db:"changelog_body"`
	SecurityScoreBefore *int      `json:"security_score_before,omitempty" db:"security_score_before"`
	SecurityScoreAfter  *int      `json:"security_score_after,omitempty" db:"security_score_after"`
	HealthCheckPassed   *bool     `json:"health_check_passed,omitempty" db:"health_check_passed"`
	RollbackReason      *string   `json:"rollback_reason,omitempty" db:"rollback_reason"`
	ErrorMessage        *string   `json:"error_message,omitempty" db:"error_message"`
	DurationMs          *int64    `json:"duration_ms,omitempty" db:"duration_ms"`
	CreatedBy           *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	StartedAt           *time.Time `json:"started_at,omitempty" db:"started_at"`
	CompletedAt         *time.Time `json:"completed_at,omitempty" db:"completed_at"`
	CreatedAt           time.Time  `json:"created_at" db:"created_at"`
}

// Duration returns the update duration
func (u *Update) Duration() time.Duration {
	if u.DurationMs == nil {
		return 0
	}
	return time.Duration(*u.DurationMs) * time.Millisecond
}

// SecurityScoreDelta returns the security score change
func (u *Update) SecurityScoreDelta() int {
	if u.SecurityScoreBefore == nil || u.SecurityScoreAfter == nil {
		return 0
	}
	return *u.SecurityScoreAfter - *u.SecurityScoreBefore
}

// CanRollback returns true if the update can be rolled back
func (u *Update) CanRollback() bool {
	if u.Status != UpdateStatusCompleted {
		return false
	}
	if u.BackupID == nil {
		return false
	}
	// Allow rollback within 24 hours
	return time.Since(u.CreatedAt) < 24*time.Hour
}

// AvailableUpdate represents an available update for a container
type AvailableUpdate struct {
	ContainerID    string    `json:"container_id"`
	ContainerName  string    `json:"container_name"`
	Image          string    `json:"image"`
	CurrentVersion string    `json:"current_version"`
	CurrentDigest  string    `json:"current_digest,omitempty"`
	LatestVersion  string    `json:"latest_version"`
	LatestDigest   string    `json:"latest_digest,omitempty"`
	IsPrerelease   bool      `json:"is_prerelease"`
	HasChangelog   bool      `json:"has_changelog"`
	Changelog      *Changelog `json:"changelog,omitempty"`
	CheckedAt      time.Time `json:"checked_at"`
}

// NeedsUpdate returns true if an update is available
func (a *AvailableUpdate) NeedsUpdate() bool {
	// Compare by digest if both are available (most accurate)
	if a.CurrentDigest != "" && a.LatestDigest != "" {
		return a.CurrentDigest != a.LatestDigest
	}
	// If current tag is "latest" and we lack digest info for comparison,
	// we cannot reliably determine update status — assume up-to-date.
	if a.CurrentVersion == "latest" && a.LatestVersion == "latest" {
		return false
	}
	// Otherwise compare versions
	return a.CurrentVersion != a.LatestVersion
}

// Changelog represents release changelog information
type Changelog struct {
	Version      string    `json:"version"`
	Title        string    `json:"title,omitempty"`
	Body         string    `json:"body"`
	URL          string    `json:"url,omitempty"`
	PublishedAt  *time.Time `json:"published_at,omitempty"`
	IsPrerelease bool      `json:"is_prerelease"`
	IsDraft      bool      `json:"is_draft"`
	Author       string    `json:"author,omitempty"`
}

// ImageVersion represents version information for a Docker image
type ImageVersion struct {
	Tag        string    `json:"tag"`
	Digest     string    `json:"digest"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
	CheckedAt  time.Time `json:"checked_at"`
	Size       int64     `json:"size,omitempty"`
	OS         string    `json:"os,omitempty"`
	Arch       string    `json:"arch,omitempty"`
}

// ImageRef represents a parsed Docker image reference
type ImageRef struct {
	Registry   string `json:"registry"`   // docker.io, ghcr.io, etc.
	Namespace  string `json:"namespace"`  // library, portainer, etc.
	Repository string `json:"repository"` // nginx, portainer-ce
	Tag        string `json:"tag"`        // latest, v2.0.0, alpine
	Digest     string `json:"digest,omitempty"`
}

// FullName returns the full image name
func (r *ImageRef) FullName() string {
	name := r.Repository
	if r.Namespace != "" && r.Namespace != "library" {
		name = r.Namespace + "/" + name
	}
	if r.Registry != "" && r.Registry != "docker.io" {
		name = r.Registry + "/" + name
	}
	return name
}

// FullNameWithTag returns the full image name with tag
func (r *ImageRef) FullNameWithTag() string {
	name := r.FullName()
	if r.Tag != "" {
		return name + ":" + r.Tag
	}
	if r.Digest != "" {
		return name + "@" + r.Digest
	}
	return name + ":latest"
}

// IsDockerHub returns true if the image is from Docker Hub
func (r *ImageRef) IsDockerHub() bool {
	return r.Registry == "" || r.Registry == "docker.io" || r.Registry == "index.docker.io"
}

// IsGHCR returns true if the image is from GitHub Container Registry
func (r *ImageRef) IsGHCR() bool {
	return r.Registry == "ghcr.io"
}

// UpdatePolicy represents update policy settings for a container/stack
type UpdatePolicy struct {
	ID              uuid.UUID `json:"id" db:"id"`
	HostID          uuid.UUID `json:"host_id" db:"host_id"`
	TargetType      UpdateType `json:"target_type" db:"target_type"`
	TargetID        string    `json:"target_id" db:"target_id"`
	TargetName      string    `json:"target_name" db:"target_name"`
	IsEnabled       bool      `json:"is_enabled" db:"is_enabled"`
	AutoUpdate      bool      `json:"auto_update" db:"auto_update"`
	AutoBackup      bool      `json:"auto_backup" db:"auto_backup"`
	IncludePrerelease bool    `json:"include_prerelease" db:"include_prerelease"`
	Schedule        *string   `json:"schedule,omitempty" db:"schedule"` // Cron expression
	NotifyOnUpdate  bool      `json:"notify_on_update" db:"notify_on_update"`
	NotifyOnFailure bool      `json:"notify_on_failure" db:"notify_on_failure"`
	MaxRetries      int       `json:"max_retries" db:"max_retries"`
	HealthCheckWait int       `json:"health_check_wait" db:"health_check_wait"` // Seconds
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time `json:"updated_at" db:"updated_at"`
}

// DefaultUpdatePolicy returns a default update policy
func DefaultUpdatePolicy() UpdatePolicy {
	return UpdatePolicy{
		IsEnabled:       true,
		AutoUpdate:      false,
		AutoBackup:      true,
		IncludePrerelease: false,
		NotifyOnUpdate:  true,
		NotifyOnFailure: true,
		MaxRetries:      3,
		HealthCheckWait: 30,
	}
}

// UpdateCheckResult represents the result of checking for updates
type UpdateCheckResult struct {
	HostID           uuid.UUID         `json:"host_id"`
	CheckedAt        time.Time         `json:"checked_at"`
	TotalContainers  int               `json:"total_containers"`
	CheckedCount     int               `json:"checked_count"`
	UpdatesAvailable int               `json:"updates_available"`
	Errors           int               `json:"errors"`
	Updates          []AvailableUpdate `json:"updates,omitempty"`
	SkippedImages    []string          `json:"skipped_images,omitempty"`
}

// UpdateOptions represents options for performing an update
type UpdateOptions struct {
	ContainerID     string        `json:"container_id" validate:"required"`
	TargetVersion   string        `json:"target_version,omitempty"` // Empty = latest
	ForcePull       bool          `json:"force_pull,omitempty"`
	BackupVolumes   bool          `json:"backup_volumes"`
	SecurityScan    bool          `json:"security_scan"`
	HealthCheckWait time.Duration `json:"health_check_wait,omitempty"`
	MaxRetries      int           `json:"max_retries,omitempty"`
	DryRun          bool          `json:"dry_run,omitempty"`
	CreatedBy       *uuid.UUID    `json:"created_by,omitempty"`
}

// DefaultUpdateOptions returns default update options
func DefaultUpdateOptions() UpdateOptions {
	return UpdateOptions{
		BackupVolumes:   true,
		SecurityScan:    true,
		HealthCheckWait: 30 * time.Second,
		MaxRetries:      3,
	}
}

// UpdateResult represents the result of an update operation
type UpdateResult struct {
	Update          *Update       `json:"update"`
	Success         bool          `json:"success"`
	FromVersion     string        `json:"from_version"`
	ToVersion       string        `json:"to_version"`
	BackupID        *uuid.UUID    `json:"backup_id,omitempty"`
	NewContainerID  string        `json:"new_container_id,omitempty"`
	Duration        time.Duration `json:"duration"`
	HealthPassed    bool          `json:"health_passed"`
	SecurityDelta   int           `json:"security_delta"`
	WasRolledBack   bool          `json:"was_rolled_back"`
	RollbackReason  string        `json:"rollback_reason,omitempty"`
        DryRun          bool          `json:"dry_run,omitempty"`
	ErrorMessage    string        `json:"error_message,omitempty"`
}

// RollbackOptions represents options for rolling back an update
type RollbackOptions struct {
	UpdateID      uuid.UUID `json:"update_id" validate:"required"`
	RestoreBackup bool      `json:"restore_backup"`
	Reason        string    `json:"reason,omitempty"`
}

// RollbackResult represents the result of a rollback operation
type RollbackResult struct {
	Success          bool          `json:"success"`
	UpdateID         uuid.UUID     `json:"update_id"`
	RestoredVersion  string        `json:"restored_version"`
	RestoredBackupID *uuid.UUID    `json:"restored_backup_id,omitempty"`
	Duration         time.Duration `json:"duration"`
	ErrorMessage     string        `json:"error_message,omitempty"`
}

// BatchUpdateInput represents input for batch updating multiple containers
type BatchUpdateInput struct {
	ContainerIDs    []string      `json:"container_ids" validate:"required,min=1"`
	BackupVolumes   bool          `json:"backup_volumes"`
	SecurityScan    bool          `json:"security_scan"`
	HealthCheckWait time.Duration `json:"health_check_wait,omitempty"`
	StopOnFailure   bool          `json:"stop_on_failure"`
}

// BatchUpdateResult represents the result of a batch update
type BatchUpdateResult struct {
	Total      int             `json:"total"`
	Succeeded  int             `json:"succeeded"`
	Failed     int             `json:"failed"`
	Skipped    int             `json:"skipped"`
	Results    []UpdateResult  `json:"results"`
	Duration   time.Duration   `json:"duration"`
}

// UpdateStats represents update statistics
type UpdateStats struct {
	TotalUpdates     int               `json:"total_updates"`
	SuccessfulCount  int               `json:"successful_count"`
	FailedCount      int               `json:"failed_count"`
	RolledBackCount  int               `json:"rolled_back_count"`
	AvgDurationMs    int64             `json:"avg_duration_ms"`
	ByStatus         map[string]int    `json:"by_status"`
	ByTrigger        map[string]int    `json:"by_trigger"`
	LastUpdateAt     *time.Time        `json:"last_update_at,omitempty"`
	MostUpdated      []ContainerUpdateCount `json:"most_updated,omitempty"`
}

// ContainerUpdateCount represents update count for a container
type ContainerUpdateCount struct {
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	Count         int    `json:"count"`
}

// UpdateListOptions represents options for listing updates
type UpdateListOptions struct {
	HostID    *uuid.UUID    `json:"host_id,omitempty"`
	TargetID  *string       `json:"target_id,omitempty"`
	Status    *UpdateStatus `json:"status,omitempty"`
	Trigger   *UpdateTrigger `json:"trigger,omitempty"`
	Before    *time.Time    `json:"before,omitempty"`
	After     *time.Time    `json:"after,omitempty"`
	Limit     int           `json:"limit,omitempty"`
	Offset    int           `json:"offset,omitempty"`
}

// CreateUpdatePolicyInput represents input for creating an update policy
type CreateUpdatePolicyInput struct {
	TargetType        UpdateType `json:"target_type" validate:"required,oneof=container stack service"`
	TargetID          string     `json:"target_id" validate:"required"`
	AutoUpdate        bool       `json:"auto_update"`
	AutoBackup        bool       `json:"auto_backup"`
	IncludePrerelease bool       `json:"include_prerelease"`
	Schedule          *string    `json:"schedule,omitempty" validate:"omitempty,cron"`
	NotifyOnUpdate    bool       `json:"notify_on_update"`
	NotifyOnFailure   bool       `json:"notify_on_failure"`
	MaxRetries        int        `json:"max_retries,omitempty" validate:"omitempty,min=0,max=10"`
	HealthCheckWait   int        `json:"health_check_wait,omitempty" validate:"omitempty,min=5,max=600"`
}

// UpdatePolicyInput represents input for updating an update policy
type UpdatePolicyInput struct {
	IsEnabled         *bool   `json:"is_enabled,omitempty"`
	AutoUpdate        *bool   `json:"auto_update,omitempty"`
	AutoBackup        *bool   `json:"auto_backup,omitempty"`
	IncludePrerelease *bool   `json:"include_prerelease,omitempty"`
	Schedule          *string `json:"schedule,omitempty" validate:"omitempty,cron"`
	NotifyOnUpdate    *bool   `json:"notify_on_update,omitempty"`
	NotifyOnFailure   *bool   `json:"notify_on_failure,omitempty"`
	MaxRetries        *int    `json:"max_retries,omitempty" validate:"omitempty,min=0,max=10"`
	HealthCheckWait   *int    `json:"health_check_wait,omitempty" validate:"omitempty,min=5,max=600"`
}

// UpdateWebhook represents a webhook configuration for updates
type UpdateWebhook struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	HostID      uuid.UUID  `json:"host_id" db:"host_id"`
	TargetType  UpdateType `json:"target_type" db:"target_type"`
	TargetID    string     `json:"target_id" db:"target_id"`
	Token       string     `json:"token" db:"token"` // Webhook token
	IsEnabled   bool       `json:"is_enabled" db:"is_enabled"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
}

// WebhookURL returns the webhook URL
func (w *UpdateWebhook) WebhookURL(baseURL string) string {
	return baseURL + "/api/webhooks/update/" + w.Token
}
