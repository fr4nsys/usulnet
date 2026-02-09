// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// VolumeScope represents the scope of a volume
type VolumeScope string

const (
	VolumeScopeLocal  VolumeScope = "local"
	VolumeScopeGlobal VolumeScope = "global"
)

// Volume represents a Docker volume (cached state)
type Volume struct {
	Name       string            `json:"name" db:"name"`
	HostID     uuid.UUID         `json:"host_id" db:"host_id"`
	Driver     string            `json:"driver" db:"driver"`
	Mountpoint string            `json:"mountpoint" db:"mountpoint"`
	Scope      VolumeScope       `json:"scope" db:"scope"`
	Labels     map[string]string `json:"labels,omitempty" db:"labels"`
	Options    map[string]string `json:"options,omitempty" db:"options"`
	Status     map[string]any    `json:"status,omitempty" db:"status"`
	UsageData  *VolumeUsageData  `json:"usage_data,omitempty" db:"usage_data"`
	CreatedAt  time.Time         `json:"created_at" db:"created_at"`
	SyncedAt   time.Time         `json:"synced_at" db:"synced_at"`
}

// VolumeUsageData represents volume usage information
type VolumeUsageData struct {
	Size     int64 `json:"size"`      // Size in bytes used by the volume
	RefCount int64 `json:"ref_count"` // Number of containers using the volume
}

// IsInUse returns true if volume is being used by containers
func (v *Volume) IsInUse() bool {
	if v.UsageData == nil {
		return false
	}
	return v.UsageData.RefCount > 0
}

// IsLocal returns true if volume uses local driver
func (v *Volume) IsLocal() bool {
	return v.Driver == "local"
}

// VolumeInspect represents detailed volume information
type VolumeInspect struct {
	Volume
	ClusterVolume *ClusterVolume `json:"cluster_volume,omitempty"`
}

// ClusterVolume represents cluster volume information (Swarm)
type ClusterVolume struct {
	ID      string              `json:"id"`
	Version ClusterVolumeVersion `json:"version"`
	Spec    ClusterVolumeSpec   `json:"spec"`
	Info    ClusterVolumeInfo   `json:"info,omitempty"`
}

// ClusterVolumeVersion represents cluster volume version
type ClusterVolumeVersion struct {
	Index uint64 `json:"index"`
}

// ClusterVolumeSpec represents cluster volume specification
type ClusterVolumeSpec struct {
	Group                string                 `json:"group,omitempty"`
	AccessMode           *VolumeAccessMode      `json:"access_mode,omitempty"`
	Secrets              []VolumeSecret         `json:"secrets,omitempty"`
	AccessibilityReqs    *TopologyRequirement   `json:"accessibility_requirements,omitempty"`
	CapacityRange        *CapacityRange         `json:"capacity_range,omitempty"`
	Availability         string                 `json:"availability,omitempty"`
}

// VolumeAccessMode represents volume access mode
type VolumeAccessMode struct {
	Scope         string `json:"scope,omitempty"`
	Sharing       string `json:"sharing,omitempty"`
	MountVolume   any    `json:"mount_volume,omitempty"`
	BlockVolume   any    `json:"block_volume,omitempty"`
}

// VolumeSecret represents a volume secret
type VolumeSecret struct {
	Key    string `json:"key"`
	Secret string `json:"secret"`
}

// TopologyRequirement represents topology requirements
type TopologyRequirement struct {
	Requisite []Topology `json:"requisite,omitempty"`
	Preferred []Topology `json:"preferred,omitempty"`
}

// Topology represents a topology
type Topology struct {
	Segments map[string]string `json:"segments,omitempty"`
}

// CapacityRange represents volume capacity range
type CapacityRange struct {
	RequiredBytes int64 `json:"required_bytes,omitempty"`
	LimitBytes    int64 `json:"limit_bytes,omitempty"`
}

// ClusterVolumeInfo represents cluster volume info
type ClusterVolumeInfo struct {
	CapacityBytes           int64             `json:"capacity_bytes,omitempty"`
	VolumeContext           map[string]string `json:"volume_context,omitempty"`
	VolumeID                string            `json:"volume_id,omitempty"`
	AccessibleTopology      []Topology        `json:"accessible_topology,omitempty"`
}

// CreateVolumeInput represents input for creating a volume
type CreateVolumeInput struct {
	Name       string            `json:"name" validate:"required,min=1,max=255"`
	Driver     string            `json:"driver,omitempty"`
	DriverOpts map[string]string `json:"driver_opts,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// VolumeListOptions represents options for listing volumes
type VolumeListOptions struct {
	Filters map[string][]string `json:"filters,omitempty"`
}

// VolumeListResponse represents volume list response
type VolumeListResponse struct {
	Volumes  []Volume `json:"volumes"`
	Warnings []string `json:"warnings,omitempty"`
}

// VolumePruneReport represents volume prune result
type VolumePruneReport struct {
	VolumesDeleted []string `json:"volumes_deleted,omitempty"`
	SpaceReclaimed int64    `json:"space_reclaimed"`
}

// VolumeBackup represents a volume backup
type VolumeBackup struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	VolumeName    string     `json:"volume_name" db:"volume_name"`
	HostID        uuid.UUID  `json:"host_id" db:"host_id"`
	Path          string     `json:"path" db:"path"`
	SizeBytes     int64      `json:"size_bytes" db:"size_bytes"`
	Compression   string     `json:"compression" db:"compression"` // none, gzip, zstd
	Encrypted     bool       `json:"encrypted" db:"encrypted"`
	Trigger       string     `json:"trigger" db:"trigger"` // manual, scheduled, pre_update
	Status        string     `json:"status" db:"status"`   // pending, running, completed, failed
	ErrorMessage  *string    `json:"error_message,omitempty" db:"error_message"`
	StartedAt     *time.Time `json:"started_at,omitempty" db:"started_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty" db:"completed_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
}

// IsCompleted returns true if backup is completed
func (b *VolumeBackup) IsCompleted() bool {
	return b.Status == "completed"
}

// IsFailed returns true if backup failed
func (b *VolumeBackup) IsFailed() bool {
	return b.Status == "failed"
}

// IsExpired returns true if backup is expired
func (b *VolumeBackup) IsExpired() bool {
	if b.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*b.ExpiresAt)
}

// CreateVolumeBackupInput represents input for creating a volume backup
type CreateVolumeBackupInput struct {
	VolumeName  string `json:"volume_name" validate:"required"`
	Compression string `json:"compression,omitempty" validate:"omitempty,oneof=none gzip zstd"`
	Encrypted   bool   `json:"encrypted,omitempty"`
	RetentionDays *int `json:"retention_days,omitempty" validate:"omitempty,min=1,max=365"`
}

// RestoreVolumeInput represents input for restoring a volume
type RestoreVolumeInput struct {
	BackupID       uuid.UUID `json:"backup_id" validate:"required"`
	TargetVolume   string    `json:"target_volume,omitempty"`
	OverwriteExisting bool   `json:"overwrite_existing,omitempty"`
}

// VolumeStats holds volume statistics.
type VolumeStats struct {
	Total      int   `json:"total"`
	InUse      int   `json:"in_use"`
	Unused     int   `json:"unused"`
	TotalSize  int64 `json:"total_size"`
	UsedSize   int64 `json:"used_size"`
	UnusedSize int64 `json:"unused_size"`
}

// VolumeBackupInfo holds information needed for volume backup.
type VolumeBackupInfo struct {
	Name       string `json:"name"`
	Driver     string `json:"driver"`
	Mountpoint string `json:"mountpoint"`
	Size       int64  `json:"size"`
	Labels     map[string]string `json:"labels,omitempty"`
}
