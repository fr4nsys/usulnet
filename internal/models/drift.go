// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Snapshot status constants.
const (
	SnapshotStatusBaseline = "baseline"
	SnapshotStatusCurrent  = "current"
	SnapshotStatusArchived = "archived"
)

// Drift status constants.
const (
	DriftStatusOpen       = "open"
	DriftStatusAccepted   = "accepted"
	DriftStatusRemediated = "remediated"
)

// Drift diff type constants.
const (
	DriftTypeEnvVar        = "env_var_changed"
	DriftTypeImage         = "image_changed"
	DriftTypePort          = "port_changed"
	DriftTypeVolume        = "volume_changed"
	DriftTypeLimit         = "limit_changed"
	DriftTypeLabel         = "label_changed"
	DriftTypeNetwork       = "network_changed"
	DriftTypeRestartPolicy = "restart_policy_changed"
	DriftTypeHealthcheck   = "healthcheck_changed"
	DriftTypePrivileged    = "privileged_changed"
)

// ConfigSnapshot represents a point-in-time snapshot of a resource's configuration.
type ConfigSnapshot struct {
	ID           uuid.UUID        `json:"id" db:"id"`
	ResourceType string           `json:"resource_type" db:"resource_type"`
	ResourceID   string           `json:"resource_id" db:"resource_id"`
	ResourceName string           `json:"resource_name" db:"resource_name"`
	Status       string           `json:"status" db:"status"`
	Snapshot     *json.RawMessage `json:"snapshot" db:"snapshot"`
	TakenBy      *uuid.UUID       `json:"taken_by,omitempty" db:"taken_by"`
	TakenAt      time.Time        `json:"taken_at" db:"taken_at"`
	Note         string           `json:"note,omitempty" db:"note"`
}

// DriftDetection represents a detected configuration drift between a baseline and current snapshot.
type DriftDetection struct {
	ID                 uuid.UUID        `json:"id" db:"id"`
	ResourceType       string           `json:"resource_type" db:"resource_type"`
	ResourceID         string           `json:"resource_id" db:"resource_id"`
	ResourceName       string           `json:"resource_name" db:"resource_name"`
	BaselineSnapshotID *uuid.UUID       `json:"baseline_snapshot_id,omitempty" db:"baseline_snapshot_id"`
	CurrentSnapshotID  *uuid.UUID       `json:"current_snapshot_id,omitempty" db:"current_snapshot_id"`
	Status             string           `json:"status" db:"status"`
	Severity           string           `json:"severity" db:"severity"`
	Diffs              *json.RawMessage `json:"diffs" db:"diffs"`
	DiffCount          int              `json:"diff_count" db:"diff_count"`
	DetectedAt         time.Time        `json:"detected_at" db:"detected_at"`
	ResolvedAt         *time.Time       `json:"resolved_at,omitempty" db:"resolved_at"`
	ResolvedBy         *uuid.UUID       `json:"resolved_by,omitempty" db:"resolved_by"`
	ResolutionNote     string           `json:"resolution_note,omitempty" db:"resolution_note"`
}

// DriftDiff represents a single diff item within a drift detection's diffs array.
type DriftDiff struct {
	Type     string `json:"type"`
	Field    string `json:"field"`
	OldValue string `json:"old_value"`
	NewValue string `json:"new_value"`
	Severity string `json:"severity"`
}

// DriftListOptions holds filtering and pagination options for listing drift detections.
type DriftListOptions struct {
	ResourceType string
	ResourceID   string
	Status       string
	Severity     string
	Limit        int
	Offset       int
}

// DriftStats holds aggregate statistics about detected drifts.
type DriftStats struct {
	TotalOpen         int            `json:"total_open"`
	Critical          int            `json:"critical"`
	Warning           int            `json:"warning"`
	Info              int            `json:"info"`
	ResourcesAffected int            `json:"resources_affected"`
	ByResource        map[string]int `json:"by_resource"`
}
