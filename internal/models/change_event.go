// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ChangeEvent represents a structured, immutable record of a change operation.
// It captures who changed what, when, and what the state was before and after.
type ChangeEvent struct {
	ID            uuid.UUID        `json:"id" db:"id"`
	Timestamp     time.Time        `json:"timestamp" db:"timestamp"`
	UserID        *uuid.UUID       `json:"user_id,omitempty" db:"user_id"`
	UserName      string           `json:"user_name" db:"user_name"`
	ClientIP      string           `json:"client_ip" db:"client_ip"`
	ResourceType  string           `json:"resource_type" db:"resource_type"`
	ResourceID    string           `json:"resource_id" db:"resource_id"`
	ResourceName  string           `json:"resource_name" db:"resource_name"`
	Action        string           `json:"action" db:"action"`
	OldState      *json.RawMessage `json:"old_state,omitempty" db:"old_state"`
	NewState      *json.RawMessage `json:"new_state,omitempty" db:"new_state"`
	DiffSummary   string           `json:"diff_summary" db:"diff_summary"`
	RelatedTicket string           `json:"related_ticket,omitempty" db:"related_ticket"`
	Metadata      *json.RawMessage `json:"metadata,omitempty" db:"metadata"`
}

// Change action constants.
const (
	ChangeActionCreate       = "create"
	ChangeActionUpdate       = "update"
	ChangeActionDelete       = "delete"
	ChangeActionStart        = "start"
	ChangeActionStop         = "stop"
	ChangeActionRestart      = "restart"
	ChangeActionDeploy       = "deploy"
	ChangeActionRollback     = "rollback"
	ChangeActionExec         = "exec"
	ChangeActionScaleUp      = "scale_up"
	ChangeActionScaleDown    = "scale_down"
	ChangeActionConfigChange = "config_change"
	ChangeActionSecretRotate = "secret_rotate"
	ChangeActionPermChange   = "permission_change"
	ChangeActionProxyUpdate  = "proxy_update"
	ChangeActionBackup       = "backup"
	ChangeActionRestore      = "restore"
)

// Change resource type constants.
const (
	ChangeResourceContainer = "container"
	ChangeResourceStack     = "stack"
	ChangeResourceImage     = "image"
	ChangeResourceVolume    = "volume"
	ChangeResourceNetwork   = "network"
	ChangeResourceProxy     = "proxy_rule"
	ChangeResourceSecret    = "secret"
	ChangeResourceUser      = "user"
	ChangeResourceConfig    = "config"
	ChangeResourceBackup    = "backup"
	ChangeResourceHost      = "host"
)

// ChangeEventListOptions provides filtering/pagination for listing change events.
type ChangeEventListOptions struct {
	UserID       *uuid.UUID
	ResourceType string
	ResourceID   string
	Action       string
	Search       string // full-text search query
	Since        *time.Time
	Until        *time.Time
	Limit        int
	Offset       int
}

// ChangeEventStats aggregates change event counts.
type ChangeEventStats struct {
	TotalEvents int              `json:"total_events"`
	TodayEvents int              `json:"today_events"`
	TopUsers    []ChangeUserStat `json:"top_users"`
	ByAction    map[string]int   `json:"by_action"`
	ByResource  map[string]int   `json:"by_resource"`
}

// ChangeUserStat is a user's change count for the stats panel.
type ChangeUserStat struct {
	UserName string `json:"user_name" db:"user_name"`
	Count    int    `json:"count" db:"count"`
}
