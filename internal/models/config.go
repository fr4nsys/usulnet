// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// VariableType represents the type of a configuration variable
type VariableType string

const (
	VariableTypePlain    VariableType = "plain"    // Plain text
	VariableTypeSecret   VariableType = "secret"   // Encrypted
	VariableTypeComputed VariableType = "computed" // Generated (UUID, timestamp, etc.)
)

// VariableScope represents the scope of a variable
type VariableScope string

const (
	VariableScopeGlobal    VariableScope = "global"    // Available to all containers
	VariableScopeTemplate  VariableScope = "template"  // Template-specific
	VariableScopeContainer VariableScope = "container" // Container-specific
	VariableScopeStack     VariableScope = "stack"     // Stack-specific
)

// ConfigVariable represents a configuration variable
type ConfigVariable struct {
	ID          uuid.UUID     `json:"id" db:"id"`
	Name        string        `json:"name" db:"name"`
	Value       string        `json:"value" db:"value"` // Encrypted if Type is secret
	Type        VariableType  `json:"type" db:"type"`
	Scope       VariableScope `json:"scope" db:"scope"`
	ScopeID     *string       `json:"scope_id,omitempty" db:"scope_id"` // Template name, container ID, or stack ID
	Description *string       `json:"description,omitempty" db:"description"`
	IsRequired  bool          `json:"is_required" db:"is_required"`
	DefaultValue *string      `json:"default_value,omitempty" db:"default_value"`
	Version     int           `json:"version" db:"version"`
	CreatedBy   *uuid.UUID    `json:"created_by,omitempty" db:"created_by"`
	UpdatedBy   *uuid.UUID    `json:"updated_by,omitempty" db:"updated_by"`
	CreatedAt   time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at" db:"updated_at"`
}

// IsSecret returns true if variable is a secret
func (v *ConfigVariable) IsSecret() bool {
	return v.Type == VariableTypeSecret
}

// IsGlobal returns true if variable has global scope
func (v *ConfigVariable) IsGlobal() bool {
	return v.Scope == VariableScopeGlobal
}

// CreateVariableInput represents input for creating a variable
type CreateVariableInput struct {
	Name         string        `json:"name" validate:"required,min=1,max=255"`
	Value        string        `json:"value" validate:"required"`
	Type         VariableType  `json:"type" validate:"required,oneof=plain secret computed"`
	Scope        VariableScope `json:"scope" validate:"required,oneof=global template container stack"`
	ScopeID      *string       `json:"scope_id,omitempty"`
	Description  *string       `json:"description,omitempty" validate:"omitempty,max=500"`
	IsRequired   bool          `json:"is_required,omitempty"`
	DefaultValue *string       `json:"default_value,omitempty"`
}

// UpdateVariableInput represents input for updating a variable
type UpdateVariableInput struct {
	Value        *string  `json:"value,omitempty"`
	Description  *string  `json:"description,omitempty" validate:"omitempty,max=500"`
	IsRequired   *bool    `json:"is_required,omitempty"`
	DefaultValue *string  `json:"default_value,omitempty"`
}

// ConfigTemplate represents a configuration template
type ConfigTemplate struct {
	ID          uuid.UUID   `json:"id" db:"id"`
	Name        string      `json:"name" db:"name"`
	Description *string     `json:"description,omitempty" db:"description"`
	Variables   []ConfigVariable `json:"variables,omitempty" db:"-"`
	VariableCount int       `json:"variable_count" db:"variable_count"`
	IsDefault   bool        `json:"is_default" db:"is_default"`
	CreatedBy   *uuid.UUID  `json:"created_by,omitempty" db:"created_by"`
	UpdatedBy   *uuid.UUID  `json:"updated_by,omitempty" db:"updated_by"`
	CreatedAt   time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at" db:"updated_at"`
}

// CreateTemplateInput represents input for creating a template
type CreateTemplateInput struct {
	Name        string  `json:"name" validate:"required,min=1,max=100"`
	Description *string `json:"description,omitempty" validate:"omitempty,max=500"`
	IsDefault   bool    `json:"is_default,omitempty"`
	CopyFrom    *string `json:"copy_from,omitempty"` // Template name to copy from
}

// UpdateTemplateInput represents input for updating a template
type UpdateTemplateInput struct {
	Name        *string `json:"name,omitempty" validate:"omitempty,min=1,max=100"`
	Description *string `json:"description,omitempty" validate:"omitempty,max=500"`
	IsDefault   *bool   `json:"is_default,omitempty"`
}

// ConfigAuditLog represents a config change audit log
type ConfigAuditLog struct {
	ID           int64      `json:"id" db:"id"`
	Action       string     `json:"action" db:"action"` // create, update, delete, sync
	EntityType   string     `json:"entity_type" db:"entity_type"` // variable, template
	EntityID     string     `json:"entity_id" db:"entity_id"`
	EntityName   string     `json:"entity_name" db:"entity_name"`
	OldValue     *string    `json:"old_value,omitempty" db:"old_value"` // Masked for secrets
	NewValue     *string    `json:"new_value,omitempty" db:"new_value"` // Masked for secrets
	UserID       *uuid.UUID `json:"user_id,omitempty" db:"user_id"`
	Username     *string    `json:"username,omitempty" db:"username"`
	IPAddress    *string    `json:"ip_address,omitempty" db:"ip_address"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
}

// ConfigSync represents a config sync operation
type ConfigSync struct {
	ID            uuid.UUID   `json:"id" db:"id"`
	HostID        uuid.UUID   `json:"host_id" db:"host_id"`
	ContainerID   string      `json:"container_id" db:"container_id"`
	ContainerName string      `json:"container_name" db:"container_name"`
	TemplateID    *uuid.UUID  `json:"template_id,omitempty" db:"template_id"`
	TemplateName  *string     `json:"template_name,omitempty" db:"template_name"`
	Status        string      `json:"status" db:"status"` // pending, synced, failed, outdated
	VariablesHash string      `json:"variables_hash" db:"variables_hash"` // Hash of applied vars
	SyncedAt      *time.Time  `json:"synced_at,omitempty" db:"synced_at"`
	ErrorMessage  *string     `json:"error_message,omitempty" db:"error_message"`
	CreatedAt     time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at" db:"updated_at"`
}

// IsSynced returns true if sync is up to date
func (s *ConfigSync) IsSynced() bool {
	return s.Status == "synced"
}

// IsOutdated returns true if sync is outdated
func (s *ConfigSync) IsOutdated() bool {
	return s.Status == "outdated"
}

// SyncConfigInput represents input for syncing config to a container
type SyncConfigInput struct {
	ContainerID string     `json:"container_id" validate:"required"`
	TemplateID  *uuid.UUID `json:"template_id,omitempty"`
	Variables   map[string]string `json:"variables,omitempty"` // Additional variables
	Force       bool       `json:"force,omitempty"` // Force restart
	DryRun      bool       `json:"dry_run,omitempty"` // Preview only
}

// SyncBulkInput represents input for bulk sync
type SyncBulkInput struct {
	ContainerIDs []string   `json:"container_ids" validate:"required,min=1"`
	TemplateID   *uuid.UUID `json:"template_id,omitempty"`
	Variables    map[string]string `json:"variables,omitempty"`
	Force        bool       `json:"force,omitempty"`
}

// ConfigDiff represents differences between current and new config
type ConfigDiff struct {
	ContainerID   string       `json:"container_id"`
	ContainerName string       `json:"container_name"`
	Added         []DiffEntry  `json:"added,omitempty"`
	Modified      []DiffEntry  `json:"modified,omitempty"`
	Removed       []DiffEntry  `json:"removed,omitempty"`
	RequiresRestart bool       `json:"requires_restart"`
}

// DiffEntry represents a single diff entry
type DiffEntry struct {
	Name     string `json:"name"`
	OldValue string `json:"old_value,omitempty"` // Masked for secrets
	NewValue string `json:"new_value,omitempty"` // Masked for secrets
	IsSecret bool   `json:"is_secret"`
}

// VariableUsage represents where a variable is used
type VariableUsage struct {
	VariableID   uuid.UUID `json:"variable_id"`
	VariableName string    `json:"variable_name"`
	UsedIn       []UsageEntry `json:"used_in"`
}

// UsageEntry represents a single usage of a variable
type UsageEntry struct {
	Type string `json:"type"` // container, stack
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ConfigExport represents exported config
type ConfigExport struct {
	Version     string           `json:"version"`
	ExportedAt  time.Time        `json:"exported_at"`
	Variables   []ConfigVariable `json:"variables"`
	Templates   []ConfigTemplate `json:"templates"`
	Encrypted   bool             `json:"encrypted"`
}

// ConfigImportInput represents input for importing config
type ConfigImportInput struct {
	Data        string `json:"data" validate:"required"`
	Password    string `json:"password,omitempty"`
	Overwrite   bool   `json:"overwrite,omitempty"`
	SkipSecrets bool   `json:"skip_secrets,omitempty"`
}

// VariableListOptions represents options for listing variables
type VariableListOptions struct {
	Scope    *VariableScope `json:"scope,omitempty"`
	ScopeID  *string        `json:"scope_id,omitempty"`
	Type     *VariableType  `json:"type,omitempty"`
	Search   *string        `json:"search,omitempty"`
	Limit    int            `json:"limit,omitempty"`
	Offset   int            `json:"offset,omitempty"`
}

// VariableHistory represents historical versions of a variable
type VariableHistory struct {
	ID          int64      `json:"id" db:"id"`
	VariableID  uuid.UUID  `json:"variable_id" db:"variable_id"`
	Version     int        `json:"version" db:"version"`
	Value       string     `json:"value" db:"value"` // Encrypted if secret
	UpdatedBy   *uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
}

// InterpolatedValue represents a variable value with interpolation
type InterpolatedValue struct {
	Name         string `json:"name"`
	OriginalValue string `json:"original_value"`
	ResolvedValue string `json:"resolved_value"`
	IsSecret     bool   `json:"is_secret"`
	References   []string `json:"references,omitempty"` // Other vars referenced
}

// InterpolateResult represents the result of variable interpolation
type InterpolateResult struct {
	Values       []InterpolatedValue `json:"values"`
	Errors       []string            `json:"errors,omitempty"`
	CircularRefs []string            `json:"circular_refs,omitempty"`
}
