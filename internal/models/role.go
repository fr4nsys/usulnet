// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Role represents a custom role with permissions
type Role struct {
	ID          uuid.UUID      `json:"id" db:"id"`
	Name        string         `json:"name" db:"name"`
	DisplayName string         `json:"display_name" db:"display_name"`
	Description *string        `json:"description,omitempty" db:"description"`
	Permissions pq.StringArray `json:"permissions" db:"permissions"`
	IsSystem    bool           `json:"is_system" db:"is_system"`
	IsActive    bool           `json:"is_active" db:"is_active"`
	Priority    int            `json:"priority" db:"priority"`
	CreatedAt   time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at" db:"updated_at"`
}

// HasPermission checks if the role has a specific permission
func (r *Role) HasPermission(permission string) bool {
	for _, p := range r.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// HasAnyPermission checks if the role has any of the specified permissions
func (r *Role) HasAnyPermission(permissions ...string) bool {
	for _, perm := range permissions {
		if r.HasPermission(perm) {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if the role has all the specified permissions
func (r *Role) HasAllPermissions(permissions ...string) bool {
	for _, perm := range permissions {
		if !r.HasPermission(perm) {
			return false
		}
	}
	return true
}

// CreateRoleInput represents input for creating a role
type CreateRoleInput struct {
	Name        string   `json:"name" validate:"required,min=2,max=100,alphanum"`
	DisplayName string   `json:"display_name" validate:"required,min=2,max=255"`
	Description *string  `json:"description,omitempty"`
	Permissions []string `json:"permissions" validate:"required,min=1"`
	Priority    int      `json:"priority" validate:"gte=0,lte=99"`
}

// UpdateRoleInput represents input for updating a role
type UpdateRoleInput struct {
	DisplayName *string  `json:"display_name,omitempty" validate:"omitempty,min=2,max=255"`
	Description *string  `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty" validate:"omitempty,min=1"`
	IsActive    *bool    `json:"is_active,omitempty"`
	Priority    *int     `json:"priority,omitempty" validate:"omitempty,gte=0,lte=99"`
}

// PermissionCategory represents a group of related permissions
type PermissionCategory struct {
	Name        string       `json:"name"`
	DisplayName string       `json:"display_name"`
	Permissions []Permission `json:"permissions"`
}

// Permission represents a single permission
type Permission struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
}

// AllPermissions returns all available permissions grouped by category
func AllPermissions() []PermissionCategory {
	return []PermissionCategory{
		{
			Name:        "container",
			DisplayName: "Containers",
			Permissions: []Permission{
				{Name: "container:view", DisplayName: "View Containers", Description: "View container list and details"},
				{Name: "container:create", DisplayName: "Create Containers", Description: "Create new containers"},
				{Name: "container:start", DisplayName: "Start Containers", Description: "Start stopped containers"},
				{Name: "container:stop", DisplayName: "Stop Containers", Description: "Stop running containers"},
				{Name: "container:restart", DisplayName: "Restart Containers", Description: "Restart containers"},
				{Name: "container:remove", DisplayName: "Remove Containers", Description: "Delete containers"},
				{Name: "container:exec", DisplayName: "Execute Commands", Description: "Execute commands in containers"},
				{Name: "container:logs", DisplayName: "View Logs", Description: "View container logs"},
			},
		},
		{
			Name:        "image",
			DisplayName: "Images",
			Permissions: []Permission{
				{Name: "image:view", DisplayName: "View Images", Description: "View image list and details"},
				{Name: "image:pull", DisplayName: "Pull Images", Description: "Pull images from registries"},
				{Name: "image:remove", DisplayName: "Remove Images", Description: "Delete images"},
				{Name: "image:build", DisplayName: "Build Images", Description: "Build images from Dockerfiles"},
			},
		},
		{
			Name:        "volume",
			DisplayName: "Volumes",
			Permissions: []Permission{
				{Name: "volume:view", DisplayName: "View Volumes", Description: "View volume list and details"},
				{Name: "volume:create", DisplayName: "Create Volumes", Description: "Create new volumes"},
				{Name: "volume:remove", DisplayName: "Remove Volumes", Description: "Delete volumes"},
			},
		},
		{
			Name:        "network",
			DisplayName: "Networks",
			Permissions: []Permission{
				{Name: "network:view", DisplayName: "View Networks", Description: "View network list and details"},
				{Name: "network:create", DisplayName: "Create Networks", Description: "Create new networks"},
				{Name: "network:remove", DisplayName: "Remove Networks", Description: "Delete networks"},
			},
		},
		{
			Name:        "stack",
			DisplayName: "Stacks",
			Permissions: []Permission{
				{Name: "stack:view", DisplayName: "View Stacks", Description: "View stack list and details"},
				{Name: "stack:deploy", DisplayName: "Deploy Stacks", Description: "Deploy new stacks"},
				{Name: "stack:update", DisplayName: "Update Stacks", Description: "Update existing stacks"},
				{Name: "stack:remove", DisplayName: "Remove Stacks", Description: "Delete stacks"},
			},
		},
		{
			Name:        "host",
			DisplayName: "Hosts",
			Permissions: []Permission{
				{Name: "host:view", DisplayName: "View Hosts", Description: "View host list and details"},
				{Name: "host:create", DisplayName: "Add Hosts", Description: "Add new hosts"},
				{Name: "host:update", DisplayName: "Update Hosts", Description: "Update host settings"},
				{Name: "host:remove", DisplayName: "Remove Hosts", Description: "Remove hosts"},
			},
		},
		{
			Name:        "user",
			DisplayName: "Users",
			Permissions: []Permission{
				{Name: "user:view", DisplayName: "View Users", Description: "View user list and details"},
				{Name: "user:create", DisplayName: "Create Users", Description: "Create new users"},
				{Name: "user:update", DisplayName: "Update Users", Description: "Update user settings"},
				{Name: "user:remove", DisplayName: "Remove Users", Description: "Delete users"},
			},
		},
		{
			Name:        "role",
			DisplayName: "Roles",
			Permissions: []Permission{
				{Name: "role:view", DisplayName: "View Roles", Description: "View role list and details"},
				{Name: "role:create", DisplayName: "Create Roles", Description: "Create new roles"},
				{Name: "role:update", DisplayName: "Update Roles", Description: "Update role permissions"},
				{Name: "role:remove", DisplayName: "Remove Roles", Description: "Delete custom roles"},
			},
		},
		{
			Name:        "settings",
			DisplayName: "Settings",
			Permissions: []Permission{
				{Name: "settings:view", DisplayName: "View Settings", Description: "View system settings"},
				{Name: "settings:update", DisplayName: "Update Settings", Description: "Modify system settings"},
			},
		},
		{
			Name:        "backup",
			DisplayName: "Backups",
			Permissions: []Permission{
				{Name: "backup:view", DisplayName: "View Backups", Description: "View backup list and details"},
				{Name: "backup:create", DisplayName: "Create Backups", Description: "Create new backups"},
				{Name: "backup:restore", DisplayName: "Restore Backups", Description: "Restore from backups"},
			},
		},
		{
			Name:        "security",
			DisplayName: "Security",
			Permissions: []Permission{
				{Name: "security:view", DisplayName: "View Security", Description: "View security scan results"},
				{Name: "security:scan", DisplayName: "Run Scans", Description: "Run security scans"},
			},
		},
		{
			Name:        "config",
			DisplayName: "Configuration",
			Permissions: []Permission{
				{Name: "config:view", DisplayName: "View Config", Description: "View configuration templates"},
				{Name: "config:create", DisplayName: "Create Config", Description: "Create configuration templates"},
				{Name: "config:update", DisplayName: "Update Config", Description: "Update configuration templates"},
				{Name: "config:remove", DisplayName: "Remove Config", Description: "Delete configuration templates"},
			},
		},
		{
			Name:        "audit",
			DisplayName: "Audit",
			Permissions: []Permission{
				{Name: "audit:view", DisplayName: "View Audit Logs", Description: "View audit logs"},
			},
		},
	}
}

// AllPermissionNames returns a flat list of all permission names
func AllPermissionNames() []string {
	var names []string
	for _, cat := range AllPermissions() {
		for _, perm := range cat.Permissions {
			names = append(names, perm.Name)
		}
	}
	return names
}
