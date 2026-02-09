// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// TeamRole represents the role of a user within a team.
type TeamRole string

const (
	TeamRoleOwner  TeamRole = "owner"
	TeamRoleMember TeamRole = "member"
)

// IsValid checks if the team role is valid.
func (r TeamRole) IsValid() bool {
	switch r {
	case TeamRoleOwner, TeamRoleMember:
		return true
	}
	return false
}

// ResourceType represents a type of scopeable resource.
type ResourceType string

const (
	ResourceTypeStack           ResourceType = "stack"
	ResourceTypeContainerGroup  ResourceType = "container_group"
	ResourceTypeGiteaConnection ResourceType = "gitea_connection"
	ResourceTypeS3Connection    ResourceType = "s3_connection"
	ResourceTypeHost            ResourceType = "host"
	ResourceTypeNetwork         ResourceType = "network"
	ResourceTypeVolume          ResourceType = "volume"
)

// IsValid checks if the resource type is valid.
func (rt ResourceType) IsValid() bool {
	switch rt {
	case ResourceTypeStack, ResourceTypeContainerGroup,
		ResourceTypeGiteaConnection, ResourceTypeS3Connection,
		ResourceTypeHost, ResourceTypeNetwork, ResourceTypeVolume:
		return true
	}
	return false
}

// AccessLevel represents the level of access granted to a team for a resource.
type AccessLevel string

const (
	AccessLevelView   AccessLevel = "view"
	AccessLevelManage AccessLevel = "manage"
)

// IsValid checks if the access level is valid.
func (al AccessLevel) IsValid() bool {
	switch al {
	case AccessLevelView, AccessLevelManage:
		return true
	}
	return false
}

// CanManage returns true if the access level allows management operations.
func (al AccessLevel) CanManage() bool {
	return al == AccessLevelManage
}

// Team represents a group of users with shared resource access.
type Team struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	Name        string     `json:"name" db:"name"`
	Description *string    `json:"description,omitempty" db:"description"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`

	// Populated by joins, not stored directly
	MemberCount     int `json:"member_count,omitempty" db:"-"`
	PermissionCount int `json:"permission_count,omitempty" db:"-"`
}

// TeamMember represents a user's membership in a team.
type TeamMember struct {
	TeamID     uuid.UUID  `json:"team_id" db:"team_id"`
	UserID     uuid.UUID  `json:"user_id" db:"user_id"`
	RoleInTeam TeamRole   `json:"role_in_team" db:"role_in_team"`
	AddedAt    time.Time  `json:"added_at" db:"added_at"`
	AddedBy    *uuid.UUID `json:"added_by,omitempty" db:"added_by"`

	// Populated by joins
	Username string `json:"username,omitempty" db:"-"`
	Email    string `json:"email,omitempty" db:"-"`
}

// ResourcePermission represents a team's access to a specific resource.
type ResourcePermission struct {
	ID           uuid.UUID    `json:"id" db:"id"`
	TeamID       uuid.UUID    `json:"team_id" db:"team_id"`
	ResourceType ResourceType `json:"resource_type" db:"resource_type"`
	ResourceID   string       `json:"resource_id" db:"resource_id"`
	AccessLevel  AccessLevel  `json:"access_level" db:"access_level"`
	GrantedAt    time.Time    `json:"granted_at" db:"granted_at"`
	GrantedBy    *uuid.UUID   `json:"granted_by,omitempty" db:"granted_by"`

	// Populated by joins - human-readable resource name
	ResourceName string `json:"resource_name,omitempty" db:"-"`
}

// ResourceScope holds the computed scope for a user based on team memberships.
// Injected into request context by the scoping middleware.
type ResourceScope struct {
	// IsAdmin means the user has global admin role — no filtering applied.
	IsAdmin bool
	// NoTeamsExist means no teams have been created — no filtering applied (backward compat).
	NoTeamsExist bool
	// UserTeamIDs are the teams this user belongs to.
	UserTeamIDs []uuid.UUID

	// Allowed resource IDs per type — resources the user's teams have access to.
	AllowedStacks          []uuid.UUID // stack IDs (also used for container filtering via stack_id)
	AllowedContainerGroups []string    // container_group label values
	AllowedGiteaConns      []uuid.UUID // gitea_connection IDs
	AllowedS3Conns         []uuid.UUID // storage_connection IDs
	AllowedHosts           []uuid.UUID // host IDs
	AllowedNetworks        []string    // network IDs (Docker networks are strings)
	AllowedVolumes         []string    // volume names

	// Assigned resource IDs per type — resources that ANY team has claimed.
	// Used for opt-in scoping: unassigned resources (not in Assigned*) are visible to all.
	AssignedStacks          []uuid.UUID
	AssignedContainerGroups []string
	AssignedGiteaConns      []uuid.UUID
	AssignedS3Conns         []uuid.UUID
	AssignedHosts           []uuid.UUID
	AssignedNetworks        []string
	AssignedVolumes         []string
}

// ShouldFilter returns true if scoping should be applied to queries.
// Returns false for admins and when no teams exist (backward compatibility).
func (s *ResourceScope) ShouldFilter() bool {
	if s == nil || s.IsAdmin || s.NoTeamsExist {
		return false
	}
	return true
}

// HasAccessToStack checks if the scope includes a specific stack.
func (s *ResourceScope) HasAccessToStack(stackID uuid.UUID) bool {
	if !s.ShouldFilter() {
		return true
	}
	// If not assigned to any team, visible to all (opt-in model)
	if !uuidInSlice(stackID, s.AssignedStacks) {
		return true
	}
	return uuidInSlice(stackID, s.AllowedStacks)
}

// HasAccessToContainerGroup checks if the scope includes a container group label.
func (s *ResourceScope) HasAccessToContainerGroup(group string) bool {
	if !s.ShouldFilter() {
		return true
	}
	// Empty group = unassigned = visible to all
	if group == "" {
		return true
	}
	// If the group is not assigned to any team, it's visible to all
	if !stringInSlice(group, s.AssignedContainerGroups) {
		return true
	}
	for _, g := range s.AllowedContainerGroups {
		if g == group {
			return true
		}
	}
	return false
}

// HasAccessToGiteaConn checks if the scope includes a Gitea connection.
func (s *ResourceScope) HasAccessToGiteaConn(connID uuid.UUID) bool {
	if !s.ShouldFilter() {
		return true
	}
	// If not assigned to any team, visible to all
	if !uuidInSlice(connID, s.AssignedGiteaConns) {
		return true
	}
	return uuidInSlice(connID, s.AllowedGiteaConns)
}

// HasAccessToS3Conn checks if the scope includes an S3 connection.
func (s *ResourceScope) HasAccessToS3Conn(connID uuid.UUID) bool {
	if !s.ShouldFilter() {
		return true
	}
	// If not assigned to any team, visible to all
	if !uuidInSlice(connID, s.AssignedS3Conns) {
		return true
	}
	return uuidInSlice(connID, s.AllowedS3Conns)
}

// HasAccessToHost checks if the scope includes a host.
func (s *ResourceScope) HasAccessToHost(hostID uuid.UUID) bool {
	if !s.ShouldFilter() {
		return true
	}
	// If not assigned to any team, visible to all
	if !uuidInSlice(hostID, s.AssignedHosts) {
		return true
	}
	return uuidInSlice(hostID, s.AllowedHosts)
}

// HasAccessToNetwork checks if the scope includes a network.
func (s *ResourceScope) HasAccessToNetwork(networkID string) bool {
	if !s.ShouldFilter() {
		return true
	}
	// If not assigned to any team, visible to all
	if !stringInSlice(networkID, s.AssignedNetworks) {
		return true
	}
	return stringInSlice(networkID, s.AllowedNetworks)
}

// HasAccessToVolume checks if the scope includes a volume.
func (s *ResourceScope) HasAccessToVolume(volumeName string) bool {
	if !s.ShouldFilter() {
		return true
	}
	// If not assigned to any team, visible to all
	if !stringInSlice(volumeName, s.AssignedVolumes) {
		return true
	}
	return stringInSlice(volumeName, s.AllowedVolumes)
}

func uuidInSlice(id uuid.UUID, slice []uuid.UUID) bool {
	for _, v := range slice {
		if v == id {
			return true
		}
	}
	return false
}

func stringInSlice(s string, slice []string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
