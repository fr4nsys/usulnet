// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package team provides team management and resource scoping services.
package team

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/models"
	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// Config contains team service configuration.
type Config struct {
	// MaxTeams is the maximum number of teams allowed (0 = unlimited).
	MaxTeams int
}

// Service provides team management operations.
type Service struct {
	teamRepo      *postgres.TeamRepository
	permRepo      *postgres.ResourcePermissionRepository
	config        Config
	logger        *logger.Logger
	limitMu       sync.RWMutex
	limitProvider license.LimitProvider
}

// SetLimitProvider sets the license limit provider for dynamic limit enforcement.
// Thread-safe: may be called while goroutines read limitProvider.
func (s *Service) SetLimitProvider(lp license.LimitProvider) {
	s.limitMu.Lock()
	s.limitProvider = lp
	s.limitMu.Unlock()
}

// NewService creates a new team service.
func NewService(
	teamRepo *postgres.TeamRepository,
	permRepo *postgres.ResourcePermissionRepository,
	config Config,
	log *logger.Logger,
) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		teamRepo: teamRepo,
		permRepo: permRepo,
		config:   config,
		logger:   log.Named("team"),
	}
}

// ============================================================================
// Team CRUD
// ============================================================================

// CreateTeam creates a new team.
func (s *Service) CreateTeam(ctx context.Context, name, description string, createdBy uuid.UUID) (*models.Team, error) {
	// Check team limit dynamically from license provider (defense in depth)
	maxTeams := s.config.MaxTeams
	s.limitMu.RLock()
	lp := s.limitProvider
	s.limitMu.RUnlock()
	if lp != nil {
		maxTeams = lp.GetLimits().MaxTeams
	}
	if maxTeams > 0 {
		count, err := s.teamRepo.Count(ctx)
		if err != nil {
			return nil, fmt.Errorf("check team limit: %w", err)
		}
		if count >= maxTeams {
			return nil, apperrors.New(apperrors.CodeBadRequest,
				fmt.Sprintf("team limit reached (%d), upgrade your license for more teams", maxTeams))
		}
	}

	// Check name uniqueness
	existing, err := s.teamRepo.GetByName(ctx, name)
	if err == nil && existing != nil {
		return nil, apperrors.New(apperrors.CodeBadRequest, "team name already exists")
	}

	team := &models.Team{
		ID:        uuid.New(),
		Name:      name,
		CreatedBy: &createdBy,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if description != "" {
		team.Description = &description
	}

	if err := s.teamRepo.Create(ctx, team); err != nil {
		return nil, fmt.Errorf("create team: %w", err)
	}

	// Auto-add creator as owner
	member := &models.TeamMember{
		TeamID:     team.ID,
		UserID:     createdBy,
		RoleInTeam: models.TeamRoleOwner,
		AddedAt:    time.Now().UTC(),
		AddedBy:    &createdBy,
	}
	if err := s.teamRepo.AddMember(ctx, member); err != nil {
		s.logger.Error("failed to add creator as team owner", "team_id", team.ID, "error", err)
		// Non-fatal: team is created, member can be added later
	}

	s.logger.Info("team created", "team_id", team.ID, "name", name, "created_by", createdBy)
	return team, nil
}

// GetTeam retrieves a team by ID.
func (s *Service) GetTeam(ctx context.Context, id uuid.UUID) (*models.Team, error) {
	return s.teamRepo.GetByID(ctx, id)
}

// ListTeams returns all teams.
func (s *Service) ListTeams(ctx context.Context) ([]*models.Team, error) {
	return s.teamRepo.List(ctx)
}

// UpdateTeam updates a team's name and description.
func (s *Service) UpdateTeam(ctx context.Context, id uuid.UUID, name, description string) (*models.Team, error) {
	team, err := s.teamRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if name != "" && name != team.Name {
		existing, err := s.teamRepo.GetByName(ctx, name)
		if err == nil && existing != nil && existing.ID != id {
			return nil, apperrors.New(apperrors.CodeBadRequest, "team name already exists")
		}
		team.Name = name
	}
	if description != "" {
		team.Description = &description
	}
	team.UpdatedAt = time.Now().UTC()

	if err := s.teamRepo.Update(ctx, team); err != nil {
		return nil, err
	}
	return team, nil
}

// DeleteTeam removes a team and all its members and permissions.
func (s *Service) DeleteTeam(ctx context.Context, id uuid.UUID) error {
	// Verify team exists
	if _, err := s.teamRepo.GetByID(ctx, id); err != nil {
		return err
	}
	// Repo handles cascading deletes via ON DELETE CASCADE in DB schema
	return s.teamRepo.Delete(ctx, id)
}

// ============================================================================
// Member Management
// ============================================================================

// AddMember adds a user to a team.
func (s *Service) AddMember(ctx context.Context, teamID, userID uuid.UUID, role models.TeamRole, addedBy uuid.UUID) error {
	if !role.IsValid() {
		return apperrors.New(apperrors.CodeBadRequest, "invalid team role: "+string(role))
	}

	// Check team exists
	if _, err := s.teamRepo.GetByID(ctx, teamID); err != nil {
		return err
	}

	// Check not already a member
	isMember, err := s.teamRepo.IsMember(ctx, teamID, userID)
	if err != nil {
		return err
	}
	if isMember {
		return apperrors.New(apperrors.CodeBadRequest, "user is already a member of this team")
	}

	member := &models.TeamMember{
		TeamID:     teamID,
		UserID:     userID,
		RoleInTeam: role,
		AddedAt:    time.Now().UTC(),
		AddedBy:    &addedBy,
	}
	return s.teamRepo.AddMember(ctx, member)
}

// RemoveMember removes a user from a team.
func (s *Service) RemoveMember(ctx context.Context, teamID, userID uuid.UUID) error {
	return s.teamRepo.RemoveMember(ctx, teamID, userID)
}

// ListMembers returns all members of a team.
func (s *Service) ListMembers(ctx context.Context, teamID uuid.UUID) ([]*models.TeamMember, error) {
	return s.teamRepo.ListMembers(ctx, teamID)
}

// ListTeamsForUser returns all teams a user belongs to.
func (s *Service) ListTeamsForUser(ctx context.Context, userID uuid.UUID) ([]*models.Team, error) {
	return s.teamRepo.ListTeamsForUser(ctx, userID)
}

// ============================================================================
// Permission Management
// ============================================================================

// GrantAccess grants a team access to a resource.
func (s *Service) GrantAccess(ctx context.Context, teamID uuid.UUID, resourceType models.ResourceType, resourceID string, level models.AccessLevel, grantedBy uuid.UUID) error {
	if !resourceType.IsValid() {
		return apperrors.New(apperrors.CodeBadRequest, "invalid resource type: "+string(resourceType))
	}
	if !level.IsValid() {
		return apperrors.New(apperrors.CodeBadRequest, "invalid access level: "+string(level))
	}
	if resourceID == "" {
		return apperrors.New(apperrors.CodeBadRequest, "resource_id is required")
	}

	// Check team exists
	if _, err := s.teamRepo.GetByID(ctx, teamID); err != nil {
		return err
	}

	perm := &models.ResourcePermission{
		TeamID:       teamID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		AccessLevel:  level,
		GrantedBy:    &grantedBy,
	}
	return s.permRepo.Grant(ctx, perm)
}

// RevokeAccess removes a team's access to a resource.
func (s *Service) RevokeAccess(ctx context.Context, teamID uuid.UUID, resourceType models.ResourceType, resourceID string) error {
	return s.permRepo.Revoke(ctx, teamID, resourceType, resourceID)
}

// RevokeAccessByID removes a permission by its ID.
func (s *Service) RevokeAccessByID(ctx context.Context, permID uuid.UUID) error {
	return s.permRepo.RevokeByID(ctx, permID)
}

// ListPermissions returns all permissions for a team.
func (s *Service) ListPermissions(ctx context.Context, teamID uuid.UUID) ([]*models.ResourcePermission, error) {
	return s.permRepo.ListByTeam(ctx, teamID)
}

// ListResourcePermissions returns all permissions for a specific resource.
func (s *Service) ListResourcePermissions(ctx context.Context, resourceType models.ResourceType, resourceID string) ([]*models.ResourcePermission, error) {
	return s.permRepo.ListByResource(ctx, resourceType, resourceID)
}

// ============================================================================
// Scope Computation (implements ScopeProvider interface)
// ============================================================================

// GetUserScope computes the ResourceScope for a user.
// Called by the scoping middleware once per request.
func (s *Service) GetUserScope(ctx context.Context, userID string, userRole string) (*models.ResourceScope, error) {
	scope := &models.ResourceScope{}

	// Admin bypasses all scoping
	if userRole == "admin" {
		scope.IsAdmin = true
		return scope, nil
	}

	// Check if any teams exist at all
	teamsExist, err := s.teamRepo.Exists(ctx)
	if err != nil {
		s.logger.Error("failed to check if teams exist", "error", err)
		// On error, don't filter (fail open for usability)
		scope.NoTeamsExist = true
		return scope, nil
	}
	if !teamsExist {
		scope.NoTeamsExist = true
		return scope, nil
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		// Invalid UUID, can't look up teams
		return scope, nil
	}

	computed, err := s.permRepo.GetUserScope(ctx, uid)
	if err != nil {
		s.logger.Error("failed to compute user scope", "user_id", userID, "error", err)
		// Fail open: don't filter on error
		scope.NoTeamsExist = true
		return scope, nil
	}

	return computed, nil
}

// TeamsExist returns whether any teams have been created.
func (s *Service) TeamsExist(ctx context.Context) (bool, error) {
	return s.teamRepo.Exists(ctx)
}

// TeamCount returns the number of teams.
func (s *Service) TeamCount(ctx context.Context) (int, error) {
	return s.teamRepo.Count(ctx)
}
