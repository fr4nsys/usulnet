// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/models"
)

// ResourcePermissionRepository handles resource permission database operations.
type ResourcePermissionRepository struct {
	db *DB
}

// NewResourcePermissionRepository creates a new resource permission repository.
func NewResourcePermissionRepository(db *DB) *ResourcePermissionRepository {
	return &ResourcePermissionRepository{db: db}
}

// ============================================================================
// Permission CRUD
// ============================================================================

// Grant creates or updates a resource permission for a team.
func (r *ResourcePermissionRepository) Grant(ctx context.Context, perm *models.ResourcePermission) error {
	if perm.ID == uuid.Nil {
		perm.ID = uuid.New()
	}
	perm.GrantedAt = time.Now().UTC()

	_, err := r.db.Exec(ctx, `
		INSERT INTO resource_permissions (id, team_id, resource_type, resource_id, access_level, granted_at, granted_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (team_id, resource_type, resource_id)
		DO UPDATE SET access_level = $5, granted_at = $6, granted_by = $7`,
		perm.ID, perm.TeamID, perm.ResourceType, perm.ResourceID,
		perm.AccessLevel, perm.GrantedAt, perm.GrantedBy,
	)
	if err != nil {
		return apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to grant permission")
	}
	return nil
}

// Revoke removes a resource permission.
func (r *ResourcePermissionRepository) Revoke(ctx context.Context, teamID uuid.UUID, resourceType models.ResourceType, resourceID string) error {
	tag, err := r.db.Exec(ctx, `
		DELETE FROM resource_permissions
		WHERE team_id = $1 AND resource_type = $2 AND resource_id = $3`,
		teamID, resourceType, resourceID,
	)
	if err != nil {
		return apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to revoke permission")
	}
	if tag.RowsAffected() == 0 {
		return apperrors.New(apperrors.CodeNotFound, "permission not found")
	}
	return nil
}

// RevokeByID removes a resource permission by its ID.
func (r *ResourcePermissionRepository) RevokeByID(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM resource_permissions WHERE id = $1`, id)
	if err != nil {
		return apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to revoke permission")
	}
	if tag.RowsAffected() == 0 {
		return apperrors.New(apperrors.CodeNotFound, "permission not found")
	}
	return nil
}

// ListByTeam returns all permissions for a team.
func (r *ResourcePermissionRepository) ListByTeam(ctx context.Context, teamID uuid.UUID) ([]*models.ResourcePermission, error) {
	query := `
		SELECT id, team_id, resource_type, resource_id, access_level, granted_at, granted_by
		FROM resource_permissions
		WHERE team_id = $1
		ORDER BY resource_type ASC, resource_id ASC`

	rows, err := r.db.Query(ctx, query, teamID)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to list permissions")
	}
	defer rows.Close()

	return r.scanRows(rows)
}

// ListByResource returns all permissions for a specific resource.
func (r *ResourcePermissionRepository) ListByResource(ctx context.Context, resourceType models.ResourceType, resourceID string) ([]*models.ResourcePermission, error) {
	query := `
		SELECT id, team_id, resource_type, resource_id, access_level, granted_at, granted_by
		FROM resource_permissions
		WHERE resource_type = $1 AND resource_id = $2
		ORDER BY team_id ASC`

	rows, err := r.db.Query(ctx, query, resourceType, resourceID)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to list permissions by resource")
	}
	defer rows.Close()

	return r.scanRows(rows)
}

// ============================================================================
// Scope Computation (critical path for scoping middleware)
// ============================================================================

// GetUserScope computes the full ResourceScope for a user based on their team
// memberships and the teams' resource permissions.
// This is called once per request by the scoping middleware.
func (r *ResourcePermissionRepository) GetUserScope(ctx context.Context, userID uuid.UUID) (*models.ResourceScope, error) {
	scope := &models.ResourceScope{}

	// 1. Get user's team IDs
	teamRows, err := r.db.Query(ctx, `
		SELECT team_id FROM team_members WHERE user_id = $1`, userID)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to get user teams")
	}
	defer teamRows.Close()

	for teamRows.Next() {
		var tid uuid.UUID
		if err := teamRows.Scan(&tid); err != nil {
			return nil, err
		}
		scope.UserTeamIDs = append(scope.UserTeamIDs, tid)
	}
	if err := teamRows.Err(); err != nil {
		return nil, err
	}

	// No team memberships → user sees everything (unless there are teams they're not part of)
	// The Assigned* fields will still be populated so ShouldFilter logic works correctly.

	// 2. Get ALL resource permissions (all teams), marking which belong to user's teams.
	// Single query approach: fetch all permissions and classify client-side.
	permRows, err := r.db.Query(ctx, `
		SELECT resource_type, resource_id, team_id
		FROM resource_permissions`)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to get resource permissions")
	}
	defer permRows.Close()

	// Build a set of user team IDs for fast lookup
	userTeamSet := make(map[uuid.UUID]struct{}, len(scope.UserTeamIDs))
	for _, tid := range scope.UserTeamIDs {
		userTeamSet[tid] = struct{}{}
	}

	// Use maps to deduplicate
	allowedStacks := make(map[uuid.UUID]struct{})
	allowedGroups := make(map[string]struct{})
	allowedGitea := make(map[uuid.UUID]struct{})
	allowedS3 := make(map[uuid.UUID]struct{})
	assignedStacks := make(map[uuid.UUID]struct{})
	assignedGroups := make(map[string]struct{})
	assignedGitea := make(map[uuid.UUID]struct{})
	assignedS3 := make(map[uuid.UUID]struct{})

	for permRows.Next() {
		var rType string
		var rID string
		var teamID uuid.UUID
		if err := permRows.Scan(&rType, &rID, &teamID); err != nil {
			return nil, err
		}

		_, isUserTeam := userTeamSet[teamID]

		switch models.ResourceType(rType) {
		case models.ResourceTypeStack:
			if uid, err := uuid.Parse(rID); err == nil {
				assignedStacks[uid] = struct{}{}
				if isUserTeam {
					allowedStacks[uid] = struct{}{}
				}
			}
		case models.ResourceTypeContainerGroup:
			assignedGroups[rID] = struct{}{}
			if isUserTeam {
				allowedGroups[rID] = struct{}{}
			}
		case models.ResourceTypeGiteaConnection:
			if uid, err := uuid.Parse(rID); err == nil {
				assignedGitea[uid] = struct{}{}
				if isUserTeam {
					allowedGitea[uid] = struct{}{}
				}
			}
		case models.ResourceTypeS3Connection:
			if uid, err := uuid.Parse(rID); err == nil {
				assignedS3[uid] = struct{}{}
				if isUserTeam {
					allowedS3[uid] = struct{}{}
				}
			}
		}
	}
	if err := permRows.Err(); err != nil {
		return nil, err
	}

	// Convert maps to slices
	scope.AllowedStacks = mapKeysUUID(allowedStacks)
	scope.AllowedContainerGroups = mapKeysString(allowedGroups)
	scope.AllowedGiteaConns = mapKeysUUID(allowedGitea)
	scope.AllowedS3Conns = mapKeysUUID(allowedS3)
	scope.AssignedStacks = mapKeysUUID(assignedStacks)
	scope.AssignedContainerGroups = mapKeysString(assignedGroups)
	scope.AssignedGiteaConns = mapKeysUUID(assignedGitea)
	scope.AssignedS3Conns = mapKeysUUID(assignedS3)

	return scope, nil
}

func mapKeysUUID(m map[uuid.UUID]struct{}) []uuid.UUID {
	if len(m) == 0 {
		return nil
	}
	s := make([]uuid.UUID, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	return s
}

func mapKeysString(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	s := make([]string, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	return s
}

// GetAccessLevel checks the access level a user has for a specific resource
// through any of their team memberships.
func (r *ResourcePermissionRepository) GetAccessLevel(ctx context.Context, userID uuid.UUID, resourceType models.ResourceType, resourceID string) (models.AccessLevel, error) {
	var level string
	err := r.db.QueryRow(ctx, `
		SELECT rp.access_level
		FROM resource_permissions rp
		JOIN team_members tm ON tm.team_id = rp.team_id
		WHERE tm.user_id = $1
			AND rp.resource_type = $2
			AND rp.resource_id = $3
		ORDER BY CASE rp.access_level WHEN 'manage' THEN 1 ELSE 2 END
		LIMIT 1`,
		userID, resourceType, resourceID,
	).Scan(&level)

	if err != nil {
		if err == pgx.ErrNoRows {
			return "", nil // No access
		}
		return "", apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to check access level")
	}
	return models.AccessLevel(level), nil
}

// ============================================================================
// Helpers
// ============================================================================

func (r *ResourcePermissionRepository) scanRows(rows pgx.Rows) ([]*models.ResourcePermission, error) {
	var perms []*models.ResourcePermission
	for rows.Next() {
		var p models.ResourcePermission
		if err := rows.Scan(
			&p.ID, &p.TeamID, &p.ResourceType, &p.ResourceID,
			&p.AccessLevel, &p.GrantedAt, &p.GrantedBy,
		); err != nil {
			return nil, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to scan permission")
		}
		perms = append(perms, &p)
	}
	return perms, rows.Err()
}
