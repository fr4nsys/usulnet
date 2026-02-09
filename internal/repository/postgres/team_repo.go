// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/models"
)

// TeamRepository handles team database operations.
type TeamRepository struct {
	db *DB
}

// NewTeamRepository creates a new team repository.
func NewTeamRepository(db *DB) *TeamRepository {
	return &TeamRepository{db: db}
}

// ============================================================================
// Team CRUD
// ============================================================================

// Create inserts a new team.
func (r *TeamRepository) Create(ctx context.Context, team *models.Team) error {
	if team.ID == uuid.Nil {
		team.ID = uuid.New()
	}
	now := time.Now().UTC()
	team.CreatedAt = now
	team.UpdatedAt = now

	_, err := r.db.Exec(ctx, `
		INSERT INTO teams (id, name, description, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		team.ID, team.Name, team.Description, team.CreatedBy,
		team.CreatedAt, team.UpdatedAt,
	)
	if err != nil {
		return apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to create team")
	}
	return nil
}

// GetByID returns a team by ID with member/permission counts.
func (r *TeamRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Team, error) {
	query := `
		SELECT t.id, t.name, t.description, t.created_by, t.created_at, t.updated_at,
			COALESCE((SELECT COUNT(*) FROM team_members WHERE team_id = t.id), 0) AS member_count,
			COALESCE((SELECT COUNT(*) FROM resource_permissions WHERE team_id = t.id), 0) AS permission_count
		FROM teams t
		WHERE t.id = $1`

	var team models.Team
	err := r.db.QueryRow(ctx, query, id).Scan(
		&team.ID, &team.Name, &team.Description, &team.CreatedBy,
		&team.CreatedAt, &team.UpdatedAt,
		&team.MemberCount, &team.PermissionCount,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.New(apperrors.CodeNotFound, "team not found")
		}
		return nil, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to get team")
	}
	return &team, nil
}

// GetByName returns a team by name.
func (r *TeamRepository) GetByName(ctx context.Context, name string) (*models.Team, error) {
	query := `
		SELECT t.id, t.name, t.description, t.created_by, t.created_at, t.updated_at,
			COALESCE((SELECT COUNT(*) FROM team_members WHERE team_id = t.id), 0) AS member_count,
			COALESCE((SELECT COUNT(*) FROM resource_permissions WHERE team_id = t.id), 0) AS permission_count
		FROM teams t
		WHERE t.name = $1`

	var team models.Team
	err := r.db.QueryRow(ctx, query, name).Scan(
		&team.ID, &team.Name, &team.Description, &team.CreatedBy,
		&team.CreatedAt, &team.UpdatedAt,
		&team.MemberCount, &team.PermissionCount,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.New(apperrors.CodeNotFound, "team not found")
		}
		return nil, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to get team by name")
	}
	return &team, nil
}

// List returns all teams with member/permission counts.
func (r *TeamRepository) List(ctx context.Context) ([]*models.Team, error) {
	query := `
		SELECT t.id, t.name, t.description, t.created_by, t.created_at, t.updated_at,
			COALESCE((SELECT COUNT(*) FROM team_members WHERE team_id = t.id), 0) AS member_count,
			COALESCE((SELECT COUNT(*) FROM resource_permissions WHERE team_id = t.id), 0) AS permission_count
		FROM teams t
		ORDER BY t.name ASC`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to list teams")
	}
	defer rows.Close()

	var teams []*models.Team
	for rows.Next() {
		var t models.Team
		if err := rows.Scan(
			&t.ID, &t.Name, &t.Description, &t.CreatedBy,
			&t.CreatedAt, &t.UpdatedAt,
			&t.MemberCount, &t.PermissionCount,
		); err != nil {
			return nil, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to scan team")
		}
		teams = append(teams, &t)
	}
	return teams, rows.Err()
}

// Count returns the total number of teams.
func (r *TeamRepository) Count(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM teams`).Scan(&count)
	if err != nil {
		return 0, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to count teams")
	}
	return count, nil
}

// Update modifies a team's name and description.
func (r *TeamRepository) Update(ctx context.Context, team *models.Team) error {
	tag, err := r.db.Exec(ctx, `
		UPDATE teams SET name = $2, description = $3, updated_at = NOW()
		WHERE id = $1`,
		team.ID, team.Name, team.Description,
	)
	if err != nil {
		return apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to update team")
	}
	if tag.RowsAffected() == 0 {
		return apperrors.New(apperrors.CodeNotFound, "team not found")
	}
	return nil
}

// Delete removes a team and all associated members/permissions (cascade).
func (r *TeamRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM teams WHERE id = $1`, id)
	if err != nil {
		return apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to delete team")
	}
	if tag.RowsAffected() == 0 {
		return apperrors.New(apperrors.CodeNotFound, "team not found")
	}
	return nil
}

// Exists checks if any teams exist at all (for backward compat scoping logic).
func (r *TeamRepository) Exists(ctx context.Context) (bool, error) {
	var exists bool
	err := r.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM teams)`).Scan(&exists)
	if err != nil {
		return false, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to check teams existence")
	}
	return exists, nil
}

// ============================================================================
// Team Members
// ============================================================================

// AddMember adds a user to a team.
func (r *TeamRepository) AddMember(ctx context.Context, member *models.TeamMember) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO team_members (team_id, user_id, role_in_team, added_at, added_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (team_id, user_id) DO UPDATE SET role_in_team = $3`,
		member.TeamID, member.UserID, member.RoleInTeam,
		time.Now().UTC(), member.AddedBy,
	)
	if err != nil {
		return apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to add team member")
	}
	return nil
}

// RemoveMember removes a user from a team.
func (r *TeamRepository) RemoveMember(ctx context.Context, teamID, userID uuid.UUID) error {
	tag, err := r.db.Exec(ctx, `
		DELETE FROM team_members WHERE team_id = $1 AND user_id = $2`,
		teamID, userID,
	)
	if err != nil {
		return apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to remove team member")
	}
	if tag.RowsAffected() == 0 {
		return apperrors.New(apperrors.CodeNotFound, "team member not found")
	}
	return nil
}

// ListMembers returns all members of a team with user info.
func (r *TeamRepository) ListMembers(ctx context.Context, teamID uuid.UUID) ([]*models.TeamMember, error) {
	query := `
		SELECT tm.team_id, tm.user_id, tm.role_in_team, tm.added_at, tm.added_by,
			u.username, COALESCE(u.email, '') AS email
		FROM team_members tm
		JOIN users u ON u.id = tm.user_id
		WHERE tm.team_id = $1
		ORDER BY tm.role_in_team ASC, u.username ASC`

	rows, err := r.db.Query(ctx, query, teamID)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to list team members")
	}
	defer rows.Close()

	var members []*models.TeamMember
	for rows.Next() {
		var m models.TeamMember
		if err := rows.Scan(
			&m.TeamID, &m.UserID, &m.RoleInTeam, &m.AddedAt, &m.AddedBy,
			&m.Username, &m.Email,
		); err != nil {
			return nil, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to scan team member")
		}
		members = append(members, &m)
	}
	return members, rows.Err()
}

// GetUserTeamIDs returns all team IDs that a user belongs to.
func (r *TeamRepository) GetUserTeamIDs(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := r.db.Query(ctx, `
		SELECT team_id FROM team_members WHERE user_id = $1`, userID)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to get user team IDs")
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ListTeamsForUser returns all teams a user belongs to.
func (r *TeamRepository) ListTeamsForUser(ctx context.Context, userID uuid.UUID) ([]*models.Team, error) {
	query := `
		SELECT t.id, t.name, t.description, t.created_by, t.created_at, t.updated_at,
			COALESCE((SELECT COUNT(*) FROM team_members WHERE team_id = t.id), 0) AS member_count,
			COALESCE((SELECT COUNT(*) FROM resource_permissions WHERE team_id = t.id), 0) AS permission_count
		FROM teams t
		JOIN team_members tm ON tm.team_id = t.id
		WHERE tm.user_id = $1
		ORDER BY t.name ASC`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to list teams for user")
	}
	defer rows.Close()

	var teams []*models.Team
	for rows.Next() {
		var t models.Team
		if err := rows.Scan(
			&t.ID, &t.Name, &t.Description, &t.CreatedBy,
			&t.CreatedAt, &t.UpdatedAt,
			&t.MemberCount, &t.PermissionCount,
		); err != nil {
			return nil, err
		}
		teams = append(teams, &t)
	}
	return teams, rows.Err()
}

// IsMember checks if a user is a member of a team.
func (r *TeamRepository) IsMember(ctx context.Context, teamID, userID uuid.UUID) (bool, error) {
	var exists bool
	err := r.db.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2
		)`, teamID, userID).Scan(&exists)
	if err != nil {
		return false, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to check team membership")
	}
	return exists, nil
}

// IsOwner checks if a user is an owner of a team.
func (r *TeamRepository) IsOwner(ctx context.Context, teamID, userID uuid.UUID) (bool, error) {
	var exists bool
	err := r.db.QueryRow(ctx, fmt.Sprintf(`
		SELECT EXISTS(
			SELECT 1 FROM team_members
			WHERE team_id = $1 AND user_id = $2 AND role_in_team = '%s'
		)`, models.TeamRoleOwner), teamID, userID).Scan(&exists)
	if err != nil {
		return false, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to check team ownership")
	}
	return exists, nil
}
