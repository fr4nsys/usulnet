// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package postgres provides PostgreSQL repository implementations.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/models"
)

// ContainerRepository handles container database operations.
// This repository manages the cached state of containers, not the containers themselves.
// The actual container operations are performed via Docker API.
type ContainerRepository struct {
	db *DB
}

// NewContainerRepository creates a new container repository.
func NewContainerRepository(db *DB) *ContainerRepository {
	return &ContainerRepository{db: db}
}

// ============================================================================
// CRUD Operations
// ============================================================================

// Upsert inserts or updates a container in the cache.
func (r *ContainerRepository) Upsert(ctx context.Context, container *models.Container) error {
	query := `
		INSERT INTO containers (
			id, host_id, name, image, image_id, status, state,
			created_at_docker, started_at, finished_at, ports, labels,
			env_vars, mounts, networks, restart_policy, current_version,
			latest_version, update_available, security_score, security_grade,
			last_scanned_at, synced_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
			$13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25
		)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			image = EXCLUDED.image,
			image_id = EXCLUDED.image_id,
			status = EXCLUDED.status,
			state = EXCLUDED.state,
			created_at_docker = EXCLUDED.created_at_docker,
			started_at = EXCLUDED.started_at,
			finished_at = EXCLUDED.finished_at,
			ports = EXCLUDED.ports,
			labels = EXCLUDED.labels,
			env_vars = EXCLUDED.env_vars,
			mounts = EXCLUDED.mounts,
			networks = EXCLUDED.networks,
			restart_policy = EXCLUDED.restart_policy,
			synced_at = EXCLUDED.synced_at,
			updated_at = EXCLUDED.updated_at`

	now := time.Now().UTC()
	container.SyncedAt = now
	container.UpdatedAt = now
	if container.CreatedAt.IsZero() {
		container.CreatedAt = now
	}

	// Serialize JSON fields - cast to string so pgx sends as text, not bytea
	portsJSON, _ := json.Marshal(container.Ports)
	labelsJSON, _ := json.Marshal(container.Labels)
	envVarsJSON, _ := json.Marshal(container.EnvVars)
	mountsJSON, _ := json.Marshal(container.Mounts)
	networksJSON, _ := json.Marshal(container.Networks)

	_, err := r.db.Exec(ctx, query,
		container.ID,
		container.HostID,
		container.Name,
		container.Image,
		container.ImageID,
		container.Status,
		container.State,
		container.CreatedAtDocker,
		container.StartedAt,
		container.FinishedAt,
		string(portsJSON),
		string(labelsJSON),
		string(envVarsJSON),
		string(mountsJSON),
		string(networksJSON),
		container.RestartPolicy,
		container.CurrentVersion,
		container.LatestVersion,
		container.UpdateAvailable,
		container.SecurityScore,
		container.SecurityGrade,
		container.LastScannedAt,
		container.SyncedAt,
		container.CreatedAt,
		container.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("upsert container: %w", err)
	}

	return nil
}

// UpsertBatch inserts or updates multiple containers efficiently.
func (r *ContainerRepository) UpsertBatch(ctx context.Context, containers []*models.Container) error {
	if len(containers) == 0 {
		return nil
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, container := range containers {
		if err := r.upsertInTx(ctx, tx, container); err != nil {
			return err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

func (r *ContainerRepository) upsertInTx(ctx context.Context, tx pgx.Tx, container *models.Container) error {
	query := `
		INSERT INTO containers (
			id, host_id, name, image, image_id, status, state,
			created_at_docker, started_at, finished_at, ports, labels,
			env_vars, mounts, networks, restart_policy, current_version,
			latest_version, update_available, security_score, security_grade,
			last_scanned_at, synced_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
			$13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25
		)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			image = EXCLUDED.image,
			image_id = EXCLUDED.image_id,
			status = EXCLUDED.status,
			state = EXCLUDED.state,
			created_at_docker = EXCLUDED.created_at_docker,
			started_at = EXCLUDED.started_at,
			finished_at = EXCLUDED.finished_at,
			ports = EXCLUDED.ports,
			labels = EXCLUDED.labels,
			env_vars = EXCLUDED.env_vars,
			mounts = EXCLUDED.mounts,
			networks = EXCLUDED.networks,
			restart_policy = EXCLUDED.restart_policy,
			synced_at = EXCLUDED.synced_at,
			updated_at = EXCLUDED.updated_at`

	now := time.Now().UTC()
	container.SyncedAt = now
	container.UpdatedAt = now
	if container.CreatedAt.IsZero() {
		container.CreatedAt = now
	}

	portsJSON, _ := json.Marshal(container.Ports)
	labelsJSON, _ := json.Marshal(container.Labels)
	envVarsJSON, _ := json.Marshal(container.EnvVars)
	mountsJSON, _ := json.Marshal(container.Mounts)
	networksJSON, _ := json.Marshal(container.Networks)

	_, err := tx.Exec(ctx, query,
		container.ID,
		container.HostID,
		container.Name,
		container.Image,
		container.ImageID,
		container.Status,
		container.State,
		container.CreatedAtDocker,
		container.StartedAt,
		container.FinishedAt,
		string(portsJSON),
		string(labelsJSON),
		string(envVarsJSON),
		string(mountsJSON),
		string(networksJSON),
		container.RestartPolicy,
		container.CurrentVersion,
		container.LatestVersion,
		container.UpdateAvailable,
		container.SecurityScore,
		container.SecurityGrade,
		container.LastScannedAt,
		container.SyncedAt,
		container.CreatedAt,
		container.UpdatedAt,
	)

	return err
}

// GetByID retrieves a container by ID.
func (r *ContainerRepository) GetByID(ctx context.Context, id string) (*models.Container, error) {
	query := `
		SELECT id, host_id, name, image, image_id, status, state,
			   created_at_docker, started_at, finished_at, ports, labels,
			   env_vars, mounts, networks, restart_policy, current_version,
			   latest_version, update_available, security_score, security_grade,
			   last_scanned_at, synced_at, created_at, updated_at
		FROM containers
		WHERE id = $1`

	return r.scanContainer(r.db.QueryRow(ctx, query, id))
}

// GetByHostAndID retrieves a container by host ID and container ID.
// Supports both full 64-char IDs and short prefix IDs (e.g. 12-char).
func (r *ContainerRepository) GetByHostAndID(ctx context.Context, hostID uuid.UUID, containerID string) (*models.Container, error) {
	// Try exact match first (most common case with full IDs)
	query := `
		SELECT id, host_id, name, image, image_id, status, state,
			   created_at_docker, started_at, finished_at, ports, labels,
			   env_vars, mounts, networks, restart_policy, current_version,
			   latest_version, update_available, security_score, security_grade,
			   last_scanned_at, synced_at, created_at, updated_at
		FROM containers
		WHERE host_id = $1 AND id = $2`

	c, err := r.scanContainer(r.db.QueryRow(ctx, query, hostID, containerID))
	if err == nil {
		return c, nil
	}

	// Fallback: prefix match for short container IDs
	if len(containerID) >= 12 && len(containerID) < 64 {
		prefixQuery := `
			SELECT id, host_id, name, image, image_id, status, state,
				   created_at_docker, started_at, finished_at, ports, labels,
				   env_vars, mounts, networks, restart_policy, current_version,
				   latest_version, update_available, security_score, security_grade,
				   last_scanned_at, synced_at, created_at, updated_at
			FROM containers
			WHERE host_id = $1 AND id LIKE $2 || '%'
			LIMIT 1`

		c, prefixErr := r.scanContainer(r.db.QueryRow(ctx, prefixQuery, hostID, containerID))
		if prefixErr == nil {
			return c, nil
		}
	}

	return nil, err
}

// GetByName retrieves a container by name within a host.
func (r *ContainerRepository) GetByName(ctx context.Context, hostID uuid.UUID, name string) (*models.Container, error) {
	// Docker container names start with /
	if !strings.HasPrefix(name, "/") {
		name = "/" + name
	}

	query := `
		SELECT id, host_id, name, image, image_id, status, state,
			   created_at_docker, started_at, finished_at, ports, labels,
			   env_vars, mounts, networks, restart_policy, current_version,
			   latest_version, update_available, security_score, security_grade,
			   last_scanned_at, synced_at, created_at, updated_at
		FROM containers
		WHERE host_id = $1 AND name = $2`

	return r.scanContainer(r.db.QueryRow(ctx, query, hostID, name))
}

// Delete removes a container from the cache.
func (r *ContainerRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM containers WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete container: %w", err)
	}

	if result.RowsAffected() == 0 {
		return apperrors.NotFound("container")
	}

	return nil
}

// DeleteByHost removes all containers for a host from the cache.
func (r *ContainerRepository) DeleteByHost(ctx context.Context, hostID uuid.UUID) (int64, error) {
	query := `DELETE FROM containers WHERE host_id = $1`

	result, err := r.db.Exec(ctx, query, hostID)
	if err != nil {
		return 0, fmt.Errorf("delete containers by host: %w", err)
	}

	return result.RowsAffected(), nil
}

// scanContainer scans a row into a Container model.
func (r *ContainerRepository) scanContainer(row pgx.Row) (*models.Container, error) {
	var (
		portsJSON    []byte
		labelsJSON   []byte
		envVarsJSON  []byte
		mountsJSON   []byte
		networksJSON []byte
	)

	container := &models.Container{}
	err := row.Scan(
		&container.ID,
		&container.HostID,
		&container.Name,
		&container.Image,
		&container.ImageID,
		&container.Status,
		&container.State,
		&container.CreatedAtDocker,
		&container.StartedAt,
		&container.FinishedAt,
		&portsJSON,
		&labelsJSON,
		&envVarsJSON,
		&mountsJSON,
		&networksJSON,
		&container.RestartPolicy,
		&container.CurrentVersion,
		&container.LatestVersion,
		&container.UpdateAvailable,
		&container.SecurityScore,
		&container.SecurityGrade,
		&container.LastScannedAt,
		&container.SyncedAt,
		&container.CreatedAt,
		&container.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.NotFound("container")
		}
		return nil, fmt.Errorf("scan container: %w", err)
	}

	// Deserialize JSON fields
	if len(portsJSON) > 0 {
		json.Unmarshal(portsJSON, &container.Ports)
	}
	if len(labelsJSON) > 0 {
		json.Unmarshal(labelsJSON, &container.Labels)
	}
	if len(envVarsJSON) > 0 {
		json.Unmarshal(envVarsJSON, &container.EnvVars)
	}
	if len(mountsJSON) > 0 {
		json.Unmarshal(mountsJSON, &container.Mounts)
	}
	if len(networksJSON) > 0 {
		json.Unmarshal(networksJSON, &container.Networks)
	}

	return container, nil
}

// ============================================================================
// List & Search
// ============================================================================

// ContainerListOptions contains options for listing containers.
type ContainerListOptions struct {
	Page     int
	PerPage  int
	HostID   *uuid.UUID              // Filter by host
	Search   string                  // Search in name and image
	State    *models.ContainerState  // Filter by state
	Image    string                  // Filter by image (partial match)
	Labels   map[string]string       // Filter by labels
	SortBy   string                  // Field to sort by
	SortDesc bool                    // Sort descending

	// Scoping fields (opt-in model)
	// Containers are scoped via stack inheritance + Docker label usulnet.team.group.
	ScopeEnabled           bool
	AllowedStackIDs        []uuid.UUID // stack IDs the user has access to
	AssignedStackIDs       []uuid.UUID // stack IDs claimed by ANY team
	AllowedContainerGroups []string    // container group labels the user has access to
	AssignedContainerGroups []string   // container group labels claimed by ANY team
}

// List retrieves containers with pagination and filtering.
func (r *ContainerRepository) List(ctx context.Context, opts ContainerListOptions) ([]*models.Container, int64, error) {
	// Build WHERE clause
	var conditions []string
	var args []interface{}
	argNum := 1

	if opts.HostID != nil {
		conditions = append(conditions, fmt.Sprintf("host_id = $%d", argNum))
		args = append(args, *opts.HostID)
		argNum++
	}

	if opts.Search != "" {
		conditions = append(conditions, fmt.Sprintf(
			"(LOWER(name) LIKE LOWER($%d) OR LOWER(image) LIKE LOWER($%d))",
			argNum, argNum,
		))
		args = append(args, "%"+opts.Search+"%")
		argNum++
	}

	if opts.State != nil {
		conditions = append(conditions, fmt.Sprintf("state = $%d", argNum))
		args = append(args, *opts.State)
		argNum++
	}

	if opts.Image != "" {
		conditions = append(conditions, fmt.Sprintf("LOWER(image) LIKE LOWER($%d)", argNum))
		args = append(args, "%"+opts.Image+"%")
		argNum++
	}

	// Label filtering using JSONB containment
	if len(opts.Labels) > 0 {
		labelsJSON, _ := json.Marshal(opts.Labels)
		conditions = append(conditions, fmt.Sprintf("labels @> $%d::jsonb", argNum))
		args = append(args, string(labelsJSON))
		argNum++
	}

	// Resource scoping (opt-in model):
	// Visible containers = allowed (via stack or group) OR unassigned.
	if opts.ScopeEnabled {
		hasAssignedStacks := len(opts.AssignedStackIDs) > 0
		hasAssignedGroups := len(opts.AssignedContainerGroups) > 0

		if !hasAssignedStacks && !hasAssignedGroups {
			// Nothing is assigned to any team → everything visible, no filter
		} else {
			// Build composite scoping condition
			var scopeParts []string

			// Part 1: Container belongs to an allowed stack (via compose project label)
			if len(opts.AllowedStackIDs) > 0 {
				scopeParts = append(scopeParts, fmt.Sprintf(
					"EXISTS (SELECT 1 FROM stacks s WHERE s.name = labels->>'com.docker.compose.project' AND s.host_id = host_id AND s.id = ANY($%d))",
					argNum,
				))
				args = append(args, opts.AllowedStackIDs)
				argNum++
			}

			// Part 2: Container has an allowed group label
			if len(opts.AllowedContainerGroups) > 0 {
				scopeParts = append(scopeParts, fmt.Sprintf(
					"labels->>'usulnet.team.group' = ANY($%d)",
					argNum,
				))
				args = append(args, opts.AllowedContainerGroups)
				argNum++
			}

			// Part 3: Container is unassigned (not in any assigned stack AND no assigned group label)
			unassignedParts := []string{}

			if hasAssignedStacks {
				unassignedParts = append(unassignedParts, fmt.Sprintf(
					"(labels->>'com.docker.compose.project' IS NULL OR NOT EXISTS (SELECT 1 FROM stacks s WHERE s.name = labels->>'com.docker.compose.project' AND s.host_id = host_id AND s.id = ANY($%d)))",
					argNum,
				))
				args = append(args, opts.AssignedStackIDs)
				argNum++
			}

			if hasAssignedGroups {
				unassignedParts = append(unassignedParts, fmt.Sprintf(
					"(labels->>'usulnet.team.group' IS NULL OR labels->>'usulnet.team.group' = '' OR NOT (labels->>'usulnet.team.group' = ANY($%d)))",
					argNum,
				))
				args = append(args, opts.AssignedContainerGroups)
				argNum++
			}

			if len(unassignedParts) > 0 {
				scopeParts = append(scopeParts, "("+strings.Join(unassignedParts, " AND ")+")")
			}

			if len(scopeParts) > 0 {
				conditions = append(conditions, "("+strings.Join(scopeParts, " OR ")+")")
			}
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM containers %s", whereClause)
	var total int64
	if err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count containers: %w", err)
	}

	// Build ORDER BY
	sortField := "name"
	allowedSortFields := map[string]bool{
		"name": true, "image": true, "state": true, "status": true,
		"created_at": true, "synced_at": true, "security_score": true,
	}
	if opts.SortBy != "" && allowedSortFields[opts.SortBy] {
		sortField = opts.SortBy
	}

	sortOrder := "ASC"
	if opts.SortDesc {
		sortOrder = "DESC"
	}

	// Pagination
	if opts.Page < 1 {
		opts.Page = 1
	}
	if opts.PerPage < 1 || opts.PerPage > 10000 {
		opts.PerPage = 20
	}
	offset := (opts.Page - 1) * opts.PerPage

	// Query containers
	query := fmt.Sprintf(`
		SELECT id, host_id, name, image, image_id, status, state,
			   created_at_docker, started_at, finished_at, ports, labels,
			   env_vars, mounts, networks, restart_policy, current_version,
			   latest_version, update_available, security_score, security_grade,
			   last_scanned_at, synced_at, created_at, updated_at
		FROM containers
		%s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d`,
		whereClause, sortField, sortOrder, argNum, argNum+1,
	)
	args = append(args, opts.PerPage, offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list containers: %w", err)
	}
	defer rows.Close()

	containers, err := r.scanContainers(rows)
	if err != nil {
		return nil, 0, err
	}

	return containers, total, nil
}

// ListByHost retrieves all containers for a specific host.
func (r *ContainerRepository) ListByHost(ctx context.Context, hostID uuid.UUID) ([]*models.Container, error) {
	containers, _, err := r.List(ctx, ContainerListOptions{
		HostID:  &hostID,
		PerPage: 10000, // Get all
	})
	return containers, err
}

// ListRunning retrieves all running containers.
func (r *ContainerRepository) ListRunning(ctx context.Context, hostID *uuid.UUID) ([]*models.Container, error) {
	state := models.ContainerStateRunning
	containers, _, err := r.List(ctx, ContainerListOptions{
		HostID:  hostID,
		State:   &state,
		PerPage: 10000,
	})
	return containers, err
}

// ListWithUpdatesAvailable retrieves containers with available updates.
func (r *ContainerRepository) ListWithUpdatesAvailable(ctx context.Context, hostID *uuid.UUID) ([]*models.Container, error) {
	query := `
		SELECT id, host_id, name, image, image_id, status, state,
			   created_at_docker, started_at, finished_at, ports, labels,
			   env_vars, mounts, networks, restart_policy, current_version,
			   latest_version, update_available, security_score, security_grade,
			   last_scanned_at, synced_at, created_at, updated_at
		FROM containers
		WHERE update_available = true`

	args := []interface{}{}
	if hostID != nil {
		query += " AND host_id = $1"
		args = append(args, *hostID)
	}

	query += " ORDER BY name"

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list containers with updates: %w", err)
	}
	defer rows.Close()

	return r.scanContainers(rows)
}

// ListBySecurityGrade retrieves containers by security grade.
func (r *ContainerRepository) ListBySecurityGrade(ctx context.Context, grade string, hostID *uuid.UUID) ([]*models.Container, error) {
	query := `
		SELECT id, host_id, name, image, image_id, status, state,
			   created_at_docker, started_at, finished_at, ports, labels,
			   env_vars, mounts, networks, restart_policy, current_version,
			   latest_version, update_available, security_score, security_grade,
			   last_scanned_at, synced_at, created_at, updated_at
		FROM containers
		WHERE security_grade = $1`

	args := []interface{}{grade}
	if hostID != nil {
		query += " AND host_id = $2"
		args = append(args, *hostID)
	}

	query += " ORDER BY security_score ASC, name"

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list containers by grade: %w", err)
	}
	defer rows.Close()

	return r.scanContainers(rows)
}

// scanContainers scans multiple rows into Container models.
func (r *ContainerRepository) scanContainers(rows pgx.Rows) ([]*models.Container, error) {
	var containers []*models.Container
	for rows.Next() {
		var (
			portsJSON    []byte
			labelsJSON   []byte
			envVarsJSON  []byte
			mountsJSON   []byte
			networksJSON []byte
		)

		container := &models.Container{}
		if err := rows.Scan(
			&container.ID,
			&container.HostID,
			&container.Name,
			&container.Image,
			&container.ImageID,
			&container.Status,
			&container.State,
			&container.CreatedAtDocker,
			&container.StartedAt,
			&container.FinishedAt,
			&portsJSON,
			&labelsJSON,
			&envVarsJSON,
			&mountsJSON,
			&networksJSON,
			&container.RestartPolicy,
			&container.CurrentVersion,
			&container.LatestVersion,
			&container.UpdateAvailable,
			&container.SecurityScore,
			&container.SecurityGrade,
			&container.LastScannedAt,
			&container.SyncedAt,
			&container.CreatedAt,
			&container.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan container: %w", err)
		}

		// Deserialize JSON
		if len(portsJSON) > 0 {
			json.Unmarshal(portsJSON, &container.Ports)
		}
		if len(labelsJSON) > 0 {
			json.Unmarshal(labelsJSON, &container.Labels)
		}
		if len(envVarsJSON) > 0 {
			json.Unmarshal(envVarsJSON, &container.EnvVars)
		}
		if len(mountsJSON) > 0 {
			json.Unmarshal(mountsJSON, &container.Mounts)
		}
		if len(networksJSON) > 0 {
			json.Unmarshal(networksJSON, &container.Networks)
		}

		containers = append(containers, container)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate containers: %w", err)
	}

	return containers, nil
}

// ============================================================================
// Update Operations
// ============================================================================

// UpdateState updates only the container state.
func (r *ContainerRepository) UpdateState(ctx context.Context, id string, state models.ContainerState, status string) error {
	query := `
		UPDATE containers SET
			state = $2,
			status = $3,
			synced_at = $4,
			updated_at = $4
		WHERE id = $1`

	now := time.Now().UTC()
	result, err := r.db.Exec(ctx, query, id, state, status, now)
	if err != nil {
		return fmt.Errorf("update container state: %w", err)
	}

	if result.RowsAffected() == 0 {
		return apperrors.NotFound("container")
	}

	return nil
}

// UpdateVersionInfo updates version-related fields.
func (r *ContainerRepository) UpdateVersionInfo(ctx context.Context, id string, currentVersion, latestVersion string, updateAvailable bool) error {
	query := `
		UPDATE containers SET
			current_version = $2,
			latest_version = $3,
			update_available = $4,
			updated_at = $5
		WHERE id = $1`

	now := time.Now().UTC()
	result, err := r.db.Exec(ctx, query, id, currentVersion, latestVersion, updateAvailable, now)
	if err != nil {
		return fmt.Errorf("update version info: %w", err)
	}

	if result.RowsAffected() == 0 {
		return apperrors.NotFound("container")
	}

	return nil
}

// UpdateSecurityInfo updates security-related fields.
func (r *ContainerRepository) UpdateSecurityInfo(ctx context.Context, id string, score int, grade string) error {
	query := `
		UPDATE containers SET
			security_score = $2,
			security_grade = $3,
			last_scanned_at = $4,
			updated_at = $4
		WHERE id = $1`

	now := time.Now().UTC()
	result, err := r.db.Exec(ctx, query, id, score, grade, now)
	if err != nil {
		return fmt.Errorf("update security info: %w", err)
	}

	if result.RowsAffected() == 0 {
		return apperrors.NotFound("container")
	}

	return nil
}

// ClearUpdateAvailable clears the update available flag after update.
func (r *ContainerRepository) ClearUpdateAvailable(ctx context.Context, id string) error {
	query := `
		UPDATE containers SET
			update_available = false,
			updated_at = $2
		WHERE id = $1`

	now := time.Now().UTC()
	_, err := r.db.Exec(ctx, query, id, now)
	return err
}

// ============================================================================
// Statistics
// ============================================================================

// ContainerStats contains container statistics.
type ContainerStats struct {
	Total           int64 `json:"total"`
	Running         int64 `json:"running"`
	Stopped         int64 `json:"stopped"`
	Paused          int64 `json:"paused"`
	Exited          int64 `json:"exited"`
	Dead            int64 `json:"dead"`
	UpdatesAvailable int64 `json:"updates_available"`
	GradeA          int64 `json:"grade_a"`
	GradeB          int64 `json:"grade_b"`
	GradeC          int64 `json:"grade_c"`
	GradeD          int64 `json:"grade_d"`
	GradeF          int64 `json:"grade_f"`
}

// GetStats retrieves container statistics.
func (r *ContainerRepository) GetStats(ctx context.Context, hostID *uuid.UUID) (*ContainerStats, error) {
	query := `
		SELECT 
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE state = 'running') as running,
			COUNT(*) FILTER (WHERE state = 'exited' AND status NOT LIKE 'Exited (0)%') as stopped,
			COUNT(*) FILTER (WHERE state = 'paused') as paused,
			COUNT(*) FILTER (WHERE state = 'exited') as exited,
			COUNT(*) FILTER (WHERE state = 'dead') as dead,
			COUNT(*) FILTER (WHERE update_available = true) as updates_available,
			COUNT(*) FILTER (WHERE security_grade = 'A') as grade_a,
			COUNT(*) FILTER (WHERE security_grade = 'B') as grade_b,
			COUNT(*) FILTER (WHERE security_grade = 'C') as grade_c,
			COUNT(*) FILTER (WHERE security_grade = 'D') as grade_d,
			COUNT(*) FILTER (WHERE security_grade = 'F') as grade_f
		FROM containers`

	args := []interface{}{}
	if hostID != nil {
		query += " WHERE host_id = $1"
		args = append(args, *hostID)
	}

	stats := &ContainerStats{}
	err := r.db.QueryRow(ctx, query, args...).Scan(
		&stats.Total,
		&stats.Running,
		&stats.Stopped,
		&stats.Paused,
		&stats.Exited,
		&stats.Dead,
		&stats.UpdatesAvailable,
		&stats.GradeA,
		&stats.GradeB,
		&stats.GradeC,
		&stats.GradeD,
		&stats.GradeF,
	)

	if err != nil {
		return nil, fmt.Errorf("get container stats: %w", err)
	}

	return stats, nil
}

// GetStatsByHost retrieves container stats grouped by host.
func (r *ContainerRepository) GetStatsByHost(ctx context.Context) (map[uuid.UUID]*ContainerStats, error) {
	query := `
		SELECT 
			host_id,
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE state = 'running') as running,
			COUNT(*) FILTER (WHERE state = 'exited' AND status NOT LIKE 'Exited (0)%') as stopped,
			COUNT(*) FILTER (WHERE state = 'paused') as paused,
			COUNT(*) FILTER (WHERE state = 'exited') as exited,
			COUNT(*) FILTER (WHERE state = 'dead') as dead,
			COUNT(*) FILTER (WHERE update_available = true) as updates_available,
			COUNT(*) FILTER (WHERE security_grade = 'A') as grade_a,
			COUNT(*) FILTER (WHERE security_grade = 'B') as grade_b,
			COUNT(*) FILTER (WHERE security_grade = 'C') as grade_c,
			COUNT(*) FILTER (WHERE security_grade = 'D') as grade_d,
			COUNT(*) FILTER (WHERE security_grade = 'F') as grade_f
		FROM containers
		GROUP BY host_id`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("get stats by host: %w", err)
	}
	defer rows.Close()

	result := make(map[uuid.UUID]*ContainerStats)
	for rows.Next() {
		var hostID uuid.UUID
		stats := &ContainerStats{}
		if err := rows.Scan(
			&hostID,
			&stats.Total,
			&stats.Running,
			&stats.Stopped,
			&stats.Paused,
			&stats.Exited,
			&stats.Dead,
			&stats.UpdatesAvailable,
			&stats.GradeA,
			&stats.GradeB,
			&stats.GradeC,
			&stats.GradeD,
			&stats.GradeF,
		); err != nil {
			return nil, fmt.Errorf("scan stats: %w", err)
		}
		result[hostID] = stats
	}

	return result, rows.Err()
}

// ============================================================================
// Sync Operations
// ============================================================================

// GetStaleContainers retrieves containers not synced recently.
func (r *ContainerRepository) GetStaleContainers(ctx context.Context, hostID uuid.UUID, threshold time.Duration) ([]*models.Container, error) {
	query := `
		SELECT id, host_id, name, image, image_id, status, state,
			   created_at_docker, started_at, finished_at, ports, labels,
			   env_vars, mounts, networks, restart_policy, current_version,
			   latest_version, update_available, security_score, security_grade,
			   last_scanned_at, synced_at, created_at, updated_at
		FROM containers
		WHERE host_id = $1 AND synced_at < $2`

	cutoff := time.Now().UTC().Add(-threshold)
	rows, err := r.db.Query(ctx, query, hostID, cutoff)
	if err != nil {
		return nil, fmt.Errorf("get stale containers: %w", err)
	}
	defer rows.Close()

	return r.scanContainers(rows)
}

// DeleteStaleContainers removes containers not synced recently (likely removed from Docker).
func (r *ContainerRepository) DeleteStaleContainers(ctx context.Context, hostID uuid.UUID, threshold time.Duration) (int64, error) {
	query := `DELETE FROM containers WHERE host_id = $1 AND synced_at < $2`

	cutoff := time.Now().UTC().Add(-threshold)
	result, err := r.db.Exec(ctx, query, hostID, cutoff)
	if err != nil {
		return 0, fmt.Errorf("delete stale containers: %w", err)
	}

	return result.RowsAffected(), nil
}

// GetContainerIDs retrieves all container IDs for a host (for sync comparison).
func (r *ContainerRepository) GetContainerIDs(ctx context.Context, hostID uuid.UUID) ([]string, error) {
	query := `SELECT id FROM containers WHERE host_id = $1`

	rows, err := r.db.Query(ctx, query, hostID)
	if err != nil {
		return nil, fmt.Errorf("get container ids: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan id: %w", err)
		}
		ids = append(ids, id)
	}

	return ids, rows.Err()
}

// ============================================================================
// Container Metrics (Stats History)
// ============================================================================

// InsertStats inserts container stats.
func (r *ContainerRepository) InsertStats(ctx context.Context, stats *models.ContainerStats) error {
	query := `
		INSERT INTO container_stats (
			container_id, host_id, cpu_percent, memory_usage, memory_limit,
			memory_percent, network_rx_bytes, network_tx_bytes, block_read,
			block_write, pids, collected_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	_, err := r.db.Exec(ctx, query,
		stats.ContainerID,
		stats.HostID,
		stats.CPUPercent,
		stats.MemoryUsage,
		stats.MemoryLimit,
		stats.MemoryPercent,
		stats.NetworkRxBytes,
		stats.NetworkTxBytes,
		stats.BlockRead,
		stats.BlockWrite,
		stats.PIDs,
		stats.CollectedAt,
	)

	if err != nil {
		return fmt.Errorf("insert container stats: %w", err)
	}

	return nil
}

// GetLatestStats retrieves the latest stats for a container.
func (r *ContainerRepository) GetLatestStats(ctx context.Context, containerID string) (*models.ContainerStats, error) {
	query := `
		SELECT id, container_id, host_id, cpu_percent, memory_usage, memory_limit,
			   memory_percent, network_rx_bytes, network_tx_bytes, block_read,
			   block_write, pids, collected_at
		FROM container_stats
		WHERE container_id = $1
		ORDER BY collected_at DESC
		LIMIT 1`

	stats := &models.ContainerStats{}
	err := r.db.QueryRow(ctx, query, containerID).Scan(
		&stats.ID,
		&stats.ContainerID,
		&stats.HostID,
		&stats.CPUPercent,
		&stats.MemoryUsage,
		&stats.MemoryLimit,
		&stats.MemoryPercent,
		&stats.NetworkRxBytes,
		&stats.NetworkTxBytes,
		&stats.BlockRead,
		&stats.BlockWrite,
		&stats.PIDs,
		&stats.CollectedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.NotFound("container stats")
		}
		return nil, fmt.Errorf("get latest stats: %w", err)
	}

	return stats, nil
}

// GetStatsHistory retrieves stats history for a container.
func (r *ContainerRepository) GetStatsHistory(ctx context.Context, containerID string, since time.Time, limit int) ([]*models.ContainerStats, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	query := `
		SELECT id, container_id, host_id, cpu_percent, memory_usage, memory_limit,
			   memory_percent, network_rx_bytes, network_tx_bytes, block_read,
			   block_write, pids, collected_at
		FROM container_stats
		WHERE container_id = $1 AND collected_at >= $2
		ORDER BY collected_at DESC
		LIMIT $3`

	rows, err := r.db.Query(ctx, query, containerID, since, limit)
	if err != nil {
		return nil, fmt.Errorf("get stats history: %w", err)
	}
	defer rows.Close()

	var statsList []*models.ContainerStats
	for rows.Next() {
		stats := &models.ContainerStats{}
		if err := rows.Scan(
			&stats.ID,
			&stats.ContainerID,
			&stats.HostID,
			&stats.CPUPercent,
			&stats.MemoryUsage,
			&stats.MemoryLimit,
			&stats.MemoryPercent,
			&stats.NetworkRxBytes,
			&stats.NetworkTxBytes,
			&stats.BlockRead,
			&stats.BlockWrite,
			&stats.PIDs,
			&stats.CollectedAt,
		); err != nil {
			return nil, fmt.Errorf("scan stats: %w", err)
		}
		statsList = append(statsList, stats)
	}

	return statsList, rows.Err()
}

// DeleteOldStats deletes stats older than the specified duration.
func (r *ContainerRepository) DeleteOldStats(ctx context.Context, olderThan time.Duration) (int64, error) {
	query := `DELETE FROM container_stats WHERE collected_at < $1`

	threshold := time.Now().UTC().Add(-olderThan)
	result, err := r.db.Exec(ctx, query, threshold)
	if err != nil {
		return 0, fmt.Errorf("delete old stats: %w", err)
	}

	return result.RowsAffected(), nil
}

// ============================================================================
// Container Logs (Optional Persistence)
// ============================================================================

// InsertLog inserts a container log entry.
func (r *ContainerRepository) InsertLog(ctx context.Context, log *models.ContainerLogEntry) error {
	query := `
		INSERT INTO container_logs (container_id, host_id, stream, message, timestamp)
		VALUES ($1, $2, $3, $4, $5)`

	_, err := r.db.Exec(ctx, query,
		log.ContainerID,
		log.HostID,
		log.Stream,
		log.Message,
		log.Timestamp,
	)

	return err
}

// GetLogs retrieves logs for a container.
func (r *ContainerRepository) GetLogs(ctx context.Context, containerID string, limit int, since *time.Time) ([]*models.ContainerLogEntry, error) {
	if limit <= 0 || limit > 10000 {
		limit = 500
	}

	query := `
		SELECT id, container_id, host_id, stream, message, timestamp
		FROM container_logs
		WHERE container_id = $1`

	args := []interface{}{containerID}
	argNum := 2

	if since != nil {
		query += fmt.Sprintf(" AND timestamp >= $%d", argNum)
		args = append(args, *since)
		argNum++
	}

	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT $%d", argNum)
	args = append(args, limit)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get logs: %w", err)
	}
	defer rows.Close()

	var logs []*models.ContainerLogEntry
	for rows.Next() {
		log := &models.ContainerLogEntry{}
		if err := rows.Scan(
			&log.ID,
			&log.ContainerID,
			&log.HostID,
			&log.Stream,
			&log.Message,
			&log.Timestamp,
		); err != nil {
			return nil, fmt.Errorf("scan log: %w", err)
		}
		logs = append(logs, log)
	}

	return logs, rows.Err()
}

// DeleteOldLogs deletes logs older than the specified duration.
func (r *ContainerRepository) DeleteOldLogs(ctx context.Context, olderThan time.Duration) (int64, error) {
	query := `DELETE FROM container_logs WHERE timestamp < $1`

	threshold := time.Now().UTC().Add(-olderThan)
	result, err := r.db.Exec(ctx, query, threshold)
	if err != nil {
		return 0, fmt.Errorf("delete old logs: %w", err)
	}

	return result.RowsAffected(), nil
}
