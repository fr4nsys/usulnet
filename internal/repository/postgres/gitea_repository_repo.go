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

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
)

// GiteaRepositoryRepository handles Gitea repository persistence.
type GiteaRepositoryRepository struct {
	db *DB
}

// NewGiteaRepositoryRepository creates a new Gitea repository repository.
func NewGiteaRepositoryRepository(db *DB) *GiteaRepositoryRepository {
	return &GiteaRepositoryRepository{db: db}
}

const giteaRepoColumns = `id, connection_id, gitea_id, full_name, description,
	clone_url, html_url, default_branch, is_private, is_fork, is_archived,
	stars_count, forks_count, open_issues, size_kb,
	last_commit_sha, last_commit_at, last_sync_at,
	created_at, updated_at`

// Upsert inserts or updates a Gitea repository (keyed on connection_id + gitea_id).
func (r *GiteaRepositoryRepository) Upsert(ctx context.Context, repo *models.GiteaRepository) error {
	if repo.ID == uuid.Nil {
		repo.ID = uuid.New()
	}
	now := time.Now()
	repo.UpdatedAt = now
	repo.LastSyncAt = &now

	query := `
		INSERT INTO gitea_repositories (
			id, connection_id, gitea_id, full_name, description,
			clone_url, html_url, default_branch, is_private, is_fork, is_archived,
			stars_count, forks_count, open_issues, size_kb,
			last_commit_sha, last_commit_at, last_sync_at,
			created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
		ON CONFLICT (connection_id, gitea_id) DO UPDATE SET
			full_name = EXCLUDED.full_name,
			description = EXCLUDED.description,
			clone_url = EXCLUDED.clone_url,
			html_url = EXCLUDED.html_url,
			default_branch = EXCLUDED.default_branch,
			is_private = EXCLUDED.is_private,
			is_fork = EXCLUDED.is_fork,
			is_archived = EXCLUDED.is_archived,
			stars_count = EXCLUDED.stars_count,
			forks_count = EXCLUDED.forks_count,
			open_issues = EXCLUDED.open_issues,
			size_kb = EXCLUDED.size_kb,
			last_commit_sha = EXCLUDED.last_commit_sha,
			last_commit_at = EXCLUDED.last_commit_at,
			last_sync_at = EXCLUDED.last_sync_at,
			updated_at = EXCLUDED.updated_at`

	_, err := r.db.Exec(ctx, query,
		repo.ID, repo.ConnectionID, repo.GiteaID, repo.FullName, repo.Description,
		repo.CloneURL, repo.HTMLURL, repo.DefaultBranch, repo.IsPrivate, repo.IsFork, repo.IsArchived,
		repo.StarsCount, repo.ForksCount, repo.OpenIssues, repo.SizeKB,
		repo.LastCommitSHA, repo.LastCommitAt, repo.LastSyncAt,
		repo.CreatedAt, repo.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to upsert gitea repository")
	}
	return nil
}

// ListByConnection returns all repositories for a connection.
func (r *GiteaRepositoryRepository) ListByConnection(ctx context.Context, connectionID uuid.UUID) ([]*models.GiteaRepository, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM gitea_repositories
		WHERE connection_id = $1
		ORDER BY full_name ASC`, giteaRepoColumns)

	rows, err := r.db.Query(ctx, query, connectionID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list gitea repositories")
	}
	defer rows.Close()

	return scanGiteaRepoRows(rows)
}

// GetByID returns a Gitea repository by ID.
func (r *GiteaRepositoryRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.GiteaRepository, error) {
	query := fmt.Sprintf(`SELECT %s FROM gitea_repositories WHERE id = $1`, giteaRepoColumns)
	row := r.db.QueryRow(ctx, query, id)
	repo, err := scanGiteaRepoRow(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.New(errors.CodeNotFound, "gitea repository not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get gitea repository")
	}
	return repo, nil
}

// GetByGiteaID returns a repo by its Gitea-side ID within a connection.
func (r *GiteaRepositoryRepository) GetByGiteaID(ctx context.Context, connectionID uuid.UUID, giteaID int64) (*models.GiteaRepository, error) {
	query := fmt.Sprintf(`SELECT %s FROM gitea_repositories WHERE connection_id = $1 AND gitea_id = $2`, giteaRepoColumns)
	row := r.db.QueryRow(ctx, query, connectionID, giteaID)
	repo, err := scanGiteaRepoRow(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get gitea repository by gitea_id")
	}
	return repo, nil
}

// DeleteByConnection removes all repositories for a connection.
func (r *GiteaRepositoryRepository) DeleteByConnection(ctx context.Context, connectionID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM gitea_repositories WHERE connection_id = $1`, connectionID)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete gitea repositories")
	}
	return nil
}

// Delete removes a single repository by ID.
func (r *GiteaRepositoryRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM gitea_repositories WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete gitea repository")
	}
	if tag.RowsAffected() == 0 {
		return errors.New(errors.CodeNotFound, "gitea repository not found")
	}
	return nil
}

// DeleteStale removes repos not present in the given gitea_id list for a connection.
func (r *GiteaRepositoryRepository) DeleteStale(ctx context.Context, connectionID uuid.UUID, activeGiteaIDs []int64) (int64, error) {
	if len(activeGiteaIDs) == 0 {
		tag, err := r.db.Exec(ctx, `DELETE FROM gitea_repositories WHERE connection_id = $1`, connectionID)
		if err != nil {
			return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to delete stale repos")
		}
		return tag.RowsAffected(), nil
	}

	tag, err := r.db.Exec(ctx, `
		DELETE FROM gitea_repositories
		WHERE connection_id = $1
		  AND gitea_id != ALL($2)`, connectionID, activeGiteaIDs)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to delete stale repos")
	}
	return tag.RowsAffected(), nil
}

// ============================================================================
// Row scanners
// ============================================================================

func scanGiteaRepoRow(row pgx.Row) (*models.GiteaRepository, error) {
	var repo models.GiteaRepository
	err := row.Scan(
		&repo.ID, &repo.ConnectionID, &repo.GiteaID, &repo.FullName, &repo.Description,
		&repo.CloneURL, &repo.HTMLURL, &repo.DefaultBranch, &repo.IsPrivate, &repo.IsFork, &repo.IsArchived,
		&repo.StarsCount, &repo.ForksCount, &repo.OpenIssues, &repo.SizeKB,
		&repo.LastCommitSHA, &repo.LastCommitAt, &repo.LastSyncAt,
		&repo.CreatedAt, &repo.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &repo, nil
}

func scanGiteaRepoRows(rows pgx.Rows) ([]*models.GiteaRepository, error) {
	var result []*models.GiteaRepository
	for rows.Next() {
		var repo models.GiteaRepository
		err := rows.Scan(
			&repo.ID, &repo.ConnectionID, &repo.GiteaID, &repo.FullName, &repo.Description,
			&repo.CloneURL, &repo.HTMLURL, &repo.DefaultBranch, &repo.IsPrivate, &repo.IsFork, &repo.IsArchived,
			&repo.StarsCount, &repo.ForksCount, &repo.OpenIssues, &repo.SizeKB,
			&repo.LastCommitSHA, &repo.LastCommitAt, &repo.LastSyncAt,
			&repo.CreatedAt, &repo.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		result = append(result, &repo)
	}
	return result, rows.Err()
}
