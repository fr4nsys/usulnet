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

// GitRepositoryRepository handles Git repository persistence (Gitea, GitHub, GitLab).
type GitRepositoryRepository struct {
	db *DB
}

// NewGitRepositoryRepository creates a new Git repository repository.
func NewGitRepositoryRepository(db *DB) *GitRepositoryRepository {
	return &GitRepositoryRepository{db: db}
}

const gitRepoColumns = `id, connection_id, provider_type, gitea_id, full_name, description,
	clone_url, html_url, default_branch, is_private, is_fork, is_archived,
	stars_count, forks_count, open_issues, size_kb, last_commit_sha,
	last_commit_at, last_sync_at, created_at, updated_at`

// Upsert inserts or updates a Git repository.
func (r *GitRepositoryRepository) Upsert(ctx context.Context, repo *models.GitRepository) error {
	if repo.ID == uuid.Nil {
		repo.ID = uuid.New()
	}
	now := time.Now()
	repo.UpdatedAt = now

	// Default to gitea if not specified
	if repo.ProviderType == "" {
		repo.ProviderType = models.GitProviderGitea
	}

	query := `
		INSERT INTO gitea_repositories (
			id, connection_id, provider_type, gitea_id, full_name, description,
			clone_url, html_url, default_branch, is_private, is_fork, is_archived,
			stars_count, forks_count, open_issues, size_kb, last_commit_sha,
			last_commit_at, last_sync_at, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
		ON CONFLICT (connection_id, gitea_id) DO UPDATE SET
			provider_type = EXCLUDED.provider_type,
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
		repo.ID, repo.ConnectionID, repo.ProviderType, repo.ProviderID, repo.FullName, repo.Description,
		repo.CloneURL, repo.HTMLURL, repo.DefaultBranch, repo.IsPrivate, repo.IsFork, repo.IsArchived,
		repo.StarsCount, repo.ForksCount, repo.OpenIssues, repo.SizeKB, repo.LastCommitSHA,
		repo.LastCommitAt, repo.LastSyncAt, repo.CreatedAt, repo.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to upsert git repository")
	}
	return nil
}

// GetByID returns a Git repository by ID.
func (r *GitRepositoryRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.GitRepository, error) {
	query := fmt.Sprintf(`SELECT %s FROM gitea_repositories WHERE id = $1`, gitRepoColumns)
	row := r.db.QueryRow(ctx, query, id)
	repo, err := scanGitRepoRow(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.New(errors.CodeNotFound, "git repository not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get git repository")
	}
	return repo, nil
}

// GetByProviderID returns a Git repository by connection ID and provider-specific ID.
func (r *GitRepositoryRepository) GetByProviderID(ctx context.Context, connectionID uuid.UUID, providerID int64) (*models.GitRepository, error) {
	query := fmt.Sprintf(`SELECT %s FROM gitea_repositories WHERE connection_id = $1 AND gitea_id = $2`, gitRepoColumns)
	row := r.db.QueryRow(ctx, query, connectionID, providerID)
	repo, err := scanGitRepoRow(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.New(errors.CodeNotFound, "git repository not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get git repository by provider ID")
	}
	return repo, nil
}

// ListByConnection returns all Git repositories for a connection.
func (r *GitRepositoryRepository) ListByConnection(ctx context.Context, connectionID uuid.UUID) ([]*models.GitRepository, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM gitea_repositories
		WHERE connection_id = $1
		ORDER BY full_name ASC`, gitRepoColumns)

	rows, err := r.db.Query(ctx, query, connectionID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list git repositories")
	}
	defer rows.Close()

	return scanGitRepoRows(rows)
}

// ListAll returns all Git repositories across all connections.
func (r *GitRepositoryRepository) ListAll(ctx context.Context) ([]*models.GitRepository, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM gitea_repositories
		ORDER BY provider_type, full_name ASC`, gitRepoColumns)

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list all git repositories")
	}
	defer rows.Close()

	return scanGitRepoRows(rows)
}

// ListByProvider returns all Git repositories for a provider type.
func (r *GitRepositoryRepository) ListByProvider(ctx context.Context, providerType models.GitProviderType) ([]*models.GitRepository, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM gitea_repositories
		WHERE provider_type = $1
		ORDER BY full_name ASC`, gitRepoColumns)

	rows, err := r.db.Query(ctx, query, providerType)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list git repositories by provider")
	}
	defer rows.Close()

	return scanGitRepoRows(rows)
}

// Delete removes a Git repository.
func (r *GitRepositoryRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM gitea_repositories WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete git repository")
	}
	if tag.RowsAffected() == 0 {
		return errors.New(errors.CodeNotFound, "git repository not found")
	}
	return nil
}

// DeleteByConnection removes all Git repositories for a connection.
func (r *GitRepositoryRepository) DeleteByConnection(ctx context.Context, connectionID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM gitea_repositories WHERE connection_id = $1`, connectionID)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete git repositories by connection")
	}
	return nil
}

// DeleteStale removes repositories not in the active list.
func (r *GitRepositoryRepository) DeleteStale(ctx context.Context, connectionID uuid.UUID, activeProviderIDs []int64) error {
	if len(activeProviderIDs) == 0 {
		// Delete all repos for this connection
		return r.DeleteByConnection(ctx, connectionID)
	}

	_, err := r.db.Exec(ctx, `
		DELETE FROM gitea_repositories
		WHERE connection_id = $1 AND NOT (gitea_id = ANY($2))`,
		connectionID, activeProviderIDs)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete stale git repositories")
	}
	return nil
}

// Search searches repositories by name.
func (r *GitRepositoryRepository) Search(ctx context.Context, query string, limit int) ([]*models.GitRepository, error) {
	if limit <= 0 {
		limit = 20
	}
	sql := fmt.Sprintf(`
		SELECT %s FROM gitea_repositories
		WHERE full_name ILIKE $1
		ORDER BY full_name ASC
		LIMIT $2`, gitRepoColumns)

	rows, err := r.db.Query(ctx, sql, "%"+query+"%", limit)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to search git repositories")
	}
	defer rows.Close()

	return scanGitRepoRows(rows)
}

// Stats returns aggregated statistics for git repositories.
type GitRepoStats struct {
	TotalRepos   int
	PrivateRepos int
	ByProvider   map[models.GitProviderType]int
}

// GetStats returns statistics for all git repositories.
func (r *GitRepositoryRepository) GetStats(ctx context.Context) (*GitRepoStats, error) {
	stats := &GitRepoStats{
		ByProvider: make(map[models.GitProviderType]int),
	}

	err := r.db.QueryRow(ctx, `
		SELECT 
			COUNT(*),
			COUNT(*) FILTER (WHERE is_private = true)
		FROM gitea_repositories`).Scan(&stats.TotalRepos, &stats.PrivateRepos)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get git repo stats")
	}

	rows, err := r.db.Query(ctx, `
		SELECT provider_type, COUNT(*) 
		FROM gitea_repositories 
		GROUP BY provider_type`)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get git repo provider stats")
	}
	defer rows.Close()

	for rows.Next() {
		var providerType models.GitProviderType
		var count int
		if err := rows.Scan(&providerType, &count); err != nil {
			return nil, err
		}
		stats.ByProvider[providerType] = count
	}

	return stats, nil
}

// ============================================================================
// Row scanners
// ============================================================================

func scanGitRepoRow(row pgx.Row) (*models.GitRepository, error) {
	var repo models.GitRepository
	err := row.Scan(
		&repo.ID, &repo.ConnectionID, &repo.ProviderType, &repo.ProviderID, &repo.FullName, &repo.Description,
		&repo.CloneURL, &repo.HTMLURL, &repo.DefaultBranch, &repo.IsPrivate, &repo.IsFork, &repo.IsArchived,
		&repo.StarsCount, &repo.ForksCount, &repo.OpenIssues, &repo.SizeKB, &repo.LastCommitSHA,
		&repo.LastCommitAt, &repo.LastSyncAt, &repo.CreatedAt, &repo.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &repo, nil
}

func scanGitRepoRows(rows pgx.Rows) ([]*models.GitRepository, error) {
	var result []*models.GitRepository
	for rows.Next() {
		var repo models.GitRepository
		err := rows.Scan(
			&repo.ID, &repo.ConnectionID, &repo.ProviderType, &repo.ProviderID, &repo.FullName, &repo.Description,
			&repo.CloneURL, &repo.HTMLURL, &repo.DefaultBranch, &repo.IsPrivate, &repo.IsFork, &repo.IsArchived,
			&repo.StarsCount, &repo.ForksCount, &repo.OpenIssues, &repo.SizeKB, &repo.LastCommitSHA,
			&repo.LastCommitAt, &repo.LastSyncAt, &repo.CreatedAt, &repo.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		result = append(result, &repo)
	}
	return result, rows.Err()
}
