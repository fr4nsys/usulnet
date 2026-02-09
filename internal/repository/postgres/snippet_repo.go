// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package postgres provides PostgreSQL repository implementations.
package postgres

import (
	"context"
	"database/sql"
	"strconv"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
)

// SnippetRepository implements snippet storage for PostgreSQL.
type SnippetRepository struct {
	db *sql.DB
}

// NewSnippetRepository creates a new snippet repository.
func NewSnippetRepository(db *sql.DB) *SnippetRepository {
	return &SnippetRepository{db: db}
}

// ============================================================================
// Snippet CRUD
// ============================================================================

// Create creates a new snippet.
func (r *SnippetRepository) Create(ctx context.Context, userID uuid.UUID, input *models.CreateSnippetInput) (*models.UserSnippet, error) {
	id := uuid.New()
	
	query := `
		INSERT INTO user_snippets (
			id, user_id, name, path, language, content, description, tags
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		)
		RETURNING id, user_id, name, path, language, content, description, tags, is_public, created_at, updated_at`

	snippet := &models.UserSnippet{}
	err := r.db.QueryRowContext(ctx, query,
		id,
		userID,
		input.Name,
		input.Path,
		input.Language,
		input.Content,
		snippetNilIfEmpty(input.Description),
		pq.Array(input.Tags),
	).Scan(
		&snippet.ID,
		&snippet.UserID,
		&snippet.Name,
		&snippet.Path,
		&snippet.Language,
		&snippet.Content,
		&snippet.Description,
		&snippet.Tags,
		&snippet.IsPublic,
		&snippet.CreatedAt,
		&snippet.UpdatedAt,
	)

	if err != nil {
		if snippetIsUniqueViolation(err) {
			return nil, errors.AlreadyExists("snippet")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create snippet")
	}

	return snippet, nil
}

// Get retrieves a snippet by ID.
func (r *SnippetRepository) Get(ctx context.Context, userID, snippetID uuid.UUID) (*models.UserSnippet, error) {
	query := `
		SELECT id, user_id, name, path, language, content, description, tags, is_public, created_at, updated_at
		FROM user_snippets
		WHERE id = $1 AND user_id = $2`

	snippet := &models.UserSnippet{}
	err := r.db.QueryRowContext(ctx, query, snippetID, userID).Scan(
		&snippet.ID,
		&snippet.UserID,
		&snippet.Name,
		&snippet.Path,
		&snippet.Language,
		&snippet.Content,
		&snippet.Description,
		&snippet.Tags,
		&snippet.IsPublic,
		&snippet.CreatedAt,
		&snippet.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, errors.NotFound("snippet")
	}
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get snippet")
	}

	return snippet, nil
}

// Update updates a snippet.
func (r *SnippetRepository) Update(ctx context.Context, userID, snippetID uuid.UUID, input *models.UpdateSnippetInput) (*models.UserSnippet, error) {
	// Build dynamic update query
	query := `
		UPDATE user_snippets SET
			name = COALESCE($3, name),
			path = COALESCE($4, path),
			language = COALESCE($5, language),
			content = COALESCE($6, content),
			description = COALESCE($7, description),
			tags = COALESCE($8, tags)
		WHERE id = $1 AND user_id = $2
		RETURNING id, user_id, name, path, language, content, description, tags, is_public, created_at, updated_at`

	snippet := &models.UserSnippet{}
	err := r.db.QueryRowContext(ctx, query,
		snippetID,
		userID,
		input.Name,
		input.Path,
		input.Language,
		input.Content,
		input.Description,
		pq.Array(input.Tags),
	).Scan(
		&snippet.ID,
		&snippet.UserID,
		&snippet.Name,
		&snippet.Path,
		&snippet.Language,
		&snippet.Content,
		&snippet.Description,
		&snippet.Tags,
		&snippet.IsPublic,
		&snippet.CreatedAt,
		&snippet.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, errors.NotFound("snippet")
	}
	if err != nil {
		if snippetIsUniqueViolation(err) {
			return nil, errors.AlreadyExists("snippet")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to update snippet")
	}

	return snippet, nil
}

// Delete deletes a snippet.
func (r *SnippetRepository) Delete(ctx context.Context, userID, snippetID uuid.UUID) error {
	query := `DELETE FROM user_snippets WHERE id = $1 AND user_id = $2`

	result, err := r.db.ExecContext(ctx, query, snippetID, userID)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete snippet")
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.NotFound("snippet")
	}

	return nil
}

// ============================================================================
// List operations
// ============================================================================

// List returns snippets for a user with optional filters.
func (r *SnippetRepository) List(ctx context.Context, userID uuid.UUID, opts *models.SnippetListOptions) ([]*models.UserSnippetListItem, error) {
	if opts == nil {
		opts = &models.SnippetListOptions{}
	}
	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	if opts.Limit > 200 {
		opts.Limit = 200
	}

	query := `
		SELECT id, name, path, language, description, tags, LENGTH(content) as content_size, updated_at
		FROM user_snippets
		WHERE user_id = $1`

	args := []interface{}{userID}
	argIdx := 2

	// Path prefix filter
	if opts.Path != "" {
		query += ` AND path LIKE $` + strconv.Itoa(argIdx)
		args = append(args, opts.Path+"%")
		argIdx++
	}

	// Language filter
	if opts.Language != "" {
		query += ` AND language = $` + strconv.Itoa(argIdx)
		args = append(args, opts.Language)
		argIdx++
	}

	// Full text search
	if opts.Search != "" {
		query += ` AND to_tsvector('english', name || ' ' || COALESCE(description, '')) @@ plainto_tsquery('english', $` + strconv.Itoa(argIdx) + `)`
		args = append(args, opts.Search)
		argIdx++
	}

	query += ` ORDER BY updated_at DESC LIMIT $` + strconv.Itoa(argIdx) + ` OFFSET $` + strconv.Itoa(argIdx+1)
	args = append(args, opts.Limit, opts.Offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list snippets")
	}
	defer rows.Close()

	var snippets []*models.UserSnippetListItem
	for rows.Next() {
		s := &models.UserSnippetListItem{}
		if err := rows.Scan(
			&s.ID,
			&s.Name,
			&s.Path,
			&s.Language,
			&s.Description,
			&s.Tags,
			&s.ContentSize,
			&s.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan snippet")
		}
		snippets = append(snippets, s)
	}

	return snippets, rows.Err()
}

// ListPaths returns unique paths for a user (for folder navigation).
func (r *SnippetRepository) ListPaths(ctx context.Context, userID uuid.UUID) ([]string, error) {
	query := `
		SELECT DISTINCT path FROM user_snippets
		WHERE user_id = $1 AND path != ''
		ORDER BY path`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list paths")
	}
	defer rows.Close()

	var paths []string
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan path")
		}
		paths = append(paths, path)
	}

	return paths, rows.Err()
}

// Count returns total snippet count for a user.
func (r *SnippetRepository) Count(ctx context.Context, userID uuid.UUID) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, 
		`SELECT COUNT(*) FROM user_snippets WHERE user_id = $1`,
		userID,
	).Scan(&count)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count snippets")
	}
	return count, nil
}

// ============================================================================
// Helpers (prefixed to avoid collision with other repos)
// ============================================================================

func snippetNilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func snippetIsUniqueViolation(err error) bool {
	if pqErr, ok := err.(*pq.Error); ok {
		return pqErr.Code == "23505"
	}
	return false
}
