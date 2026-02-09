// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// WebShortcutRepository
// ============================================================================

// WebShortcutRepository manages web shortcut records.
type WebShortcutRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewWebShortcutRepository creates a new WebShortcutRepository.
func NewWebShortcutRepository(db *DB, log *logger.Logger) *WebShortcutRepository {
	return &WebShortcutRepository{
		db:     db,
		logger: log.Named("shortcut_repo"),
	}
}

// Create inserts a new web shortcut.
func (r *WebShortcutRepository) Create(ctx context.Context, shortcut *models.WebShortcut) error {
	shortcut.ID = uuid.New()
	now := time.Now()
	shortcut.CreatedAt = now
	shortcut.UpdatedAt = now

	_, err := r.db.Exec(ctx, `
		INSERT INTO web_shortcuts (
			id, name, description, url, type, icon, icon_type, color,
			category, sort_order, open_in_new, show_in_menu, is_public,
			created_by, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		shortcut.ID, shortcut.Name, shortcut.Description, shortcut.URL,
		shortcut.Type, shortcut.Icon, shortcut.IconType, shortcut.Color,
		shortcut.Category, shortcut.SortOrder, shortcut.OpenInNew,
		shortcut.ShowInMenu, shortcut.IsPublic, shortcut.CreatedBy,
		shortcut.CreatedAt, shortcut.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create web shortcut")
	}
	return nil
}

// GetByID retrieves a shortcut by ID.
func (r *WebShortcutRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.WebShortcut, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, description, url, type, icon, icon_type, color,
			category, sort_order, open_in_new, show_in_menu, is_public,
			created_by, created_at, updated_at
		FROM web_shortcuts WHERE id = $1`, id)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query web shortcut")
	}
	shortcut, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.WebShortcut])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("web shortcut")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan web shortcut")
	}
	return shortcut, nil
}

// ListByUser retrieves all shortcuts for a user (own + public).
func (r *WebShortcutRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.WebShortcut, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, description, url, type, icon, icon_type, color,
			category, sort_order, open_in_new, show_in_menu, is_public,
			created_by, created_at, updated_at
		FROM web_shortcuts
		WHERE created_by = $1 OR is_public = true
		ORDER BY category, sort_order, name ASC`, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list web shortcuts")
	}
	shortcuts, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.WebShortcut])
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan web shortcuts")
	}
	return shortcuts, nil
}

// ListForMenu retrieves shortcuts marked for menu display.
func (r *WebShortcutRepository) ListForMenu(ctx context.Context, userID uuid.UUID) ([]*models.WebShortcut, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, description, url, type, icon, icon_type, color,
			category, sort_order, open_in_new, show_in_menu, is_public,
			created_by, created_at, updated_at
		FROM web_shortcuts
		WHERE show_in_menu = true AND (created_by = $1 OR is_public = true)
		ORDER BY sort_order, name ASC`, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list menu shortcuts")
	}
	shortcuts, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.WebShortcut])
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan menu shortcuts")
	}
	return shortcuts, nil
}

// ListByCategory retrieves shortcuts for a user by category.
func (r *WebShortcutRepository) ListByCategory(ctx context.Context, userID uuid.UUID, category string) ([]*models.WebShortcut, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, description, url, type, icon, icon_type, color,
			category, sort_order, open_in_new, show_in_menu, is_public,
			created_by, created_at, updated_at
		FROM web_shortcuts
		WHERE (created_by = $1 OR is_public = true) AND category = $2
		ORDER BY sort_order, name ASC`, userID, category)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list shortcuts by category")
	}
	shortcuts, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.WebShortcut])
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan shortcuts by category")
	}
	return shortcuts, nil
}

// Update updates a web shortcut.
func (r *WebShortcutRepository) Update(ctx context.Context, shortcut *models.WebShortcut) error {
	shortcut.UpdatedAt = time.Now()

	_, err := r.db.Exec(ctx, `
		UPDATE web_shortcuts SET
			name=$2, description=$3, url=$4, type=$5, icon=$6, icon_type=$7,
			color=$8, category=$9, sort_order=$10, open_in_new=$11,
			show_in_menu=$12, is_public=$13, updated_at=$14
		WHERE id = $1`,
		shortcut.ID, shortcut.Name, shortcut.Description, shortcut.URL,
		shortcut.Type, shortcut.Icon, shortcut.IconType, shortcut.Color,
		shortcut.Category, shortcut.SortOrder, shortcut.OpenInNew,
		shortcut.ShowInMenu, shortcut.IsPublic, shortcut.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update web shortcut")
	}
	return nil
}

// Delete removes a web shortcut.
func (r *WebShortcutRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM web_shortcuts WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete web shortcut")
	}
	return nil
}

// GetCategories returns all unique categories for a user.
func (r *WebShortcutRepository) GetCategories(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT category FROM web_shortcuts
		WHERE (created_by = $1 OR is_public = true) AND category != ''
		ORDER BY category`, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get shortcut categories")
	}
	defer rows.Close()

	var categories []string
	for rows.Next() {
		var cat string
		if err := rows.Scan(&cat); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan category")
		}
		categories = append(categories, cat)
	}
	return categories, nil
}

// UpdateSortOrder updates the sort order for multiple shortcuts.
func (r *WebShortcutRepository) UpdateSortOrder(ctx context.Context, orders map[uuid.UUID]int) error {
	for id, order := range orders {
		_, err := r.db.Exec(ctx, `
			UPDATE web_shortcuts SET sort_order=$2, updated_at=$3
			WHERE id = $1`, id, order, time.Now())
		if err != nil {
			return errors.Wrap(err, errors.CodeDatabaseError, "failed to update shortcut sort order")
		}
	}
	return nil
}

// ============================================================================
// ShortcutCategoryRepository
// ============================================================================

// ShortcutCategoryRepository manages shortcut category records.
type ShortcutCategoryRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewShortcutCategoryRepository creates a new ShortcutCategoryRepository.
func NewShortcutCategoryRepository(db *DB, log *logger.Logger) *ShortcutCategoryRepository {
	return &ShortcutCategoryRepository{
		db:     db,
		logger: log.Named("shortcut_cat_repo"),
	}
}

// Create inserts a new category.
func (r *ShortcutCategoryRepository) Create(ctx context.Context, cat *models.ShortcutCategory) error {
	cat.ID = uuid.New()
	now := time.Now()
	cat.CreatedAt = now
	cat.UpdatedAt = now

	_, err := r.db.Exec(ctx, `
		INSERT INTO shortcut_categories (
			id, name, icon, color, sort_order, is_default, created_by, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		cat.ID, cat.Name, cat.Icon, cat.Color, cat.SortOrder,
		cat.IsDefault, cat.CreatedBy, cat.CreatedAt, cat.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create shortcut category")
	}
	return nil
}

// GetByID retrieves a category by ID.
func (r *ShortcutCategoryRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ShortcutCategory, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, icon, color, sort_order, is_default, created_by, created_at, updated_at
		FROM shortcut_categories WHERE id = $1`, id)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query shortcut category")
	}
	cat, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.ShortcutCategory])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("shortcut category")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan shortcut category")
	}
	return cat, nil
}

// ListByUser retrieves all categories for a user.
func (r *ShortcutCategoryRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.ShortcutCategory, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, icon, color, sort_order, is_default, created_by, created_at, updated_at
		FROM shortcut_categories WHERE created_by = $1
		ORDER BY sort_order, name ASC`, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list shortcut categories")
	}
	cats, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.ShortcutCategory])
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan shortcut categories")
	}
	return cats, nil
}

// Update updates a category.
func (r *ShortcutCategoryRepository) Update(ctx context.Context, cat *models.ShortcutCategory) error {
	cat.UpdatedAt = time.Now()

	_, err := r.db.Exec(ctx, `
		UPDATE shortcut_categories SET
			name=$2, icon=$3, color=$4, sort_order=$5, is_default=$6, updated_at=$7
		WHERE id = $1`,
		cat.ID, cat.Name, cat.Icon, cat.Color, cat.SortOrder, cat.IsDefault, cat.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update shortcut category")
	}
	return nil
}

// Delete removes a category.
func (r *ShortcutCategoryRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM shortcut_categories WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete shortcut category")
	}
	return nil
}
