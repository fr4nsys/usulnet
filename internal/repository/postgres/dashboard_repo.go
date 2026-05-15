// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
)

// DashboardRepository implements dashboard layout and widget storage.
type DashboardRepository struct {
	db *DB
}

// NewDashboardRepository creates a new dashboard repository.
func NewDashboardRepository(db *DB) *DashboardRepository {
	return &DashboardRepository{db: db}
}

// ============================================================================
// Layout CRUD
// ============================================================================

// CreateLayout creates a new dashboard layout.
func (r *DashboardRepository) CreateLayout(ctx context.Context, layout *models.DashboardLayout) error {
	if layout.ID == uuid.Nil {
		layout.ID = uuid.New()
	}
	now := time.Now()
	layout.CreatedAt = now
	layout.UpdatedAt = now

	if layout.LayoutJSON == nil {
		layout.LayoutJSON = json.RawMessage("[]")
	}

	query := `
		INSERT INTO dashboard_layouts (
			id, name, description, user_id, is_default, is_shared,
			layout_json, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		)`

	_, err := r.db.Exec(ctx, query,
		layout.ID,
		layout.Name,
		layout.Description,
		layout.UserID,
		layout.IsDefault,
		layout.IsShared,
		layout.LayoutJSON,
		layout.CreatedAt,
		layout.UpdatedAt,
	)
	if err != nil {
		if IsDuplicateKeyError(err) {
			return errors.AlreadyExists("dashboard layout")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create dashboard layout")
	}

	return nil
}

// GetLayout retrieves a layout by ID.
func (r *DashboardRepository) GetLayout(ctx context.Context, id uuid.UUID) (*models.DashboardLayout, error) {
	query := `
		SELECT id, name, description, user_id, is_default, is_shared,
			layout_json, created_at, updated_at
		FROM dashboard_layouts
		WHERE id = $1`

	layout := &models.DashboardLayout{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&layout.ID,
		&layout.Name,
		&layout.Description,
		&layout.UserID,
		&layout.IsDefault,
		&layout.IsShared,
		&layout.LayoutJSON,
		&layout.CreatedAt,
		&layout.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.NotFound("dashboard layout")
	}
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get dashboard layout")
	}

	return layout, nil
}

// UpdateLayout updates an existing layout.
func (r *DashboardRepository) UpdateLayout(ctx context.Context, layout *models.DashboardLayout) error {
	layout.UpdatedAt = time.Now()

	query := `
		UPDATE dashboard_layouts SET
			name = $2,
			description = $3,
			is_default = $4,
			is_shared = $5,
			layout_json = $6,
			updated_at = $7
		WHERE id = $1`

	result, err := r.db.Exec(ctx, query,
		layout.ID,
		layout.Name,
		layout.Description,
		layout.IsDefault,
		layout.IsShared,
		layout.LayoutJSON,
		layout.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update dashboard layout")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("dashboard layout")
	}

	return nil
}

// DeleteLayout deletes a layout and its widgets (cascade).
func (r *DashboardRepository) DeleteLayout(ctx context.Context, id uuid.UUID) error {
	result, err := r.db.Exec(ctx, `DELETE FROM dashboard_layouts WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete dashboard layout")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("dashboard layout")
	}
	return nil
}

// ListLayouts returns layouts visible to a user (own + shared).
func (r *DashboardRepository) ListLayouts(ctx context.Context, userID uuid.UUID) ([]*models.DashboardLayout, error) {
	query := `
		SELECT id, name, description, user_id, is_default, is_shared,
			layout_json, created_at, updated_at
		FROM dashboard_layouts
		WHERE user_id = $1 OR is_shared = true
		ORDER BY is_default DESC, name ASC`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list dashboard layouts")
	}
	defer rows.Close()

	var layouts []*models.DashboardLayout
	for rows.Next() {
		l := &models.DashboardLayout{}
		if err := rows.Scan(
			&l.ID,
			&l.Name,
			&l.Description,
			&l.UserID,
			&l.IsDefault,
			&l.IsShared,
			&l.LayoutJSON,
			&l.CreatedAt,
			&l.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan dashboard layout")
		}
		layouts = append(layouts, l)
	}

	return layouts, rows.Err()
}

// GetDefaultLayout retrieves the user's default layout.
func (r *DashboardRepository) GetDefaultLayout(ctx context.Context, userID uuid.UUID) (*models.DashboardLayout, error) {
	query := `
		SELECT id, name, description, user_id, is_default, is_shared,
			layout_json, created_at, updated_at
		FROM dashboard_layouts
		WHERE user_id = $1 AND is_default = true
		LIMIT 1`

	layout := &models.DashboardLayout{}
	err := r.db.QueryRow(ctx, query, userID).Scan(
		&layout.ID,
		&layout.Name,
		&layout.Description,
		&layout.UserID,
		&layout.IsDefault,
		&layout.IsShared,
		&layout.LayoutJSON,
		&layout.CreatedAt,
		&layout.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil // No default set — not an error
	}
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get default layout")
	}

	return layout, nil
}

// ClearDefault removes the default flag from all layouts for a user.
func (r *DashboardRepository) ClearDefault(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE dashboard_layouts SET is_default = false WHERE user_id = $1 AND is_default = true`,
		userID,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to clear default layout")
	}
	return nil
}

// ============================================================================
// Widget CRUD
// ============================================================================

// CreateWidget creates a new widget on a layout.
func (r *DashboardRepository) CreateWidget(ctx context.Context, widget *models.DashboardWidget) error {
	if widget.ID == uuid.Nil {
		widget.ID = uuid.New()
	}
	now := time.Now()
	widget.CreatedAt = now
	widget.UpdatedAt = now

	if widget.Config == nil {
		widget.Config = json.RawMessage("{}")
	}

	query := `
		INSERT INTO dashboard_widgets (
			id, layout_id, widget_type, title, config,
			position_x, position_y, width, height,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		)`

	_, err := r.db.Exec(ctx, query,
		widget.ID,
		widget.LayoutID,
		widget.WidgetType,
		widget.Title,
		widget.Config,
		widget.PositionX,
		widget.PositionY,
		widget.Width,
		widget.Height,
		widget.CreatedAt,
		widget.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create dashboard widget")
	}

	return nil
}

// GetWidget retrieves a widget by ID.
func (r *DashboardRepository) GetWidget(ctx context.Context, id uuid.UUID) (*models.DashboardWidget, error) {
	query := `
		SELECT id, layout_id, widget_type, title, config,
			position_x, position_y, width, height,
			created_at, updated_at
		FROM dashboard_widgets
		WHERE id = $1`

	w := &models.DashboardWidget{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&w.ID,
		&w.LayoutID,
		&w.WidgetType,
		&w.Title,
		&w.Config,
		&w.PositionX,
		&w.PositionY,
		&w.Width,
		&w.Height,
		&w.CreatedAt,
		&w.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.NotFound("dashboard widget")
	}
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get dashboard widget")
	}

	return w, nil
}

// UpdateWidget updates a widget.
func (r *DashboardRepository) UpdateWidget(ctx context.Context, widget *models.DashboardWidget) error {
	widget.UpdatedAt = time.Now()

	query := `
		UPDATE dashboard_widgets SET
			widget_type = $2,
			title = $3,
			config = $4,
			position_x = $5,
			position_y = $6,
			width = $7,
			height = $8,
			updated_at = $9
		WHERE id = $1`

	result, err := r.db.Exec(ctx, query,
		widget.ID,
		widget.WidgetType,
		widget.Title,
		widget.Config,
		widget.PositionX,
		widget.PositionY,
		widget.Width,
		widget.Height,
		widget.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update dashboard widget")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("dashboard widget")
	}

	return nil
}

// DeleteWidget deletes a widget.
func (r *DashboardRepository) DeleteWidget(ctx context.Context, id uuid.UUID) error {
	result, err := r.db.Exec(ctx, `DELETE FROM dashboard_widgets WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete dashboard widget")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("dashboard widget")
	}
	return nil
}

// ListWidgets returns all widgets for a layout.
func (r *DashboardRepository) ListWidgets(ctx context.Context, layoutID uuid.UUID) ([]*models.DashboardWidget, error) {
	query := `
		SELECT id, layout_id, widget_type, title, config,
			position_x, position_y, width, height,
			created_at, updated_at
		FROM dashboard_widgets
		WHERE layout_id = $1
		ORDER BY position_y, position_x`

	rows, err := r.db.Query(ctx, query, layoutID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list dashboard widgets")
	}
	defer rows.Close()

	var widgets []*models.DashboardWidget
	for rows.Next() {
		w := &models.DashboardWidget{}
		if err := rows.Scan(
			&w.ID,
			&w.LayoutID,
			&w.WidgetType,
			&w.Title,
			&w.Config,
			&w.PositionX,
			&w.PositionY,
			&w.Width,
			&w.Height,
			&w.CreatedAt,
			&w.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan dashboard widget")
		}
		widgets = append(widgets, w)
	}

	return widgets, rows.Err()
}
