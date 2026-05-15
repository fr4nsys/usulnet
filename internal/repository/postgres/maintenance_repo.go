// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// Type alias pointing to shared model type.
type MaintenanceWindow = models.MaintenanceWindowRecord

// MaintenanceRepository handles CRUD for maintenance windows.
type MaintenanceRepository struct {
	db *DB
}

// NewMaintenanceRepository creates a new maintenance repository.
func NewMaintenanceRepository(db *DB) *MaintenanceRepository {
	return &MaintenanceRepository{db: db}
}

// Create creates a new maintenance window.
func (r *MaintenanceRepository) Create(ctx context.Context, mw *MaintenanceWindow) error {
	if mw.ID == uuid.Nil {
		mw.ID = uuid.New()
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO maintenance_windows (id, name, description, host_id, host_name, schedule, duration_minutes, actions, is_enabled, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		mw.ID, mw.Name, mw.Description, mw.HostID, mw.HostName,
		mw.Schedule, mw.DurationMinutes, mw.Actions, mw.IsEnabled, mw.CreatedBy,
	)
	return err
}

// GetByID retrieves a maintenance window by ID.
func (r *MaintenanceRepository) GetByID(ctx context.Context, id uuid.UUID) (*MaintenanceWindow, error) {
	mw := &MaintenanceWindow{}
	err := r.db.QueryRow(ctx, `
		SELECT id, name, description, host_id, host_name, schedule, duration_minutes,
			actions, is_enabled, is_active, last_run_at, last_status, created_by, created_at, updated_at
		FROM maintenance_windows WHERE id = $1`, id).Scan(
		&mw.ID, &mw.Name, &mw.Description, &mw.HostID, &mw.HostName,
		&mw.Schedule, &mw.DurationMinutes, &mw.Actions, &mw.IsEnabled,
		&mw.IsActive, &mw.LastRunAt, &mw.LastStatus, &mw.CreatedBy, &mw.CreatedAt, &mw.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return mw, nil
}

// List returns all maintenance windows.
func (r *MaintenanceRepository) List(ctx context.Context) ([]*MaintenanceWindow, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, description, host_id, host_name, schedule, duration_minutes,
			actions, is_enabled, is_active, last_run_at, last_status, created_by, created_at, updated_at
		FROM maintenance_windows ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var windows []*MaintenanceWindow
	for rows.Next() {
		mw := &MaintenanceWindow{}
		if err := rows.Scan(
			&mw.ID, &mw.Name, &mw.Description, &mw.HostID, &mw.HostName,
			&mw.Schedule, &mw.DurationMinutes, &mw.Actions, &mw.IsEnabled,
			&mw.IsActive, &mw.LastRunAt, &mw.LastStatus, &mw.CreatedBy, &mw.CreatedAt, &mw.UpdatedAt,
		); err != nil {
			return nil, err
		}
		windows = append(windows, mw)
	}
	return windows, nil
}

// Delete deletes a maintenance window.
func (r *MaintenanceRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM maintenance_windows WHERE id = $1`, id)
	return err
}

// Toggle toggles a maintenance window's enabled status.
func (r *MaintenanceRepository) Toggle(ctx context.Context, id uuid.UUID) (bool, error) {
	var newState bool
	err := r.db.QueryRow(ctx, `
		UPDATE maintenance_windows SET is_enabled = NOT is_enabled WHERE id = $1
		RETURNING is_enabled`, id).Scan(&newState)
	return newState, err
}

// SetActive marks a maintenance window as active/inactive.
func (r *MaintenanceRepository) SetActive(ctx context.Context, id uuid.UUID, active bool) error {
	_, err := r.db.Exec(ctx, `UPDATE maintenance_windows SET is_active=$2 WHERE id=$1`, id, active)
	return err
}

// UpdateLastRun updates the last run timestamp and status.
func (r *MaintenanceRepository) UpdateLastRun(ctx context.Context, id uuid.UUID, runAt time.Time, status string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE maintenance_windows SET last_run_at=$2, last_status=$3, is_active=false WHERE id=$1`,
		id, runAt, status,
	)
	return err
}
