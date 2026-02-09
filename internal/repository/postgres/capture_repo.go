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

// CaptureRepository handles packet capture database operations.
type CaptureRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewCaptureRepository creates a new CaptureRepository.
func NewCaptureRepository(db *DB, log *logger.Logger) *CaptureRepository {
	return &CaptureRepository{
		db:     db,
		logger: log.Named("capture_repo"),
	}
}

// Create inserts a new packet capture record.
func (r *CaptureRepository) Create(ctx context.Context, capture *models.PacketCapture) error {
	capture.ID = uuid.New()
	capture.CreatedAt = time.Now()
	capture.UpdatedAt = time.Now()
	capture.StartedAt = time.Now()

	query := `INSERT INTO packet_captures (
		id, user_id, name, interface, filter, status, status_message,
		packet_count, file_size, file_path, max_packets, max_duration, pid,
		started_at, stopped_at, created_at, updated_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`

	_, err := r.db.Pool().Exec(ctx, query,
		capture.ID, capture.UserID, capture.Name, capture.Interface,
		capture.Filter, capture.Status, capture.StatusMsg,
		capture.PacketCount, capture.FileSize, capture.FilePath,
		capture.MaxPackets, capture.MaxDuration, capture.PID,
		capture.StartedAt, capture.StoppedAt, capture.CreatedAt, capture.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to create capture")
	}

	return nil
}

// GetByID retrieves a capture by ID.
func (r *CaptureRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.PacketCapture, error) {
	query := `SELECT id, user_id, name, interface, filter, status, status_message,
		packet_count, file_size, file_path, max_packets, max_duration, pid,
		started_at, stopped_at, created_at, updated_at
	FROM packet_captures WHERE id = $1`

	var c models.PacketCapture
	err := r.db.Pool().QueryRow(ctx, query, id).Scan(
		&c.ID, &c.UserID, &c.Name, &c.Interface, &c.Filter,
		&c.Status, &c.StatusMsg, &c.PacketCount, &c.FileSize, &c.FilePath,
		&c.MaxPackets, &c.MaxDuration, &c.PID,
		&c.StartedAt, &c.StoppedAt, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("capture")
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get capture")
	}

	return &c, nil
}

// ListByUser retrieves all captures for a user, ordered by creation time desc.
func (r *CaptureRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.PacketCapture, error) {
	query := `SELECT id, user_id, name, interface, filter, status, status_message,
		packet_count, file_size, file_path, max_packets, max_duration, pid,
		started_at, stopped_at, created_at, updated_at
	FROM packet_captures WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50`

	rows, err := r.db.Pool().Query(ctx, query, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to list captures")
	}
	defer rows.Close()

	var captures []*models.PacketCapture
	for rows.Next() {
		var c models.PacketCapture
		if err := rows.Scan(
			&c.ID, &c.UserID, &c.Name, &c.Interface, &c.Filter,
			&c.Status, &c.StatusMsg, &c.PacketCount, &c.FileSize, &c.FilePath,
			&c.MaxPackets, &c.MaxDuration, &c.PID,
			&c.StartedAt, &c.StoppedAt, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to scan capture")
		}
		captures = append(captures, &c)
	}

	return captures, nil
}

// UpdateStatus updates the status and related fields of a capture.
func (r *CaptureRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.CaptureStatus, msg string) error {
	query := `UPDATE packet_captures SET status = $2, status_message = $3 WHERE id = $1`
	_, err := r.db.Pool().Exec(ctx, query, id, status, msg)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to update capture status")
	}
	return nil
}

// UpdateStats updates packet count and file size for a running capture.
func (r *CaptureRepository) UpdateStats(ctx context.Context, id uuid.UUID, packetCount int64, fileSize int64) error {
	query := `UPDATE packet_captures SET packet_count = $2, file_size = $3 WHERE id = $1`
	_, err := r.db.Pool().Exec(ctx, query, id, packetCount, fileSize)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to update capture stats")
	}
	return nil
}

// Stop marks a capture as stopped with final stats.
func (r *CaptureRepository) Stop(ctx context.Context, id uuid.UUID, packetCount int64, fileSize int64) error {
	now := time.Now()
	query := `UPDATE packet_captures SET status = $2, stopped_at = $3, packet_count = $4, file_size = $5, pid = 0 WHERE id = $1`
	_, err := r.db.Pool().Exec(ctx, query, id, models.CaptureStatusStopped, now, packetCount, fileSize)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to stop capture")
	}
	return nil
}

// SetPID sets the process ID of the tcpdump process.
func (r *CaptureRepository) SetPID(ctx context.Context, id uuid.UUID, pid int) error {
	query := `UPDATE packet_captures SET pid = $2 WHERE id = $1`
	_, err := r.db.Pool().Exec(ctx, query, id, pid)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to set capture PID")
	}
	return nil
}

// Delete removes a capture record.
func (r *CaptureRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM packet_captures WHERE id = $1`
	result, err := r.db.Pool().Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to delete capture")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("capture")
	}
	return nil
}
