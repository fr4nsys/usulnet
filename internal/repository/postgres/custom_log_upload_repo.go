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

// CustomLogUploadRepository handles custom log upload database operations.
type CustomLogUploadRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewCustomLogUploadRepository creates a new CustomLogUploadRepository.
func NewCustomLogUploadRepository(db *DB, log *logger.Logger) *CustomLogUploadRepository {
	return &CustomLogUploadRepository{
		db:     db,
		logger: log.Named("custom_log_upload_repo"),
	}
}

// Create inserts a new custom log upload record.
func (r *CustomLogUploadRepository) Create(ctx context.Context, upload *models.CustomLogUpload) error {
	if upload.ID == uuid.Nil {
		upload.ID = uuid.New()
	}
	if upload.UploadedAt.IsZero() {
		upload.UploadedAt = time.Now()
	}

	query := `INSERT INTO custom_log_uploads (
		id, user_id, filename, size, format, line_count, error_count,
		description, file_path, uploaded_at, created_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())`

	_, err := r.db.Pool().Exec(ctx, query,
		upload.ID, upload.UserID, upload.Filename, upload.Size,
		upload.Format, upload.LineCount, upload.ErrorCount,
		upload.Description, upload.FilePath, upload.UploadedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to create log upload")
	}

	return nil
}

// GetByID retrieves a log upload by ID.
func (r *CustomLogUploadRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.CustomLogUpload, error) {
	query := `SELECT id, user_id, filename, size, format, line_count, error_count,
		description, file_path, uploaded_at
	FROM custom_log_uploads WHERE id = $1`

	var u models.CustomLogUpload
	err := r.db.Pool().QueryRow(ctx, query, id).Scan(
		&u.ID, &u.UserID, &u.Filename, &u.Size, &u.Format,
		&u.LineCount, &u.ErrorCount, &u.Description, &u.FilePath, &u.UploadedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("log upload")
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get log upload")
	}

	return &u, nil
}

// ListByUser retrieves all log uploads for a user, ordered by upload time desc.
func (r *CustomLogUploadRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.CustomLogUpload, error) {
	query := `SELECT id, user_id, filename, size, format, line_count, error_count,
		description, file_path, uploaded_at
	FROM custom_log_uploads WHERE user_id = $1 ORDER BY uploaded_at DESC LIMIT 100`

	rows, err := r.db.Pool().Query(ctx, query, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to list log uploads")
	}
	defer rows.Close()

	var uploads []*models.CustomLogUpload
	for rows.Next() {
		var u models.CustomLogUpload
		if err := rows.Scan(
			&u.ID, &u.UserID, &u.Filename, &u.Size, &u.Format,
			&u.LineCount, &u.ErrorCount, &u.Description, &u.FilePath, &u.UploadedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to scan log upload")
		}
		uploads = append(uploads, &u)
	}

	return uploads, nil
}

// Delete removes a log upload record.
func (r *CustomLogUploadRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM custom_log_uploads WHERE id = $1`
	result, err := r.db.Pool().Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to delete log upload")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("log upload")
	}
	return nil
}
