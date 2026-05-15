// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	stderrors "errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// ImageBuildJobRepository
// ============================================================================

// ImageBuildJobRepository implements imagebuilder.BuildJobRepository on
// PostgreSQL. The struct holds the pool wrapper and a service-named logger.
type ImageBuildJobRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewImageBuildJobRepository constructs a build job repository.
func NewImageBuildJobRepository(db *DB, log *logger.Logger) *ImageBuildJobRepository {
	return &ImageBuildJobRepository{
		db:     db,
		logger: log.Named("repo.image_build_jobs"),
	}
}

// Create inserts a new build job, generating an ID if missing and stamping
// CreatedAt/UpdatedAt.
func (r *ImageBuildJobRepository) Create(ctx context.Context, job *models.ImageBuildJob) error {
	if job.ID == uuid.Nil {
		job.ID = uuid.New()
	}
	now := time.Now()
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	}
	job.UpdatedAt = now

	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO image_build_jobs (
			id, host_id, name, tags, dockerfile, context_path,
			build_args, labels, target, no_cache, pull, platform,
			status, output, error_message, image_id, image_size, duration_ms,
			signed, signature_ref,
			created_by, started_at, completed_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11, $12,
			$13, $14, $15, $16, $17, $18,
			$19, $20,
			$21, $22, $23, $24, $25
		)`,
		job.ID, job.HostID, job.Name, job.Tags, job.Dockerfile, job.ContextPath,
		job.BuildArgs, job.Labels, job.Target, job.NoCache, job.Pull, job.Platform,
		job.Status, job.Output, job.ErrorMessage, job.ImageID, job.ImageSize, job.DurationMs,
		job.Signed, job.SignatureRef,
		job.CreatedBy, job.StartedAt, job.CompletedAt, job.CreatedAt, job.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "create image build job")
	}
	return nil
}

// GetByID returns a build job, or NotFound if no row exists.
func (r *ImageBuildJobRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ImageBuildJob, error) {
	var job models.ImageBuildJob
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, host_id, name, tags, dockerfile, context_path,
			build_args, labels, target, no_cache, pull, platform,
			status, output, error_message, image_id, image_size, duration_ms,
			signed, signature_ref,
			created_by, started_at, completed_at, created_at, updated_at
		FROM image_build_jobs WHERE id = $1`, id,
	).Scan(
		&job.ID, &job.HostID, &job.Name, &job.Tags, &job.Dockerfile, &job.ContextPath,
		&job.BuildArgs, &job.Labels, &job.Target, &job.NoCache, &job.Pull, &job.Platform,
		&job.Status, &job.Output, &job.ErrorMessage, &job.ImageID, &job.ImageSize, &job.DurationMs,
		&job.Signed, &job.SignatureRef,
		&job.CreatedBy, &job.StartedAt, &job.CompletedAt, &job.CreatedAt, &job.UpdatedAt,
	)
	if err != nil {
		if stderrors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("image_build_job")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get image build job")
	}
	return &job, nil
}

// Update writes the mutable fields of an existing build job.
func (r *ImageBuildJobRepository) Update(ctx context.Context, job *models.ImageBuildJob) error {
	job.UpdatedAt = time.Now()
	_, err := r.db.Pool().Exec(ctx, `
		UPDATE image_build_jobs SET
			name = $2, tags = $3, dockerfile = $4, context_path = $5,
			build_args = $6, labels = $7, target = $8, no_cache = $9,
			pull = $10, platform = $11, status = $12, output = $13,
			error_message = $14, image_id = $15, image_size = $16,
			duration_ms = $17, signed = $18, signature_ref = $19,
			started_at = $20, completed_at = $21, updated_at = $22
		WHERE id = $1`,
		job.ID, job.Name, job.Tags, job.Dockerfile, job.ContextPath,
		job.BuildArgs, job.Labels, job.Target, job.NoCache,
		job.Pull, job.Platform, job.Status, job.Output,
		job.ErrorMessage, job.ImageID, job.ImageSize,
		job.DurationMs, job.Signed, job.SignatureRef,
		job.StartedAt, job.CompletedAt, job.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "update image build job")
	}
	return nil
}

// ListByHost returns paginated build jobs for a host, ordered newest first.
// total counts all matching rows so the UI can render pagination.
func (r *ImageBuildJobRepository) ListByHost(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]models.ImageBuildJob, int, error) {
	var total int
	err := r.db.Pool().QueryRow(ctx,
		`SELECT COUNT(*) FROM image_build_jobs WHERE host_id = $1`, hostID,
	).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "count image build jobs")
	}

	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, host_id, name, tags, dockerfile, context_path,
			build_args, labels, target, no_cache, pull, platform,
			status, output, error_message, image_id, image_size, duration_ms,
			signed, signature_ref,
			created_by, started_at, completed_at, created_at, updated_at
		FROM image_build_jobs WHERE host_id = $1
		ORDER BY created_at DESC LIMIT $2 OFFSET $3`, hostID, limit, offset,
	)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "list image build jobs")
	}
	defer rows.Close()

	results := make([]models.ImageBuildJob, 0, limit)
	for rows.Next() {
		var job models.ImageBuildJob
		if err := rows.Scan(
			&job.ID, &job.HostID, &job.Name, &job.Tags, &job.Dockerfile, &job.ContextPath,
			&job.BuildArgs, &job.Labels, &job.Target, &job.NoCache, &job.Pull, &job.Platform,
			&job.Status, &job.Output, &job.ErrorMessage, &job.ImageID, &job.ImageSize, &job.DurationMs,
			&job.Signed, &job.SignatureRef,
			&job.CreatedBy, &job.StartedAt, &job.CompletedAt, &job.CreatedAt, &job.UpdatedAt,
		); err != nil {
			return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "scan image build job")
		}
		results = append(results, job)
	}
	return results, total, nil
}

// GetStats returns aggregate counts and average duration for the dashboard.
func (r *ImageBuildJobRepository) GetStats(ctx context.Context, hostID uuid.UUID) (*models.ImageBuildJobStats, error) {
	stats := &models.ImageBuildJobStats{}

	err := r.db.Pool().QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status = 'success'),
			COUNT(*) FILTER (WHERE status = 'failed'),
			COUNT(*) FILTER (WHERE status = 'building'),
			COALESCE(AVG(duration_ms) FILTER (WHERE status = 'success'), 0)::INTEGER
		FROM image_build_jobs WHERE host_id = $1`, hostID,
	).Scan(&stats.TotalBuilds, &stats.Successful, &stats.Failed, &stats.Building, &stats.AvgDurationMs)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get image build job stats")
	}

	var lastBuildAt *time.Time
	err = r.db.Pool().QueryRow(ctx, `
		SELECT MAX(completed_at) FROM image_build_jobs WHERE host_id = $1 AND completed_at IS NOT NULL`, hostID,
	).Scan(&lastBuildAt)
	if err == nil && lastBuildAt != nil {
		stats.LastBuildAt = lastBuildAt
	}

	return stats, nil
}

// ============================================================================
// DockerfileTemplateRepository
// ============================================================================

// DockerfileTemplateRepository implements imagebuilder.TemplateRepository
// on PostgreSQL.
type DockerfileTemplateRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewDockerfileTemplateRepository constructs a template repository.
func NewDockerfileTemplateRepository(db *DB, log *logger.Logger) *DockerfileTemplateRepository {
	return &DockerfileTemplateRepository{
		db:     db,
		logger: log.Named("repo.dockerfile_templates"),
	}
}

// Create inserts a new Dockerfile template.
func (r *DockerfileTemplateRepository) Create(ctx context.Context, t *models.DockerfileTemplate) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	now := time.Now()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now

	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO dockerfile_templates (
			id, host_id, name, description, category, dockerfile,
			default_args, default_labels, is_builtin, created_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		t.ID, t.HostID, t.Name, t.Description, t.Category, t.Dockerfile,
		t.DefaultArgs, t.DefaultLabels, t.IsBuiltin, t.CreatedBy, t.CreatedAt, t.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "create dockerfile template")
	}
	return nil
}

// GetByID returns a template, or NotFound if no row exists.
func (r *DockerfileTemplateRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.DockerfileTemplate, error) {
	var t models.DockerfileTemplate
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, host_id, name, description, category, dockerfile,
			default_args, default_labels, is_builtin, created_by, created_at, updated_at
		FROM dockerfile_templates WHERE id = $1`, id,
	).Scan(
		&t.ID, &t.HostID, &t.Name, &t.Description, &t.Category, &t.Dockerfile,
		&t.DefaultArgs, &t.DefaultLabels, &t.IsBuiltin, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		if stderrors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("dockerfile_template")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get dockerfile template")
	}
	return &t, nil
}

// List returns all templates for a host, newest first.
func (r *DockerfileTemplateRepository) List(ctx context.Context, hostID uuid.UUID) ([]models.DockerfileTemplate, error) {
	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, host_id, name, description, category, dockerfile,
			default_args, default_labels, is_builtin, created_by, created_at, updated_at
		FROM dockerfile_templates WHERE host_id = $1
		ORDER BY is_builtin DESC, created_at DESC`, hostID,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "list dockerfile templates")
	}
	defer rows.Close()

	results := make([]models.DockerfileTemplate, 0)
	for rows.Next() {
		var t models.DockerfileTemplate
		if err := rows.Scan(
			&t.ID, &t.HostID, &t.Name, &t.Description, &t.Category, &t.Dockerfile,
			&t.DefaultArgs, &t.DefaultLabels, &t.IsBuiltin, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "scan dockerfile template")
		}
		results = append(results, t)
	}
	return results, nil
}

// Update writes the mutable fields of an existing template.
func (r *DockerfileTemplateRepository) Update(ctx context.Context, t *models.DockerfileTemplate) error {
	t.UpdatedAt = time.Now()
	_, err := r.db.Pool().Exec(ctx, `
		UPDATE dockerfile_templates SET
			name = $2, description = $3, category = $4, dockerfile = $5,
			default_args = $6, default_labels = $7, is_builtin = $8, updated_at = $9
		WHERE id = $1`,
		t.ID, t.Name, t.Description, t.Category, t.Dockerfile,
		t.DefaultArgs, t.DefaultLabels, t.IsBuiltin, t.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "update dockerfile template")
	}
	return nil
}

// Delete removes a template by ID. Builtin templates can be deleted at the
// repository level — the service layer enforces the IsBuiltin guard.
func (r *DockerfileTemplateRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Pool().Exec(ctx, `DELETE FROM dockerfile_templates WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "delete dockerfile template")
	}
	return nil
}
