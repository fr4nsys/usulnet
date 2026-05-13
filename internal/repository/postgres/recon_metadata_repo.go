// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/fr4nsys/usulnet/internal/services/metadata"
)

// ReconMetadataRepository implements metadata.Repository against
// PostgreSQL. It writes recon_metadata_jobs and recon_metadata_artifacts
// rows. Artifact file storage itself is handled by metadata.ArtifactStore;
// the repository only persists references (storage_ref) and content hashes.
type ReconMetadataRepository struct {
	db *DB
}

// NewReconMetadataRepository constructs a ReconMetadataRepository.
func NewReconMetadataRepository(db *DB) *ReconMetadataRepository {
	return &ReconMetadataRepository{db: db}
}

// ============================================================================
// Jobs
// ============================================================================

// InsertJob persists a new metadata job. On return, j.ID, j.CreatedAt and
// j.UpdatedAt are populated. If j.ID is non-zero on entry, that value is
// honored; otherwise the database generates one via gen_random_uuid().
func (r *ReconMetadataRepository) InsertJob(ctx context.Context, j *metadata.Job) error {
	return r.insertJob(ctx, r.db, j)
}

// insertJob is the shared implementation used by both InsertJob and
// InsertJobWithArtifacts. The querier argument lets the caller wire it
// to either *DB or pgx.Tx.
func (r *ReconMetadataRepository) insertJob(ctx context.Context, q execQuerier, j *metadata.Job) error {
	const query = `
		INSERT INTO recon_metadata_jobs
			(id, source, source_ref, mode, status, artifact_count, error,
			 started_at, finished_at, created_by)
		VALUES (COALESCE($1, gen_random_uuid()), $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, created_at, updated_at`

	status := j.Status
	if status == "" {
		status = metadata.JobQueued
	}

	var idArg any
	if j.ID != uuid.Nil {
		idArg = j.ID
	}

	err := q.QueryRow(ctx, query,
		idArg,
		string(j.Source), nullableString(j.SourceRef), string(j.Mode), string(status),
		j.ArtifactCount, nullableString(j.Error), j.StartedAt, j.FinishedAt, j.CreatedBy,
	).Scan(&j.ID, &j.CreatedAt, &j.UpdatedAt)
	if err != nil {
		return fmt.Errorf("recon repo: insert metadata job: %w", err)
	}
	j.Status = status
	return nil
}

// execQuerier is the subset of *DB / pgx.Tx the metadata repo uses for
// single-row queries. It lets insertJob and insertArtifact run inside a
// caller-provided transaction.
type execQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
	Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
}

// UpdateJob updates the mutable fields of a metadata job.
func (r *ReconMetadataRepository) UpdateJob(ctx context.Context, j *metadata.Job) error {
	const query = `
		UPDATE recon_metadata_jobs
		SET status = $2,
		    artifact_count = $3,
		    error = $4,
		    started_at = $5,
		    finished_at = $6,
		    updated_at = NOW()
		WHERE id = $1
		RETURNING updated_at`
	err := r.db.QueryRow(ctx, query,
		j.ID, string(j.Status), j.ArtifactCount, nullableString(j.Error),
		j.StartedAt, j.FinishedAt,
	).Scan(&j.UpdatedAt)
	if err != nil {
		return fmt.Errorf("recon repo: update metadata job: %w", err)
	}
	return nil
}

// GetJobByID returns a metadata job by primary key.
func (r *ReconMetadataRepository) GetJobByID(ctx context.Context, id uuid.UUID) (*metadata.Job, error) {
	j, err := r.scanJob(r.db.QueryRow(ctx, metadataJobSelect+` WHERE id = $1`, id))
	if err != nil {
		return nil, fmt.Errorf("recon repo: get metadata job by id: %w", err)
	}
	return j, nil
}

// ListJobs returns metadata jobs matching filter, ordered by creation time
// descending.
func (r *ReconMetadataRepository) ListJobs(ctx context.Context, filter metadata.ListJobsFilter) ([]metadata.Job, error) {
	var (
		conds []string
		args  []any
	)
	if filter.Status != nil {
		conds = append(conds, fmt.Sprintf("status = $%d", len(args)+1))
		args = append(args, string(*filter.Status))
	}
	if filter.CreatedBy != nil {
		conds = append(conds, fmt.Sprintf("created_by = $%d", len(args)+1))
		args = append(args, *filter.CreatedBy)
	}
	if filter.Since != nil {
		conds = append(conds, fmt.Sprintf("created_at >= $%d", len(args)+1))
		args = append(args, *filter.Since)
	}

	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}

	limit, offset := paginate(filter.Limit, filter.Offset, 50)
	args = append(args, limit, offset)

	query := fmt.Sprintf("%s %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d",
		metadataJobSelect, where, len(args)-1, len(args))

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("recon repo: list metadata jobs: %w", err)
	}
	defer rows.Close()

	var out []metadata.Job
	for rows.Next() {
		j, err := r.scanJob(rows)
		if err != nil {
			return nil, fmt.Errorf("recon repo: list metadata jobs: %w", err)
		}
		out = append(out, *j)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("recon repo: list metadata jobs: %w", err)
	}
	return out, nil
}

const metadataJobSelect = `
	SELECT id, source, COALESCE(source_ref, ''), mode, status, artifact_count,
	       COALESCE(error, ''), started_at, finished_at, created_by,
	       created_at, updated_at
	FROM recon_metadata_jobs`

func (r *ReconMetadataRepository) scanJob(row pgx.Row) (*metadata.Job, error) {
	var (
		j         metadata.Job
		sourceStr string
		modeStr   string
		statusStr string
	)
	if err := row.Scan(
		&j.ID, &sourceStr, &j.SourceRef, &modeStr, &statusStr, &j.ArtifactCount,
		&j.Error, &j.StartedAt, &j.FinishedAt, &j.CreatedBy,
		&j.CreatedAt, &j.UpdatedAt,
	); err != nil {
		return nil, err
	}
	j.Source = metadata.JobSource(sourceStr)
	j.Mode = metadata.JobMode(modeStr)
	j.Status = metadata.JobStatus(statusStr)
	return &j, nil
}

// ============================================================================
// Artifacts
// ============================================================================

// InsertArtifact persists a new artifact row. If a.ID is non-zero on
// entry, that value is honored; otherwise the database generates one.
// This lets callers (the metadata Service) compute storage_ref ahead of
// the insert and store the file under <job_id>/<artifact_id>/original.
func (r *ReconMetadataRepository) InsertArtifact(ctx context.Context, a *metadata.Artifact) error {
	return r.insertArtifact(ctx, r.db, a)
}

func (r *ReconMetadataRepository) insertArtifact(ctx context.Context, q execQuerier, a *metadata.Artifact) error {
	extracted, err := encodeJSONObject(a.Extracted)
	if err != nil {
		return fmt.Errorf("recon repo: insert artifact: %w", err)
	}

	var idArg any
	if a.ID != uuid.Nil {
		idArg = a.ID
	}

	const query = `
		INSERT INTO recon_metadata_artifacts
			(id, job_id, filename, mime, size_bytes, sha256, stripped_sha256,
			 extracted, storage_ref)
		VALUES (COALESCE($1, gen_random_uuid()), $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at`
	err = q.QueryRow(ctx, query,
		idArg,
		a.JobID, a.Filename, nullableString(a.MIME), a.SizeBytes,
		a.SHA256, a.StrippedSHA256, extracted, nullableString(a.StorageRef),
	).Scan(&a.ID, &a.CreatedAt)
	if err != nil {
		return fmt.Errorf("recon repo: insert artifact: %w", err)
	}
	return nil
}

// UpdateArtifact updates the mutable per-artifact fields after a
// metadata job has produced results: the extracted-metadata map, the
// stripped-copy SHA-256, and (if it changed) the storage_ref. The
// filename, size, and original sha256 are immutable.
func (r *ReconMetadataRepository) UpdateArtifact(ctx context.Context, a *metadata.Artifact) error {
	extracted, err := encodeJSONObject(a.Extracted)
	if err != nil {
		return fmt.Errorf("recon repo: update artifact: %w", err)
	}
	const query = `
		UPDATE recon_metadata_artifacts
		SET stripped_sha256 = $2,
		    extracted       = $3,
		    storage_ref     = $4
		WHERE id = $1`
	tag, err := r.db.Exec(ctx, query,
		a.ID, a.StrippedSHA256, extracted, nullableString(a.StorageRef),
	)
	if err != nil {
		return fmt.Errorf("recon repo: update artifact: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("recon repo: update artifact: %w", pgx.ErrNoRows)
	}
	return nil
}

// InsertJobWithArtifacts persists a job and its artifacts in one
// transaction. If j.ID or any a.ID is non-zero on entry, those values
// are honored; otherwise the database assigns them. On any failure the
// transaction is rolled back and no rows are visible.
func (r *ReconMetadataRepository) InsertJobWithArtifacts(ctx context.Context, j *metadata.Job, artifacts []*metadata.Artifact) error {
	return r.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := r.insertJob(ctx, &txQuerier{tx: tx}, j); err != nil {
			return err
		}
		for i, a := range artifacts {
			a.JobID = j.ID
			if err := r.insertArtifact(ctx, &txQuerier{tx: tx}, a); err != nil {
				return fmt.Errorf("artifact %d: %w", i, err)
			}
		}
		return nil
	})
}

// txQuerier adapts a pgx.Tx to the execQuerier interface used by the
// metadata repo's shared insert helpers.
type txQuerier struct{ tx pgx.Tx }

func (t *txQuerier) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	return t.tx.QueryRow(ctx, sql, args...)
}
func (t *txQuerier) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	return t.tx.Exec(ctx, sql, args...)
}

// ListArtifactsByJob returns all artifacts for a job, ordered by creation
// time ascending so the UI can render upload order.
func (r *ReconMetadataRepository) ListArtifactsByJob(ctx context.Context, jobID uuid.UUID) ([]metadata.Artifact, error) {
	const query = artifactSelect + ` WHERE job_id = $1 ORDER BY created_at ASC`
	rows, err := r.db.Query(ctx, query, jobID)
	if err != nil {
		return nil, fmt.Errorf("recon repo: list artifacts by job: %w", err)
	}
	defer rows.Close()

	var out []metadata.Artifact
	for rows.Next() {
		a, err := r.scanArtifact(rows)
		if err != nil {
			return nil, fmt.Errorf("recon repo: list artifacts by job: %w", err)
		}
		out = append(out, *a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("recon repo: list artifacts by job: %w", err)
	}
	return out, nil
}

// GetArtifactByID returns a single artifact by primary key.
func (r *ReconMetadataRepository) GetArtifactByID(ctx context.Context, id uuid.UUID) (*metadata.Artifact, error) {
	a, err := r.scanArtifact(r.db.QueryRow(ctx, artifactSelect+` WHERE id = $1`, id))
	if err != nil {
		return nil, fmt.Errorf("recon repo: get artifact by id: %w", err)
	}
	return a, nil
}

const artifactSelect = `
	SELECT id, job_id, filename, COALESCE(mime, ''), size_bytes, sha256,
	       stripped_sha256, extracted, COALESCE(storage_ref, ''), created_at
	FROM recon_metadata_artifacts`

func (r *ReconMetadataRepository) scanArtifact(row pgx.Row) (*metadata.Artifact, error) {
	var (
		a         metadata.Artifact
		extracted []byte
	)
	if err := row.Scan(
		&a.ID, &a.JobID, &a.Filename, &a.MIME, &a.SizeBytes, &a.SHA256,
		&a.StrippedSHA256, &extracted, &a.StorageRef, &a.CreatedAt,
	); err != nil {
		return nil, err
	}
	if len(extracted) > 0 {
		if err := json.Unmarshal(extracted, &a.Extracted); err != nil {
			return nil, fmt.Errorf("decode extracted: %w", err)
		}
	}
	return &a, nil
}
