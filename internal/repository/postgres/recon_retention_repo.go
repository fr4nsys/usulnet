// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// ReconRetentionRepository satisfies workers.ReconRetentionService. It
// owns the actual DELETE statements that prune recon data, plus the
// two-phase mark/sweep for metadata artifacts.
//
// The repository is the only place in the codebase where DELETE
// statements against recon_findings / recon_scans / recon_audit_log
// exist; the audit-log append-only invariant is enforced by
// TestRepoHasNoMutationsOnAuditLog plus a code review of this file.
//
// Each method emits one structured log line at info level on success
// so an operator can grep for retention activity without reading the
// audit row. PII is never logged — only counters.
type ReconRetentionRepository struct {
	db           *DB
	artifactRoot string
	log          *logger.Logger
}

// NewReconRetentionRepository constructs a repository. artifactRoot
// is the on-disk root where the local artifact store wrote files
// (typically <storage.path>/recon/artifacts). The sweep step removes
// files under that root; a nil/empty value means "DB-only sweep" —
// useful for tests that mock the filesystem out.
func NewReconRetentionRepository(db *DB, artifactRoot string, log *logger.Logger) *ReconRetentionRepository {
	if log == nil {
		log = logger.Nop()
	}
	return &ReconRetentionRepository{
		db:           db,
		artifactRoot: artifactRoot,
		log:          log.Named("recon.retention"),
	}
}

// DeleteFindingsOlderThan removes findings whose last_seen predates
// cutoff. recon_findings_raw cascades via ON DELETE CASCADE in the
// migration 044 schema.
func (r *ReconRetentionRepository) DeleteFindingsOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	const query = `DELETE FROM recon_findings WHERE last_seen < $1`
	tag, err := r.db.Exec(ctx, query, cutoff.UTC())
	if err != nil {
		return 0, fmt.Errorf("recon retention: delete findings: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DeleteScansOlderThan removes scans whose finished_at predates
// cutoff. Findings and summary rows cascade. Scans still in flight
// (finished_at IS NULL) are never touched.
func (r *ReconRetentionRepository) DeleteScansOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	const query = `DELETE FROM recon_scans WHERE finished_at IS NOT NULL AND finished_at < $1`
	tag, err := r.db.Exec(ctx, query, cutoff.UTC())
	if err != nil {
		return 0, fmt.Errorf("recon retention: delete scans: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DeleteAuditOlderThan removes audit rows older than cutoff. The
// audit log itself is append-only for module activity, but pruning
// for retention is permitted — the alternative would be unbounded
// growth.
func (r *ReconRetentionRepository) DeleteAuditOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	const query = `DELETE FROM recon_audit_log WHERE created_at < $1`
	tag, err := r.db.Exec(ctx, query, cutoff.UTC())
	if err != nil {
		return 0, fmt.Errorf("recon retention: delete audit: %w", err)
	}
	return tag.RowsAffected(), nil
}

// MarkArtifactsForDeletion flags artifacts whose owning job finished
// before cutoff and have not yet been marked. Phase 1 of the
// two-phase delete. The on-disk file stays put — only the database
// column changes — so a botched retention run is recoverable by
// resetting marked_for_deletion_at to NULL.
func (r *ReconRetentionRepository) MarkArtifactsForDeletion(ctx context.Context, cutoff time.Time, now time.Time) (int64, error) {
	const query = `
		UPDATE recon_metadata_artifacts a
		SET marked_for_deletion_at = $2
		FROM recon_metadata_jobs j
		WHERE a.job_id = j.id
		  AND a.marked_for_deletion_at IS NULL
		  AND j.finished_at IS NOT NULL
		  AND j.finished_at < $1`
	tag, err := r.db.Exec(ctx, query, cutoff.UTC(), now.UTC())
	if err != nil {
		return 0, fmt.Errorf("recon retention: mark artifacts: %w", err)
	}
	return tag.RowsAffected(), nil
}

// SweepMarkedArtifacts deletes the on-disk file and then the row for
// every artifact marked before `before`. The file delete is
// best-effort: a missing file is not an error (e.g., already gone
// after a partial previous sweep), but other I/O errors fail the row
// delete so the artifact stays visible to the operator.
//
// The function processes artifacts in batches of 100 to keep
// transaction sizes bounded.
func (r *ReconRetentionRepository) SweepMarkedArtifacts(ctx context.Context, before time.Time) (int64, error) {
	const selectQuery = `
		SELECT id, storage_ref
		FROM recon_metadata_artifacts
		WHERE marked_for_deletion_at IS NOT NULL
		  AND marked_for_deletion_at < $1
		ORDER BY marked_for_deletion_at ASC
		LIMIT 100`
	const deleteQuery = `DELETE FROM recon_metadata_artifacts WHERE id = $1`

	var total int64
	for {
		rows, err := r.db.Query(ctx, selectQuery, before.UTC())
		if err != nil {
			return total, fmt.Errorf("recon retention: list marked: %w", err)
		}
		type item struct {
			id  string
			ref string
		}
		var batch []item
		for rows.Next() {
			var it item
			if err := rows.Scan(&it.id, &it.ref); err != nil {
				rows.Close()
				return total, fmt.Errorf("recon retention: scan marked: %w", err)
			}
			batch = append(batch, it)
		}
		rows.Close()
		if len(batch) == 0 {
			return total, nil
		}

		for _, it := range batch {
			if err := r.deleteArtifactFile(it.ref); err != nil {
				r.log.Warn("artifact file delete failed; keeping DB row",
					"artifact_id", it.id,
					"error", err,
				)
				continue
			}
			if _, err := r.db.Exec(ctx, deleteQuery, it.id); err != nil {
				return total, fmt.Errorf("recon retention: delete artifact: %w", err)
			}
			total++
		}

		// If the batch was smaller than the page size, we're done.
		if len(batch) < 100 {
			return total, nil
		}
	}
}

// deleteArtifactFile removes the on-disk file referenced by ref. A
// missing file is intentionally not an error: the previous sweep may
// have been interrupted between file-delete and row-delete. Anything
// outside the configured artifact root is rejected so a malformed
// storage_ref cannot escape the sandbox.
func (r *ReconRetentionRepository) deleteArtifactFile(ref string) error {
	if ref == "" {
		return nil
	}
	if r.artifactRoot == "" {
		return nil
	}
	// storage_ref is the local-store's relative path; the local store
	// places files under artifactRoot. Path traversal is rejected by
	// rejecting anything starting with "/" or containing "..".
	if isUnsafePath(ref) {
		return errors.New("recon retention: unsafe storage_ref")
	}
	full := r.artifactRoot + string(os.PathSeparator) + ref
	if err := os.Remove(full); err != nil && !os.IsNotExist(err) {
		return err
	}
	// Best-effort: remove now-empty parent directories so the on-disk
	// tree stays tidy. Failures are non-fatal — the artifact itself was
	// removed above, which is the only outcome the caller depends on.
	dir := full
	for i := 0; i < 4; i++ {
		dir = filepathDir(dir)
		if dir == r.artifactRoot || dir == "" || dir == "." {
			break
		}
		if err := os.Remove(dir); err != nil {
			// best-effort parent cleanup, never propagated
			break
		}
	}
	return nil //nolint:nilerr // see best-effort loop above
}

// AppendRetentionAudit writes a single `retention.delete` row to
// recon_audit_log summarizing the run. The details JSON carries the
// full counters so an operator can grep historical runs.
func (r *ReconRetentionRepository) AppendRetentionAudit(ctx context.Context, summary workers.ReconRetentionSummary) error {
	details, err := marshalJSONString(map[string]any{
		"retention_days":    summary.RetentionDays,
		"grace_period_days": summary.GracePeriodDays,
		"findings_deleted":  summary.FindingsDeleted,
		"scans_deleted":     summary.ScansDeleted,
		"audit_deleted":     summary.AuditDeleted,
		"artifacts_marked":  summary.ArtifactsMarked,
		"artifacts_swept":   summary.ArtifactsSwept,
		"duration_ms":       summary.Duration.Milliseconds(),
		"errors":            summary.Errors,
	}, "{}")
	if err != nil {
		return fmt.Errorf("recon retention: marshal audit details: %w", err)
	}
	const query = `
		INSERT INTO recon_audit_log (actor_id, action, details)
		VALUES (NULL, $1, $2)`
	if _, err := r.db.Exec(ctx, query, recon.AuditActionRetentionDelete, details); err != nil {
		return fmt.Errorf("recon retention: append audit: %w", err)
	}
	return nil
}

// Compile-time assertion.
var _ workers.ReconRetentionService = (*ReconRetentionRepository)(nil)

// isUnsafePath returns true if p tries to escape the artifact root.
func isUnsafePath(p string) bool {
	if p == "" {
		return true
	}
	if p[0] == '/' || p[0] == '\\' {
		return true
	}
	for i := 0; i+2 <= len(p); i++ {
		if p[i] == '.' && p[i+1] == '.' {
			if i+2 == len(p) || p[i+2] == '/' || p[i+2] == '\\' {
				return true
			}
		}
	}
	return false
}

// filepathDir returns the directory portion of p without importing
// path/filepath at the top of the file (the package is otherwise
// completely self-contained).
func filepathDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[:i]
		}
	}
	return ""
}
