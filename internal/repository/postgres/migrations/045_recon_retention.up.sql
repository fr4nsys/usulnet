-- Recon retention worker — two-phase delete marker for metadata artifacts.
-- See docs/v26.5/sessions/12-release.md and the retention worker comments.
-- usulnet v26.5.0.

-- Phase 1 marks an artifact for deletion (storage_ref is preserved so the
-- sweep can still locate the on-disk file). Phase 2 (after the grace
-- period) removes the row, deletes the file, and appends to
-- recon_audit_log with action='retention.delete'.
ALTER TABLE recon_metadata_artifacts
    ADD COLUMN IF NOT EXISTS marked_for_deletion_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_recon_metadata_artifacts_marked
    ON recon_metadata_artifacts(marked_for_deletion_at)
    WHERE marked_for_deletion_at IS NOT NULL;
