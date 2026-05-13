-- Rollback for the recon retention worker mark column.

DROP INDEX IF EXISTS idx_recon_metadata_artifacts_marked;

ALTER TABLE recon_metadata_artifacts
    DROP COLUMN IF EXISTS marked_for_deletion_at;
