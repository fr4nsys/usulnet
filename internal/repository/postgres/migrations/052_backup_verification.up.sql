-- 052_backup_verification: scheduled and on-demand backup verification.
-- Ported from v26.2.7 050_backup_verification; renumbered to 052 to slot
-- above v26.5.0 044_recon_module / 045_recon_retention and the v26.5.1
-- session-01/02/05 migrations (049_crontab, 050_firewall, 051_ssl_observatory).
--
-- Tables:
--   backup_verifications           — one row per verification run.
--   backup_verification_schedules  — cron-triggered verification policies.
--
-- The verification worker writes a row for every restore-test it executes;
-- rows are append-only and pruned by the existing retention worker.

CREATE TABLE IF NOT EXISTS backup_verifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backup_id       UUID NOT NULL REFERENCES backups(id) ON DELETE CASCADE,
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    method          VARCHAR(30) NOT NULL DEFAULT 'extract',
    checksum_valid  BOOLEAN,
    files_readable  BOOLEAN,
    container_test  BOOLEAN,
    data_valid      BOOLEAN,
    file_count      INTEGER NOT NULL DEFAULT 0,
    size_bytes      BIGINT NOT NULL DEFAULT 0,
    duration_ms     INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT NOT NULL DEFAULT '',
    details         JSONB NOT NULL DEFAULT '{}'::jsonb,
    verified_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_backup_verifications_backup ON backup_verifications(backup_id);
CREATE INDEX IF NOT EXISTS idx_backup_verifications_host ON backup_verifications(host_id);
CREATE INDEX IF NOT EXISTS idx_backup_verifications_status ON backup_verifications(status);
CREATE INDEX IF NOT EXISTS idx_backup_verifications_created ON backup_verifications(created_at DESC);

CREATE TABLE IF NOT EXISTS backup_verification_schedules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    schedule        VARCHAR(100) NOT NULL DEFAULT '0 3 * * 0',
    method          VARCHAR(30) NOT NULL DEFAULT 'extract',
    max_backups     INTEGER NOT NULL DEFAULT 5,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_run_at     TIMESTAMPTZ,
    last_run_status VARCHAR(20) NOT NULL DEFAULT '',
    next_run_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_bv_schedules_host ON backup_verification_schedules(host_id);
CREATE INDEX IF NOT EXISTS idx_bv_schedules_enabled ON backup_verification_schedules(enabled);

CREATE TRIGGER backup_verification_schedules_updated_at
    BEFORE UPDATE ON backup_verification_schedules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
