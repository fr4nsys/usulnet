-- ============================================================================
-- 006_backups: Backup management and schedules
-- ============================================================================

CREATE TABLE backups (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id             UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name                VARCHAR(255) NOT NULL,
    type                VARCHAR(50) NOT NULL,
    target_type         VARCHAR(50) NOT NULL,
    target_id           VARCHAR(255) NOT NULL,
    target_name         VARCHAR(255),
    status              VARCHAR(50) NOT NULL DEFAULT 'pending',
    size_bytes          BIGINT NOT NULL DEFAULT 0,
    storage_path        TEXT,
    storage_type        VARCHAR(50) NOT NULL DEFAULT 'local',
    compression         VARCHAR(20) NOT NULL DEFAULT 'gzip',
    encrypted           BOOLEAN NOT NULL DEFAULT false,
    checksum            VARCHAR(128),
    error_message       TEXT,
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ,
    verified_at         TIMESTAMPTZ,
    created_by          UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_backups_host_id ON backups(host_id);
CREATE INDEX idx_backups_type ON backups(type);
CREATE INDEX idx_backups_target ON backups(target_type, target_id);
CREATE INDEX idx_backups_status ON backups(status);
CREATE INDEX idx_backups_created_at ON backups(created_at);
CREATE INDEX idx_backups_expires_at ON backups(expires_at);
CREATE INDEX idx_backups_host_type_created ON backups(host_id, type, created_at DESC);

-- ============================================================================
-- Backup Schedules
-- ============================================================================
CREATE TABLE backup_schedules (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id             UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name                VARCHAR(255) NOT NULL,
    target_type         VARCHAR(50) NOT NULL,
    target_id           VARCHAR(255) NOT NULL,
    target_name         VARCHAR(255),
    schedule            VARCHAR(100) NOT NULL,
    retention_count     INTEGER NOT NULL DEFAULT 5,
    storage_type        VARCHAR(50) NOT NULL DEFAULT 'local',
    compression         VARCHAR(20) NOT NULL DEFAULT 'gzip',
    encrypted           BOOLEAN NOT NULL DEFAULT false,
    is_enabled          BOOLEAN NOT NULL DEFAULT true,
    last_run_at         TIMESTAMPTZ,
    last_status         VARCHAR(50),
    next_run_at         TIMESTAMPTZ,
    created_by          UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_backup_schedules_host_id ON backup_schedules(host_id);
CREATE INDEX idx_backup_schedules_enabled ON backup_schedules(is_enabled);

CREATE TRIGGER update_backup_schedules_updated_at
    BEFORE UPDATE ON backup_schedules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
