-- 049_crontab: managed cron job entries and execution history.
-- Part of the usulnet crontab manager — ported from v26.2.7 047_crontab.
-- Renumbered to 049 to slot above v26.5.0's 044 (recon_module) /
-- 045 (recon_retention) and the v26.5.1 session-01 050_firewall.

CREATE TABLE crontab_entries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    description     TEXT DEFAULT '',
    schedule        VARCHAR(100) NOT NULL,                  -- 5-field cron expression
    command_type    VARCHAR(20) NOT NULL DEFAULT 'shell',   -- shell, docker, http
    command         TEXT NOT NULL,
    container_id    VARCHAR(128),                           -- for docker command_type
    working_dir     VARCHAR(512),                           -- for shell command_type
    http_method     VARCHAR(10),                            -- for http command_type
    http_url        TEXT,                                   -- for http command_type
    enabled         BOOLEAN NOT NULL DEFAULT true,
    run_count       BIGINT NOT NULL DEFAULT 0,
    fail_count      BIGINT NOT NULL DEFAULT 0,
    last_run_at     TIMESTAMPTZ,
    last_run_status VARCHAR(20),                            -- success, failed
    last_run_output TEXT,
    next_run_at     TIMESTAMPTZ,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_crontab_entries_host    ON crontab_entries(host_id);
CREATE INDEX idx_crontab_entries_enabled ON crontab_entries(enabled);

CREATE TABLE crontab_executions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entry_id    UUID NOT NULL REFERENCES crontab_entries(id) ON DELETE CASCADE,
    host_id     UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    status      VARCHAR(20) NOT NULL DEFAULT 'running',     -- running, success, failed
    output      TEXT DEFAULT '',
    error       TEXT DEFAULT '',
    exit_code   INTEGER,
    duration_ms BIGINT NOT NULL DEFAULT 0,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_crontab_executions_entry   ON crontab_executions(entry_id);
CREATE INDEX idx_crontab_executions_started ON crontab_executions(started_at DESC);

CREATE TRIGGER crontab_entries_updated_at
    BEFORE UPDATE ON crontab_entries
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
