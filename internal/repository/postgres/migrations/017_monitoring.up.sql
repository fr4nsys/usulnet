-- ============================================================================
-- 017_monitoring: Unified metrics snapshots and terminal session tracking
-- ============================================================================

-- ============================================================================
-- Metrics Snapshots (unified host + container time-series)
-- ============================================================================
CREATE TABLE metrics_snapshots (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id             UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    metric_type         TEXT NOT NULL,
    container_id        TEXT,
    container_name      TEXT,
    -- Common metrics
    cpu_percent         DOUBLE PRECISION,
    memory_used         BIGINT,
    memory_total        BIGINT,
    memory_percent      DOUBLE PRECISION,
    -- Network I/O
    network_rx_bytes    BIGINT DEFAULT 0,
    network_tx_bytes    BIGINT DEFAULT 0,
    -- Disk / Block I/O
    disk_used           BIGINT,
    disk_total          BIGINT,
    disk_percent        DOUBLE PRECISION,
    block_read          BIGINT DEFAULT 0,
    block_write         BIGINT DEFAULT 0,
    -- Container-specific
    pids                INT,
    state               TEXT,
    health              TEXT,
    uptime_seconds      BIGINT,
    -- Host-specific
    containers_total    INT,
    containers_running  INT,
    containers_stopped  INT,
    images_total        INT,
    volumes_total       INT,
    -- Extra
    labels              JSONB DEFAULT '{}',
    collected_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_metrics_snapshots_host_time ON metrics_snapshots(host_id, collected_at DESC);
CREATE INDEX idx_metrics_snapshots_type_time ON metrics_snapshots(metric_type, collected_at DESC);
CREATE INDEX idx_metrics_snapshots_container ON metrics_snapshots(container_id, collected_at DESC)
    WHERE container_id IS NOT NULL;
CREATE INDEX idx_metrics_snapshots_collected ON metrics_snapshots(collected_at);
CREATE INDEX idx_metrics_snapshots_collected_brin ON metrics_snapshots USING BRIN (collected_at)
    WITH (pages_per_range = 128);

COMMENT ON TABLE metrics_snapshots IS 'Unified time-series metrics for hosts and containers (primary metrics storage)';

-- ============================================================================
-- Terminal Sessions (audit for container/host terminal access)
-- ============================================================================
CREATE TABLE terminal_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    username        VARCHAR(100) NOT NULL,
    target_type     VARCHAR(20) NOT NULL,
    target_id       VARCHAR(255) NOT NULL,
    target_name     VARCHAR(255) NOT NULL,
    host_id         UUID REFERENCES hosts(id) ON DELETE SET NULL,
    shell           VARCHAR(100) NOT NULL DEFAULT '/bin/sh',
    term_type       VARCHAR(50) NOT NULL DEFAULT 'xterm-256color',
    term_cols       INTEGER NOT NULL DEFAULT 80,
    term_rows       INTEGER NOT NULL DEFAULT 24,
    client_ip       VARCHAR(45) NOT NULL DEFAULT '',
    user_agent      TEXT NOT NULL DEFAULT '',
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at        TIMESTAMPTZ,
    duration_ms     BIGINT GENERATED ALWAYS AS (
        CASE WHEN ended_at IS NOT NULL
        THEN EXTRACT(EPOCH FROM (ended_at - started_at)) * 1000
        ELSE NULL END
    ) STORED,
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    error_message   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_terminal_sessions_user ON terminal_sessions(user_id);
CREATE INDEX idx_terminal_sessions_target ON terminal_sessions(target_type, target_id);
CREATE INDEX idx_terminal_sessions_host ON terminal_sessions(host_id);
CREATE INDEX idx_terminal_sessions_started ON terminal_sessions(started_at DESC);
CREATE INDEX idx_terminal_sessions_status ON terminal_sessions(status) WHERE status = 'active';

-- Active sessions view
CREATE OR REPLACE VIEW active_terminal_sessions AS
SELECT
    ts.*, u.email as user_email, h.name as host_name
FROM terminal_sessions ts
LEFT JOIN users u ON ts.user_id = u.id
LEFT JOIN hosts h ON ts.host_id = h.id
WHERE ts.status = 'active';

-- Stale session cleanup
CREATE OR REPLACE FUNCTION cleanup_stale_terminal_sessions(max_age_hours INTEGER DEFAULT 24)
RETURNS INTEGER AS $$
DECLARE affected_rows INTEGER;
BEGIN
    UPDATE terminal_sessions
    SET status = 'disconnected',
        ended_at = started_at + (max_age_hours * INTERVAL '1 hour'),
        error_message = 'Session cleanup: assumed disconnected'
    WHERE status = 'active'
      AND started_at < NOW() - (max_age_hours * INTERVAL '1 hour');
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    RETURN affected_rows;
END;
$$ LANGUAGE plpgsql;
