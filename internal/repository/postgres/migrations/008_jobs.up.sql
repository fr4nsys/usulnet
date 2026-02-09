-- ============================================================================
-- 008_jobs: Background job system
-- ============================================================================

CREATE TABLE jobs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type                VARCHAR(50) NOT NULL,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    priority            INTEGER NOT NULL DEFAULT 5,
    payload             JSONB,
    result              JSONB,
    error_message       TEXT,
    progress            INTEGER DEFAULT 0,
    progress_message    TEXT,
    attempts            INTEGER NOT NULL DEFAULT 0,
    max_attempts        INTEGER NOT NULL DEFAULT 3,
    host_id             UUID REFERENCES hosts(id) ON DELETE CASCADE,
    target_type         VARCHAR(20),
    target_id           UUID,
    created_by          UUID REFERENCES users(id) ON DELETE SET NULL,
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_jobs_status ON jobs(status);
CREATE INDEX idx_jobs_type ON jobs(type);
CREATE INDEX idx_jobs_priority ON jobs(priority DESC);
CREATE INDEX idx_jobs_host ON jobs(host_id);
CREATE INDEX idx_jobs_target ON jobs(target_type, target_id);
CREATE INDEX idx_jobs_created ON jobs(created_at);
CREATE INDEX idx_jobs_pending ON jobs(status, priority DESC, created_at)
    WHERE status IN ('pending', 'queued');

CREATE TRIGGER update_jobs_updated_at
    BEFORE UPDATE ON jobs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Scheduled Jobs (recurring)
-- ============================================================================
CREATE TABLE scheduled_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    type            VARCHAR(50) NOT NULL,
    schedule        VARCHAR(100) NOT NULL,
    payload         JSONB,
    is_enabled      BOOLEAN NOT NULL DEFAULT true,
    host_id         UUID REFERENCES hosts(id) ON DELETE CASCADE,
    target_type     VARCHAR(20),
    target_id       UUID,
    target_name     VARCHAR(255),
    last_run_at     TIMESTAMPTZ,
    last_run_status VARCHAR(20),
    next_run_at     TIMESTAMPTZ,
    run_count       INTEGER NOT NULL DEFAULT 0,
    fail_count      INTEGER NOT NULL DEFAULT 0,
    priority        INTEGER NOT NULL DEFAULT 5,
    max_attempts    INTEGER NOT NULL DEFAULT 3,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scheduled_jobs_enabled ON scheduled_jobs(is_enabled, next_run_at)
    WHERE is_enabled = true;
CREATE INDEX idx_scheduled_jobs_host ON scheduled_jobs(host_id);
CREATE INDEX idx_scheduled_jobs_type ON scheduled_jobs(type);

CREATE TRIGGER update_scheduled_jobs_updated_at
    BEFORE UPDATE ON scheduled_jobs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Job Events (real-time progress)
-- ============================================================================
CREATE TABLE job_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id          UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    event_type      VARCHAR(50) NOT NULL,
    data            JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_job_events_job ON job_events(job_id);
CREATE INDEX idx_job_events_created ON job_events(created_at);
CREATE INDEX idx_job_events_created_brin ON job_events USING BRIN (created_at)
    WITH (pages_per_range = 128);
