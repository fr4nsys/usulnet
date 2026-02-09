-- ============================================================================
-- 004_stacks: Docker Compose / Swarm stacks
-- ============================================================================

CREATE TABLE stacks (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id             UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name                VARCHAR(255) NOT NULL,
    type                VARCHAR(50) NOT NULL DEFAULT 'compose',
    status              VARCHAR(50) NOT NULL DEFAULT 'unknown',
    project_dir         TEXT,
    compose_file        TEXT NOT NULL,
    env_file            TEXT,
    variables           JSONB DEFAULT '{}',
    service_count       INTEGER NOT NULL DEFAULT 0,
    running_count       INTEGER NOT NULL DEFAULT 0,
    git_repo            VARCHAR(512),
    git_branch          VARCHAR(255),
    git_commit          VARCHAR(64),
    last_deployed_at    TIMESTAMPTZ,
    last_deployed_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(host_id, name)
);

CREATE INDEX idx_stacks_host_id ON stacks(host_id);
CREATE INDEX idx_stacks_name ON stacks(name);
CREATE INDEX idx_stacks_status ON stacks(status);

CREATE TRIGGER update_stacks_updated_at
    BEFORE UPDATE ON stacks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Stack Logs
-- ============================================================================
CREATE TABLE stack_logs (
    id              BIGSERIAL PRIMARY KEY,
    stack_id        UUID NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    operation       VARCHAR(50) NOT NULL,
    status          VARCHAR(50) NOT NULL DEFAULT 'running',
    output          TEXT,
    error_msg       TEXT,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX idx_stack_logs_stack_id ON stack_logs(stack_id);
CREATE INDEX idx_stack_logs_started_at ON stack_logs(started_at);
