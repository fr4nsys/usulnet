-- ============================================================================
-- 010_updates: Update tracking, policies, webhooks, caches
-- ============================================================================

-- ============================================================================
-- Updates (operation records)
-- ============================================================================
CREATE TABLE updates (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id                 UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    type                    VARCHAR(20) NOT NULL DEFAULT 'container',
    target_id               VARCHAR(255) NOT NULL,
    target_name             VARCHAR(255) NOT NULL,
    image                   VARCHAR(500) NOT NULL,
    from_version            VARCHAR(255) NOT NULL,
    to_version              VARCHAR(255) NOT NULL,
    from_digest             VARCHAR(100),
    to_digest               VARCHAR(100),
    status                  VARCHAR(30) NOT NULL DEFAULT 'pending',
    trigger                 VARCHAR(30) NOT NULL DEFAULT 'manual',
    backup_id               UUID REFERENCES backups(id) ON DELETE SET NULL,
    changelog_url           TEXT,
    changelog_body          TEXT,
    security_score_before   INTEGER,
    security_score_after    INTEGER,
    health_check_passed     BOOLEAN,
    rollback_reason         TEXT,
    error_message           TEXT,
    duration_ms             BIGINT,
    created_by              UUID REFERENCES users(id) ON DELETE SET NULL,
    started_at              TIMESTAMPTZ,
    completed_at            TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT updates_type_check CHECK (type IN ('container', 'stack', 'service')),
    CONSTRAINT updates_status_check CHECK (status IN (
        'pending', 'checking', 'available', 'pulling', 'backing_up',
        'updating', 'health_check', 'completed', 'failed', 'rolled_back', 'skipped'
    )),
    CONSTRAINT updates_trigger_check CHECK (trigger IN (
        'manual', 'scheduled', 'webhook', 'watchtower', 'automatic'
    ))
);

CREATE INDEX idx_updates_host_id ON updates(host_id);
CREATE INDEX idx_updates_target_id ON updates(target_id);
CREATE INDEX idx_updates_status ON updates(status);
CREATE INDEX idx_updates_trigger ON updates(trigger);
CREATE INDEX idx_updates_created_at ON updates(created_at DESC);
CREATE INDEX idx_updates_host_target ON updates(host_id, target_id);
CREATE INDEX idx_updates_host_status ON updates(host_id, status);
CREATE INDEX idx_updates_host_target_status_created ON updates(host_id, target_id, status, created_at DESC);

-- Auto-calculate duration on insert/update
CREATE OR REPLACE FUNCTION calculate_update_duration()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.completed_at IS NOT NULL AND NEW.started_at IS NOT NULL THEN
        NEW.duration_ms = EXTRACT(EPOCH FROM (NEW.completed_at - NEW.started_at)) * 1000;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_duration
    BEFORE INSERT OR UPDATE ON updates
    FOR EACH ROW EXECUTE FUNCTION calculate_update_duration();

-- ============================================================================
-- Update Policies
-- ============================================================================
CREATE TABLE update_policies (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id             UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    target_type         VARCHAR(20) NOT NULL DEFAULT 'container',
    target_id           VARCHAR(255) NOT NULL,
    target_name         VARCHAR(255) NOT NULL,
    is_enabled          BOOLEAN NOT NULL DEFAULT true,
    auto_update         BOOLEAN NOT NULL DEFAULT false,
    auto_backup         BOOLEAN NOT NULL DEFAULT true,
    include_prerelease  BOOLEAN NOT NULL DEFAULT false,
    schedule            VARCHAR(100),
    notify_on_update    BOOLEAN NOT NULL DEFAULT true,
    notify_on_failure   BOOLEAN NOT NULL DEFAULT true,
    max_retries         INTEGER NOT NULL DEFAULT 3,
    health_check_wait   INTEGER NOT NULL DEFAULT 30,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT update_policies_target_type_check CHECK (target_type IN ('container', 'stack', 'service')),
    CONSTRAINT update_policies_max_retries_check CHECK (max_retries >= 0 AND max_retries <= 10),
    CONSTRAINT update_policies_health_check_wait_check CHECK (health_check_wait >= 5 AND health_check_wait <= 600),
    CONSTRAINT update_policies_unique_target UNIQUE (host_id, target_type, target_id)
);

CREATE INDEX idx_update_policies_host_id ON update_policies(host_id);
CREATE INDEX idx_update_policies_target ON update_policies(target_type, target_id);
CREATE INDEX idx_update_policies_enabled ON update_policies(is_enabled) WHERE is_enabled = true;
CREATE INDEX idx_update_policies_auto_update ON update_policies(auto_update) WHERE auto_update = true;

CREATE TRIGGER update_policies_updated_at
    BEFORE UPDATE ON update_policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Update Webhooks
-- ============================================================================
CREATE TABLE update_webhooks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    target_type     VARCHAR(20) NOT NULL DEFAULT 'container',
    target_id       VARCHAR(255) NOT NULL,
    token           VARCHAR(64) NOT NULL UNIQUE,
    is_enabled      BOOLEAN NOT NULL DEFAULT true,
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT update_webhooks_target_type_check CHECK (target_type IN ('container', 'stack', 'service')),
    CONSTRAINT update_webhooks_unique_target UNIQUE (host_id, target_type, target_id)
);

CREATE INDEX idx_update_webhooks_token ON update_webhooks(token);
CREATE INDEX idx_update_webhooks_host_id ON update_webhooks(host_id);
CREATE INDEX idx_update_webhooks_enabled ON update_webhooks(is_enabled) WHERE is_enabled = true;

-- ============================================================================
-- Image Version Cache
-- ============================================================================
CREATE TABLE image_version_cache (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    image           VARCHAR(500) NOT NULL,
    registry        VARCHAR(255) NOT NULL,
    tag             VARCHAR(255) NOT NULL,
    digest          VARCHAR(100),
    size_bytes      BIGINT,
    os              VARCHAR(50),
    arch            VARCHAR(50),
    created_at      TIMESTAMPTZ,
    checked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    CONSTRAINT image_version_cache_unique UNIQUE (image, tag)
);

CREATE INDEX idx_image_version_cache_image ON image_version_cache(image);
CREATE INDEX idx_image_version_cache_expires ON image_version_cache(expires_at);
CREATE INDEX idx_image_version_cache_checked ON image_version_cache(checked_at DESC);

-- ============================================================================
-- Changelog Cache
-- ============================================================================
CREATE TABLE changelog_cache (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    image           VARCHAR(500) NOT NULL,
    version         VARCHAR(255) NOT NULL,
    title           VARCHAR(500),
    body            TEXT,
    url             TEXT,
    author          VARCHAR(255),
    is_prerelease   BOOLEAN NOT NULL DEFAULT false,
    is_draft        BOOLEAN NOT NULL DEFAULT false,
    published_at    TIMESTAMPTZ,
    fetched_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    source          VARCHAR(50) NOT NULL DEFAULT 'github',
    CONSTRAINT changelog_cache_unique UNIQUE (image, version)
);

CREATE INDEX idx_changelog_cache_image ON changelog_cache(image);
CREATE INDEX idx_changelog_cache_expires ON changelog_cache(expires_at);

-- ============================================================================
-- Views
-- ============================================================================
CREATE OR REPLACE VIEW update_stats_by_host AS
SELECT
    host_id,
    COUNT(*) AS total_updates,
    COUNT(*) FILTER (WHERE status = 'completed') AS successful_count,
    COUNT(*) FILTER (WHERE status = 'failed') AS failed_count,
    COUNT(*) FILTER (WHERE status = 'rolled_back') AS rolled_back_count,
    AVG(duration_ms) FILTER (WHERE duration_ms IS NOT NULL) AS avg_duration_ms,
    MAX(created_at) AS last_update_at
FROM updates GROUP BY host_id;

CREATE OR REPLACE VIEW pending_updates AS
SELECT DISTINCT ON (u.host_id, u.target_id)
    u.host_id, u.target_id, u.target_name, u.image,
    u.to_version AS available_version, u.created_at AS detected_at,
    p.auto_update, p.auto_backup
FROM updates u
LEFT JOIN update_policies p ON p.host_id = u.host_id
    AND p.target_type = u.type AND p.target_id = u.target_id
WHERE u.status = 'available'
ORDER BY u.host_id, u.target_id, u.created_at DESC;

CREATE OR REPLACE VIEW recent_updates AS
SELECT
    u.id, u.host_id, h.name AS host_name, u.type, u.target_id, u.target_name,
    u.image, u.from_version, u.to_version, u.status, u.trigger,
    u.duration_ms, u.security_score_before, u.security_score_after,
    (u.security_score_after - u.security_score_before) AS security_delta,
    u.health_check_passed, u.created_at, u.completed_at
FROM updates u
JOIN hosts h ON h.id = u.host_id
WHERE u.created_at > NOW() - INTERVAL '7 days'
ORDER BY u.created_at DESC;

-- Cache cleanup function
CREATE OR REPLACE FUNCTION cleanup_update_caches()
RETURNS void AS $$
BEGIN
    DELETE FROM image_version_cache WHERE expires_at < NOW();
    DELETE FROM changelog_cache WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

COMMENT ON TABLE updates IS 'Records of container/stack update operations';
COMMENT ON TABLE update_policies IS 'Configuration for automatic update behavior per target';
COMMENT ON TABLE update_webhooks IS 'Webhook tokens for triggering updates externally';
COMMENT ON TABLE image_version_cache IS 'Cache for remote registry version information';
COMMENT ON TABLE changelog_cache IS 'Cache for fetched release changelogs';
