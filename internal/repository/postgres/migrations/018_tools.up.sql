-- ============================================================================
-- 018_tools: User snippets, packet captures, custom log uploads
-- ============================================================================

-- ============================================================================
-- User Snippets (code editor files)
-- ============================================================================
CREATE TABLE user_snippets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    path            VARCHAR(1024) NOT NULL DEFAULT '',
    language        VARCHAR(50) NOT NULL DEFAULT 'plaintext',
    content         TEXT NOT NULL DEFAULT '',
    description     TEXT,
    tags            TEXT[],
    is_public       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_snippets_user_id ON user_snippets(user_id);
CREATE INDEX idx_user_snippets_path ON user_snippets(user_id, path);
CREATE INDEX idx_user_snippets_language ON user_snippets(language);
CREATE INDEX idx_user_snippets_updated ON user_snippets(updated_at DESC);
CREATE INDEX idx_user_snippets_search ON user_snippets USING gin(
    to_tsvector('english', name || ' ' || COALESCE(description, ''))
);
CREATE UNIQUE INDEX idx_user_snippets_unique_name ON user_snippets(user_id, path, name);

CREATE TRIGGER update_user_snippets_updated_at
    BEFORE UPDATE ON user_snippets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

COMMENT ON TABLE user_snippets IS 'User-owned code snippets and files for the editor';
COMMENT ON COLUMN user_snippets.path IS 'Virtual folder path for organization, empty string means root';
COMMENT ON COLUMN user_snippets.language IS 'Monaco editor language ID (go, javascript, python, etc)';

-- ============================================================================
-- Packet Captures
-- ============================================================================
CREATE TABLE packet_captures (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            VARCHAR(100) NOT NULL,
    interface       VARCHAR(50) NOT NULL,
    filter          TEXT DEFAULT '',
    status          VARCHAR(20) NOT NULL DEFAULT 'stopped'
        CHECK (status IN ('running', 'stopped', 'completed', 'error')),
    status_message  TEXT,
    packet_count    BIGINT NOT NULL DEFAULT 0,
    file_size       BIGINT NOT NULL DEFAULT 0,
    file_path       TEXT,
    max_packets     INTEGER DEFAULT 0,
    max_duration    INTEGER DEFAULT 0,
    pid             INTEGER DEFAULT 0,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    stopped_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_packet_captures_user ON packet_captures(user_id);
CREATE INDEX idx_packet_captures_status ON packet_captures(status);

CREATE TRIGGER update_packet_captures_updated_at
    BEFORE UPDATE ON packet_captures
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Custom Log Uploads
-- ============================================================================
CREATE TABLE custom_log_uploads (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename        VARCHAR(255) NOT NULL,
    size            BIGINT NOT NULL DEFAULT 0,
    format          VARCHAR(20) NOT NULL DEFAULT 'plain',
    line_count      INTEGER NOT NULL DEFAULT 0,
    error_count     INTEGER NOT NULL DEFAULT 0,
    description     TEXT DEFAULT '',
    file_path       TEXT DEFAULT '',
    uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_custom_log_uploads_user_id ON custom_log_uploads(user_id);
CREATE INDEX idx_custom_log_uploads_uploaded_at ON custom_log_uploads(uploaded_at DESC);
