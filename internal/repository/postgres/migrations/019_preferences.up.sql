-- ============================================================================
-- 019_preferences: User preferences and session tracking
-- ============================================================================

-- ============================================================================
-- User Preferences (structured per-user settings)
-- ============================================================================
CREATE TABLE user_preferences (
    user_id                 UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- Terminal preferences
    terminal_shell          TEXT NOT NULL DEFAULT '/bin/bash',
    terminal_theme          TEXT NOT NULL DEFAULT 'dark',
    terminal_font_size      INT NOT NULL DEFAULT 14,
    terminal_scrollback     INT NOT NULL DEFAULT 10000,
    -- UI preferences
    ui_theme                TEXT NOT NULL DEFAULT 'dark',
    ui_items_per_page       INT NOT NULL DEFAULT 25,
    ui_date_format          TEXT NOT NULL DEFAULT 'YYYY-MM-DD HH:mm:ss',
    ui_sidebar_collapsed    BOOLEAN NOT NULL DEFAULT false,
    -- Notification preferences
    notify_updates          BOOLEAN NOT NULL DEFAULT true,
    notify_security         BOOLEAN NOT NULL DEFAULT true,
    notify_backups          BOOLEAN NOT NULL DEFAULT true,
    -- Default connections
    default_gitea_connection_id     UUID REFERENCES gitea_connections(id) ON DELETE SET NULL,
    default_codeserver_workspace_id UUID REFERENCES codeserver_workspaces(id) ON DELETE SET NULL,
    -- Metrics dashboard layout
    metrics_dashboard_layout JSONB DEFAULT '{}',
    -- Timestamps
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_user_preferences_updated_at
    BEFORE UPDATE ON user_preferences
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- User Sessions (for profile session management display)
-- ============================================================================
CREATE TABLE user_sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL,
    ip_address  INET,
    user_agent  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_expires ON user_sessions(expires_at);

COMMENT ON TABLE user_sessions IS 'User session tracking for profile/security display';
