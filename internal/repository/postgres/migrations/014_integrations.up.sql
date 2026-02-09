-- ============================================================================
-- 014_integrations: Git providers (Gitea/GitHub/GitLab), Code Server
-- ============================================================================

-- ============================================================================
-- Git Connections (multi-provider)
-- ============================================================================
CREATE TABLE gitea_connections (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id                     UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name                        TEXT NOT NULL,
    url                         TEXT NOT NULL,
    provider_type               VARCHAR(20) NOT NULL DEFAULT 'gitea',
    api_token_encrypted         TEXT NOT NULL,
    webhook_secret_encrypted    TEXT,
    status                      TEXT NOT NULL DEFAULT 'pending',
    status_message              TEXT,
    last_sync_at                TIMESTAMPTZ,
    repos_count                 INT NOT NULL DEFAULT 0,
    auto_sync                   BOOLEAN NOT NULL DEFAULT true,
    sync_interval_minutes       INT NOT NULL DEFAULT 30,
    gitea_version               TEXT,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by                  UUID REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_gitea_connections_host ON gitea_connections(host_id);
CREATE INDEX idx_gitea_connections_status ON gitea_connections(status);
CREATE INDEX idx_gitea_connections_provider ON gitea_connections(provider_type);

CREATE TRIGGER update_gitea_connections_updated_at
    BEFORE UPDATE ON gitea_connections
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

COMMENT ON COLUMN gitea_connections.provider_type IS 'Git provider: gitea, github, gitlab';

-- ============================================================================
-- Git Repositories
-- ============================================================================
CREATE TABLE gitea_repositories (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id   UUID NOT NULL REFERENCES gitea_connections(id) ON DELETE CASCADE,
    provider_type   VARCHAR(20) NOT NULL DEFAULT 'gitea',
    gitea_id        BIGINT NOT NULL,
    full_name       TEXT NOT NULL,
    description     TEXT,
    clone_url       TEXT NOT NULL,
    html_url        TEXT NOT NULL,
    default_branch  TEXT NOT NULL DEFAULT 'main',
    is_private      BOOLEAN NOT NULL DEFAULT false,
    is_fork         BOOLEAN NOT NULL DEFAULT false,
    is_archived     BOOLEAN NOT NULL DEFAULT false,
    stars_count     INT NOT NULL DEFAULT 0,
    forks_count     INT NOT NULL DEFAULT 0,
    open_issues     INT NOT NULL DEFAULT 0,
    size_kb         BIGINT NOT NULL DEFAULT 0,
    last_commit_sha TEXT,
    last_commit_at  TIMESTAMPTZ,
    last_sync_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(connection_id, gitea_id)
);

CREATE INDEX idx_gitea_repos_connection ON gitea_repositories(connection_id);
CREATE INDEX idx_gitea_repos_fullname ON gitea_repositories(full_name);
CREATE INDEX idx_gitea_repositories_provider ON gitea_repositories(provider_type);

CREATE TRIGGER update_gitea_repositories_updated_at
    BEFORE UPDATE ON gitea_repositories
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

COMMENT ON COLUMN gitea_repositories.provider_type IS 'Git provider: gitea, github, gitlab';

-- ============================================================================
-- Git Webhooks (received events log)
-- ============================================================================
CREATE TABLE gitea_webhooks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id   UUID NOT NULL REFERENCES gitea_connections(id) ON DELETE CASCADE,
    repository_id   UUID REFERENCES gitea_repositories(id) ON DELETE SET NULL,
    event_type      TEXT NOT NULL,
    delivery_id     TEXT,
    payload         JSONB NOT NULL,
    processed       BOOLEAN NOT NULL DEFAULT false,
    processed_at    TIMESTAMPTZ,
    process_result  TEXT,
    process_error   TEXT,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_gitea_webhooks_connection ON gitea_webhooks(connection_id);
CREATE INDEX idx_gitea_webhooks_event ON gitea_webhooks(event_type);
CREATE INDEX idx_gitea_webhooks_unprocessed ON gitea_webhooks(processed) WHERE processed = false;

-- ============================================================================
-- Code Server Workspaces
-- ============================================================================
CREATE TABLE codeserver_workspaces (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    workspace_path      TEXT NOT NULL,
    bind_host           TEXT,
    bind_container_id   TEXT,
    settings            JSONB DEFAULT '{}',
    status              TEXT NOT NULL DEFAULT 'stopped',
    last_accessed_at    TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, name)
);

CREATE INDEX idx_codeserver_workspaces_user ON codeserver_workspaces(user_id);

CREATE TRIGGER update_codeserver_workspaces_updated_at
    BEFORE UPDATE ON codeserver_workspaces
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
