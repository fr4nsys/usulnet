-- ============================================================================
-- 016_connections: SSH, SFTP, tunnels, web shortcuts, DB browser, LDAP browser
-- ============================================================================

-- ============================================================================
-- SSH Keys
-- ============================================================================
CREATE TABLE ssh_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(100) NOT NULL,
    key_type        VARCHAR(20) NOT NULL DEFAULT 'ed25519',
    public_key      TEXT NOT NULL,
    private_key     TEXT NOT NULL,
    passphrase      TEXT NOT NULL DEFAULT '',
    fingerprint     VARCHAR(100) NOT NULL,
    comment         VARCHAR(200) NOT NULL DEFAULT '',
    created_by      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used       TIMESTAMPTZ
);

CREATE INDEX idx_ssh_keys_created_by ON ssh_keys(created_by);
CREATE INDEX idx_ssh_keys_fingerprint ON ssh_keys(fingerprint);

CREATE TRIGGER update_ssh_keys_updated_at
    BEFORE UPDATE ON ssh_keys
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- SSH Connections
-- ============================================================================
CREATE TABLE ssh_connections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(100) NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    host            VARCHAR(255) NOT NULL,
    port            INTEGER NOT NULL DEFAULT 22,
    username        VARCHAR(100) NOT NULL,
    auth_type       VARCHAR(20) NOT NULL DEFAULT 'key',
    key_id          UUID REFERENCES ssh_keys(id) ON DELETE SET NULL,
    password        TEXT NOT NULL DEFAULT '',
    jump_host       UUID REFERENCES ssh_connections(id) ON DELETE SET NULL,
    tags            JSONB NOT NULL DEFAULT '[]',
    category        VARCHAR(50) NOT NULL DEFAULT '',
    status          VARCHAR(20) NOT NULL DEFAULT 'unknown',
    status_message  TEXT NOT NULL DEFAULT '',
    options         JSONB NOT NULL DEFAULT '{}',
    last_checked    TIMESTAMPTZ,
    created_by      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ssh_connections_created_by ON ssh_connections(created_by);
CREATE INDEX idx_ssh_connections_category ON ssh_connections(category);
CREATE INDEX idx_ssh_connections_status ON ssh_connections(status);
CREATE INDEX idx_ssh_connections_host ON ssh_connections(host);

CREATE TRIGGER update_ssh_connections_updated_at
    BEFORE UPDATE ON ssh_connections
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- SSH Sessions (audit trail)
-- ============================================================================
CREATE TABLE ssh_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id   UUID NOT NULL REFERENCES ssh_connections(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at        TIMESTAMPTZ,
    client_ip       VARCHAR(45) NOT NULL DEFAULT '',
    term_type       VARCHAR(50) NOT NULL DEFAULT 'xterm-256color',
    term_cols       INTEGER NOT NULL DEFAULT 80,
    term_rows       INTEGER NOT NULL DEFAULT 24
);

CREATE INDEX idx_ssh_sessions_connection ON ssh_sessions(connection_id);
CREATE INDEX idx_ssh_sessions_user ON ssh_sessions(user_id);
CREATE INDEX idx_ssh_sessions_started ON ssh_sessions(started_at DESC);

-- ============================================================================
-- SSH Tunnels
-- ============================================================================
CREATE TABLE ssh_tunnels (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id   UUID NOT NULL REFERENCES ssh_connections(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type            VARCHAR(20) NOT NULL CHECK (type IN ('local', 'remote', 'dynamic')),
    local_host      VARCHAR(255) NOT NULL DEFAULT '127.0.0.1',
    local_port      INTEGER NOT NULL CHECK (local_port > 0 AND local_port <= 65535),
    remote_host     VARCHAR(255) DEFAULT 'localhost',
    remote_port     INTEGER CHECK (remote_port > 0 AND remote_port <= 65535),
    status          VARCHAR(20) NOT NULL DEFAULT 'stopped' CHECK (status IN ('active', 'stopped', 'error')),
    status_message  TEXT,
    auto_start      BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ssh_tunnels_connection ON ssh_tunnels(connection_id);
CREATE INDEX idx_ssh_tunnels_user ON ssh_tunnels(user_id);
CREATE INDEX idx_ssh_tunnels_status ON ssh_tunnels(status);
CREATE UNIQUE INDEX idx_ssh_tunnels_unique ON ssh_tunnels(connection_id, user_id, type, local_port);

CREATE TRIGGER update_ssh_tunnels_updated_at
    BEFORE UPDATE ON ssh_tunnels
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

COMMENT ON TABLE ssh_tunnels IS 'Persistent SSH tunnel configurations for port forwarding';

-- ============================================================================
-- SFTP Transfers (audit log)
-- ============================================================================
CREATE TABLE sftp_transfers (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id       UUID NOT NULL REFERENCES ssh_connections(id) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    operation           VARCHAR(20) NOT NULL,
    local_path          TEXT NOT NULL DEFAULT '',
    remote_path         TEXT NOT NULL,
    size                BIGINT NOT NULL DEFAULT 0,
    bytes_transferred   BIGINT NOT NULL DEFAULT 0,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    error               TEXT NOT NULL DEFAULT '',
    started_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ
);

CREATE INDEX idx_sftp_transfers_connection ON sftp_transfers(connection_id);
CREATE INDEX idx_sftp_transfers_user ON sftp_transfers(user_id);
CREATE INDEX idx_sftp_transfers_started ON sftp_transfers(started_at DESC);

-- ============================================================================
-- Web Shortcuts
-- ============================================================================
CREATE TABLE web_shortcuts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(100) NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    url             TEXT NOT NULL,
    type            VARCHAR(20) NOT NULL DEFAULT 'web',
    icon            TEXT NOT NULL DEFAULT '',
    icon_type       VARCHAR(20) NOT NULL DEFAULT 'fa',
    color           VARCHAR(7) NOT NULL DEFAULT '',
    category        VARCHAR(50) NOT NULL DEFAULT '',
    sort_order      INTEGER NOT NULL DEFAULT 0,
    open_in_new     BOOLEAN NOT NULL DEFAULT true,
    show_in_menu    BOOLEAN NOT NULL DEFAULT false,
    is_public       BOOLEAN NOT NULL DEFAULT false,
    created_by      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_web_shortcuts_created_by ON web_shortcuts(created_by);
CREATE INDEX idx_web_shortcuts_category ON web_shortcuts(category);
CREATE INDEX idx_web_shortcuts_sort ON web_shortcuts(sort_order);
CREATE INDEX idx_web_shortcuts_public ON web_shortcuts(is_public) WHERE is_public = true;

CREATE TRIGGER update_web_shortcuts_updated_at
    BEFORE UPDATE ON web_shortcuts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Shortcut Categories
-- ============================================================================
CREATE TABLE shortcut_categories (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(50) NOT NULL,
    icon            VARCHAR(100) NOT NULL DEFAULT '',
    color           VARCHAR(7) NOT NULL DEFAULT '',
    sort_order      INTEGER NOT NULL DEFAULT 0,
    is_default      BOOLEAN NOT NULL DEFAULT false,
    created_by      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(name, created_by)
);

CREATE INDEX idx_shortcut_categories_created_by ON shortcut_categories(created_by);

CREATE TRIGGER update_shortcut_categories_updated_at
    BEFORE UPDATE ON shortcut_categories
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Database Connections (browser)
-- ============================================================================
CREATE TABLE database_connections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            VARCHAR(100) NOT NULL,
    type            VARCHAR(20) NOT NULL CHECK (type IN ('postgres', 'mysql', 'mariadb', 'mongodb', 'redis', 'sqlite')),
    host            VARCHAR(255) NOT NULL,
    port            INTEGER NOT NULL CHECK (port > 0 AND port <= 65535),
    database        VARCHAR(255) NOT NULL,
    username        VARCHAR(255),
    password        TEXT,
    ssl             BOOLEAN NOT NULL DEFAULT false,
    ssl_mode        VARCHAR(50),
    ca_cert         TEXT,
    client_cert     TEXT,
    client_key      TEXT,
    options         JSONB DEFAULT '{}',
    status          VARCHAR(20) NOT NULL DEFAULT 'disconnected' CHECK (status IN ('connected', 'disconnected', 'error')),
    status_message  TEXT,
    last_checked    TIMESTAMPTZ,
    last_connected_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_database_connections_user ON database_connections(user_id);
CREATE INDEX idx_database_connections_type ON database_connections(type);
CREATE INDEX idx_database_connections_status ON database_connections(status);
CREATE UNIQUE INDEX idx_database_connections_unique_name ON database_connections(user_id, name);

CREATE TRIGGER update_database_connections_updated_at
    BEFORE UPDATE ON database_connections
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

COMMENT ON TABLE database_connections IS 'Database connection configurations for browser functionality';

-- ============================================================================
-- LDAP Browser Connections
-- ============================================================================
CREATE TABLE ldap_browser_connections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            VARCHAR(100) NOT NULL,
    host            VARCHAR(255) NOT NULL,
    port            INTEGER NOT NULL DEFAULT 389,
    use_tls         BOOLEAN NOT NULL DEFAULT false,
    start_tls       BOOLEAN NOT NULL DEFAULT false,
    skip_tls_verify BOOLEAN NOT NULL DEFAULT false,
    bind_dn         VARCHAR(500) NOT NULL,
    bind_password   TEXT NOT NULL,
    base_dn         VARCHAR(500) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'disconnected' CHECK (status IN ('connected', 'disconnected', 'error')),
    status_message  TEXT,
    last_checked    TIMESTAMPTZ,
    last_connected_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ldap_browser_connections_user ON ldap_browser_connections(user_id);
CREATE INDEX idx_ldap_browser_connections_status ON ldap_browser_connections(status);
CREATE UNIQUE INDEX idx_ldap_browser_connections_unique_name ON ldap_browser_connections(user_id, name);

CREATE TRIGGER update_ldap_browser_connections_updated_at
    BEFORE UPDATE ON ldap_browser_connections
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

COMMENT ON TABLE ldap_browser_connections IS 'LDAP browser connection configurations for directory browsing';
