-- ============================================================================
-- 011_proxy: Reverse proxy (Caddy + NPM integration)
-- ============================================================================

-- ============================================================================
-- Caddy: DNS Providers
-- ============================================================================
CREATE TABLE proxy_dns_providers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    provider        VARCHAR(50) NOT NULL,
    api_token       TEXT NOT NULL,
    zone            VARCHAR(255) DEFAULT '',
    propagation     INTEGER DEFAULT 60,
    is_default      BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_proxy_dns_providers_host ON proxy_dns_providers(host_id);

CREATE TRIGGER update_proxy_dns_providers_updated_at
    BEFORE UPDATE ON proxy_dns_providers
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Caddy: Certificates
-- ============================================================================
CREATE TABLE proxy_certificates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    domains         TEXT[] NOT NULL,
    provider        VARCHAR(50) NOT NULL DEFAULT 'custom',
    cert_pem        TEXT DEFAULT '',
    key_pem         TEXT DEFAULT '',
    chain_pem       TEXT DEFAULT '',
    expires_at      TIMESTAMPTZ,
    is_wildcard     BOOLEAN NOT NULL DEFAULT false,
    auto_renew      BOOLEAN NOT NULL DEFAULT true,
    last_renewed    TIMESTAMPTZ,
    error_message   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_proxy_certificates_host ON proxy_certificates(host_id);

CREATE TRIGGER update_proxy_certificates_updated_at
    BEFORE UPDATE ON proxy_certificates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Caddy: Proxy Hosts
-- ============================================================================
CREATE TABLE proxy_hosts (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id                 UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name                    VARCHAR(255) NOT NULL,
    domains                 TEXT[] NOT NULL,
    enabled                 BOOLEAN NOT NULL DEFAULT true,
    status                  VARCHAR(20) NOT NULL DEFAULT 'pending',
    status_message          TEXT DEFAULT '',
    upstream_scheme         VARCHAR(10) NOT NULL DEFAULT 'http',
    upstream_host           VARCHAR(512) NOT NULL,
    upstream_port           INTEGER NOT NULL,
    upstream_path           VARCHAR(512) DEFAULT '',
    ssl_mode                VARCHAR(20) NOT NULL DEFAULT 'auto',
    ssl_force_https         BOOLEAN NOT NULL DEFAULT true,
    certificate_id          UUID REFERENCES proxy_certificates(id) ON DELETE SET NULL,
    dns_provider_id         UUID REFERENCES proxy_dns_providers(id) ON DELETE SET NULL,
    enable_websocket        BOOLEAN NOT NULL DEFAULT false,
    enable_compression      BOOLEAN NOT NULL DEFAULT true,
    enable_hsts             BOOLEAN NOT NULL DEFAULT true,
    enable_http2            BOOLEAN NOT NULL DEFAULT true,
    health_check_enabled    BOOLEAN NOT NULL DEFAULT false,
    health_check_path       VARCHAR(512) DEFAULT '',
    health_check_interval   INTEGER DEFAULT 30,
    container_id            VARCHAR(128) DEFAULT '',
    container_name          VARCHAR(255) DEFAULT '',
    auto_created            BOOLEAN NOT NULL DEFAULT false,
    created_by              UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_by              UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_proxy_hosts_host ON proxy_hosts(host_id);
CREATE INDEX idx_proxy_hosts_enabled ON proxy_hosts(enabled);
CREATE INDEX idx_proxy_hosts_status ON proxy_hosts(status);
CREATE INDEX idx_proxy_hosts_container ON proxy_hosts(container_id) WHERE container_id != '';

CREATE TRIGGER update_proxy_hosts_updated_at
    BEFORE UPDATE ON proxy_hosts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Caddy: Custom Headers
-- ============================================================================
CREATE TABLE proxy_headers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proxy_host_id   UUID NOT NULL REFERENCES proxy_hosts(id) ON DELETE CASCADE,
    direction       VARCHAR(10) NOT NULL DEFAULT 'request',
    operation       VARCHAR(10) NOT NULL DEFAULT 'set',
    name            VARCHAR(255) NOT NULL,
    value           TEXT DEFAULT '',
    CONSTRAINT chk_proxy_header_direction CHECK (direction IN ('request', 'response')),
    CONSTRAINT chk_proxy_header_operation CHECK (operation IN ('set', 'add', 'delete'))
);

CREATE INDEX idx_proxy_headers_host ON proxy_headers(proxy_host_id);

-- ============================================================================
-- Caddy: Audit Log
-- ============================================================================
CREATE TABLE proxy_audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    action          VARCHAR(20) NOT NULL,
    resource_type   VARCHAR(30) NOT NULL,
    resource_id     UUID NOT NULL,
    resource_name   VARCHAR(255) DEFAULT '',
    details         TEXT DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_proxy_audit_host ON proxy_audit_log(host_id);
CREATE INDEX idx_proxy_audit_created ON proxy_audit_log(created_at DESC);

-- ============================================================================
-- NPM: Connection configuration
-- ============================================================================
CREATE TABLE npm_connections (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id                 UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    base_url                TEXT NOT NULL,
    admin_email             TEXT NOT NULL,
    admin_password_encrypted TEXT NOT NULL,
    is_enabled              BOOLEAN DEFAULT true,
    last_health_check       TIMESTAMPTZ,
    health_status           TEXT DEFAULT 'unknown',
    health_message          TEXT,
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    updated_at              TIMESTAMPTZ DEFAULT NOW(),
    created_by              UUID REFERENCES users(id),
    updated_by              UUID REFERENCES users(id),
    UNIQUE(host_id)
);

CREATE INDEX idx_npm_connections_host ON npm_connections(host_id);

CREATE TRIGGER update_npm_connections_updated_at
    BEFORE UPDATE ON npm_connections
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- NPM: Container proxy mappings
-- ============================================================================
CREATE TABLE container_proxy_mappings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    container_id    TEXT NOT NULL,
    container_name  TEXT NOT NULL,
    npm_proxy_host_id INTEGER NOT NULL,
    auto_created    BOOLEAN DEFAULT false,
    domain_source   TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(host_id, container_id)
);

CREATE INDEX idx_container_proxy_mappings_host ON container_proxy_mappings(host_id);
CREATE INDEX idx_container_proxy_mappings_container ON container_proxy_mappings(container_id);

CREATE TRIGGER update_container_proxy_mappings_updated_at
    BEFORE UPDATE ON container_proxy_mappings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- NPM: Audit Log
-- ============================================================================
CREATE TABLE npm_audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    user_id         UUID REFERENCES users(id),
    operation       TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    resource_id     INTEGER NOT NULL,
    resource_name   TEXT,
    details         JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_npm_audit_log_host ON npm_audit_log(host_id);
CREATE INDEX idx_npm_audit_log_created ON npm_audit_log(created_at);

COMMENT ON TABLE npm_connections IS 'NPM connection configuration per Docker host';
COMMENT ON TABLE container_proxy_mappings IS 'Maps Docker containers to NPM proxy hosts';
