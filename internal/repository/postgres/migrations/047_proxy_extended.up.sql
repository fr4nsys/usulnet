-- ============================================================================
-- 047_proxy_extended: Extended proxy features (locally-managed state)
--
-- Ports v26.2.7 migration 045 into v26.5.1. Adds:
--   - access lists (HTTP basic auth + IP allow/deny)
--   - 404 / dead hosts (catch-all domains)
--   - locations (per-path routing within a proxy host)
--   - redirections (redirect-only hosts)
--   - streams (raw TCP/UDP forwarding — nginx only)
--
-- The proxy service is the authoritative source of state. On apply, the
-- active backend (NPM full, Caddy partial) translates this state to its
-- native API. Streams are unsupported by Caddy; the service surfaces a
-- 422 with ErrFeatureNotSupported, not a 500.
-- ============================================================================

-- Add missing per-host fields to proxy_hosts (introduced by v26.2.7's 045).
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS block_exploits BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS caching_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS custom_nginx_config TEXT DEFAULT '';
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS hsts_subdomains BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS access_list_id UUID;

-- ============================================================================
-- Redirections (redirect-only hosts; 30x responses, no upstream)
-- ============================================================================
CREATE TABLE IF NOT EXISTS proxy_redirections (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id           UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    domains           TEXT[] NOT NULL,
    forward_scheme    VARCHAR(10) NOT NULL DEFAULT 'https',
    forward_domain    VARCHAR(512) NOT NULL,
    forward_http_code INTEGER NOT NULL DEFAULT 301,
    preserve_path     BOOLEAN NOT NULL DEFAULT true,
    ssl_mode          VARCHAR(20) NOT NULL DEFAULT 'none',
    ssl_force_https   BOOLEAN NOT NULL DEFAULT false,
    certificate_id    UUID REFERENCES proxy_certificates(id) ON DELETE SET NULL,
    enabled           BOOLEAN NOT NULL DEFAULT true,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_proxy_redirections_host ON proxy_redirections(host_id);

DO $$ BEGIN
    CREATE TRIGGER update_proxy_redirections_updated_at
        BEFORE UPDATE ON proxy_redirections
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ============================================================================
-- Streams (raw TCP/UDP forwarding — nginx stream module only)
-- ============================================================================
CREATE TABLE IF NOT EXISTS proxy_streams (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    incoming_port   INTEGER NOT NULL,
    forwarding_host VARCHAR(512) NOT NULL,
    forwarding_port INTEGER NOT NULL,
    tcp_forwarding  BOOLEAN NOT NULL DEFAULT true,
    udp_forwarding  BOOLEAN NOT NULL DEFAULT false,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_proxy_streams_host ON proxy_streams(host_id);

DO $$ BEGIN
    CREATE TRIGGER update_proxy_streams_updated_at
        BEFORE UPDATE ON proxy_streams
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ============================================================================
-- Dead hosts (404 catch-all domains)
-- ============================================================================
CREATE TABLE IF NOT EXISTS proxy_dead_hosts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    domains         TEXT[] NOT NULL,
    ssl_mode        VARCHAR(20) NOT NULL DEFAULT 'none',
    ssl_force_https BOOLEAN NOT NULL DEFAULT false,
    certificate_id  UUID REFERENCES proxy_certificates(id) ON DELETE SET NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_proxy_dead_hosts_host ON proxy_dead_hosts(host_id);

DO $$ BEGIN
    CREATE TRIGGER update_proxy_dead_hosts_updated_at
        BEFORE UPDATE ON proxy_dead_hosts
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ============================================================================
-- Access lists (HTTP basic auth + IP allow/deny)
-- ============================================================================
CREATE TABLE IF NOT EXISTS proxy_access_lists (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id     UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name        VARCHAR(255) NOT NULL,
    satisfy_any BOOLEAN NOT NULL DEFAULT false,
    pass_auth   BOOLEAN NOT NULL DEFAULT false,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_proxy_access_lists_host ON proxy_access_lists(host_id);

DO $$ BEGIN
    CREATE TRIGGER update_proxy_access_lists_updated_at
        BEFORE UPDATE ON proxy_access_lists
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS proxy_access_list_auth (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    access_list_id UUID NOT NULL REFERENCES proxy_access_lists(id) ON DELETE CASCADE,
    username       VARCHAR(255) NOT NULL,
    password_hash  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_proxy_access_list_auth_list ON proxy_access_list_auth(access_list_id);

CREATE TABLE IF NOT EXISTS proxy_access_list_clients (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    access_list_id UUID NOT NULL REFERENCES proxy_access_lists(id) ON DELETE CASCADE,
    address        VARCHAR(255) NOT NULL,
    directive      VARCHAR(10) NOT NULL DEFAULT 'allow',
    CONSTRAINT chk_proxy_access_list_client_directive CHECK (directive IN ('allow', 'deny'))
);

CREATE INDEX IF NOT EXISTS idx_proxy_access_list_clients_list ON proxy_access_list_clients(access_list_id);

-- Wire proxy_hosts.access_list_id to the access lists table.
ALTER TABLE proxy_hosts DROP CONSTRAINT IF EXISTS fk_proxy_hosts_access_list;
DO $$ BEGIN
    ALTER TABLE proxy_hosts ADD CONSTRAINT fk_proxy_hosts_access_list
        FOREIGN KEY (access_list_id) REFERENCES proxy_access_lists(id) ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ============================================================================
-- Locations (per-path routing within a proxy host)
-- ============================================================================
CREATE TABLE IF NOT EXISTS proxy_locations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proxy_host_id   UUID NOT NULL REFERENCES proxy_hosts(id) ON DELETE CASCADE,
    path            VARCHAR(512) NOT NULL DEFAULT '/',
    upstream_scheme VARCHAR(10) NOT NULL DEFAULT 'http',
    upstream_host   VARCHAR(512) NOT NULL,
    upstream_port   INTEGER NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true
);

CREATE INDEX IF NOT EXISTS idx_proxy_locations_host ON proxy_locations(proxy_host_id);
