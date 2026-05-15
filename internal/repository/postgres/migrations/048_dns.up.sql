-- ============================================================================
-- 048_dns: DNS provider plugins for ACME DNS-01 automation
--
-- Ports v26.2.7's DNS module forward into v26.5.1, redirected from the
-- v26.2.7 embedded DNS server (out of scope per session-10) to provider
-- plugins (Cloudflare, Route53, DigitalOcean, RFC 2136). The provider
-- credentials column is encrypted at rest with the installation
-- AES-256-GCM key (same posture as recon HIBP credentials and TOTP
-- secrets), so the column is TEXT, not JSONB.
--
-- Tables:
--   - dns_providers          provider configs (cloudflare/route53/...)
--   - dns_records            records the platform owns through a provider
--   - dns_acme_orders        DNS-01 challenge state machine (persistent)
--   - dns_audit_log          provider/record CRUD + ACME transitions
-- ============================================================================

-- ============================================================================
-- DNS Providers
-- ============================================================================
CREATE TABLE IF NOT EXISTS dns_providers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    provider_kind   VARCHAR(50) NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    description     TEXT NOT NULL DEFAULT '',
    -- AES-256-GCM encrypted JSON blob, base64-encoded.
    credentials     TEXT NOT NULL,
    -- Public, non-secret per-provider knobs (default zone, propagation
    -- timeout, RFC 2136 server address, ...).
    config          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (host_id, name)
);
CREATE INDEX IF NOT EXISTS idx_dns_providers_host ON dns_providers(host_id);
CREATE INDEX IF NOT EXISTS idx_dns_providers_kind ON dns_providers(provider_kind);

CREATE TRIGGER update_dns_providers_updated_at
    BEFORE UPDATE ON dns_providers
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- DNS Records
-- ============================================================================
CREATE TABLE IF NOT EXISTS dns_records (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id         UUID NOT NULL REFERENCES dns_providers(id) ON DELETE CASCADE,
    host_id             UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name                VARCHAR(512) NOT NULL,
    type                VARCHAR(10) NOT NULL
                        CHECK (type IN ('A','AAAA','CNAME','MX','TXT','NS','SRV','PTR','CAA')),
    content             TEXT NOT NULL,
    ttl                 INTEGER NOT NULL DEFAULT 300,
    -- Native record id returned by the upstream provider; used for
    -- delete/update so we don't fall back to "match by name + content".
    provider_record_id  VARCHAR(255) NOT NULL DEFAULT '',
    -- 'manual' | 'acme:<order_id>' | 'discovery:<container_id>'.
    managed_by          VARCHAR(128) NOT NULL DEFAULT 'manual',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dns_records_provider ON dns_records(provider_id);
CREATE INDEX IF NOT EXISTS idx_dns_records_host ON dns_records(host_id);
CREATE INDEX IF NOT EXISTS idx_dns_records_managed_by ON dns_records(managed_by);
CREATE INDEX IF NOT EXISTS idx_dns_records_name ON dns_records(name);

CREATE TRIGGER update_dns_records_updated_at
    BEFORE UPDATE ON dns_records
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- ACME DNS-01 Orders (state machine, survives restarts mid-order)
-- ============================================================================
CREATE TABLE IF NOT EXISTS dns_acme_orders (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id                  UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    provider_id              UUID NOT NULL REFERENCES dns_providers(id) ON DELETE CASCADE,
    domain                   VARCHAR(512) NOT NULL,
    challenge_fqdn           VARCHAR(512) NOT NULL,
    challenge_value          TEXT NOT NULL,
    -- pending → dropping → propagating → ready → completing →
    --   completed / failed; cleanup → cleaned (terminal).
    state                    VARCHAR(32) NOT NULL DEFAULT 'pending',
    error_msg                TEXT NOT NULL DEFAULT '',
    record_id                UUID REFERENCES dns_records(id) ON DELETE SET NULL,
    propagation_check_count  INTEGER NOT NULL DEFAULT 0,
    last_check_at            TIMESTAMPTZ,
    completed_at             TIMESTAMPTZ,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dns_acme_orders_host ON dns_acme_orders(host_id);
CREATE INDEX IF NOT EXISTS idx_dns_acme_orders_state ON dns_acme_orders(state);
CREATE INDEX IF NOT EXISTS idx_dns_acme_orders_domain ON dns_acme_orders(domain);
CREATE INDEX IF NOT EXISTS idx_dns_acme_orders_provider ON dns_acme_orders(provider_id);

CREATE TRIGGER update_dns_acme_orders_updated_at
    BEFORE UPDATE ON dns_acme_orders
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- DNS Audit Log (provider/record CRUD + ACME state transitions)
-- ============================================================================
CREATE TABLE IF NOT EXISTS dns_audit_log (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id       UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    action        VARCHAR(32) NOT NULL,
    resource_type VARCHAR(32) NOT NULL,
    resource_id   UUID NOT NULL,
    resource_name VARCHAR(512) NOT NULL DEFAULT '',
    details       TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dns_audit_host ON dns_audit_log(host_id);
CREATE INDEX IF NOT EXISTS idx_dns_audit_resource ON dns_audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_dns_audit_created ON dns_audit_log(created_at DESC);
