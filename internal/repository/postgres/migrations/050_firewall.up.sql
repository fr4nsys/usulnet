-- 050_firewall.up.sql — Firewall rule management tables.
-- Ported from v26.2.7 migration 048_firewall (renumbered to avoid
-- collisions with v26.5.0's 044_recon_module / 045_recon_retention).

CREATE TABLE IF NOT EXISTS firewall_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    description     TEXT DEFAULT '',
    chain           VARCHAR(20) NOT NULL DEFAULT 'INPUT',
    protocol        VARCHAR(10) DEFAULT 'tcp',
    source          VARCHAR(255) DEFAULT '',
    destination     VARCHAR(255) DEFAULT '',
    src_port        VARCHAR(50) DEFAULT '',
    dst_port        VARCHAR(50) DEFAULT '',
    action          VARCHAR(20) NOT NULL DEFAULT 'DROP',
    direction       VARCHAR(10) NOT NULL DEFAULT 'inbound',
    interface_name  VARCHAR(50) DEFAULT '',
    position        INTEGER NOT NULL DEFAULT 0,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    applied         BOOLEAN NOT NULL DEFAULT false,
    container_id    VARCHAR(128) DEFAULT '',
    network_name    VARCHAR(255) DEFAULT '',
    comment         VARCHAR(255) DEFAULT '',
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_firewall_rules_host ON firewall_rules(host_id);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_enabled ON firewall_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_chain ON firewall_rules(chain);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_position ON firewall_rules(host_id, position);

CREATE TRIGGER update_firewall_rules_updated_at
    BEFORE UPDATE ON firewall_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TABLE IF NOT EXISTS firewall_audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    action          VARCHAR(50) NOT NULL,
    rule_id         UUID,
    rule_summary    TEXT NOT NULL,
    details         TEXT DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_firewall_audit_host ON firewall_audit_log(host_id);
CREATE INDEX IF NOT EXISTS idx_firewall_audit_created ON firewall_audit_log(created_at DESC);
