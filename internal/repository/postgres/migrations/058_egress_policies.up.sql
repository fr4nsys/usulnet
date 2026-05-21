-- 058_egress_policies.up.sql — L7 egress filtering policies.
--
-- v26.5.2 ships an in-process HTTP forward proxy at internal/services/egress.
-- Operators point a workload's HTTP_PROXY / HTTPS_PROXY env at the listener;
-- every outbound request is evaluated against the policy rows in this table,
-- and denials are recorded in egress_audit_log so the operator can debug
-- "why was my call blocked" without grepping logs.
--
-- target_glob accepts filepath.Match syntax — '*' matches any string, so
-- '*.github.com' covers every subdomain. Allow rules are first-match-wins
-- evaluated in created_at order. When at least one policy exists for a host
-- and none match, the request is denied; a host with zero policies is
-- pass-through (the operator has not opted in to filtering for that host).

CREATE TABLE IF NOT EXISTS egress_policies (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id     UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    target_glob TEXT NOT NULL,
    allow       BOOLEAN NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_egress_policies_host ON egress_policies(host_id);
CREATE INDEX IF NOT EXISTS idx_egress_policies_host_created ON egress_policies(host_id, created_at);

CREATE TRIGGER update_egress_policies_updated_at
    BEFORE UPDATE ON egress_policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TABLE IF NOT EXISTS egress_audit_log (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id    UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    target     TEXT NOT NULL,
    method     VARCHAR(10) NOT NULL DEFAULT '',
    decision   VARCHAR(10) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_egress_audit_host_created ON egress_audit_log(host_id, created_at DESC);
