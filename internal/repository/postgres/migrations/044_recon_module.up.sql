-- Recon & Privacy module schema (usulnet v26.5.0)
-- See docs/recon.md for the full RFC.
-- usulnet is single-tenant; scoping is by created_by where relevant.

-- Targets: identifiers the operator wants to scan. Always lowercased and
-- hashed; the hash is indexed instead of the raw value to avoid leaking PII
-- through pg_stat / index dumps.
CREATE TABLE IF NOT EXISTS recon_targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type TEXT NOT NULL CHECK (type IN ('email', 'phone', 'username', 'domain', 'ip', 'ip_range')),
    value TEXT NOT NULL,
    value_hash BYTEA NOT NULL,
    label TEXT,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT recon_targets_unique UNIQUE (type, value_hash)
);

CREATE INDEX IF NOT EXISTS idx_recon_targets_type ON recon_targets(type);
CREATE INDEX IF NOT EXISTS idx_recon_targets_creator ON recon_targets(created_by);

-- Ownership proofs: verification challenges that gate scan execution.
CREATE TABLE IF NOT EXISTS recon_ownership_proofs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID NOT NULL REFERENCES recon_targets(id) ON DELETE CASCADE,
    method TEXT NOT NULL CHECK (method IN ('dns_txt', 'email_link', 'rdap_match', 'admin_attest', 'self_assert')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'failed', 'revoked')),
    challenge TEXT,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_recon_ownership_proofs_target ON recon_ownership_proofs(target_id);
CREATE INDEX IF NOT EXISTS idx_recon_ownership_proofs_pending ON recon_ownership_proofs(status) WHERE status = 'pending';

-- Profiles: curated module sets for SpiderFoot + the toolkit container.
-- Built-in profiles are seeded by the migration; custom profiles arrive in v26.5.1.
CREATE TABLE IF NOT EXISTS recon_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT,
    kind TEXT NOT NULL CHECK (kind IN ('builtin', 'custom')),
    target_types TEXT[] NOT NULL,
    modules JSONB NOT NULL DEFAULT '[]'::jsonb,
    options JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT recon_profiles_name_unique UNIQUE (name)
);

CREATE INDEX IF NOT EXISTS idx_recon_profiles_kind ON recon_profiles(kind);

-- Scans: one execution of a profile against a target.
CREATE TABLE IF NOT EXISTS recon_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID NOT NULL REFERENCES recon_targets(id) ON DELETE CASCADE,
    profile_id UUID NOT NULL REFERENCES recon_profiles(id) ON DELETE RESTRICT,
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    engine TEXT NOT NULL DEFAULT 'spiderfoot',
    engine_run_id TEXT,
    error TEXT,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_recon_scans_target ON recon_scans(target_id);
CREATE INDEX IF NOT EXISTS idx_recon_scans_status ON recon_scans(status) WHERE status IN ('queued', 'running');
CREATE INDEX IF NOT EXISTS idx_recon_scans_created_at ON recon_scans(created_at DESC);

-- Findings: normalized output. value_hash again indexes PII without exposing it.
CREATE TABLE IF NOT EXISTS recon_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES recon_scans(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES recon_targets(id) ON DELETE CASCADE,
    module TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    value TEXT NOT NULL,
    value_hash BYTEA NOT NULL,
    source TEXT,
    confidence INT NOT NULL DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT recon_findings_unique UNIQUE (scan_id, module, value_hash)
);

CREATE INDEX IF NOT EXISTS idx_recon_findings_scan ON recon_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_recon_findings_target ON recon_findings(target_id);
CREATE INDEX IF NOT EXISTS idx_recon_findings_severity ON recon_findings(severity) WHERE severity IN ('high', 'critical');
CREATE INDEX IF NOT EXISTS idx_recon_findings_category ON recon_findings(category);

-- Raw engine payloads (encrypted at rest via the AES-GCM helper).
-- One row per finding to keep findings table small and queryable.
CREATE TABLE IF NOT EXISTS recon_findings_raw (
    finding_id UUID PRIMARY KEY REFERENCES recon_findings(id) ON DELETE CASCADE,
    engine TEXT NOT NULL,
    payload_encrypted BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Per-scan aggregated summary and grade.
CREATE TABLE IF NOT EXISTS recon_scan_summary (
    scan_id UUID PRIMARY KEY REFERENCES recon_scans(id) ON DELETE CASCADE,
    counts JSONB NOT NULL DEFAULT '{}'::jsonb,
    grade TEXT,
    correlations JSONB NOT NULL DEFAULT '[]'::jsonb,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Metadata jobs: strip/extract on uploaded files or host paths.
CREATE TABLE IF NOT EXISTS recon_metadata_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source TEXT NOT NULL CHECK (source IN ('upload', 'host_path', 'volume', 'registry')),
    source_ref TEXT,
    mode TEXT NOT NULL CHECK (mode IN ('extract', 'strip', 'both')),
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    artifact_count INT NOT NULL DEFAULT 0,
    error TEXT,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_recon_metadata_jobs_status ON recon_metadata_jobs(status) WHERE status IN ('queued', 'running');
CREATE INDEX IF NOT EXISTS idx_recon_metadata_jobs_creator ON recon_metadata_jobs(created_by);

-- Per-file artifact for metadata jobs.
CREATE TABLE IF NOT EXISTS recon_metadata_artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES recon_metadata_jobs(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    mime TEXT,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    sha256 BYTEA NOT NULL,
    stripped_sha256 BYTEA,
    extracted JSONB NOT NULL DEFAULT '{}'::jsonb,
    storage_ref TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_recon_metadata_artifacts_job ON recon_metadata_artifacts(job_id);
CREATE INDEX IF NOT EXISTS idx_recon_metadata_artifacts_sha ON recon_metadata_artifacts(sha256);

-- Connectors: optional external API credentials, encrypted at rest.
CREATE TABLE IF NOT EXISTS recon_connectors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    credentials_encrypted BYTEA,
    nonce BYTEA,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT recon_connectors_kind_unique UNIQUE (kind)
);

-- Append-only audit log. target_id is nullable so deleting a target does
-- not destroy historical evidence of access.
CREATE TABLE IF NOT EXISTS recon_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_id UUID REFERENCES recon_targets(id) ON DELETE SET NULL,
    scan_id UUID REFERENCES recon_scans(id) ON DELETE SET NULL,
    ip INET,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_recon_audit_log_actor ON recon_audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_recon_audit_log_action ON recon_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_recon_audit_log_created_at ON recon_audit_log(created_at DESC);

-- Seed built-in profiles. These are deliberately conservative and only
-- enable passive modules in v26.5.0. Module IDs use SpiderFoot's native
-- naming where applicable; toolkit-only modules are prefixed `toolkit:`.
INSERT INTO recon_profiles (name, description, kind, target_types, modules)
VALUES
    ('email-exposure-lite',
     'Passive email exposure check: breaches, public mentions, gravatar, social presence.',
     'builtin', ARRAY['email'],
     '["sfp_haveibeen", "sfp_hunter", "sfp_emailrep", "sfp_gravatar", "toolkit:holehe"]'::jsonb),
    ('domain-surface',
     'Passive domain surface: subdomains, DNS, certificate transparency, public exposure.',
     'builtin', ARRAY['domain'],
     '["sfp_dnsresolve", "sfp_crt", "sfp_subdomain_enum", "sfp_dnsbrute", "toolkit:subfinder"]'::jsonb),
    ('username-presence',
     'Passive username lookup across public platforms.',
     'builtin', ARRAY['username'],
     '["sfp_sherlock", "sfp_socialprofiles"]'::jsonb),
    ('phone-public-info',
     'Public phone number lookup (PhoneInfoga). Self-scan only in v26.5.0.',
     'builtin', ARRAY['phone'],
     '["toolkit:phoneinfoga"]'::jsonb)
ON CONFLICT (name) DO NOTHING;
