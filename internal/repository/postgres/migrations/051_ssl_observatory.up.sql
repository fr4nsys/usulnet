-- Session 05 (v26.5.1) — SSL Observatory.
-- Renumbered from v26.2.7 migration 049.
--
-- ssl_targets stores TLS/SSL endpoints the operator wants to monitor.
-- extra_hostnames lets one target scan many SNI virtual hosts that
-- resolve to the same address; alert_thresholds is the per-target
-- expiry warning list (days before expiry); empty falls back to the
-- service-wide defaults {30,14,7,3,1}.
--
-- ssl_scan_results stores one row per (target, scan_hostname) per
-- scan run. scan_hostname records the SNI server_name used in the
-- handshake so SNI scans don't overwrite each other.

CREATE TABLE ssl_targets (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id          UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name             VARCHAR(255) NOT NULL,
    hostname         VARCHAR(512) NOT NULL,
    port             INTEGER NOT NULL DEFAULT 443,
    extra_hostnames  TEXT[] NOT NULL DEFAULT '{}',
    alert_thresholds INTEGER[] NOT NULL DEFAULT '{}',
    auto_discovered  BOOLEAN NOT NULL DEFAULT false,
    enabled          BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ssl_targets_host ON ssl_targets(host_id);

CREATE TABLE ssl_scan_results (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id           UUID NOT NULL REFERENCES ssl_targets(id) ON DELETE CASCADE,
    scan_hostname       VARCHAR(512) NOT NULL DEFAULT '',
    grade               VARCHAR(5) NOT NULL DEFAULT 'U',
    score               INTEGER NOT NULL DEFAULT 0,
    protocol_versions   TEXT[] NOT NULL DEFAULT '{}',
    cipher_suites       JSONB NOT NULL DEFAULT '[]',
    certificate_cn      VARCHAR(512) NOT NULL DEFAULT '',
    certificate_issuer  VARCHAR(512) NOT NULL DEFAULT '',
    certificate_sans    TEXT[] NOT NULL DEFAULT '{}',
    cert_not_before     TIMESTAMPTZ,
    cert_not_after      TIMESTAMPTZ,
    cert_key_type       VARCHAR(20) NOT NULL DEFAULT '',
    cert_key_bits       INTEGER NOT NULL DEFAULT 0,
    cert_chain_valid    BOOLEAN NOT NULL DEFAULT false,
    cert_chain_length   INTEGER NOT NULL DEFAULT 0,
    has_hsts            BOOLEAN NOT NULL DEFAULT false,
    has_ocsp_stapling   BOOLEAN NOT NULL DEFAULT false,
    has_sct             BOOLEAN NOT NULL DEFAULT false,
    vulnerabilities     JSONB NOT NULL DEFAULT '[]',
    error_message       TEXT NOT NULL DEFAULT '',
    scan_duration_ms    INTEGER NOT NULL DEFAULT 0,
    scanned_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ssl_scans_target ON ssl_scan_results(target_id);
CREATE INDEX idx_ssl_scans_target_host ON ssl_scan_results(target_id, scan_hostname);
CREATE INDEX idx_ssl_scans_grade ON ssl_scan_results(grade);
CREATE INDEX idx_ssl_scans_date ON ssl_scan_results(scanned_at DESC);
CREATE INDEX idx_ssl_scans_expiry ON ssl_scan_results(cert_not_after) WHERE cert_not_after IS NOT NULL;
