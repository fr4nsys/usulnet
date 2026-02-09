-- ============================================================================
-- 005_security: Security scans and issues
-- ============================================================================

CREATE TABLE security_scans (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id             UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    container_id        VARCHAR(64) NOT NULL,
    container_name      VARCHAR(255) NOT NULL,
    image               VARCHAR(512) NOT NULL,
    score               INTEGER NOT NULL DEFAULT 0,
    grade               VARCHAR(2) NOT NULL DEFAULT 'F',
    issue_count         INTEGER NOT NULL DEFAULT 0,
    critical_count      INTEGER NOT NULL DEFAULT 0,
    high_count          INTEGER NOT NULL DEFAULT 0,
    medium_count        INTEGER NOT NULL DEFAULT 0,
    low_count           INTEGER NOT NULL DEFAULT 0,
    cve_count           INTEGER NOT NULL DEFAULT 0,
    include_cve         BOOLEAN NOT NULL DEFAULT false,
    scan_duration_ms    BIGINT NOT NULL DEFAULT 0,
    completed_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_security_scans_host_id ON security_scans(host_id);
CREATE INDEX idx_security_scans_container ON security_scans(container_id);
CREATE INDEX idx_security_scans_score ON security_scans(score);
CREATE INDEX idx_security_scans_grade ON security_scans(grade);
CREATE INDEX idx_security_scans_completed_at ON security_scans(completed_at);

-- ============================================================================
-- Security Issues
-- ============================================================================
CREATE TABLE security_issues (
    id                  BIGSERIAL PRIMARY KEY,
    scan_id             UUID NOT NULL REFERENCES security_scans(id) ON DELETE CASCADE,
    container_id        VARCHAR(64) NOT NULL,
    host_id             UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    severity            VARCHAR(20) NOT NULL,
    category            VARCHAR(50) NOT NULL,
    check_id            VARCHAR(50) NOT NULL,
    title               VARCHAR(255) NOT NULL,
    description         TEXT NOT NULL,
    recommendation      TEXT NOT NULL,
    fix_command          TEXT,
    documentation_url   TEXT,
    cve_id              VARCHAR(50),
    cvss_score          DECIMAL(3,1),
    status              VARCHAR(50) NOT NULL DEFAULT 'open',
    acknowledged_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    acknowledged_at     TIMESTAMPTZ,
    resolved_by         UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at         TIMESTAMPTZ,
    detected_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_security_issues_scan_id ON security_issues(scan_id);
CREATE INDEX idx_security_issues_container ON security_issues(container_id);
CREATE INDEX idx_security_issues_host_id ON security_issues(host_id);
CREATE INDEX idx_security_issues_severity ON security_issues(severity);
CREATE INDEX idx_security_issues_category ON security_issues(category);
CREATE INDEX idx_security_issues_status ON security_issues(status);
CREATE INDEX idx_security_issues_cve ON security_issues(cve_id);
CREATE INDEX idx_security_issues_detected_at ON security_issues(detected_at);
CREATE INDEX idx_security_issues_host_status_severity ON security_issues(host_id, status, severity);
