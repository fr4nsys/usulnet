-- ============================================================================
-- 012_storage: S3/MinIO object storage management
-- ============================================================================

CREATE TABLE storage_connections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name            VARCHAR(100) NOT NULL,
    endpoint        VARCHAR(500) NOT NULL,
    region          VARCHAR(50) NOT NULL DEFAULT 'us-east-1',
    access_key      TEXT NOT NULL,
    secret_key      TEXT NOT NULL,
    use_path_style  BOOLEAN NOT NULL DEFAULT true,
    use_ssl         BOOLEAN NOT NULL DEFAULT true,
    is_default      BOOLEAN NOT NULL DEFAULT false,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    status_message  TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      VARCHAR(100) NOT NULL DEFAULT '',
    last_checked    TIMESTAMPTZ
);

CREATE INDEX idx_storage_connections_host ON storage_connections(host_id);
CREATE INDEX idx_storage_connections_status ON storage_connections(status);

CREATE TRIGGER update_storage_connections_updated_at
    BEFORE UPDATE ON storage_connections
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Storage Buckets (cached metadata)
-- ============================================================================
CREATE TABLE storage_buckets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id   UUID NOT NULL REFERENCES storage_connections(id) ON DELETE CASCADE,
    name            VARCHAR(63) NOT NULL,
    region          VARCHAR(50) NOT NULL DEFAULT '',
    size_bytes      BIGINT NOT NULL DEFAULT 0,
    object_count    BIGINT NOT NULL DEFAULT 0,
    is_public       BOOLEAN NOT NULL DEFAULT false,
    versioning      BOOLEAN NOT NULL DEFAULT false,
    tags            JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_synced     TIMESTAMPTZ,
    UNIQUE(connection_id, name)
);

CREATE INDEX idx_storage_buckets_connection ON storage_buckets(connection_id);

CREATE TRIGGER update_storage_buckets_updated_at
    BEFORE UPDATE ON storage_buckets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Storage Audit Log
-- ============================================================================
CREATE TABLE storage_audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id   UUID NOT NULL REFERENCES storage_connections(id) ON DELETE CASCADE,
    action          VARCHAR(50) NOT NULL,
    resource_type   VARCHAR(30) NOT NULL,
    resource_name   VARCHAR(500) NOT NULL,
    details         JSONB NOT NULL DEFAULT '{}',
    user_id         VARCHAR(100) NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_storage_audit_connection ON storage_audit_log(connection_id);
CREATE INDEX idx_storage_audit_created ON storage_audit_log(created_at DESC);
