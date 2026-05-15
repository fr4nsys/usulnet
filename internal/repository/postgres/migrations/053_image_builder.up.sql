-- Image Builder: build job tracking and Dockerfile templates.
-- Renumbered from v26.2.7's 051 to slot above 052_backup_verification
-- and below 054_automated_rollback in the v26.5.1 sequence.
CREATE TABLE IF NOT EXISTS image_build_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL DEFAULT '',
    tags            TEXT[] NOT NULL DEFAULT '{}',
    dockerfile      TEXT NOT NULL DEFAULT '',
    context_path    TEXT NOT NULL DEFAULT '',
    build_args      JSONB DEFAULT '{}',
    labels          JSONB DEFAULT '{}',
    target          VARCHAR(255) DEFAULT '',
    no_cache        BOOLEAN NOT NULL DEFAULT false,
    pull            BOOLEAN NOT NULL DEFAULT false,
    platform        VARCHAR(100) DEFAULT '',
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',  -- pending, building, success, failed, cancelled
    output          TEXT DEFAULT '',
    error_message   TEXT DEFAULT '',
    image_id        VARCHAR(128) DEFAULT '',                  -- resulting image ID
    image_size      BIGINT DEFAULT 0,
    duration_ms     INTEGER DEFAULT 0,
    -- v26.5.1 additions: optional cosign hook (Sigstore) tracking.
    signed          BOOLEAN NOT NULL DEFAULT false,
    signature_ref   VARCHAR(255) DEFAULT '',
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_image_build_jobs_host ON image_build_jobs(host_id);
CREATE INDEX IF NOT EXISTS idx_image_build_jobs_status ON image_build_jobs(status);
CREATE INDEX IF NOT EXISTS idx_image_build_jobs_created ON image_build_jobs(created_at DESC);

CREATE TABLE IF NOT EXISTS dockerfile_templates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    description     TEXT DEFAULT '',
    category        VARCHAR(100) DEFAULT 'custom',    -- web, database, api, worker, custom
    dockerfile      TEXT NOT NULL,
    default_args    JSONB DEFAULT '{}',
    default_labels  JSONB DEFAULT '{}',
    is_builtin      BOOLEAN NOT NULL DEFAULT false,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dockerfile_templates_host ON dockerfile_templates(host_id);
CREATE INDEX IF NOT EXISTS idx_dockerfile_templates_category ON dockerfile_templates(category);
