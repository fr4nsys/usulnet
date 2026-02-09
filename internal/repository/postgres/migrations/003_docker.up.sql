-- ============================================================================
-- 003_docker: Containers, images, volumes, networks, registries
-- ============================================================================

-- ============================================================================
-- Containers (cached state from Docker)
-- ============================================================================
CREATE TABLE containers (
    id                      VARCHAR(64) PRIMARY KEY,
    host_id                 UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name                    VARCHAR(255) NOT NULL,
    image                   VARCHAR(512) NOT NULL,
    image_id                VARCHAR(80),
    status                  VARCHAR(50) NOT NULL,
    state                   VARCHAR(50) NOT NULL,
    state_reason            TEXT,
    exit_code               INTEGER,
    created_at_docker       TIMESTAMPTZ,
    started_at              TIMESTAMPTZ,
    finished_at             TIMESTAMPTZ,
    -- Networking
    ports                   JSONB DEFAULT '[]',
    networks                JSONB DEFAULT '[]',
    ip_address              VARCHAR(45),
    -- Configuration
    labels                  JSONB DEFAULT '{}',
    env_vars                JSONB DEFAULT '[]',
    mounts                  JSONB DEFAULT '[]',
    -- Resource limits
    memory_limit            BIGINT,
    cpu_limit               REAL,
    restart_policy          VARCHAR(50),
    -- Health
    healthcheck_status      VARCHAR(50),
    healthcheck_failing_streak INTEGER DEFAULT 0,
    -- Updates
    current_version         VARCHAR(255),
    latest_version          VARCHAR(255),
    update_available        BOOLEAN DEFAULT false,
    update_checked_at       TIMESTAMPTZ,
    -- Security
    security_score          INTEGER DEFAULT 0,
    security_grade          VARCHAR(2) DEFAULT 'F',
    last_scanned_at         TIMESTAMPTZ,
    -- Sync
    synced_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(host_id, name)
);

CREATE INDEX idx_containers_host_id ON containers(host_id);
CREATE INDEX idx_containers_name ON containers(name);
CREATE INDEX idx_containers_status ON containers(status);
CREATE INDEX idx_containers_image ON containers(image);
CREATE INDEX idx_containers_update_available ON containers(update_available);
CREATE INDEX idx_containers_security_score ON containers(security_score);
CREATE INDEX idx_containers_security_grade ON containers(security_grade);
CREATE INDEX idx_containers_synced_at ON containers(synced_at);
CREATE INDEX idx_containers_host_status_name ON containers(host_id, status, name);

CREATE TRIGGER update_containers_updated_at
    BEFORE UPDATE ON containers
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Container Stats (time-series metrics)
-- ============================================================================
CREATE TABLE container_stats (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    container_id        VARCHAR(64) NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
    cpu_percent         REAL,
    memory_usage        BIGINT,
    memory_limit        BIGINT,
    memory_percent      REAL,
    network_rx_bytes    BIGINT,
    network_tx_bytes    BIGINT,
    block_read_bytes    BIGINT,
    block_write_bytes   BIGINT,
    pids                INTEGER,
    recorded_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_container_stats_container_id ON container_stats(container_id);
CREATE INDEX idx_container_stats_container_time ON container_stats(container_id, recorded_at DESC);
CREATE INDEX idx_container_stats_recorded_brin ON container_stats USING BRIN (recorded_at)
    WITH (pages_per_range = 128);

COMMENT ON TABLE container_stats IS 'Per-container time-series metrics; see also metrics_snapshots for unified storage';

-- ============================================================================
-- Container Logs (indexed log entries)
-- ============================================================================
CREATE TABLE container_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    container_id    VARCHAR(64) NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
    host_id         UUID REFERENCES hosts(id) ON DELETE CASCADE,
    stream          VARCHAR(10) NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL,
    message         TEXT NOT NULL,
    attributes      JSONB DEFAULT '{}'
);

CREATE INDEX idx_container_logs_container_id ON container_logs(container_id);
CREATE INDEX idx_container_logs_timestamp ON container_logs(timestamp);
CREATE INDEX idx_container_logs_stream ON container_logs(stream);
CREATE INDEX idx_container_logs_host_id ON container_logs(host_id);

-- ============================================================================
-- Images (cached state)
-- ============================================================================
CREATE TABLE images (
    id              VARCHAR(64) NOT NULL,
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    repo_tags       JSONB DEFAULT '[]',
    repo_digests    JSONB DEFAULT '[]',
    parent_id       VARCHAR(64),
    size            BIGINT NOT NULL DEFAULT 0,
    virtual_size    BIGINT NOT NULL DEFAULT 0,
    shared_size     BIGINT NOT NULL DEFAULT 0,
    labels          JSONB DEFAULT '{}',
    containers      BIGINT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL,
    synced_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, host_id)
);

CREATE INDEX idx_images_host_id ON images(host_id);
CREATE INDEX idx_images_synced_at ON images(synced_at);

-- ============================================================================
-- Volumes (cached state)
-- ============================================================================
CREATE TABLE volumes (
    name            VARCHAR(255) NOT NULL,
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    driver          VARCHAR(100) NOT NULL DEFAULT 'local',
    mountpoint      TEXT,
    scope           VARCHAR(50) NOT NULL DEFAULT 'local',
    labels          JSONB DEFAULT '{}',
    options         JSONB DEFAULT '{}',
    status          JSONB DEFAULT '{}',
    usage_size      BIGINT DEFAULT 0,
    usage_ref_count BIGINT DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    synced_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (name, host_id)
);

CREATE INDEX idx_volumes_host_id ON volumes(host_id);
CREATE INDEX idx_volumes_driver ON volumes(driver);

-- ============================================================================
-- Volume Backups
-- ============================================================================
CREATE TABLE volume_backups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    volume_name     VARCHAR(255) NOT NULL,
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    path            TEXT NOT NULL,
    size_bytes      BIGINT NOT NULL DEFAULT 0,
    compression     VARCHAR(20) NOT NULL DEFAULT 'none',
    encrypted       BOOLEAN NOT NULL DEFAULT false,
    trigger         VARCHAR(50) NOT NULL DEFAULT 'manual',
    status          VARCHAR(50) NOT NULL DEFAULT 'pending',
    error_message   TEXT,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_volume_backups_host_id ON volume_backups(host_id);
CREATE INDEX idx_volume_backups_volume_name ON volume_backups(volume_name);
CREATE INDEX idx_volume_backups_status ON volume_backups(status);
CREATE INDEX idx_volume_backups_expires_at ON volume_backups(expires_at);

-- ============================================================================
-- Registries
-- ============================================================================
CREATE TABLE registries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    url             VARCHAR(512) NOT NULL,
    username        VARCHAR(255),
    password        TEXT,
    is_default      BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_registries_url ON registries(url);

CREATE TRIGGER update_registries_updated_at
    BEFORE UPDATE ON registries
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Networks (cached state)
-- ============================================================================
CREATE TABLE networks (
    id              VARCHAR(64) NOT NULL,
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    driver          VARCHAR(100) NOT NULL DEFAULT 'bridge',
    scope           VARCHAR(50) NOT NULL DEFAULT 'local',
    enable_ipv6     BOOLEAN NOT NULL DEFAULT false,
    internal        BOOLEAN NOT NULL DEFAULT false,
    attachable      BOOLEAN NOT NULL DEFAULT false,
    ingress         BOOLEAN NOT NULL DEFAULT false,
    ipam_driver     VARCHAR(100),
    ipam_config     JSONB DEFAULT '[]',
    ipam_options    JSONB DEFAULT '{}',
    options         JSONB DEFAULT '{}',
    labels          JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    synced_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, host_id)
);

CREATE INDEX idx_networks_host_id ON networks(host_id);
CREATE INDEX idx_networks_name ON networks(name);
CREATE INDEX idx_networks_driver ON networks(driver);

-- ============================================================================
-- Container Network Connections (many-to-many)
-- ============================================================================
CREATE TABLE container_network_connections (
    container_id    VARCHAR(64) NOT NULL,
    network_id      VARCHAR(64) NOT NULL,
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    endpoint_id     VARCHAR(64),
    mac_address     VARCHAR(17),
    ipv4_address    VARCHAR(45),
    ipv6_address    VARCHAR(45),
    aliases         JSONB DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (container_id, network_id, host_id)
);

CREATE INDEX idx_container_network_host ON container_network_connections(host_id);
CREATE INDEX idx_container_network_container ON container_network_connections(container_id);
CREATE INDEX idx_container_network_network ON container_network_connections(network_id);
