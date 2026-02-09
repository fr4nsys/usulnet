-- ============================================================================
-- 002_hosts: Docker hosts/agents and host metrics
-- ============================================================================

CREATE TABLE hosts (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                    VARCHAR(255) NOT NULL UNIQUE,
    display_name            VARCHAR(255),
    endpoint_type           VARCHAR(50) NOT NULL,  -- 'local' | 'socket' | 'tcp' | 'agent'
    endpoint_url            VARCHAR(512),
    agent_id                UUID UNIQUE,
    agent_token_hash        VARCHAR(255),
    agent_info              JSONB,
    tls_enabled             BOOLEAN NOT NULL DEFAULT false,
    tls_ca_cert             TEXT,
    tls_client_cert         TEXT,
    tls_client_key          TEXT,
    status                  VARCHAR(50) NOT NULL DEFAULT 'unknown',
    status_message          TEXT,
    last_seen_at            TIMESTAMPTZ,
    docker_version          VARCHAR(50),
    docker_api_version      VARCHAR(20),
    os_type                 VARCHAR(50),
    os_version              VARCHAR(100),
    architecture            VARCHAR(50),
    kernel_version          VARCHAR(100),
    total_memory            BIGINT,
    total_cpus              INTEGER,
    storage_driver          VARCHAR(50),
    labels                  JSONB DEFAULT '{}',
    -- Swarm fields
    swarm_role              TEXT,           -- 'manager', 'worker', NULL
    swarm_node_id           TEXT,
    swarm_state             TEXT,           -- 'active', 'down', 'ready', 'disconnected'
    swarm_availability      TEXT,           -- 'active', 'pause', 'drain'
    -- Timestamps
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_hosts_name ON hosts(name);
CREATE INDEX idx_hosts_status ON hosts(status);
CREATE INDEX idx_hosts_agent_id ON hosts(agent_id);
CREATE INDEX idx_hosts_endpoint_type ON hosts(endpoint_type);
CREATE INDEX idx_hosts_last_seen_at ON hosts(last_seen_at);
CREATE INDEX idx_hosts_agent_token ON hosts(endpoint_type, agent_token_hash)
    WHERE endpoint_type = 'agent' AND agent_token_hash IS NOT NULL;
CREATE INDEX idx_hosts_last_seen ON hosts(last_seen_at)
    WHERE last_seen_at IS NOT NULL;

CREATE TRIGGER update_hosts_updated_at
    BEFORE UPDATE ON hosts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

COMMENT ON COLUMN hosts.agent_info IS 'Full agent metadata as JSONB (version, hostname, os, arch, capabilities)';
COMMENT ON COLUMN hosts.tls_client_key IS 'TLS client private key (encrypted at application layer)';

-- ============================================================================
-- Host Metrics (time-series for charts)
-- ============================================================================
CREATE TABLE host_metrics (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id             UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    cpu_percent         REAL,
    memory_used         BIGINT,
    memory_total        BIGINT,
    disk_used           BIGINT,
    disk_total          BIGINT,
    network_rx_bytes    BIGINT,
    network_tx_bytes    BIGINT,
    containers_running  INTEGER,
    containers_stopped  INTEGER,
    containers_total    INTEGER,
    recorded_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_host_metrics_host_id ON host_metrics(host_id);
CREATE INDEX idx_host_metrics_host_time ON host_metrics(host_id, recorded_at DESC);
CREATE INDEX idx_host_metrics_recorded_brin ON host_metrics USING BRIN (recorded_at)
    WITH (pages_per_range = 128);

COMMENT ON TABLE host_metrics IS 'Host-level time-series metrics; see also metrics_snapshots for unified storage';
