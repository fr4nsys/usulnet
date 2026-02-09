-- ============================================================================
-- 020_swarm: Docker Swarm service tracking
-- ============================================================================

CREATE TABLE swarm_services (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    docker_service_id   TEXT NOT NULL UNIQUE,
    name                TEXT NOT NULL,
    image               TEXT NOT NULL,
    replicas_desired    INTEGER NOT NULL DEFAULT 1,
    replicas_running    INTEGER NOT NULL DEFAULT 0,
    mode                TEXT NOT NULL DEFAULT 'replicated',
    status              TEXT NOT NULL DEFAULT 'running',
    source_container_id TEXT,
    ports               JSONB DEFAULT '[]',
    env                 JSONB DEFAULT '[]',
    labels              JSONB DEFAULT '{}',
    constraints         JSONB DEFAULT '[]',
    update_config       JSONB,
    rollback_config     JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_swarm_services_docker_id ON swarm_services(docker_service_id);
CREATE INDEX idx_swarm_services_name ON swarm_services(name);
CREATE INDEX idx_swarm_services_status ON swarm_services(status);

CREATE TRIGGER update_swarm_services_updated_at
    BEFORE UPDATE ON swarm_services
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
