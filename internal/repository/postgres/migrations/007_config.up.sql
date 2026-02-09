-- ============================================================================
-- 007_config: Configuration management (variables, templates, sync)
-- ============================================================================

-- ============================================================================
-- Config Variables
-- ============================================================================
CREATE TABLE config_variables (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(255) NOT NULL,
    value               TEXT,
    encrypted_value     BYTEA,
    type                VARCHAR(20) NOT NULL DEFAULT 'plain',
    scope               VARCHAR(20) NOT NULL DEFAULT 'global',
    scope_id            UUID,
    description         TEXT,
    is_required         BOOLEAN NOT NULL DEFAULT false,
    default_value       TEXT,
    version             INTEGER NOT NULL DEFAULT 1,
    created_by          UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_by          UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(name, scope, scope_id)
);

CREATE INDEX idx_config_variables_scope ON config_variables(scope, scope_id);
CREATE INDEX idx_config_variables_name ON config_variables(name);
CREATE INDEX idx_config_variables_type ON config_variables(type);

CREATE TRIGGER update_config_variables_updated_at
    BEFORE UPDATE ON config_variables
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Config Variable History
-- ============================================================================
CREATE TABLE config_variable_history (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    variable_id     UUID NOT NULL REFERENCES config_variables(id) ON DELETE CASCADE,
    version         INTEGER NOT NULL,
    value           TEXT,
    updated_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(variable_id, version)
);

CREATE INDEX idx_config_variable_history_variable ON config_variable_history(variable_id);
CREATE INDEX idx_config_variable_history_version ON config_variable_history(variable_id, version DESC);

-- ============================================================================
-- Config Templates
-- ============================================================================
CREATE TABLE config_templates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL UNIQUE,
    description     TEXT,
    is_default      BOOLEAN NOT NULL DEFAULT false,
    variable_count  INTEGER NOT NULL DEFAULT 0,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_config_templates_updated_at
    BEFORE UPDATE ON config_templates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Config Sync State
-- ============================================================================
CREATE TABLE config_syncs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    container_id    VARCHAR(255) NOT NULL,
    container_name  VARCHAR(255) NOT NULL DEFAULT '',
    template_id     UUID,
    template_name   VARCHAR(255),
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    variables_hash  VARCHAR(64) NOT NULL DEFAULT '',
    synced_at       TIMESTAMPTZ,
    error_message   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(host_id, container_id)
);

CREATE INDEX idx_config_syncs_host ON config_syncs(host_id);
CREATE INDEX idx_config_syncs_status ON config_syncs(status);
CREATE INDEX idx_config_syncs_container ON config_syncs(container_id);

CREATE TRIGGER update_config_syncs_updated_at
    BEFORE UPDATE ON config_syncs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Config Audit Log
-- ============================================================================
CREATE TABLE config_audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action          VARCHAR(20) NOT NULL,
    entity_type     VARCHAR(20) NOT NULL,
    entity_id       UUID NOT NULL,
    entity_name     VARCHAR(255),
    old_value       TEXT,
    new_value       TEXT,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    username        VARCHAR(255),
    ip_address      INET,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_config_audit_log_entity ON config_audit_log(entity_type, entity_id);
CREATE INDEX idx_config_audit_log_user ON config_audit_log(user_id);
CREATE INDEX idx_config_audit_log_created ON config_audit_log(created_at);
