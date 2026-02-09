-- Alert Rules
CREATE TABLE IF NOT EXISTS alert_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID REFERENCES hosts(id) ON DELETE CASCADE,
    container_id    VARCHAR(128),
    name            VARCHAR(255) NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    metric          VARCHAR(64) NOT NULL,
    operator        VARCHAR(8) NOT NULL,
    threshold       DOUBLE PRECISION NOT NULL,
    severity        VARCHAR(16) NOT NULL DEFAULT 'warning',
    duration_seconds INTEGER NOT NULL DEFAULT 0,
    cooldown_seconds INTEGER NOT NULL DEFAULT 300,
    eval_interval_seconds INTEGER NOT NULL DEFAULT 60,
    state           VARCHAR(16) NOT NULL DEFAULT 'ok',
    state_changed_at TIMESTAMPTZ,
    last_evaluated  TIMESTAMPTZ,
    last_fired_at   TIMESTAMPTZ,
    firing_value    DOUBLE PRECISION,
    notify_channels TEXT[] NOT NULL DEFAULT '{}',
    auto_actions    JSONB,
    is_enabled      BOOLEAN NOT NULL DEFAULT true,
    labels          JSONB NOT NULL DEFAULT '{}',
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alert_rules_state ON alert_rules(state);
CREATE INDEX idx_alert_rules_enabled ON alert_rules(is_enabled);
CREATE INDEX idx_alert_rules_host ON alert_rules(host_id);
CREATE INDEX idx_alert_rules_metric ON alert_rules(metric);

CREATE TRIGGER set_updated_at_alert_rules
    BEFORE UPDATE ON alert_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Alert Events
CREATE TABLE IF NOT EXISTS alert_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id        UUID NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    host_id         UUID NOT NULL,
    container_id    VARCHAR(128),
    state           VARCHAR(16) NOT NULL,
    value           DOUBLE PRECISION NOT NULL,
    threshold       DOUBLE PRECISION NOT NULL,
    message         TEXT NOT NULL DEFAULT '',
    labels          JSONB NOT NULL DEFAULT '{}',
    fired_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alert_events_alert ON alert_events(alert_id);
CREATE INDEX idx_alert_events_state ON alert_events(state);
CREATE INDEX idx_alert_events_fired ON alert_events(fired_at);
CREATE INDEX idx_alert_events_host ON alert_events(host_id);

-- Alert Silences
CREATE TABLE IF NOT EXISTS alert_silences (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id    UUID REFERENCES alert_rules(id) ON DELETE CASCADE,
    host_id     UUID REFERENCES hosts(id) ON DELETE CASCADE,
    reason      TEXT NOT NULL DEFAULT '',
    starts_at   TIMESTAMPTZ NOT NULL,
    ends_at     TIMESTAMPTZ NOT NULL,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alert_silences_alert ON alert_silences(alert_id);
CREATE INDEX idx_alert_silences_active ON alert_silences(starts_at, ends_at);

-- Registries repository (table exists from 003 but no repo was wired)
-- Add missing index for lookups
CREATE INDEX IF NOT EXISTS idx_registries_name ON registries(name);

-- Webhook delivery logs for outgoing webhooks
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id      VARCHAR(255) NOT NULL,
    event_type      VARCHAR(128) NOT NULL,
    url             VARCHAR(2048) NOT NULL,
    method          VARCHAR(8) NOT NULL DEFAULT 'POST',
    request_headers JSONB,
    request_body    TEXT,
    response_code   INTEGER,
    response_body   TEXT,
    duration_ms     INTEGER,
    status          VARCHAR(16) NOT NULL DEFAULT 'pending',
    error_message   TEXT,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);
CREATE INDEX idx_webhook_deliveries_status ON webhook_deliveries(status);
CREATE INDEX idx_webhook_deliveries_created ON webhook_deliveries(created_at);

-- Outgoing webhook configurations
CREATE TABLE IF NOT EXISTS outgoing_webhooks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,
    url         VARCHAR(2048) NOT NULL,
    secret      TEXT,
    events      TEXT[] NOT NULL DEFAULT '{}',
    is_enabled  BOOLEAN NOT NULL DEFAULT true,
    headers     JSONB NOT NULL DEFAULT '{}',
    retry_count INTEGER NOT NULL DEFAULT 3,
    timeout     INTEGER NOT NULL DEFAULT 30,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER set_updated_at_outgoing_webhooks
    BEFORE UPDATE ON outgoing_webhooks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Auto-deploy rules
CREATE TABLE IF NOT EXISTS auto_deploy_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    source_type     VARCHAR(32) NOT NULL,
    source_id       UUID,
    repository      VARCHAR(512) NOT NULL DEFAULT '',
    branch_pattern  VARCHAR(255) NOT NULL DEFAULT '*',
    event_types     TEXT[] NOT NULL DEFAULT '{push}',
    target_type     VARCHAR(32) NOT NULL,
    target_id       VARCHAR(255) NOT NULL,
    action          VARCHAR(32) NOT NULL DEFAULT 'redeploy',
    is_enabled      BOOLEAN NOT NULL DEFAULT true,
    auto_rollback   BOOLEAN NOT NULL DEFAULT true,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auto_deploy_rules_source ON auto_deploy_rules(source_type, source_id);
CREATE INDEX idx_auto_deploy_rules_enabled ON auto_deploy_rules(is_enabled);

CREATE TRIGGER set_updated_at_auto_deploy_rules
    BEFORE UPDATE ON auto_deploy_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Runbooks
CREATE TABLE IF NOT EXISTS runbooks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    steps           JSONB NOT NULL DEFAULT '[]',
    trigger_type    VARCHAR(32) NOT NULL DEFAULT 'manual',
    trigger_config  JSONB NOT NULL DEFAULT '{}',
    is_enabled      BOOLEAN NOT NULL DEFAULT true,
    last_run_at     TIMESTAMPTZ,
    last_run_status VARCHAR(16),
    run_count       BIGINT NOT NULL DEFAULT 0,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_runbooks_enabled ON runbooks(is_enabled);
CREATE INDEX idx_runbooks_trigger ON runbooks(trigger_type);

CREATE TRIGGER set_updated_at_runbooks
    BEFORE UPDATE ON runbooks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Runbook executions
CREATE TABLE IF NOT EXISTS runbook_executions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    runbook_id      UUID NOT NULL REFERENCES runbooks(id) ON DELETE CASCADE,
    status          VARCHAR(16) NOT NULL DEFAULT 'running',
    trigger_type    VARCHAR(32) NOT NULL,
    trigger_data    JSONB,
    steps_completed INTEGER NOT NULL DEFAULT 0,
    steps_total     INTEGER NOT NULL DEFAULT 0,
    result          JSONB,
    error_message   TEXT,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    triggered_by    UUID REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_runbook_executions_runbook ON runbook_executions(runbook_id);
CREATE INDEX idx_runbook_executions_status ON runbook_executions(status);
