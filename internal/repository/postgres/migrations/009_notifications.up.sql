-- ============================================================================
-- 009_notifications: In-app notifications, delivery, preferences, routing
-- ============================================================================

-- ============================================================================
-- Notifications (in-app)
-- ============================================================================
CREATE TABLE notifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type            VARCHAR(20) NOT NULL,
    event           VARCHAR(50) NOT NULL,
    title           VARCHAR(255) NOT NULL,
    message         TEXT NOT NULL,
    entity_type     VARCHAR(20),
    entity_id       UUID,
    entity_name     VARCHAR(255),
    data            JSONB,
    is_read         BOOLEAN NOT NULL DEFAULT false,
    read_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notifications_user ON notifications(user_id);
CREATE INDEX idx_notifications_unread ON notifications(user_id, is_read) WHERE is_read = false;
CREATE INDEX idx_notifications_event ON notifications(event);
CREATE INDEX idx_notifications_entity ON notifications(entity_type, entity_id);
CREATE INDEX idx_notifications_created ON notifications(created_at);
CREATE INDEX idx_notifications_user_created ON notifications(user_id, created_at DESC);

-- ============================================================================
-- Notification Sends (external delivery tracking)
-- ============================================================================
CREATE TABLE notification_sends (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    notification_id     UUID NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
    channel             VARCHAR(20) NOT NULL,
    recipient           VARCHAR(255) NOT NULL,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempts            INTEGER NOT NULL DEFAULT 0,
    last_attempt_at     TIMESTAMPTZ,
    sent_at             TIMESTAMPTZ,
    error_message       TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notification_sends_notification ON notification_sends(notification_id);
CREATE INDEX idx_notification_sends_status ON notification_sends(status);
CREATE INDEX idx_notification_sends_pending ON notification_sends(status, channel)
    WHERE status = 'pending';

-- ============================================================================
-- Notification Preferences (per user, per event)
-- ============================================================================
CREATE TABLE notification_preferences (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event           VARCHAR(50) NOT NULL,
    channel         VARCHAR(20) NOT NULL,
    is_enabled      BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, event, channel)
);

CREATE INDEX idx_notification_preferences_user ON notification_preferences(user_id);
CREATE INDEX idx_notification_preferences_event ON notification_preferences(event);

CREATE TRIGGER update_notification_preferences_updated_at
    BEFORE UPDATE ON notification_preferences
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Notification Channels (global config)
-- ============================================================================
CREATE TABLE notification_channels (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(20) NOT NULL UNIQUE,
    type                VARCHAR(20) NOT NULL DEFAULT 'generic',
    enabled             BOOLEAN NOT NULL DEFAULT false,
    settings            JSONB NOT NULL DEFAULT '{}',
    notification_types  JSONB DEFAULT '[]',
    min_priority        INTEGER NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_notification_channels_updated_at
    BEFORE UPDATE ON notification_channels
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Notification Routing Rules
-- ============================================================================
CREATE TABLE notification_routing_rules (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(255) NOT NULL,
    enabled             BOOLEAN NOT NULL DEFAULT true,
    notification_types  JSONB DEFAULT '[]',
    min_priority        INTEGER NOT NULL DEFAULT 0,
    categories          JSONB DEFAULT '[]',
    channels            JSONB DEFAULT '[]',
    exclude_channels    JSONB DEFAULT '[]',
    time_window         JSONB,
    position            INTEGER NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notification_routing_rules_enabled ON notification_routing_rules(enabled);
CREATE INDEX idx_notification_routing_rules_position ON notification_routing_rules(position);

CREATE TRIGGER update_notification_routing_rules_updated_at
    BEFORE UPDATE ON notification_routing_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Notification Logs (delivery history)
-- ============================================================================
CREATE TABLE notification_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type            VARCHAR(50) NOT NULL,
    priority        INTEGER NOT NULL DEFAULT 0,
    title           VARCHAR(500) NOT NULL,
    body            TEXT,
    channels        JSONB NOT NULL DEFAULT '[]',
    results         JSONB NOT NULL DEFAULT '[]',
    throttled       BOOLEAN NOT NULL DEFAULT false,
    success_count   INTEGER NOT NULL DEFAULT 0,
    failed_count    INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notification_logs_type ON notification_logs(type);
CREATE INDEX idx_notification_logs_created ON notification_logs(created_at DESC);
CREATE INDEX idx_notification_logs_priority ON notification_logs(priority);
