-- ============================================================================
-- 021_retention: Data retention functions and advisory lock helpers
-- ============================================================================

-- ============================================================================
-- Retention cleanup functions (call via scheduler or pg_cron)
-- ============================================================================

CREATE OR REPLACE FUNCTION cleanup_old_metrics(retention_days INTEGER DEFAULT 30)
RETURNS INTEGER AS $$
DECLARE deleted_count INTEGER;
BEGIN
    DELETE FROM metrics_snapshots WHERE collected_at < NOW() - (retention_days * INTERVAL '1 day');
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION cleanup_old_container_stats(retention_days INTEGER DEFAULT 7)
RETURNS INTEGER AS $$
DECLARE deleted_count INTEGER;
BEGIN
    DELETE FROM container_stats WHERE recorded_at < NOW() - (retention_days * INTERVAL '1 day');
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION cleanup_old_host_metrics(retention_days INTEGER DEFAULT 30)
RETURNS INTEGER AS $$
DECLARE deleted_count INTEGER;
BEGIN
    DELETE FROM host_metrics WHERE recorded_at < NOW() - (retention_days * INTERVAL '1 day');
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION cleanup_old_audit_log(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE deleted_count INTEGER;
BEGIN
    DELETE FROM audit_log WHERE created_at < NOW() - (retention_days * INTERVAL '1 day');
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION cleanup_old_job_events(retention_days INTEGER DEFAULT 7)
RETURNS INTEGER AS $$
DECLARE deleted_count INTEGER;
BEGIN
    DELETE FROM job_events WHERE created_at < NOW() - (retention_days * INTERVAL '1 day');
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION cleanup_old_notification_logs(retention_days INTEGER DEFAULT 30)
RETURNS INTEGER AS $$
DECLARE deleted_count INTEGER;
BEGIN
    DELETE FROM notification_logs WHERE created_at < NOW() - (retention_days * INTERVAL '1 day');
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION cleanup_expired_password_reset_tokens()
RETURNS INTEGER AS $$
DECLARE deleted_count INTEGER;
BEGIN
    DELETE FROM password_reset_tokens
    WHERE expires_at < NOW() - INTERVAL '1 day'
       OR (used_at IS NOT NULL AND used_at < NOW() - INTERVAL '1 hour');
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE deleted_count INTEGER;
BEGIN
    DELETE FROM user_sessions WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Migration advisory lock helpers
-- ============================================================================

-- usulnet migration lock ID: 0x7573756C = 'usul' in hex = 1970500972
CREATE OR REPLACE FUNCTION acquire_migration_lock()
RETURNS BOOLEAN AS $$
BEGIN
    RETURN pg_try_advisory_lock(1970500972);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION release_migration_lock()
RETURNS VOID AS $$
BEGIN
    PERFORM pg_advisory_unlock(1970500972);
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Comments
-- ============================================================================
COMMENT ON FUNCTION cleanup_old_metrics IS 'Delete metrics_snapshots older than N days (default 30)';
COMMENT ON FUNCTION cleanup_old_container_stats IS 'Delete container_stats older than N days (default 7)';
COMMENT ON FUNCTION cleanup_old_host_metrics IS 'Delete host_metrics older than N days (default 30)';
COMMENT ON FUNCTION cleanup_old_audit_log IS 'Delete audit_log entries older than N days (default 90)';
COMMENT ON FUNCTION cleanup_old_job_events IS 'Delete job_events older than N days (default 7)';
COMMENT ON FUNCTION cleanup_old_notification_logs IS 'Delete notification_logs older than N days (default 30)';
COMMENT ON FUNCTION acquire_migration_lock IS 'Try to acquire advisory lock for safe concurrent migrations';
COMMENT ON FUNCTION release_migration_lock IS 'Release advisory lock after migration completes';
