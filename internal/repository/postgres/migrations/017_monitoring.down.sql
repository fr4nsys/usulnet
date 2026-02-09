DROP FUNCTION IF EXISTS cleanup_stale_terminal_sessions(INTEGER) CASCADE;
DROP VIEW IF EXISTS active_terminal_sessions CASCADE;
DROP TABLE IF EXISTS terminal_sessions CASCADE;
DROP TABLE IF EXISTS metrics_snapshots CASCADE;
