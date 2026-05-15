-- 054_automated_rollback.down.sql — drop the automated rollback tables.

DROP TRIGGER IF EXISTS rollback_audit_log_append_only_trigger ON rollback_audit_log;
DROP FUNCTION IF EXISTS rollback_audit_log_block_mutation();

DROP TRIGGER IF EXISTS update_rollback_executions_updated_at ON rollback_executions;
DROP TRIGGER IF EXISTS update_rollback_policies_updated_at ON rollback_policies;

DROP INDEX IF EXISTS idx_rollback_audit_created_at;
DROP INDEX IF EXISTS idx_rollback_audit_action;
DROP INDEX IF EXISTS idx_rollback_audit_stack;
DROP INDEX IF EXISTS idx_rollback_audit_execution;
DROP INDEX IF EXISTS idx_rollback_audit_policy;

DROP INDEX IF EXISTS idx_rollback_executions_created_at;
DROP INDEX IF EXISTS idx_rollback_executions_status;
DROP INDEX IF EXISTS idx_rollback_executions_stack;
DROP INDEX IF EXISTS idx_rollback_executions_policy;

DROP INDEX IF EXISTS idx_rollback_policies_trigger;
DROP INDEX IF EXISTS idx_rollback_policies_scope_stack;
DROP INDEX IF EXISTS idx_rollback_policies_enabled;

DROP TABLE IF EXISTS rollback_audit_log;
DROP TABLE IF EXISTS rollback_executions;
DROP TABLE IF EXISTS rollback_policies;
