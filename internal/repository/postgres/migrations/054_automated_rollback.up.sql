-- 054_automated_rollback.up.sql — Automated rollback module.
-- Ported from v26.2.7 migration 052_automated_rollback (renumbered to
-- avoid collisions with v26.5.0's 044_recon_module / 045_recon_retention,
-- session-01 firewall (050), session-02 crontab (049), and session-03
-- backup verification slots).
--
-- The module subscribes to the change_events stream (migration 039) and,
-- on detection of a failed deploy that matches a policy, executes a
-- rollback against the existing stack-revert API. Every executed action
-- is recorded in rollback_audit_log; the table is enforced as
-- APPEND-ONLY by the rollback_audit_log_append_only_trigger below — only
-- INSERT is permitted at the SQL layer, UPDATE/DELETE/TRUNCATE raise.

-- ============================================================================
-- rollback_policies — operator-defined detection rules.
--
-- A policy matches a deploy result by (stack scope, trigger kind, optional
-- target). When fired, it executes the action against the stack's last
-- known-good version. last_good_strategy controls how that version is
-- chosen at execution time:
--   - "previous"   — the version immediately before the failing one
--   - "last_healthy" — the most recent version with a successful
--                       deploy + healthcheck pass (default)
-- ============================================================================
CREATE TABLE IF NOT EXISTS rollback_policies (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(255) NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    enabled             BOOLEAN NOT NULL DEFAULT true,
    -- Scope: "all" applies to every stack on the host; "stack" applies
    -- to a specific stack_id (column below); "tag" applies to any stack
    -- whose name matches scope_value (substring match).
    scope               VARCHAR(20) NOT NULL DEFAULT 'all'
                        CHECK (scope IN ('all', 'stack', 'tag')),
    scope_stack_id      UUID REFERENCES stacks(id) ON DELETE CASCADE,
    scope_value         VARCHAR(255) NOT NULL DEFAULT '',
    -- Trigger: which signal fires the policy.
    --   "deploy_failed"     — stack_deploy completed with non-zero exit
    --   "healthcheck_failed" — post-deploy healthcheck never went green
    --   "container_crash"   — restart loop detected within window_seconds
    trigger_kind        VARCHAR(40) NOT NULL DEFAULT 'deploy_failed'
                        CHECK (trigger_kind IN (
                            'deploy_failed',
                            'healthcheck_failed',
                            'container_crash'
                        )),
    -- For "container_crash": how many restarts inside how many seconds
    -- to consider the deploy bad. NULL = use defaults from the service.
    failure_threshold   INT,
    window_seconds      INT,
    -- Strategy for picking the version to roll back to.
    last_good_strategy  VARCHAR(40) NOT NULL DEFAULT 'last_healthy'
                        CHECK (last_good_strategy IN ('previous', 'last_healthy')),
    -- Optional cooldown — refuse to fire again on the same stack within
    -- N seconds of the previous execution. Protects against flapping.
    cooldown_seconds    INT NOT NULL DEFAULT 300,
    -- If true the policy is evaluated but does NOT execute the rollback;
    -- an audit row is recorded with action='dry_run' so the operator can
    -- confirm the matching logic before going live.
    dry_run             BOOLEAN NOT NULL DEFAULT false,
    created_by          UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rollback_policies_enabled
    ON rollback_policies(enabled) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_rollback_policies_scope_stack
    ON rollback_policies(scope_stack_id) WHERE scope_stack_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_rollback_policies_trigger
    ON rollback_policies(trigger_kind);

CREATE TRIGGER update_rollback_policies_updated_at
    BEFORE UPDATE ON rollback_policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- rollback_executions — one row per fired policy. status moves through
-- pending -> running -> {succeeded, failed, skipped}. dry_run records
-- the candidate target without invoking the stack revert.
-- ============================================================================
CREATE TABLE IF NOT EXISTS rollback_executions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id           UUID NOT NULL REFERENCES rollback_policies(id) ON DELETE CASCADE,
    stack_id            UUID NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    change_event_id     UUID,
    trigger_kind        VARCHAR(40) NOT NULL,
    from_version        INT,
    to_version          INT,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending'
                        CHECK (status IN (
                            'pending', 'running', 'succeeded', 'failed',
                            'skipped', 'dry_run'
                        )),
    reason              TEXT NOT NULL DEFAULT '',
    error               TEXT NOT NULL DEFAULT '',
    started_at          TIMESTAMPTZ,
    finished_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rollback_executions_policy
    ON rollback_executions(policy_id);
CREATE INDEX IF NOT EXISTS idx_rollback_executions_stack
    ON rollback_executions(stack_id);
CREATE INDEX IF NOT EXISTS idx_rollback_executions_status
    ON rollback_executions(status) WHERE status IN ('pending', 'running');
CREATE INDEX IF NOT EXISTS idx_rollback_executions_created_at
    ON rollback_executions(created_at DESC);

CREATE TRIGGER update_rollback_executions_updated_at
    BEFORE UPDATE ON rollback_executions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- rollback_audit_log — append-only record of every policy-related action.
--
-- The append-only posture mirrors recon_audit_log: only INSERT is
-- permitted at the SQL layer. The trigger below raises on UPDATE,
-- DELETE, and TRUNCATE so even a privileged DBA cannot silently rewrite
-- history through the application connection. The retention worker is
-- modelled after recon_retention_repo.go: it is the single authorised
-- DELETE writer and operates through a SECURITY DEFINER function that
-- bypasses the trigger (added in a follow-up retention session).
-- ============================================================================
CREATE TABLE IF NOT EXISTS rollback_audit_log (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id           UUID,
    execution_id        UUID,
    stack_id            UUID,
    actor_id            UUID REFERENCES users(id) ON DELETE SET NULL,
    action              VARCHAR(64) NOT NULL,
    details             TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rollback_audit_policy
    ON rollback_audit_log(policy_id);
CREATE INDEX IF NOT EXISTS idx_rollback_audit_execution
    ON rollback_audit_log(execution_id);
CREATE INDEX IF NOT EXISTS idx_rollback_audit_stack
    ON rollback_audit_log(stack_id);
CREATE INDEX IF NOT EXISTS idx_rollback_audit_action
    ON rollback_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_rollback_audit_created_at
    ON rollback_audit_log(created_at DESC);

-- Append-only enforcement. The trigger raises on UPDATE / DELETE /
-- TRUNCATE so the API and service paths cannot mutate audit rows. The
-- static guard test (rollback_audit_append_only_test.go) provides the
-- same posture at the Go source layer; the trigger is the runtime
-- backstop for direct SQL access.
CREATE OR REPLACE FUNCTION rollback_audit_log_block_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'rollback_audit_log is append-only; %.% rejected', TG_TABLE_NAME, TG_OP
        USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER rollback_audit_log_append_only_trigger
    BEFORE UPDATE OR DELETE OR TRUNCATE ON rollback_audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION rollback_audit_log_block_mutation();
