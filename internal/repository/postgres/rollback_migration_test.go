// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRollbackMigrationTriggerPresent asserts that the 054 migration's
// up.sql file contains the append-only trigger SQL. This is a cheap
// guard against accidentally regenerating / overwriting the file in a
// way that drops the trigger; the runtime tests against a live Postgres
// live in tests/e2e/.
func TestRollbackMigrationTriggerPresent(t *testing.T) {
	upPath := filepath.Join("migrations", "054_automated_rollback.up.sql")
	body, err := os.ReadFile(upPath)
	if err != nil {
		t.Fatalf("read %s: %v", upPath, err)
	}
	content := string(body)

	mustContain := []string{
		"rollback_audit_log_block_mutation",
		"rollback_audit_log_append_only_trigger",
		"BEFORE UPDATE OR DELETE OR TRUNCATE ON rollback_audit_log",
		"RAISE EXCEPTION",
	}
	for _, needle := range mustContain {
		if !strings.Contains(content, needle) {
			t.Errorf("migration 054 does not contain expected fragment %q", needle)
		}
	}
}

// TestRollbackMigrationDownDropsTrigger ensures the down migration
// removes the trigger and function — the up/down pair must be
// reversible.
func TestRollbackMigrationDownDropsTrigger(t *testing.T) {
	downPath := filepath.Join("migrations", "054_automated_rollback.down.sql")
	body, err := os.ReadFile(downPath)
	if err != nil {
		t.Fatalf("read %s: %v", downPath, err)
	}
	content := string(body)
	mustContain := []string{
		"DROP TRIGGER IF EXISTS rollback_audit_log_append_only_trigger",
		"DROP FUNCTION IF EXISTS rollback_audit_log_block_mutation",
		"DROP TABLE IF EXISTS rollback_audit_log",
		"DROP TABLE IF EXISTS rollback_executions",
		"DROP TABLE IF EXISTS rollback_policies",
	}
	for _, needle := range mustContain {
		if !strings.Contains(content, needle) {
			t.Errorf("migration 054 down does not contain expected fragment %q", needle)
		}
	}
}
