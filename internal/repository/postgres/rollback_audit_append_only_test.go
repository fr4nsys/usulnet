// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestRollbackAuditLog_NoMutationStatements is the static guard the
// security review checklist requires: every UPDATE / DELETE / TRUNCATE
// against rollback_audit_log must be impossible from the API surface.
// The Postgres trigger rollback_audit_log_append_only_trigger (migration
// 054) provides the runtime backstop; this test enforces the same at
// the Go source layer so a stray write is caught at compile time
// instead of in production.
//
// The test scans every non-test *.go file under
// internal/repository/postgres for SQL strings that touch
// rollback_audit_log with a UPDATE / DELETE / TRUNCATE verb. No file
// is exempt from UPDATE/TRUNCATE; DELETE is permitted only from a
// future rollback_retention_repo.go (when added, the constant below
// must be updated deliberately by the engineer adding it).
//
// Failure means someone added a write path to the audit log that
// bypasses the AppendAudit API. Either move the write through
// AppendAudit / Append or update the allow-list deliberately.
func TestRollbackAuditLog_NoMutationStatements(t *testing.T) {
	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`(?i)UPDATE\s+rollback_audit_log`),
		regexp.MustCompile(`(?i)TRUNCATE\s+rollback_audit_log`),
	}
	deletePattern := regexp.MustCompile(`(?i)DELETE\s+FROM\s+rollback_audit_log`)

	// DELETE is permitted only from the future retention repo (mirrors
	// recon_retention_repo.go). v26.5.1 ships without one; the allow
	// list is empty.
	allowedDeleteFiles := map[string]bool{}

	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Tests can truncate freely (they bypass the trigger via SUPERUSER
		// or use SET session_replication_role = replica). The static guard
		// applies to non-test code.
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		base := filepath.Base(path)
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		content := string(data)

		for _, rx := range forbidden {
			if rx.MatchString(content) {
				t.Errorf("%s contains a forbidden audit-log mutation: %s",
					path, rx.String())
			}
		}
		if deletePattern.MatchString(content) {
			if !allowedDeleteFiles[base] {
				t.Errorf("%s contains a DELETE from rollback_audit_log; "+
					"only the (future) retention repo may delete audit rows", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
