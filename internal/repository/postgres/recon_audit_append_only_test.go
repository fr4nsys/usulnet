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

// TestReconAuditLog_NoMutationStatements is the static guard the
// security review checklist requires: every UPDATE / DELETE against
// recon_audit_log must come from the retention worker via the
// well-known `recon_audit_log` retention path. Anywhere else, the
// audit table is append-only — no UPDATEs, no DELETEs from the API
// surface, no soft-deletes, no purges.
//
// The test scans every *.go file under internal/repository/postgres
// (and recon_repo.go specifically) for SQL strings that touch
// recon_audit_log with a UPDATE / DELETE / TRUNCATE verb. The
// retention repository is exempted (it lives in
// recon_retention_repo.go and is the single permitted writer). Tests
// are exempted because they truncate the table between cases.
//
// Failure of this test means someone added a write path to the audit
// log that bypasses the AppendAudit API. Either move the write
// through AppendAudit or update this allow-list deliberately.
func TestReconAuditLog_NoMutationStatements(t *testing.T) {
	// The forbidden patterns. We use regex to allow flexible
	// whitespace and to match both single-line and multi-line SQL
	// constants.
	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`(?i)UPDATE\s+recon_audit_log`),
		regexp.MustCompile(`(?i)TRUNCATE\s+recon_audit_log`),
	}

	// DELETE is permitted from recon_retention_repo.go (which runs
	// retention pruning under a separate audit action) and from the
	// test helper that truncates between test cases.
	deletePattern := regexp.MustCompile(`(?i)DELETE\s+FROM\s+recon_audit_log`)

	allowedDeleteFiles := map[string]bool{
		"recon_retention_repo.go": true,
	}

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
		// Tests get a pass — they truncate the table between cases.
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
				t.Errorf("%s contains a DELETE from recon_audit_log; "+
					"only the retention repo may delete audit rows", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
