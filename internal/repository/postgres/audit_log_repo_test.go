// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres_test

import (
	"context"
	"testing"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// TestAuditLogRepo_Create_JSONBBinding locks the simple-protocol JSONB
// fix in place: the connection pool runs in
// pgx.QueryExecModeSimpleProtocol (see db.go) under which a []byte
// argument is rendered as a hex-encoded bytea literal that the audit_log
// details column rejects with "invalid input syntax for type json"
// (SQLSTATE 22P02). audit_log_repo.Create therefore passes
// string(detailsJSON) — if a later edit converts it back to []byte this
// test fails fast against a real Postgres.
func TestAuditLogRepo_Create_JSONBBinding(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}

	repo := postgres.NewAuditLogRepository(testDB, logger.Nop())
	ctx := context.Background()

	username := "smoke"
	cases := []struct {
		name  string
		input *postgres.CreateAuditLogInput
	}{
		{
			name: "with_details_map",
			input: &postgres.CreateAuditLogInput{
				Username:     &username,
				Action:       "login",
				ResourceType: "session",
				Details:      map[string]any{"trigger": "test", "n": 1},
				Success:      true,
			},
		},
		{
			name: "without_details_map",
			input: &postgres.CreateAuditLogInput{
				Username:     &username,
				Action:       "login",
				ResourceType: "session",
				Details:      nil,
				Success:      false,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := repo.Create(ctx, tc.input); err != nil {
				t.Fatalf("Create: %v", err)
			}
		})
	}

	// Confirm rows actually landed and the JSONB documents are well-formed
	// (a successful insert with a malformed bytea literal would still
	// register as an error from Postgres; the assertion guards against a
	// regression where the row inserts but the JSON content is corrupt).
	var n int
	if err := testDB.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE action = 'login' AND details ? 'success'`,
	).Scan(&n); err != nil {
		t.Fatalf("verify count: %v", err)
	}
	if n < len(cases) {
		t.Errorf("expected at least %d audit rows with details.success, got %d", len(cases), n)
	}

	t.Cleanup(func() {
		_, _ = testDB.Exec(ctx, "DELETE FROM audit_log WHERE action = 'login' AND details ? 'success'")
	})
}
