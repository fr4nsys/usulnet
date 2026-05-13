// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"testing"
)

// TestNullableJSONBytes locks the contract of the shared helper used to
// bind JSON-marshaled byte slices to JSONB columns under
// pgx.QueryExecModeSimpleProtocol. The helper returns:
//   - nil for nil/empty input (so the column receives SQL NULL),
//   - string(b) for non-empty input (so pgx renders a JSON document
//     instead of the bytea hex literal that the simple-protocol encoder
//     would otherwise produce, which PostgreSQL rejects with SQLSTATE
//     22P02).
//
// See encodeJSONObject in recon_repo.go for the full rationale.
func TestNullableJSONBytes(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want any
	}{
		{"nil_slice", nil, nil},
		{"empty_slice", []byte{}, nil},
		{"json_null_literal_stays_string", []byte("null"), "null"},
		{"empty_object", []byte("{}"), "{}"},
		{"empty_array", []byte("[]"), "[]"},
		{"populated_object", []byte(`{"k":1}`), `{"k":1}`},
		{"populated_array", []byte(`["a","b"]`), `["a","b"]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := nullableJSONBytes(tc.in)
			if got != tc.want {
				t.Errorf("nullableJSONBytes(%q) = %v (%T), want %v (%T)",
					tc.in, got, got, tc.want, tc.want)
			}
		})
	}
}
