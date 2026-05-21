// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// =============================================================================
// --json / --output precedence (P2)
// =============================================================================

// TestJSONShortcutForcesJSONOutput pins the contract that `--json`
// overrides whatever --output had been set to (including its default).
func TestJSONShortcutForcesJSONOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"t1","type":"email","value":"a@b.com","created_at":"2026-01-01T00:00:00Z"}]`))
	}))
	defer srv.Close()
	t.Setenv("USULNET_API_URL", srv.URL)

	// --json alone should produce JSON output.
	out, err := runRoot(t, []string{"recon", "target", "list", "--json"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	var got []map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Errorf("--json should emit valid JSON, got %q (err=%v)", out, err)
	}
	if len(got) != 1 || got[0]["id"] != "t1" {
		t.Errorf("unexpected JSON shape: %+v", got)
	}
}

// TestJSONShortcutBeatsExplicitOutput verifies the precedence: when both
// --json and --output yaml are passed, --json wins.
func TestJSONShortcutBeatsExplicitOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	t.Setenv("USULNET_API_URL", srv.URL)

	out, err := runRoot(t, []string{"recon", "target", "list", "--json", "--output", "yaml"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	// Empty JSON array (with newline) — not YAML's "[]\n" with no envelope.
	if strings.TrimSpace(out) != "[]" {
		t.Errorf("--json should win over --output yaml; got %q", out)
	}
}

// =============================================================================
// --quiet suppresses CLI info lines but not errors (P2 + infof)
// =============================================================================

// TestQuietSuppressesCancelMessage exercises the recon scan cancel info
// line ("canceled <id>") under --quiet. The cancel endpoint returns 204;
// in quiet mode the CLI must emit nothing on stdout.
func TestQuietSuppressesCancelMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	t.Setenv("USULNET_API_URL", srv.URL)

	out, err := runRoot(t, []string{"recon", "scan", "cancel", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "--quiet"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("--quiet should suppress the canceled message; got %q", out)
	}
}

// TestQuietDoesNotSuppressErrors confirms --quiet only affects infof()
// lines, not error output. An infra error still bubbles up.
func TestQuietDoesNotSuppressErrors(t *testing.T) {
	t.Setenv("USULNET_API_URL", "")
	_, err := runRoot(t, []string{"recon", "target", "list", "--quiet"})
	if err == nil {
		t.Fatal("expected infra error even with --quiet")
	}
	code, _ := metaExitCode(err)
	if code != exitServerUnreach {
		t.Errorf("expected exitServerUnreach (%d), got %d", exitServerUnreach, code)
	}
}

// =============================================================================
// formatError (H4)
// =============================================================================

// TestFormatErrorPlainText pins the default stderr line format:
// "usulnet: <message>". No prefix appears in --output json.
func TestFormatErrorPlainText(t *testing.T) {
	resetReconFlags()
	resetMetaFlags()
	outputFormat = "table"
	got := formatError(&usageError{msg: "bad input"})
	want := "usulnet: bad input"
	if got != want {
		t.Errorf("plain error format = %q, want %q", got, want)
	}
}

// TestFormatErrorJSON verifies the JSON envelope when --output json is
// active. Shape: {"error":"...","code":N} where N is the typed exit
// code (64 for usageError).
func TestFormatErrorJSON(t *testing.T) {
	resetReconFlags()
	resetMetaFlags()
	outputFormat = "json"
	t.Cleanup(func() { outputFormat = "table" })

	got := formatError(&usageError{msg: "bad input"})
	var decoded struct {
		Error string `json:"error"`
		Code  int    `json:"code"`
	}
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("JSON error should be valid JSON; got %q (err=%v)", got, err)
	}
	if decoded.Error != "bad input" {
		t.Errorf("JSON error.error = %q, want %q", decoded.Error, "bad input")
	}
	if decoded.Code != exitUsage {
		t.Errorf("JSON error.code = %d, want %d", decoded.Code, exitUsage)
	}
}

// TestFormatErrorJSONFallsBackToPlainOnMarshalFailure isn't directly
// reachable through public APIs because every error type satisfies the
// json.Marshaler default. Documenting the contract here keeps the dual
// branch in formatError honest if a future error type causes a panic
// during Marshal.
func TestFormatErrorPreservesExitCodeForInfraErrors(t *testing.T) {
	got := formatError(&infraError{msg: "server down", code: exitServerUnreach})
	if !strings.Contains(got, "usulnet: server down") {
		t.Errorf("expected plain prefix on infra error, got %q", got)
	}

	outputFormat = "json"
	t.Cleanup(func() { outputFormat = "table" })
	gotJSON := formatError(&infraError{msg: "server down", code: exitServerUnreach})
	var decoded struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal([]byte(gotJSON), &decoded); err != nil {
		t.Fatalf("JSON decode: %v", err)
	}
	if decoded.Code != exitServerUnreach {
		t.Errorf("expected JSON code %d (exitServerUnreach), got %d", exitServerUnreach, decoded.Code)
	}
}

// =============================================================================
// writeView (H2) — single output helper used by every list/record command
// =============================================================================

// TestWriteViewTable renders a header + rows via tabwriter in default
// mode. The point of the test is to lock the contract that the same
// (headers, rows) shape works irrespective of the json/yaml/table
// distinction at the call site.
func TestWriteViewTable(t *testing.T) {
	outputFormat = "table"
	cmd := &cobra.Command{}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	err := writeView(cmd, nil,
		[]string{"ID", "VALUE"},
		[][]string{{"a", "1"}, {"b", "2"}},
	)
	if err != nil {
		t.Fatalf("writeView: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "ID") || !strings.Contains(got, "VALUE") {
		t.Errorf("table output missing headers: %q", got)
	}
	if !strings.Contains(got, "a") || !strings.Contains(got, "2") {
		t.Errorf("table output missing data: %q", got)
	}
}

// TestWriteViewJSONUsesStructuredData verifies the structured payload
// (first arg) is what gets marshaled — not the [][]string table rows.
// This is the headline H2 fix: --output json on `recon target add` no
// longer emits a nested-array shape, it emits the target struct.
func TestWriteViewJSONUsesStructuredData(t *testing.T) {
	outputFormat = "json"
	t.Cleanup(func() { outputFormat = "table" })

	cmd := &cobra.Command{}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	type record struct {
		ID    string `json:"id"`
		Value string `json:"value"`
	}
	err := writeView(cmd, record{ID: "a", Value: "1"},
		[]string{"ID", "VALUE"},
		[][]string{{"a", "1"}},
	)
	if err != nil {
		t.Fatalf("writeView: %v", err)
	}
	var decoded record
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON decode (got %q): %v", buf.String(), err)
	}
	if decoded.ID != "a" || decoded.Value != "1" {
		t.Errorf("JSON should marshal the struct, got %+v", decoded)
	}
}
