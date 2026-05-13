// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// -update regenerates the *.golden files when true. Run as:
//
//	go test ./cmd/usulnet -run TestHelpSnapshots -update
var update = flag.Bool("update", false, "update golden files")

// =============================================================================
// Snapshot tests for help text — one golden file per leaf subcommand.
// =============================================================================

func TestHelpSnapshots(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"recon", []string{"recon", "--help"}},
		{"recon-target", []string{"recon", "target", "--help"}},
		{"recon-target-add", []string{"recon", "target", "add", "--help"}},
		{"recon-target-list", []string{"recon", "target", "list", "--help"}},
		{"recon-target-verify", []string{"recon", "target", "verify", "--help"}},
		{"recon-profile-list", []string{"recon", "profile", "list", "--help"}},
		{"recon-scan-start", []string{"recon", "scan", "start", "--help"}},
		{"recon-scan-list", []string{"recon", "scan", "list", "--help"}},
		{"recon-scan-status", []string{"recon", "scan", "status", "--help"}},
		{"recon-scan-cancel", []string{"recon", "scan", "cancel", "--help"}},
		{"recon-scan-report", []string{"recon", "scan", "report", "--help"}},
		{"recon-findings-list", []string{"recon", "findings", "list", "--help"}},
		{"meta", []string{"meta", "--help"}},
		{"meta-extract", []string{"meta", "extract", "--help"}},
		{"meta-strip", []string{"meta", "strip", "--help"}},
		{"meta-scan", []string{"meta", "scan", "--help"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := captureHelp(t, tc.args)
			goldenPath := filepath.Join("testdata", tc.name+".golden")
			if *update {
				if err := os.WriteFile(goldenPath, []byte(got), 0o600); err != nil {
					t.Fatalf("write golden: %v", err)
				}
				return
			}
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden %s: %v (run `go test -update` to regenerate)", goldenPath, err)
			}
			if string(want) != got {
				t.Errorf("help text mismatch for %s\n=== want ===\n%s\n=== got ===\n%s",
					tc.name, want, got)
			}
		})
	}
}

// captureHelp invokes the global rootCmd with the supplied args and returns
// captured stdout. Cobra's help routine writes to OutOrStdout, so SetOut is
// sufficient to intercept it without affecting global state.
func captureHelp(t *testing.T, args []string) string {
	t.Helper()
	buf := &bytes.Buffer{}
	resetCobraFlags(rootCmd)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(args)
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
		resetCobraFlags(rootCmd)
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute %v: %v", args, err)
	}
	return buf.String()
}

// =============================================================================
// Round-trip tests against a fake API server.
// =============================================================================

func TestReconTargetAddRoundTrip(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"id":"11111111-1111-1111-1111-111111111111","type":"email","value":"a@b.com","created_at":"2026-01-01T00:00:00Z"}`)
	}))
	defer srv.Close()

	t.Setenv("USULNET_API_URL", srv.URL)
	t.Setenv("USULNET_API_TOKEN", "tkn")

	out, err := runRoot(t, []string{"recon", "target", "add", "email", "a@b.com", "--output", "json"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	if gotMethod != http.MethodPost || gotPath != "/api/v1/recon/targets" {
		t.Errorf("wrong request: %s %s", gotMethod, gotPath)
	}
	if gotAuth != "Bearer tkn" {
		t.Errorf("missing/wrong auth header: %q", gotAuth)
	}
	if gotBody["type"] != "email" || gotBody["value"] != "a@b.com" {
		t.Errorf("body decoded wrong: %+v", gotBody)
	}
	if !strings.Contains(out, "11111111-1111-1111-1111-111111111111") {
		t.Errorf("stdout missing target ID: %q", out)
	}
}

func TestReconScanListRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[
		  {"id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","target_id":"t1","profile_id":"p1","status":"completed","created_at":"2026-01-01T00:00:00Z"},
		  {"id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","target_id":"t2","profile_id":"p1","status":"running","created_at":"2026-01-02T00:00:00Z"}
		]`)
	}))
	defer srv.Close()
	t.Setenv("USULNET_API_URL", srv.URL)
	t.Setenv("USULNET_API_TOKEN", "")

	out, err := runRoot(t, []string{"recon", "scan", "list", "--output", "table"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	for _, want := range []string{"aaaaaaaa", "completed", "running"} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q: %q", want, out)
		}
	}
}

func TestReconScanReportRoundTrip(t *testing.T) {
	wantBody := `id,severity,module
1,high,dns`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/report.csv") {
			http.Error(w, "wrong path: "+r.URL.Path, http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, wantBody)
	}))
	defer srv.Close()
	t.Setenv("USULNET_API_URL", srv.URL)

	out, err := runRoot(t, []string{"recon", "scan", "report",
		"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "--format", "csv"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if out != wantBody {
		t.Errorf("body mismatch: got %q want %q", out, wantBody)
	}
}

func TestReconScanStartMissingProfile(t *testing.T) {
	t.Setenv("USULNET_API_URL", "http://127.0.0.1:1") // never reached
	_, err := runRoot(t, []string{"recon", "scan", "start", "11111111-1111-1111-1111-111111111111"})
	if err == nil {
		t.Fatal("expected usage error, got nil")
	}
	code, ok := metaExitCode(err)
	if !ok || code != exitUsage {
		t.Errorf("expected exitUsage (%d), got %d (ok=%v)", exitUsage, code, ok)
	}
}

func TestReconNoServerConfigured(t *testing.T) {
	t.Setenv("USULNET_API_URL", "")
	t.Setenv("USULNET_API_TOKEN", "")
	_, err := runRoot(t, []string{"recon", "target", "list"})
	if err == nil {
		t.Fatal("expected infra error, got nil")
	}
	code, ok := metaExitCode(err)
	if !ok || code != exitServerUnreach {
		t.Errorf("expected exitServerUnreach (%d), got %d (ok=%v)", exitServerUnreach, code, ok)
	}
}

func TestReconFindingsListFilterRoundTrip(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/recon/scans":
			if r.URL.Query().Get("target_id") != "t1" {
				http.Error(w, "missing target_id filter", http.StatusBadRequest)
				return
			}
			_, _ = io.WriteString(w, `[{"id":"sc1","target_id":"t1","profile_id":"p","status":"completed","created_at":"2026-01-01T00:00:00Z"}]`)
		case strings.HasSuffix(r.URL.Path, "/findings"):
			if r.URL.Query().Get("severity") != "high" {
				http.Error(w, "missing severity filter", http.StatusBadRequest)
				return
			}
			_, _ = io.WriteString(w, `[{"id":"f1","scan_id":"sc1","target_id":"t1","module":"dns","severity":"high","value":"open port 22"}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("USULNET_API_URL", srv.URL)

	out, err := runRoot(t, []string{"recon", "findings", "list",
		"--target", "t1", "--severity", "high", "--output", "json"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if calls < 2 {
		t.Errorf("expected at least 2 API calls (scans + findings), got %d", calls)
	}
	if !strings.Contains(out, "open port 22") {
		t.Errorf("output missing finding value: %q", out)
	}
}

// =============================================================================
// Helpers
// =============================================================================

// runRoot invokes the global rootCmd with the supplied args and returns its
// stdout. Tests that need to assert error behavior should ignore the bool
// and inspect the returned error.
func runRoot(t *testing.T, args []string) (string, error) {
	t.Helper()
	buf := &bytes.Buffer{}
	resetReconFlags()
	resetMetaFlags()
	resetCobraFlags(rootCmd)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(args)
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
		resetReconFlags()
		resetMetaFlags()
		resetCobraFlags(rootCmd)
	})
	err := rootCmd.Execute()
	return buf.String(), err
}

// resetCobraFlags walks the command tree and resets every flag to its
// declared default. Cobra retains parsed values across Execute() calls
// (including the "--help" bool), so without this reset later tests would
// see stale state — for example, after a `--help` snapshot test the help
// flag would still fire on the next functional test.
func resetCobraFlags(c *cobra.Command) {
	visit := func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	}
	c.Flags().VisitAll(visit)
	c.PersistentFlags().VisitAll(visit)
	for _, sub := range c.Commands() {
		resetCobraFlags(sub)
	}
}

func resetReconFlags() {
	reconAPIURL = ""
	reconAPIToken = ""
	scanStartProfile = ""
	scanStartWatch = false
	scanReportFormat = "json"
	findingsTarget = ""
	findingsSeverity = ""
	outputFormat = "table"
}
