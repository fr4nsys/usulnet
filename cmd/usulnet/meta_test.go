// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Help-text snapshot tests live in recon_test.go (one TestHelpSnapshots
// table covers both subcommand trees). The tests below exercise the
// remaining meta-specific behavior: server-mode HTTP round-trip, scan
// path collection, MIME guessing, and error mapping.

// =============================================================================
// Server mode round-trip
// =============================================================================

func TestMetaExtractServerRoundTrip(t *testing.T) {
	var gotContentType, gotMethod, gotPath string
	var gotMode string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			http.Error(w, "bad multipart: "+err.Error(), http.StatusBadRequest)
			return
		}
		gotMode = r.FormValue("mode")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"job-1","status":"queued","artifact_count":1,"mode":"extract"}`))
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	sample := filepath.Join(tmpDir, "image.jpg")
	if err := os.WriteFile(sample, []byte("fake-jpeg-bytes"), 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	t.Setenv("USULNET_API_URL", srv.URL)
	t.Setenv("USULNET_API_TOKEN", "tkn")

	out, err := runRoot(t, []string{"meta", "extract", sample, "--output", "json"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/v1/metadata/jobs" {
		t.Errorf("wrong request: %s %s", gotMethod, gotPath)
	}
	if !strings.HasPrefix(gotContentType, "multipart/form-data") {
		t.Errorf("wrong content type: %q", gotContentType)
	}
	if gotMode != "extract" {
		t.Errorf("wrong mode: %q", gotMode)
	}
	if !strings.Contains(out, "job-1") {
		t.Errorf("missing job id in output: %q", out)
	}
}

func TestMetaStripServerRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	in := filepath.Join(tmpDir, "doc.pdf")
	if err := os.WriteFile(in, []byte("%PDF-1.4"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	out := filepath.Join(tmpDir, "cleaned.pdf")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{
			  "id":"job-2","status":"completed","mode":"strip","artifact_count":1,
			  "artifacts":[{"id":"art-1","filename":"doc.pdf"}]
			}`))
		case http.MethodGet:
			if !strings.Contains(r.URL.Path, "/artifacts/art-1/stripped") {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte("cleaned-bytes"))
		}
	}))
	defer srv.Close()

	t.Setenv("USULNET_API_URL", srv.URL)
	stdout, err := runRoot(t, []string{"meta", "strip", in, "-o", out})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("expected cleaned file at %s: %v", out, err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read cleaned: %v", err)
	}
	if string(got) != "cleaned-bytes" {
		t.Errorf("cleaned bytes mismatch: %q", got)
	}
	if !strings.Contains(stdout, "stripped:") {
		t.Errorf("stdout missing summary line: %q", stdout)
	}
}

// =============================================================================
// Local mode helpers — no Docker required
// =============================================================================

func TestCollectScanPathsNonRecursive(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "a.txt"), "a")
	mustWrite(t, filepath.Join(dir, "b.txt"), "b")
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	mustWrite(t, filepath.Join(sub, "c.txt"), "c")

	got, err := collectScanPaths(dir, false)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("want 2 files, got %d: %v", len(got), got)
	}
}

func TestCollectScanPathsRecursive(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "a.txt"), "a")
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	mustWrite(t, filepath.Join(sub, "b.txt"), "b")

	got, err := collectScanPaths(dir, true)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("want 2 files, got %d: %v", len(got), got)
	}
}

func TestDetectMIME(t *testing.T) {
	cases := map[string]string{
		"x.jpg":  "image/jpeg",
		"y.pdf":  "application/pdf",
		"z.heic": "image/heic",
		"":       "application/octet-stream",
	}
	for in, want := range cases {
		got := detectMIME(in)
		if got != want {
			t.Errorf("detectMIME(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMetaExitCodeMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"usage", &usageError{msg: "bad"}, exitUsage},
		{"infra", &infraError{msg: "x", code: exitServerUnreach}, exitServerUnreach},
		{"perfile", &perFileError{count: 3}, exitPerFileFailures},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, ok := metaExitCode(tc.err)
			if !ok {
				t.Fatalf("expected typed-error mapping, got ok=false")
			}
			if code != tc.want {
				t.Errorf("got %d, want %d", code, tc.want)
			}
		})
	}
}

// =============================================================================
// Integration test for `meta strip` local mode.
//
// The build-tag gate (`//go:build integration`) the original session brief
// asked for would have required a fifth file, contrary to the explicit
// four-file budget. The functional equivalent is a runtime skip on
// $USULNET_RECON_INTEGRATION; CI exercises this code path by setting that
// variable in the integration job.
// =============================================================================

func TestMetaStripLocalIntegration(t *testing.T) {
	if os.Getenv("USULNET_RECON_INTEGRATION") == "" {
		t.Skip("set USULNET_RECON_INTEGRATION=1 to run the recon-toolkit container integration test")
	}
	if testing.Short() {
		t.Skip("integration test")
	}

	fixture := filepath.Join("testdata", "sample.jpg")
	if _, err := os.Stat(fixture); err != nil {
		t.Skipf("fixture %s missing: %v", fixture, err)
	}
	tmp := t.TempDir()
	in := filepath.Join(tmp, "sample.jpg")
	srcBytes, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := os.WriteFile(in, srcBytes, 0o600); err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
	out := filepath.Join(tmp, "cleaned.jpg")

	// Local mode is selected when neither --server nor $USULNET_API_URL is set.
	t.Setenv("USULNET_API_URL", "")
	stdout, err := runRoot(t, []string{"meta", "strip", in, "-o", out})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("cleaned file missing at %s: %v", out, err)
	}
	if !strings.Contains(stdout, "stripped:") {
		t.Errorf("missing summary in stdout: %q", stdout)
	}
}

// TestMetaStripOutputFileFlag pins the rename of the strip destination flag.
// Before this PR the destination flag was --output, which shadowed the global
// --output table|json|yaml format flag. The destination is now --output-file
// (short -o); --output keeps its parent-tree meaning (output format).
func TestMetaStripOutputFileFlag(t *testing.T) {
	local := metaStripCmd.LocalFlags()
	if f := local.Lookup("output-file"); f == nil {
		t.Fatal("meta strip is missing --output-file flag")
	}
	// LocalFlags excludes inherited persistent flags, so a hit here would
	// mean strip redeclared --output and re-introduced the shadow.
	if f := local.Lookup("output"); f != nil {
		t.Errorf("meta strip should not declare its own --output flag (shadows the global format flag); got %v", f)
	}
	if f := local.ShorthandLookup("o"); f == nil || f.Name != "output-file" {
		t.Errorf("expected -o shorthand to map to --output-file, got %+v", f)
	}
	// The global format flag must still be present on the root and visible
	// in strip's effective flag set (i.e. inherited as a persistent flag).
	root := rootCmd.PersistentFlags().Lookup("output")
	if root == nil {
		t.Fatal("root --output (format) flag is missing")
	}
	if !strings.Contains(root.Usage, "table|json|yaml") {
		t.Errorf("global --output should still describe table|json|yaml; got %q", root.Usage)
	}
	// The effective set on strip should now also include the global --output,
	// which it previously hid by shadowing.
	if f := metaStripCmd.Flags().Lookup("output"); f == nil {
		t.Error("global --output (format) is not visible on meta strip — rename should have un-shadowed it")
	} else if !strings.Contains(f.Usage, "table|json|yaml") {
		t.Errorf("meta strip's --output is not the format flag; got %q", f.Usage)
	}
}

// Compile-time reference so a stray refactor that drops the context import
// from local-mode code surfaces here rather than at link time.
var _ = context.Background

func resetMetaFlags() {
	metaServerURL = ""
	metaServerTok = ""
	metaToolkitImg = ""
	metaTimeout = ""
	metaStripOutput = ""
	metaScanRecursive = false
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
