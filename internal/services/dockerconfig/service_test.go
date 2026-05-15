// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package dockerconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ----------------------------------------------------------------------------
// Test helpers
// ----------------------------------------------------------------------------

// newTestService spins up a Service backed by a freshly-created temp
// dir. Returns the service and the temp paths so a test can poke at
// the on-disk state directly.
func newTestService(t *testing.T) (*Service, string, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{
		ConfigPath:         filepath.Join(dir, "daemon.json"),
		SnapshotDir:        filepath.Join(dir, "snapshots"),
		ReloadTimeout:      200 * time.Millisecond,
		ReloadPollInterval: 20 * time.Millisecond,
		MaxSnapshots:       5,
	}
	return NewService(cfg, logger.Nop()), cfg.ConfigPath, cfg.SnapshotDir
}

// newServiceWithLogBuffer returns the service plus a buffer that
// captures every JSON log line. Credential-redaction tests assert
// against the full buffer contents.
func newServiceWithLogBuffer(t *testing.T) (*Service, *bytes.Buffer, string, string) {
	t.Helper()
	buf := &bytes.Buffer{}
	log, err := logger.NewWithOutput("debug", "json", buf)
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	dir := t.TempDir()
	cfg := Config{
		ConfigPath:         filepath.Join(dir, "daemon.json"),
		SnapshotDir:        filepath.Join(dir, "snapshots"),
		ReloadTimeout:      200 * time.Millisecond,
		ReloadPollInterval: 20 * time.Millisecond,
		MaxSnapshots:       5,
	}
	return NewService(cfg, log), buf, cfg.ConfigPath, cfg.SnapshotDir
}

// healthyChecker is a HealthChecker that always returns nil.
type healthyChecker struct{}

func (healthyChecker) Ping(_ context.Context) error { return nil }

// unhealthyChecker is a HealthChecker that always errors.
type unhealthyChecker struct{}

func (unhealthyChecker) Ping(_ context.Context) error { return errors.New("ping refused") }

// laggyChecker becomes healthy after `after` calls. Used to verify
// the poll loop tolerates a daemon that takes a few seconds to come
// back after SIGHUP.
type laggyChecker struct {
	mu    sync.Mutex
	after int
	calls int
}

func (l *laggyChecker) Ping(_ context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if l.calls >= l.after {
		return nil
	}
	return errors.New("not ready")
}

// ----------------------------------------------------------------------------
// Read / ReadRaw
// ----------------------------------------------------------------------------

func TestRead_MissingFileReturnsEmptyConfig(t *testing.T) {
	s, _, _ := newTestService(t)
	cfg, err := s.Read(context.Background())
	if err != nil {
		t.Fatalf("Read on missing file: unexpected error %v", err)
	}
	if cfg == nil {
		t.Fatal("Read returned nil cfg")
	}
}

func TestRead_ParsesValidConfig(t *testing.T) {
	s, path, _ := newTestService(t)
	body := []byte(`{"log-driver":"json-file","log-opts":{"max-size":"10m"}}`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := s.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if cfg.LogDriver == nil || *cfg.LogDriver != "json-file" {
		t.Errorf("log-driver: got %v", cfg.LogDriver)
	}
	if cfg.LogOpts["max-size"] != "10m" {
		t.Errorf("log-opts.max-size: got %v", cfg.LogOpts)
	}
}

func TestRead_MalformedJSONReturnsError(t *testing.T) {
	s, path, _ := newTestService(t)
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(context.Background()); err == nil {
		t.Fatal("expected error parsing malformed JSON")
	}
}

func TestReadRaw_PrettyPrints(t *testing.T) {
	s, path, _ := newTestService(t)
	if err := os.WriteFile(path, []byte(`{"log-driver":"local"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := s.ReadRaw(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "  \"log-driver\"") {
		t.Errorf("expected indented output, got %q", out)
	}
}

func TestReadRaw_MissingFileReturnsEmptyObject(t *testing.T) {
	s, _, _ := newTestService(t)
	out, err := s.ReadRaw(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "{}" {
		t.Errorf("expected {}, got %q", out)
	}
}

// ----------------------------------------------------------------------------
// Atomic write
// ----------------------------------------------------------------------------

func TestWriteAtomic_LeavesNoTempFileOnSuccess(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "daemon.json")
	if err := writeAtomic(dst, []byte(`{"log-driver":"local"}`)); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected 1 file, got %d: %v", len(entries), names)
	}
	if entries[0].Name() != "daemon.json" {
		t.Fatalf("unexpected leftover %q", entries[0].Name())
	}
}

func TestWriteAtomic_PreservesOriginalOnRenameFailure(t *testing.T) {
	// Force the rename to fail by making dst a directory rather than
	// a file. The atomic writer must surface the failure and not
	// touch the existing dst.
	dir := t.TempDir()
	dst := filepath.Join(dir, "daemon.json")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(dst, []byte(`{"x":1}`)); err == nil {
		t.Fatal("expected rename onto directory to fail")
	}
	// Original directory still present (untouched).
	st, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("dst missing after failed write: %v", err)
	}
	if !st.IsDir() {
		t.Fatal("dst should still be a directory")
	}
}

func TestWriteAtomic_NoStaleTempFilesAfterFailure(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "subdir-that-exists-as-file")
	// Create the parent path as a regular file so the writer's
	// MkdirAll on dst.Dir() succeeds, but the rename fails because
	// dst's parent is a file masquerading as a dir.
	if err := writeAtomic(dst, []byte(`{}`)); err != nil {
		t.Fatalf("first write should succeed: %v", err)
	}
	// Now attempt a write whose temp file should be cleaned up.
	bad := filepath.Join(dst, "child")
	if err := writeAtomic(bad, []byte(`{}`)); err == nil {
		t.Fatal("write under regular-file parent should fail")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Errorf("stale temp file left behind: %s", e.Name())
		}
	}
}

func TestWriteAtomic_ConcurrentWritersDoNotCorrupt(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "daemon.json")
	const n = 20

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			payload := []byte(fmt.Sprintf(`{"shutdown-timeout":%d}`, i))
			if err := writeAtomic(dst, payload); err != nil {
				t.Errorf("concurrent write %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	// Whatever writer won, the file must still parse as valid JSON
	// (no half-written bytes — atomicity guarantee).
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]int
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("file is not valid JSON after concurrent writes: %v\n%s", err, data)
	}

	// No stale temp files.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Errorf("stale temp file: %s", e.Name())
		}
	}
}

// ----------------------------------------------------------------------------
// Snapshot / list / restore
// ----------------------------------------------------------------------------

func TestSnapshot_RoundTrip(t *testing.T) {
	s, path, _ := newTestService(t)
	original := []byte(`{"log-driver":"local"}`)
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := s.snapshot("manual")
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("snapshot id empty")
	}
	got, err := s.readSnapshot(id)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Errorf("snapshot roundtrip mismatch:\n  got=%q\n  want=%q", got, original)
	}
}

func TestSnapshot_NoFileReturnsEmptyID(t *testing.T) {
	s, _, _ := newTestService(t)
	id, err := s.snapshot("first-time")
	if err != nil {
		t.Fatal(err)
	}
	if id != "" {
		t.Errorf("expected empty id, got %q", id)
	}
}

func TestSnapshotPath_RejectsTraversal(t *testing.T) {
	s, _, _ := newTestService(t)
	cases := []string{
		"../etc/passwd",
		"/abs/path",
		"name.with.dots",
		"with space",
		"name/sub",
	}
	for _, c := range cases {
		if _, err := s.snapshotPath(c); err == nil {
			t.Errorf("snapshotPath(%q) should reject", c)
		}
	}
}

func TestListSnapshots_NewestFirst(t *testing.T) {
	s, path, _ := newTestService(t)
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := s.snapshot(""); err != nil {
			t.Fatal(err)
		}
		// Force distinct mtimes; resolution on some FS is 1s.
		time.Sleep(20 * time.Millisecond)
	}
	snaps, err := s.ListSnapshots(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 3 {
		t.Fatalf("expected 3 snapshots, got %d", len(snaps))
	}
	for i := 1; i < len(snaps); i++ {
		if snaps[i-1].Timestamp.Before(snaps[i].Timestamp) {
			t.Errorf("snapshots not newest-first at %d", i)
		}
	}
}

func TestSnapshot_PrunesToMax(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		ConfigPath:   filepath.Join(dir, "daemon.json"),
		SnapshotDir:  filepath.Join(dir, "snapshots"),
		MaxSnapshots: 3,
	}
	s := NewService(cfg, logger.Nop())
	if err := os.WriteFile(cfg.ConfigPath, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		if _, err := s.snapshot(""); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	entries, _ := os.ReadDir(cfg.SnapshotDir)
	count := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), snapshotPrefix) {
			count++
		}
	}
	if count > cfg.MaxSnapshots {
		t.Errorf("expected at most %d snapshots, got %d", cfg.MaxSnapshots, count)
	}
}

// ----------------------------------------------------------------------------
// Apply: happy path + skipped reload
// ----------------------------------------------------------------------------

func TestApply_WritesAndReloads(t *testing.T) {
	s, path, _ := newTestService(t)
	s.SetHealthChecker(healthyChecker{})

	new := []byte(`{"log-driver":"local"}`)
	res, err := s.Apply(context.Background(), new, "test")
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// On hosts without a real dockerd, findDockerdPID will fail and
	// the apply path returns Skipped=true rather than Reloaded. Both
	// outcomes are valid for "the file was written safely".
	if !res.Reloaded && res.WarningMsg == "" {
		t.Errorf("expected Reloaded=true or a skip warning, got %+v", res)
	}

	// The file must have been written.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"log-driver"`) {
		t.Errorf("daemon.json was not written: %q", got)
	}
}

func TestApply_RejectsInvalidConfig(t *testing.T) {
	s, _, _ := newTestService(t)
	// Bogus log driver.
	bad := []byte(`{"log-driver":"not-a-driver"}`)
	if _, err := s.Apply(context.Background(), bad, "test"); err == nil {
		t.Fatal("Apply should reject invalid log-driver")
	}
}

func TestApply_RejectsMalformedJSON(t *testing.T) {
	s, _, _ := newTestService(t)
	if _, err := s.Apply(context.Background(), []byte("not json"), "test"); err == nil {
		t.Fatal("Apply should reject malformed JSON")
	}
}

func TestApply_NoDaemonHealthChecker_SkipsReload(t *testing.T) {
	s, _, _ := newTestService(t)
	// No SetHealthChecker call.
	res, err := s.Apply(context.Background(), []byte(`{"log-driver":"local"}`), "test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Reloaded {
		t.Error("expected Reloaded=false when no health checker is wired")
	}
	if res.WarningMsg == "" {
		t.Error("expected a warning message about skipped reload")
	}
}

// ----------------------------------------------------------------------------
// Apply: rollback path (the explicit scenario the spec calls for)
// ----------------------------------------------------------------------------

// TestApply_RollsBackWhenReloadFails wires an unhealthy checker so the
// reload path will time out, then asserts that the original daemon.json
// is restored from the snapshot.
//
// This test exercises the rollback path entirely without dockerd by
// replacing the PID resolver with a stub that returns a benign PID
// (the test's own PID). The kill(getpid, SIGHUP) call is harmless to
// the Go test process — Go's runtime ignores SIGHUP by default in
// test binaries — so the apply path proceeds into the poll loop where
// our unhealthyChecker drives the timeout.
func TestApply_RollsBackWhenReloadFails(t *testing.T) {
	s, path, _ := newTestService(t)
	s.SetHealthChecker(unhealthyChecker{})

	// Seed with a reload-mode field so the apply path actually
	// drives SIGHUP + verify + rollback (registry-mirrors is
	// reload-only). Using a restart-only field like log-driver
	// short-circuits before the reload step.
	original := []byte(`{"registry-mirrors":["https://mirror-a.example.com"]}`)
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}

	// Stub out the SIGHUP delivery so the test runner is not killed.
	// The poll loop still drives the verify-and-rollback path against
	// the unhealthyChecker.
	sighupForTest = func() error { return nil }
	t.Cleanup(func() { sighupForTest = nil })

	new := []byte(`{"registry-mirrors":["https://mirror-b.example.com"]}`)
	res, err := s.Apply(context.Background(), new, "test-rollback")
	if err == nil {
		t.Fatal("Apply should report rollback as an error")
	}
	if res == nil || !res.RolledBack {
		t.Fatalf("expected RolledBack=true, got %+v err=%v", res, err)
	}

	// File on disk must equal the original content (post round-trip
	// through json.MarshalIndent).
	got, _ := os.ReadFile(path)
	var gotMap, wantMap map[string]any
	_ = json.Unmarshal(got, &gotMap)
	_ = json.Unmarshal(original, &wantMap)
	if fmt.Sprintf("%v", gotMap) != fmt.Sprintf("%v", wantMap) {
		t.Errorf("rollback did not restore content:\n  got=%v\n  want=%v", gotMap, wantMap)
	}
}

// TestApply_PollLoopAcceptsLaggyDaemon ensures the apply path keeps
// polling within the timeout window if the daemon takes a few hundred
// milliseconds to come back up. This proves the rollback only fires on
// genuine timeout, not on a single transient ping failure.
func TestApply_PollLoopAcceptsLaggyDaemon(t *testing.T) {
	s, path, _ := newTestService(t)
	s.SetHealthChecker(&laggyChecker{after: 3})

	// registry-mirrors is reload-only so the apply path drives the
	// poll loop. log-driver would skip straight to "restart required".
	if err := os.WriteFile(path, []byte(`{"registry-mirrors":["https://m1.example.com"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	s.cfg.ReloadTimeout = 200 * time.Millisecond
	s.cfg.ReloadPollInterval = 30 * time.Millisecond

	sighupForTest = func() error { return nil }
	t.Cleanup(func() { sighupForTest = nil })

	res, err := s.Apply(context.Background(), []byte(`{"registry-mirrors":["https://m2.example.com"]}`), "lag")
	if err != nil {
		t.Fatalf("expected lag-tolerant apply to succeed, got %v (res=%+v)", err, res)
	}
	if !res.Reloaded {
		t.Errorf("expected Reloaded=true, got %+v", res)
	}
}

// ----------------------------------------------------------------------------
// Restore via Apply
// ----------------------------------------------------------------------------

func TestRestore_ReplaysSnapshot(t *testing.T) {
	s, path, _ := newTestService(t)
	s.SetHealthChecker(healthyChecker{})

	if err := os.WriteFile(path, []byte(`{"log-driver":"local"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := s.snapshot("seed")
	if err != nil {
		t.Fatal(err)
	}

	// Mutate the file to something else.
	if err := os.WriteFile(path, []byte(`{"debug":true}`), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Restore(context.Background(), id, "manual-rollback"); err != nil {
		// On hosts without dockerd, restore reports a skipped reload;
		// the file must still be restored.
		t.Logf("Restore returned: %v", err)
	}

	got, _ := os.ReadFile(path)
	if !strings.Contains(string(got), `"log-driver"`) {
		t.Errorf("Restore did not replay snapshot content; got %q", got)
	}
}

// ----------------------------------------------------------------------------
// Diff
// ----------------------------------------------------------------------------

func TestDiffFields_DetectsAdditionAndRemoval(t *testing.T) {
	driver := "local"
	a := &DaemonConfig{}
	b := &DaemonConfig{LogDriver: &driver}
	got := diffFields(a, b)
	if len(got) != 1 || got[0] != "log-driver" {
		t.Errorf("addition: %v", got)
	}

	got = diffFields(b, a)
	if len(got) != 1 || got[0] != "log-driver" {
		t.Errorf("removal: %v", got)
	}
}

func TestDiffFields_IgnoresEqual(t *testing.T) {
	driver := "local"
	a := &DaemonConfig{LogDriver: &driver}
	b := &DaemonConfig{LogDriver: &driver}
	if got := diffFields(a, b); len(got) != 0 {
		t.Errorf("expected no changes, got %v", got)
	}
}

// ----------------------------------------------------------------------------
// Validation
// ----------------------------------------------------------------------------

func TestValidate_HappyPath(t *testing.T) {
	driver := "json-file"
	mtu := 1500
	cfg := &DaemonConfig{LogDriver: &driver, MTU: &mtu}
	if errs := ValidateConfig(cfg); len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
}

func TestValidate_BadLogDriver(t *testing.T) {
	bad := "made-up"
	cfg := &DaemonConfig{LogDriver: &bad}
	if errs := ValidateConfig(cfg); len(errs) == 0 {
		t.Error("expected error for bad log driver")
	}
}

func TestValidate_BadMTU(t *testing.T) {
	low := 50
	cfg := &DaemonConfig{MTU: &low}
	if errs := ValidateConfig(cfg); len(errs) == 0 {
		t.Error("expected error for MTU < 68")
	}
}

func TestValidate_BadCIDR(t *testing.T) {
	bad := "not-a-cidr"
	cfg := &DaemonConfig{BIP: &bad}
	if errs := ValidateConfig(cfg); len(errs) == 0 {
		t.Error("expected error for bad bip CIDR")
	}
}

func TestValidate_RegistryMirrorWithCredentialsRejected(t *testing.T) {
	cfg := &DaemonConfig{RegistryMirrors: []string{"https://user:pass@mirror.example.com"}}
	errs := ValidateConfig(cfg)
	if len(errs) == 0 {
		t.Fatal("expected validation error for credential-bearing mirror")
	}
	// The error message itself must not contain the password.
	for _, e := range errs {
		if strings.Contains(e.Message, "pass") {
			t.Errorf("validation error leaked password: %q", e.Message)
		}
	}
}

// ----------------------------------------------------------------------------
// Credential redaction (the non-negotiable from the spec)
// ----------------------------------------------------------------------------

func TestCredentialRedaction_URLHelper(t *testing.T) {
	cases := map[string]string{
		"https://user:pass@mirror.example.com":    "https://***@mirror.example.com",
		"http://admin:secret@registry.io:5000/v2": "http://***@registry.io:5000/v2",
		"https://no-creds.example.com":            "https://no-creds.example.com",
		"not-a-url":                               "not-a-url",
	}
	for in, want := range cases {
		got := redactURL(in)
		if got != want {
			t.Errorf("redactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestApply_DoesNotLogRegistryMirrorPasswords is the assertion the
// spec calls for: registry mirror passwords MUST NOT appear in logs.
//
// We feed a daemon.json containing a mirror with embedded credentials,
// drive Apply to completion, and inspect every captured log message.
// Both the password string and the userinfo segment must be absent.
//
// Note: the validator rejects credential-bearing mirrors today, which
// is itself a redaction-by-rejection. We still assert no log line
// contains the password, because the apply path executes log calls
// before validation when computing the diff and audit summary.
func TestApply_DoesNotLogRegistryMirrorPasswords(t *testing.T) {
	s, buf, path, _ := newServiceWithLogBuffer(t)
	s.SetHealthChecker(healthyChecker{})

	// Seed an existing daemon.json with a credential-bearing mirror
	// so it shows up in the diff and any audit summary log line. The
	// validator will reject the new config, but the diff call sites
	// will still touch the value.
	if err := os.WriteFile(path, []byte(`{"registry-mirrors":["https://docker-user:s3cr3t-PASS@mirror.example.com"]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	new := []byte(`{"registry-mirrors":["https://other-user:another-PASS@mirror2.example.com"]}`)
	_, _ = s.Apply(context.Background(), new, "test")

	logs := buf.String()
	for _, leaked := range []string{"s3cr3t-PASS", "another-PASS", "docker-user:s3cr3t", "other-user:another"} {
		if strings.Contains(logs, leaked) {
			t.Errorf("log buffer leaked credential %q: %s", leaked, logs)
		}
	}
}

// TestFieldRedactor_Strings verifies the in-process helper redacts a
// single URL string.
func TestFieldRedactor_Strings(t *testing.T) {
	got := fieldRedactor("registry-mirrors", "https://u:p@m.example.com")
	want := "https://***@m.example.com"
	if got != want {
		t.Errorf("fieldRedactor: got %q, want %q", got, want)
	}
}

// TestFieldRedactor_Slices verifies the helper redacts every element
// of a string slice.
func TestFieldRedactor_Slices(t *testing.T) {
	in := []string{"https://u:p@a.example", "https://b.example", "not-url"}
	got, ok := fieldRedactor("registry-mirrors", in).([]string)
	if !ok {
		t.Fatalf("fieldRedactor did not return []string, got %T", fieldRedactor("registry-mirrors", in))
	}
	want := []string{"https://***@a.example", "https://b.example", "not-url"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("fieldRedactor slice: got %v, want %v", got, want)
	}
}

func TestFieldRedactor_NonRedactedKey(t *testing.T) {
	if got := fieldRedactor("log-driver", "json-file"); got != "json-file" {
		t.Errorf("non-redacted key should pass through, got %v", got)
	}
}

// ----------------------------------------------------------------------------
// JSON round-trip preserves unknown fields
// ----------------------------------------------------------------------------

func TestRoundTrip_PreservesUnknownFields(t *testing.T) {
	in := []byte(`{"log-driver":"local","custom-key":{"foo":"bar"}}`)
	cfg, err := parseConfig(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := marshalIndent(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "custom-key") {
		t.Errorf("unknown field dropped: %s", out)
	}
}

// ----------------------------------------------------------------------------
// Health-checker init guard
// ----------------------------------------------------------------------------

func TestNewService_DefaultsAreApplied(t *testing.T) {
	s := NewService(Config{}, nil)
	if s.cfg.ConfigPath == "" {
		t.Error("ConfigPath default not applied")
	}
	if s.cfg.SnapshotDir == "" {
		t.Error("SnapshotDir default not applied")
	}
	if s.cfg.ReloadTimeout != 60*time.Second {
		t.Errorf("ReloadTimeout default: got %v want 60s", s.cfg.ReloadTimeout)
	}
	if s.cfg.MaxSnapshots != 50 {
		t.Errorf("MaxSnapshots default: got %d want 50", s.cfg.MaxSnapshots)
	}
}

func TestApplyMode_DangerousFieldsForceRestart(t *testing.T) {
	if got := determineApplyMode([]string{"log-driver"}); got != ApplyRestart {
		t.Errorf("log-driver should require restart, got %q", got)
	}
	if got := determineApplyMode([]string{"registry-mirrors"}); got != ApplyReload {
		t.Errorf("registry-mirrors should be reloadable, got %q", got)
	}
	if got := determineApplyMode([]string{"registry-mirrors", "storage-driver"}); got != ApplyRestart {
		t.Errorf("mixed set should escalate to restart, got %q", got)
	}
}
