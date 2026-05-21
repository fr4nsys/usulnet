// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet
package forensics

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	dockersvc "github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// fakeDocker is a deterministic DockerClient for tests. Every probe
// invocation receives a recorded reply keyed by the command string.
type fakeDocker struct {
	byCmd     map[string]*dockersvc.ExecResult
	errByCmd  map[string]error
	callCount int
}

func newFakeDocker() *fakeDocker {
	return &fakeDocker{
		byCmd:    map[string]*dockersvc.ExecResult{},
		errByCmd: map[string]error{},
	}
}

func (f *fakeDocker) ContainerExec(_ context.Context, _ string, cmd []string, _ dockersvc.ExecOptions) (*dockersvc.ExecResult, error) {
	f.callCount++
	key := strings.Join(cmd, " ")
	if err, ok := f.errByCmd[key]; ok {
		return nil, err
	}
	if res, ok := f.byCmd[key]; ok {
		return res, nil
	}
	return &dockersvc.ExecResult{ExitCode: 0, Stdout: "", Stderr: ""}, nil
}

func testLogger(t *testing.T) *logger.Logger {
	t.Helper()
	l, err := logger.New("error", "json")
	if err != nil {
		t.Fatalf("logger.New: %v", err)
	}
	return l
}

func TestSnapshot_EmptyContainerIDIsAnError(t *testing.T) {
	svc := NewService(newFakeDocker(), testLogger(t))
	_, err := svc.Snapshot(context.Background(), "")
	if !errors.Is(err, ErrContainerRequired) {
		t.Errorf("want ErrContainerRequired, got %v", err)
	}
}

func TestSnapshot_RunsEveryProbe(t *testing.T) {
	fake := newFakeDocker()
	svc := NewService(fake, testLogger(t))

	if _, err := svc.Snapshot(context.Background(), "abc123"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if got, want := fake.callCount, len(defaultProbes); got != want {
		t.Errorf("called Docker %d times; want one per probe (%d)", got, want)
	}
}

func TestSnapshot_TarballContainsManifestAndEveryProbeFile(t *testing.T) {
	svc := NewService(newFakeDocker(), testLogger(t))
	body, err := svc.Snapshot(context.Background(), "abc123")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	files := readTarEntries(t, body)
	if _, ok := files["abc123/MANIFEST.txt"]; !ok {
		t.Error("tarball must contain MANIFEST.txt at the container-id root")
	}
	for _, probe := range defaultProbes {
		key := "abc123/" + probe.Name
		if _, ok := files[key]; !ok {
			t.Errorf("tarball missing probe output %q", key)
		}
	}
}

func TestSnapshot_RecordsExecFailuresInBand(t *testing.T) {
	fake := newFakeDocker()
	// Make ps fail; the snapshot should still complete, with the
	// failure visible in the probe's own file.
	psKey := strings.Join(defaultProbes[0].Cmd, " ")
	fake.errByCmd[psKey] = errors.New("container not running")

	svc := NewService(fake, testLogger(t))
	body, err := svc.Snapshot(context.Background(), "abc123")
	if err != nil {
		t.Fatalf("Snapshot must NOT propagate per-probe failures, got %v", err)
	}

	files := readTarEntries(t, body)
	got := string(files["abc123/"+defaultProbes[0].Name])
	if !strings.Contains(got, "ERROR: container not running") {
		t.Errorf("expected ERROR line in failing probe, got %q", got)
	}
}

func TestSnapshot_TruncatesOversizedOutput(t *testing.T) {
	fake := newFakeDocker()
	// Pick the lsof probe (1 MiB cap) and stuff it with 2 MiB of
	// output to ensure the truncation marker fires.
	lsofKey := strings.Join(defaultProbes[2].Cmd, " ")
	fake.byCmd[lsofKey] = &dockersvc.ExecResult{
		ExitCode: 0,
		Stdout:   strings.Repeat("x", 2*1024*1024),
	}

	svc := NewService(fake, testLogger(t))
	body, err := svc.Snapshot(context.Background(), "abc123")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	files := readTarEntries(t, body)
	got := string(files["abc123/"+defaultProbes[2].Name])
	if len(got) > 1024*1024+128 {
		t.Errorf("output not truncated; got %d bytes", len(got))
	}
	if !strings.Contains(got, "TRUNCATED") {
		t.Error("truncation marker not present in oversized probe output")
	}
}

func TestSnapshot_ManifestNamesEveryProbe(t *testing.T) {
	svc := NewService(newFakeDocker(), testLogger(t))
	body, err := svc.Snapshot(context.Background(), "abc123")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	files := readTarEntries(t, body)
	manifest := string(files["abc123/MANIFEST.txt"])
	for _, probe := range defaultProbes {
		if !strings.Contains(manifest, probe.Name) {
			t.Errorf("MANIFEST.txt missing entry for probe %q", probe.Name)
		}
	}
	if !strings.Contains(manifest, "container_id: abc123") {
		t.Error("MANIFEST.txt must record the container ID")
	}
}

func readTarEntries(t *testing.T, body []byte) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(body))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}
		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, tr); err != nil {
			t.Fatalf("tar copy %s: %v", hdr.Name, err)
		}
		out[hdr.Name] = buf.Bytes()
	}
	return out
}

// ---------------------------------------------------------------------------
// v26.5.2 — YARA probe integration
// ---------------------------------------------------------------------------

type stubYARA struct {
	report      string
	lastID      string
	lastPath    string
	lastRuleset string
	calls       int
}

func (s *stubYARA) ScanContainerPath(_ context.Context, containerID, path, ruleset string) string {
	s.calls++
	s.lastID = containerID
	s.lastPath = path
	s.lastRuleset = ruleset
	return s.report
}

func TestSnapshot_DefaultDoesNotInvokeYARA(t *testing.T) {
	// With ProbeOptions{} (zero value) the YARA probe must not run,
	// even if a runner is registered — the default contract is
	// "byte-identical to v26.5.1 forensics output".
	docker := newFakeDocker()
	yara := &stubYARA{report: "matched"}
	svc := NewService(docker, testLogger(t)).WithYARAScanner(yara)

	out, err := svc.Snapshot(context.Background(), "abc123")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if yara.calls != 0 {
		t.Errorf("expected 0 YARA calls in default Snapshot; got %d", yara.calls)
	}
	files := readTarEntries(t, out)
	if _, has := files["abc123/yara-elf-scan.txt"]; has {
		t.Errorf("default snapshot must not contain yara-elf-scan.txt")
	}
}

func TestSnapshotWithOptions_YARAEnabled_AddsTarEntry(t *testing.T) {
	docker := newFakeDocker()
	yara := &stubYARA{report: "linux_elf_reverse_shell_strings /proc/1/exe\n--- linux-elf-suspicious matched 1 rule ---\n"}
	svc := NewService(docker, testLogger(t)).WithYARAScanner(yara)

	out, err := svc.SnapshotWithOptions(context.Background(), "abc123", ProbeOptions{YARAELFScan: true})
	if err != nil {
		t.Fatalf("SnapshotWithOptions: %v", err)
	}
	if yara.calls != 1 {
		t.Fatalf("expected 1 YARA call; got %d", yara.calls)
	}
	if yara.lastID != "abc123" || yara.lastRuleset != DefaultYARARuleset || yara.lastPath != DefaultYARAPath {
		t.Errorf("YARA invocation args wrong: id=%q ruleset=%q path=%q", yara.lastID, yara.lastRuleset, yara.lastPath)
	}
	files := readTarEntries(t, out)
	body, ok := files["abc123/yara-elf-scan.txt"]
	if !ok {
		t.Fatalf("missing yara-elf-scan.txt; have %v", keysOf(files))
	}
	if !bytes.Contains(body, []byte("linux_elf_reverse_shell_strings")) {
		t.Errorf("yara report missing match; got %s", body)
	}
}

func TestSnapshotWithOptions_YARAEnabled_NoRunner_NoPanic(t *testing.T) {
	// YARAELFScan=true but no runner registered → probe is silently
	// skipped, the tar still produces correctly.
	docker := newFakeDocker()
	svc := NewService(docker, testLogger(t))

	out, err := svc.SnapshotWithOptions(context.Background(), "abc123", ProbeOptions{YARAELFScan: true})
	if err != nil {
		t.Fatalf("SnapshotWithOptions: %v", err)
	}
	files := readTarEntries(t, out)
	if _, has := files["abc123/yara-elf-scan.txt"]; has {
		t.Errorf("expected no yara-elf-scan.txt when runner is nil")
	}
}

func TestSnapshotWithOptions_YARA_CustomPathAndRuleset(t *testing.T) {
	docker := newFakeDocker()
	yara := &stubYARA{report: "no-matches\n"}
	svc := NewService(docker, testLogger(t)).WithYARAScanner(yara)

	_, err := svc.SnapshotWithOptions(context.Background(), "abc123", ProbeOptions{
		YARAELFScan: true,
		YARARuleset: "custom-pack",
		YARAPath:    "/var/lib/myapp",
	})
	if err != nil {
		t.Fatalf("SnapshotWithOptions: %v", err)
	}
	if yara.lastRuleset != "custom-pack" {
		t.Errorf("ruleset override lost: %q", yara.lastRuleset)
	}
	if yara.lastPath != "/var/lib/myapp" {
		t.Errorf("path override lost: %q", yara.lastPath)
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
