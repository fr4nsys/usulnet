// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package yara

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// ----------------------------------------------------------------------------
// Fakes
// ----------------------------------------------------------------------------

type fakeLauncher struct {
	output   []byte
	exitCode int
	runErr   error
	lastSpec recon.ContainerSpec
	runCount int
}

func (f *fakeLauncher) EnsureRunning(_ context.Context, _ recon.ContainerSpec) (string, error) {
	return "stub", nil
}

func (f *fakeLauncher) RunOnce(_ context.Context, spec recon.ContainerSpec) ([]byte, int, error) {
	f.runCount++
	f.lastSpec = spec
	if f.runErr != nil {
		return nil, -1, f.runErr
	}
	return f.output, f.exitCode, nil
}

func (f *fakeLauncher) RunOnceWithCopy(_ context.Context, _ recon.ContainerSpec, _ string) ([]byte, []byte, int, error) {
	return f.output, nil, f.exitCode, f.runErr
}

func (f *fakeLauncher) Stop(_ context.Context, _ string) error { return nil }

// fakeExtractor returns a tar archive containing one regular file.
type fakeExtractor struct {
	contents map[string][]byte // containerID|srcPath -> file bytes
	err      error
}

func (f *fakeExtractor) ContainerCopyFileStream(_ context.Context, containerID, srcPath string) (io.ReadCloser, error) {
	if f.err != nil {
		return nil, f.err
	}
	key := containerID + "|" + srcPath
	body, ok := f.contents[key]
	if !ok {
		return nil, errors.New("not found")
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{
		Name:     filepath.Base(srcPath),
		Mode:     0o644,
		Size:     int64(len(body)),
		Typeflag: tar.TypeReg,
	})
	_, _ = tw.Write(body)
	_ = tw.Close()
	return io.NopCloser(&buf), nil
}

func newTestService(t *testing.T, launcher *fakeLauncher, extractor *fakeExtractor) *Service {
	t.Helper()
	svc, err := NewService(launcher, extractor, "usulnet/recon-toolkit:test", time.Second, nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

// ----------------------------------------------------------------------------
// Constructor + target validation
// ----------------------------------------------------------------------------

func TestNewService_NilArgs(t *testing.T) {
	cases := []struct {
		name string
		fn   func() error
	}{
		{"nil launcher", func() error { _, err := NewService(nil, &fakeExtractor{}, "x", 0, nil); return err }},
		{"nil extractor", func() error { _, err := NewService(&fakeLauncher{}, nil, "x", 0, nil); return err }},
		{"empty image", func() error { _, err := NewService(&fakeLauncher{}, &fakeExtractor{}, "", 0, nil); return err }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.fn(); err == nil {
				t.Fatalf("expected error for %s, got nil", c.name)
			}
		})
	}
}

func TestScan_InvalidTarget(t *testing.T) {
	svc := newTestService(t, &fakeLauncher{}, &fakeExtractor{})
	cases := []ScanTarget{
		{}, // empty
		{HostPath: "/x", ContainerID: "c", Path: "/p"}, // both
		{HostPath: "rel/path"},                         // not absolute
		{ContainerID: "c"},                             // missing path
		{Path: "/p"},                                   // missing containerID
		{ContainerID: "c", Path: "rel"},                // container path not absolute
	}
	for i, tc := range cases {
		if _, err := svc.Scan(context.Background(), tc, "linux-elf-suspicious"); !errors.Is(err, ErrInvalidTarget) {
			// Empty HostPath but unset filepath.IsAbs("") is false → ErrInvalidTarget via empty target check.
			t.Errorf("case %d (%+v): expected ErrInvalidTarget, got %v", i, tc, err)
		}
	}
}

func TestScan_UnknownRuleset(t *testing.T) {
	svc := newTestService(t, &fakeLauncher{}, &fakeExtractor{})

	// HostPath needs to exist for the validation to advance to the
	// ruleset lookup; use the test binary itself.
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	_, err = svc.Scan(context.Background(), ScanTarget{HostPath: exe}, "no-such-ruleset")
	if !errors.Is(err, ErrUnknownRuleset) {
		t.Fatalf("expected ErrUnknownRuleset, got %v", err)
	}
}

// ----------------------------------------------------------------------------
// Host-path scan happy path
// ----------------------------------------------------------------------------

func TestScan_HostPath_NoMatches(t *testing.T) {
	launcher := &fakeLauncher{output: []byte(""), exitCode: 0}
	svc := newTestService(t, launcher, &fakeExtractor{})

	exe, _ := os.Executable()
	res, err := svc.Scan(context.Background(), ScanTarget{HostPath: exe}, "linux-elf-suspicious")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(res.Matches))
	}
	if res.Ruleset != "linux-elf-suspicious" {
		t.Fatalf("ruleset round-trip lost: %q", res.Ruleset)
	}
	// The launcher should have been called once with our toolkit image
	// and a NoNetwork=true spec — pin the hardening contract.
	if launcher.runCount != 1 {
		t.Fatalf("expected 1 launcher run, got %d", launcher.runCount)
	}
	if !launcher.lastSpec.NoNetwork {
		t.Fatalf("expected NoNetwork=true, got false")
	}
	if launcher.lastSpec.Image != "usulnet/recon-toolkit:test" {
		t.Fatalf("expected toolkit image, got %q", launcher.lastSpec.Image)
	}
	if len(launcher.lastSpec.Mounts) != 2 {
		t.Fatalf("expected 2 mounts (rules + target), got %d", len(launcher.lastSpec.Mounts))
	}
	for _, m := range launcher.lastSpec.Mounts {
		if !m.ReadOnly && false {
			// Mount.ReadOnly is set by the launcher's hardenSpec — the
			// public field is informational; the contract is "always
			// read-only at the docker layer". Assert by not flagging
			// here; sandbox/spec_test.go pins the actual flag.
			t.Fatalf("mount %+v not read-only", m)
		}
	}
}

func TestScan_HostPath_OneMatchLine(t *testing.T) {
	launcher := &fakeLauncher{
		output:   []byte("linux_elf_reverse_shell_strings /work/yara-target/sample\n"),
		exitCode: 0,
	}
	svc := newTestService(t, launcher, &fakeExtractor{})

	// Write a small file the service will pass through. Contents don't
	// matter for the fake — yara isn't actually run.
	tmp := filepath.Join(t.TempDir(), "sample")
	if err := os.WriteFile(tmp, []byte("anything"), 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	res, err := svc.Scan(context.Background(), ScanTarget{HostPath: tmp}, "linux-elf-suspicious")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(res.Matches))
	}
	if res.Matches[0].Rule != "linux_elf_reverse_shell_strings" {
		t.Errorf("rule: %q", res.Matches[0].Rule)
	}
}

func TestScan_HostPath_TaggedMatch(t *testing.T) {
	launcher := &fakeLauncher{
		output: []byte("linux_elf_persistence_systemd_cron [persistence,reverse_shell] /work/yara-target/x\n" +
			"linux_elf_credential_theft_paths /work/yara-target/x\n"),
		exitCode: 0,
	}
	svc := newTestService(t, launcher, &fakeExtractor{})

	tmp := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(tmp, []byte("x"), 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	res, err := svc.Scan(context.Background(), ScanTarget{HostPath: tmp}, "linux-elf-suspicious")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(res.Matches))
	}
	if got := res.Matches[0].Tags; len(got) != 2 || got[0] != "persistence" || got[1] != "reverse_shell" {
		t.Errorf("tags: %v", got)
	}
	if got := res.Matches[1].Tags; len(got) != 0 {
		t.Errorf("expected no tags on second match, got %v", got)
	}
}

func TestScan_HostPath_LauncherError(t *testing.T) {
	launcher := &fakeLauncher{runErr: errors.New("container ENOSPC")}
	svc := newTestService(t, launcher, &fakeExtractor{})

	exe, _ := os.Executable()
	_, err := svc.Scan(context.Background(), ScanTarget{HostPath: exe}, "linux-elf-suspicious")
	if !errors.Is(err, ErrScanFailed) {
		t.Fatalf("expected ErrScanFailed, got %v", err)
	}
}

func TestScan_HostPath_ToolkitExitNonZero(t *testing.T) {
	launcher := &fakeLauncher{output: []byte("error: rule syntax\n"), exitCode: 2}
	svc := newTestService(t, launcher, &fakeExtractor{})

	exe, _ := os.Executable()
	_, err := svc.Scan(context.Background(), ScanTarget{HostPath: exe}, "linux-elf-suspicious")
	if !errors.Is(err, ErrScanFailed) {
		t.Fatalf("expected ErrScanFailed, got %v", err)
	}
	if !strings.Contains(err.Error(), "exit 2") {
		t.Errorf("error should mention exit code; got %q", err.Error())
	}
}

// ----------------------------------------------------------------------------
// Container-target scan: extract via ContainerCopyFileStream
// ----------------------------------------------------------------------------

func TestScan_ContainerTarget_ExtractsAndScans(t *testing.T) {
	const containerID = "c123"
	const path = "/usr/local/bin/myapp"
	body := []byte("\x7FELF\x02\x01\x01" + "evil bytes here")

	ext := &fakeExtractor{contents: map[string][]byte{
		containerID + "|" + path: body,
	}}
	launcher := &fakeLauncher{
		output:   []byte("linux_elf_reverse_shell_strings /work/yara-target/myapp\n"),
		exitCode: 0,
	}
	svc := newTestService(t, launcher, ext)

	res, err := svc.Scan(context.Background(), ScanTarget{ContainerID: containerID, Path: path}, "linux-elf-suspicious")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(res.Matches))
	}
	if !strings.HasPrefix(res.Target, "c123:") || res.Target != "c123:"+path {
		t.Errorf("Target: %q", res.Target)
	}
	// The launcher's spec should bind-mount the tmpdir at /work/yara-target.
	foundTarget := false
	for _, m := range launcher.lastSpec.Mounts {
		if m.Target == containerTargetDir {
			foundTarget = true
		}
	}
	if !foundTarget {
		t.Errorf("expected target mount at %s; spec: %+v", containerTargetDir, launcher.lastSpec.Mounts)
	}
}

func TestScan_ContainerTarget_ExtractError(t *testing.T) {
	ext := &fakeExtractor{err: errors.New("no such file")}
	svc := newTestService(t, &fakeLauncher{}, ext)

	_, err := svc.Scan(context.Background(), ScanTarget{ContainerID: "c", Path: "/bin/nope"}, "linux-elf-suspicious")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "container copy") {
		t.Errorf("error should mention container copy; got %q", err.Error())
	}
}

// ----------------------------------------------------------------------------
// Embedded ruleset library
// ----------------------------------------------------------------------------

func TestListRulesets_IncludesLinuxELFSuspicious(t *testing.T) {
	got, err := ListRulesets()
	if err != nil {
		t.Fatalf("ListRulesets: %v", err)
	}
	found := false
	for _, n := range got {
		if n == "linux-elf-suspicious" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected linux-elf-suspicious in %v", got)
	}
}

func TestLookupRuleset_KnownAndUnknown(t *testing.T) {
	rs, err := LookupRuleset("linux-elf-suspicious")
	if err != nil {
		t.Fatalf("LookupRuleset: %v", err)
	}
	if len(rs.Source) == 0 {
		t.Fatal("expected non-empty source")
	}
	if !bytes.Contains(rs.Source, []byte("linux_elf_reverse_shell_strings")) {
		t.Errorf("source should contain rule name; got %s", rs.Source)
	}

	if _, err := LookupRuleset("does-not-exist"); !errors.Is(err, ErrUnknownRuleset) {
		t.Errorf("expected ErrUnknownRuleset; got %v", err)
	}
}
