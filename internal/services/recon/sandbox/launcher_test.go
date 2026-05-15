// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// ---------------------------------------------------------------------------
// Test double
// ---------------------------------------------------------------------------

type fakeDocker struct {
	mu sync.Mutex

	// programmed behavior
	createErr  error
	startErr   error
	killErr    error
	removeErr  error
	listResult []docker.Container
	listErr    error
	netGetErr  error
	netGetResp *docker.Network
	netCreate  *docker.Network
	netCreErr  error
	logsBody   string
	logsErr    error
	waitCode   int64
	waitErr    error
	waitDelay  time.Duration

	// CopyFileStream
	copyBody []byte
	copyErr  error

	// captured calls
	created   []docker.ContainerCreateOptions
	started   []string
	killed    []string
	removed   []string
	waited    []string
	copyCalls []string
	netCalls  int
	netGetCnt int
}

func (f *fakeDocker) ContainerCreate(ctx context.Context, opts docker.ContainerCreateOptions) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return "", f.createErr
	}
	f.created = append(f.created, opts)
	return "container-id", nil
}

func (f *fakeDocker) ContainerStart(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = append(f.started, id)
	return f.startErr
}

func (f *fakeDocker) ContainerKill(ctx context.Context, id, sig string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.killed = append(f.killed, id+":"+sig)
	return f.killErr
}

func (f *fakeDocker) ContainerRemove(ctx context.Context, id string, force, vols bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, id)
	return f.removeErr
}

func (f *fakeDocker) ContainerWait(ctx context.Context, id string) (int64, error) {
	f.mu.Lock()
	f.waited = append(f.waited, id)
	delay := f.waitDelay
	code := f.waitCode
	err := f.waitErr
	f.mu.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return -1, ctx.Err()
		}
	}
	return code, err
}

func (f *fakeDocker) ContainerLogs(ctx context.Context, id string, opts docker.LogOptions) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.logsErr != nil {
		return nil, f.logsErr
	}
	return io.NopCloser(strings.NewReader(f.logsBody)), nil
}

func (f *fakeDocker) ContainerList(ctx context.Context, opts docker.ContainerListOptions) ([]docker.Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listResult, f.listErr
}

func (f *fakeDocker) ContainerCopyFileStream(ctx context.Context, id, srcPath string) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.copyCalls = append(f.copyCalls, id+":"+srcPath)
	if f.copyErr != nil {
		return nil, f.copyErr
	}
	if f.copyBody == nil {
		return io.NopCloser(bytes.NewReader(nil)), nil
	}
	return io.NopCloser(bytes.NewReader(f.copyBody)), nil
}

func (f *fakeDocker) NetworkCreate(ctx context.Context, opts docker.NetworkCreateOptions) (*docker.Network, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.netCalls++
	if f.netCreErr != nil {
		return nil, f.netCreErr
	}
	if f.netCreate == nil {
		return &docker.Network{ID: "net-id", Name: opts.Name}, nil
	}
	return f.netCreate, nil
}

func (f *fakeDocker) NetworkGetByName(ctx context.Context, name string) (*docker.Network, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.netGetCnt++
	if f.netGetErr != nil {
		return nil, f.netGetErr
	}
	return f.netGetResp, nil
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestNewLauncher_NilClient(t *testing.T) {
	_, err := NewLauncher(nil, Config{}, nil)
	if !errors.Is(err, ErrNilClient) {
		t.Fatalf("err = %v, want ErrNilClient", err)
	}
}

func TestNewLauncher_NilLoggerOK(t *testing.T) {
	l, err := newLauncher(&fakeDocker{}, Config{}, nil)
	if err != nil {
		t.Fatalf("newLauncher: %v", err)
	}
	if l.log == nil {
		t.Fatal("expected non-nil logger after defaulting")
	}
}

func TestConfig_Defaults(t *testing.T) {
	l, err := newLauncher(&fakeDocker{}, Config{}, logger.Nop())
	if err != nil {
		t.Fatalf("newLauncher: %v", err)
	}
	if l.cfg.NetworkName != DefaultNetworkName {
		t.Errorf("NetworkName = %q, want %q", l.cfg.NetworkName, DefaultNetworkName)
	}
	if l.cfg.NetworkSubnet != DefaultNetworkSubnet {
		t.Errorf("NetworkSubnet = %q", l.cfg.NetworkSubnet)
	}
	if l.cfg.MaxOutputBytes != DefaultMaxOutputBytes {
		t.Errorf("MaxOutputBytes = %d", l.cfg.MaxOutputBytes)
	}
	if l.cfg.DefaultTimeout != DefaultTimeout {
		t.Errorf("DefaultTimeout = %s", l.cfg.DefaultTimeout)
	}
	if l.cfg.StopGrace != DefaultStopGrace {
		t.Errorf("StopGrace = %s", l.cfg.StopGrace)
	}
}

// ---------------------------------------------------------------------------
// hardenSpec
// ---------------------------------------------------------------------------

func TestHardenSpec_SetsEveryRequiredFlag(t *testing.T) {
	spec := recon.ContainerSpec{
		Image:   "ghcr.io/example/toolkit:dev",
		Command: []string{"extract", "--path", "/tmp/x"},
		Env:     map[string]string{"FOO": "bar"},
		Mounts: []recon.ContainerMount{
			{Source: "/host/data", Target: "/data", ReadOnly: false},
		},
		Labels: map[string]string{"caller.id": "abc"},
	}

	got := hardenSpec(spec, "usulnet-recon")

	if got.User != SandboxUser {
		t.Errorf("User = %q, want %q", got.User, SandboxUser)
	}
	if !got.ReadonlyRootfs {
		t.Error("ReadonlyRootfs must be true")
	}
	if got.Privileged {
		t.Error("Privileged must be false")
	}
	if len(got.CapDrop) == 0 || got.CapDrop[0] != "ALL" {
		t.Errorf("CapDrop = %v, want [ALL]", got.CapDrop)
	}
	wantSec := map[string]bool{"no-new-privileges:true": true, "seccomp=default": true}
	for _, s := range got.SecurityOpt {
		delete(wantSec, s)
	}
	if len(wantSec) > 0 {
		t.Errorf("SecurityOpt missing required entries: %v (got %v)", wantSec, got.SecurityOpt)
	}
	if got.PidsLimit != DefaultPidsLimit {
		t.Errorf("PidsLimit = %d, want %d", got.PidsLimit, DefaultPidsLimit)
	}
	if got.Memory != DefaultMemoryBytes {
		t.Errorf("Memory = %d, want %d", got.Memory, DefaultMemoryBytes)
	}
	if got.MemorySwap != DefaultMemoryBytes {
		t.Errorf("MemorySwap = %d, want %d (swap disabled)", got.MemorySwap, DefaultMemoryBytes)
	}
	if got.NanoCPUs != DefaultNanoCPUs {
		t.Errorf("NanoCPUs = %d, want %d", got.NanoCPUs, DefaultNanoCPUs)
	}
	if v, ok := got.Tmpfs[DefaultTmpfsTarget]; !ok || v != DefaultTmpfsOptions {
		t.Errorf("Tmpfs[%q] = %q, want %q", DefaultTmpfsTarget, v, DefaultTmpfsOptions)
	}
	if got.NetworkMode != "usulnet-recon" {
		t.Errorf("NetworkMode = %q, want usulnet-recon", got.NetworkMode)
	}
	if got.AutoRemove {
		t.Error("AutoRemove must be false (RunOnce removes explicitly)")
	}
	if got.Labels[LabelModule] != LabelModuleValue {
		t.Errorf("module label missing: %v", got.Labels)
	}
	if got.Labels["caller.id"] != "abc" {
		t.Errorf("caller label not preserved")
	}
	// Bind format <host>:<target>:ro
	if len(got.Binds) != 1 || got.Binds[0] != "/host/data:/data:ro" {
		t.Errorf("Binds = %v, want [/host/data:/data:ro]", got.Binds)
	}
}

func TestHardenSpec_NoNetworkOverridesNetworkMode(t *testing.T) {
	spec := recon.ContainerSpec{Image: "x", NoNetwork: true}
	got := hardenSpec(spec, "usulnet-recon")
	if got.NetworkMode != "none" {
		t.Errorf("NetworkMode = %q, want none", got.NetworkMode)
	}
}

func TestHardenSpec_MountAlwaysReadOnly(t *testing.T) {
	spec := recon.ContainerSpec{
		Image:  "x",
		Mounts: []recon.ContainerMount{{Source: "/h", Target: "/c", ReadOnly: false}},
	}
	got := hardenSpec(spec, "n")
	if len(got.Binds) != 1 || !strings.HasSuffix(got.Binds[0], ":ro") {
		t.Errorf("mount not forced read-only: %v", got.Binds)
	}
}

// ---------------------------------------------------------------------------
// EnsureRunning
// ---------------------------------------------------------------------------

func TestEnsureRunning_ReusesExisting(t *testing.T) {
	fd := &fakeDocker{
		netGetResp: &docker.Network{ID: "net", Name: DefaultNetworkName},
		listResult: []docker.Container{{ID: "existing-id"}},
	}
	l := mustLauncher(t, fd)

	id, err := l.EnsureRunning(context.Background(), recon.ContainerSpec{Image: "x"})
	if err != nil {
		t.Fatalf("EnsureRunning: %v", err)
	}
	if id != "existing-id" {
		t.Errorf("id = %q, want existing-id", id)
	}
	if len(fd.created) != 0 {
		t.Error("did not expect ContainerCreate when match exists")
	}
}

func TestEnsureRunning_CreatesWhenAbsent(t *testing.T) {
	fd := &fakeDocker{
		netGetResp: &docker.Network{ID: "net", Name: DefaultNetworkName},
	}
	l := mustLauncher(t, fd)

	id, err := l.EnsureRunning(context.Background(), recon.ContainerSpec{Image: "x"})
	if err != nil {
		t.Fatalf("EnsureRunning: %v", err)
	}
	if id != "container-id" {
		t.Errorf("id = %q, want container-id", id)
	}
	if len(fd.created) != 1 {
		t.Fatalf("created count = %d, want 1", len(fd.created))
	}
	if len(fd.started) != 1 {
		t.Errorf("started count = %d, want 1", len(fd.started))
	}
	if fd.created[0].Labels[LabelSpecHash] == "" {
		t.Error("spec_hash label not set on container")
	}
}

func TestEnsureRunning_StartFailureCleansUp(t *testing.T) {
	fd := &fakeDocker{
		netGetResp: &docker.Network{ID: "net", Name: DefaultNetworkName},
		startErr:   errors.New("boom"),
	}
	l := mustLauncher(t, fd)

	_, err := l.EnsureRunning(context.Background(), recon.ContainerSpec{Image: "x"})
	if err == nil {
		t.Fatal("expected error")
	}
	if len(fd.removed) != 1 {
		t.Errorf("expected cleanup remove, got %v", fd.removed)
	}
}

// ---------------------------------------------------------------------------
// RunOnce
// ---------------------------------------------------------------------------

func TestRunOnce_HappyPath(t *testing.T) {
	fd := &fakeDocker{
		netGetResp: &docker.Network{ID: "net", Name: DefaultNetworkName},
		logsBody:   "hello world\n",
		waitCode:   0,
	}
	l := mustLauncher(t, fd)

	out, code, err := l.RunOnce(context.Background(), recon.ContainerSpec{Image: "x", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !bytes.Contains(out, []byte("hello world")) {
		t.Errorf("output = %q, want contains hello world", out)
	}
	if len(fd.removed) != 1 {
		t.Errorf("expected exactly one remove, got %v", fd.removed)
	}
}

func TestRunOnce_TimeoutTearsDown(t *testing.T) {
	fd := &fakeDocker{
		netGetResp: &docker.Network{ID: "net", Name: DefaultNetworkName},
		waitDelay:  2 * time.Second, // longer than spec timeout
		waitCode:   0,
	}
	l := mustLauncher(t, fd)

	ctx := context.Background()
	_, code, err := l.RunOnce(ctx, recon.ContainerSpec{Image: "x", Timeout: 50 * time.Millisecond})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want DeadlineExceeded", err)
	}
	if code != -1 {
		t.Errorf("code = %d on timeout, want -1", code)
	}
	// killAndRemove invokes Kill (SIGKILL) and Remove in addition to
	// the defer'd Remove from RunOnce.
	if len(fd.killed) == 0 {
		t.Error("expected SIGKILL during teardown")
	}
	if len(fd.removed) == 0 {
		t.Error("expected force-remove during teardown")
	}
}

func TestRunOnce_OutputCap(t *testing.T) {
	// 1.5 MiB of payload; cap to 1 MiB.
	payload := bytes.Repeat([]byte("a"), 1_500_000)
	fd := &fakeDocker{
		netGetResp: &docker.Network{ID: "net", Name: DefaultNetworkName},
		logsBody:   string(payload),
		waitCode:   0,
	}
	cfg := Config{MaxOutputBytes: 1_000_000}
	l, err := newLauncher(fd, cfg, logger.Nop())
	if err != nil {
		t.Fatalf("newLauncher: %v", err)
	}

	out, _, err := l.RunOnce(context.Background(), recon.ContainerSpec{Image: "x", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if int64(len(out)) <= 1_000_000 {
		t.Errorf("output length = %d, expected truncated marker", len(out))
	}
	if !bytes.Contains(out, []byte("[truncated]")) {
		t.Error("expected truncation marker in capped output")
	}
}

// ---------------------------------------------------------------------------
// Stop
// ---------------------------------------------------------------------------

func TestStop_SendsTermThenKill(t *testing.T) {
	fd := &fakeDocker{}
	l, err := newLauncher(fd, Config{StopGrace: 5 * time.Millisecond}, logger.Nop())
	if err != nil {
		t.Fatalf("newLauncher: %v", err)
	}

	if err := l.Stop(context.Background(), "abc"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if len(fd.killed) != 2 {
		t.Errorf("kill calls = %v, want [SIGTERM, SIGKILL]", fd.killed)
	}
	if fd.killed[0] != "abc:SIGTERM" || fd.killed[1] != "abc:SIGKILL" {
		t.Errorf("kill sequence = %v", fd.killed)
	}
	if len(fd.removed) != 1 {
		t.Errorf("removed = %v, want one entry", fd.removed)
	}
}

// ---------------------------------------------------------------------------
// specHash determinism
// ---------------------------------------------------------------------------

func TestSpecHash_Stable(t *testing.T) {
	s := recon.ContainerSpec{
		Image:   "img",
		Command: []string{"a", "b"},
		Env:     map[string]string{"X": "1", "Y": "2"},
		Labels:  map[string]string{"foo": "bar"},
	}
	a := specHash(s)
	b := specHash(s)
	if a != b {
		t.Errorf("hash not stable: %q vs %q", a, b)
	}

	s2 := s
	s2.Image = "other"
	if specHash(s2) == a {
		t.Error("hash should change with image")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func mustLauncher(t *testing.T, fd dockerAPI) *Launcher {
	t.Helper()
	l, err := newLauncher(fd, Config{}, logger.Nop())
	if err != nil {
		t.Fatalf("newLauncher: %v", err)
	}
	return l
}
