// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package host

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newStandaloneService() *Service {
	return NewStandaloneService(DefaultConfig(), logger.Nop())
}

func strPtr(s string) *string { return &s }

// ---------------------------------------------------------------------------
// Tests: DefaultConfig
// ---------------------------------------------------------------------------

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.HealthCheckInterval != 30*time.Second {
		t.Errorf("HealthCheckInterval = %v, want 30s", cfg.HealthCheckInterval)
	}
	if cfg.StaleThreshold != 2*time.Minute {
		t.Errorf("StaleThreshold = %v, want 2m", cfg.StaleThreshold)
	}
	if cfg.MetricsRetention != 7*24*time.Hour {
		t.Errorf("MetricsRetention = %v, want 168h", cfg.MetricsRetention)
	}
	if cfg.DefaultTimeout != 30*time.Second {
		t.Errorf("DefaultTimeout = %v, want 30s", cfg.DefaultTimeout)
	}
}

// ---------------------------------------------------------------------------
// Tests: Constructor
// ---------------------------------------------------------------------------

func TestNewStandaloneService(t *testing.T) {
	svc := newStandaloneService()

	if svc.repo != nil {
		t.Error("expected nil repo in standalone mode")
	}
	if svc.clientPool == nil {
		t.Error("expected non-nil clientPool")
	}
	if svc.proxyClients == nil {
		t.Error("expected non-nil proxyClients map")
	}
}

func TestNewService_NilLogger(t *testing.T) {
	svc := NewStandaloneService(DefaultConfig(), nil)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	// Should not panic — nil logger replaced with Nop
}

// ---------------------------------------------------------------------------
// Tests: GetStats (standalone / nil repo path)
// ---------------------------------------------------------------------------

func TestGetStats_StandaloneReturnsEmpty(t *testing.T) {
	svc := newStandaloneService()

	stats, err := svc.GetStats(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats == nil {
		t.Fatal("expected non-nil stats")
	}
}

// ---------------------------------------------------------------------------
// Tests: List (standalone / nil repo path)
// ---------------------------------------------------------------------------

func TestList_StandaloneReturnsEmpty(t *testing.T) {
	svc := newStandaloneService()

	hosts, total, err := svc.List(context.Background(), postgres.HostListOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 0 {
		t.Errorf("total = %d, want 0", total)
	}
	if len(hosts) != 0 {
		t.Errorf("hosts = %d, want 0", len(hosts))
	}
}

// ---------------------------------------------------------------------------
// Tests: GetOnlineHosts
// ---------------------------------------------------------------------------

func TestGetOnlineHosts_Empty(t *testing.T) {
	svc := newStandaloneService()

	hosts := svc.GetOnlineHosts()
	if len(hosts) != 0 {
		t.Errorf("expected empty hosts, got %d", len(hosts))
	}
}

// ---------------------------------------------------------------------------
// Tests: GetClientPool
// ---------------------------------------------------------------------------

func TestGetClientPool_NotNil(t *testing.T) {
	svc := newStandaloneService()
	pool := svc.GetClientPool()
	if pool == nil {
		t.Fatal("expected non-nil client pool")
	}
}

// ---------------------------------------------------------------------------
// Tests: IsOnline (empty pool)
// ---------------------------------------------------------------------------

func TestIsOnline_EmptyPool(t *testing.T) {
	svc := newStandaloneService()

	online := svc.IsOnline(context.Background(), uuid.New())
	if online {
		t.Error("expected false for nonexistent host")
	}
}

// ---------------------------------------------------------------------------
// Tests: Start/Stop lifecycle
// ---------------------------------------------------------------------------

func TestStartStop_StandaloneNoop(t *testing.T) {
	svc := newStandaloneService()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Start should not panic with nil repo
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("unexpected start error: %v", err)
	}

	// Stop should be idempotent
	svc.Stop()
	svc.Stop() // second stop should be safe
}

// ---------------------------------------------------------------------------
// Tests: dockerInfoToModel
// ---------------------------------------------------------------------------

func TestDockerInfoToModel_AllFields(t *testing.T) {
	info := &docker.DockerInfo{
		ID:                "abc123",
		Name:              "docker-host",
		ServerVersion:     "24.0.7",
		APIVersion:        "1.43",
		OS:                "Ubuntu 22.04.3 LTS",
		OSType:            "linux",
		Architecture:      "x86_64",
		KernelVersion:     "5.15.0-91-generic",
		Containers:        10,
		ContainersRunning: 5,
		ContainersPaused:  1,
		ContainersStopped: 4,
		Images:            25,
		MemTotal:          17179869184,
		NCPU:              8,
		DockerRootDir:     "/var/lib/docker",
		StorageDriver:     "overlay2",
		LoggingDriver:     "json-file",
		CgroupDriver:      "systemd",
		CgroupVersion:     "2",
		DefaultRuntime:    "runc",
		SecurityOptions:   []string{"apparmor", "seccomp"},
		Runtimes:          []string{"runc", "nvidia"},
		Swarm:             true,
	}

	result := dockerInfoToModel(info)

	if result.ID != "abc123" {
		t.Errorf("ID = %q, want %q", result.ID, "abc123")
	}
	if result.Name != "docker-host" {
		t.Errorf("Name = %q, want %q", result.Name, "docker-host")
	}
	if result.ServerVersion != "24.0.7" {
		t.Errorf("ServerVersion = %q, want %q", result.ServerVersion, "24.0.7")
	}
	if result.APIVersion != "1.43" {
		t.Errorf("APIVersion = %q, want %q", result.APIVersion, "1.43")
	}
	if result.OperatingSystem != "Ubuntu 22.04.3 LTS" {
		t.Errorf("OperatingSystem = %q, want %q", result.OperatingSystem, "Ubuntu 22.04.3 LTS")
	}
	if result.OSType != "linux" {
		t.Errorf("OSType = %q, want %q", result.OSType, "linux")
	}
	if result.Architecture != "x86_64" {
		t.Errorf("Architecture = %q, want %q", result.Architecture, "x86_64")
	}
	if result.KernelVersion != "5.15.0-91-generic" {
		t.Errorf("KernelVersion = %q, want %q", result.KernelVersion, "5.15.0-91-generic")
	}
	if result.Containers != 10 {
		t.Errorf("Containers = %d, want 10", result.Containers)
	}
	if result.ContainersRunning != 5 {
		t.Errorf("ContainersRunning = %d, want 5", result.ContainersRunning)
	}
	if result.ContainersPaused != 1 {
		t.Errorf("ContainersPaused = %d, want 1", result.ContainersPaused)
	}
	if result.ContainersStopped != 4 {
		t.Errorf("ContainersStopped = %d, want 4", result.ContainersStopped)
	}
	if result.Images != 25 {
		t.Errorf("Images = %d, want 25", result.Images)
	}
	if result.MemTotal != 17179869184 {
		t.Errorf("MemTotal = %d, want 17179869184", result.MemTotal)
	}
	if result.NCPU != 8 {
		t.Errorf("NCPU = %d, want 8", result.NCPU)
	}
	if result.DockerRootDir != "/var/lib/docker" {
		t.Errorf("DockerRootDir = %q, want %q", result.DockerRootDir, "/var/lib/docker")
	}
	if result.StorageDriver != "overlay2" {
		t.Errorf("StorageDriver = %q, want %q", result.StorageDriver, "overlay2")
	}
	if result.LoggingDriver != "json-file" {
		t.Errorf("LoggingDriver = %q, want %q", result.LoggingDriver, "json-file")
	}
	if result.CgroupDriver != "systemd" {
		t.Errorf("CgroupDriver = %q, want %q", result.CgroupDriver, "systemd")
	}
	if result.CgroupVersion != "2" {
		t.Errorf("CgroupVersion = %q, want %q", result.CgroupVersion, "2")
	}
	if result.DefaultRuntime != "runc" {
		t.Errorf("DefaultRuntime = %q, want %q", result.DefaultRuntime, "runc")
	}
	if len(result.SecurityOptions) != 2 || result.SecurityOptions[0] != "apparmor" {
		t.Errorf("SecurityOptions = %v, want [apparmor seccomp]", result.SecurityOptions)
	}
	if len(result.RuntimeNames) != 2 || result.RuntimeNames[0] != "runc" {
		t.Errorf("RuntimeNames = %v, want [runc nvidia]", result.RuntimeNames)
	}
	if !result.SwarmActive {
		t.Error("SwarmActive = false, want true")
	}
}

func TestDockerInfoToModel_EmptySlices(t *testing.T) {
	info := &docker.DockerInfo{
		ID:              "empty-host",
		SecurityOptions: nil,
		Runtimes:        nil,
	}

	result := dockerInfoToModel(info)

	if result.ID != "empty-host" {
		t.Errorf("ID = %q, want %q", result.ID, "empty-host")
	}
	if result.SecurityOptions != nil {
		t.Errorf("SecurityOptions = %v, want nil", result.SecurityOptions)
	}
	if result.RuntimeNames != nil {
		t.Errorf("RuntimeNames = %v, want nil", result.RuntimeNames)
	}
}

// ---------------------------------------------------------------------------
// Tests: buildClientOptions
// ---------------------------------------------------------------------------

func TestBuildClientOptions_Local(t *testing.T) {
	svc := newStandaloneService()
	host := &models.Host{
		EndpointType: models.EndpointLocal,
	}

	opts, err := svc.buildClientOptions(host)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Host == "" {
		t.Error("expected non-empty host URL for local endpoint")
	}
	if opts.Timeout != 30*time.Second {
		t.Errorf("timeout = %v, want 30s", opts.Timeout)
	}
}

func TestBuildClientOptions_Socket_Default(t *testing.T) {
	svc := newStandaloneService()
	host := &models.Host{
		EndpointType: models.EndpointSocket,
		EndpointURL:  nil,
	}

	opts, err := svc.buildClientOptions(host)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Host == "" {
		t.Error("expected default socket path when URL is nil")
	}
}

func TestBuildClientOptions_Socket_Custom(t *testing.T) {
	svc := newStandaloneService()
	host := &models.Host{
		EndpointType: models.EndpointSocket,
		EndpointURL:  strPtr("unix:///custom/docker.sock"),
	}

	opts, err := svc.buildClientOptions(host)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Host != "unix:///custom/docker.sock" {
		t.Errorf("host = %q, want %q", opts.Host, "unix:///custom/docker.sock")
	}
}

func TestBuildClientOptions_TCP_NoURL(t *testing.T) {
	svc := newStandaloneService()
	host := &models.Host{
		EndpointType: models.EndpointTCP,
		EndpointURL:  nil,
	}

	_, err := svc.buildClientOptions(host)
	if err == nil {
		t.Fatal("expected error for TCP without URL")
	}
}

func TestBuildClientOptions_TCP_WithURL(t *testing.T) {
	svc := newStandaloneService()
	host := &models.Host{
		EndpointType: models.EndpointTCP,
		EndpointURL:  strPtr("tcp://10.0.0.5:2376"),
	}

	opts, err := svc.buildClientOptions(host)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Host != "tcp://10.0.0.5:2376" {
		t.Errorf("host = %q, want %q", opts.Host, "tcp://10.0.0.5:2376")
	}
}

func TestBuildClientOptions_Agent_ReturnsError(t *testing.T) {
	svc := newStandaloneService()
	host := &models.Host{
		Name:         "remote-agent",
		EndpointType: models.EndpointAgent,
	}

	_, err := svc.buildClientOptions(host)
	if err == nil {
		t.Fatal("expected error for agent endpoint type")
	}
}

func TestBuildClientOptions_TLS_NoEncryptor(t *testing.T) {
	svc := newStandaloneService()
	host := &models.Host{
		EndpointType: models.EndpointLocal,
		TLSEnabled:   true,
		TLSCACert:    strPtr("encrypted-ca"),
	}

	// With nil encryptor we accept either outcome: a panic (caught by
	// the recover below) or an error from the return path. The one
	// thing the test guards against is a silent (nil, nil) success on
	// a TLS host whose secrets we have no way to decrypt.
	defer func() { _ = recover() }()
	_, err := svc.buildClientOptions(host)
	if err == nil {
		t.Fatal("expected error or panic when TLSCACert is encrypted but encryptor is nil")
	}
}

// ---------------------------------------------------------------------------
// Tests: SetLimitProvider / SetCommandSender / SetRepository
// ---------------------------------------------------------------------------

func TestSetLimitProvider(t *testing.T) {
	svc := newStandaloneService()
	// Should not panic with nil
	svc.SetLimitProvider(nil)
}

func TestSetCommandSender(t *testing.T) {
	svc := newStandaloneService()
	svc.SetCommandSender(nil)
}

func TestSetRepository(t *testing.T) {
	svc := newStandaloneService()
	svc.SetRepository(nil)
}

// ---------------------------------------------------------------------------
// Tests: enrichSummariesParallel — guard paths only
//
// The fan-out itself opens Docker API connections per host, which
// isn't available in a unit test environment. These tests pin the
// pre-fan-out filtering — empty slice, nil pointers, offline status,
// missing client — that the function uses to skip work before
// touching any Docker client. A test that exercises the actual
// goroutine fan-out belongs in an integration tier (build tag e2e)
// where the test environment provides a real Docker daemon.
// ---------------------------------------------------------------------------

func TestEnrichSummariesParallel_EmptyInput(t *testing.T) {
	svc := newStandaloneService()
	// Must return immediately without panic; len == 0 path.
	svc.enrichSummariesParallel(context.Background(), nil)
	svc.enrichSummariesParallel(context.Background(), []*models.HostSummary{})
}

func TestEnrichSummariesParallel_NilSummaryEntries(t *testing.T) {
	svc := newStandaloneService()
	// Mixed slice with nil entries — the per-entry guard skips them.
	// No panic = pass.
	summaries := []*models.HostSummary{nil, nil}
	svc.enrichSummariesParallel(context.Background(), summaries)
}

func TestEnrichSummariesParallel_SkipsOfflineHosts(t *testing.T) {
	svc := newStandaloneService()
	offline := &models.HostSummary{
		Host: models.Host{
			ID:     uuid.New(),
			Status: models.HostStatusOffline,
		},
	}
	connecting := &models.HostSummary{
		Host: models.Host{
			ID:     uuid.New(),
			Status: models.HostStatusConnecting,
		},
	}
	summaries := []*models.HostSummary{offline, connecting}

	svc.enrichSummariesParallel(context.Background(), summaries)

	// Neither summary should have been enriched — every "live" field stays at
	// its zero value because no Info() call was issued.
	for i, s := range summaries {
		if s.DockerVersion != nil {
			t.Errorf("summary[%d] (%s): DockerVersion enriched on non-online host", i, s.Status)
		}
		if s.ContainerCount != 0 {
			t.Errorf("summary[%d] (%s): ContainerCount=%d, want 0", i, s.Status, s.ContainerCount)
		}
		if s.LastSeenAt != nil {
			t.Errorf("summary[%d] (%s): LastSeenAt enriched on non-online host", i, s.Status)
		}
	}
}

func TestEnrichSummariesParallel_OnlineButNoClientInPool(t *testing.T) {
	svc := newStandaloneService()
	// The clientPool from NewStandaloneService is empty — any UUID we ask
	// for will return (nil, false), so the per-host goroutine never
	// launches and the summary is untouched.
	summary := &models.HostSummary{
		Host: models.Host{
			ID:     uuid.New(),
			Status: models.HostStatusOnline,
		},
	}
	summaries := []*models.HostSummary{summary}

	svc.enrichSummariesParallel(context.Background(), summaries)

	if summary.DockerVersion != nil {
		t.Errorf("DockerVersion enriched even though no client was in the pool")
	}
	if summary.ContainerCount != 0 {
		t.Errorf("ContainerCount=%d, want 0 (no client to enrich from)", summary.ContainerCount)
	}
	if summary.LastSeenAt != nil {
		t.Errorf("LastSeenAt enriched even though no client was in the pool")
	}
}

// TestListSummaries_StandaloneEmpty pins the standalone (no-repo) path
// of Service.ListSummaries: with an empty client pool the function
// must return an empty slice and no error. This is the dashboard's
// cold-start state on a fresh standalone install before any host has
// registered through RegisterClient.
func TestListSummaries_StandaloneEmpty(t *testing.T) {
	svc := newStandaloneService()
	summaries, err := svc.ListSummaries(context.Background())
	if err != nil {
		t.Fatalf("ListSummaries: %v", err)
	}
	if len(summaries) != 0 {
		t.Errorf("expected 0 summaries with empty client pool, got %d", len(summaries))
	}
}

// TestEnrichSummariesParallel_MixedStatuses combines all three guard
// paths in one call: a nil entry, an offline entry, and an online entry
// with no client. None should produce enrichment side-effects, and the
// function must return without deadlock or panic.
func TestEnrichSummariesParallel_MixedStatuses(t *testing.T) {
	svc := newStandaloneService()
	online := &models.HostSummary{
		Host: models.Host{ID: uuid.New(), Status: models.HostStatusOnline},
	}
	offline := &models.HostSummary{
		Host: models.Host{ID: uuid.New(), Status: models.HostStatusOffline},
	}
	summaries := []*models.HostSummary{nil, offline, online}

	done := make(chan struct{})
	go func() {
		svc.enrichSummariesParallel(context.Background(), summaries)
		close(done)
	}()
	select {
	case <-done:
		// Pass: returned without blocking.
	case <-time.After(2 * time.Second):
		t.Fatal("enrichSummariesParallel blocked — semaphore or WaitGroup deadlock?")
	}

	if online.DockerVersion != nil || offline.DockerVersion != nil {
		t.Errorf("no enrichment expected without a real client in the pool")
	}
}
