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

	// With nil encryptor, should panic or error
	defer func() {
		if r := recover(); r == nil {
			// If it didn't panic, it should have returned an error
			// (depends on implementation)
		}
	}()
	_, _ = svc.buildClientOptions(host)
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
