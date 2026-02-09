// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fr4nsys/usulnet/internal/agent"
)

// ============================================================================
// Agent Config YAML Loading Pipeline Tests
// ============================================================================

func TestLoadConfigFile_FullConfig(t *testing.T) {
	configYAML := `
gateway_url: "nats://master.example.com:4222"
token: "my-secret-token"
docker_host: "unix:///var/run/docker.sock"
hostname: "agent-host-1"
agent_id: "agent-abc-123"
labels:
  env: production
  region: eu-west
data_dir: "/data/usulnet"
log_level: "debug"
log_format: "console"
tls:
  enabled: true
  cert_file: "/app/certs/agent.crt"
  key_file: "/app/certs/agent.key"
  ca_file: "/app/certs/ca.crt"
`
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(configPath, []byte(configYAML), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg := agent.DefaultConfig()
	if err := loadConfigFile(configPath, &cfg); err != nil {
		t.Fatalf("loadConfigFile() error: %v", err)
	}

	if cfg.GatewayURL != "nats://master.example.com:4222" {
		t.Errorf("GatewayURL = %q, want %q", cfg.GatewayURL, "nats://master.example.com:4222")
	}
	if cfg.Token != "my-secret-token" {
		t.Errorf("Token = %q, want %q", cfg.Token, "my-secret-token")
	}
	if cfg.DockerHost != "unix:///var/run/docker.sock" {
		t.Errorf("DockerHost = %q, want %q", cfg.DockerHost, "unix:///var/run/docker.sock")
	}
	if cfg.Hostname != "agent-host-1" {
		t.Errorf("Hostname = %q, want %q", cfg.Hostname, "agent-host-1")
	}
	if cfg.AgentID != "agent-abc-123" {
		t.Errorf("AgentID = %q, want %q", cfg.AgentID, "agent-abc-123")
	}
	if cfg.Labels["env"] != "production" {
		t.Errorf("Labels[env] = %q, want %q", cfg.Labels["env"], "production")
	}
	if cfg.Labels["region"] != "eu-west" {
		t.Errorf("Labels[region] = %q, want %q", cfg.Labels["region"], "eu-west")
	}
	if cfg.DataDir != "/data/usulnet" {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, "/data/usulnet")
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
	}
	if !cfg.TLSEnabled {
		t.Error("TLSEnabled should be true")
	}
	if cfg.TLSCertFile != "/app/certs/agent.crt" {
		t.Errorf("TLSCertFile = %q, want %q", cfg.TLSCertFile, "/app/certs/agent.crt")
	}
	if cfg.TLSKeyFile != "/app/certs/agent.key" {
		t.Errorf("TLSKeyFile = %q, want %q", cfg.TLSKeyFile, "/app/certs/agent.key")
	}
	if cfg.TLSCAFile != "/app/certs/ca.crt" {
		t.Errorf("TLSCAFile = %q, want %q", cfg.TLSCAFile, "/app/certs/ca.crt")
	}
}

func TestLoadConfigFile_MinimalConfig(t *testing.T) {
	configYAML := `
gateway_url: "nats://10.0.0.1:4222"
token: "tok"
`
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.yaml")
	os.WriteFile(configPath, []byte(configYAML), 0644)

	cfg := agent.DefaultConfig()
	originalDockerHost := cfg.DockerHost
	originalDataDir := cfg.DataDir

	if err := loadConfigFile(configPath, &cfg); err != nil {
		t.Fatalf("loadConfigFile() error: %v", err)
	}

	if cfg.GatewayURL != "nats://10.0.0.1:4222" {
		t.Errorf("GatewayURL = %q, want %q", cfg.GatewayURL, "nats://10.0.0.1:4222")
	}
	if cfg.Token != "tok" {
		t.Errorf("Token = %q, want %q", cfg.Token, "tok")
	}

	// Fields not in the file should keep defaults
	if cfg.DockerHost != originalDockerHost {
		t.Errorf("DockerHost should remain default %q, got %q", originalDockerHost, cfg.DockerHost)
	}
	if cfg.DataDir != originalDataDir {
		t.Errorf("DataDir should remain default %q, got %q", originalDataDir, cfg.DataDir)
	}
	if cfg.TLSEnabled {
		t.Error("TLSEnabled should remain false when not set in config")
	}
}

func TestLoadConfigFile_TLSDisabled(t *testing.T) {
	configYAML := `
gateway_url: "nats://10.0.0.1:4222"
token: "tok"
tls:
  enabled: false
`
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.yaml")
	os.WriteFile(configPath, []byte(configYAML), 0644)

	cfg := agent.DefaultConfig()
	if err := loadConfigFile(configPath, &cfg); err != nil {
		t.Fatalf("loadConfigFile() error: %v", err)
	}

	if cfg.TLSEnabled {
		t.Error("TLSEnabled should be false")
	}
	if cfg.TLSCertFile != "" {
		t.Errorf("TLSCertFile should be empty, got %q", cfg.TLSCertFile)
	}
}

func TestLoadConfigFile_NotFound(t *testing.T) {
	cfg := agent.DefaultConfig()
	err := loadConfigFile("/nonexistent/path/agent.yaml", &cfg)
	if err == nil {
		t.Error("should error on missing file")
	}
}

func TestLoadConfigFile_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.yaml")
	os.WriteFile(configPath, []byte("{{{{invalid yaml"), 0644)

	cfg := agent.DefaultConfig()
	err := loadConfigFile(configPath, &cfg)
	if err == nil {
		t.Error("should error on invalid YAML")
	}
}

func TestLoadConfigFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.yaml")
	os.WriteFile(configPath, []byte(""), 0644)

	cfg := agent.DefaultConfig()
	origGateway := cfg.GatewayURL
	if err := loadConfigFile(configPath, &cfg); err != nil {
		t.Fatalf("empty file should not error: %v", err)
	}

	// Defaults should be preserved
	if cfg.GatewayURL != origGateway {
		t.Errorf("GatewayURL should remain default %q, got %q", origGateway, cfg.GatewayURL)
	}
}

func TestLoadConfigFile_PartialOverride(t *testing.T) {
	// Only override some fields, rest keep defaults
	configYAML := `
hostname: "custom-hostname"
log_level: "warn"
`
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.yaml")
	os.WriteFile(configPath, []byte(configYAML), 0644)

	cfg := agent.DefaultConfig()
	if err := loadConfigFile(configPath, &cfg); err != nil {
		t.Fatalf("loadConfigFile() error: %v", err)
	}

	if cfg.Hostname != "custom-hostname" {
		t.Errorf("Hostname = %q, want %q", cfg.Hostname, "custom-hostname")
	}
	if cfg.LogLevel != "warn" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "warn")
	}

	// Other fields should keep defaults
	if cfg.GatewayURL != "nats://localhost:4222" {
		t.Errorf("GatewayURL should be default, got %q", cfg.GatewayURL)
	}
}

// ============================================================================
// Deploy-Generated Config Pipeline Test
// ============================================================================

func TestDeployGeneratedConfig_LoadsCorrectly(t *testing.T) {
	// This tests the full pipeline: deploy service generates YAML config →
	// agent loads it correctly
	//
	// The deploy service generates this exact format:
	deployGeneratedConfig := `# usulnet Agent Configuration (auto-generated)
gateway_url: "nats://10.0.0.1:4222"
token: "deploy-token-xyz"
docker_host: "unix:///var/run/docker.sock"
hostname: "10.0.0.50"
data_dir: "/app/data"
log_level: "info"
log_format: "json"

tls:
  enabled: true
  cert_file: "/app/certs/agent.crt"
  key_file: "/app/certs/agent.key"
  ca_file: "/app/certs/ca.crt"
`
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.yaml")
	os.WriteFile(configPath, []byte(deployGeneratedConfig), 0644)

	cfg := agent.DefaultConfig()
	if err := loadConfigFile(configPath, &cfg); err != nil {
		t.Fatalf("loadConfigFile() error: %v", err)
	}

	// Verify all fields are loaded correctly
	if cfg.GatewayURL != "nats://10.0.0.1:4222" {
		t.Errorf("GatewayURL = %q", cfg.GatewayURL)
	}
	if cfg.Token != "deploy-token-xyz" {
		t.Errorf("Token = %q", cfg.Token)
	}
	if cfg.Hostname != "10.0.0.50" {
		t.Errorf("Hostname = %q", cfg.Hostname)
	}
	if cfg.DataDir != "/app/data" {
		t.Errorf("DataDir = %q", cfg.DataDir)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q", cfg.LogLevel)
	}
	if !cfg.TLSEnabled {
		t.Error("TLSEnabled should be true")
	}
	if cfg.TLSCertFile != "/app/certs/agent.crt" {
		t.Errorf("TLSCertFile = %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/app/certs/agent.key" {
		t.Errorf("TLSKeyFile = %q", cfg.TLSKeyFile)
	}
	if cfg.TLSCAFile != "/app/certs/ca.crt" {
		t.Errorf("TLSCAFile = %q", cfg.TLSCAFile)
	}
}

func TestDeployGeneratedConfig_NoTLS(t *testing.T) {
	// Config generated by deploy when PKI is not available
	deployGeneratedConfigNoTLS := `# usulnet Agent Configuration (auto-generated)
gateway_url: "nats://10.0.0.1:4222"
token: "deploy-token-xyz"
docker_host: "unix:///var/run/docker.sock"
hostname: "10.0.0.50"
data_dir: "/app/data"
log_level: "info"
log_format: "json"
`
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.yaml")
	os.WriteFile(configPath, []byte(deployGeneratedConfigNoTLS), 0644)

	cfg := agent.DefaultConfig()
	if err := loadConfigFile(configPath, &cfg); err != nil {
		t.Fatalf("loadConfigFile() error: %v", err)
	}

	if cfg.TLSEnabled {
		t.Error("TLSEnabled should be false for no-TLS config")
	}
	if cfg.GatewayURL != "nats://10.0.0.1:4222" {
		t.Errorf("GatewayURL = %q", cfg.GatewayURL)
	}
}

// ============================================================================
// envOrDefault helper tests
// ============================================================================

func TestEnvOrDefault(t *testing.T) {
	// Without env var set
	result := envOrDefault("USULNET_TEST_NONEXISTENT_12345", "fallback")
	if result != "fallback" {
		t.Errorf("envOrDefault() = %q, want %q", result, "fallback")
	}

	// With env var set
	t.Setenv("USULNET_TEST_ENV_VAR", "custom-value")
	result = envOrDefault("USULNET_TEST_ENV_VAR", "fallback")
	if result != "custom-value" {
		t.Errorf("envOrDefault() = %q, want %q", result, "custom-value")
	}
}
