// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package deploy

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestGenerateAgentConfig(t *testing.T) {
	svc := &Service{}

	req := DeployRequest{
		GatewayURL: "nats://10.0.0.1:4222",
		AgentToken: "test-token-abc-123",
		SSHHost:    "10.0.0.50",
	}

	// Without TLS
	config, err := svc.generateAgentConfig(req, false)
	if err != nil {
		t.Fatalf("generateAgentConfig() error: %v", err)
	}

	if !strings.Contains(config, "nats://10.0.0.1:4222") {
		t.Error("config should contain gateway URL")
	}
	if !strings.Contains(config, "test-token-abc-123") {
		t.Error("config should contain token")
	}
	if !strings.Contains(config, "10.0.0.50") {
		t.Error("config should contain hostname")
	}
	if strings.Contains(config, "tls:") {
		t.Error("config should not contain TLS section when disabled")
	}

	// With TLS
	configTLS, err := svc.generateAgentConfig(req, true)
	if err != nil {
		t.Fatalf("generateAgentConfig() with TLS error: %v", err)
	}

	if !strings.Contains(configTLS, "enabled: true") {
		t.Error("TLS config should have enabled: true")
	}
	if !strings.Contains(configTLS, "cert_file: \"/app/certs/agent.crt\"") {
		t.Error("TLS config should have cert_file")
	}
}

func TestGenerateComposeFile(t *testing.T) {
	svc := &Service{}

	req := DeployRequest{
		AgentImage: "usulnet-agent:v1.0",
		GatewayURL: "nats://master:4222",
		AgentToken: "my-token",
	}

	// Without TLS
	compose, err := svc.generateComposeFile(req, false)
	if err != nil {
		t.Fatalf("generateComposeFile() error: %v", err)
	}

	if !strings.Contains(compose, "usulnet-agent:v1.0") {
		t.Error("compose should contain agent image")
	}
	if !strings.Contains(compose, "USULNET_GATEWAY_URL=nats://master:4222") {
		t.Error("compose should contain gateway URL env var")
	}
	if !strings.Contains(compose, "/var/run/docker.sock") {
		t.Error("compose should mount Docker socket")
	}
	if strings.Contains(compose, "./certs") {
		t.Error("compose should not mount certs when TLS disabled")
	}

	// With TLS
	composeTLS, err := svc.generateComposeFile(req, true)
	if err != nil {
		t.Fatalf("generateComposeFile() with TLS error: %v", err)
	}

	if !strings.Contains(composeTLS, "./certs:/app/certs:ro") {
		t.Error("compose should mount certs volume when TLS enabled")
	}
}

func TestDeployRequestValidation(t *testing.T) {
	svc := &Service{
		deployments: make(map[string]*DeployResult),
	}

	tests := []struct {
		name    string
		req     DeployRequest
		wantErr string
	}{
		{
			name:    "missing SSH host",
			req:     DeployRequest{SSHUser: "root", AgentToken: "tok", GatewayURL: "nats://x"},
			wantErr: "SSH host is required",
		},
		{
			name:    "missing SSH user",
			req:     DeployRequest{SSHHost: "1.2.3.4", AgentToken: "tok", GatewayURL: "nats://x"},
			wantErr: "SSH user is required",
		},
		{
			name:    "missing token",
			req:     DeployRequest{SSHHost: "1.2.3.4", SSHUser: "root", GatewayURL: "nats://x"},
			wantErr: "agent token is required",
		},
		{
			name:    "missing gateway",
			req:     DeployRequest{SSHHost: "1.2.3.4", SSHUser: "root", AgentToken: "tok"},
			wantErr: "gateway URL is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.Deploy(t.Context(), tt.req)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestDeployResult_Tracking(t *testing.T) {
	svc := &Service{
		deployments: make(map[string]*DeployResult),
	}

	result := &DeployResult{
		ID:        "test-123",
		HostID:    uuid.New(),
		HostName:  "test-host",
		Status:    StatusPending,
	}

	svc.mu.Lock()
	svc.deployments["test-123"] = result
	svc.mu.Unlock()

	// Get deployment
	got, ok := svc.GetDeployment("test-123")
	if !ok {
		t.Fatal("deployment should be found")
	}
	if got.Status != StatusPending {
		t.Errorf("status = %q, want %q", got.Status, StatusPending)
	}

	// Not found
	_, ok = svc.GetDeployment("nonexistent")
	if ok {
		t.Error("nonexistent deployment should not be found")
	}

	// List
	all := svc.ListDeployments()
	if len(all) != 1 {
		t.Errorf("ListDeployments() returned %d, want 1", len(all))
	}
}

func TestDeployResult_StatusTransitions(t *testing.T) {
	r := &DeployResult{
		ID:     "test",
		Status: StatusPending,
	}

	r.setStatus(StatusConnecting, "connecting")
	if r.Status != StatusConnecting {
		t.Errorf("status = %q, want %q", r.Status, StatusConnecting)
	}
	if r.Step != "connecting" {
		t.Errorf("step = %q, want %q", r.Step, "connecting")
	}

	r.addLog("test log message")
	if len(r.Logs) != 1 {
		t.Errorf("logs = %d, want 1", len(r.Logs))
	}
	if !strings.Contains(r.Logs[0], "test log message") {
		t.Errorf("log = %q, want containing 'test log message'", r.Logs[0])
	}

	r.setComplete()
	if r.Status != StatusComplete {
		t.Errorf("status = %q, want %q", r.Status, StatusComplete)
	}
	if r.EndedAt == nil {
		t.Error("EndedAt should be set after complete")
	}
}

func TestDeployResult_ErrorState(t *testing.T) {
	r := &DeployResult{
		ID:     "test",
		Status: StatusDeploying,
	}

	r.setError(errForTest("connection refused"))

	if r.Status != StatusFailed {
		t.Errorf("status = %q, want %q", r.Status, StatusFailed)
	}
	if r.Error != "connection refused" {
		t.Errorf("error = %q, want 'connection refused'", r.Error)
	}
	if r.EndedAt == nil {
		t.Error("EndedAt should be set after error")
	}
}

type errForTest string

func (e errForTest) Error() string { return string(e) }
