// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package protocol

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// Message Serialization Round-Trip Tests
// ============================================================================

func TestMessage_RoundTrip(t *testing.T) {
	payload := map[string]string{"key": "value"}
	msg, err := NewMessage(MessageTypeCommand, payload)
	if err != nil {
		t.Fatalf("NewMessage() error: %v", err)
	}

	msg.WithAgent("agent-1", "host-1").WithReply("usulnet.reply.abc")

	// Encode
	data, err := msg.Encode()
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	// Decode
	decoded, err := DecodeMessage(data)
	if err != nil {
		t.Fatalf("DecodeMessage() error: %v", err)
	}

	if decoded.ID != msg.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, msg.ID)
	}
	if decoded.Type != MessageTypeCommand {
		t.Errorf("Type = %q, want %q", decoded.Type, MessageTypeCommand)
	}
	if decoded.AgentID != "agent-1" {
		t.Errorf("AgentID = %q, want %q", decoded.AgentID, "agent-1")
	}
	if decoded.HostID != "host-1" {
		t.Errorf("HostID = %q, want %q", decoded.HostID, "host-1")
	}
	if decoded.ReplyTo != "usulnet.reply.abc" {
		t.Errorf("ReplyTo = %q, want %q", decoded.ReplyTo, "usulnet.reply.abc")
	}

	// Decode payload
	var decodedPayload map[string]string
	if err := decoded.DecodePayload(&decodedPayload); err != nil {
		t.Fatalf("DecodePayload() error: %v", err)
	}
	if decodedPayload["key"] != "value" {
		t.Errorf("payload key = %q, want %q", decodedPayload["key"], "value")
	}
}

func TestRegistrationRequest_RoundTrip(t *testing.T) {
	req := RegistrationRequest{
		Token: "test-token-abc",
		Info: AgentInfo{
			AgentID:    "agent-123",
			Version:    "1.0.0",
			Hostname:   "docker-host-1",
			OS:         "linux",
			Arch:       "amd64",
			DockerHost: "unix:///var/run/docker.sock",
			Labels:     map[string]string{"env": "production", "region": "eu-west"},
			Capabilities: []string{"docker", "compose", "backup"},
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded RegistrationRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if decoded.Token != req.Token {
		t.Errorf("Token = %q, want %q", decoded.Token, req.Token)
	}
	if decoded.Info.AgentID != req.Info.AgentID {
		t.Errorf("AgentID = %q, want %q", decoded.Info.AgentID, req.Info.AgentID)
	}
	if decoded.Info.Labels["env"] != "production" {
		t.Errorf("Label env = %q, want %q", decoded.Info.Labels["env"], "production")
	}
	if len(decoded.Info.Capabilities) != 3 {
		t.Errorf("Capabilities = %d, want 3", len(decoded.Info.Capabilities))
	}
}

func TestRegistrationResponse_RoundTrip(t *testing.T) {
	resp := RegistrationResponse{
		Success:           true,
		AgentID:           "agent-456",
		HeartbeatInterval: 30 * time.Second,
		InventoryInterval: 5 * time.Minute,
		Config: AgentConfig{
			LogLevel:         "info",
			MetricsEnabled:   true,
			MetricsInterval:  60,
			BackupEnabled:    true,
			ScannerEnabled:   true,
			MaxConcurrentOps: 5,
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded RegistrationResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if !decoded.Success {
		t.Error("Success should be true")
	}
	if decoded.AgentID != "agent-456" {
		t.Errorf("AgentID = %q, want %q", decoded.AgentID, "agent-456")
	}
	if decoded.HeartbeatInterval != 30*time.Second {
		t.Errorf("HeartbeatInterval = %v, want %v", decoded.HeartbeatInterval, 30*time.Second)
	}
	if decoded.Config.MaxConcurrentOps != 5 {
		t.Errorf("MaxConcurrentOps = %d, want 5", decoded.Config.MaxConcurrentOps)
	}
}

func TestHeartbeat_RoundTrip(t *testing.T) {
	now := time.Now().UTC()
	hb := Heartbeat{
		AgentID:   "agent-789",
		Timestamp: now,
		Uptime:    2 * time.Hour,
		Stats: &QuickStats{
			ContainersRunning: 5,
			ContainersStopped: 2,
			ContainersTotal:   7,
			ImagesCount:       12,
			VolumesCount:      3,
			NetworksCount:     4,
			CPUPercent:        45.5,
			MemoryUsedBytes:   4294967296,
			MemoryTotalBytes:  8589934592,
			DiskUsedBytes:     107374182400,
			DiskTotalBytes:    214748364800,
		},
		ActiveJobs: 1,
		Health:     HealthStatusHealthy,
		Metrics: &AgentMetrics{
			CollectedAt:      now,
			CPUUsagePercent:  45.5,
			MemoryUsageBytes: 4294967296,
			MemoryLimitBytes: 8589934592,
			Goroutines:       42,
		},
	}

	data, err := json.Marshal(hb)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded Heartbeat
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if decoded.AgentID != "agent-789" {
		t.Errorf("AgentID = %q, want %q", decoded.AgentID, "agent-789")
	}
	if decoded.Health != HealthStatusHealthy {
		t.Errorf("Health = %q, want %q", decoded.Health, HealthStatusHealthy)
	}
	if decoded.Stats.ContainersRunning != 5 {
		t.Errorf("ContainersRunning = %d, want 5", decoded.Stats.ContainersRunning)
	}
	if decoded.Stats.CPUPercent != 45.5 {
		t.Errorf("CPUPercent = %f, want 45.5", decoded.Stats.CPUPercent)
	}
	if decoded.Metrics.Goroutines != 42 {
		t.Errorf("Goroutines = %d, want 42", decoded.Metrics.Goroutines)
	}
}

func TestCommand_RoundTrip(t *testing.T) {
	cmd := Command{
		ID:       uuid.New().String(),
		Type:     CmdContainerList,
		HostID:   uuid.New().String(),
		Priority: PriorityHigh,
		Timeout:  30 * time.Second,
		ReplyTo:  "usulnet.reply.xyz",
		CreatedAt: time.Now().UTC(),
		CreatedBy: "admin",
		Params: CommandParams{
			All:     true,
			Filters: map[string][]string{"status": {"running"}},
			Limit:   100,
		},
		Idempotent: true,
	}

	data, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded Command
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if decoded.Type != CmdContainerList {
		t.Errorf("Type = %q, want %q", decoded.Type, CmdContainerList)
	}
	if decoded.Priority != PriorityHigh {
		t.Errorf("Priority = %d, want %d", decoded.Priority, PriorityHigh)
	}
	if decoded.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want %v", decoded.Timeout, 30*time.Second)
	}
	if !decoded.Params.All {
		t.Error("Params.All should be true")
	}
	if decoded.Params.Filters["status"][0] != "running" {
		t.Error("filter status should be 'running'")
	}
	if !decoded.Idempotent {
		t.Error("Idempotent should be true")
	}
}

func TestCommandResult_RoundTrip(t *testing.T) {
	result := NewCommandResult("cmd-abc", map[string]interface{}{
		"containers": []string{"web-1", "db-1"},
	})
	result.StartedAt = time.Now().UTC().Add(-100 * time.Millisecond)
	result.Duration = 100 * time.Millisecond
	result.Warnings = []string{"high memory usage"}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded CommandResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if decoded.CommandID != "cmd-abc" {
		t.Errorf("CommandID = %q, want %q", decoded.CommandID, "cmd-abc")
	}
	if decoded.Status != CommandStatusCompleted {
		t.Errorf("Status = %q, want %q", decoded.Status, CommandStatusCompleted)
	}
	if len(decoded.Warnings) != 1 {
		t.Errorf("Warnings = %d, want 1", len(decoded.Warnings))
	}
}

func TestCommandResultError_RoundTrip(t *testing.T) {
	cmdErr := &CommandError{
		Code:        "DOCKER_ERROR",
		Message:     "container not found",
		DockerError: "No such container: abc123",
	}
	result := NewCommandResultError("cmd-fail", cmdErr)

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded CommandResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if decoded.Status != CommandStatusFailed {
		t.Errorf("Status = %q, want %q", decoded.Status, CommandStatusFailed)
	}
	if decoded.Error == nil {
		t.Fatal("Error should not be nil")
	}
	if decoded.Error.Code != "DOCKER_ERROR" {
		t.Errorf("Error.Code = %q, want %q", decoded.Error.Code, "DOCKER_ERROR")
	}
	if decoded.Error.DockerError != "No such container: abc123" {
		t.Errorf("Error.DockerError = %q", decoded.Error.DockerError)
	}
}

func TestEvent_RoundTrip(t *testing.T) {
	event := Event{
		ID:       uuid.New().String(),
		Type:     EventContainerStart,
		AgentID:  "agent-1",
		HostID:   uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Severity: SeverityInfo,
		Message:  "Container started",
		Actor: &EventActor{
			Type: "container",
			ID:   "abc123",
			Name: "web-server",
			Attributes: map[string]string{
				"image": "nginx:latest",
			},
		},
		Attributes: map[string]string{
			"action": "start",
		},
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded Event
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if decoded.Type != EventContainerStart {
		t.Errorf("Type = %q, want %q", decoded.Type, EventContainerStart)
	}
	if decoded.Severity != SeverityInfo {
		t.Errorf("Severity = %q, want %q", decoded.Severity, SeverityInfo)
	}
	if decoded.Actor == nil {
		t.Fatal("Actor should not be nil")
	}
	if decoded.Actor.Name != "web-server" {
		t.Errorf("Actor.Name = %q, want %q", decoded.Actor.Name, "web-server")
	}
	if decoded.Actor.Attributes["image"] != "nginx:latest" {
		t.Errorf("Actor.Attributes[image] = %q", decoded.Actor.Attributes["image"])
	}
}

func TestInventory_RoundTrip(t *testing.T) {
	inv := Inventory{
		AgentID:     "agent-inv",
		HostID:      uuid.New().String(),
		CollectedAt: time.Now().UTC(),
		Containers: []ContainerInfo{
			{
				ID:      "abc123",
				Names:   []string{"/web-server"},
				Image:   "nginx:latest",
				ImageID: "sha256:abc",
				Command: "nginx -g 'daemon off;'",
				Created: time.Now().Unix(),
				State:   "running",
				Status:  "Up 2 hours",
				Ports: []PortBinding{
					{PrivatePort: 80, PublicPort: 8080, Type: "tcp"},
				},
				Labels: map[string]string{"app": "web"},
			},
		},
		Images: []ImageInfo{
			{
				ID:       "sha256:abc",
				RepoTags: []string{"nginx:latest"},
				Size:     142000000,
			},
		},
		Volumes: []VolumeInfo{
			{
				Name:       "data-vol",
				Driver:     "local",
				Mountpoint: "/var/lib/docker/volumes/data-vol/_data",
				Scope:      "local",
			},
		},
		Networks: []NetworkInfo{
			{
				ID:     "net-123",
				Name:   "bridge",
				Driver: "bridge",
				Scope:  "local",
			},
		},
		SystemInfo: &SystemInfo{
			Name:              "docker-host-1",
			ServerVersion:     "24.0.7",
			OS:                "linux",
			Arch:              "amd64",
			ContainersTotal:   5,
			ContainersRunning: 3,
			Images:            10,
			MemoryTotal:       8589934592,
			CPUs:              4,
		},
	}

	data, err := json.Marshal(inv)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded Inventory
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if decoded.AgentID != "agent-inv" {
		t.Errorf("AgentID = %q, want %q", decoded.AgentID, "agent-inv")
	}
	if len(decoded.Containers) != 1 {
		t.Fatalf("Containers = %d, want 1", len(decoded.Containers))
	}
	if decoded.Containers[0].State != "running" {
		t.Errorf("Container state = %q, want %q", decoded.Containers[0].State, "running")
	}
	if decoded.Containers[0].Ports[0].PublicPort != 8080 {
		t.Errorf("Port = %d, want 8080", decoded.Containers[0].Ports[0].PublicPort)
	}
	if decoded.SystemInfo.CPUs != 4 {
		t.Errorf("CPUs = %d, want 4", decoded.SystemInfo.CPUs)
	}
}

// ============================================================================
// Message Wrapping Tests (Message envelope with typed payloads)
// ============================================================================

func TestMessage_RegistrationPayload(t *testing.T) {
	req := RegistrationRequest{
		Token: "tok-xyz",
		Info: AgentInfo{
			AgentID:  "agent-wrap",
			Hostname: "host-wrap",
		},
	}

	msg, err := NewMessage(MessageTypeRegister, req)
	if err != nil {
		t.Fatalf("NewMessage() error: %v", err)
	}

	data, _ := msg.Encode()
	decoded, _ := DecodeMessage(data)

	var decodedReq RegistrationRequest
	if err := decoded.DecodePayload(&decodedReq); err != nil {
		t.Fatalf("DecodePayload() error: %v", err)
	}

	if decodedReq.Token != "tok-xyz" {
		t.Errorf("Token = %q, want %q", decodedReq.Token, "tok-xyz")
	}
	if decodedReq.Info.AgentID != "agent-wrap" {
		t.Errorf("AgentID = %q, want %q", decodedReq.Info.AgentID, "agent-wrap")
	}
}

func TestMessage_HeartbeatPayload(t *testing.T) {
	hb := Heartbeat{
		AgentID: "hb-agent",
		Health:  HealthStatusDegraded,
		Stats: &QuickStats{
			ContainersRunning: 3,
		},
	}

	msg, err := NewMessage(MessageTypeHeartbeat, hb)
	if err != nil {
		t.Fatalf("NewMessage() error: %v", err)
	}

	data, _ := msg.Encode()
	decoded, _ := DecodeMessage(data)

	var decodedHB Heartbeat
	if err := decoded.DecodePayload(&decodedHB); err != nil {
		t.Fatalf("DecodePayload() error: %v", err)
	}

	if decodedHB.Health != HealthStatusDegraded {
		t.Errorf("Health = %q, want %q", decodedHB.Health, HealthStatusDegraded)
	}
	if decodedHB.Stats.ContainersRunning != 3 {
		t.Errorf("ContainersRunning = %d, want 3", decodedHB.Stats.ContainersRunning)
	}
}

func TestMessage_CommandPayload(t *testing.T) {
	cmd := Command{
		ID:       "cmd-envelope",
		Type:     CmdContainerStop,
		Priority: PriorityCritical,
		Params: CommandParams{
			ContainerID: "container-abc",
		},
	}

	msg, err := NewMessage(MessageTypeCommand, cmd)
	if err != nil {
		t.Fatalf("NewMessage() error: %v", err)
	}
	msg.WithAgent("agent-x", "host-x")

	data, _ := msg.Encode()
	decoded, _ := DecodeMessage(data)

	if decoded.Type != MessageTypeCommand {
		t.Errorf("Type = %q, want %q", decoded.Type, MessageTypeCommand)
	}

	var decodedCmd Command
	if err := decoded.DecodePayload(&decodedCmd); err != nil {
		t.Fatalf("DecodePayload() error: %v", err)
	}

	if decodedCmd.Type != CmdContainerStop {
		t.Errorf("CmdType = %q, want %q", decodedCmd.Type, CmdContainerStop)
	}
	if decodedCmd.Params.ContainerID != "container-abc" {
		t.Errorf("ContainerID = %q, want %q", decodedCmd.Params.ContainerID, "container-abc")
	}
}

// ============================================================================
// Command Classification Tests
// ============================================================================

func TestDefaultTimeout(t *testing.T) {
	tests := []struct {
		cmdType CommandType
		want    time.Duration
	}{
		{CmdContainerList, 30 * time.Second},
		{CmdImagePull, 10 * time.Minute},
		{CmdStackDeploy, 5 * time.Minute},
		{CmdBackupVolume, 30 * time.Minute},
		{CmdSecurityScan, 10 * time.Minute},
		{CmdUpdateApply, 15 * time.Minute},
		{CmdSystemPrune, 5 * time.Minute},
		{CmdContainerLogs, 30 * time.Second},
	}

	for _, tt := range tests {
		got := DefaultTimeout(tt.cmdType)
		if got != tt.want {
			t.Errorf("DefaultTimeout(%q) = %v, want %v", tt.cmdType, got, tt.want)
		}
	}
}

func TestIsIdempotent(t *testing.T) {
	idempotent := []CommandType{
		CmdContainerList, CmdContainerInspect, CmdContainerLogs,
		CmdImageList, CmdImageInspect,
		CmdVolumeList, CmdNetworkList,
		CmdSystemInfo, CmdSystemVersion, CmdSystemPing,
	}
	for _, ct := range idempotent {
		if !IsIdempotent(ct) {
			t.Errorf("IsIdempotent(%q) = false, want true", ct)
		}
	}

	nonIdempotent := []CommandType{
		CmdContainerStart, CmdContainerStop, CmdContainerRemove,
		CmdImagePull, CmdImageRemove,
		CmdVolumeCreate, CmdNetworkCreate,
		CmdStackDeploy,
	}
	for _, ct := range nonIdempotent {
		if IsIdempotent(ct) {
			t.Errorf("IsIdempotent(%q) = true, want false", ct)
		}
	}
}

func TestIsDestructive(t *testing.T) {
	destructive := []CommandType{
		CmdContainerRemove, CmdContainerKill,
		CmdImageRemove, CmdImagePrune,
		CmdVolumeRemove, CmdVolumePrune,
		CmdNetworkRemove, CmdNetworkPrune,
		CmdStackRemove, CmdSystemPrune,
	}
	for _, ct := range destructive {
		if !IsDestructive(ct) {
			t.Errorf("IsDestructive(%q) = false, want true", ct)
		}
	}

	safe := []CommandType{
		CmdContainerList, CmdContainerStart, CmdContainerStop,
		CmdImageList, CmdImagePull,
		CmdStackDeploy, CmdSystemInfo,
	}
	for _, ct := range safe {
		if IsDestructive(ct) {
			t.Errorf("IsDestructive(%q) = true, want false", ct)
		}
	}
}

// ============================================================================
// Event Classification Tests
// ============================================================================

func TestGetSeverity(t *testing.T) {
	tests := []struct {
		event EventType
		want  EventSeverity
	}{
		{EventContainerDie, SeverityError},
		{EventContainerOOM, SeverityError},
		{EventAgentError, SeverityError},
		{EventContainerHealth, SeverityWarning},
		{EventSecurityVulnFound, SeverityWarning},
		{EventContainerStart, SeverityInfo},
		{EventImagePull, SeverityInfo},
		{EventAgentStarted, SeverityInfo},
	}

	for _, tt := range tests {
		got := GetSeverity(tt.event)
		if got != tt.want {
			t.Errorf("GetSeverity(%q) = %q, want %q", tt.event, got, tt.want)
		}
	}
}

func TestShouldPersist(t *testing.T) {
	persist := []EventType{
		EventContainerCreate, EventContainerDie, EventContainerOOM,
		EventImagePull, EventAgentStarted, EventAgentError,
		EventSecurityScanCompleted, EventBackupCompleted,
	}
	for _, et := range persist {
		if !ShouldPersist(et) {
			t.Errorf("ShouldPersist(%q) = false, want true", et)
		}
	}

	noPersist := []EventType{
		EventContainerPause, EventContainerUnpause,
		EventContainerExec,
		EventVolumeMount, EventVolumeUnmount,
	}
	for _, et := range noPersist {
		if ShouldPersist(et) {
			t.Errorf("ShouldPersist(%q) = true, want false", et)
		}
	}
}

func TestShouldNotify(t *testing.T) {
	notify := []EventType{
		EventContainerDie, EventContainerOOM,
		EventAgentError, EventSecurityVulnFound,
		EventBackupFailed, EventUpdateAvailable,
		EventResourceCritical,
	}
	for _, et := range notify {
		if !ShouldNotify(et) {
			t.Errorf("ShouldNotify(%q) = false, want true", et)
		}
	}

	noNotify := []EventType{
		EventContainerStart, EventContainerStop,
		EventImagePull, EventAgentStarted,
		EventBackupCompleted,
	}
	for _, et := range noNotify {
		if ShouldNotify(et) {
			t.Errorf("ShouldNotify(%q) = true, want false", et)
		}
	}
}

// ============================================================================
// Protocol Error Tests
// ============================================================================

func TestProtocolError(t *testing.T) {
	err := NewProtocolError(ErrCodeInvalidToken, "token expired")
	if err.Error() != "INVALID_TOKEN: token expired" {
		t.Errorf("Error() = %q", err.Error())
	}

	err.WithDetails("token was valid until 2024-01-01")
	if err.Error() != "INVALID_TOKEN: token expired (token was valid until 2024-01-01)" {
		t.Errorf("Error() with details = %q", err.Error())
	}

	// Round-trip
	data, _ := json.Marshal(err)
	var decoded ProtocolError
	json.Unmarshal(data, &decoded)

	if decoded.Code != ErrCodeInvalidToken {
		t.Errorf("Code = %q, want %q", decoded.Code, ErrCodeInvalidToken)
	}
	if decoded.Details != "token was valid until 2024-01-01" {
		t.Errorf("Details = %q", decoded.Details)
	}
}

func TestCommandError(t *testing.T) {
	err := &CommandError{
		Code:        ErrCodeCommandFailed,
		Message:     "container not found",
		DockerError: "No such container: xyz",
	}

	expected := "COMMAND_FAILED: container not found (docker: No such container: xyz)"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}

	// Without docker error
	err2 := &CommandError{
		Code:    ErrCodeCommandTimeout,
		Message: "operation timed out",
	}
	if err2.Error() != "COMMAND_TIMEOUT: operation timed out" {
		t.Errorf("Error() = %q", err2.Error())
	}
}

// ============================================================================
// Event Data Type Tests
// ============================================================================

func TestContainerEventData_RoundTrip(t *testing.T) {
	data := ContainerEventData{
		ContainerID:   "abc123",
		ContainerName: "web-server",
		Image:         "nginx:latest",
		Status:        "running",
		ExitCode:      0,
	}

	event := Event{
		ID:       uuid.New().String(),
		Type:     EventContainerStart,
		Severity: SeverityInfo,
		Data:     data,
	}

	bytes, _ := json.Marshal(event)
	var decoded Event
	json.Unmarshal(bytes, &decoded)

	// Data comes back as map, need to re-marshal/unmarshal
	dataBytes, _ := json.Marshal(decoded.Data)
	var decodedData ContainerEventData
	json.Unmarshal(dataBytes, &decodedData)

	if decodedData.ContainerID != "abc123" {
		t.Errorf("ContainerID = %q, want %q", decodedData.ContainerID, "abc123")
	}
	if decodedData.Image != "nginx:latest" {
		t.Errorf("Image = %q, want %q", decodedData.Image, "nginx:latest")
	}
}

func TestDeregistrationRequest_RoundTrip(t *testing.T) {
	req := DeregistrationRequest{
		AgentID: "agent-leaving",
		Reason:  "graceful shutdown",
	}

	data, _ := json.Marshal(req)
	var decoded DeregistrationRequest
	json.Unmarshal(data, &decoded)

	if decoded.AgentID != "agent-leaving" {
		t.Errorf("AgentID = %q, want %q", decoded.AgentID, "agent-leaving")
	}
	if decoded.Reason != "graceful shutdown" {
		t.Errorf("Reason = %q, want %q", decoded.Reason, "graceful shutdown")
	}
}

func TestHeartbeatResponse_RoundTrip(t *testing.T) {
	resp := HeartbeatResponse{
		Acknowledged:  true,
		ServerTime:    time.Now().UTC(),
		ConfigChanged: true,
		NewConfig: &AgentConfig{
			LogLevel:       "debug",
			MetricsEnabled: true,
		},
		PendingJobs: 3,
	}

	data, _ := json.Marshal(resp)
	var decoded HeartbeatResponse
	json.Unmarshal(data, &decoded)

	if !decoded.Acknowledged {
		t.Error("Acknowledged should be true")
	}
	if !decoded.ConfigChanged {
		t.Error("ConfigChanged should be true")
	}
	if decoded.NewConfig == nil {
		t.Fatal("NewConfig should not be nil")
	}
	if decoded.NewConfig.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", decoded.NewConfig.LogLevel, "debug")
	}
	if decoded.PendingJobs != 3 {
		t.Errorf("PendingJobs = %d, want 3", decoded.PendingJobs)
	}
}
