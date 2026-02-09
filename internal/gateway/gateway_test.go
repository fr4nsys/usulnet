// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// Agent Connection State Tests
// ============================================================================

func TestAgentConnection_Management(t *testing.T) {
	s := &Server{
		agents:    make(map[string]*AgentConnection),
		hostIndex: make(map[uuid.UUID]string),
	}

	hostID := uuid.New()
	agentID := "agent-test-1"
	now := time.Now().UTC()

	// Add agent
	conn := &AgentConnection{
		AgentID:     agentID,
		HostID:      hostID,
		HostName:    "test-host",
		ConnectedAt: now,
		LastSeen:    now,
		Status:      "connected",
		Health:      protocol.HealthStatusHealthy,
		Info: &protocol.AgentInfo{
			AgentID:  agentID,
			Hostname: "docker-host-1",
			Version:  "1.0.0",
		},
	}

	s.mu.Lock()
	s.agents[agentID] = conn
	s.hostIndex[hostID] = agentID
	s.mu.Unlock()

	// GetAgent
	got, ok := s.GetAgent(agentID)
	if !ok {
		t.Fatal("agent should be found")
	}
	if got.AgentID != agentID {
		t.Errorf("AgentID = %q, want %q", got.AgentID, agentID)
	}

	// GetAgentByHost
	got, ok = s.GetAgentByHost(hostID)
	if !ok {
		t.Fatal("agent should be found by host")
	}
	if got.HostName != "test-host" {
		t.Errorf("HostName = %q, want %q", got.HostName, "test-host")
	}

	// IsAgentConnected
	if !s.IsAgentConnected(hostID) {
		t.Error("host should be connected")
	}
	if s.IsAgentConnected(uuid.New()) {
		t.Error("unknown host should not be connected")
	}

	// AgentCount
	if s.AgentCount() != 1 {
		t.Errorf("AgentCount() = %d, want 1", s.AgentCount())
	}

	// ConnectedCount
	if s.ConnectedCount() != 1 {
		t.Errorf("ConnectedCount() = %d, want 1", s.ConnectedCount())
	}

	// ListAgents
	agents := s.ListAgents()
	if len(agents) != 1 {
		t.Errorf("ListAgents() = %d, want 1", len(agents))
	}

	// GetAgentHealth
	health, err := s.GetAgentHealth(hostID)
	if err != nil {
		t.Fatalf("GetAgentHealth() error: %v", err)
	}
	if health != protocol.HealthStatusHealthy {
		t.Errorf("Health = %q, want %q", health, protocol.HealthStatusHealthy)
	}

	// GetAgentHealth for unknown host
	_, err = s.GetAgentHealth(uuid.New())
	if err == nil {
		t.Error("GetAgentHealth() should return error for unknown host")
	}
}

func TestAgentConnection_MultipleAgents(t *testing.T) {
	s := &Server{
		agents:    make(map[string]*AgentConnection),
		hostIndex: make(map[uuid.UUID]string),
	}

	// Add 3 agents
	for i := 0; i < 3; i++ {
		hostID := uuid.New()
		agentID := uuid.New().String()
		now := time.Now().UTC()

		s.mu.Lock()
		s.agents[agentID] = &AgentConnection{
			AgentID:     agentID,
			HostID:      hostID,
			ConnectedAt: now,
			LastSeen:    now,
			Status:      "connected",
			Health:      protocol.HealthStatusHealthy,
		}
		s.hostIndex[hostID] = agentID
		s.mu.Unlock()
	}

	if s.AgentCount() != 3 {
		t.Errorf("AgentCount() = %d, want 3", s.AgentCount())
	}
	if s.ConnectedCount() != 3 {
		t.Errorf("ConnectedCount() = %d, want 3", s.ConnectedCount())
	}
}

func TestAgentConnection_ReplacesOldAgent(t *testing.T) {
	s := &Server{
		agents:    make(map[string]*AgentConnection),
		hostIndex: make(map[uuid.UUID]string),
	}

	hostID := uuid.New()

	// First agent for this host
	s.mu.Lock()
	s.agents["old-agent"] = &AgentConnection{
		AgentID: "old-agent",
		HostID:  hostID,
		Status:  "connected",
	}
	s.hostIndex[hostID] = "old-agent"
	s.mu.Unlock()

	// Replace with new agent (simulating re-registration)
	s.mu.Lock()
	if oldAgentID, exists := s.hostIndex[hostID]; exists {
		delete(s.agents, oldAgentID)
	}
	s.agents["new-agent"] = &AgentConnection{
		AgentID: "new-agent",
		HostID:  hostID,
		Status:  "connected",
	}
	s.hostIndex[hostID] = "new-agent"
	s.mu.Unlock()

	// Only new agent should exist
	if s.AgentCount() != 1 {
		t.Errorf("AgentCount() = %d, want 1", s.AgentCount())
	}
	_, ok := s.GetAgent("old-agent")
	if ok {
		t.Error("old agent should be removed")
	}
	got, ok := s.GetAgent("new-agent")
	if !ok {
		t.Fatal("new agent should exist")
	}
	if got.HostID != hostID {
		t.Error("new agent should have same host ID")
	}
}

func TestAgentConnection_DegradedStatus(t *testing.T) {
	s := &Server{
		agents:    make(map[string]*AgentConnection),
		hostIndex: make(map[uuid.UUID]string),
	}

	hostID := uuid.New()
	s.mu.Lock()
	s.agents["degraded-agent"] = &AgentConnection{
		AgentID: "degraded-agent",
		HostID:  hostID,
		Status:  "degraded",
		Health:  protocol.HealthStatusDegraded,
	}
	s.hostIndex[hostID] = "degraded-agent"
	s.mu.Unlock()

	// Connected count should not include degraded
	if s.ConnectedCount() != 0 {
		t.Errorf("ConnectedCount() = %d, want 0 (degraded agents excluded)", s.ConnectedCount())
	}
	if s.AgentCount() != 1 {
		t.Errorf("AgentCount() = %d, want 1", s.AgentCount())
	}
}

// ============================================================================
// Stale Agent Cleanup Tests
// ============================================================================

func TestCleanupStaleAgents(t *testing.T) {
	hostRepo := &mockHostRepo{}
	s := &Server{
		agents:    make(map[string]*AgentConnection),
		hostIndex: make(map[uuid.UUID]string),
		hostRepo:  hostRepo,
		log:       testLogger().Named("gateway"),
		config: ServerConfig{
			HeartbeatTimeout: 90 * time.Second,
		},
	}

	// Add a stale agent (last seen 2 minutes ago)
	staleHostID := uuid.New()
	s.mu.Lock()
	s.agents["stale-agent"] = &AgentConnection{
		AgentID:  "stale-agent",
		HostID:   staleHostID,
		LastSeen: time.Now().UTC().Add(-2 * time.Minute),
		Status:   "connected",
	}
	s.hostIndex[staleHostID] = "stale-agent"
	s.mu.Unlock()

	// Add a fresh agent
	freshHostID := uuid.New()
	s.mu.Lock()
	s.agents["fresh-agent"] = &AgentConnection{
		AgentID:  "fresh-agent",
		HostID:   freshHostID,
		LastSeen: time.Now().UTC(),
		Status:   "connected",
	}
	s.hostIndex[freshHostID] = "fresh-agent"
	s.mu.Unlock()

	s.cleanupStaleAgents()

	// Allow goroutine to run for UpdateStatus
	time.Sleep(50 * time.Millisecond)

	if s.AgentCount() != 1 {
		t.Errorf("AgentCount() = %d, want 1 (stale removed)", s.AgentCount())
	}
	_, ok := s.GetAgent("stale-agent")
	if ok {
		t.Error("stale agent should be removed")
	}
	_, ok = s.GetAgent("fresh-agent")
	if !ok {
		t.Error("fresh agent should remain")
	}
}

// ============================================================================
// Registration Serialization Tests
// ============================================================================

func TestRegistration_JSONFlow(t *testing.T) {
	// Simulates the JSON flow that happens over NATS
	// Agent sends RegistrationRequest → Gateway responds with RegistrationResponse

	req := protocol.RegistrationRequest{
		Token: "test-token",
		Info: protocol.AgentInfo{
			AgentID:    "agent-reg",
			Version:    "1.0.0",
			Hostname:   "docker-host",
			OS:         "linux",
			Arch:       "amd64",
			DockerHost: "unix:///var/run/docker.sock",
		},
	}

	// Marshal (what agent sends)
	reqData, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal request: %v", err)
	}

	// Unmarshal (what gateway receives)
	var receivedReq protocol.RegistrationRequest
	if err := json.Unmarshal(reqData, &receivedReq); err != nil {
		t.Fatalf("Unmarshal request: %v", err)
	}

	if receivedReq.Token != "test-token" {
		t.Errorf("Token = %q, want %q", receivedReq.Token, "test-token")
	}

	// Gateway creates response
	resp := protocol.RegistrationResponse{
		Success:           true,
		AgentID:           receivedReq.Info.AgentID,
		HeartbeatInterval: 30 * time.Second,
		InventoryInterval: 5 * time.Minute,
		Config: protocol.AgentConfig{
			LogLevel:         "info",
			MetricsEnabled:   true,
			MetricsInterval:  60,
			MaxConcurrentOps: 5,
		},
	}

	// Marshal (what gateway sends back)
	respData, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal response: %v", err)
	}

	// Unmarshal (what agent receives)
	var receivedResp protocol.RegistrationResponse
	if err := json.Unmarshal(respData, &receivedResp); err != nil {
		t.Fatalf("Unmarshal response: %v", err)
	}

	if !receivedResp.Success {
		t.Error("response should be successful")
	}
	if receivedResp.AgentID != "agent-reg" {
		t.Errorf("AgentID = %q, want %q", receivedResp.AgentID, "agent-reg")
	}
	if receivedResp.Config.MaxConcurrentOps != 5 {
		t.Errorf("MaxConcurrentOps = %d, want 5", receivedResp.Config.MaxConcurrentOps)
	}
}

// ============================================================================
// Heartbeat JSON Flow Tests
// ============================================================================

func TestHeartbeat_JSONFlow(t *testing.T) {
	// Agent sends heartbeat
	hb := protocol.Heartbeat{
		AgentID:   "hb-agent",
		Timestamp: time.Now().UTC(),
		Uptime:    1 * time.Hour,
		Health:    protocol.HealthStatusHealthy,
		Stats: &protocol.QuickStats{
			ContainersRunning: 5,
			ContainersTotal:   8,
		},
	}

	hbData, err := json.Marshal(hb)
	if err != nil {
		t.Fatalf("Marshal heartbeat: %v", err)
	}

	var receivedHB protocol.Heartbeat
	if err := json.Unmarshal(hbData, &receivedHB); err != nil {
		t.Fatalf("Unmarshal heartbeat: %v", err)
	}

	if receivedHB.AgentID != "hb-agent" {
		t.Errorf("AgentID = %q, want %q", receivedHB.AgentID, "hb-agent")
	}
	if receivedHB.Stats.ContainersRunning != 5 {
		t.Errorf("ContainersRunning = %d, want 5", receivedHB.Stats.ContainersRunning)
	}

	// Gateway responds
	resp := protocol.HeartbeatResponse{
		Acknowledged: true,
		ServerTime:   time.Now().UTC(),
		PendingJobs:  0,
	}

	respData, _ := json.Marshal(resp)
	var receivedResp protocol.HeartbeatResponse
	json.Unmarshal(respData, &receivedResp)

	if !receivedResp.Acknowledged {
		t.Error("should be acknowledged")
	}
}

// ============================================================================
// Command Dispatch JSON Flow Tests
// ============================================================================

func TestCommand_JSONDispatchFlow(t *testing.T) {
	// Master creates command for agent
	cmd := protocol.Command{
		ID:       uuid.New().String(),
		Type:     protocol.CmdContainerStop,
		HostID:   uuid.New().String(),
		Priority: protocol.PriorityNormal,
		Timeout:  30 * time.Second,
		ReplyTo:  "usulnet.reply." + uuid.New().String(),
		Params: protocol.CommandParams{
			ContainerID: "abc123",
			StopTimeout: intPtr(10),
		},
	}

	// Serialize (send over NATS)
	cmdData, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("Marshal command: %v", err)
	}

	// Agent receives and deserializes
	var receivedCmd protocol.Command
	if err := json.Unmarshal(cmdData, &receivedCmd); err != nil {
		t.Fatalf("Unmarshal command: %v", err)
	}

	if receivedCmd.Type != protocol.CmdContainerStop {
		t.Errorf("Type = %q, want %q", receivedCmd.Type, protocol.CmdContainerStop)
	}
	if receivedCmd.Params.ContainerID != "abc123" {
		t.Errorf("ContainerID = %q, want %q", receivedCmd.Params.ContainerID, "abc123")
	}
	if *receivedCmd.Params.StopTimeout != 10 {
		t.Errorf("StopTimeout = %d, want 10", *receivedCmd.Params.StopTimeout)
	}

	// Agent executes and sends result
	result := protocol.NewCommandResult(receivedCmd.ID, map[string]string{
		"status": "stopped",
	})
	result.StartedAt = time.Now().UTC().Add(-500 * time.Millisecond)
	result.Duration = 500 * time.Millisecond

	resultData, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal result: %v", err)
	}

	// Master receives result
	var receivedResult protocol.CommandResult
	if err := json.Unmarshal(resultData, &receivedResult); err != nil {
		t.Fatalf("Unmarshal result: %v", err)
	}

	if receivedResult.CommandID != cmd.ID {
		t.Errorf("CommandID = %q, want %q", receivedResult.CommandID, cmd.ID)
	}
	if receivedResult.Status != protocol.CommandStatusCompleted {
		t.Errorf("Status = %q, want %q", receivedResult.Status, protocol.CommandStatusCompleted)
	}
}

func TestCommand_ErrorFlow(t *testing.T) {
	cmdID := uuid.New().String()

	// Agent encounters error
	cmdErr := &protocol.CommandError{
		Code:        protocol.ErrCodeCommandFailed,
		Message:     "container not found",
		DockerError: "No such container: xyz",
	}
	result := protocol.NewCommandResultError(cmdID, cmdErr)

	// Round-trip
	data, _ := json.Marshal(result)
	var decoded protocol.CommandResult
	json.Unmarshal(data, &decoded)

	if decoded.Status != protocol.CommandStatusFailed {
		t.Errorf("Status = %q, want %q", decoded.Status, protocol.CommandStatusFailed)
	}
	if decoded.Error.Code != protocol.ErrCodeCommandFailed {
		t.Errorf("Error.Code = %q, want %q", decoded.Error.Code, protocol.ErrCodeCommandFailed)
	}
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestServer_ConcurrentAccess(t *testing.T) {
	s := &Server{
		agents:    make(map[string]*AgentConnection),
		hostIndex: make(map[uuid.UUID]string),
	}

	var wg sync.WaitGroup
	const n = 50

	// Concurrent writes
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			hostID := uuid.New()
			agentID := uuid.New().String()
			s.mu.Lock()
			s.agents[agentID] = &AgentConnection{
				AgentID:  agentID,
				HostID:   hostID,
				LastSeen: time.Now().UTC(),
				Status:   "connected",
				Health:   protocol.HealthStatusHealthy,
			}
			s.hostIndex[hostID] = agentID
			s.mu.Unlock()
		}()
	}
	wg.Wait()

	// Concurrent reads
	wg.Add(n * 3)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			s.AgentCount()
		}()
		go func() {
			defer wg.Done()
			s.ConnectedCount()
		}()
		go func() {
			defer wg.Done()
			s.ListAgents()
		}()
	}
	wg.Wait()

	if s.AgentCount() != n {
		t.Errorf("AgentCount() = %d, want %d", s.AgentCount(), n)
	}
}

// ============================================================================
// Heartbeat Monitor Tests
// ============================================================================

func TestHeartbeatMonitor_RecordHeartbeat(t *testing.T) {
	s := &Server{
		agents:    make(map[string]*AgentConnection),
		hostIndex: make(map[uuid.UUID]string),
	}

	cfg := DefaultHeartbeatMonitorConfig()
	monitor := NewHeartbeatMonitor(s, cfg, testLogger())

	hostID := uuid.New()
	hb := &protocol.Heartbeat{
		AgentID:   "hb-test",
		Timestamp: time.Now().UTC(),
		Health:    protocol.HealthStatusHealthy,
	}

	monitor.RecordHeartbeat("hb-test", hostID, hb)

	stats, ok := monitor.GetAgentStats("hb-test")
	if !ok {
		t.Fatal("stats should be found")
	}
	if stats.TotalHeartbeats != 1 {
		t.Errorf("TotalHeartbeats = %d, want 1", stats.TotalHeartbeats)
	}
	if stats.ConsecutiveMisses != 0 {
		t.Errorf("ConsecutiveMisses = %d, want 0", stats.ConsecutiveMisses)
	}
	if stats.LastHealth != protocol.HealthStatusHealthy {
		t.Errorf("LastHealth = %q, want %q", stats.LastHealth, protocol.HealthStatusHealthy)
	}
}

func TestHeartbeatMonitor_MultipleHeartbeats(t *testing.T) {
	s := &Server{
		agents:    make(map[string]*AgentConnection),
		hostIndex: make(map[uuid.UUID]string),
	}

	cfg := DefaultHeartbeatMonitorConfig()
	monitor := NewHeartbeatMonitor(s, cfg, testLogger())

	hostID := uuid.New()
	for i := 0; i < 10; i++ {
		hb := &protocol.Heartbeat{
			AgentID:   "multi-hb",
			Timestamp: time.Now().UTC(),
			Health:    protocol.HealthStatusHealthy,
		}
		monitor.RecordHeartbeat("multi-hb", hostID, hb)
	}

	stats, _ := monitor.GetAgentStats("multi-hb")
	if stats.TotalHeartbeats != 10 {
		t.Errorf("TotalHeartbeats = %d, want 10", stats.TotalHeartbeats)
	}
}

func TestHeartbeatMonitor_HealthTransitions(t *testing.T) {
	s := &Server{
		agents:    make(map[string]*AgentConnection),
		hostIndex: make(map[uuid.UUID]string),
	}

	cfg := DefaultHeartbeatMonitorConfig()
	monitor := NewHeartbeatMonitor(s, cfg, testLogger())

	hostID := uuid.New()

	// Healthy
	monitor.RecordHeartbeat("transition-agent", hostID, &protocol.Heartbeat{
		AgentID:   "transition-agent",
		Timestamp: time.Now().UTC(),
		Health:    protocol.HealthStatusHealthy,
	})

	// Degraded (health change)
	monitor.RecordHeartbeat("transition-agent", hostID, &protocol.Heartbeat{
		AgentID:   "transition-agent",
		Timestamp: time.Now().UTC(),
		Health:    protocol.HealthStatusDegraded,
	})

	stats, _ := monitor.GetAgentStats("transition-agent")
	if stats.HealthChanges != 2 { // Unknown→Healthy, Healthy→Degraded
		t.Errorf("HealthChanges = %d, want 2", stats.HealthChanges)
	}
	if stats.LastHealth != protocol.HealthStatusDegraded {
		t.Errorf("LastHealth = %q, want %q", stats.LastHealth, protocol.HealthStatusDegraded)
	}
}

func TestHeartbeatMonitor_CheckAgentHealth(t *testing.T) {
	s := &Server{
		agents:    make(map[string]*AgentConnection),
		hostIndex: make(map[uuid.UUID]string),
	}

	cfg := HeartbeatMonitorConfig{
		WarningThreshold:  60 * time.Second,
		CriticalThreshold: 90 * time.Second,
		DeadThreshold:     180 * time.Second,
	}
	monitor := NewHeartbeatMonitor(s, cfg, testLogger())

	var healthChanges []struct {
		hostID    uuid.UUID
		oldHealth protocol.HealthStatus
		newHealth protocol.HealthStatus
	}
	monitor.OnHealthChange(func(hostID uuid.UUID, old, new protocol.HealthStatus) {
		healthChanges = append(healthChanges, struct {
			hostID    uuid.UUID
			oldHealth protocol.HealthStatus
			newHealth protocol.HealthStatus
		}{hostID, old, new})
	})

	hostID := uuid.New()
	now := time.Now().UTC()

	// Fresh agent - should be healthy
	freshAgent := &AgentConnection{
		AgentID:  "fresh",
		HostID:   hostID,
		LastSeen: now,
		Health:   protocol.HealthStatusHealthy,
	}
	monitor.checkAgentHealth(freshAgent, now)
	// No health change expected (was already healthy)

	// Stale agent - should become degraded
	staleAgent := &AgentConnection{
		AgentID:  "stale",
		HostID:   uuid.New(),
		LastSeen: now.Add(-70 * time.Second), // past warning threshold
		Health:   protocol.HealthStatusHealthy,
	}
	monitor.checkAgentHealth(staleAgent, now)

	if len(healthChanges) != 1 {
		t.Fatalf("expected 1 health change, got %d", len(healthChanges))
	}

	// Critical agent
	criticalAgent := &AgentConnection{
		AgentID:  "critical",
		HostID:   uuid.New(),
		LastSeen: now.Add(-100 * time.Second), // past critical threshold
		Health:   protocol.HealthStatusHealthy,
	}
	monitor.checkAgentHealth(criticalAgent, now)

	if len(healthChanges) != 2 {
		t.Fatalf("expected 2 health changes, got %d", len(healthChanges))
	}
}

func TestHeartbeatMonitor_AgentLostCallback(t *testing.T) {
	s := &Server{
		agents:    make(map[string]*AgentConnection),
		hostIndex: make(map[uuid.UUID]string),
	}

	cfg := HeartbeatMonitorConfig{
		WarningThreshold:  60 * time.Second,
		CriticalThreshold: 90 * time.Second,
		DeadThreshold:     180 * time.Second,
	}
	monitor := NewHeartbeatMonitor(s, cfg, testLogger())

	var lostHosts []uuid.UUID
	monitor.OnAgentLost(func(hostID uuid.UUID, lastSeen time.Time) {
		lostHosts = append(lostHosts, hostID)
	})

	now := time.Now().UTC()
	hostID := uuid.New()

	deadAgent := &AgentConnection{
		AgentID:  "dead",
		HostID:   hostID,
		LastSeen: now.Add(-200 * time.Second), // past dead threshold
		Health:   protocol.HealthStatusHealthy,
	}
	monitor.checkAgentHealth(deadAgent, now)

	if len(lostHosts) != 1 {
		t.Fatalf("expected 1 lost host, got %d", len(lostHosts))
	}
	if lostHosts[0] != hostID {
		t.Error("lost host ID should match")
	}
}

func TestHeartbeatMonitor_RemoveAgent(t *testing.T) {
	s := &Server{
		agents:    make(map[string]*AgentConnection),
		hostIndex: make(map[uuid.UUID]string),
	}

	cfg := DefaultHeartbeatMonitorConfig()
	monitor := NewHeartbeatMonitor(s, cfg, testLogger())

	hostID := uuid.New()
	monitor.RecordHeartbeat("remove-test", hostID, &protocol.Heartbeat{
		AgentID:   "remove-test",
		Timestamp: time.Now().UTC(),
		Health:    protocol.HealthStatusHealthy,
	})

	_, ok := monitor.GetAgentStats("remove-test")
	if !ok {
		t.Fatal("stats should exist")
	}

	monitor.RemoveAgent("remove-test")

	_, ok = monitor.GetAgentStats("remove-test")
	if ok {
		t.Error("stats should be removed")
	}
}

func TestHeartbeatMonitor_Summary(t *testing.T) {
	s := &Server{
		agents:    make(map[string]*AgentConnection),
		hostIndex: make(map[uuid.UUID]string),
	}

	cfg := DefaultHeartbeatMonitorConfig()
	monitor := NewHeartbeatMonitor(s, cfg, testLogger())

	// Add agents with different health states
	monitor.RecordHeartbeat("healthy-1", uuid.New(), &protocol.Heartbeat{
		AgentID: "healthy-1", Timestamp: time.Now().UTC(), Health: protocol.HealthStatusHealthy,
	})
	monitor.RecordHeartbeat("healthy-2", uuid.New(), &protocol.Heartbeat{
		AgentID: "healthy-2", Timestamp: time.Now().UTC(), Health: protocol.HealthStatusHealthy,
	})
	monitor.RecordHeartbeat("degraded-1", uuid.New(), &protocol.Heartbeat{
		AgentID: "degraded-1", Timestamp: time.Now().UTC(), Health: protocol.HealthStatusDegraded,
	})

	summary := monitor.GetSummary()
	if summary.TotalAgents != 3 {
		t.Errorf("TotalAgents = %d, want 3", summary.TotalAgents)
	}
	if summary.HealthyAgents != 2 {
		t.Errorf("HealthyAgents = %d, want 2", summary.HealthyAgents)
	}
	if summary.DegradedAgents != 1 {
		t.Errorf("DegradedAgents = %d, want 1", summary.DegradedAgents)
	}
}

func TestHeartbeatMonitor_SuccessRate(t *testing.T) {
	s := &Server{
		agents:    make(map[string]*AgentConnection),
		hostIndex: make(map[uuid.UUID]string),
	}

	cfg := DefaultHeartbeatMonitorConfig()
	monitor := NewHeartbeatMonitor(s, cfg, testLogger())

	hostID := uuid.New()

	// Record 8 heartbeats
	for i := 0; i < 8; i++ {
		monitor.RecordHeartbeat("rate-agent", hostID, &protocol.Heartbeat{
			AgentID: "rate-agent", Timestamp: time.Now().UTC(), Health: protocol.HealthStatusHealthy,
		})
	}

	// Manually increment missed heartbeats
	monitor.incrementMissedHeartbeat("rate-agent")
	monitor.incrementMissedHeartbeat("rate-agent")

	stats, _ := monitor.GetAgentStats("rate-agent")
	if stats.TotalHeartbeats != 8 {
		t.Errorf("TotalHeartbeats = %d, want 8", stats.TotalHeartbeats)
	}
	if stats.MissedHeartbeats != 2 {
		t.Errorf("MissedHeartbeats = %d, want 2", stats.MissedHeartbeats)
	}
	// 8/(8+2) = 80%
	if stats.SuccessRate != 80 {
		t.Errorf("SuccessRate = %f, want 80", stats.SuccessRate)
	}
}

// ============================================================================
// ServerConfig Tests
// ============================================================================

func TestDefaultServerConfig(t *testing.T) {
	cfg := DefaultServerConfig()

	if cfg.HeartbeatInterval != 30*time.Second {
		t.Errorf("HeartbeatInterval = %v, want 30s", cfg.HeartbeatInterval)
	}
	if cfg.HeartbeatTimeout != 90*time.Second {
		t.Errorf("HeartbeatTimeout = %v, want 90s", cfg.HeartbeatTimeout)
	}
	if cfg.InventoryInterval != 5*time.Minute {
		t.Errorf("InventoryInterval = %v, want 5m", cfg.InventoryInterval)
	}
	if cfg.CleanupInterval != 60*time.Second {
		t.Errorf("CleanupInterval = %v, want 60s", cfg.CleanupInterval)
	}
	if cfg.CommandTimeout != 30*time.Second {
		t.Errorf("CommandTimeout = %v, want 30s", cfg.CommandTimeout)
	}
}

// ============================================================================
// Mock implementations
// ============================================================================

type mockHostRepo struct {
	mu      sync.Mutex
	updates []mockStatusUpdate
}

type mockStatusUpdate struct {
	HostID uuid.UUID
	Status string
}

func (m *mockHostRepo) GetByAgentToken(_ context.Context, token string) (*HostInfo, error) {
	if token == "valid-token" {
		return &HostInfo{
			ID:     uuid.New(),
			Name:   "test-host",
			Status: "pending",
		}, nil
	}
	return nil, fmt.Errorf("invalid token")
}

func (m *mockHostRepo) UpdateStatus(_ context.Context, hostID uuid.UUID, status string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updates = append(m.updates, mockStatusUpdate{HostID: hostID, Status: status})
	return nil
}

func (m *mockHostRepo) UpdateAgentInfo(_ context.Context, _ uuid.UUID, _ *protocol.AgentInfo) error {
	return nil
}

// ============================================================================
// Test Helpers
// ============================================================================

func testLogger() *logger.Logger {
	log, _ := logger.New("error", "console")
	return log
}

func intPtr(i int) *int {
	return &i
}
