// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package gateway provides heartbeat monitoring for agent connections.
package gateway

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// HeartbeatMonitor monitors agent heartbeats and tracks health status.
type HeartbeatMonitor struct {
	server    *Server
	log       *logger.Logger

	// Thresholds
	warningThreshold  time.Duration // Time before warning
	criticalThreshold time.Duration // Time before marking unhealthy
	deadThreshold     time.Duration // Time before removing

	// Callbacks
	onHealthChange func(hostID uuid.UUID, oldHealth, newHealth protocol.HealthStatus)
	onAgentLost    func(hostID uuid.UUID, lastSeen time.Time)

	// Stats tracking
	stats     map[string]*agentStats
	statsMu   sync.RWMutex
}

// agentStats tracks per-agent statistics.
type agentStats struct {
	AgentID           string
	HostID            uuid.UUID
	TotalHeartbeats   int64
	MissedHeartbeats  int64
	LastHeartbeat     time.Time
	AverageLatency    time.Duration
	latencySum        time.Duration
	latencyCount      int64
	LastHealth        protocol.HealthStatus
	HealthChanges     int
	ConsecutiveMisses int
}

// HeartbeatMonitorConfig configures the heartbeat monitor.
type HeartbeatMonitorConfig struct {
	WarningThreshold  time.Duration
	CriticalThreshold time.Duration
	DeadThreshold     time.Duration
	CheckInterval     time.Duration
}

// DefaultHeartbeatMonitorConfig returns default configuration.
func DefaultHeartbeatMonitorConfig() HeartbeatMonitorConfig {
	return HeartbeatMonitorConfig{
		WarningThreshold:  60 * time.Second,
		CriticalThreshold: 90 * time.Second,
		DeadThreshold:     180 * time.Second,
		CheckInterval:     30 * time.Second,
	}
}

// NewHeartbeatMonitor creates a new heartbeat monitor.
func NewHeartbeatMonitor(server *Server, cfg HeartbeatMonitorConfig, log *logger.Logger) *HeartbeatMonitor {
	return &HeartbeatMonitor{
		server:            server,
		log:               log.Named("heartbeat-monitor"),
		warningThreshold:  cfg.WarningThreshold,
		criticalThreshold: cfg.CriticalThreshold,
		deadThreshold:     cfg.DeadThreshold,
		stats:             make(map[string]*agentStats),
	}
}

// OnHealthChange sets callback for health status changes.
func (m *HeartbeatMonitor) OnHealthChange(fn func(hostID uuid.UUID, oldHealth, newHealth protocol.HealthStatus)) {
	m.onHealthChange = fn
}

// OnAgentLost sets callback for lost agents.
func (m *HeartbeatMonitor) OnAgentLost(fn func(hostID uuid.UUID, lastSeen time.Time)) {
	m.onAgentLost = fn
}

// Start starts the heartbeat monitor.
func (m *HeartbeatMonitor) Start(ctx context.Context, checkInterval time.Duration) {
	go m.monitorLoop(ctx, checkInterval)
}

// monitorLoop periodically checks agent health.
func (m *HeartbeatMonitor) monitorLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkAllAgents()
		}
	}
}

// checkAllAgents checks health of all agents.
func (m *HeartbeatMonitor) checkAllAgents() {
	now := time.Now().UTC()
	agents := m.server.ListAgents()

	for _, agent := range agents {
		m.checkAgentHealth(agent, now)
	}
}

// checkAgentHealth checks a single agent's health.
func (m *HeartbeatMonitor) checkAgentHealth(agent *AgentConnection, now time.Time) {
	sinceLastSeen := now.Sub(agent.LastSeen)
	oldHealth := agent.Health
	var newHealth protocol.HealthStatus

	switch {
	case sinceLastSeen >= m.deadThreshold:
		// Agent is dead
		m.log.Warn("Agent presumed dead",
			"agent_id", agent.AgentID,
			"host_id", agent.HostID,
			"last_seen", agent.LastSeen,
			"silence_duration", sinceLastSeen,
		)
		if m.onAgentLost != nil {
			m.onAgentLost(agent.HostID, agent.LastSeen)
		}
		newHealth = protocol.HealthStatusUnknown

	case sinceLastSeen >= m.criticalThreshold:
		newHealth = protocol.HealthStatusUnhealthy
		m.incrementMissedHeartbeat(agent.AgentID)

	case sinceLastSeen >= m.warningThreshold:
		newHealth = protocol.HealthStatusDegraded
		m.incrementMissedHeartbeat(agent.AgentID)

	default:
		newHealth = protocol.HealthStatusHealthy
		m.resetMissedHeartbeats(agent.AgentID)
	}

	// Notify on health change
	if oldHealth != newHealth {
		m.log.Info("Agent health changed",
			"agent_id", agent.AgentID,
			"host_id", agent.HostID,
			"old_health", oldHealth,
			"new_health", newHealth,
		)

		m.recordHealthChange(agent.AgentID)

		if m.onHealthChange != nil {
			m.onHealthChange(agent.HostID, oldHealth, newHealth)
		}
	}
}

// RecordHeartbeat records a received heartbeat.
func (m *HeartbeatMonitor) RecordHeartbeat(agentID string, hostID uuid.UUID, hb *protocol.Heartbeat) {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()

	stats, exists := m.stats[agentID]
	if !exists {
		stats = &agentStats{
			AgentID:    agentID,
			HostID:     hostID,
			LastHealth: protocol.HealthStatusUnknown,
		}
		m.stats[agentID] = stats
	}

	now := time.Now().UTC()

	// Calculate latency (difference between heartbeat timestamp and now)
	latency := now.Sub(hb.Timestamp)
	stats.latencySum += latency
	stats.latencyCount++
	stats.AverageLatency = stats.latencySum / time.Duration(stats.latencyCount)

	stats.TotalHeartbeats++
	stats.LastHeartbeat = now
	stats.ConsecutiveMisses = 0

	// Track health changes
	if stats.LastHealth != hb.Health {
		stats.HealthChanges++
		stats.LastHealth = hb.Health
	}
}

// incrementMissedHeartbeat increments missed heartbeat counter.
func (m *HeartbeatMonitor) incrementMissedHeartbeat(agentID string) {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()

	if stats, exists := m.stats[agentID]; exists {
		stats.MissedHeartbeats++
		stats.ConsecutiveMisses++
	}
}

// resetMissedHeartbeats resets consecutive miss counter.
func (m *HeartbeatMonitor) resetMissedHeartbeats(agentID string) {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()

	if stats, exists := m.stats[agentID]; exists {
		stats.ConsecutiveMisses = 0
	}
}

// recordHealthChange records a health status change.
func (m *HeartbeatMonitor) recordHealthChange(agentID string) {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()

	if stats, exists := m.stats[agentID]; exists {
		stats.HealthChanges++
	}
}

// RemoveAgent removes an agent from monitoring.
func (m *HeartbeatMonitor) RemoveAgent(agentID string) {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	delete(m.stats, agentID)
}

// AgentStats returns statistics for an agent.
type AgentHeartbeatStats struct {
	AgentID           string                `json:"agent_id"`
	HostID            uuid.UUID             `json:"host_id"`
	TotalHeartbeats   int64                 `json:"total_heartbeats"`
	MissedHeartbeats  int64                 `json:"missed_heartbeats"`
	LastHeartbeat     time.Time             `json:"last_heartbeat"`
	AverageLatency    time.Duration         `json:"average_latency"`
	LastHealth        protocol.HealthStatus `json:"last_health"`
	HealthChanges     int                   `json:"health_changes"`
	ConsecutiveMisses int                   `json:"consecutive_misses"`
	SuccessRate       float64               `json:"success_rate"`
}

// GetAgentStats returns statistics for a specific agent.
func (m *HeartbeatMonitor) GetAgentStats(agentID string) (*AgentHeartbeatStats, bool) {
	m.statsMu.RLock()
	defer m.statsMu.RUnlock()

	stats, exists := m.stats[agentID]
	if !exists {
		return nil, false
	}

	total := stats.TotalHeartbeats + stats.MissedHeartbeats
	var successRate float64
	if total > 0 {
		successRate = float64(stats.TotalHeartbeats) / float64(total) * 100
	}

	return &AgentHeartbeatStats{
		AgentID:           stats.AgentID,
		HostID:            stats.HostID,
		TotalHeartbeats:   stats.TotalHeartbeats,
		MissedHeartbeats:  stats.MissedHeartbeats,
		LastHeartbeat:     stats.LastHeartbeat,
		AverageLatency:    stats.AverageLatency,
		LastHealth:        stats.LastHealth,
		HealthChanges:     stats.HealthChanges,
		ConsecutiveMisses: stats.ConsecutiveMisses,
		SuccessRate:       successRate,
	}, true
}

// GetAllStats returns statistics for all agents.
func (m *HeartbeatMonitor) GetAllStats() []AgentHeartbeatStats {
	m.statsMu.RLock()
	defer m.statsMu.RUnlock()

	result := make([]AgentHeartbeatStats, 0, len(m.stats))
	for _, stats := range m.stats {
		total := stats.TotalHeartbeats + stats.MissedHeartbeats
		var successRate float64
		if total > 0 {
			successRate = float64(stats.TotalHeartbeats) / float64(total) * 100
		}

		result = append(result, AgentHeartbeatStats{
			AgentID:           stats.AgentID,
			HostID:            stats.HostID,
			TotalHeartbeats:   stats.TotalHeartbeats,
			MissedHeartbeats:  stats.MissedHeartbeats,
			LastHeartbeat:     stats.LastHeartbeat,
			AverageLatency:    stats.AverageLatency,
			LastHealth:        stats.LastHealth,
			HealthChanges:     stats.HealthChanges,
			ConsecutiveMisses: stats.ConsecutiveMisses,
			SuccessRate:       successRate,
		})
	}

	return result
}

// Summary returns a summary of all agent health.
type HeartbeatSummary struct {
	TotalAgents     int     `json:"total_agents"`
	HealthyAgents   int     `json:"healthy_agents"`
	DegradedAgents  int     `json:"degraded_agents"`
	UnhealthyAgents int     `json:"unhealthy_agents"`
	AverageLatency  time.Duration `json:"average_latency"`
	OverallSuccessRate float64 `json:"overall_success_rate"`
}

// GetSummary returns a summary of all agent health.
func (m *HeartbeatMonitor) GetSummary() HeartbeatSummary {
	m.statsMu.RLock()
	defer m.statsMu.RUnlock()

	summary := HeartbeatSummary{
		TotalAgents: len(m.stats),
	}

	var totalLatency time.Duration
	var totalHeartbeats, totalMissed int64

	for _, stats := range m.stats {
		totalLatency += stats.AverageLatency
		totalHeartbeats += stats.TotalHeartbeats
		totalMissed += stats.MissedHeartbeats

		switch stats.LastHealth {
		case protocol.HealthStatusHealthy:
			summary.HealthyAgents++
		case protocol.HealthStatusDegraded:
			summary.DegradedAgents++
		default:
			summary.UnhealthyAgents++
		}
	}

	if summary.TotalAgents > 0 {
		summary.AverageLatency = totalLatency / time.Duration(summary.TotalAgents)
	}

	total := totalHeartbeats + totalMissed
	if total > 0 {
		summary.OverallSuccessRate = float64(totalHeartbeats) / float64(total) * 100
	}

	return summary
}
