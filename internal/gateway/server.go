// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package gateway provides the central server for managing agent connections
// and routing commands/events between the usulnet platform and remote agents.
package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"

	inats "github.com/fr4nsys/usulnet/internal/nats"
	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// HostRepository defines the interface for host data access.
// This allows the gateway to verify agent tokens and update host status.
// Note: Token validation uses hash comparison - the repository receives the raw token
// and compares against the stored hash internally.
type HostRepository interface {
	GetByAgentToken(ctx context.Context, token string) (*HostInfo, error)
	UpdateStatus(ctx context.Context, hostID uuid.UUID, status string, lastSeen time.Time) error
	UpdateAgentInfo(ctx context.Context, hostID uuid.UUID, info *protocol.AgentInfo) error
}

// HostInfo contains minimal host information needed by the gateway.
// Maps to models.Host - AgentToken is validated via hash comparison in repository.
type HostInfo struct {
	ID     uuid.UUID
	Name   string
	Status string
}

// AgentConnection represents a connected agent.
type AgentConnection struct {
	AgentID     string
	HostID      uuid.UUID
	HostName    string
	ConnectedAt time.Time
	LastSeen    time.Time
	Status      string
	Info        *protocol.AgentInfo
	Health      protocol.HealthStatus
}

// ServerConfig configures the gateway server.
type ServerConfig struct {
	// HeartbeatInterval is the expected interval between agent heartbeats
	HeartbeatInterval time.Duration
	// HeartbeatTimeout is how long to wait before marking an agent as stale
	HeartbeatTimeout time.Duration
	// InventoryInterval is how often agents should send inventory
	InventoryInterval time.Duration
	// CleanupInterval is how often to check for stale agents
	CleanupInterval time.Duration
	// CommandTimeout is the default timeout for commands
	CommandTimeout time.Duration
}

// DefaultServerConfig returns sensible defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		HeartbeatInterval: 30 * time.Second,
		HeartbeatTimeout:  90 * time.Second,
		InventoryInterval: 5 * time.Minute,
		CleanupInterval:   60 * time.Second,
		CommandTimeout:    30 * time.Second,
	}
}

// Server is the gateway server that manages agent connections.
type Server struct {
	natsClient *inats.Client
	jetstream  *inats.JetStream
	publisher  *inats.Publisher
	subscriber *inats.Subscriber
	hostRepo   HostRepository
	config     ServerConfig
	log        *logger.Logger

	agents    map[string]*AgentConnection // agentID -> connection
	hostIndex map[uuid.UUID]string        // hostID -> agentID
	mu        sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewServer creates a new gateway server.
func NewServer(
	natsClient *inats.Client,
	hostRepo HostRepository,
	config ServerConfig,
	log *logger.Logger,
) (*Server, error) {
	js, err := inats.NewJetStream(natsClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create JetStream: %w", err)
	}

	return &Server{
		natsClient: natsClient,
		jetstream:  js,
		publisher:  inats.NewPublisher(natsClient),
		subscriber: inats.NewSubscriber(natsClient),
		hostRepo:   hostRepo,
		config:     config,
		log:        log.Named("gateway"),
		agents:     make(map[string]*AgentConnection),
		hostIndex:  make(map[uuid.UUID]string),
	}, nil
}

// Start starts the gateway server.
func (s *Server) Start(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)

	s.log.Info("Starting gateway server")

	// Setup JetStream streams for commands and events
	if err := s.setupStreams(); err != nil {
		return fmt.Errorf("failed to setup streams: %w", err)
	}

	// Subscribe to agent messages
	if err := s.setupSubscriptions(); err != nil {
		return fmt.Errorf("failed to setup subscriptions: %w", err)
	}

	// Start cleanup goroutine
	s.wg.Add(1)
	go s.cleanupLoop()

	s.log.Info("Gateway server started",
		"heartbeat_interval", s.config.HeartbeatInterval,
		"heartbeat_timeout", s.config.HeartbeatTimeout,
	)

	return nil
}

// Stop stops the gateway server gracefully.
func (s *Server) Stop() error {
	s.log.Info("Stopping gateway server")

	s.cancel()
	s.wg.Wait()

	if err := s.subscriber.Close(); err != nil {
		s.log.Warn("Error closing subscriber", "error", err)
	}

	s.log.Info("Gateway server stopped")
	return nil
}

// setupStreams creates the required JetStream streams.
func (s *Server) setupStreams() error {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	streams := []inats.StreamConfig{
		{
			Name:        protocol.StreamCommands,
			Description: "Agent command queue",
			Subjects:    []string{"usulnet.commands.>"},
			MaxAge:      24 * time.Hour,
			Storage:     nats.FileStorage,
		},
		{
			Name:        protocol.StreamEvents,
			Description: "Agent events",
			Subjects:    []string{"usulnet.agent.events.>"},
			MaxAge:      24 * time.Hour,
			Storage:     nats.FileStorage,
		},
		{
			Name:        protocol.StreamInventory,
			Description: "Agent inventory snapshots",
			Subjects:    []string{"usulnet.agent.inventory.>"},
			MaxAge:      1 * time.Hour,
			Storage:     nats.FileStorage,
		},
	}

	for _, cfg := range streams {
		if _, err := s.jetstream.CreateStream(ctx, cfg); err != nil {
			return fmt.Errorf("failed to create stream %s: %w", cfg.Name, err)
		}
		s.log.Debug("Stream created/updated", "name", cfg.Name)
	}

	return nil
}

// setupSubscriptions sets up NATS subscriptions for agent communication.
func (s *Server) setupSubscriptions() error {
	// Agent registration (request-reply)
	if err := s.subscriber.SubscribeRequest(protocol.SubjectAgentRegister, s.handleRegistration); err != nil {
		return fmt.Errorf("failed to subscribe to registration: %w", err)
	}

	// Agent heartbeats (wildcard for agent ID)
	if err := s.subscriber.Subscribe(protocol.SubjectAgentHeartbeat, s.handleHeartbeat); err != nil {
		return fmt.Errorf("failed to subscribe to heartbeats: %w", err)
	}

	// Agent events (wildcard for agent ID)
	if err := s.subscriber.Subscribe(protocol.SubjectAgentEvents, s.handleEvent); err != nil {
		return fmt.Errorf("failed to subscribe to events: %w", err)
	}

	// Agent inventory (wildcard for agent ID)
	if err := s.subscriber.Subscribe(protocol.SubjectAgentInventory, s.handleInventory); err != nil {
		return fmt.Errorf("failed to subscribe to inventory: %w", err)
	}

	// Agent deregistration
	if err := s.subscriber.Subscribe(protocol.SubjectAgentDeregister, s.handleDeregistration); err != nil {
		return fmt.Errorf("failed to subscribe to deregistration: %w", err)
	}

	s.log.Debug("Subscriptions setup complete")
	return nil
}

// handleRegistration handles agent registration requests.
func (s *Server) handleRegistration(msg *nats.Msg) ([]byte, error) {
	var req protocol.RegistrationRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		s.log.Warn("Invalid registration request", "error", err)
		return s.errorResponse(protocol.ErrCodeInvalidPayload, "invalid request format")
	}

	s.log.Debug("Registration request received",
		"agent_id", req.Info.AgentID,
		"hostname", req.Info.Hostname,
	)

	// Verify agent token
	host, err := s.hostRepo.GetByAgentToken(s.ctx, req.Token)
	if err != nil {
		s.log.Warn("Invalid agent token", "error", err)
		return s.errorResponse(protocol.ErrCodeInvalidToken, "invalid or expired token")
	}

	// Create or update agent connection
	agentID := req.Info.AgentID
	if agentID == "" {
		agentID = uuid.New().String()
	}

	now := time.Now().UTC()
	conn := &AgentConnection{
		AgentID:     agentID,
		HostID:      host.ID,
		HostName:    host.Name,
		ConnectedAt: now,
		LastSeen:    now,
		Status:      "connected",
		Info:        &req.Info,
		Health:      protocol.HealthStatusHealthy,
	}

	s.mu.Lock()
	// Remove old agent for this host if exists
	if oldAgentID, exists := s.hostIndex[host.ID]; exists {
		delete(s.agents, oldAgentID)
	}
	s.agents[agentID] = conn
	s.hostIndex[host.ID] = agentID
	s.mu.Unlock()

	// Update host status in database
	if err := s.hostRepo.UpdateStatus(s.ctx, host.ID, "online", now); err != nil {
		s.log.Warn("Failed to update host status", "host_id", host.ID, "error", err)
	}

	// Update agent info
	if err := s.hostRepo.UpdateAgentInfo(s.ctx, host.ID, &req.Info); err != nil {
		s.log.Warn("Failed to update agent info", "host_id", host.ID, "error", err)
	}

	s.log.Info("Agent registered",
		"agent_id", agentID,
		"host_id", host.ID,
		"hostname", req.Info.Hostname,
	)

	// Build response
	resp := protocol.RegistrationResponse{
		Success:           true,
		AgentID:           agentID,
		HeartbeatInterval: s.config.HeartbeatInterval,
		InventoryInterval: s.config.InventoryInterval,
		Config: protocol.AgentConfig{
			LogLevel:         "info",
			MetricsEnabled:   true,
			MetricsInterval:  60,
			BackupEnabled:    true,
			ScannerEnabled:   true,
			UpdaterEnabled:   true,
			MaxConcurrentOps: 5,
		},
	}

	return json.Marshal(resp)
}

// handleHeartbeat handles agent heartbeat messages.
func (s *Server) handleHeartbeat(msg *nats.Msg) error {
	var hb protocol.Heartbeat
	if err := json.Unmarshal(msg.Data, &hb); err != nil {
		s.log.Warn("Invalid heartbeat", "error", err)
		return fmt.Errorf("invalid heartbeat: %w", err)
	}

	s.mu.Lock()
	conn, exists := s.agents[hb.AgentID]
	if exists {
		conn.LastSeen = time.Now().UTC()
		conn.Health = hb.Health
		if hb.LastError != "" {
			conn.Status = "degraded"
		} else {
			conn.Status = "connected"
		}
	}
	s.mu.Unlock()

	if !exists {
		s.log.Warn("Heartbeat from unknown agent", "agent_id", hb.AgentID)
		return nil
	}

	// Update host status
	if err := s.hostRepo.UpdateStatus(s.ctx, conn.HostID, "online", conn.LastSeen); err != nil {
		s.log.Warn("Failed to update host status", "error", err)
	}

	// Send response if reply subject exists
	if msg.Reply != "" {
		resp := protocol.HeartbeatResponse{
			Acknowledged: true,
			ServerTime:   time.Now().UTC(),
		}
		data, _ := json.Marshal(resp)
		msg.Respond(data)
	}

	return nil
}

// handleEvent handles agent event messages.
func (s *Server) handleEvent(msg *nats.Msg) error {
	var event protocol.Event
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		s.log.Warn("Invalid event", "error", err)
		return fmt.Errorf("invalid event: %w", err)
	}

	s.log.Debug("Event received",
		"type", event.Type,
		"agent_id", event.AgentID,
		"severity", event.Severity,
	)

	// Persist event if needed
	if protocol.ShouldPersist(event.Type) {
		// Sprint 2: Persist to event repository (requires event store table + repo)
		s.log.Info("Agent event received (persistence pending)",
			"event_id", event.ID,
			"type", event.Type,
			"agent_id", event.AgentID,
			"severity", event.Severity,
			"message", event.Message,
		)
	}

	// Check if notification needed
	if protocol.ShouldNotify(event.Type) {
		// Sprint 2: Route to notification service for alerting
		s.log.Warn("Agent event requires notification (alerting pending)",
			"event_id", event.ID,
			"type", event.Type,
			"severity", event.Severity,
		)
	}

	// Acknowledge event
	if msg.Reply != "" {
		ack := protocol.EventAck{
			EventID:      event.ID,
			Acknowledged: true,
		}
		data, _ := json.Marshal(ack)
		msg.Respond(data)
	}

	return nil
}

// handleInventory handles agent inventory messages.
func (s *Server) handleInventory(msg *nats.Msg) error {
	var inv protocol.Inventory
	if err := json.Unmarshal(msg.Data, &inv); err != nil {
		s.log.Warn("Invalid inventory", "error", err)
		return fmt.Errorf("invalid inventory: %w", err)
	}

	s.log.Debug("Inventory received",
		"agent_id", inv.AgentID,
		"containers", len(inv.Containers),
		"images", len(inv.Images),
	)

	// Update agent connection with latest inventory stats
	s.mu.Lock()
	conn, exists := s.agents[inv.AgentID]
	s.mu.Unlock()

	if exists {
		s.log.Info("Agent inventory processed",
			"agent_id", inv.AgentID,
			"host_id", conn.HostID,
			"containers", len(inv.Containers),
			"images", len(inv.Images),
			"volumes", len(inv.Volumes),
			"networks", len(inv.Networks),
		)
	}

	// Sprint 2: Sync inventory to container/image/volume/network repositories
	// to enable dashboard data for agent-managed hosts without live queries

	return nil
}

// handleDeregistration handles agent deregistration.
func (s *Server) handleDeregistration(msg *nats.Msg) error {
	var req protocol.DeregistrationRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		return fmt.Errorf("invalid deregistration request: %w", err)
	}

	s.mu.Lock()
	conn, exists := s.agents[req.AgentID]
	if exists {
		delete(s.agents, req.AgentID)
		delete(s.hostIndex, conn.HostID)
	}
	s.mu.Unlock()

	if exists {
		s.log.Info("Agent deregistered",
			"agent_id", req.AgentID,
			"reason", req.Reason,
		)
		// Update host status
		s.hostRepo.UpdateStatus(s.ctx, conn.HostID, "offline", time.Now().UTC())
	}

	return nil
}

// cleanupLoop periodically checks for stale agent connections.
func (s *Server) cleanupLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.cleanupStaleAgents()
		}
	}
}

// cleanupStaleAgents removes agents that haven't sent heartbeats.
func (s *Server) cleanupStaleAgents() {
	threshold := time.Now().UTC().Add(-s.config.HeartbeatTimeout)

	s.mu.Lock()
	var stale []string
	for agentID, conn := range s.agents {
		if conn.LastSeen.Before(threshold) {
			stale = append(stale, agentID)
		}
	}

	for _, agentID := range stale {
		conn := s.agents[agentID]
		delete(s.agents, agentID)
		delete(s.hostIndex, conn.HostID)

		s.log.Warn("Agent connection stale, removing",
			"agent_id", agentID,
			"host_id", conn.HostID,
			"last_seen", conn.LastSeen,
		)

		// Update host status (outside lock to avoid deadlock)
		go s.hostRepo.UpdateStatus(s.ctx, conn.HostID, "offline", conn.LastSeen)
	}
	s.mu.Unlock()
}

// errorResponse creates an error response for registration.
func (s *Server) errorResponse(code, message string) ([]byte, error) {
	resp := protocol.RegistrationResponse{
		Success: false,
		Error:   code + ": " + message,
	}
	return json.Marshal(resp)
}

// ============================================================================
// Public Query Methods
// ============================================================================

// GetAgent returns an agent connection by ID.
func (s *Server) GetAgent(agentID string) (*AgentConnection, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	conn, ok := s.agents[agentID]
	return conn, ok
}

// GetAgentByHost returns the agent for a host.
func (s *Server) GetAgentByHost(hostID uuid.UUID) (*AgentConnection, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	agentID, ok := s.hostIndex[hostID]
	if !ok {
		return nil, false
	}
	return s.agents[agentID], true
}

// ListAgents returns all connected agents.
func (s *Server) ListAgents() []*AgentConnection {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agents := make([]*AgentConnection, 0, len(s.agents))
	for _, conn := range s.agents {
		agents = append(agents, conn)
	}
	return agents
}

// AgentCount returns the number of connected agents.
func (s *Server) AgentCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.agents)
}

// ConnectedCount returns the number of actively connected (non-stale) agents.
func (s *Server) ConnectedCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, conn := range s.agents {
		if conn.Status == "connected" {
			count++
		}
	}
	return count
}

// IsAgentConnected checks if a host has a connected agent.
func (s *Server) IsAgentConnected(hostID uuid.UUID) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.hostIndex[hostID]
	return ok
}

// GetAgentHealth returns the health status of an agent.
func (s *Server) GetAgentHealth(hostID uuid.UUID) (protocol.HealthStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agentID, ok := s.hostIndex[hostID]
	if !ok {
		return protocol.HealthStatusUnknown, fmt.Errorf("agent not connected")
	}

	conn := s.agents[agentID]
	return conn.Health, nil
}

// NATSHealth performs a NATS health check.
func (s *Server) NATSHealth(ctx context.Context) error {
	return s.natsClient.Health(ctx)
}

// IsNATSConnected returns true if connected to NATS.
func (s *Server) IsNATSConnected() bool {
	return s.natsClient.IsConnected()
}
