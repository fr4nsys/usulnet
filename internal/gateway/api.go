// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package gateway provides HTTP API handlers for the gateway server.
package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// AgentStatus represents the connection status of an agent.
type AgentStatus string

const (
	AgentStatusConnected    AgentStatus = "connected"
	AgentStatusDisconnected AgentStatus = "disconnected"
	AgentStatusStale        AgentStatus = "stale"
)

// APIHandler provides HTTP handlers for gateway operations.
type APIHandler struct {
	server     *Server
	dispatcher *CommandDispatcher
	log        *logger.Logger
}

// NewAPIHandler creates a new API handler.
func NewAPIHandler(server *Server, log *logger.Logger) *APIHandler {
	return &APIHandler{
		server:     server,
		dispatcher: NewCommandDispatcher(server, log),
		log:        log.Named("gateway-api"),
	}
}

// RegisterRoutes registers the gateway API routes.
func (h *APIHandler) RegisterRoutes(r chi.Router) {
	r.Route("/gateway", func(r chi.Router) {
		// Agent management
		r.Get("/agents", h.ListAgents)
		r.Get("/agents/{agentID}", h.GetAgent)
		r.Get("/agents/host/{hostID}", h.GetAgentByHost)
		r.Delete("/agents/{agentID}", h.DisconnectAgent)

		// Command execution
		r.Post("/commands", h.SendCommand)
		r.Post("/commands/{hostID}", h.SendHostCommand)
		r.Post("/commands/broadcast", h.BroadcastCommand)

		// Health and statistics
		r.Get("/stats", h.GetStats)
		r.Get("/health", h.HealthCheck)
	})
}

// ============================================================================
// Agent Handlers
// ============================================================================

// AgentResponse is the API response for an agent.
type AgentResponse struct {
	AgentID     string                `json:"agent_id"`
	HostID      string                `json:"host_id"`
	HostName    string                `json:"host_name"`
	Status      AgentStatus           `json:"status"`
	Health      protocol.HealthStatus `json:"health"`
	ConnectedAt time.Time             `json:"connected_at"`
	LastSeen    time.Time             `json:"last_seen"`
	Info        *AgentInfoResponse    `json:"info,omitempty"`
}

// AgentInfoResponse is the agent info for API responses.
type AgentInfoResponse struct {
	Version      string   `json:"version"`
	Hostname     string   `json:"hostname"`
	OS           string   `json:"os"`
	Arch         string   `json:"arch"`
	DockerHost   string   `json:"docker_host"`
	Capabilities []string `json:"capabilities"`
}

// ListAgents returns all connected agents.
func (h *APIHandler) ListAgents(w http.ResponseWriter, r *http.Request) {
	agents := h.server.ListAgents()

	response := make([]AgentResponse, 0, len(agents))
	for _, agent := range agents {
		response = append(response, h.agentToResponse(agent))
	}

	h.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"agents": response,
		"total":  len(response),
	})
}

// GetAgent returns a specific agent.
func (h *APIHandler) GetAgent(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentID")
	if agentID == "" {
		h.errorResponse(w, http.StatusBadRequest, "agent_id is required")
		return
	}

	agent, ok := h.server.GetAgent(agentID)
	if !ok {
		h.errorResponse(w, http.StatusNotFound, "agent not found")
		return
	}

	h.jsonResponse(w, http.StatusOK, h.agentToResponse(agent))
}

// GetAgentByHost returns the agent for a specific host.
func (h *APIHandler) GetAgentByHost(w http.ResponseWriter, r *http.Request) {
	hostIDStr := chi.URLParam(r, "hostID")
	hostID, err := uuid.Parse(hostIDStr)
	if err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid host_id")
		return
	}

	agent, ok := h.server.GetAgentByHost(hostID)
	if !ok {
		h.errorResponse(w, http.StatusNotFound, "no agent connected for host")
		return
	}

	h.jsonResponse(w, http.StatusOK, h.agentToResponse(agent))
}

// DisconnectAgent forcefully disconnects an agent.
func (h *APIHandler) DisconnectAgent(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentID")
	if agentID == "" {
		h.errorResponse(w, http.StatusBadRequest, "agent_id is required")
		return
	}

	agent, ok := h.server.GetAgent(agentID)
	if !ok {
		h.errorResponse(w, http.StatusNotFound, "agent not found")
		return
	}

	// Send disconnect command to agent
	ctx := r.Context()
	cmd := NewCommandBuilder(protocol.CmdAgentDisconnect).Build()

	result, err := h.dispatcher.SendCommand(ctx, agent.HostID, cmd)
	if err != nil {
		h.log.Error("Failed to send disconnect command", "error", err)
		// Continue anyway - remove from local state
	}

	// Remove from local state
	h.server.mu.Lock()
	delete(h.server.agents, agentID)
	h.server.mu.Unlock()

	h.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"message":        "agent disconnected",
		"agent_id":       agentID,
		"command_result": result,
	})
}

// ============================================================================
// Command Handlers
// ============================================================================

// CommandRequest is the request body for sending commands.
type CommandRequest struct {
	Type       string                 `json:"type"`
	HostID     string                 `json:"host_id,omitempty"`
	Params     map[string]interface{} `json:"params,omitempty"`
	Timeout    int                    `json:"timeout_seconds,omitempty"`
	Priority   string                 `json:"priority,omitempty"`
	Idempotent bool                   `json:"idempotent,omitempty"`
}

// SendCommand sends a command to a specific host.
func (h *APIHandler) SendCommand(w http.ResponseWriter, r *http.Request) {
	var req CommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.HostID == "" {
		h.errorResponse(w, http.StatusBadRequest, "host_id is required")
		return
	}

	hostID, err := uuid.Parse(req.HostID)
	if err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid host_id")
		return
	}

	// Build command
	cmd := h.buildCommand(req)

	// Send command
	ctx := r.Context()
	result, err := h.dispatcher.SendCommand(ctx, hostID, cmd)
	if err != nil {
		h.handleCommandError(w, err)
		return
	}

	h.jsonResponse(w, http.StatusOK, result)
}

// SendHostCommand sends a command to a host by path parameter.
func (h *APIHandler) SendHostCommand(w http.ResponseWriter, r *http.Request) {
	hostIDStr := chi.URLParam(r, "hostID")
	hostID, err := uuid.Parse(hostIDStr)
	if err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid host_id")
		return
	}

	var req CommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	cmd := h.buildCommand(req)

	ctx := r.Context()
	result, err := h.dispatcher.SendCommand(ctx, hostID, cmd)
	if err != nil {
		h.handleCommandError(w, err)
		return
	}

	h.jsonResponse(w, http.StatusOK, result)
}

// BroadcastCommand sends a command to all connected agents.
func (h *APIHandler) BroadcastCommand(w http.ResponseWriter, r *http.Request) {
	var req CommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	cmd := h.buildCommand(req)

	ctx := r.Context()
	results := h.dispatcher.BroadcastCommand(ctx, cmd)

	// Convert results map to JSON-serializable format
	response := make(map[string]interface{})
	for hostID, result := range results {
		response[hostID.String()] = result
	}

	h.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"results": response,
		"total":   len(results),
	})
}

// ============================================================================
// Statistics Handlers
// ============================================================================

// GatewayStats contains gateway statistics.
type GatewayStats struct {
	TotalAgents     int       `json:"total_agents"`
	ConnectedAgents int       `json:"connected_agents"`
	StaleAgents     int       `json:"stale_agents"`
	PendingCommands int       `json:"pending_commands"`
	ServerTime      time.Time `json:"server_time"`
}

// GetStats returns gateway statistics.
func (h *APIHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	agents := h.server.ListAgents()

	stats := GatewayStats{
		TotalAgents:     len(agents),
		PendingCommands: h.dispatcher.PendingCount(),
		ServerTime:      time.Now().UTC(),
	}

	for _, agent := range agents {
		// Compare with string values since AgentConnection.Status is string
		switch agent.Status {
		case string(AgentStatusConnected):
			stats.ConnectedAgents++
		case string(AgentStatusStale):
			stats.StaleAgents++
		}
	}

	h.jsonResponse(w, http.StatusOK, stats)
}

// HealthCheck returns the gateway health status.
func (h *APIHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check NATS connection
	if err := h.server.NATSHealth(ctx); err != nil {
		h.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"status":  "unhealthy",
			"message": "NATS connection failed",
			"error":   err.Error(),
		})
		return
	}

	h.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":         "healthy",
		"agent_count":    h.server.ConnectedCount(),
		"nats_connected": h.server.IsNATSConnected(),
	})
}

// ============================================================================
// Helper Methods
// ============================================================================

func (h *APIHandler) agentToResponse(agent *AgentConnection) AgentResponse {
	resp := AgentResponse{
		AgentID:     agent.AgentID,
		HostID:      agent.HostID.String(),
		HostName:    agent.HostName,
		Status:      AgentStatus(agent.Status), // Convert string to AgentStatus
		Health:      agent.Health,
		ConnectedAt: agent.ConnectedAt,
		LastSeen:    agent.LastSeen,
	}

	if agent.Info != nil {
		resp.Info = &AgentInfoResponse{
			Version:      agent.Info.Version,
			Hostname:     agent.Info.Hostname,
			OS:           agent.Info.OS,
			Arch:         agent.Info.Arch,
			DockerHost:   agent.Info.DockerHost,
			Capabilities: agent.Info.Capabilities,
		}
	}

	return resp
}

func (h *APIHandler) buildCommand(req CommandRequest) *protocol.Command {
	builder := NewCommandBuilder(protocol.CommandType(req.Type))

	if req.Timeout > 0 {
		builder.WithTimeout(time.Duration(req.Timeout) * time.Second)
	}

	if req.Priority != "" {
		var priority protocol.CommandPriority
		switch req.Priority {
		case "low":
			priority = protocol.PriorityLow
		case "high":
			priority = protocol.PriorityHigh
		case "critical":
			priority = protocol.PriorityCritical
		default:
			priority = protocol.PriorityNormal
		}
		builder.WithPriority(priority)
	}

	if req.Idempotent {
		builder.Idempotent()
	}

	// Map params to command params
	cmd := builder.Build()
	if len(req.Params) > 0 {
		if v, ok := req.Params["container_id"].(string); ok {
			cmd.Params.ContainerID = v
		}
		if v, ok := req.Params["container_name"].(string); ok {
			cmd.Params.ContainerName = v
		}
		if v, ok := req.Params["image_ref"].(string); ok {
			cmd.Params.ImageRef = v
		}
		if v, ok := req.Params["stack_name"].(string); ok {
			cmd.Params.StackName = v
		}
		if v, ok := req.Params["compose_file"].(string); ok {
			cmd.Params.ComposeFile = v
		}
		if v, ok := req.Params["volume_name"].(string); ok {
			cmd.Params.VolumeName = v
		}
		if v, ok := req.Params["network_id"].(string); ok {
			cmd.Params.NetworkID = v
		}
		if v, ok := req.Params["force"].(bool); ok {
			cmd.Params.Force = v
		}
		if v, ok := req.Params["signal"].(string); ok {
			cmd.Params.Signal = v
		}
	}

	return cmd
}

func (h *APIHandler) handleCommandError(w http.ResponseWriter, err error) {
	if protocolErr, ok := err.(*protocol.ProtocolError); ok {
		switch protocolErr.Code {
		case protocol.ErrCodeAgentUnavailable:
			h.errorResponse(w, http.StatusServiceUnavailable, protocolErr.Message)
		case protocol.ErrCodeCommandTimeout:
			h.errorResponse(w, http.StatusGatewayTimeout, protocolErr.Message)
		default:
			h.errorResponse(w, http.StatusInternalServerError, protocolErr.Message)
		}
		return
	}

	if errors.Is(err, context.DeadlineExceeded) {
		h.errorResponse(w, http.StatusGatewayTimeout, "command timed out")
		return
	}

	h.errorResponse(w, http.StatusInternalServerError, err.Error())
}

func (h *APIHandler) jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *APIHandler) errorResponse(w http.ResponseWriter, status int, message string) {
	h.jsonResponse(w, status, map[string]interface{}{
		"error":   true,
		"message": message,
	})
}
