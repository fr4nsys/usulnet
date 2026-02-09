// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package protocol defines the NATS message types for Gateway-Agent communication.
package protocol

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// MessageType identifies the type of NATS message.
type MessageType string

const (
	// Registration messages
	MessageTypeRegister         MessageType = "register"
	MessageTypeRegisterResponse MessageType = "register_response"
	MessageTypeDeregister       MessageType = "deregister"

	// Heartbeat messages
	MessageTypeHeartbeat         MessageType = "heartbeat"
	MessageTypeHeartbeatResponse MessageType = "heartbeat_response"

	// Command messages
	MessageTypeCommand        MessageType = "command"
	MessageTypeCommandResult  MessageType = "command_result"
	MessageTypeCommandTimeout MessageType = "command_timeout"

	// Event messages
	MessageTypeEvent    MessageType = "event"
	MessageTypeEventAck MessageType = "event_ack"

	// Inventory messages
	MessageTypeInventory        MessageType = "inventory"
	MessageTypeInventoryRequest MessageType = "inventory_request"

	// System messages
	MessageTypeShutdown MessageType = "shutdown"
	MessageTypePing     MessageType = "ping"
	MessageTypePong     MessageType = "pong"
)

// NATS subject patterns for usulnet Gateway-Agent communication.
const (
	// Gateway subjects (Gateway listens)
	SubjectAgentRegister   = "usulnet.agent.register"
	SubjectAgentHeartbeat  = "usulnet.agent.heartbeat.*"  // wildcard for agent ID
	SubjectAgentEvents     = "usulnet.agent.events.*"     // wildcard for agent ID
	SubjectAgentInventory  = "usulnet.agent.inventory.*"  // wildcard for agent ID
	SubjectAgentDeregister = "usulnet.agent.deregister.*" // wildcard for agent ID

	// Agent subjects (Agent listens) - uses agent ID
	SubjectCommandPrefix = "usulnet.commands." // + agentID
	SubjectBroadcast     = "usulnet.broadcast" // all agents

	// Reply subjects
	SubjectReplyPrefix = "usulnet.reply." // + unique ID
)

// JetStream stream names.
const (
	StreamCommands   = "USULNET_COMMANDS"
	StreamEvents     = "USULNET_EVENTS"
	StreamInventory  = "USULNET_INVENTORY"
	StreamAudit      = "USULNET_AUDIT"
	StreamDeadLetter = "USULNET_DLQ"
)

// Message is the base envelope for all NATS messages.
type Message struct {
	ID        string          `json:"id"`
	Type      MessageType     `json:"type"`
	Timestamp time.Time       `json:"timestamp"`
	AgentID   string          `json:"agent_id,omitempty"`
	HostID    string          `json:"host_id,omitempty"`
	ReplyTo   string          `json:"reply_to,omitempty"`
	Payload   json.RawMessage `json:"payload"`
}

// NewMessage creates a new message with generated ID and current timestamp.
func NewMessage(msgType MessageType, payload interface{}) (*Message, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	return &Message{
		ID:        uuid.New().String(),
		Type:      msgType,
		Timestamp: time.Now().UTC(),
		Payload:   data,
	}, nil
}

// WithAgent sets agent and host IDs on the message.
func (m *Message) WithAgent(agentID, hostID string) *Message {
	m.AgentID = agentID
	m.HostID = hostID
	return m
}

// WithReply sets a reply subject for request-response pattern.
func (m *Message) WithReply(replyTo string) *Message {
	m.ReplyTo = replyTo
	return m
}

// Encode serializes the message to JSON bytes.
func (m *Message) Encode() ([]byte, error) {
	return json.Marshal(m)
}

// DecodeMessage deserializes a message from JSON bytes.
func DecodeMessage(data []byte) (*Message, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// DecodePayload unmarshals the payload into the provided type.
func (m *Message) DecodePayload(v interface{}) error {
	return json.Unmarshal(m.Payload, v)
}

// AgentInfo contains metadata about a connected agent.
type AgentInfo struct {
	AgentID      string            `json:"agent_id"`
	Version      string            `json:"version"`
	Hostname     string            `json:"hostname"`
	OS           string            `json:"os"`
	Arch         string            `json:"arch"`
	DockerHost   string            `json:"docker_host"`
	Labels       map[string]string `json:"labels,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty"`
}

// RegistrationRequest is sent by agent to register with gateway.
type RegistrationRequest struct {
	Token string    `json:"token"` // Pre-shared token for authentication
	Info  AgentInfo `json:"info"`
}

// RegistrationResponse is sent by gateway to confirm registration.
type RegistrationResponse struct {
	Success           bool          `json:"success"`
	Error             string        `json:"error,omitempty"`
	AgentID           string        `json:"agent_id,omitempty"`
	HeartbeatInterval time.Duration `json:"heartbeat_interval,omitempty"`
	InventoryInterval time.Duration `json:"inventory_interval,omitempty"`
	Config            AgentConfig   `json:"config,omitempty"`
}

// AgentConfig contains runtime configuration pushed to agents.
type AgentConfig struct {
	LogLevel         string `json:"log_level"`
	MetricsEnabled   bool   `json:"metrics_enabled"`
	MetricsInterval  int    `json:"metrics_interval_seconds"`
	BackupEnabled    bool   `json:"backup_enabled"`
	ScannerEnabled   bool   `json:"scanner_enabled"`
	UpdaterEnabled   bool   `json:"updater_enabled"`
	MaxConcurrentOps int    `json:"max_concurrent_ops"`
}

// Heartbeat is sent periodically by agent to indicate liveness.
type Heartbeat struct {
	AgentID       string         `json:"agent_id"`
	Timestamp     time.Time      `json:"timestamp"`
	Uptime        time.Duration  `json:"uptime"`
	Stats         *QuickStats    `json:"stats,omitempty"`
	ActiveJobs    int            `json:"active_jobs"`
	LastError     string         `json:"last_error,omitempty"`
	LastErrorTime *time.Time     `json:"last_error_time,omitempty"`
	Health        HealthStatus   `json:"health"`
	Metrics       *AgentMetrics  `json:"metrics,omitempty"`
}

// HealthStatus represents agent health state.
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// QuickStats contains lightweight stats sent with heartbeat.
type QuickStats struct {
	ContainersRunning int   `json:"containers_running"`
	ContainersStopped int   `json:"containers_stopped"`
	ContainersTotal   int   `json:"containers_total"`
	ImagesCount       int   `json:"images_count"`
	VolumesCount      int   `json:"volumes_count"`
	NetworksCount     int   `json:"networks_count"`
	CPUPercent        float64 `json:"cpu_percent"`
	MemoryUsedBytes   int64   `json:"memory_used_bytes"`
	MemoryTotalBytes  int64   `json:"memory_total_bytes"`
	DiskUsedBytes     int64   `json:"disk_used_bytes"`
	DiskTotalBytes    int64   `json:"disk_total_bytes"`
}

// AgentMetrics contains detailed metrics collected by agent.
type AgentMetrics struct {
	CollectedAt      time.Time `json:"collected_at"`
	CPUUsagePercent  float64   `json:"cpu_usage_percent"`
	MemoryUsageBytes int64     `json:"memory_usage_bytes"`
	MemoryLimitBytes int64     `json:"memory_limit_bytes"`
	DiskReadBytes    int64     `json:"disk_read_bytes"`
	DiskWriteBytes   int64     `json:"disk_write_bytes"`
	NetworkRxBytes   int64     `json:"network_rx_bytes"`
	NetworkTxBytes   int64     `json:"network_tx_bytes"`
	Goroutines       int       `json:"goroutines"`
	OpenFiles        int       `json:"open_files"`
}

// HeartbeatResponse is sent by gateway to acknowledge heartbeat.
type HeartbeatResponse struct {
	Acknowledged  bool         `json:"acknowledged"`
	ServerTime    time.Time    `json:"server_time"`
	ConfigChanged bool         `json:"config_changed"`
	NewConfig     *AgentConfig `json:"new_config,omitempty"`
	PendingJobs   int          `json:"pending_jobs"`
}

// DeregistrationRequest is sent by agent when shutting down gracefully.
type DeregistrationRequest struct {
	AgentID string `json:"agent_id"`
	Reason  string `json:"reason"`
}

// Error codes for protocol errors.
const (
	ErrCodeInvalidToken     = "INVALID_TOKEN"
	ErrCodeAgentNotFound    = "AGENT_NOT_FOUND"
	ErrCodeHostNotFound     = "HOST_NOT_FOUND"
	ErrCodeCommandTimeout   = "COMMAND_TIMEOUT"
	ErrCodeCommandFailed    = "COMMAND_FAILED"
	ErrCodeInvalidPayload   = "INVALID_PAYLOAD"
	ErrCodeUnauthorized     = "UNAUTHORIZED"
	ErrCodeRateLimited      = "RATE_LIMITED"
	ErrCodeInternalError    = "INTERNAL_ERROR"
	ErrCodeAgentUnavailable = "AGENT_UNAVAILABLE"
)

// ProtocolError represents a standardized error in the protocol.
type ProtocolError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (e *ProtocolError) Error() string {
	if e.Details != "" {
		return e.Code + ": " + e.Message + " (" + e.Details + ")"
	}
	return e.Code + ": " + e.Message
}

// NewProtocolError creates a new protocol error.
func NewProtocolError(code, message string) *ProtocolError {
	return &ProtocolError{
		Code:    code,
		Message: message,
	}
}

// WithDetails adds details to the error.
func (e *ProtocolError) WithDetails(details string) *ProtocolError {
	e.Details = details
	return e
}
