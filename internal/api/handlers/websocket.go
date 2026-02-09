// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/container"
)

// WebSocket configuration constants.
const (
	// WriteWait is time allowed to write a message to the peer.
	WriteWait = 10 * time.Second

	// PongWait is time allowed to read the next pong message from the peer.
	PongWait = 60 * time.Second

	// PingPeriod is period for sending pings. Must be less than PongWait.
	PingPeriod = 50 * time.Second

	// MaxMessageSize is maximum message size allowed from peer.
	MaxMessageSize = 8192

	// ReaderBufferSize is buffer size for reading from streams.
	ReaderBufferSize = 2048
)

// WebSocketUpgrader is the default upgrader for WebSocket connections.
var WebSocketUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// In production, validate origin against allowed list
		return true
	},
}

// WebSocketHandler handles WebSocket connections.
type WebSocketHandler struct {
	BaseHandler
	containerService *container.Service
}

// NewWebSocketHandler creates a new WebSocket handler.
func NewWebSocketHandler(containerService *container.Service, log *logger.Logger) *WebSocketHandler {
	return &WebSocketHandler{
		BaseHandler:      NewBaseHandler(log),
		containerService: containerService,
	}
}

// Routes returns the WebSocket routes.
func (h *WebSocketHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Container logs streaming
	r.Get("/containers/{hostID}/{containerID}/logs", h.ContainerLogs)

	// Container stats streaming
	r.Get("/containers/{hostID}/{containerID}/stats", h.ContainerStats)

	// Container exec (create exec instance and return ID)
	r.Post("/containers/{hostID}/{containerID}/exec", h.ContainerExec)

	return r
}

// ============================================================================
// WebSocket message types
// ============================================================================

// WSMessage represents a WebSocket message.
type WSMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// LogMessage represents a log message.
type LogMessage struct {
	Stream    string `json:"stream"` // stdout or stderr
	Timestamp string `json:"timestamp,omitempty"`
	Message   string `json:"message"`
}

// StatsMessage represents container stats.
type StatsMessage struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryUsage   int64   `json:"memory_usage"`
	MemoryLimit   int64   `json:"memory_limit"`
	MemoryPercent float64 `json:"memory_percent"`
	NetworkRx     int64   `json:"network_rx"`
	NetworkTx     int64   `json:"network_tx"`
	BlockRead     int64   `json:"block_read"`
	BlockWrite    int64   `json:"block_write"`
	PIDs          int     `json:"pids"`
	Timestamp     string  `json:"timestamp"`
}

// WSExecRequest represents an exec request via WebSocket.
type WSExecRequest struct {
	Cmd        []string `json:"cmd"`
	Tty        bool     `json:"tty,omitempty"`
	Env        []string `json:"env,omitempty"`
	WorkingDir string   `json:"working_dir,omitempty"`
	User       string   `json:"user,omitempty"`
}

// ============================================================================
// Handlers
// ============================================================================

// ContainerLogs streams container logs via WebSocket.
// GET /api/v1/ws/containers/{hostID}/{containerID}/logs
func (h *WebSocketHandler) ContainerLogs(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	containerID := h.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "containerID is required")
		return
	}

	// Upgrade connection
	conn, err := h.upgradeConnection(w, r)
	if err != nil {
		return
	}
	defer conn.Close()

	// Parse options
	tail := h.QueryParam(r, "tail")
	if tail == "" {
		tail = "100"
	}
	follow := h.QueryParamBool(r, "follow", true)
	timestamps := h.QueryParamBool(r, "timestamps", false)

	opts := container.LogOptions{
		Tail:       tail,
		Follow:     follow,
		Timestamps: timestamps,
		Stdout:     true,
		Stderr:     true,
	}

	// Create context that cancels when connection closes
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Handle client disconnect
	go func() {
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				cancel()
				return
			}
		}
	}()

	// Start ping/pong
	go h.pingPong(ctx, conn)

	// Get log reader
	reader, err := h.containerService.GetLogs(ctx, hostID, containerID, opts)
	if err != nil {
		h.writeWSError(conn, err)
		return
	}
	defer reader.Close()

	// Stream logs to WebSocket
	h.streamReaderToWS(ctx, conn, reader)
}

// ContainerStats streams container stats via WebSocket.
// GET /api/v1/ws/containers/{hostID}/{containerID}/stats
func (h *WebSocketHandler) ContainerStats(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	containerID := h.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "containerID is required")
		return
	}

	// Upgrade connection
	conn, err := h.upgradeConnection(w, r)
	if err != nil {
		return
	}
	defer conn.Close()

	// Parse interval
	intervalStr := h.QueryParam(r, "interval")
	interval := 2 * time.Second
	if intervalStr != "" {
		if secs, err := strconv.Atoi(intervalStr); err == nil && secs > 0 {
			interval = time.Duration(secs) * time.Second
		}
	}

	// Create context that cancels when connection closes
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Handle client disconnect
	go func() {
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				cancel()
				return
			}
		}
	}()

	// Start ping/pong
	go h.pingPong(ctx, conn)

	// Stream stats
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats, err := h.containerService.GetStats(ctx, hostID, containerID)
			if err != nil {
				h.writeWSError(conn, err)
				return
			}

			msg := WSMessage{
				Type: "stats",
				Payload: StatsMessage{
					CPUPercent:    stats.CPUPercent,
					MemoryUsage:   stats.MemoryUsage,
					MemoryLimit:   stats.MemoryLimit,
					MemoryPercent: stats.MemoryPercent,
					NetworkRx:     stats.NetworkRxBytes,
					NetworkTx:     stats.NetworkTxBytes,
					BlockRead:     stats.BlockRead,
					BlockWrite:    stats.BlockWrite,
					PIDs:          stats.PIDs,
					Timestamp:     stats.CollectedAt.Format(time.RFC3339),
				},
			}

			if err := h.writeWSMessage(conn, msg); err != nil {
				return
			}
		}
	}
}

// ContainerExec creates an exec instance.
// POST /api/v1/ws/containers/{hostID}/{containerID}/exec
func (h *WebSocketHandler) ContainerExec(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	containerID := h.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "containerID is required")
		return
	}

	var req WSExecRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if len(req.Cmd) == 0 {
		h.BadRequest(w, "cmd is required")
		return
	}

	config := container.ExecConfig{
		Cmd:          req.Cmd,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          req.Tty,
		Env:          req.Env,
		WorkingDir:   req.WorkingDir,
		User:         req.User,
	}

	execID, err := h.containerService.ExecCreate(r.Context(), hostID, containerID, config)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]string{"exec_id": execID})
}

// ============================================================================
// WebSocket helpers
// ============================================================================

// upgradeConnection upgrades an HTTP connection to WebSocket.
func (h *WebSocketHandler) upgradeConnection(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	conn, err := WebSocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		h.Logger().Error("websocket upgrade failed", "error", err)
		return nil, err
	}

	conn.SetReadLimit(MaxMessageSize)
	conn.SetReadDeadline(time.Now().Add(PongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(PongWait))
		return nil
	})

	return conn, nil
}

// pingPong sends periodic pings to keep the connection alive.
func (h *WebSocketHandler) pingPong(ctx context.Context, conn *websocket.Conn) {
	ticker := time.NewTicker(PingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			conn.SetWriteDeadline(time.Now().Add(WriteWait))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// writeWSMessage writes a message to the WebSocket.
func (h *WebSocketHandler) writeWSMessage(conn *websocket.Conn, msg WSMessage) error {
	conn.SetWriteDeadline(time.Now().Add(WriteWait))

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return conn.WriteMessage(websocket.TextMessage, data)
}

// writeWSError writes an error message to the WebSocket.
func (h *WebSocketHandler) writeWSError(conn *websocket.Conn, err error) {
	msg := WSMessage{
		Type:  "error",
		Error: err.Error(),
	}

	h.writeWSMessage(conn, msg)
}

// streamReaderToWS streams data from an io.Reader to a WebSocket connection.
func (h *WebSocketHandler) streamReaderToWS(ctx context.Context, conn *websocket.Conn, reader io.Reader) {
	buf := make([]byte, ReaderBufferSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := reader.Read(buf)
			if err != nil {
				if err != io.EOF {
					h.writeWSError(conn, err)
				}
				return
			}

			if n > 0 {
				msg := WSMessage{
					Type: "log",
					Payload: LogMessage{
						Stream:    "stdout",
						Message:   string(buf[:n]),
						Timestamp: time.Now().Format(time.RFC3339),
					},
				}

				if err := h.writeWSMessage(conn, msg); err != nil {
					return
				}
			}
		}
	}
}
