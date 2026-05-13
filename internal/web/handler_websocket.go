// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/fr4nsys/usulnet/internal/docker"
)

// ============================================================================
// WebSocket Upgrader Configuration
// ============================================================================

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		return isAllowedWebSocketOrigin(r)
	},
	HandshakeTimeout: 10 * time.Second,
}

// safeWSConn wraps a WebSocket connection with a write mutex to prevent
// concurrent write panics (gorilla/websocket requires serial writes).
type safeWSConn struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func newSafeWSConn(conn *websocket.Conn) *safeWSConn {
	return &safeWSConn{conn: conn}
}

func (s *safeWSConn) WriteJSON(v interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return s.conn.WriteJSON(v)
}

func (s *safeWSConn) WriteControl(messageType int, data []byte, deadline time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.WriteControl(messageType, data, deadline)
}

// ============================================================================
// WebSocket Message Types
// ============================================================================

type WSMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

type WSLogMessage struct {
	Type      string `json:"type"`
	Data      string `json:"data"`
	Stream    string `json:"stream,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

type WSExecMessage struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

type WSStatsMessage struct {
	Type        string  `json:"type"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemoryUsage int64   `json:"memory_usage"`
	MemoryLimit int64   `json:"memory_limit"`
	MemoryPct   float64 `json:"memory_percent"`
	NetRx       int64   `json:"net_rx"`
	NetTx       int64   `json:"net_tx"`
	BlockRead   int64   `json:"block_read"`
	BlockWrite  int64   `json:"block_write"`
	PIDs        int64   `json:"pids"`
	Timestamp   string  `json:"timestamp"`
}

type WSEventMessage struct {
	Type      string            `json:"type"`
	Action    string            `json:"action"`
	Actor     string            `json:"actor"`
	ActorID   string            `json:"actor_id"`
	ActorType string            `json:"actor_type"`
	Attrs     map[string]string `json:"attrs,omitempty"`
	Timestamp string            `json:"timestamp"`
}

type WSJobMessage struct {
	Type     string `json:"type"`
	JobID    string `json:"job_id"`
	Status   string `json:"status"`
	Progress int    `json:"progress"`
	Message  string `json:"message,omitempty"`
	Error    string `json:"error,omitempty"`
}

// ============================================================================
// WebSocket Container Logs Handler
// ============================================================================

func (h *Handler) WSContainerLogs(w http.ResponseWriter, r *http.Request) {
	containerID := chi.URLParam(r, "id")
	if containerID == "" {
		http.Error(w, "Container ID required", http.StatusBadRequest)
		return
	}

	tailStr := r.URL.Query().Get("tail")
	tail := 500
	if tailStr != "" {
		if t, err := strconv.Atoi(tailStr); err == nil && t > 0 {
			tail = t
		}
	}
	follow := r.URL.Query().Get("follow") != "false"

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ERROR] WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Ping/pong keep-alive
	conn.SetReadLimit(512)
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)); err != nil {
					cancel()
					return
				}
			}
		}
	}()

	go func() {
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				cancel()
				return
			}
		}
	}()

	// Get Docker client
	dockerClientAPI, err := h.services.Containers().GetDockerClient(ctx)
	if err != nil {
		h.sendWSMessage(conn, WSLogMessage{Type: "error", Data: "Failed to get Docker client: " + err.Error()})
		return
	}

	// Log streaming requires a direct Docker client connection
	directClient, ok := dockerClientAPI.(*docker.Client)
	if !ok {
		h.sendWSMessage(conn, WSLogMessage{Type: "error", Data: "Log streaming not available for remote hosts"})
		return
	}

	h.sendWSMessage(conn, WSLogMessage{
		Type:      "connected",
		Data:      "Connected to log stream",
		Timestamp: time.Now().Format(time.RFC3339),
	})

	// Use Docker streaming logs API
	logOpts := docker.LogOptions{
		Follow:     follow,
		Timestamps: true,
		Tail:       strconv.Itoa(tail),
		Stdout:     true,
		Stderr:     true,
	}

	logCh, err := directClient.ContainerLogsStream(ctx, containerID, logOpts)
	if err != nil {
		h.sendWSMessage(conn, WSLogMessage{Type: "error", Data: "Failed to stream logs: " + err.Error()})
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case logLine, ok := <-logCh:
			if !ok {
				h.sendWSMessage(conn, WSLogMessage{
					Type:      "disconnected",
					Data:      "Log stream ended",
					Timestamp: time.Now().Format(time.RFC3339),
				})
				return
			}

			msg := WSLogMessage{
				Type:      "log",
				Data:      logLine.Message,
				Stream:    logLine.Stream,
				Timestamp: logLine.Timestamp.Format(time.RFC3339),
			}
			if err := h.sendWSMessage(conn, msg); err != nil {
				return
			}
		}
	}
}

// ============================================================================
// WebSocket Container Exec Handler (Real Docker Exec)
// ============================================================================

func (h *Handler) WSContainerExec(w http.ResponseWriter, r *http.Request) {
	containerID := chi.URLParam(r, "id")
	if containerID == "" {
		http.Error(w, "Container ID required", http.StatusBadRequest)
		return
	}

	shell := r.URL.Query().Get("shell")
	if shell == "" {
		shell = "/bin/sh"
	}

	cols := 80
	rows := 24
	if c, err := strconv.Atoi(r.URL.Query().Get("cols")); err == nil && c > 0 {
		cols = c
	}
	if ro, err := strconv.Atoi(r.URL.Query().Get("rows")); err == nil && ro > 0 {
		rows = ro
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ERROR] WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Check container is running
	container, err := h.services.Containers().Get(ctx, containerID)
	if err != nil {
		h.sendWSError(conn, "Container not found: "+err.Error())
		return
	}
	if container.State != "running" {
		h.sendWSError(conn, "Container is not running. Start the container first.")
		return
	}

	// Get Docker client - terminal requires direct connection
	dockerClientAPI, err := h.services.Containers().GetDockerClient(ctx)
	if err != nil {
		h.sendWSError(conn, "Failed to get Docker client: "+err.Error())
		return
	}
	dockerClient, ok := dockerClientAPI.(*docker.Client)
	if !ok {
		h.sendWSError(conn, "Terminal not available for remote hosts")
		return
	}

	// Detect available shell
	actualShell := shell
	if shell == "/bin/bash" {
		if hasBash, err := dockerClient.CheckCommandExists(ctx, containerID, "bash"); err != nil || !hasBash {
			actualShell = "/bin/sh"
			log.Printf("[DEBUG] Terminal: bash not available, falling back to /bin/sh for %s", container.Name)
		}
	}

	log.Printf("[INFO] Terminal: container=%s name=%s shell=%s cols=%d rows=%d", containerID, container.Name, actualShell, cols, rows)

	// Create interactive exec session
	execOpts := docker.ExecOptions{
		Tty:         true,
		AttachStdin: true,
		Env:         []string{"TERM=xterm-256color", "COLUMNS=" + strconv.Itoa(cols), "LINES=" + strconv.Itoa(rows)},
	}

	hijacked, execID, err := dockerClient.ContainerExecInteractive(ctx, containerID, []string{actualShell}, execOpts)
	if err != nil {
		log.Printf("[ERROR] Terminal exec failed: container=%s error=%v", containerID, err)
		h.sendWSError(conn, "Failed to create exec session: "+err.Error())
		return
	}
	log.Printf("[DEBUG] Terminal exec created: execID=%s container=%s", execID, containerID)

	// Log terminal session if repository is available
	var terminalSessionID uuid.UUID
	if h.terminalSessionRepo != nil {
		user := GetUserFromContext(r.Context())
		userName := "anonymous"
		var userID uuid.UUID
		if user != nil {
			userName = user.Username
			if parsedID, err := uuid.Parse(user.ID); err == nil {
				userID = parsedID
			}
		}

		var hostID *uuid.UUID
		if container.HostID != "" {
			if hid, err := uuid.Parse(container.HostID); err == nil {
				hostID = &hid
			}
		}

		sessionInput := &CreateTerminalSessionInput{
			UserID:     userID,
			Username:   userName,
			TargetType: "container",
			TargetID:   containerID,
			TargetName: container.Name,
			HostID:     hostID,
			Shell:      actualShell,
			TermCols:   cols,
			TermRows:   rows,
			ClientIP:   getRealIP(r),
			UserAgent:  r.UserAgent(),
		}

		if sid, err := h.terminalSessionRepo.Create(context.Background(), sessionInput); err != nil {
			log.Printf("[WARN] Failed to log terminal session: %v", err)
		} else {
			terminalSessionID = sid
			log.Printf("[DEBUG] Terminal session created: sessionID=%s", sid)
		}
	}

	h.sendWSMessage(conn, WSExecMessage{
		Type: "connected",
		Data: "Connected to " + container.Name,
	})

	// Initial resize
	if err := dockerClient.ContainerExecResize(ctx, execID, uint(rows), uint(cols)); err != nil {
		log.Printf("[WARN] Terminal initial resize failed: %v", err)
	}

	// Use sync.Once to ensure cleanup happens exactly once
	var closeOnce sync.Once
	cleanup := func() {
		closeOnce.Do(func() {
			cancel()

			// End terminal session if it was created
			if h.terminalSessionRepo != nil && terminalSessionID != uuid.Nil {
				if err := h.terminalSessionRepo.End(context.Background(), terminalSessionID, "completed", ""); err != nil {
					log.Printf("[WARN] Failed to end terminal session: %v", err)
				}
			}

			// Close hijacked to unblock output goroutine
			hijacked.Close()
			// Close WebSocket to unblock input goroutine
			conn.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "session ended"),
				time.Now().Add(time.Second),
			)
		})
	}
	defer cleanup()

	var wg sync.WaitGroup

	// Docker exec output -> WebSocket
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cleanup()

		buf := make([]byte, 4096)
		for {
			n, err := hijacked.Reader.Read(buf)
			if n > 0 {
				if writeErr := h.sendWSMessage(conn, WSExecMessage{
					Type: "output",
					Data: string(buf[:n]),
				}); writeErr != nil {
					log.Printf("[DEBUG] Terminal WS write error: %v", writeErr)
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("[DEBUG] Terminal exec read ended: %v", err)
				} else {
					log.Printf("[DEBUG] Terminal exec EOF: container=%s", containerID)
				}
				return
			}
		}
	}()

	// WebSocket input -> Docker exec stdin
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cleanup()

		conn.SetReadLimit(64 * 1024) // 64KB max per message — sufficient for terminal input + resize commands

		for {
			conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
			_, message, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
					log.Printf("[DEBUG] Terminal WS read error: %v", err)
				}
				return
			}

			var execMsg WSExecMessage
			if err := json.Unmarshal(message, &execMsg); err != nil {
				continue
			}

			switch execMsg.Type {
			case "input":
				if _, err := hijacked.Conn.Write([]byte(execMsg.Data)); err != nil {
					log.Printf("[DEBUG] Terminal exec write error: %v", err)
					return
				}
			case "resize":
				if execMsg.Cols > 0 && execMsg.Rows > 0 {
					if err := dockerClient.ContainerExecResize(ctx, execID, uint(execMsg.Rows), uint(execMsg.Cols)); err != nil {
						log.Printf("[DEBUG] Terminal resize error: %v", err)
					}
				}
			}
		}
	}()

	wg.Wait()
	log.Printf("[DEBUG] Terminal session ended: container=%s", containerID)
}

// ============================================================================
// WebSocket Container Stats Handler (Real Docker Stats)
// ============================================================================

func (h *Handler) WSContainerStats(w http.ResponseWriter, r *http.Request) {
	containerID := chi.URLParam(r, "id")
	if containerID == "" {
		http.Error(w, "Container ID required", http.StatusBadRequest)
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ERROR] WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Ping/pong keepalive
	conn.SetReadLimit(512)
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	go func() {
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				cancel()
				return
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)); err != nil {
					cancel()
					return
				}
			}
		}
	}()

	dockerClientAPI, err := h.services.Containers().GetDockerClient(ctx)
	if err != nil {
		h.sendWSMessage(conn, map[string]string{"type": "error", "message": "Failed to get Docker client: " + err.Error()})
		return
	}
	dockerClient, ok := dockerClientAPI.(*docker.Client)
	if !ok {
		h.sendWSMessage(conn, map[string]string{"type": "error", "message": "Stats streaming not available for remote hosts"})
		return
	}

	h.sendWSMessage(conn, map[string]string{"type": "connected", "message": "Stats stream connected"})

	// Docker streaming stats
	statsCh, err := dockerClient.ContainerStats(ctx, containerID)
	if err != nil {
		h.sendWSMessage(conn, map[string]string{"type": "error", "message": "Failed to stream stats: " + err.Error()})
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case stats, ok := <-statsCh:
			if !ok {
				return
			}
			msg := WSStatsMessage{
				Type:        "stats",
				CPUPercent:  stats.CPUPercent,
				MemoryUsage: int64(stats.MemoryUsage),
				MemoryLimit: int64(stats.MemoryLimit),
				MemoryPct:   stats.MemoryPercent,
				NetRx:       int64(stats.NetworkRx),
				NetTx:       int64(stats.NetworkTx),
				BlockRead:   int64(stats.BlockRead),
				BlockWrite:  int64(stats.BlockWrite),
				PIDs:        int64(stats.PIDs),
				Timestamp:   stats.Read.Format(time.RFC3339),
			}
			if err := h.sendWSMessage(conn, msg); err != nil {
				return
			}
		}
	}
}

// ============================================================================
// WebSocket Events Handler
// ============================================================================

func (h *Handler) WSEvents(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ERROR] WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Ping/pong keepalive
	conn.SetReadLimit(512)
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	go func() {
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				cancel()
				return
			}
		}
	}()

	go func() {
		pingTicker := time.NewTicker(30 * time.Second)
		defer pingTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-pingTicker.C:
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)); err != nil {
					cancel()
					return
				}
			}
		}
	}()

	h.sendWSMessage(conn, map[string]string{"type": "connected", "message": "Event stream connected"})

	// Stream real Docker events
	eventCh, err := h.services.Events().Stream(ctx)
	if err != nil {
		log.Printf("[ERROR] Failed to start event stream: %v", err)
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-eventCh:
			if !ok {
				// Event channel closed, keep heartbeat alive
				eventCh = nil
				continue
			}
			msg := map[string]string{
				"type":       "event",
				"event_type": ev.Type,
				"action":     ev.Action,
				"actor_id":   ev.ActorID,
				"actor_name": ev.ActorName,
				"message":    ev.Message,
				"timestamp":  ev.Timestamp.Format(time.RFC3339),
				"time_human": ev.TimeHuman,
			}
			if err := h.sendWSMessage(conn, msg); err != nil {
				return
			}
		case <-ticker.C:
			if err := h.sendWSMessage(conn, map[string]string{
				"type":      "heartbeat",
				"timestamp": time.Now().Format(time.RFC3339),
			}); err != nil {
				return
			}
		}
	}
}

// ============================================================================
// WebSocket Job Progress Handler
// ============================================================================

func (h *Handler) WSJobProgress(w http.ResponseWriter, r *http.Request) {
	jobID := chi.URLParam(r, "id")
	if jobID == "" {
		http.Error(w, "Job ID required", http.StatusBadRequest)
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ERROR] WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Ping/pong keepalive
	conn.SetReadLimit(512)
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	go func() {
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				cancel()
				return
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)); err != nil {
					cancel()
					return
				}
			}
		}
	}()

	h.sendWSMessage(conn, WSJobMessage{
		Type:    "connected",
		JobID:   jobID,
		Status:  "connected",
		Message: "Job progress stream connected",
	})

	parsedJobID, parseErr := uuid.Parse(jobID)
	if parseErr != nil {
		h.sendWSError(conn, "Invalid job ID")
		return
	}

	// Poll job status every 2 seconds
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var lastStatus string
	var lastProgress int
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			schedulerSvc := h.services.Scheduler()
			if schedulerSvc == nil {
				continue
			}

			job, err := schedulerSvc.GetJob(ctx, parsedJobID)
			if err != nil {
				continue
			}

			status := string(job.Status)
			progress := job.Progress
			// Only send updates when something changed
			if status != lastStatus || progress != lastProgress {
				lastStatus = status
				lastProgress = progress
				msg := WSJobMessage{
					Type:     "progress",
					JobID:    jobID,
					Status:   status,
					Progress: progress,
				}
				if job.ErrorMessage != nil && *job.ErrorMessage != "" {
					msg.Error = *job.ErrorMessage
				}
				if err := h.sendWSMessage(conn, msg); err != nil {
					return
				}

				// If job is finished, send final update and close
				if status == "completed" || status == "failed" || status == "cancelled" {
					return
				}
			}
		}
	}
}

// ============================================================================
// WebSocket Capture Stats Handler
// ============================================================================

func (h *Handler) WSCapture(w http.ResponseWriter, r *http.Request) {
	captureID := chi.URLParam(r, "id")
	if captureID == "" {
		http.Error(w, "Capture ID required", http.StatusBadRequest)
		return
	}

	id, err := uuid.Parse(captureID)
	if err != nil {
		http.Error(w, "Invalid capture ID", http.StatusBadRequest)
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ERROR] WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Ping/pong keepalive
	conn.SetReadLimit(512)
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	go func() {
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				cancel()
				return
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)); err != nil {
					cancel()
					return
				}
			}
		}
	}()

	h.sendWSMessage(conn, map[string]interface{}{
		"type":    "connected",
		"message": "Capture stream connected",
	})

	// Poll capture stats every 2 seconds
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var lastPacketCount int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if h.captureService == nil {
				continue
			}
			capture, err := h.captureService.GetCapture(ctx, id)
			if err != nil {
				continue
			}

			msg := map[string]interface{}{
				"type":         "stats",
				"status":       string(capture.Status),
				"packet_count": capture.PacketCount,
				"file_size":    capture.FileSize,
			}

			// Only send if something changed or capture is running
			if capture.PacketCount != lastPacketCount || capture.Status == "running" {
				lastPacketCount = capture.PacketCount
				if err := h.sendWSMessage(conn, msg); err != nil {
					return
				}
			}

			// If capture is no longer running, send final update and close
			if capture.Status != "running" {
				h.sendWSMessage(conn, map[string]interface{}{
					"type":    "finished",
					"status":  string(capture.Status),
					"message": "Capture " + string(capture.Status),
				})
				return
			}
		}
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

func (h *Handler) sendWSMessage(conn *websocket.Conn, msg interface{}) error {
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return conn.WriteJSON(msg)
}

func (h *Handler) sendWSError(conn *websocket.Conn, message string) {
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	conn.WriteJSON(map[string]string{
		"type":    "error",
		"message": message,
	})
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
