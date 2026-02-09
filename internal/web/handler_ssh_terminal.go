// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/connections"
)

// SSHTerminalMessage represents a WebSocket message for SSH terminal.
type SSHTerminalMessage struct {
	Type     string `json:"type"` // "input", "output", "resize", "error", "connected", "disconnected", "credential_request", "credential_response"
	Data     string `json:"data,omitempty"`
	Cols     int    `json:"cols,omitempty"`
	Rows     int    `json:"rows,omitempty"`
	Field    string `json:"field,omitempty"`    // "username" or "password" for credential prompts
	Username string `json:"username,omitempty"` // for credential_response
	Password string `json:"password,omitempty"` // for credential_response
}

// WSSSHExec handles WebSocket connections for SSH terminal.
func (h *Handler) WSSSHExec(w http.ResponseWriter, r *http.Request) {
	connIDStr := chi.URLParam(r, "id")
	if connIDStr == "" {
		http.Error(w, "connection ID required", http.StatusBadRequest)
		return
	}

	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		http.Error(w, "invalid connection ID", http.StatusBadRequest)
		return
	}

	user := h.getUserData(r)
	if user == nil || user.ID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	userID, err := uuid.Parse(user.ID)
	if err != nil {
		http.Error(w, "invalid user", http.StatusUnauthorized)
		return
	}

	if h.sshService == nil {
		http.Error(w, "SSH service not configured", http.StatusServiceUnavailable)
		return
	}

	// Use the shared upgrader (proper origin validation, larger buffers)
	ws, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error("failed to upgrade WebSocket", "error", err)
		return
	}
	defer ws.Close()

	// Write mutex to prevent concurrent WebSocket writes (stdout + stderr goroutines)
	var wsMu sync.Mutex
	writeSSH := func(msg SSHTerminalMessage) error {
		wsMu.Lock()
		defer wsMu.Unlock()
		ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return ws.WriteJSON(msg)
	}

	clientIP := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		clientIP = xff
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Get connection to check if credentials are needed
	conn, err := h.sshService.GetConnection(ctx, connID)
	if err != nil {
		writeSSH(SSHTerminalMessage{Type: "error", Data: "Connection not found: " + err.Error()})
		return
	}

	// Check if we need to prompt for credentials
	needsUsername := conn.Username == ""
	needsPassword := conn.AuthType == models.SSHAuthPassword && conn.Password == ""

	var runtimeUsername, runtimePassword string

	if needsUsername {
		writeSSH(SSHTerminalMessage{
			Type:  "credential_request",
			Field: "username",
			Data:  "Username required for " + conn.Host,
		})

		ws.SetReadDeadline(time.Now().Add(2 * time.Minute))
		_, message, err := ws.ReadMessage()
		if err != nil {
			return
		}
		var resp SSHTerminalMessage
		if err := json.Unmarshal(message, &resp); err != nil || resp.Type != "credential_response" {
			writeSSH(SSHTerminalMessage{Type: "error", Data: "Invalid credential response"})
			return
		}
		runtimeUsername = resp.Username
		if runtimeUsername == "" {
			writeSSH(SSHTerminalMessage{Type: "error", Data: "Username cannot be empty"})
			return
		}
	}

	if needsPassword {
		writeSSH(SSHTerminalMessage{
			Type:  "credential_request",
			Field: "password",
			Data:  "Password required",
		})

		ws.SetReadDeadline(time.Now().Add(2 * time.Minute))
		_, message, err := ws.ReadMessage()
		if err != nil {
			return
		}
		var resp SSHTerminalMessage
		if err := json.Unmarshal(message, &resp); err != nil || resp.Type != "credential_response" {
			writeSSH(SSHTerminalMessage{Type: "error", Data: "Invalid credential response"})
			return
		}
		runtimePassword = resp.Password
	}

	// Connect SSH
	var sshClient *ssh.Client
	var session *models.SSHSession

	if needsUsername || needsPassword {
		sshClient, session, err = h.connectSSHWithCredentials(ctx, conn, connID, userID, clientIP, runtimeUsername, runtimePassword)
	} else {
		sshClient, session, err = h.sshService.Connect(ctx, connID, userID, clientIP)
	}

	if err != nil {
		writeSSH(SSHTerminalMessage{Type: "error", Data: "Failed to connect: " + err.Error()})
		return
	}

	// Create SSH session (PTY)
	sshSession, err := sshClient.NewSession()
	if err != nil {
		sshClient.Close()
		if session != nil && session.ID != uuid.Nil {
			h.sshService.EndSession(ctx, session.ID)
		}
		writeSSH(SSHTerminalMessage{Type: "error", Data: "Failed to create session: " + err.Error()})
		return
	}

	// Request PTY
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	cols, rows := 80, 24
	if c, err := strconv.Atoi(r.URL.Query().Get("cols")); err == nil && c > 0 {
		cols = c
	}
	if rr, err := strconv.Atoi(r.URL.Query().Get("rows")); err == nil && rr > 0 {
		rows = rr
	}

	if err := sshSession.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		sshSession.Close()
		sshClient.Close()
		if session != nil && session.ID != uuid.Nil {
			h.sshService.EndSession(ctx, session.ID)
		}
		writeSSH(SSHTerminalMessage{Type: "error", Data: "Failed to request PTY: " + err.Error()})
		return
	}

	// Get stdin/stdout pipes
	stdin, err := sshSession.StdinPipe()
	if err != nil {
		sshSession.Close()
		sshClient.Close()
		if session != nil && session.ID != uuid.Nil {
			h.sshService.EndSession(ctx, session.ID)
		}
		writeSSH(SSHTerminalMessage{Type: "error", Data: "Failed to get stdin: " + err.Error()})
		return
	}

	stdout, err := sshSession.StdoutPipe()
	if err != nil {
		sshSession.Close()
		sshClient.Close()
		if session != nil && session.ID != uuid.Nil {
			h.sshService.EndSession(ctx, session.ID)
		}
		writeSSH(SSHTerminalMessage{Type: "error", Data: "Failed to get stdout: " + err.Error()})
		return
	}

	stderr, err := sshSession.StderrPipe()
	if err != nil {
		sshSession.Close()
		sshClient.Close()
		if session != nil && session.ID != uuid.Nil {
			h.sshService.EndSession(ctx, session.ID)
		}
		writeSSH(SSHTerminalMessage{Type: "error", Data: "Failed to get stderr: " + err.Error()})
		return
	}

	// Start shell
	if err := sshSession.Shell(); err != nil {
		sshSession.Close()
		sshClient.Close()
		if session != nil && session.ID != uuid.Nil {
			h.sshService.EndSession(ctx, session.ID)
		}
		writeSSH(SSHTerminalMessage{Type: "error", Data: "Failed to start shell: " + err.Error()})
		return
	}

	writeSSH(SSHTerminalMessage{Type: "connected", Data: "SSH connection established"})

	log.Printf("[INFO] SSH Terminal: conn=%s host=%s user=%s", connID, conn.Host, conn.Username)

	// Cleanup with sync.Once to ensure it runs exactly once
	var closeOnce sync.Once
	cleanup := func() {
		closeOnce.Do(func() {
			cancel()
			sshSession.Close()
			sshClient.Close()
			if session != nil && session.ID != uuid.Nil {
				h.sshService.EndSession(context.Background(), session.ID)
			}
			wsMu.Lock()
			ws.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "session ended"),
				time.Now().Add(time.Second),
			)
			wsMu.Unlock()
		})
	}
	defer cleanup()

	// Ping/pong keepalive
	ws.SetPongHandler(func(string) error {
		ws.SetReadDeadline(time.Now().Add(5 * time.Minute))
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
				wsMu.Lock()
				err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second))
				wsMu.Unlock()
				if err != nil {
					cleanup()
					return
				}
			}
		}
	}()

	var wg sync.WaitGroup

	// SSH stdout -> WebSocket
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cleanup()
		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				if writeErr := writeSSH(SSHTerminalMessage{
					Type: "output",
					Data: string(buf[:n]),
				}); writeErr != nil {
					log.Printf("[DEBUG] SSH terminal WS write error: %v", writeErr)
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("[DEBUG] SSH stdout read ended: %v", err)
				}
				return
			}
		}
	}()

	// SSH stderr -> WebSocket
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cleanup()
		buf := make([]byte, 4096)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				if writeErr := writeSSH(SSHTerminalMessage{
					Type: "output",
					Data: string(buf[:n]),
				}); writeErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// WebSocket -> SSH stdin
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cleanup()

		for {
			ws.SetReadDeadline(time.Now().Add(5 * time.Minute))
			_, message, err := ws.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
					log.Printf("[DEBUG] SSH terminal WS read error: %v", err)
				}
				return
			}

			var msg SSHTerminalMessage
			if err := json.Unmarshal(message, &msg); err != nil {
				continue
			}

			switch msg.Type {
			case "input":
				if _, err := stdin.Write([]byte(msg.Data)); err != nil {
					log.Printf("[DEBUG] SSH stdin write error: %v", err)
					return
				}
			case "resize":
				if msg.Cols > 0 && msg.Rows > 0 {
					sshSession.WindowChange(msg.Rows, msg.Cols)
				}
			}
		}
	}()

	// Wait for shell to exit then cleanup
	sshSession.Wait()
	cleanup()
	wg.Wait()

	writeSSH(SSHTerminalMessage{Type: "disconnected", Data: "SSH connection closed"})
	log.Printf("[DEBUG] SSH terminal session ended: conn=%s", connID)
}

// connectSSHWithCredentials establishes an SSH connection with runtime-provided credentials
// when the stored connection doesn't have a username or password.
func (h *Handler) connectSSHWithCredentials(ctx context.Context, conn *models.SSHConnection, connID, userID uuid.UUID, clientIP, username, password string) (*ssh.Client, *models.SSHSession, error) {
	if username == "" {
		username = conn.Username
	}

	var authMethods []ssh.AuthMethod
	if password != "" {
		authMethods = append(authMethods, ssh.Password(password))
		// Also add keyboard-interactive for servers that require it
		authMethods = append(authMethods, ssh.KeyboardInteractive(
			func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			},
		))
	} else if conn.Password != "" && h.encryptor != nil {
		if decrypted, err := h.encryptor.Decrypt(conn.Password); err == nil {
			authMethods = append(authMethods, ssh.Password(decrypted))
		}
	}

	if len(authMethods) == 0 {
		return nil, nil, fmt.Errorf("no authentication methods available")
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            authMethods,
		HostKeyCallback: h.buildSSHHostKeyCallback(conn),
		Timeout:         30 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", conn.Host, conn.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, nil, fmt.Errorf("SSH dial failed: %w", err)
	}

	// Create and save session record via the service
	session := &models.SSHSession{
		ConnectionID: connID,
		UserID:       userID,
		ClientIP:     clientIP,
		TermType:     "xterm-256color",
		TermCols:     80,
		TermRows:     24,
	}

	if h.sshService != nil {
		if err := h.sshService.CreateSession(ctx, session); err != nil {
			h.logger.Warn("failed to save SSH session", "error", err)
			// Don't fail the connection for session recording issues
		}
	}

	return client, session, nil
}

// sendSSHMessage sends a message over the WebSocket (use writeSSH closure in WSSSHExec instead).
func (h *Handler) sendSSHMessage(ws *websocket.Conn, msg SSHTerminalMessage) error {
	ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return ws.WriteJSON(msg)
}

// SSHTerminalTempl renders the SSH terminal page.
func (h *Handler) SSHTerminalTempl(w http.ResponseWriter, r *http.Request) {
	connIDStr := chi.URLParam(r, "id")
	if connIDStr == "" {
		http.Error(w, "connection ID required", http.StatusBadRequest)
		return
	}

	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		http.Error(w, "invalid connection ID", http.StatusBadRequest)
		return
	}

	if h.sshService == nil {
		http.Error(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	conn, err := h.sshService.GetConnection(r.Context(), connID)
	if err != nil {
		http.Error(w, "connection not found", http.StatusNotFound)
		return
	}

	pageData := h.preparePageData(r, "SSH Terminal - "+conn.Name, "connections-ssh")

	data := connections.SSHTerminalData{
		PageData:   ToTemplPageData(pageData),
		Connection: toSSHConnectionData(conn),
	}

	if err := connections.SSHTerminal(data).Render(r.Context(), w); err != nil {
		log.Printf("[ERROR] failed to render SSH terminal: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// SSHService interface for handler
type SSHService interface {
	Connect(ctx context.Context, connID uuid.UUID, userID uuid.UUID, clientIP string) (*ssh.Client, *models.SSHSession, error)
	EndSession(ctx context.Context, sessionID uuid.UUID) error
	GetConnection(ctx context.Context, id uuid.UUID) (*models.SSHConnection, error)
	SaveConnectionOptions(ctx context.Context, conn *models.SSHConnection) error
	CreateSession(ctx context.Context, session *models.SSHSession) error
}

// SetSSHService sets the SSH service for terminal connections.
func (h *Handler) SetSSHService(svc SSHService) {
	h.sshService = svc
}

// buildSSHHostKeyCallback returns a TOFU (Trust On First Use) host key callback.
// On first connection the server's key fingerprint is stored; on subsequent
// connections the key is verified against the stored value.
func (h *Handler) buildSSHHostKeyCallback(conn *models.SSHConnection) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		hash := sha256.Sum256(key.Marshal())
		fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])

		stored := conn.Options.HostKeyFingerprint
		if stored == "" {
			// TOFU: store fingerprint on first connection
			conn.Options.HostKeyFingerprint = fingerprint
			if h.sshService != nil {
				if err := h.sshService.SaveConnectionOptions(context.Background(), conn); err != nil {
					log.Printf("[WARN] failed to persist SSH host key: %v", err)
				}
			}
			return nil
		}

		if stored != fingerprint {
			return fmt.Errorf("host key mismatch for %s: expected %s, got %s",
				hostname, stored, fingerprint)
		}
		return nil
	}
}
