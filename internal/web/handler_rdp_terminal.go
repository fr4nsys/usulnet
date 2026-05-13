// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/fr4nsys/usulnet/internal/web/templates/pages/connections"
)

// rdpUpgrader is a WebSocket upgrader for RDP sessions that negotiates
// the "guacamole" subprotocol required by guacamole-common-js.
var rdpUpgrader = websocket.Upgrader{
	ReadBufferSize:  32768,
	WriteBufferSize: 32768,
	Subprotocols:    []string{"guacamole"},
	CheckOrigin: func(r *http.Request) bool {
		return isAllowedWebSocketOrigin(r)
	},
	HandshakeTimeout: 10 * time.Second,
}

// GuacdConfig holds Apache Guacamole daemon connection settings.
type GuacdConfig struct {
	Enabled bool   // GUACD_ENABLED (default: true)
	Host    string // GUACD_HOST (default: guacd)
	Port    int    // GUACD_PORT (default: 4822)
}

// DefaultGuacdConfig returns default guacd configuration.
func DefaultGuacdConfig() GuacdConfig {
	return GuacdConfig{
		Enabled: true,
		Host:    "guacd",
		Port:    4822,
	}
}

// buildGuacdConfig builds GuacdConfig from HandlerDeps, applying defaults.
func buildGuacdConfig(deps HandlerDeps) GuacdConfig {
	cfg := DefaultGuacdConfig()
	cfg.Enabled = deps.GuacdEnabled
	if deps.GuacdHost != "" {
		cfg.Host = deps.GuacdHost
	}
	if deps.GuacdPort > 0 {
		cfg.Port = deps.GuacdPort
	}
	return cfg
}

// WSRDPExec handles WebSocket connections for RDP via Apache Guacamole daemon.
// The handler establishes a TCP connection to guacd, performs the Guacamole
// protocol handshake, and relays traffic bidirectionally between the browser
// (WebSocket) and guacd (TCP).
func (h *Handler) WSRDPExec(w http.ResponseWriter, r *http.Request) {
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

	if h.rdpService == nil {
		http.Error(w, "RDP service not configured", http.StatusServiceUnavailable)
		return
	}

	// Get RDP connection details
	conn, err := h.rdpService.GetConnection(r.Context(), connID)
	if err != nil {
		http.Error(w, "connection not found", http.StatusNotFound)
		return
	}

	// Get guacd configuration
	guacdCfg := h.getGuacdConfig()
	if !guacdCfg.Enabled {
		http.Error(w, "RDP web access not configured (guacd not enabled)", http.StatusServiceUnavailable)
		return
	}

	// Upgrade to WebSocket with "guacamole" subprotocol
	ws, err := rdpUpgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error("failed to upgrade WebSocket for RDP", "error", err)
		return
	}
	defer ws.Close()

	// Clear any deadlines inherited from http.Server.WriteTimeout/ReadTimeout.
	// After hijack, the raw net.Conn retains the server's deadline which would
	// kill this long-lived WebSocket connection after WriteTimeout seconds.
	ws.NetConn().SetDeadline(time.Time{})

	// Connect to guacd
	guacdAddr := net.JoinHostPort(guacdCfg.Host, strconv.Itoa(guacdCfg.Port))
	guacdConn, err := net.DialTimeout("tcp", guacdAddr, 10*time.Second)
	if err != nil {
		h.logger.Error("RDP: failed to connect to guacd", "address", guacdAddr, "error", err)
		ws.WriteMessage(websocket.TextMessage, []byte(guacEncode("error", "Failed to connect to RDP gateway", "519")))
		return
	}
	defer guacdConn.Close()

	// Perform Guacamole protocol handshake
	// 1. Send "select" instruction with protocol type "rdp"
	if _, err := guacdConn.Write([]byte(guacEncode("select", "rdp"))); err != nil {
		h.logger.Error("RDP: failed to send select to guacd", "error", err)
		ws.WriteMessage(websocket.TextMessage, []byte(guacEncode("error", "Protocol error", "519")))
		return
	}

	// 2. Read the "args" instruction from guacd (list of expected parameters)
	argsBuf := make([]byte, 16384)
	n, err := guacdConn.Read(argsBuf)
	if err != nil {
		h.logger.Error("RDP: failed to read args from guacd", "error", err)
		ws.WriteMessage(websocket.TextMessage, []byte(guacEncode("error", "Protocol error", "519")))
		return
	}
	argsResponse := string(argsBuf[:n])
	h.logger.Debug("RDP guacd args response", "bytes", n)

	// Parse the args instruction to get parameter names
	paramNames := guacParseArgs(argsResponse)
	h.logger.Debug("RDP guacd param count", "count", len(paramNames))

	// 3. Build connection parameters
	password := ""
	if conn.Password != "" && h.encryptor != nil {
		if decrypted, err := h.encryptor.Decrypt(conn.Password); err == nil {
			password = decrypted
		}
	}

	// Parse resolution
	width, height := "1024", "768"
	if conn.Resolution != "" && conn.Resolution != "auto" {
		parts := strings.SplitN(conn.Resolution, "x", 2)
		if len(parts) == 2 {
			width = parts[0]
			height = parts[1]
		}
	}

	// Map security mode
	security := "any"
	switch string(conn.Security) {
	case "nla":
		security = "nla"
	case "tls":
		security = "tls"
	case "rdp":
		security = "rdp"
	}

	// Build parameter values map
	paramValues := map[string]string{
		// Protocol version — must match guacd and JS client version.
		// Without this, guacd falls back to legacy protocol and sends
		// instructions that guacamole-common-js 1.5.0 cannot parse.
		"VERSION_1_5_0":         "VERSION_1_5_0",
		"hostname":              conn.Host,
		"port":                  fmt.Sprintf("%d", conn.Port),
		"username":              conn.Username,
		"password":              password,
		"domain":                conn.Domain,
		"width":                 width,
		"height":                height,
		"dpi":                   "96",
		"color-depth":           conn.ColorDepth,
		"security":              security,
		"ignore-cert":           "true",
		"disable-audio":         "true",
		"enable-wallpaper":      "false",
		"enable-theming":        "true",
		"enable-font-smoothing": "true",
		"resize-method":         "display-update",
	}

	// 4. Send "size" instruction
	if _, err := guacdConn.Write([]byte(guacEncode("size", width, height, "96"))); err != nil {
		h.logger.Error("RDP: failed to send size to guacd", "error", err)
		return
	}

	// 5. Send "audio" instruction (empty - no audio)
	if _, err := guacdConn.Write([]byte(guacEncode("audio"))); err != nil {
		h.logger.Error("RDP: failed to send audio to guacd", "error", err)
		return
	}

	// 6. Send "video" instruction (empty - no video)
	if _, err := guacdConn.Write([]byte(guacEncode("video"))); err != nil {
		h.logger.Error("RDP: failed to send video to guacd", "error", err)
		return
	}

	// 7. Send "image" instruction (supported formats)
	if _, err := guacdConn.Write([]byte(guacEncode("image", "image/png", "image/jpeg", "image/webp"))); err != nil {
		h.logger.Error("RDP: failed to send image to guacd", "error", err)
		return
	}

	// 8. Send "connect" instruction with parameters matching the args order
	connectArgs := make([]string, len(paramNames))
	for i, name := range paramNames {
		if val, ok := paramValues[name]; ok {
			connectArgs[i] = val
		}
	}
	connectInstruction := guacEncode("connect", connectArgs...)
	if _, err := guacdConn.Write([]byte(connectInstruction)); err != nil {
		h.logger.Error("RDP: failed to send connect to guacd", "error", err)
		return
	}

	// 9. Read guacd response to connect (should be "ready" instruction)
	readyBuf := make([]byte, 8192)
	rn, err := guacdConn.Read(readyBuf)
	if err != nil {
		h.logger.Error("RDP: failed to read connect response from guacd", "error", err)
		ws.WriteMessage(websocket.TextMessage, []byte(guacEncode("error", "RDP connection failed", "519")))
		return
	}
	_ = string(readyBuf[:rn]) // log payload omitted to keep PII out of debug
	h.logger.Debug("RDP guacd connect response", "bytes", rn)

	// Forward the guacd response to the browser — the JS client needs it
	if err := ws.WriteMessage(websocket.TextMessage, readyBuf[:rn]); err != nil {
		h.logger.Error("RDP: failed to forward ready to browser", "error", err)
		return
	}

	h.logger.Info("RDP session started",
		"conn_id", connID,
		"host", conn.Host,
		"rdp_user", conn.Username,
		"user_id", user.ID,
	)

	// Record terminal session for audit trail
	var terminalSessionID uuid.UUID
	if h.terminalSessionRepo != nil {
		userUUID, parseErr := uuid.Parse(user.ID)
		if parseErr == nil {
			sessionInput := &CreateTerminalSessionInput{
				UserID:     userUUID,
				Username:   user.Username,
				TargetType: "rdp",
				TargetID:   connID.String(),
				TargetName: fmt.Sprintf("RDP (%s@%s:%d)", conn.Username, conn.Host, conn.Port),
				Shell:      "rdp",
				TermCols:   0,
				TermRows:   0,
				ClientIP:   getRealIP(r),
				UserAgent:  r.UserAgent(),
			}

			if sid, createErr := h.terminalSessionRepo.Create(context.Background(), sessionInput); createErr != nil {
				h.logger.Warn("Failed to log RDP terminal session", "error", createErr)
			} else {
				terminalSessionID = sid
				h.logger.Debug("RDP terminal session created", "session_id", sid)
			}
		}
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	var closeOnce sync.Once
	var wsMu sync.Mutex
	cleanup := func() {
		closeOnce.Do(func() {
			cancel()

			// End terminal session if it was created
			if h.terminalSessionRepo != nil && terminalSessionID != uuid.Nil {
				if endErr := h.terminalSessionRepo.End(context.Background(), terminalSessionID, "completed", ""); endErr != nil {
					h.logger.Warn("Failed to end RDP terminal session", "error", endErr)
				}
			}

			guacdConn.Close()
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

	// guacd -> WebSocket (relay Guacamole protocol instructions to browser)
	//
	// IMPORTANT: Each WebSocket message MUST contain only complete Guacamole
	// instructions (terminated by ';'). TCP is a stream protocol, so a single
	// Read() may return data ending mid-instruction. The Guacamole JS parser
	// in WebSocketTunnel calls close("Incomplete instruction.") if a message
	// doesn't parse cleanly, killing the tunnel immediately.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cleanup()
		buf := make([]byte, 32768)
		var pending []byte // leftover data from previous Read (partial instruction)
		for {
			guacdConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
			n, err := guacdConn.Read(buf)
			if n > 0 {
				data := buf[:n]
				if len(pending) > 0 {
					data = append(pending, data...)
					pending = nil
				}

				// Find the last complete instruction boundary (last ';')
				lastSemicolon := bytes.LastIndexByte(data, ';')
				if lastSemicolon == -1 {
					// No complete instruction yet — buffer everything
					pending = append(pending, data...)
				} else {
					// Send only complete instructions (up to and including last ';')
					complete := data[:lastSemicolon+1]
					if lastSemicolon+1 < len(data) {
						// Buffer the trailing partial instruction for next Read
						pending = append(pending, data[lastSemicolon+1:]...)
					}

					wsMu.Lock()
					ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
					writeErr := ws.WriteMessage(websocket.TextMessage, complete)
					wsMu.Unlock()
					if writeErr != nil {
						h.logger.Debug("RDP WS write error", "error", writeErr)
						return
					}
				}
			}
			if err != nil {
				// Flush any remaining buffered data before exiting
				if len(pending) > 0 {
					wsMu.Lock()
					ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
					ws.WriteMessage(websocket.TextMessage, pending)
					wsMu.Unlock()
				}
				if err != io.EOF {
					h.logger.Debug("RDP guacd read ended", "error", err)
				}
				return
			}
		}
	}()

	// WebSocket -> guacd (relay browser input to guacd)
	//
	// The Guacamole JS WebSocketTunnel sends internal ping instructions with
	// an empty opcode ("0.,4.ping,<len>.<timestamp>;"). These must be echoed
	// back to the browser to keep the tunnel's receive-timeout from firing.
	// They must NOT be forwarded to guacd which doesn't understand them.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cleanup()
		for {
			ws.SetReadDeadline(time.Now().Add(5 * time.Minute))
			_, message, err := ws.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
					h.logger.Debug("RDP WS read error", "error", err)
				}
				return
			}

			// Intercept internal tunnel pings (opcode "" = "0.,...")
			// and echo them back instead of forwarding to guacd.
			if bytes.HasPrefix(message, []byte("0.")) {
				wsMu.Lock()
				ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
				ws.WriteMessage(websocket.TextMessage, message)
				wsMu.Unlock()
				continue
			}

			guacdConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := guacdConn.Write(message); err != nil {
				h.logger.Debug("RDP guacd write error", "error", err)
				return
			}
		}
	}()

	wg.Wait()
	h.logger.Debug("RDP session ended", "conn_id", connID)
}

// RDPSessionTempl renders the RDP session page with the web client.
func (h *Handler) RDPSessionTempl(w http.ResponseWriter, r *http.Request) {
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

	if h.rdpService == nil {
		http.Error(w, "RDP service not available", http.StatusServiceUnavailable)
		return
	}

	conn, err := h.rdpService.GetConnection(r.Context(), connID)
	if err != nil {
		http.Error(w, "connection not found", http.StatusNotFound)
		return
	}

	guacdCfg := h.getGuacdConfig()

	pageData := h.preparePageData(r, "RDP Session - "+conn.Name, "connections-rdp")

	data := connections.RDPSessionData{
		PageData:     ToTemplPageData(pageData),
		Connection:   toRDPConnectionData(conn),
		GuacdEnabled: guacdCfg.Enabled,
	}

	if err := connections.RDPSession(data).Render(r.Context(), w); err != nil {
		h.logger.Error("Failed to render RDP session", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// getGuacdConfig returns the guacd configuration from the handler.
func (h *Handler) getGuacdConfig() GuacdConfig {
	return h.guacdConfig
}

// ============================================================================
// Guacamole Protocol Helpers
// ============================================================================

// guacEncode encodes a Guacamole protocol instruction.
// Format: <length>.<value>,<length>.<value>,...;
// Example: guacEncode("select", "rdp") => "6.select,3.rdp;"
func guacEncode(opcode string, args ...string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%d.%s", len(opcode), opcode))
	for _, arg := range args {
		b.WriteString(fmt.Sprintf(",%d.%s", len(arg), arg))
	}
	b.WriteByte(';')
	return b.String()
}

// guacParseArgs parses a Guacamole "args" instruction and returns parameter names.
// Input format: "4.args,8.hostname,4.port,...;"
func guacParseArgs(instruction string) []string {
	instruction = strings.TrimSpace(instruction)
	instruction = strings.TrimSuffix(instruction, ";")

	parts := strings.Split(instruction, ",")
	if len(parts) < 2 {
		return nil
	}

	// Skip the opcode (first element, which should be "args")
	var names []string
	for _, part := range parts[1:] {
		// Format: <length>.<value>
		idx := strings.Index(part, ".")
		if idx < 0 {
			continue
		}
		names = append(names, part[idx+1:])
	}
	return names
}
