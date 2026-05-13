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
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/hosts"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// =============================================================================
// Host Terminal Configuration
// =============================================================================

// HostTerminalConfig holds host terminal settings from environment variables.
type HostTerminalConfig struct {
	Enabled bool   // HOST_TERMINAL_ENABLED (default: true)
	User    string // HOST_TERMINAL_USER (default: nobody_usulnet)
	Shell   string // HOST_TERMINAL_SHELL (default: /bin/bash)
}

// =============================================================================
// Host User Auto-Provisioning
// =============================================================================

var ensureHostUserOnce sync.Once
var ensureHostUserErr error

// ensureHostUser uses docker exec (as root) + nsenter to create the user on the host.
// The Go process runs as unprivileged usulnet user, so direct nsenter fails.
// docker exec -u 0 elevates to root inside the container, then nsenter works.
// Tries useradd first (shadow-utils), falls back to adduser (busybox/alpine).
// Runs once via sync.Once.
func ensureHostUser(selfContainerID, user, shell string) error {
	ensureHostUserOnce.Do(func() {
		if user == "root" {
			return
		}

		// Base: docker exec -u 0 <self> nsenter --target 1 --mount --uts --pid --
		base := []string{"exec", "-u", "0", selfContainerID,
			"nsenter", "--target", "1", "--mount", "--uts", "--pid", "--"}

		// Check if user already exists on host
		checkArgs := make([]string, len(base))
		copy(checkArgs, base)
		checkArgs = append(checkArgs, "id", "-u", user)
		if exec.Command("docker", checkArgs...).Run() == nil {
			log.Printf("[INFO] Host terminal: user '%s' already exists on host", user)
			return
		}

		// Try useradd (Arch, Debian, RHEL, Fedora — shadow-utils)
		// -r = system, -M = no home, -s = shell, -N = no user group
		uaArgs := make([]string, len(base))
		copy(uaArgs, base)
		uaArgs = append(uaArgs, "useradd", "-r", "-M", "-s", shell, "-N", user)
		if output, err := exec.Command("docker", uaArgs...).CombinedOutput(); err == nil {
			log.Printf("[INFO] Host terminal: created user '%s' on host via useradd", user)
			return
		} else {
			log.Printf("[DEBUG] Host terminal: useradd failed (%v: %s), trying adduser", err, strings.TrimSpace(string(output)))
		}

		// Fallback: adduser (BusyBox/Alpine)
		// -S = system, -D = no password, -H = no home, -s = shell
		auArgs := make([]string, len(base))
		copy(auArgs, base)
		auArgs = append(auArgs, "adduser", "-S", "-D", "-H", "-s", shell, user)
		if output, err := exec.Command("docker", auArgs...).CombinedOutput(); err != nil {
			ensureHostUserErr = err
			log.Printf("[ERROR] Host terminal: both useradd and adduser failed: %v — %s", err, strings.TrimSpace(string(output)))
			return
		}

		log.Printf("[INFO] Host terminal: created user '%s' on host via adduser", user)
	})

	return ensureHostUserErr
}

// =============================================================================
// Self Container ID Detection
// =============================================================================

var (
	selfContainerID     string
	selfContainerIDOnce sync.Once
)

// detectSelfContainerID finds our own Docker container ID.
// Tries /proc/self/cgroup first (cgroup v1 and v2), then hostname as fallback.
func detectSelfContainerID() string {
	selfContainerIDOnce.Do(func() {
		// Method 1: Parse /proc/self/cgroup
		if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				// cgroup v1: "N:controller:/docker/<container_id>"
				if idx := strings.Index(line, "/docker/"); idx >= 0 {
					id := strings.TrimSpace(line[idx+len("/docker/"):])
					id = strings.TrimSuffix(id, ".scope")
					if len(id) >= 12 {
						selfContainerID = id[:12]
						return
					}
				}
				// cgroup v2 systemd: "0::/system.slice/docker-<container_id>.scope"
				if idx := strings.Index(line, "/docker-"); idx >= 0 {
					id := line[idx+len("/docker-"):]
					id = strings.TrimSuffix(strings.TrimSpace(id), ".scope")
					if len(id) >= 12 {
						selfContainerID = id[:12]
						return
					}
				}
			}
		}

		// Method 2: /proc/self/mountinfo — look for docker overlay paths
		if data, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				for _, prefix := range []string{"/docker/containers/", "/docker-", "/docker/"} {
					if idx := strings.Index(line, prefix); idx >= 0 {
						after := line[idx+len(prefix):]
						var id strings.Builder
						for _, c := range after {
							if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
								id.WriteRune(c)
							} else {
								break
							}
						}
						if id.Len() >= 12 {
							selfContainerID = id.String()[:12]
							return
						}
					}
				}
			}
		}

		// Method 3: Hostname (Docker sets it to short container ID by default)
		if h, err := os.Hostname(); err == nil {
			selfContainerID = h
		}
	})

	return selfContainerID
}

// isHostPIDNamespace checks if the container shares the host PID namespace.
// Required for nsenter --target 1 to reach the host.
func isHostPIDNamespace() bool {
	// In host PID namespace, PID 1 is the host's init (systemd/init).
	// In container PID namespace, PID 1 is our own entrypoint.
	data, err := os.ReadFile("/proc/1/cmdline")
	if err != nil {
		return false
	}
	cmdline := string(data)
	// Our binary is "usulnet" or our entrypoint. If PID 1 is NOT us, we share host PID.
	return !strings.Contains(cmdline, "usulnet")
}

// =============================================================================
// Host Terminal Page Handler
// =============================================================================

// HostTerminalTempl renders the host terminal page.
func (h *Handler) HostTerminalTempl(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		id = getIDParam(r)
	}

	cfg := h.hostTerminalConfig

	if !cfg.Enabled {
		h.RenderErrorTempl(w, r, http.StatusForbidden,
			"Host Terminal Disabled",
			"Set HOST_TERMINAL_ENABLED=true in usulnet environment to enable this feature.",
		)
		return
	}

	// Get host info for display
	host, err := h.services.Hosts().Get(r.Context(), id)
	if err != nil || host == nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Host Not Found", "The specified host was not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Terminal: "+host.Name, "nodes")

	data := hosts.HostTerminalData{
		PageData: pageData,
		HostID:   id,
		HostName: host.Name,
		User:     cfg.User,
		Shell:    cfg.Shell,
		Ready:    isHostPIDNamespace(),
	}

	h.renderTempl(w, r, hosts.HostTerminal(data))
}

// =============================================================================
// WebSocket Host Exec Handler
// =============================================================================

// WSHostExec opens an interactive terminal on the Docker host via nsenter.
//
// How it works:
//  1. usulnet container must run with pid:"host" + cap_add:[SYS_PTRACE,SYS_ADMIN]
//  2. We detect our own container ID
//  3. We docker exec into ourselves with: nsenter --target 1 --mount --uts --ipc --net --pid -- su - <user>
//  4. nsenter enters the host namespaces, su drops to the unprivileged user
//  5. The user gets a standard shell on the host, no sudo, no root
func (h *Handler) WSHostExec(w http.ResponseWriter, r *http.Request) {
	hostID := chi.URLParam(r, "id")
	if hostID == "" {
		http.Error(w, "Host ID required", http.StatusBadRequest)
		return
	}

	cfg := h.hostTerminalConfig
	if !cfg.Enabled {
		http.Error(w, "Host terminal disabled", http.StatusForbidden)
		return
	}

	// Parse terminal dimensions
	cols := 80
	rows := 24
	if c, err := strconv.Atoi(r.URL.Query().Get("cols")); err == nil && c > 0 {
		cols = c
	}
	if ro, err := strconv.Atoi(r.URL.Query().Get("rows")); err == nil && ro > 0 {
		rows = ro
	}

	// Upgrade to WebSocket
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ERROR] Host terminal: WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Verify host PID namespace
	if !isHostPIDNamespace() {
		h.sendWSMessage(conn, WSExecMessage{
			Type: "error",
			Data: "Host PID namespace not available. Add pid:\"host\" to usulnet docker-compose.",
		})
		return
	}

	// Detect our own container ID
	selfID := detectSelfContainerID()
	if selfID == "" {
		h.sendWSMessage(conn, WSExecMessage{
			Type: "error",
			Data: "Cannot detect own container ID.",
		})
		return
	}

	// Auto-create unprivileged user on host if needed (runs once)
	if err := ensureHostUser(selfID, cfg.User, cfg.Shell); err != nil {
		h.sendWSMessage(conn, WSExecMessage{
			Type: "error",
			Data: "Failed to provision host user '" + cfg.User + "': " + err.Error(),
		})
		return
	}

	// Get Docker client - host terminal requires direct connection
	dockerClientAPI, err := h.services.Containers().GetDockerClient(ctx)
	if err != nil {
		h.sendWSMessage(conn, WSExecMessage{
			Type: "error",
			Data: "Failed to get Docker client: " + err.Error(),
		})
		return
	}
	dockerClient, ok := dockerClientAPI.(*docker.Client)
	if !ok {
		h.sendWSMessage(conn, WSExecMessage{
			Type: "error",
			Data: "Host terminal not available for remote hosts",
		})
		return
	}

	// Build nsenter command:
	// nsenter enters ALL host namespaces via PID 1
	// su - drops to the configured unprivileged user with a login shell
	nsenterCmd := []string{
		"nsenter",
		"--target", "1",
		"--mount", "--uts", "--ipc", "--net", "--pid",
		"--", "su", "-", cfg.User, "-s", cfg.Shell,
	}

	user := GetUserFromContext(r.Context())
	userName := "unknown"
	if user != nil {
		userName = user.Username
	}
	log.Printf("[INFO] Host terminal: user=%s host=%s target_user=%s shell=%s container=%s",
		userName, hostID, cfg.User, cfg.Shell, selfID)

	// Exec in OUR OWN container — as root (required for nsenter capability)
	execOpts := docker.ExecOptions{
		User:        "0",
		Tty:         true,
		AttachStdin: true,
		Env: []string{
			"TERM=xterm-256color",
			"COLUMNS=" + strconv.Itoa(cols),
			"LINES=" + strconv.Itoa(rows),
		},
	}

	hijacked, execID, err := dockerClient.ContainerExecInteractive(ctx, selfID, nsenterCmd, execOpts)
	if err != nil {
		log.Printf("[ERROR] Host terminal: exec failed: selfID=%s error=%v", selfID, err)
		h.sendWSMessage(conn, WSExecMessage{
			Type: "error",
			Data: "Failed to create host exec session: " + err.Error(),
		})
		return
	}
	log.Printf("[DEBUG] Host terminal: exec created: execID=%s selfID=%s", execID, selfID)

	// Log terminal session if repository is available
	var terminalSessionID uuid.UUID
	if h.terminalSessionRepo != nil {
		var userID uuid.UUID
		if user != nil {
			if parsedID, err := uuid.Parse(user.ID); err == nil {
				userID = parsedID
			}
		}

		var parsedHostID *uuid.UUID
		if hid, err := uuid.Parse(hostID); err == nil {
			parsedHostID = &hid
		}

		sessionInput := &CreateTerminalSessionInput{
			UserID:     userID,
			Username:   userName,
			TargetType: "host",
			TargetID:   hostID,
			TargetName: "Host (" + cfg.User + "@host)",
			HostID:     parsedHostID,
			Shell:      cfg.Shell,
			TermCols:   cols,
			TermRows:   rows,
			ClientIP:   getRealIP(r),
			UserAgent:  r.UserAgent(),
		}

		if sid, err := h.terminalSessionRepo.Create(context.Background(), sessionInput); err != nil {
			log.Printf("[WARN] Failed to log host terminal session: %v", err)
		} else {
			terminalSessionID = sid
			log.Printf("[DEBUG] Host terminal session created: sessionID=%s", sid)
		}
	}

	h.sendWSMessage(conn, WSExecMessage{
		Type: "connected",
		Data: "Connected to host as " + cfg.User,
	})

	// Initial resize
	if err := dockerClient.ContainerExecResize(ctx, execID, uint(rows), uint(cols)); err != nil {
		log.Printf("[WARN] Host terminal: initial resize failed: %v", err)
	}

	// Cleanup (same pattern as WSContainerExec)
	var closeOnce sync.Once
	cleanup := func() {
		closeOnce.Do(func() {
			cancel()

			// End terminal session if it was created
			if h.terminalSessionRepo != nil && terminalSessionID != uuid.Nil {
				if err := h.terminalSessionRepo.End(context.Background(), terminalSessionID, "completed", ""); err != nil {
					log.Printf("[WARN] Failed to end host terminal session: %v", err)
				}
			}

			hijacked.Close()
			conn.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "session ended"),
				time.Now().Add(time.Second),
			)
		})
	}
	defer cleanup()

	var wg sync.WaitGroup

	// Host exec output → WebSocket
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
					log.Printf("[DEBUG] Host terminal: WS write error: %v", writeErr)
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("[DEBUG] Host terminal: exec read ended: %v", err)
				}
				return
			}
		}
	}()

	// WebSocket input → Host exec stdin
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cleanup()

		for {
			conn.SetReadDeadline(time.Now().Add(10 * time.Minute))
			_, message, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
					log.Printf("[DEBUG] Host terminal: WS read error: %v", err)
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
					log.Printf("[DEBUG] Host terminal: exec write error: %v", err)
					return
				}
			case "resize":
				if execMsg.Cols > 0 && execMsg.Rows > 0 {
					if err := dockerClient.ContainerExecResize(ctx, execID, uint(execMsg.Rows), uint(execMsg.Cols)); err != nil {
						log.Printf("[DEBUG] Host terminal: resize error: %v", err)
					}
				}
			}
		}
	}()

	wg.Wait()
	log.Printf("[INFO] Host terminal session ended: user=%s host=%s", userName, hostID)
}
