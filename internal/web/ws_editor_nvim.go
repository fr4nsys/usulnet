// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// wsEditorMsg is the WebSocket message format for the editor.
type wsEditorMsg struct {
	Type string `json:"type"` // "input", "output", "resize", "committed", "error"
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

// WSEditorNvim handles the WebSocket connection for the nvim editor.
//
// Flow (git mode):
//  1. Fetch file from Gitea → write to temp dir
//  2. Create FIFO for commit signaling
//  3. Inject BufWritePost autocmd that writes to FIFO on :w
//  4. Spawn nvim on a pty via creack/pty
//  5. Bridge pty ↔ WebSocket
//  6. FIFO goroutine: on signal → read file → commit to Gitea
//
// Flow (scratch mode - no repo):
//  1. Create empty temp file
//  2. Spawn nvim without commit hook
//  3. Bridge pty ↔ WebSocket
//
// GET /ws/editor/nvim?repo={id}&file={path}&ref={branch}&cols=N&rows=N
// GET /ws/editor/nvim?file=scratch&cols=N&rows=N (scratch mode)
func (h *Handler) WSEditorNvim(w http.ResponseWriter, r *http.Request) {
	// ── Parse params ─────────────────────────────────────────────────
	repoIDStr := r.URL.Query().Get("repo")
	filePath := r.URL.Query().Get("file")
	ref := r.URL.Query().Get("ref")
	colsStr := r.URL.Query().Get("cols")
	rowsStr := r.URL.Query().Get("rows")

	// Scratch mode: no repo, just a blank nvim
	scratchMode := repoIDStr == ""
	if filePath == "" {
		filePath = "scratch"
	}

	cols, _ := strconv.Atoi(colsStr)
	rows, _ := strconv.Atoi(rowsStr)
	if cols < 40 {
		cols = 120
	}
	if rows < 10 {
		rows = 40
	}

	ctx := r.Context()

	var repoID uuid.UUID
	var repoName string
	var content []byte
	var err error

	svc := h.services.Gitea()

	if !scratchMode {
		if svc == nil {
			http.Error(w, "Gitea not configured", http.StatusServiceUnavailable)
			return
		}

		repoID, err = uuid.Parse(repoIDStr)
		if err != nil {
			http.Error(w, "Invalid repo ID", http.StatusBadRequest)
			return
		}

		// ── Verify repo ──────────────────────────────────────────────────
		repo, err := svc.GetRepository(ctx, repoID)
		if err != nil {
			http.Error(w, "Repo not found", http.StatusNotFound)
			return
		}
		repoName = repo.FullName
		if ref == "" {
			ref = repo.DefaultBranch
		}

		// ── Fetch file ───────────────────────────────────────────────────
		content, err = svc.GetFileContent(ctx, repoID, filePath, ref)
		if err != nil {
			http.Error(w, "Failed to fetch file: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// ── Upgrade WebSocket ────────────────────────────────────────────
	upgrader := websocket.Upgrader{
		CheckOrigin:     func(r *http.Request) bool { return true },
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("ws upgrade failed", "error", err)
		return
	}
	defer conn.Close()

	// ── Setup workspace ──────────────────────────────────────────────
	sessionID := uuid.New().String()[:8]
	workDir, err := os.MkdirTemp("", "usulnet-nvim-"+sessionID+"-")
	if err != nil {
		editorWSSendError(conn, "Failed to create workspace: "+err.Error())
		return
	}
	defer os.RemoveAll(workDir)

	targetFile := filepath.Join(workDir, filepath.Base(filePath))
	if err := os.WriteFile(targetFile, content, 0644); err != nil {
		editorWSSendError(conn, "Failed to write file: "+err.Error())
		return
	}

	var fifoPath string
	var initPath string

	// Only setup FIFO and commit hook in git mode
	if !scratchMode {
		// ── Create commit signal FIFO ────────────────────────────────────
		fifoPath = filepath.Join(workDir, ".commit-signal")
		if err := syscall.Mkfifo(fifoPath, 0600); err != nil {
			editorWSSendError(conn, "Failed to create FIFO: "+err.Error())
			return
		}

		// ── Write autocmd init for :w → commit ───────────────────────────
		initPath = filepath.Join(workDir, ".usulnet-init.lua")
		initLua := fmt.Sprintf(`-- usulnet: auto-commit on :w
local fifo = %q
local fname = %q
local branch = %q

vim.api.nvim_create_autocmd("BufWritePost", {
  pattern = fname,
  callback = function()
    vim.schedule(function()
      local ok = pcall(function()
        local f = io.open(fifo, "w")
        if f then f:write("commit\n"); f:close() end
      end)
      if ok then
        vim.notify(" Committed to " .. branch, vim.log.levels.INFO)
      else
        vim.notify(" Commit signal failed", vim.log.levels.WARN)
      end
    end)
  end,
})
`, fifoPath, filepath.Base(filePath), ref)
		os.WriteFile(initPath, []byte(initLua), 0644)
	}

	// ── Copy platform nvim config ────────────────────────────────────
	nvimConfigDir := filepath.Join(workDir, ".config", "nvim")
	copyNvimUserConfig(nvimConfigDir)

	// ── Resolve nvim binary ──────────────────────────────────────────
	nvimBin := findNvimBinary()

	// ── Build command ────────────────────────────────────────────────
	var cmd *exec.Cmd
	if scratchMode {
		cmd = exec.Command(nvimBin, targetFile)
	} else {
		cmd = exec.Command(nvimBin,
			"--cmd", "luafile "+initPath, // our commit hook (loads before user config)
			targetFile,
		)
	}
	cmd.Dir = workDir
	cmd.Env = buildNvimEnv(workDir)

	// ── Start on pty ─────────────────────────────────────────────────
	winSize := &pty.Winsize{
		Rows: uint16(rows),
		Cols: uint16(cols),
	}
	ptmx, err := pty.StartWithSize(cmd, winSize)
	if err != nil {
		editorWSSendError(conn, "Failed to start nvim: "+err.Error())
		return
	}
	defer ptmx.Close()

	if scratchMode {
		slog.Info("nvim scratch session started",
			"session", sessionID,
			"file", filePath,
			"pid", cmd.Process.Pid,
		)
	} else {
		slog.Info("nvim session started",
			"session", sessionID,
			"repo", repoName,
			"file", filePath,
			"ref", ref,
			"pid", cmd.Process.Pid,
		)
	}

	// ── Session context ──────────────────────────────────────────────
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Mutex for WebSocket writes (gorilla/websocket is not thread-safe)
	var wsMu sync.Mutex

	var wg sync.WaitGroup

	// ── Goroutine: pty output → WebSocket (nvim → browser) ──────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if err != nil {
				if err != io.EOF {
					slog.Debug("pty read error", "error", err)
				}
				cancel()
				return
			}
			msg, _ := json.Marshal(wsEditorMsg{Type: "output", Data: string(buf[:n])})
			wsMu.Lock()
			writeErr := conn.WriteMessage(websocket.TextMessage, msg)
			wsMu.Unlock()
			if writeErr != nil {
				cancel()
				return
			}
		}
	}()

	// ── Goroutine: FIFO watcher → commit on :w (only in git mode) ────
	if !scratchMode {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-sessionCtx.Done():
					return
				default:
				}

				// Open blocks until nvim writes "commit\n"
				f, err := os.Open(fifoPath)
				if err != nil {
					if sessionCtx.Err() != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
					continue
				}

				scanner := bufio.NewScanner(f)
				for scanner.Scan() {
					if scanner.Text() != "commit" {
						continue
					}

					saved, err := os.ReadFile(targetFile)
					if err != nil {
						slog.Error("read saved file failed", "error", err)
						wsMu.Lock()
						editorWSSendJSON(conn, wsEditorMsg{Type: "error", Data: "Read failed"})
						wsMu.Unlock()
						continue
					}

					// Build commit message
					user := GetUserFromContext(ctx)
					author := "usulnet"
					if user != nil {
						author = user.Username
					}
					commitMsg := fmt.Sprintf("Update %s via usulnet nvim (%s)",
						filepath.Base(filePath), author)

					if err := svc.UpdateFile(ctx, repoID, filePath, ref, string(saved), commitMsg); err != nil {
						slog.Error("gitea commit failed", "error", err)
						wsMu.Lock()
						editorWSSendJSON(conn, wsEditorMsg{Type: "error", Data: "Commit failed: " + err.Error()})
						wsMu.Unlock()
					} else {
						slog.Info("nvim commit ok", "file", filePath, "ref", ref)
						wsMu.Lock()
						editorWSSendJSON(conn, wsEditorMsg{Type: "committed", Data: filePath})
						wsMu.Unlock()
					}
				}
				f.Close()
			}
		}()
	}

	// ── Goroutine: WebSocket input → pty (browser → nvim) ───────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				cancel()
				return
			}
			var msg wsEditorMsg
			if err := json.Unmarshal(raw, &msg); err != nil {
				continue
			}
			switch msg.Type {
			case "input":
				if _, err := ptmx.Write([]byte(msg.Data)); err != nil {
					cancel()
					return
				}
			case "resize":
				if msg.Cols > 0 && msg.Rows > 0 {
					pty.Setsize(ptmx, &pty.Winsize{
						Rows: uint16(msg.Rows),
						Cols: uint16(msg.Cols),
					})
					if cmd.Process != nil {
						cmd.Process.Signal(syscall.SIGWINCH)
					}
				}
			}
		}
	}()

	// Wait for nvim to exit
	cmd.Wait()
	cancel()
	wg.Wait()

	slog.Info("nvim session ended", "session", sessionID)
}

// ============================================================================
// Helpers
// ============================================================================

// findNvimBinary resolves the nvim path.
func findNvimBinary() string {
	candidates := []string{
		"/usr/bin/nvim",
		"/usr/local/bin/nvim",
		"/opt/nvim/bin/nvim",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("nvim"); err == nil {
		return p
	}
	return "nvim"
}

// buildNvimEnv constructs the environment for the nvim process.
func buildNvimEnv(workDir string) []string {
	env := []string{
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"HOME=" + workDir,
		"XDG_CONFIG_HOME=" + filepath.Join(workDir, ".config"),
		"XDG_DATA_HOME=" + filepath.Join(workDir, ".local/share"),
		"XDG_STATE_HOME=" + filepath.Join(workDir, ".local/state"),
		"XDG_CACHE_HOME=" + filepath.Join(workDir, ".cache"),
		"LANG=en_US.UTF-8",
		"LC_ALL=en_US.UTF-8",
	}
	if p := os.Getenv("PATH"); p != "" {
		env = append(env, "PATH="+p)
	}
	return env
}

// copyNvimUserConfig copies the platform nvim config into the session workspace.
// Looks for config at /opt/usulnet/nvim-config/ (shipped with the Docker image).
// Also copies pre-installed plugin data from /opt/usulnet/nvim-data/ if available.
func copyNvimUserConfig(destDir string) {
	sources := []string{
		"/opt/usulnet/nvim-config",
		"/etc/usulnet/nvim",
	}
	for _, src := range sources {
		if info, err := os.Stat(src); err == nil && info.IsDir() {
			os.MkdirAll(destDir, 0755)
			cmd := exec.Command("cp", "-a", src+"/.", destDir+"/")
			if err := cmd.Run(); err != nil {
				slog.Warn("copy nvim config failed", "src", src, "error", err)
			} else {
				slog.Debug("nvim config copied", "src", src, "dest", destDir)
				break
			}
		}
	}

	// Copy pre-installed plugin data (lazy.nvim + plugins)
	// This avoids downloading plugins on every nvim session start.
	nvimDataSrc := "/opt/usulnet/nvim-data"
	if info, err := os.Stat(nvimDataSrc); err == nil && info.IsDir() {
		workDir := filepath.Dir(filepath.Dir(destDir)) // workDir/.config/nvim → workDir
		nvimDataDest := filepath.Join(workDir, ".local", "share", "nvim")
		os.MkdirAll(nvimDataDest, 0755)
		cmd := exec.Command("cp", "-a", nvimDataSrc+"/.", nvimDataDest+"/")
		if err := cmd.Run(); err != nil {
			slog.Warn("copy nvim plugin data failed", "error", err)
		} else {
			slog.Debug("nvim plugin data copied", "dest", nvimDataDest)
		}
	}
}

// editorWSSendError sends an error message over the editor WebSocket.
func editorWSSendError(conn *websocket.Conn, msg string) {
	editorWSSendJSON(conn, wsEditorMsg{Type: "error", Data: msg})
}

// editorWSSendJSON sends a typed JSON message over the editor WebSocket.
func editorWSSendJSON(conn *websocket.Conn, msg wsEditorMsg) {
	data, _ := json.Marshal(msg)
	conn.WriteMessage(websocket.TextMessage, data)
}
