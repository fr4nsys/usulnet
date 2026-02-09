// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/web/templates/pages/hosts"
	"github.com/go-chi/chi/v5"
)

// =============================================================================
// Host Filesystem Browser
// =============================================================================

// HostFilesTempl renders the host file browser page.
func (h *Handler) HostFilesTempl(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		id = getIDParam(r)
	}

	cfg := loadHostTerminalConfig()

	if !cfg.Enabled {
		h.RenderErrorTempl(w, r, http.StatusForbidden,
			"Host Files Browser Disabled",
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

	// Get path from wildcard or default to /
	path := chi.URLParam(r, "*")
	if path == "" {
		path = "/"
	}

	pageData := h.prepareTemplPageData(r, "Files: "+host.Name, "nodes")

	data := hosts.HostFilesData{
		PageData: pageData,
		HostID:   id,
		HostName: host.Name,
		Path:     path,
		Ready:    isHostPIDNamespace(),
	}

	h.renderTempl(w, r, hosts.HostFiles(data))
}

// =============================================================================
// Host Filesystem API
// =============================================================================

// HostFileEntry represents a file or directory on the host.
type HostFileEntry struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	IsDir      bool   `json:"is_dir"`
	Size       int64  `json:"size"`
	SizeHuman  string `json:"size_human"`
	Mode       string `json:"mode"`
	ModTime    string `json:"mod_time"`
	ModTimeAgo string `json:"mod_time_ago"`
	Owner      string `json:"owner"`
	Group      string `json:"group"`
	LinkTarget string `json:"link_target,omitempty"`
	IsSymlink  bool   `json:"is_symlink"`
}

// HostFileContent represents file content from the host.
type HostFileContent struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	Size      int64  `json:"size"`
	Truncated bool   `json:"truncated"`
	Binary    bool   `json:"binary"`
}

// APIHostBrowse lists files on the host filesystem via nsenter.
// GET /api/v1/hosts/{hostID}/browse
// GET /api/v1/hosts/{hostID}/browse/*
func (h *Handler) APIHostBrowse(w http.ResponseWriter, r *http.Request) {
	hostID := chi.URLParam(r, "hostID")
	if hostID == "" {
		h.jsonError(w, "Host ID required", http.StatusBadRequest)
		return
	}

	cfg := loadHostTerminalConfig()
	if !cfg.Enabled {
		h.jsonError(w, "Host file browser disabled", http.StatusForbidden)
		return
	}

	if !isHostPIDNamespace() {
		h.jsonError(w, "Host PID namespace not available", http.StatusServiceUnavailable)
		return
	}

	path := chi.URLParam(r, "*")
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	selfID := detectSelfContainerID()
	if selfID == "" {
		h.jsonError(w, "Cannot detect container ID", http.StatusInternalServerError)
		return
	}

	// Run ls -la on host via nsenter
	output, err := runNsenterCommand(selfID, []string{
		"ls", "-la", "--time-style=+%Y-%m-%dT%H:%M:%S", path,
	})
	if err != nil {
		h.jsonError(w, "Failed to list directory: "+err.Error(), http.StatusInternalServerError)
		return
	}

	files := parseHostLS(output, path)

	h.jsonResponse(w, map[string]interface{}{
		"path":  path,
		"files": files,
	})
}

// APIHostReadFile reads a file from the host filesystem via nsenter.
// GET /api/v1/hosts/{hostID}/file/*
func (h *Handler) APIHostReadFile(w http.ResponseWriter, r *http.Request) {
	hostID := chi.URLParam(r, "hostID")
	if hostID == "" {
		h.jsonError(w, "Host ID required", http.StatusBadRequest)
		return
	}

	cfg := loadHostTerminalConfig()
	if !cfg.Enabled {
		h.jsonError(w, "Host file browser disabled", http.StatusForbidden)
		return
	}

	if !isHostPIDNamespace() {
		h.jsonError(w, "Host PID namespace not available", http.StatusServiceUnavailable)
		return
	}

	path := chi.URLParam(r, "*")
	if path == "" {
		h.jsonError(w, "File path required", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	maxSize := 1024 * 1024 // 1MB default
	if ms := r.URL.Query().Get("max_size"); ms != "" {
		if parsed, err := strconv.Atoi(ms); err == nil {
			maxSize = parsed
		}
	}

	selfID := detectSelfContainerID()
	if selfID == "" {
		h.jsonError(w, "Cannot detect container ID", http.StatusInternalServerError)
		return
	}

	// Get file size first
	statOutput, _ := runNsenterCommand(selfID, []string{"stat", "-c", "%s", path})
	var fileSize int64
	fmt.Sscanf(strings.TrimSpace(statOutput), "%d", &fileSize)

	truncated := fileSize > int64(maxSize)

	// Read file content
	var cmd []string
	if truncated {
		cmd = []string{"head", "-c", strconv.Itoa(maxSize), path}
	} else {
		cmd = []string{"cat", path}
	}

	content, err := runNsenterCommand(selfID, cmd)
	if err != nil {
		h.jsonError(w, "Failed to read file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if binary
	binary := strings.Contains(content, "\x00")

	h.jsonResponse(w, HostFileContent{
		Path:      path,
		Content:   content,
		Size:      fileSize,
		Truncated: truncated,
		Binary:    binary,
	})
}

// APIHostDownloadFile downloads a file from the host filesystem.
// GET /api/v1/hosts/{hostID}/download/*
func (h *Handler) APIHostDownloadFile(w http.ResponseWriter, r *http.Request) {
	hostID := chi.URLParam(r, "hostID")
	if hostID == "" {
		h.jsonError(w, "Host ID required", http.StatusBadRequest)
		return
	}

	cfg := loadHostTerminalConfig()
	if !cfg.Enabled {
		h.jsonError(w, "Host file browser disabled", http.StatusForbidden)
		return
	}

	if !isHostPIDNamespace() {
		h.jsonError(w, "Host PID namespace not available", http.StatusServiceUnavailable)
		return
	}

	path := chi.URLParam(r, "*")
	if path == "" {
		h.jsonError(w, "File path required", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	selfID := detectSelfContainerID()
	if selfID == "" {
		h.jsonError(w, "Cannot detect container ID", http.StatusInternalServerError)
		return
	}

	// Get file content via nsenter
	content, err := runNsenterCommand(selfID, []string{"cat", path})
	if err != nil {
		h.jsonError(w, "Failed to read file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract filename from path
	parts := strings.Split(path, "/")
	filename := parts[len(parts)-1]
	if filename == "" {
		filename = "download"
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.Write([]byte(content))
}

// APIHostMkdir creates a directory on the host filesystem via nsenter.
// POST /api/v1/hosts/{hostID}/mkdir/*
func (h *Handler) APIHostMkdir(w http.ResponseWriter, r *http.Request) {
	hostID := chi.URLParam(r, "hostID")
	if hostID == "" {
		h.jsonError(w, "Host ID required", http.StatusBadRequest)
		return
	}

	cfg := loadHostTerminalConfig()
	if !cfg.Enabled {
		h.jsonError(w, "Host file browser disabled", http.StatusForbidden)
		return
	}

	if !isHostPIDNamespace() {
		h.jsonError(w, "Host PID namespace not available", http.StatusServiceUnavailable)
		return
	}

	path := chi.URLParam(r, "*")
	if path == "" {
		h.jsonError(w, "Directory path required", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	selfID := detectSelfContainerID()
	if selfID == "" {
		h.jsonError(w, "Cannot detect container ID", http.StatusInternalServerError)
		return
	}

	// Create directory via nsenter (as configured user)
	_, err := runNsenterCommand(selfID, []string{"mkdir", "-p", path})
	if err != nil {
		h.jsonError(w, "Failed to create directory: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.jsonResponse(w, map[string]string{"status": "ok", "path": path})
}

// APIHostDeleteFile deletes a file or directory on the host filesystem via nsenter.
// DELETE /api/v1/hosts/{hostID}/file/*
func (h *Handler) APIHostDeleteFile(w http.ResponseWriter, r *http.Request) {
	hostID := chi.URLParam(r, "hostID")
	if hostID == "" {
		h.jsonError(w, "Host ID required", http.StatusBadRequest)
		return
	}

	cfg := loadHostTerminalConfig()
	if !cfg.Enabled {
		h.jsonError(w, "Host file browser disabled", http.StatusForbidden)
		return
	}

	if !isHostPIDNamespace() {
		h.jsonError(w, "Host PID namespace not available", http.StatusServiceUnavailable)
		return
	}

	path := chi.URLParam(r, "*")
	if path == "" {
		h.jsonError(w, "File path required", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	recursive := r.URL.Query().Get("recursive") == "true"

	selfID := detectSelfContainerID()
	if selfID == "" {
		h.jsonError(w, "Cannot detect container ID", http.StatusInternalServerError)
		return
	}

	// Delete file/directory via nsenter
	var cmd []string
	if recursive {
		cmd = []string{"rm", "-rf", path}
	} else {
		cmd = []string{"rm", path}
	}

	_, err := runNsenterCommand(selfID, cmd)
	if err != nil {
		h.jsonError(w, "Failed to delete: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Helper Functions
// =============================================================================

// runNsenterCommand executes a command on the host via nsenter.
// It uses docker exec -u 0 to run nsenter with root privileges.
func runNsenterCommand(selfContainerID string, cmd []string) (string, error) {
	cfg := loadHostTerminalConfig()

	// Build nsenter command
	// We use su to drop to the configured unprivileged user
	args := []string{
		"exec", "-u", "0", selfContainerID,
		"nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid",
		"--", "su", "-", cfg.User, "-c",
	}

	// Join the command with proper escaping
	cmdStr := strings.Join(cmd, " ")
	args = append(args, cmdStr)

	log.Printf("[DEBUG] Host files: running command: docker %v", args)

	output, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%s: %w", string(output), err)
	}

	return string(output), nil
}

// parseHostLS parses ls -la output from the host.
func parseHostLS(output, basePath string) []HostFileEntry {
	var files []HostFileEntry
	scanner := bufio.NewScanner(strings.NewReader(output))
	now := time.Now()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "total") {
			continue
		}

		// Parse ls -l output
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}

		mode := fields[0]
		owner := fields[2]
		group := fields[3]

		var size int64
		fmt.Sscanf(fields[4], "%d", &size)

		// Parse filename and date
		var name string
		var modTime time.Time

		// Check if using ISO time format
		if len(fields) >= 6 && strings.Contains(fields[5], "T") {
			modTime, _ = time.Parse("2006-01-02T15:04:05", fields[5])
			name = strings.Join(fields[6:], " ")
		} else if len(fields) >= 8 {
			dateStr := strings.Join(fields[5:8], " ")
			modTime, _ = time.Parse("Jan 2 15:04", dateStr)
			if modTime.IsZero() {
				modTime, _ = time.Parse("Jan 2 2006", dateStr)
			}
			if modTime.Year() == 0 {
				modTime = modTime.AddDate(now.Year(), 0, 0)
			}
			name = strings.Join(fields[8:], " ")
		}

		if name == "" || name == "." || name == ".." {
			continue
		}

		// Check for symlink
		var linkTarget string
		isSymlink := mode[0] == 'l'
		if isSymlink && strings.Contains(name, " -> ") {
			parts := strings.SplitN(name, " -> ", 2)
			name = parts[0]
			if len(parts) > 1 {
				linkTarget = parts[1]
			}
		}

		// Build full path
		fullPath := basePath
		if !strings.HasSuffix(fullPath, "/") {
			fullPath += "/"
		}
		fullPath += name

		files = append(files, HostFileEntry{
			Name:       name,
			Path:       fullPath,
			IsDir:      mode[0] == 'd',
			Size:       size,
			SizeHuman:  humanizeHostSize(size),
			Mode:       mode,
			ModTime:    modTime.Format(time.RFC3339),
			ModTimeAgo: hostTimeAgo(modTime),
			Owner:      owner,
			Group:      group,
			LinkTarget: linkTarget,
			IsSymlink:  isSymlink,
		})
	}

	return files
}

func humanizeHostSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

func hostTimeAgo(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	diff := time.Since(t)
	switch {
	case diff < time.Minute:
		return "just now"
	case diff < time.Hour:
		mins := int(diff.Minutes())
		if mins == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", mins)
	case diff < 24*time.Hour:
		hours := int(diff.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	case diff < 7*24*time.Hour:
		days := int(diff.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	default:
		return t.Format("Jan 2, 2006")
	}
}
