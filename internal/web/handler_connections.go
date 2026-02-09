// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/models"
	sshsvc "github.com/fr4nsys/usulnet/internal/services/ssh"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/connections"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ============================================================================
// Model to Template Converters
// ============================================================================

func toSSHConnectionData(conn *models.SSHConnection) connections.SSHConnectionData {
	data := connections.SSHConnectionData{
		ID:        conn.ID.String(),
		Name:      conn.Name,
		Host:      conn.Host,
		Port:      conn.Port,
		Username:  conn.Username,
		AuthType:  string(conn.AuthType),
		Status:    string(conn.Status),
		Tags:      conn.Tags,
		CreatedAt: conn.CreatedAt.Format("Jan 2, 2006"),
	}

	if conn.KeyID != nil {
		data.KeyID = conn.KeyID.String()
		if conn.Key != nil {
			data.KeyName = conn.Key.Name
		}
	}

	if conn.JumpHost != nil {
		data.JumpHostID = conn.JumpHost.String()
	}

	if conn.LastChecked != nil {
		data.LastUsed = sshFormatTimeAgo(*conn.LastChecked)
	}

	return data
}

func toSSHKeyData(key *models.SSHKey) connections.SSHKeyData {
	data := connections.SSHKeyData{
		ID:          key.ID.String(),
		Name:        key.Name,
		Type:        string(key.KeyType),
		Fingerprint: key.Fingerprint,
		PublicKey:   key.PublicKey,
		Comment:     key.Comment,
		CreatedAt:   key.CreatedAt.Format("Jan 2, 2006"),
	}

	if key.LastUsed != nil {
		data.LastUsed = sshFormatTimeAgo(*key.LastUsed)
	}

	return data
}

func toSSHSessionData(session *models.SSHSession) connections.SSHSessionData {
	data := connections.SSHSessionData{
		ID:        session.ID.String(),
		Username:  "",
		ClientIP:  session.ClientIP,
		StartedAt: session.StartedAt.Format("Jan 2, 2006 15:04"),
	}

	if session.EndedAt != nil {
		data.Status = "ended"
		data.EndedAt = session.EndedAt.Format("Jan 2, 2006 15:04")
		data.Duration = sshFormatDuration(session.EndedAt.Sub(session.StartedAt))
	} else {
		data.Status = "active"
		data.Duration = sshFormatDuration(time.Since(session.StartedAt))
	}

	return data
}

func sshFormatTimeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		m := int(d.Minutes())
		if m == 1 {
			return "1 minute ago"
		}
		return strconv.Itoa(m) + " minutes ago"
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1 hour ago"
		}
		return strconv.Itoa(h) + " hours ago"
	case d < 7*24*time.Hour:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return strconv.Itoa(days) + " days ago"
	default:
		return t.Format("Jan 2, 2006")
	}
}

func sshFormatDuration(d time.Duration) string {
	if d < time.Minute {
		return "< 1m"
	}
	if d < time.Hour {
		return strconv.Itoa(int(d.Minutes())) + "m"
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if m == 0 {
		return strconv.Itoa(h) + "h"
	}
	return strconv.Itoa(h) + "h " + strconv.Itoa(m) + "m"
}

// getSSHService returns the SSH service or nil if not available
func (h *Handler) getSSHService() *sshsvc.Service {
	if h.sshService == nil {
		return nil
	}
	// Type assert to the concrete service type
	if svc, ok := h.sshService.(*sshsvc.Service); ok {
		return svc
	}
	return nil
}

// ShortcutsService interface for managing web shortcuts.
type ShortcutsService interface {
	Create(ctx context.Context, input models.CreateWebShortcutInput, userID uuid.UUID) (*models.WebShortcut, error)
	Get(ctx context.Context, id uuid.UUID) (*models.WebShortcut, error)
	List(ctx context.Context, userID uuid.UUID) ([]*models.WebShortcut, error)
	ListByCategory(ctx context.Context, userID uuid.UUID, category string) ([]*models.WebShortcut, error)
	Update(ctx context.Context, id uuid.UUID, input models.UpdateWebShortcutInput) (*models.WebShortcut, error)
	Delete(ctx context.Context, id uuid.UUID) error
	GetCategories(ctx context.Context, userID uuid.UUID) ([]string, error)
	FetchAndSetFavicon(ctx context.Context, shortcutID uuid.UUID) error
}

// SetShortcutsService sets the shortcuts service.
func (h *Handler) SetShortcutsService(svc ShortcutsService) {
	h.shortcutsService = svc
}

// toShortcutData converts a model to template data.
func toShortcutData(s *models.WebShortcut) connections.ShortcutData {
	return connections.ShortcutData{
		ID:          s.ID.String(),
		Name:        s.Name,
		Description: s.Description,
		URL:         s.URL,
		Type:        string(s.Type),
		Icon:        s.Icon,
		IconType:    s.IconType,
		Color:       s.Color,
		Category:    s.Category,
		OpenInNew:   s.OpenInNew,
		ShowInMenu:  s.ShowInMenu,
		IsPublic:    s.IsPublic,
		CreatedAt:   s.CreatedAt.Format("Jan 2, 2006"),
	}
}

// ============================================================================
// Connections Dashboard
// ============================================================================

// ConnectionsTempl renders the main connections dashboard.
func (h *Handler) ConnectionsTempl(w http.ResponseWriter, r *http.Request) {
	// Redirect to SSH connections as the default
	http.Redirect(w, r, "/connections/ssh", http.StatusFound)
}

// ============================================================================
// SSH Connections
// ============================================================================

// SSHConnectionsTempl renders the SSH connections list.
func (h *Handler) SSHConnectionsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.preparePageData(r, "SSH Connections", "connections-ssh")
	userData := h.getUserData(r)

	var connData []connections.SSHConnectionData
	var keyData []connections.SSHKeyData

	// Fetch connections if service is available
	svc := h.getSSHService()
	if svc != nil && userData != nil {
		userID, err := uuid.Parse(userData.ID)
		if err == nil {
			conns, err := svc.ListConnections(ctx, userID)
			if err == nil {
				for _, conn := range conns {
					connData = append(connData, toSSHConnectionData(conn))
				}
			}

			keys, err := svc.ListKeys(ctx, userID)
			if err == nil {
				for _, key := range keys {
					keyData = append(keyData, toSSHKeyData(key))
				}
			}
		}
	}

	data := connections.SSHConnectionsListData{
		PageData:    ToTemplPageData(pageData),
		Connections: connData,
		Keys:        keyData,
	}

	if err := connections.SSHConnectionsList(data).Render(ctx, w); err != nil {
		h.logger.Error("failed to render SSH connections template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// SSHConnectionNewTempl renders the new SSH connection form.
func (h *Handler) SSHConnectionNewTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.preparePageData(r, "New SSH Connection", "connections-ssh")
	userData := h.getUserData(r)

	var keyData []connections.SSHKeyData
	var jumpHosts []connections.SSHConnectionData

	// Fetch keys and existing connections for jump host selection
	svc := h.getSSHService()
	if svc != nil && userData != nil {
		userID, err := uuid.Parse(userData.ID)
		if err == nil {
			keys, err := svc.ListKeys(ctx, userID)
			if err == nil {
				for _, key := range keys {
					keyData = append(keyData, toSSHKeyData(key))
				}
			}

			conns, err := svc.ListConnections(ctx, userID)
			if err == nil {
				for _, conn := range conns {
					jumpHosts = append(jumpHosts, toSSHConnectionData(conn))
				}
			}
		}
	}

	data := connections.SSHConnectionNewData{
		PageData:  ToTemplPageData(pageData),
		Keys:      keyData,
		JumpHosts: jumpHosts,
	}

	if err := connections.SSHConnectionNew(data).Render(ctx, w); err != nil {
		h.logger.Error("failed to render new SSH connection template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// SSHConnectionCreate handles creating a new SSH connection.
func (h *Handler) SSHConnectionCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userData := h.getUserData(r)

	svc := h.getSSHService()
	if svc == nil {
		http.Error(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	if userData == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	userID, err := uuid.Parse(userData.ID)
	if err != nil {
		http.Error(w, "Invalid user session", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	port, _ := strconv.Atoi(r.FormValue("port"))
	if port == 0 {
		port = 22
	}

	input := models.CreateSSHConnectionInput{
		Name:     r.FormValue("name"),
		Host:     r.FormValue("host"),
		Port:     port,
		Username: r.FormValue("username"),
		AuthType: models.SSHAuthType(r.FormValue("auth_type")),
	}

	// Handle password auth
	if input.AuthType == models.SSHAuthPassword {
		input.Password = r.FormValue("password")
	}

	// Handle key auth
	if input.AuthType == models.SSHAuthKey {
		if keyID := r.FormValue("key_id"); keyID != "" {
			id, err := uuid.Parse(keyID)
			if err == nil {
				input.KeyID = &id
			}
		}
	}

	// Handle jump host
	if jumpHostID := r.FormValue("jump_host_id"); jumpHostID != "" {
		id, err := uuid.Parse(jumpHostID)
		if err == nil {
			input.JumpHost = &id
		}
	}

	// Handle tags
	if tags := r.FormValue("tags"); tags != "" {
		input.Tags = strings.Split(tags, ",")
		for i := range input.Tags {
			input.Tags[i] = strings.TrimSpace(input.Tags[i])
		}
	}

	// Handle timeout option
	if timeout := r.FormValue("timeout"); timeout != "" {
		t, _ := strconv.Atoi(timeout)
		if t > 0 {
			input.Options = &models.SSHConnectionOptions{
				ConnectionTimeout: t,
			}
		}
	}

	_, err = svc.CreateConnection(ctx, input, userID)
	if err != nil {
		h.logger.Error("failed to create SSH connection", "error", err)
		h.setFlash(w, r, "error", "Failed to create connection: "+err.Error())
		http.Redirect(w, r, "/connections/ssh/new", http.StatusSeeOther)
		return
	}

	h.setFlash(w, r, "success", "SSH connection created")
	http.Redirect(w, r, "/connections/ssh", http.StatusSeeOther)
}

// SSHConnectionDetailTempl renders the SSH connection detail page.
func (h *Handler) SSHConnectionDetailTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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

	svc := h.getSSHService()
	if svc == nil {
		http.Error(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	conn, err := svc.GetConnection(ctx, connID)
	if err != nil {
		http.Error(w, "Connection not found", http.StatusNotFound)
		return
	}

	pageData := h.preparePageData(r, conn.Name, "connections-ssh")

	// Fetch session history
	var sessionData []connections.SSHSessionData
	sessions, err := svc.GetSessionHistory(ctx, connID, 20)
	if err == nil {
		for _, session := range sessions {
			sessionData = append(sessionData, toSSHSessionData(session))
		}
	}

	data := connections.SSHConnectionDetailData{
		PageData:   ToTemplPageData(pageData),
		Connection: toSSHConnectionData(conn),
		Sessions:   sessionData,
	}

	if err := connections.SSHConnectionDetail(data).Render(ctx, w); err != nil {
		h.logger.Error("failed to render SSH connection detail", "error", err)
		http.Error(w, "Render error", http.StatusInternalServerError)
	}
}

// SSHConnectionTerminalTempl renders the SSH terminal page.
func (h *Handler) SSHConnectionTerminalTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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

	svc := h.getSSHService()
	if svc == nil {
		http.Error(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	conn, err := svc.GetConnection(ctx, connID)
	if err != nil {
		http.Error(w, "Connection not found", http.StatusNotFound)
		return
	}

	pageData := h.preparePageData(r, "Terminal - "+conn.Name, "connections-ssh")

	data := connections.SSHTerminalData{
		PageData:   ToTemplPageData(pageData),
		Connection: toSSHConnectionData(conn),
	}

	if err := connections.SSHTerminal(data).Render(ctx, w); err != nil {
		h.logger.Error("failed to render SSH terminal template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// SSHConnectionUpdate handles updating an SSH connection.
func (h *Handler) SSHConnectionUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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

	svc := h.getSSHService()
	if svc == nil {
		http.Error(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	input := models.UpdateSSHConnectionInput{}

	if name := r.FormValue("name"); name != "" {
		input.Name = &name
	}
	if host := r.FormValue("host"); host != "" {
		input.Host = &host
	}
	if portStr := r.FormValue("port"); portStr != "" {
		port, _ := strconv.Atoi(portStr)
		if port > 0 {
			input.Port = &port
		}
	}
	// Username can be empty (will prompt on connect)
	if r.Form.Has("username") {
		username := r.FormValue("username")
		input.Username = &username
	}

	if authType := r.FormValue("auth_type"); authType != "" {
		at := models.SSHAuthType(authType)
		input.AuthType = &at
	}

	// Handle password - only update if non-empty
	if password := r.FormValue("password"); password != "" {
		input.Password = &password
	}

	// Handle key ID
	if keyID := r.FormValue("key_id"); keyID != "" {
		id, parseErr := uuid.Parse(keyID)
		if parseErr == nil {
			input.KeyID = &id
		}
	}

	_, err = svc.UpdateConnection(ctx, connID, input)
	if err != nil {
		h.logger.Error("failed to update SSH connection", "error", err)
		h.setFlash(w, r, "error", "Failed to update connection: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/connections/ssh/%s", connIDStr), http.StatusSeeOther)
		return
	}

	h.setFlash(w, r, "success", "Connection updated successfully")
	http.Redirect(w, r, fmt.Sprintf("/connections/ssh/%s", connIDStr), http.StatusSeeOther)
}

// SSHConnectionDelete handles deleting an SSH connection.
func (h *Handler) SSHConnectionDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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

	svc := h.getSSHService()
	if svc == nil {
		http.Error(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	if err := svc.DeleteConnection(ctx, connID); err != nil {
		h.logger.Error("failed to delete SSH connection", "error", err)
		http.Error(w, "Failed to delete connection", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// SSHConnectionTest tests an SSH connection.
func (h *Handler) SSHConnectionTest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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

	svc := h.getSSHService()
	if svc == nil {
		http.Error(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	result, err := svc.TestConnection(ctx, connID)
	if err != nil {
		h.logger.Error("failed to test SSH connection", "error", err)
		http.Error(w, "Failed to test connection: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if result.Success {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success": true, "message": "` + result.Message + `", "latency_ms": ` + strconv.FormatInt(result.Latency, 10) + `}`))
	} else {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success": false, "message": "` + result.Message + `"}`))
	}
}

// ============================================================================
// SFTP Browser
// ============================================================================

// SFTPBrowserTempl renders the SFTP file browser.
func (h *Handler) SFTPBrowserTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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

	svc := h.getSSHService()
	if svc == nil {
		http.Error(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	conn, err := svc.GetConnection(ctx, connID)
	if err != nil {
		http.Error(w, "Connection not found", http.StatusNotFound)
		return
	}

	pageData := h.preparePageData(r, "File Browser - "+conn.Name, "connections-ssh")

	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/"
	}

	data := connections.SFTPBrowserData{
		PageData:    ToTemplPageData(pageData),
		Connection:  toSSHConnectionData(conn),
		CurrentPath: path,
		Files:       []connections.SFTPFileData{}, // Will be loaded via API
	}

	if err := connections.SFTPBrowser(data).Render(ctx, w); err != nil {
		h.logger.Error("failed to render SFTP browser template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// SFTPUpload handles file uploads via SFTP.
func (h *Handler) SFTPUpload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connIDStr := chi.URLParam(r, "id")
	if connIDStr == "" {
		h.jsonError(w, "connection ID required", http.StatusBadRequest)
		return
	}

	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		h.jsonError(w, "invalid connection ID", http.StatusBadRequest)
		return
	}

	svc := h.getSSHService()
	if svc == nil {
		h.jsonError(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	// Parse multipart form (32MB max)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		h.jsonError(w, "failed to parse form: "+err.Error(), http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		h.jsonError(w, "no file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	remotePath := r.FormValue("path")
	if remotePath == "" {
		remotePath = "/"
	}
	// Ensure full remote path
	fullRemotePath := filepath.Join(remotePath, header.Filename)

	// Connect to SFTP
	client, err := svc.ConnectSFTP(ctx, connID)
	if err != nil {
		h.jsonError(w, "failed to connect: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer client.Close()

	// Upload file
	if err := svc.UploadFile(ctx, client, file, fullRemotePath, nil); err != nil {
		h.jsonError(w, "upload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.jsonSuccess(w, map[string]interface{}{
		"message": "File uploaded successfully",
		"path":    fullRemotePath,
	})
}

// SFTPDownload handles file downloads via SFTP.
func (h *Handler) SFTPDownload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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

	remotePath := r.URL.Query().Get("path")
	if remotePath == "" {
		http.Error(w, "path required", http.StatusBadRequest)
		return
	}

	svc := h.getSSHService()
	if svc == nil {
		http.Error(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	// Connect to SFTP
	client, err := svc.ConnectSFTP(ctx, connID)
	if err != nil {
		http.Error(w, "failed to connect: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer client.Close()

	// Get file info for headers
	fileInfo, err := svc.GetFileInfo(ctx, client, remotePath)
	if err != nil {
		http.Error(w, "file not found: "+err.Error(), http.StatusNotFound)
		return
	}

	if fileInfo.IsDir {
		http.Error(w, "cannot download directory", http.StatusBadRequest)
		return
	}

	// Read file
	reader, _, err := svc.ReadFile(ctx, client, remotePath)
	if err != nil {
		http.Error(w, "failed to read file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer reader.Close()

	// Set headers for download
	filename := filepath.Base(remotePath)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.Header().Set("Content-Type", "application/octet-stream")

	// Stream file
	io.Copy(w, reader)
}

// SFTPDelete handles file deletion via SFTP.
func (h *Handler) SFTPDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connIDStr := chi.URLParam(r, "id")
	if connIDStr == "" {
		h.jsonError(w, "connection ID required", http.StatusBadRequest)
		return
	}

	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		h.jsonError(w, "invalid connection ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Path      string `json:"path"`
		Recursive bool   `json:"recursive"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Try form data
		req.Path = r.FormValue("path")
		req.Recursive = r.FormValue("recursive") == "true"
	}

	if req.Path == "" {
		h.jsonError(w, "path required", http.StatusBadRequest)
		return
	}

	svc := h.getSSHService()
	if svc == nil {
		h.jsonError(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	// Connect to SFTP
	client, err := svc.ConnectSFTP(ctx, connID)
	if err != nil {
		h.jsonError(w, "failed to connect: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer client.Close()

	// Delete file or directory
	if req.Recursive {
		err = svc.DeleteRecursive(ctx, client, req.Path)
	} else {
		err = svc.DeleteFile(ctx, client, req.Path)
	}

	if err != nil {
		h.jsonError(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.jsonSuccess(w, map[string]interface{}{
		"message": "Deleted successfully",
		"path":    req.Path,
	})
}

// SFTPMkdir creates a directory via SFTP.
func (h *Handler) SFTPMkdir(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connIDStr := chi.URLParam(r, "id")
	if connIDStr == "" {
		h.jsonError(w, "connection ID required", http.StatusBadRequest)
		return
	}

	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		h.jsonError(w, "invalid connection ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Path = r.FormValue("path")
	}

	if req.Path == "" {
		h.jsonError(w, "path required", http.StatusBadRequest)
		return
	}

	svc := h.getSSHService()
	if svc == nil {
		h.jsonError(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	// Connect to SFTP
	client, err := svc.ConnectSFTP(ctx, connID)
	if err != nil {
		h.jsonError(w, "failed to connect: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer client.Close()

	// Create directory
	if err := svc.CreateDirectory(ctx, client, req.Path); err != nil {
		h.jsonError(w, "mkdir failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.jsonSuccess(w, map[string]interface{}{
		"message": "Directory created",
		"path":    req.Path,
	})
}

// SFTPRename renames a file or directory via SFTP.
func (h *Handler) SFTPRename(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connIDStr := chi.URLParam(r, "id")
	if connIDStr == "" {
		h.jsonError(w, "connection ID required", http.StatusBadRequest)
		return
	}

	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		h.jsonError(w, "invalid connection ID", http.StatusBadRequest)
		return
	}

	var req struct {
		OldPath string `json:"old_path"`
		NewPath string `json:"new_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.OldPath = r.FormValue("old_path")
		req.NewPath = r.FormValue("new_path")
	}

	if req.OldPath == "" || req.NewPath == "" {
		h.jsonError(w, "old_path and new_path required", http.StatusBadRequest)
		return
	}

	svc := h.getSSHService()
	if svc == nil {
		h.jsonError(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	// Connect to SFTP
	client, err := svc.ConnectSFTP(ctx, connID)
	if err != nil {
		h.jsonError(w, "failed to connect: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer client.Close()

	// Rename
	if err := svc.Rename(ctx, client, req.OldPath, req.NewPath); err != nil {
		h.jsonError(w, "rename failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.jsonSuccess(w, map[string]interface{}{
		"message":  "Renamed successfully",
		"old_path": req.OldPath,
		"new_path": req.NewPath,
	})
}

// SFTPListFiles returns directory contents as JSON (for HTMX/JS).
func (h *Handler) SFTPListFiles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connIDStr := chi.URLParam(r, "id")
	if connIDStr == "" {
		h.jsonError(w, "connection ID required", http.StatusBadRequest)
		return
	}

	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		h.jsonError(w, "invalid connection ID", http.StatusBadRequest)
		return
	}

	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/"
	}

	svc := h.getSSHService()
	if svc == nil {
		h.jsonError(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	// Connect to SFTP
	client, err := svc.ConnectSFTP(ctx, connID)
	if err != nil {
		h.jsonError(w, "failed to connect: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer client.Close()

	// List directory
	files, err := svc.ListDirectory(ctx, client, path)
	if err != nil {
		h.jsonError(w, "failed to list: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert to response format
	var fileData []map[string]interface{}
	for _, f := range files {
		fileData = append(fileData, map[string]interface{}{
			"name":       f.Name,
			"path":       f.Path,
			"size":       f.Size,
			"mode":       f.Mode,
			"is_dir":     f.IsDir,
			"mod_time":   f.ModTime.Format(time.RFC3339),
			"owner":      f.Owner,
			"group":      f.Group,
			"is_symlink": f.IsLink,
		})
	}

	h.jsonSuccess(w, map[string]interface{}{
		"path":  path,
		"files": fileData,
	})
}

// ============================================================================
// SSH Keys
// ============================================================================

// SSHKeysTempl renders the SSH keys list.
func (h *Handler) SSHKeysTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.preparePageData(r, "SSH Keys", "connections-keys")
	userData := h.getUserData(r)

	var keyData []connections.SSHKeyData

	// Fetch keys if service is available
	svc := h.getSSHService()
	if svc != nil && userData != nil {
		userID, err := uuid.Parse(userData.ID)
		if err == nil {
			keys, err := svc.ListKeys(ctx, userID)
			if err == nil {
				for _, key := range keys {
					keyData = append(keyData, toSSHKeyData(key))
				}
			}
		}
	}

	data := connections.SSHKeysListData{
		PageData: ToTemplPageData(pageData),
		Keys:     keyData,
	}

	if err := connections.SSHKeysList(data).Render(ctx, w); err != nil {
		h.logger.Error("failed to render SSH keys template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// SSHKeyNewTempl renders the new SSH key form.
func (h *Handler) SSHKeyNewTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.preparePageData(r, "New SSH Key", "connections-keys")

	if err := connections.SSHKeyNew(ToTemplPageData(pageData)).Render(ctx, w); err != nil {
		h.logger.Error("failed to render new SSH key template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// SSHKeyCreate handles creating/generating a new SSH key.
func (h *Handler) SSHKeyCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userData := h.getUserData(r)

	svc := h.getSSHService()
	if svc == nil {
		http.Error(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	if userData == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	userID, err := uuid.Parse(userData.ID)
	if err != nil {
		http.Error(w, "Invalid user session", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// Check if importing or generating
	isImport := r.FormValue("import") == "true"

	input := models.CreateSSHKeyInput{
		Name:       r.FormValue("name"),
		KeyType:    models.SSHKeyType(r.FormValue("type")),
		Passphrase: r.FormValue("passphrase"),
		Comment:    r.FormValue("comment"),
		Generate:   !isImport,
	}

	if isImport {
		input.PrivateKey = r.FormValue("private_key")
	}

	var key *models.SSHKey
	if isImport {
		key, err = svc.ImportKey(ctx, input, userID)
	} else {
		key, err = svc.GenerateKey(ctx, input, userID)
	}

	if err != nil {
		h.logger.Error("failed to create SSH key", "error", err)
		h.setFlash(w, r, "error", "Failed to create key: "+err.Error())
		http.Redirect(w, r, "/connections/keys", http.StatusSeeOther)
		return
	}

	_ = key
	h.setFlash(w, r, "success", "SSH key created")
	http.Redirect(w, r, "/connections/keys", http.StatusSeeOther)
}

// SSHKeyDetailTempl renders the SSH key detail page.
func (h *Handler) SSHKeyDetailTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	keyIDStr := chi.URLParam(r, "id")
	if keyIDStr == "" {
		http.Error(w, "key ID required", http.StatusBadRequest)
		return
	}

	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		http.Error(w, "invalid key ID", http.StatusBadRequest)
		return
	}

	svc := h.getSSHService()
	if svc == nil {
		http.Error(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	key, err := svc.GetKey(ctx, keyID)
	if err != nil {
		http.Error(w, "Key not found", http.StatusNotFound)
		return
	}

	pageData := h.preparePageData(r, key.Name, "connections-keys")

	// Note: UsedBy is left empty for now until GetConnectionsUsingKey is implemented in the SSH service
	data := connections.SSHKeyDetailData{
		PageData: ToTemplPageData(pageData),
		Key:      toSSHKeyData(key),
		UsedBy:   []connections.SSHConnectionData{},
	}

	if err := connections.SSHKeyDetail(data).Render(ctx, w); err != nil {
		h.logger.Error("failed to render SSH key detail", "error", err)
		http.Error(w, "Render error", http.StatusInternalServerError)
	}
}

// SSHKeyDelete handles deleting an SSH key.
func (h *Handler) SSHKeyDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	keyIDStr := chi.URLParam(r, "id")
	if keyIDStr == "" {
		http.Error(w, "key ID required", http.StatusBadRequest)
		return
	}

	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		http.Error(w, "invalid key ID", http.StatusBadRequest)
		return
	}

	svc := h.getSSHService()
	if svc == nil {
		http.Error(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	if err := svc.DeleteKey(ctx, keyID); err != nil {
		h.logger.Error("failed to delete SSH key", "error", err)
		http.Error(w, "Failed to delete key", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// SSHKeyDownload downloads the public key.
func (h *Handler) SSHKeyDownload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	keyIDStr := chi.URLParam(r, "id")
	if keyIDStr == "" {
		http.Error(w, "key ID required", http.StatusBadRequest)
		return
	}

	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		http.Error(w, "invalid key ID", http.StatusBadRequest)
		return
	}

	svc := h.getSSHService()
	if svc == nil {
		http.Error(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	key, err := svc.GetKey(ctx, keyID)
	if err != nil {
		http.Error(w, "Key not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+key.Name+".pub\"")
	w.Write([]byte(key.PublicKey))
}

// ============================================================================
// Web Shortcuts
// ============================================================================

// ShortcutsTempl renders the web shortcuts list.
func (h *Handler) ShortcutsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.preparePageData(r, "Web Shortcuts", "connections-shortcuts")
	userData := h.getUserData(r)

	var shortcutData []connections.ShortcutData
	var categories []string

	if h.shortcutsService != nil && userData != nil {
		userID, err := uuid.Parse(userData.ID)
		if err == nil {
			// Check for category filter
			categoryFilter := r.URL.Query().Get("category")
			var shortcuts []*models.WebShortcut

			if categoryFilter != "" {
				shortcuts, err = h.shortcutsService.ListByCategory(ctx, userID, categoryFilter)
			} else {
				shortcuts, err = h.shortcutsService.List(ctx, userID)
			}

			if err == nil {
				for _, s := range shortcuts {
					shortcutData = append(shortcutData, toShortcutData(s))
				}
			}

			// Get categories for filter
			categories, _ = h.shortcutsService.GetCategories(ctx, userID)
		}
	}

	data := connections.ShortcutsListData{
		PageData:   ToTemplPageData(pageData),
		Shortcuts:  shortcutData,
		Categories: categories,
	}

	if err := connections.ShortcutsList(data).Render(ctx, w); err != nil {
		h.logger.Error("failed to render shortcuts template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// ShortcutNewTempl renders the new shortcut form.
func (h *Handler) ShortcutNewTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.preparePageData(r, "New Shortcut", "connections-shortcuts")
	userData := h.getUserData(r)

	var categories []string
	if h.shortcutsService != nil && userData != nil {
		userID, err := uuid.Parse(userData.ID)
		if err == nil {
			categories, _ = h.shortcutsService.GetCategories(ctx, userID)
		}
	}

	data := connections.ShortcutNewData{
		PageData:   ToTemplPageData(pageData),
		Categories: categories,
	}

	if err := connections.ShortcutNew(data).Render(ctx, w); err != nil {
		h.logger.Error("failed to render new shortcut template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// ShortcutCreate handles creating a new web shortcut.
func (h *Handler) ShortcutCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userData := h.getUserData(r)

	if h.shortcutsService == nil {
		http.Error(w, "Shortcuts service not available", http.StatusServiceUnavailable)
		return
	}

	if userData == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	userID, err := uuid.Parse(userData.ID)
	if err != nil {
		http.Error(w, "Invalid user session", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	input := models.CreateWebShortcutInput{
		Name:        r.FormValue("name"),
		Description: r.FormValue("description"),
		URL:         r.FormValue("url"),
		Type:        models.ShortcutType(r.FormValue("type")),
		Icon:        r.FormValue("icon"),
		IconType:    r.FormValue("icon_type"),
		Color:       r.FormValue("color"),
		Category:    r.FormValue("category"),
		OpenInNew:   r.FormValue("open_in_new") == "true",
		ShowInMenu:  r.FormValue("show_in_menu") == "true",
		IsPublic:    r.FormValue("is_public") == "true",
	}

	// Set default type if not provided
	if input.Type == "" {
		input.Type = models.ShortcutTypeWeb
	}

	shortcut, err := h.shortcutsService.Create(ctx, input, userID)
	if err != nil {
		h.logger.Error("failed to create shortcut", "error", err)
		h.setFlash(w, r, "error", "Failed to create shortcut: "+err.Error())
		http.Redirect(w, r, "/connections/shortcuts", http.StatusSeeOther)
		return
	}

	// Auto-fetch favicon if icon is empty and icon_type is url
	if input.Icon == "" && (input.IconType == "url" || input.IconType == "") {
		go func() {
			_ = h.shortcutsService.FetchAndSetFavicon(context.Background(), shortcut.ID)
		}()
	}

	h.setFlash(w, r, "success", "Shortcut created")
	http.Redirect(w, r, "/connections/shortcuts", http.StatusSeeOther)
}

// ShortcutUpdate handles updating a web shortcut.
func (h *Handler) ShortcutUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	shortcutIDStr := chi.URLParam(r, "id")
	if shortcutIDStr == "" {
		http.Error(w, "shortcut ID required", http.StatusBadRequest)
		return
	}

	shortcutID, err := uuid.Parse(shortcutIDStr)
	if err != nil {
		http.Error(w, "invalid shortcut ID", http.StatusBadRequest)
		return
	}

	if h.shortcutsService == nil {
		http.Error(w, "Shortcuts service not available", http.StatusServiceUnavailable)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	input := models.UpdateWebShortcutInput{}

	if name := r.FormValue("name"); name != "" {
		input.Name = &name
	}
	if desc := r.FormValue("description"); desc != "" {
		input.Description = &desc
	}
	if url := r.FormValue("url"); url != "" {
		input.URL = &url
	}
	if icon := r.FormValue("icon"); icon != "" {
		input.Icon = &icon
	}
	if iconType := r.FormValue("icon_type"); iconType != "" {
		input.IconType = &iconType
	}
	if color := r.FormValue("color"); color != "" {
		input.Color = &color
	}
	if cat := r.FormValue("category"); cat != "" {
		input.Category = &cat
	}

	openInNew := r.FormValue("open_in_new") == "true"
	showInMenu := r.FormValue("show_in_menu") == "true"
	isPublic := r.FormValue("is_public") == "true"
	input.OpenInNew = &openInNew
	input.ShowInMenu = &showInMenu
	input.IsPublic = &isPublic

	_, err = h.shortcutsService.Update(ctx, shortcutID, input)
	if err != nil {
		h.logger.Error("failed to update shortcut", "error", err)
		http.Error(w, "Failed to update shortcut", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/connections/shortcuts", http.StatusFound)
}

// ShortcutDelete handles deleting a web shortcut.
func (h *Handler) ShortcutDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	shortcutIDStr := chi.URLParam(r, "id")
	if shortcutIDStr == "" {
		http.Error(w, "shortcut ID required", http.StatusBadRequest)
		return
	}

	shortcutID, err := uuid.Parse(shortcutIDStr)
	if err != nil {
		http.Error(w, "invalid shortcut ID", http.StatusBadRequest)
		return
	}

	if h.shortcutsService == nil {
		http.Error(w, "Shortcuts service not available", http.StatusServiceUnavailable)
		return
	}

	if err := h.shortcutsService.Delete(ctx, shortcutID); err != nil {
		h.logger.Error("failed to delete shortcut", "error", err)
		http.Error(w, "Failed to delete shortcut", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ShortcutEditTempl renders the edit shortcut form.
func (h *Handler) ShortcutEditTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	shortcutIDStr := chi.URLParam(r, "id")
	if shortcutIDStr == "" {
		http.Error(w, "shortcut ID required", http.StatusBadRequest)
		return
	}

	shortcutID, err := uuid.Parse(shortcutIDStr)
	if err != nil {
		http.Error(w, "invalid shortcut ID", http.StatusBadRequest)
		return
	}

	if h.shortcutsService == nil {
		http.Error(w, "Shortcuts service not available", http.StatusServiceUnavailable)
		return
	}

	shortcut, err := h.shortcutsService.Get(ctx, shortcutID)
	if err != nil {
		http.Error(w, "Shortcut not found", http.StatusNotFound)
		return
	}

	pageData := h.preparePageData(r, "Edit Shortcut", "connections-shortcuts")
	userData := h.getUserData(r)

	var categories []string
	if userData != nil {
		userID, err := uuid.Parse(userData.ID)
		if err == nil {
			categories, _ = h.shortcutsService.GetCategories(ctx, userID)
		}
	}

	data := connections.ShortcutEditData{
		PageData:   ToTemplPageData(pageData),
		Shortcut:   toShortcutData(shortcut),
		Categories: categories,
	}

	if err := connections.ShortcutEdit(data).Render(ctx, w); err != nil {
		h.logger.Error("failed to render edit shortcut template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
