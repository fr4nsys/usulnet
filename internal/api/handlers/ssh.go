// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/ssh"
)

// SSHHandler handles SSH-related API requests.
type SSHHandler struct {
	BaseHandler
	sshService *ssh.Service
}

// NewSSHHandler creates a new SSH handler.
func NewSSHHandler(sshService *ssh.Service, log *logger.Logger) *SSHHandler {
	return &SSHHandler{
		BaseHandler: NewBaseHandler(log),
		sshService:  sshService,
	}
}

// Routes registers SSH API routes.
func (h *SSHHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// SSH Keys
	r.Route("/keys", func(r chi.Router) {
		r.Get("/", h.ListKeys)
		r.Post("/", h.CreateKey)
		r.Get("/{id}", h.GetKey)
		r.Delete("/{id}", h.DeleteKey)
	})

	// SSH Connections
	r.Route("/connections", func(r chi.Router) {
		r.Get("/", h.ListConnections)
		r.Post("/", h.CreateConnection)
		r.Get("/categories", h.GetCategories)
		r.Get("/{id}", h.GetConnection)
		r.Put("/{id}", h.UpdateConnection)
		r.Delete("/{id}", h.DeleteConnection)
		r.Post("/{id}/test", h.TestConnection)
		r.Get("/{id}/sessions", h.GetSessionHistory)
	})

	// Active sessions
	r.Get("/sessions/active", h.GetActiveSessions)

	return r
}

// ============================================================================
// SSH Key Handlers
// ============================================================================

// ListKeys returns all SSH keys for the current user.
func (h *SSHHandler) ListKeys(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	keys, err := h.sshService.ListKeys(r.Context(), userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	// Sanitize output - don't expose private keys
	type KeyResponse struct {
		ID          uuid.UUID           `json:"id"`
		Name        string              `json:"name"`
		KeyType     models.SSHKeyType   `json:"key_type"`
		PublicKey   string              `json:"public_key"`
		Fingerprint string              `json:"fingerprint"`
		Comment     string              `json:"comment,omitempty"`
		CreatedAt   string              `json:"created_at"`
		LastUsed    *string             `json:"last_used,omitempty"`
	}

	response := make([]KeyResponse, 0, len(keys))
	for _, key := range keys {
		k := KeyResponse{
			ID:          key.ID,
			Name:        key.Name,
			KeyType:     key.KeyType,
			PublicKey:   key.PublicKey,
			Fingerprint: key.Fingerprint,
			Comment:     key.Comment,
			CreatedAt:   key.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}
		if key.LastUsed != nil {
			t := key.LastUsed.Format("2006-01-02T15:04:05Z")
			k.LastUsed = &t
		}
		response = append(response, k)
	}

	h.OK(w, response)
}

// CreateKey creates a new SSH key or imports an existing one.
func (h *SSHHandler) CreateKey(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var input models.CreateSSHKeyInput
	if err := h.ParseJSON(r, &input); err != nil {
		h.HandleError(w, err)
		return
	}

	var key *models.SSHKey
	if input.Generate {
		key, err = h.sshService.GenerateKey(r.Context(), input, userID)
	} else {
		key, err = h.sshService.ImportKey(r.Context(), input, userID)
	}

	if err != nil {
		h.HandleError(w, err)
		return
	}

	// Return response (with private key only on generation)
	response := map[string]any{
		"id":          key.ID,
		"name":        key.Name,
		"key_type":    key.KeyType,
		"public_key":  key.PublicKey,
		"fingerprint": key.Fingerprint,
		"comment":     key.Comment,
		"created_at":  key.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}

	// Include private key only for newly generated keys (so user can download it)
	if input.Generate {
		// Decrypt for response (one-time display)
		// Note: In production, consider secure key delivery mechanism
		response["private_key_generated"] = true
	}

	h.Created(w, response)
}

// GetKey returns an SSH key by ID.
func (h *SSHHandler) GetKey(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	key, err := h.sshService.GetKey(r.Context(), id)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	response := map[string]any{
		"id":          key.ID,
		"name":        key.Name,
		"key_type":    key.KeyType,
		"public_key":  key.PublicKey,
		"fingerprint": key.Fingerprint,
		"comment":     key.Comment,
		"created_at":  key.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}

	if key.LastUsed != nil {
		response["last_used"] = key.LastUsed.Format("2006-01-02T15:04:05Z")
	}

	h.OK(w, response)
}

// DeleteKey deletes an SSH key.
func (h *SSHHandler) DeleteKey(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.sshService.DeleteKey(r.Context(), id); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// ============================================================================
// SSH Connection Handlers
// ============================================================================

// ListConnections returns all SSH connections for the current user.
func (h *SSHHandler) ListConnections(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	category := h.QueryParam(r, "category")

	var conns []*models.SSHConnection
	if category != "" {
		conns, err = h.sshService.ListConnectionsByCategory(r.Context(), userID, category)
	} else {
		conns, err = h.sshService.ListConnections(r.Context(), userID)
	}

	if err != nil {
		h.HandleError(w, err)
		return
	}

	// Sanitize output - don't expose passwords
	response := make([]map[string]any, 0, len(conns))
	for _, conn := range conns {
		c := map[string]any{
			"id":          conn.ID,
			"name":        conn.Name,
			"description": conn.Description,
			"host":        conn.Host,
			"port":        conn.Port,
			"username":    conn.Username,
			"auth_type":   conn.AuthType,
			"category":    conn.Category,
			"tags":        conn.Tags,
			"status":      conn.Status,
			"created_at":  conn.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}

		if conn.KeyID != nil {
			c["key_id"] = conn.KeyID
		}
		if conn.JumpHost != nil {
			c["jump_host"] = conn.JumpHost
		}
		if conn.LastChecked != nil {
			c["last_checked"] = conn.LastChecked.Format("2006-01-02T15:04:05Z")
		}
		if conn.StatusMsg != "" {
			c["status_message"] = conn.StatusMsg
		}

		response = append(response, c)
	}

	h.OK(w, response)
}

// CreateConnection creates a new SSH connection.
func (h *SSHHandler) CreateConnection(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var input models.CreateSSHConnectionInput
	if err := h.ParseJSON(r, &input); err != nil {
		h.HandleError(w, err)
		return
	}

	conn, err := h.sshService.CreateConnection(r.Context(), input, userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	response := map[string]any{
		"id":          conn.ID,
		"name":        conn.Name,
		"host":        conn.Host,
		"port":        conn.Port,
		"username":    conn.Username,
		"auth_type":   conn.AuthType,
		"status":      conn.Status,
		"created_at":  conn.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}

	h.Created(w, response)
}

// GetConnection returns an SSH connection by ID.
func (h *SSHHandler) GetConnection(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	conn, err := h.sshService.GetConnection(r.Context(), id)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	response := map[string]any{
		"id":          conn.ID,
		"name":        conn.Name,
		"description": conn.Description,
		"host":        conn.Host,
		"port":        conn.Port,
		"username":    conn.Username,
		"auth_type":   conn.AuthType,
		"category":    conn.Category,
		"tags":        conn.Tags,
		"status":      conn.Status,
		"options":     conn.Options,
		"created_at":  conn.CreatedAt.Format("2006-01-02T15:04:05Z"),
		"updated_at":  conn.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}

	if conn.KeyID != nil {
		response["key_id"] = conn.KeyID
	}
	if conn.JumpHost != nil {
		response["jump_host"] = conn.JumpHost
	}
	if conn.LastChecked != nil {
		response["last_checked"] = conn.LastChecked.Format("2006-01-02T15:04:05Z")
	}
	if conn.StatusMsg != "" {
		response["status_message"] = conn.StatusMsg
	}
	if conn.Key != nil {
		response["key"] = map[string]any{
			"id":          conn.Key.ID,
			"name":        conn.Key.Name,
			"fingerprint": conn.Key.Fingerprint,
		}
	}

	h.OK(w, response)
}

// UpdateConnection updates an SSH connection.
func (h *SSHHandler) UpdateConnection(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var input models.UpdateSSHConnectionInput
	if err := h.ParseJSON(r, &input); err != nil {
		h.HandleError(w, err)
		return
	}

	conn, err := h.sshService.UpdateConnection(r.Context(), id, input)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	response := map[string]any{
		"id":         conn.ID,
		"name":       conn.Name,
		"host":       conn.Host,
		"port":       conn.Port,
		"username":   conn.Username,
		"auth_type":  conn.AuthType,
		"status":     conn.Status,
		"updated_at": conn.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}

	h.OK(w, response)
}

// DeleteConnection deletes an SSH connection.
func (h *SSHHandler) DeleteConnection(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.sshService.DeleteConnection(r.Context(), id); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// TestConnection tests connectivity to an SSH host.
func (h *SSHHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	result, err := h.sshService.TestConnection(r.Context(), id)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, result)
}

// GetCategories returns all unique categories for the current user.
func (h *SSHHandler) GetCategories(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	categories, err := h.sshService.GetCategories(r.Context(), userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]any{
		"categories": categories,
	})
}

// ============================================================================
// Session Handlers
// ============================================================================

// GetActiveSessions returns all active SSH sessions.
func (h *SSHHandler) GetActiveSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := h.sshService.GetActiveSessions(r.Context())
	if err != nil {
		h.HandleError(w, err)
		return
	}

	response := make([]map[string]any, 0, len(sessions))
	for _, s := range sessions {
		response = append(response, map[string]any{
			"id":            s.ID,
			"connection_id": s.ConnectionID,
			"user_id":       s.UserID,
			"started_at":    s.StartedAt.Format("2006-01-02T15:04:05Z"),
			"client_ip":     s.ClientIP,
			"term_type":     s.TermType,
		})
	}

	h.OK(w, response)
}

// GetSessionHistory returns session history for a connection.
func (h *SSHHandler) GetSessionHistory(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	limit := h.QueryParamInt(r, "limit", 20)
	if limit > 100 {
		limit = 100
	}

	sessions, err := h.sshService.GetSessionHistory(r.Context(), id, limit)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	response := make([]map[string]any, 0, len(sessions))
	for _, s := range sessions {
		sess := map[string]any{
			"id":            s.ID,
			"connection_id": s.ConnectionID,
			"user_id":       s.UserID,
			"started_at":    s.StartedAt.Format("2006-01-02T15:04:05Z"),
			"client_ip":     s.ClientIP,
			"term_type":     s.TermType,
		}
		if s.EndedAt != nil {
			sess["ended_at"] = s.EndedAt.Format("2006-01-02T15:04:05Z")
		}
		response = append(response, sess)
	}

	h.OK(w, response)
}
