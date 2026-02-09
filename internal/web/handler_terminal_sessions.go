// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// TerminalSession represents a terminal session for the web layer.
type TerminalSession struct {
	ID           uuid.UUID  `json:"id"`
	UserID       uuid.UUID  `json:"user_id"`
	Username     string     `json:"username"`
	TargetType   string     `json:"target_type"`
	TargetID     string     `json:"target_id"`
	TargetName   string     `json:"target_name"`
	HostID       *uuid.UUID `json:"host_id,omitempty"`
	Shell        string     `json:"shell"`
	TermCols     int        `json:"term_cols"`
	TermRows     int        `json:"term_rows"`
	ClientIP     string     `json:"client_ip"`
	StartedAt    time.Time  `json:"started_at"`
	EndedAt      *time.Time `json:"ended_at,omitempty"`
	DurationMs   *int64     `json:"duration_ms,omitempty"`
	DurationHuman string    `json:"duration_human,omitempty"`
	Status       string     `json:"status"`
	ErrorMessage string     `json:"error_message,omitempty"`
}

// CreateTerminalSessionInput is the input for creating a terminal session.
type CreateTerminalSessionInput struct {
	UserID     uuid.UUID
	Username   string
	TargetType string
	TargetID   string
	TargetName string
	HostID     *uuid.UUID
	Shell      string
	TermCols   int
	TermRows   int
	ClientIP   string
	UserAgent  string
}

// TerminalSessionRepository defines the interface for terminal session storage.
type TerminalSessionRepository interface {
	Create(ctx context.Context, input *CreateTerminalSessionInput) (uuid.UUID, error)
	End(ctx context.Context, sessionID uuid.UUID, status, errorMsg string) error
	UpdateResize(ctx context.Context, sessionID uuid.UUID, cols, rows int) error
	Get(ctx context.Context, sessionID uuid.UUID) (*TerminalSession, error)
	List(ctx context.Context, opts TerminalSessionListOptions) ([]*TerminalSession, int, error)
	GetByTarget(ctx context.Context, targetType, targetID string, limit int) ([]*TerminalSession, error)
	GetByUser(ctx context.Context, userID uuid.UUID, limit int) ([]*TerminalSession, error)
	GetActiveSessions(ctx context.Context) ([]*TerminalSession, error)
}

// TerminalSessionListOptions contains options for listing terminal sessions.
type TerminalSessionListOptions struct {
	UserID     *uuid.UUID
	TargetType *string
	TargetID   *string
	HostID     *uuid.UUID
	Status     *string
	Since      *time.Time
	Until      *time.Time
	Limit      int
	Offset     int
}

// SetTerminalSessionRepo sets the terminal session repository.
func (h *Handler) SetTerminalSessionRepo(repo TerminalSessionRepository) {
	h.terminalSessionRepo = repo
}

// ============================================================================
// API Handlers for Terminal Session History
// ============================================================================

// APITerminalSessionList returns a list of terminal sessions.
// GET /api/v1/terminal/sessions
func (h *Handler) APITerminalSessionList(w http.ResponseWriter, r *http.Request) {
	if h.terminalSessionRepo == nil {
		h.jsonResponseWithStatus(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Terminal session tracking not configured",
		})
		return
	}

	ctx := r.Context()

	// Parse query parameters
	opts := TerminalSessionListOptions{
		Limit:  50,
		Offset: 0,
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			opts.Limit = limit
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			opts.Offset = offset
		}
	}
	if targetType := r.URL.Query().Get("target_type"); targetType != "" {
		opts.TargetType = &targetType
	}
	if targetID := r.URL.Query().Get("target_id"); targetID != "" {
		opts.TargetID = &targetID
	}
	if status := r.URL.Query().Get("status"); status != "" {
		opts.Status = &status
	}
	if userIDStr := r.URL.Query().Get("user_id"); userIDStr != "" {
		if userID, err := uuid.Parse(userIDStr); err == nil {
			opts.UserID = &userID
		}
	}
	if hostIDStr := r.URL.Query().Get("host_id"); hostIDStr != "" {
		if hostID, err := uuid.Parse(hostIDStr); err == nil {
			opts.HostID = &hostID
		}
	}

	sessions, total, err := h.terminalSessionRepo.List(ctx, opts)
	if err != nil {
		h.jsonResponseWithStatus(w, http.StatusInternalServerError, map[string]interface{}{
			"error": "Failed to list terminal sessions: " + err.Error(),
		})
		return
	}

	// Add duration_human to each session
	for _, s := range sessions {
		if s.DurationMs != nil {
			s.DurationHuman = formatDurationMs(*s.DurationMs)
		}
	}

	h.jsonResponseWithStatus(w, http.StatusOK, map[string]interface{}{
		"sessions": sessions,
		"total":    total,
		"limit":    opts.Limit,
		"offset":   opts.Offset,
	})
}

// APITerminalSessionGet returns a specific terminal session.
// GET /api/v1/terminal/sessions/{id}
func (h *Handler) APITerminalSessionGet(w http.ResponseWriter, r *http.Request) {
	if h.terminalSessionRepo == nil {
		h.jsonResponseWithStatus(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Terminal session tracking not configured",
		})
		return
	}

	sessionID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonResponseWithStatus(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Invalid session ID",
		})
		return
	}

	session, err := h.terminalSessionRepo.Get(r.Context(), sessionID)
	if err != nil {
		h.jsonResponseWithStatus(w, http.StatusNotFound, map[string]interface{}{
			"error": "Terminal session not found",
		})
		return
	}

	if session.DurationMs != nil {
		session.DurationHuman = formatDurationMs(*session.DurationMs)
	}

	h.jsonResponseWithStatus(w, http.StatusOK, session)
}

// APITerminalSessionsActive returns all active terminal sessions.
// GET /api/v1/terminal/sessions/active
func (h *Handler) APITerminalSessionsActive(w http.ResponseWriter, r *http.Request) {
	if h.terminalSessionRepo == nil {
		h.jsonResponseWithStatus(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Terminal session tracking not configured",
		})
		return
	}

	sessions, err := h.terminalSessionRepo.GetActiveSessions(r.Context())
	if err != nil {
		h.jsonResponseWithStatus(w, http.StatusInternalServerError, map[string]interface{}{
			"error": "Failed to get active sessions: " + err.Error(),
		})
		return
	}

	h.jsonResponseWithStatus(w, http.StatusOK, map[string]interface{}{
		"sessions": sessions,
		"count":    len(sessions),
	})
}

// APITerminalSessionsByTarget returns terminal sessions for a specific target.
// GET /api/v1/terminal/sessions/target/{type}/{id}
func (h *Handler) APITerminalSessionsByTarget(w http.ResponseWriter, r *http.Request) {
	if h.terminalSessionRepo == nil {
		h.jsonResponseWithStatus(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Terminal session tracking not configured",
		})
		return
	}

	targetType := chi.URLParam(r, "type")
	targetID := chi.URLParam(r, "id")

	if targetType == "" || targetID == "" {
		h.jsonResponseWithStatus(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Target type and ID required",
		})
		return
	}

	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	sessions, err := h.terminalSessionRepo.GetByTarget(r.Context(), targetType, targetID, limit)
	if err != nil {
		h.jsonResponseWithStatus(w, http.StatusInternalServerError, map[string]interface{}{
			"error": "Failed to get sessions: " + err.Error(),
		})
		return
	}

	for _, s := range sessions {
		if s.DurationMs != nil {
			s.DurationHuman = formatDurationMs(*s.DurationMs)
		}
	}

	h.jsonResponseWithStatus(w, http.StatusOK, map[string]interface{}{
		"sessions": sessions,
		"count":    len(sessions),
	})
}

// ============================================================================
// Helper Functions
// ============================================================================

// formatDurationMs formats a duration in milliseconds to a human-readable string.
// Uses the existing formatDuration from handler_monitoring.go
func formatDurationMs(ms int64) string {
	return formatDuration(time.Duration(ms) * time.Millisecond)
}

// jsonResponseWithStatus sends a JSON response with a status code.
func (h *Handler) jsonResponseWithStatus(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// getRealIP extracts the real client IP from the request.
// It checks X-Forwarded-For and X-Real-IP headers before falling back to RemoteAddr.
func getRealIP(r *http.Request) string {
	// Check X-Forwarded-For header (can contain multiple IPs)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	// Strip port if present
	if idx := strings.LastIndex(ip, ":"); idx > 0 {
		// Check if this is IPv6 (contains brackets)
		if strings.Contains(ip, "[") {
			if bracketIdx := strings.Index(ip, "]:"); bracketIdx > 0 {
				return ip[1:bracketIdx]
			}
		}
		return ip[:idx]
	}
	return ip
}
