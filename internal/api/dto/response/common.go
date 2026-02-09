// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package response contains standardized response DTOs for the API.
package response

import (
	"encoding/json"
	"net/http"
	"time"
)

// ============================================================================
// Base response structures
// ============================================================================

// Response is the standard wrapper for all successful API responses.
type Response struct {
	// Success indicates if the request was successful
	Success bool `json:"success"`

	// Data contains the response payload
	Data any `json:"data,omitempty"`

	// Meta contains pagination and other metadata
	Meta *Meta `json:"meta,omitempty"`
}

// Meta contains metadata about the response (pagination, timing, etc).
type Meta struct {
	// Pagination info
	Page       int   `json:"page,omitempty"`
	PerPage    int   `json:"per_page,omitempty"`
	Total      int64 `json:"total,omitempty"`
	TotalPages int   `json:"total_pages,omitempty"`

	// Request timing
	RequestID    string `json:"request_id,omitempty"`
	ResponseTime int64  `json:"response_time_ms,omitempty"`

	// Timestamps
	Timestamp time.Time `json:"timestamp,omitempty"`
}

// Empty represents an empty successful response (for DELETE, etc).
type Empty struct{}

// ID represents a response with just an ID (for CREATE operations).
type ID struct {
	ID string `json:"id"`
}

// Message represents a simple message response.
type Message struct {
	Message string `json:"message"`
}

// ============================================================================
// Response writers
// ============================================================================

// JSON writes a JSON response with the given status code.
func JSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// OK writes a 200 OK response with data.
func OK(w http.ResponseWriter, data any) {
	JSON(w, http.StatusOK, &Response{
		Success: true,
		Data:    data,
	})
}

// OKWithMeta writes a 200 OK response with data and metadata.
func OKWithMeta(w http.ResponseWriter, data any, meta *Meta) {
	JSON(w, http.StatusOK, &Response{
		Success: true,
		Data:    data,
		Meta:    meta,
	})
}

// Created writes a 201 Created response with the created resource ID.
func Created(w http.ResponseWriter, id string) {
	JSON(w, http.StatusCreated, &Response{
		Success: true,
		Data:    &ID{ID: id},
	})
}

// CreatedWithData writes a 201 Created response with full resource data.
func CreatedWithData(w http.ResponseWriter, data any) {
	JSON(w, http.StatusCreated, &Response{
		Success: true,
		Data:    data,
	})
}

// NoContent writes a 204 No Content response.
func NoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// Accepted writes a 202 Accepted response (for async operations).
func Accepted(w http.ResponseWriter, data any) {
	JSON(w, http.StatusAccepted, &Response{
		Success: true,
		Data:    data,
	})
}

// ============================================================================
// Pagination helpers
// ============================================================================

// PaginatedResponse is a helper for creating paginated responses.
type PaginatedResponse struct {
	Items      any   `json:"items"`
	Page       int   `json:"page"`
	PerPage    int   `json:"per_page"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
}

// NewPaginatedResponse creates a new paginated response.
func NewPaginatedResponse(items any, page, perPage int, total int64) *PaginatedResponse {
	totalPages := int(total) / perPage
	if int(total)%perPage > 0 {
		totalPages++
	}

	return &PaginatedResponse{
		Items:      items,
		Page:       page,
		PerPage:    perPage,
		Total:      total,
		TotalPages: totalPages,
	}
}

// Paginated writes a paginated response.
func Paginated(w http.ResponseWriter, items any, page, perPage int, total int64) {
	resp := NewPaginatedResponse(items, page, perPage, total)
	OK(w, resp)
}

// ============================================================================
// Common data structures
// ============================================================================

// Timestamp is a helper for consistent timestamp formatting.
type Timestamp struct {
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

// ResourceRef is a minimal reference to a resource (for lists, relationships).
type ResourceRef struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

// HealthStatus represents a component health status.
type HealthStatus struct {
	Status    string `json:"status"` // "healthy", "degraded", "unhealthy"
	Message   string `json:"message,omitempty"`
	Latency   int64  `json:"latency_ms,omitempty"`
	CheckedAt string `json:"checked_at,omitempty"`
}

// ============================================================================
// System responses
// ============================================================================

// Health is the response for health check endpoints.
type Health struct {
	Status     string                   `json:"status"` // "healthy", "degraded", "unhealthy"
	Version    string                   `json:"version"`
	Uptime     int64                    `json:"uptime_seconds"`
	Components map[string]*HealthStatus `json:"components,omitempty"`
}

// Version is the response for version endpoint.
type Version struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	BuildTime string `json:"build_time,omitempty"`
	GoVersion string `json:"go_version,omitempty"`
}

// SystemInfo is the response for system info endpoint.
type SystemInfo struct {
	Version       *Version          `json:"version"`
	Platform      string            `json:"platform"`
	Architecture  string            `json:"architecture"`
	Hostname      string            `json:"hostname"`
	StartedAt     time.Time         `json:"started_at"`
	Uptime        int64             `json:"uptime_seconds"`
	DockerVersion string            `json:"docker_version,omitempty"`
	Features      map[string]bool   `json:"features,omitempty"`
	License       *LicenseInfo      `json:"license,omitempty"`
}

// LicenseInfo contains license information.
type LicenseInfo struct {
	Type      string     `json:"type"` // "community", "enterprise"
	Valid     bool       `json:"valid"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Features  []string   `json:"features,omitempty"`
}

// ============================================================================
// Auth responses
// ============================================================================

// LoginResponse is returned after successful authentication.
type LoginResponse struct {
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	User         *UserInfo `json:"user"`
}

// UserInfo contains basic user information.
type UserInfo struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Email    string   `json:"email,omitempty"`
	Role     string   `json:"role"`
	Teams    []string `json:"teams,omitempty"`
}

// TokenRefreshResponse is returned after token refresh.
type TokenRefreshResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ============================================================================
// Async operation responses
// ============================================================================

// AsyncOperation represents an asynchronous operation status.
type AsyncOperation struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"` // "pending", "running", "completed", "failed"
	Progress  int       `json:"progress,omitempty"` // 0-100
	Message   string    `json:"message,omitempty"`
	Result    any       `json:"result,omitempty"`
	Error     string    `json:"error,omitempty"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
}

// ============================================================================
// WebSocket responses
// ============================================================================

// WSMessage represents a WebSocket message.
type WSMessage struct {
	Type      string `json:"type"`
	Payload   any    `json:"payload,omitempty"`
	Timestamp int64  `json:"timestamp"`
}

// WSError represents a WebSocket error message.
type WSError struct {
	Type    string `json:"type"` // always "error"
	Code    string `json:"code"`
	Message string `json:"message"`
}

// NewWSMessage creates a new WebSocket message.
func NewWSMessage(msgType string, payload any) *WSMessage {
	return &WSMessage{
		Type:      msgType,
		Payload:   payload,
		Timestamp: time.Now().UnixMilli(),
	}
}

// NewWSError creates a new WebSocket error message.
func NewWSError(code, message string) *WSError {
	return &WSError{
		Type:    "error",
		Code:    code,
		Message: message,
	}
}
