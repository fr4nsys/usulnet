// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// BaseHandler provides common functionality for all handlers.
type BaseHandler struct {
	logger *logger.Logger
}

// NewBaseHandler creates a new base handler.
func NewBaseHandler(log *logger.Logger) BaseHandler {
	if log == nil {
		log = logger.Nop()
	}
	return BaseHandler{logger: log}
}

// ============================================================================
// Response helpers
// ============================================================================

// JSON writes a JSON response with the given status code.
func (h *BaseHandler) JSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			h.logger.Error("failed to encode JSON response", "error", err)
		}
	}
}

// NoContent writes a 204 No Content response.
func (h *BaseHandler) NoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// Created writes a 201 Created response with the given data.
func (h *BaseHandler) Created(w http.ResponseWriter, data any) {
	h.JSON(w, http.StatusCreated, data)
}

// OK writes a 200 OK response with the given data.
func (h *BaseHandler) OK(w http.ResponseWriter, data any) {
	h.JSON(w, http.StatusOK, data)
}

// ============================================================================
// Error helpers
// ============================================================================

// Error writes an API error response.
func (h *BaseHandler) Error(w http.ResponseWriter, err *apierrors.APIError) {
	apierrors.WriteError(w, err)
}

// InternalError writes a 500 Internal Server Error.
func (h *BaseHandler) InternalError(w http.ResponseWriter, err error) {
	h.logger.Error("internal error", "error", err)
	apierrors.WriteError(w, apierrors.Internal(""))
}

// BadRequest writes a 400 Bad Request error.
func (h *BaseHandler) BadRequest(w http.ResponseWriter, message string) {
	apierrors.WriteError(w, apierrors.InvalidInput(message))
}

// NotFound writes a 404 Not Found error.
func (h *BaseHandler) NotFound(w http.ResponseWriter, resource string) {
	apierrors.WriteError(w, apierrors.NotFound(resource))
}

// Forbidden writes a 403 Forbidden error.
func (h *BaseHandler) Forbidden(w http.ResponseWriter, message string) {
	apierrors.WriteError(w, apierrors.Forbidden(message))
}

// HandleError converts a service error to an API error response.
func (h *BaseHandler) HandleError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}

	// Check if it's already an API error
	if apiErr, ok := err.(*apierrors.APIError); ok {
		apierrors.WriteError(w, apiErr)
		return
	}

	// Convert from app error
	apiErr := apierrors.FromError(err)
	apierrors.WriteError(w, apiErr)
}

// ============================================================================
// Request parsing helpers
// ============================================================================

// ParseJSON decodes the request body as JSON into the given value.
func (h *BaseHandler) ParseJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return apierrors.InvalidInput("request body is empty")
	}

	defer r.Body.Close()

	// Limit request body size (10MB)
	body := io.LimitReader(r.Body, 10*1024*1024)

	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(v); err != nil {
		if err == io.EOF {
			return apierrors.InvalidInput("request body is empty")
		}
		return apierrors.InvalidInput("invalid JSON: " + err.Error())
	}

	return nil
}

// ============================================================================
// URL parameter helpers
// ============================================================================

// URLParam returns a URL parameter value.
func (h *BaseHandler) URLParam(r *http.Request, key string) string {
	return chi.URLParam(r, key)
}

// URLParamUUID returns a URL parameter as UUID.
func (h *BaseHandler) URLParamUUID(r *http.Request, key string) (uuid.UUID, error) {
	param := chi.URLParam(r, key)
	if param == "" {
		return uuid.Nil, apierrors.InvalidInput(key + " is required")
	}

	id, err := uuid.Parse(param)
	if err != nil {
		return uuid.Nil, apierrors.InvalidInput("invalid " + key + " format")
	}

	return id, nil
}

// URLParamInt returns a URL parameter as int.
func (h *BaseHandler) URLParamInt(r *http.Request, key string, defaultValue int) int {
	param := chi.URLParam(r, key)
	if param == "" {
		return defaultValue
	}

	val, err := strconv.Atoi(param)
	if err != nil {
		return defaultValue
	}

	return val
}

// ============================================================================
// Query parameter helpers
// ============================================================================

// QueryParam returns a query parameter value.
func (h *BaseHandler) QueryParam(r *http.Request, key string) string {
	return r.URL.Query().Get(key)
}

// QueryParamInt returns a query parameter as int.
func (h *BaseHandler) QueryParamInt(r *http.Request, key string, defaultValue int) int {
	param := r.URL.Query().Get(key)
	if param == "" {
		return defaultValue
	}

	val, err := strconv.Atoi(param)
	if err != nil {
		return defaultValue
	}

	return val
}

// QueryParamInt64 returns a query parameter as int64.
func (h *BaseHandler) QueryParamInt64(r *http.Request, key string, defaultValue int64) int64 {
	param := r.URL.Query().Get(key)
	if param == "" {
		return defaultValue
	}

	val, err := strconv.ParseInt(param, 10, 64)
	if err != nil {
		return defaultValue
	}

	return val
}

// QueryParamBool returns a query parameter as bool.
func (h *BaseHandler) QueryParamBool(r *http.Request, key string, defaultValue bool) bool {
	param := r.URL.Query().Get(key)
	if param == "" {
		return defaultValue
	}

	val, err := strconv.ParseBool(param)
	if err != nil {
		return defaultValue
	}

	return val
}

// QueryParamUUID returns a query parameter as UUID, or nil if not present.
func (h *BaseHandler) QueryParamUUID(r *http.Request, key string) *uuid.UUID {
	param := r.URL.Query().Get(key)
	if param == "" {
		return nil
	}

	id, err := uuid.Parse(param)
	if err != nil {
		return nil
	}

	return &id
}

// ============================================================================
// Auth helpers
// ============================================================================

// GetClaims returns the user claims from the request context.
func (h *BaseHandler) GetClaims(r *http.Request) *middleware.UserClaims {
	return middleware.GetUserFromRequest(r)
}

// GetUserID returns the user ID from the request context.
func (h *BaseHandler) GetUserID(r *http.Request) (uuid.UUID, error) {
	claims := middleware.GetUserFromRequest(r)
	if claims == nil {
		return uuid.Nil, apierrors.Unauthorized("")
	}

	id, err := uuid.Parse(claims.UserID)
	if err != nil {
		return uuid.Nil, apierrors.Unauthorized("invalid user ID in token")
	}

	return id, nil
}

// GetUserRole returns the user role from the request context.
func (h *BaseHandler) GetUserRole(r *http.Request) string {
	claims := middleware.GetUserFromRequest(r)
	if claims == nil {
		return ""
	}
	return claims.Role
}

// RequireAdmin checks if the user is an admin.
func (h *BaseHandler) RequireAdmin(r *http.Request) error {
	role := h.GetUserRole(r)
	if role != "admin" {
		return apierrors.Forbidden("admin access required")
	}
	return nil
}

// ============================================================================
// Host ID helpers
// ============================================================================

// GetHostID returns the host ID from URL or query parameter.
func (h *BaseHandler) GetHostID(r *http.Request) (uuid.UUID, error) {
	// Try URL parameter first
	hostIDStr := chi.URLParam(r, "hostID")
	if hostIDStr == "" {
		hostIDStr = chi.URLParam(r, "host_id")
	}

	// Fallback to query parameter
	if hostIDStr == "" {
		hostIDStr = r.URL.Query().Get("host_id")
	}

	if hostIDStr == "" {
		return uuid.Nil, apierrors.MissingField("host_id")
	}

	hostID, err := uuid.Parse(hostIDStr)
	if err != nil {
		return uuid.Nil, apierrors.InvalidInput("invalid host_id format")
	}

	return hostID, nil
}

// ============================================================================
// Pagination helpers
// ============================================================================

// PaginationParams contains pagination parameters.
type PaginationParams struct {
	Page    int
	PerPage int
	Offset  int
}

// GetPagination extracts pagination parameters from the request.
func (h *BaseHandler) GetPagination(r *http.Request) PaginationParams {
	page := h.QueryParamInt(r, "page", 1)
	perPage := h.QueryParamInt(r, "per_page", 20)

	// Clamp values
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 20
	}
	if perPage > 100 {
		perPage = 100
	}

	return PaginationParams{
		Page:    page,
		PerPage: perPage,
		Offset:  (page - 1) * perPage,
	}
}

// PaginatedResponse wraps data with pagination metadata.
type PaginatedResponse struct {
	Data       any   `json:"data"`
	Total      int64 `json:"total"`
	Page       int   `json:"page"`
	PerPage    int   `json:"per_page"`
	TotalPages int   `json:"total_pages"`
}

// NewPaginatedResponse creates a paginated response.
func NewPaginatedResponse(data any, total int64, params PaginationParams) PaginatedResponse {
	totalPages := int(total) / params.PerPage
	if int(total)%params.PerPage != 0 {
		totalPages++
	}

	return PaginatedResponse{
		Data:       data,
		Total:      total,
		Page:       params.Page,
		PerPage:    params.PerPage,
		TotalPages: totalPages,
	}
}

// ============================================================================
// Sorting helpers
// ============================================================================

// SortParams contains sorting parameters.
type SortParams struct {
	Field string
	Order string // "asc" or "desc"
}

// GetSort extracts sorting parameters from the request.
func (h *BaseHandler) GetSort(r *http.Request, defaultField string) SortParams {
	field := h.QueryParam(r, "sort")
	if field == "" {
		field = defaultField
	}

	order := h.QueryParam(r, "order")
	if order == "" {
		order = "asc"
	}

	// Validate order
	order = strings.ToLower(order)
	if order != "asc" && order != "desc" {
		order = "asc"
	}

	return SortParams{
		Field: field,
		Order: order,
	}
}

// ============================================================================
// Logger access
// ============================================================================

// Logger returns the handler's logger.
func (h *BaseHandler) Logger() *logger.Logger {
	return h.logger
}
