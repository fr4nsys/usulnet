// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/services/config"
)

// ConfigHandler handles configuration management endpoints.
type ConfigHandler struct {
	BaseHandler
	configService *config.Service
	syncService   *config.SyncService
}

// NewConfigHandler creates a new config handler.
func NewConfigHandler(configService *config.Service, syncService *config.SyncService, log *logger.Logger) *ConfigHandler {
	return &ConfigHandler{
		BaseHandler:   NewBaseHandler(log),
		configService: configService,
		syncService:   syncService,
	}
}

// Routes returns the config routes.
func (h *ConfigHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Variables
	r.Route("/variables", func(r chi.Router) {
		// Read-only (viewer+)
		r.Get("/", h.ListVariables)

		r.Route("/{variableID}", func(r chi.Router) {
			r.Get("/", h.GetVariable)
			r.Get("/usage", h.GetVariableUsage)
			r.Get("/history", h.GetVariableHistory)

			// Operator+ for mutations
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireOperator)
				r.Put("/", h.UpdateVariable)
				r.Delete("/", h.DeleteVariable)
				r.Post("/rollback", h.RollbackVariable)
			})
		})

		// Operator+ for creation
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireOperator)
			r.Post("/", h.CreateVariable)
		})
	})

	// Templates
	r.Route("/templates", func(r chi.Router) {
		// Read-only (viewer+)
		r.Get("/", h.ListTemplates)

		r.Route("/{templateID}", func(r chi.Router) {
			r.Get("/", h.GetTemplate)

			// Operator+ for mutations
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireOperator)
				r.Put("/", h.UpdateTemplate)
				r.Delete("/", h.DeleteTemplate)
				r.Post("/default", h.SetDefaultTemplate)
			})
		})

		// Operator+ for creation
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireOperator)
			r.Post("/", h.CreateTemplate)
		})
	})

	// Sync - Configuration synchronization to containers
	r.Route("/sync", func(r chi.Router) {
		// Read-only (viewer+)
		r.Get("/outdated", h.ListOutdatedSyncs)
		r.Get("/stats", h.GetSyncStats)
		r.Get("/{hostID}/{containerID}", h.GetSyncStatus)

		// Operator+ for mutations
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireOperator)
			r.Post("/", h.SyncConfig)
			r.Post("/preview", h.PreviewSync)
			r.Post("/bulk", h.BulkSyncConfig)
			r.Delete("/{hostID}/{containerID}", h.RemoveSync)
		})
	})

	// Admin-only: Export/Import
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		r.Post("/export", h.ExportConfig)
		r.Post("/import", h.ImportConfig)
	})

	// Audit (viewer+)
	r.Get("/audit", h.GetAuditLog)

	return r
}

// ============================================================================
// Request/Response types
// ============================================================================

// CreateVariableRequest represents a variable creation request.
type CreateVariableRequest struct {
	Name         string  `json:"name"`
	Value        string  `json:"value"`
	Type         string  `json:"type"`  // plain, secret, computed
	Scope        string  `json:"scope"` // global, template, container, stack
	ScopeID      *string `json:"scope_id,omitempty"`
	Description  *string `json:"description,omitempty"`
	IsRequired   bool    `json:"is_required,omitempty"`
	DefaultValue *string `json:"default_value,omitempty"`
}

// UpdateVariableRequest represents a variable update request.
type UpdateVariableRequest struct {
	Value        *string `json:"value,omitempty"`
	Description  *string `json:"description,omitempty"`
	IsRequired   *bool   `json:"is_required,omitempty"`
	DefaultValue *string `json:"default_value,omitempty"`
}

// RollbackVariableRequest represents a variable rollback request.
type RollbackVariableRequest struct {
	Version int `json:"version"`
}

// CreateTemplateRequest represents a template creation request.
type CreateTemplateRequest struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	IsDefault   bool    `json:"is_default,omitempty"`
	CopyFrom    *string `json:"copy_from,omitempty"`
}

// UpdateTemplateRequest represents a template update request.
type UpdateTemplateRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	IsDefault   *bool   `json:"is_default,omitempty"`
}

// ExportConfigRequest represents a config export request.
type ExportConfigRequest struct {
	Password *string `json:"password,omitempty"`
}

// ImportConfigRequest represents a config import request.
type ImportConfigRequest struct {
	Data      string  `json:"data"`
	Password  *string `json:"password,omitempty"`
	Overwrite bool    `json:"overwrite,omitempty"`
}

// VariableResponse represents a variable in API responses.
type VariableResponse struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Value        string  `json:"value"`
	Type         string  `json:"type"`
	Scope        string  `json:"scope"`
	ScopeID      *string `json:"scope_id,omitempty"`
	Description  *string `json:"description,omitempty"`
	IsRequired   bool    `json:"is_required"`
	DefaultValue *string `json:"default_value,omitempty"`
	Version      int     `json:"version"`
	CreatedAt    string  `json:"created_at"`
	UpdatedAt    string  `json:"updated_at"`
	CreatedBy    *string `json:"created_by,omitempty"`
	UpdatedBy    *string `json:"updated_by,omitempty"`
}

// VariableUsageResponse represents variable usage info.
type VariableUsageResponse struct {
	VariableID   string             `json:"variable_id"`
	VariableName string             `json:"variable_name"`
	UsedIn       []VariableUsageRef `json:"used_in"`
}

// VariableUsageRef represents a reference to where a variable is used.
type VariableUsageRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

// VariableHistoryResponse represents a variable history entry.
type VariableHistoryResponse struct {
	ID         int64   `json:"id"`
	VariableID string  `json:"variable_id"`
	Version    int     `json:"version"`
	Value      string  `json:"value"`
	UpdatedBy  *string `json:"updated_by,omitempty"`
	UpdatedAt  string  `json:"updated_at"`
}

// TemplateResponse represents a template in API responses.
type TemplateResponse struct {
	ID            string             `json:"id"`
	Name          string             `json:"name"`
	Description   *string            `json:"description,omitempty"`
	Variables     []VariableResponse `json:"variables,omitempty"`
	VariableCount int                `json:"variable_count"`
	IsDefault     bool               `json:"is_default"`
	CreatedAt     string             `json:"created_at"`
	UpdatedAt     string             `json:"updated_at"`
	CreatedBy     *string            `json:"created_by,omitempty"`
	UpdatedBy     *string            `json:"updated_by,omitempty"`
}

// ConfigExportResponse represents an exported config.
type ConfigExportResponse struct {
	Version   string `json:"version"`
	Data      string `json:"data"`
	CreatedAt string `json:"created_at"`
}

// AuditLogResponse represents an audit log entry.
type AuditLogResponse struct {
	ID         int64   `json:"id"`
	Action     string  `json:"action"`
	EntityType string  `json:"entity_type"`
	EntityID   string  `json:"entity_id"`
	EntityName string  `json:"entity_name,omitempty"`
	OldValue   *string `json:"old_value,omitempty"`
	NewValue   *string `json:"new_value,omitempty"`
	UserID     *string `json:"user_id,omitempty"`
	CreatedAt  string  `json:"created_at"`
}

// ============================================================================
// Variable handlers
// ============================================================================

// ListVariables returns all variables.
// GET /api/v1/config/variables
func (h *ConfigHandler) ListVariables(w http.ResponseWriter, r *http.Request) {
	pagination := h.GetPagination(r)

	opts := models.VariableListOptions{
		Limit:  pagination.PerPage,
		Offset: pagination.Offset,
	}

	// Optional filters
	if scope := h.QueryParam(r, "scope"); scope != "" {
		varScope := models.VariableScope(scope)
		opts.Scope = &varScope
	}
	if scopeID := h.QueryParam(r, "scope_id"); scopeID != "" {
		opts.ScopeID = &scopeID
	}
	if search := h.QueryParam(r, "search"); search != "" {
		opts.Search = &search
	}
	if varType := h.QueryParam(r, "type"); varType != "" {
		vt := models.VariableType(varType)
		opts.Type = &vt
	}

	variables, total, err := h.configService.ListVariables(r.Context(), opts)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]VariableResponse, len(variables))
	for i, v := range variables {
		resp[i] = toVariableResponse(v)
	}

	h.OK(w, NewPaginatedResponse(resp, int64(total), pagination))
}

// CreateVariable creates a new variable.
// POST /api/v1/config/variables
func (h *ConfigHandler) CreateVariable(w http.ResponseWriter, r *http.Request) {
	userID, _ := h.GetUserID(r)

	var req CreateVariableRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Name == "" {
		h.BadRequest(w, "name is required")
		return
	}
	if req.Value == "" {
		h.BadRequest(w, "value is required")
		return
	}
	if req.Type == "" {
		h.BadRequest(w, "type is required")
		return
	}
	if req.Scope == "" {
		h.BadRequest(w, "scope is required")
		return
	}

	input := models.CreateVariableInput{
		Name:         req.Name,
		Value:        req.Value,
		Type:         models.VariableType(req.Type),
		Scope:        models.VariableScope(req.Scope),
		ScopeID:      req.ScopeID,
		Description:  req.Description,
		IsRequired:   req.IsRequired,
		DefaultValue: req.DefaultValue,
	}

	variable, err := h.configService.CreateVariable(r.Context(), input, &userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, toVariableResponse(variable))
}

// GetVariable returns a specific variable.
// GET /api/v1/config/variables/{variableID}
func (h *ConfigHandler) GetVariable(w http.ResponseWriter, r *http.Request) {
	variableID, err := h.URLParamUUID(r, "variableID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	decrypt := h.QueryParamBool(r, "decrypt", false)

	var variable *models.ConfigVariable
	if decrypt {
		variable, err = h.configService.GetVariableDecrypted(r.Context(), variableID)
	} else {
		variable, err = h.configService.GetVariable(r.Context(), variableID)
	}

	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toVariableResponse(variable))
}

// UpdateVariable updates a variable.
// PUT /api/v1/config/variables/{variableID}
func (h *ConfigHandler) UpdateVariable(w http.ResponseWriter, r *http.Request) {
	variableID, err := h.URLParamUUID(r, "variableID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	userID, _ := h.GetUserID(r)

	var req UpdateVariableRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	input := models.UpdateVariableInput{
		Value:        req.Value,
		Description:  req.Description,
		IsRequired:   req.IsRequired,
		DefaultValue: req.DefaultValue,
	}

	variable, err := h.configService.UpdateVariable(r.Context(), variableID, input, &userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toVariableResponse(variable))
}

// DeleteVariable deletes a variable.
// DELETE /api/v1/config/variables/{variableID}
func (h *ConfigHandler) DeleteVariable(w http.ResponseWriter, r *http.Request) {
	variableID, err := h.URLParamUUID(r, "variableID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	userID, _ := h.GetUserID(r)

	if err := h.configService.DeleteVariable(r.Context(), variableID, &userID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// GetVariableUsage returns where a variable is used.
// GET /api/v1/config/variables/{variableID}/usage
func (h *ConfigHandler) GetVariableUsage(w http.ResponseWriter, r *http.Request) {
	variableID, err := h.URLParamUUID(r, "variableID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	usage, err := h.configService.GetVariableUsage(r.Context(), variableID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	refs := make([]VariableUsageRef, len(usage.UsedIn))
	for i, u := range usage.UsedIn {
		refs[i] = VariableUsageRef{
			Type: u.Type,
			ID:   u.ID,
			Name: u.Name,
		}
	}

	h.OK(w, VariableUsageResponse{
		VariableID:   usage.VariableID.String(),
		VariableName: usage.VariableName,
		UsedIn:       refs,
	})
}

// GetVariableHistory returns the history of a variable.
// GET /api/v1/config/variables/{variableID}/history
func (h *ConfigHandler) GetVariableHistory(w http.ResponseWriter, r *http.Request) {
	variableID, err := h.URLParamUUID(r, "variableID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	limit := h.QueryParamInt(r, "limit", 20)

	history, err := h.configService.GetVariableHistory(r.Context(), variableID, limit)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]VariableHistoryResponse, len(history))
	for i, h := range history {
		entry := VariableHistoryResponse{
			ID:         h.ID,
			VariableID: h.VariableID.String(),
			Version:    h.Version,
			Value:      h.Value,
			UpdatedAt:  h.UpdatedAt.Format(time.RFC3339),
		}
		if h.UpdatedBy != nil {
			s := h.UpdatedBy.String()
			entry.UpdatedBy = &s
		}
		resp[i] = entry
	}

	h.OK(w, resp)
}

// RollbackVariable rolls back a variable to a previous version.
// POST /api/v1/config/variables/{variableID}/rollback
func (h *ConfigHandler) RollbackVariable(w http.ResponseWriter, r *http.Request) {
	variableID, err := h.URLParamUUID(r, "variableID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	userID, _ := h.GetUserID(r)

	var req RollbackVariableRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Version < 1 {
		h.BadRequest(w, "version must be >= 1")
		return
	}

	variable, err := h.configService.RollbackVariable(r.Context(), variableID, req.Version, &userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toVariableResponse(variable))
}

// ============================================================================
// Template handlers
// ============================================================================

// ListTemplates returns all templates.
// GET /api/v1/config/templates
func (h *ConfigHandler) ListTemplates(w http.ResponseWriter, r *http.Request) {
	pagination := h.GetPagination(r)

	var search *string
	if s := h.QueryParam(r, "search"); s != "" {
		search = &s
	}

	templates, total, err := h.configService.ListTemplates(r.Context(), search, pagination.PerPage, pagination.Offset)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]TemplateResponse, len(templates))
	for i, t := range templates {
		resp[i] = toTemplateResponse(t)
	}

	h.OK(w, NewPaginatedResponse(resp, int64(total), pagination))
}

// CreateTemplate creates a new template.
// POST /api/v1/config/templates
func (h *ConfigHandler) CreateTemplate(w http.ResponseWriter, r *http.Request) {
	userID, _ := h.GetUserID(r)

	var req CreateTemplateRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Name == "" {
		h.BadRequest(w, "name is required")
		return
	}

	input := models.CreateTemplateInput{
		Name:        req.Name,
		Description: req.Description,
		IsDefault:   req.IsDefault,
		CopyFrom:    req.CopyFrom,
	}

	template, err := h.configService.CreateTemplate(r.Context(), input, &userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, toTemplateResponse(template))
}

// GetTemplate returns a specific template.
// GET /api/v1/config/templates/{templateID}
func (h *ConfigHandler) GetTemplate(w http.ResponseWriter, r *http.Request) {
	templateID, err := h.URLParamUUID(r, "templateID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	template, err := h.configService.GetTemplate(r.Context(), templateID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toTemplateResponse(template))
}

// UpdateTemplate updates a template.
// PUT /api/v1/config/templates/{templateID}
func (h *ConfigHandler) UpdateTemplate(w http.ResponseWriter, r *http.Request) {
	templateID, err := h.URLParamUUID(r, "templateID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	userID, _ := h.GetUserID(r)

	var req UpdateTemplateRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	input := models.UpdateTemplateInput{
		Name:        req.Name,
		Description: req.Description,
		IsDefault:   req.IsDefault,
	}

	template, err := h.configService.UpdateTemplate(r.Context(), templateID, input, &userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toTemplateResponse(template))
}

// DeleteTemplate deletes a template.
// DELETE /api/v1/config/templates/{templateID}
func (h *ConfigHandler) DeleteTemplate(w http.ResponseWriter, r *http.Request) {
	templateID, err := h.URLParamUUID(r, "templateID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	userID, _ := h.GetUserID(r)

	if err := h.configService.DeleteTemplate(r.Context(), templateID, &userID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// SetDefaultTemplate sets a template as default.
// POST /api/v1/config/templates/{templateID}/default
func (h *ConfigHandler) SetDefaultTemplate(w http.ResponseWriter, r *http.Request) {
	templateID, err := h.URLParamUUID(r, "templateID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	userID, _ := h.GetUserID(r)

	if err := h.configService.SetDefaultTemplate(r.Context(), templateID, &userID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// ============================================================================
// Export/Import handlers
// ============================================================================

// ExportConfig exports the configuration.
// POST /api/v1/config/export
func (h *ConfigHandler) ExportConfig(w http.ResponseWriter, r *http.Request) {
	var req ExportConfigRequest
	h.ParseJSON(r, &req) // Optional password

	export, err := h.configService.ExportConfig(r.Context(), req.Password)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	// Serialize export to JSON string for transport
	exportData, err := json.Marshal(export)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, ConfigExportResponse{
		Version:   export.Version,
		Data:      string(exportData),
		CreatedAt: export.ExportedAt.Format(time.RFC3339),
	})
}

// ImportConfig imports a configuration.
// POST /api/v1/config/import
func (h *ConfigHandler) ImportConfig(w http.ResponseWriter, r *http.Request) {
	userID, _ := h.GetUserID(r)

	var req ImportConfigRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Data == "" {
		h.BadRequest(w, "data is required")
		return
	}

	input := models.ConfigImportInput{
		Data:      req.Data,
		Overwrite: req.Overwrite,
	}
	if req.Password != nil {
		input.Password = *req.Password
	}

	if err := h.configService.ImportConfig(r.Context(), input, &userID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// ============================================================================
// Audit handlers
// ============================================================================

// GetAuditLog returns the audit log.
// GET /api/v1/config/audit
func (h *ConfigHandler) GetAuditLog(w http.ResponseWriter, r *http.Request) {
	pagination := h.GetPagination(r)

	opts := postgres.AuditListOptions{
		Limit:  pagination.PerPage,
		Offset: pagination.Offset,
	}

	// Optional filters
	if action := h.QueryParam(r, "action"); action != "" {
		opts.Action = &action
	}
	if entityType := h.QueryParam(r, "entity_type"); entityType != "" {
		opts.EntityType = &entityType
	}
	if entityID := h.QueryParam(r, "entity_id"); entityID != "" {
		opts.EntityID = &entityID
	}

	logs, total, err := h.configService.GetAuditLog(r.Context(), opts)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]AuditLogResponse, len(logs))
	for i, l := range logs {
		entry := AuditLogResponse{
			ID:         l.ID,
			Action:     l.Action,
			EntityType: l.EntityType,
			EntityID:   l.EntityID,
			EntityName: l.EntityName,
			OldValue:   l.OldValue,
			NewValue:   l.NewValue,
			CreatedAt:  l.CreatedAt.Format(time.RFC3339),
		}
		if l.UserID != nil {
			s := l.UserID.String()
			entry.UserID = &s
		}
		resp[i] = entry
	}

	h.OK(w, NewPaginatedResponse(resp, int64(total), pagination))
}

// ============================================================================
// Helpers
// ============================================================================

func toVariableResponse(v *models.ConfigVariable) VariableResponse {
	resp := VariableResponse{
		ID:           v.ID.String(),
		Name:         v.Name,
		Value:        v.Value,
		Type:         string(v.Type),
		Scope:        string(v.Scope),
		ScopeID:      v.ScopeID,
		Description:  v.Description,
		IsRequired:   v.IsRequired,
		DefaultValue: v.DefaultValue,
		Version:      v.Version,
		CreatedAt:    v.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    v.UpdatedAt.Format(time.RFC3339),
	}

	if v.CreatedBy != nil {
		s := v.CreatedBy.String()
		resp.CreatedBy = &s
	}
	if v.UpdatedBy != nil {
		s := v.UpdatedBy.String()
		resp.UpdatedBy = &s
	}

	return resp
}

func toTemplateResponse(t *models.ConfigTemplate) TemplateResponse {
	resp := TemplateResponse{
		ID:            t.ID.String(),
		Name:          t.Name,
		Description:   t.Description,
		VariableCount: t.VariableCount,
		IsDefault:     t.IsDefault,
		CreatedAt:     t.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     t.UpdatedAt.Format(time.RFC3339),
	}

	if t.CreatedBy != nil {
		s := t.CreatedBy.String()
		resp.CreatedBy = &s
	}
	if t.UpdatedBy != nil {
		s := t.UpdatedBy.String()
		resp.UpdatedBy = &s
	}

	// Variables
	if len(t.Variables) > 0 {
		resp.Variables = make([]VariableResponse, len(t.Variables))
		for i, v := range t.Variables {
			resp.Variables[i] = toVariableResponse(&v)
		}
	}

	return resp
}

// ============================================================================
// Sync Request/Response types
// ============================================================================

// SyncConfigRequest represents a sync configuration request.
type SyncConfigRequest struct {
	HostID        string            `json:"host_id"`
	ContainerID   string            `json:"container_id"`
	ContainerName string            `json:"container_name"`
	TemplateID    *string           `json:"template_id,omitempty"`
	TemplateName  *string           `json:"template_name,omitempty"`
	Overrides     map[string]string `json:"overrides,omitempty"`
	Force         bool              `json:"force,omitempty"`
}

// BulkSyncRequest represents a bulk sync request.
type BulkSyncRequest struct {
	HostID       string            `json:"host_id"`
	ContainerIDs []string          `json:"container_ids"`
	TemplateID   *string           `json:"template_id,omitempty"`
	Variables    map[string]string `json:"variables,omitempty"`
	Force        bool              `json:"force,omitempty"`
}

// SyncResponse represents a sync operation result.
type SyncResponse struct {
	Success         bool                   `json:"success"`
	ContainerID     string                 `json:"container_id"`
	ContainerName   string                 `json:"container_name"`
	TemplateName    *string                `json:"template_name,omitempty"`
	VariablesHash   string                 `json:"variables_hash"`
	RequiresRestart bool                   `json:"requires_restart"`
	Diff            *ConfigDiffResponse    `json:"diff,omitempty"`
	Variables       []VariableResponse     `json:"variables,omitempty"`
	ErrorMessage    *string                `json:"error_message,omitempty"`
}

// ConfigDiffResponse represents configuration differences.
type ConfigDiffResponse struct {
	ContainerID     string              `json:"container_id"`
	ContainerName   string              `json:"container_name"`
	Added           []DiffEntryResponse `json:"added"`
	Modified        []DiffEntryResponse `json:"modified"`
	Removed         []DiffEntryResponse `json:"removed"`
	RequiresRestart bool                `json:"requires_restart"`
}

// DiffEntryResponse represents a single diff entry.
type DiffEntryResponse struct {
	Name     string `json:"name"`
	OldValue string `json:"old_value,omitempty"`
	NewValue string `json:"new_value,omitempty"`
	IsSecret bool   `json:"is_secret"`
}

// SyncStatusResponse represents sync status for a container.
type SyncStatusResponse struct {
	ID            string  `json:"id"`
	HostID        string  `json:"host_id"`
	ContainerID   string  `json:"container_id"`
	ContainerName string  `json:"container_name"`
	TemplateID    *string `json:"template_id,omitempty"`
	TemplateName  *string `json:"template_name,omitempty"`
	Status        string  `json:"status"`
	VariablesHash string  `json:"variables_hash"`
	LastSyncedAt  *string `json:"last_synced_at,omitempty"`
	ErrorMessage  *string `json:"error_message,omitempty"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

// SyncStatsResponse represents sync statistics.
type SyncStatsResponse struct {
	Total    int `json:"total"`
	Synced   int `json:"synced"`
	Pending  int `json:"pending"`
	Failed   int `json:"failed"`
	Outdated int `json:"outdated"`
}

// ============================================================================
// Sync handlers
// ============================================================================

// SyncConfig synchronizes configuration to a container.
// POST /api/v1/config/sync
func (h *ConfigHandler) SyncConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, _ := h.GetUserID(r)

	var req SyncConfigRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.HostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}
	if req.ContainerID == "" {
		h.BadRequest(w, "container_id is required")
		return
	}

	hostID, err := h.parseUUID(req.HostID)
	if err != nil {
		h.BadRequest(w, "invalid host_id")
		return
	}

	var templateID *uuid.UUID
	if req.TemplateID != nil {
		tid, err := h.parseUUID(*req.TemplateID)
		if err != nil {
			h.BadRequest(w, "invalid template_id")
			return
		}
		templateID = &tid
	}

	opts := config.SyncOptions{
		HostID:        hostID,
		ContainerID:   req.ContainerID,
		ContainerName: req.ContainerName,
		TemplateID:    templateID,
		TemplateName:  req.TemplateName,
		Overrides:     req.Overrides,
		Force:         req.Force,
	}

	result, err := h.syncService.Sync(ctx, opts, &userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toSyncResponse(result))
}

// PreviewSync previews what would change without applying.
// POST /api/v1/config/sync/preview
func (h *ConfigHandler) PreviewSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req SyncConfigRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.HostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}
	if req.ContainerID == "" {
		h.BadRequest(w, "container_id is required")
		return
	}

	hostID, err := h.parseUUID(req.HostID)
	if err != nil {
		h.BadRequest(w, "invalid host_id")
		return
	}

	var templateID *uuid.UUID
	if req.TemplateID != nil {
		tid, err := h.parseUUID(*req.TemplateID)
		if err != nil {
			h.BadRequest(w, "invalid template_id")
			return
		}
		templateID = &tid
	}

	opts := config.SyncOptions{
		HostID:        hostID,
		ContainerID:   req.ContainerID,
		ContainerName: req.ContainerName,
		TemplateID:    templateID,
		TemplateName:  req.TemplateName,
		Overrides:     req.Overrides,
		DryRun:        true,
	}

	result, err := h.syncService.PreviewSync(ctx, opts)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toSyncResponse(result))
}

// BulkSyncConfig synchronizes configuration to multiple containers.
// POST /api/v1/config/sync/bulk
func (h *ConfigHandler) BulkSyncConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, _ := h.GetUserID(r)

	var req BulkSyncRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.HostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}
	if len(req.ContainerIDs) == 0 {
		h.BadRequest(w, "container_ids is required")
		return
	}

	hostID, err := h.parseUUID(req.HostID)
	if err != nil {
		h.BadRequest(w, "invalid host_id")
		return
	}

	var templateID *uuid.UUID
	if req.TemplateID != nil {
		tid, err := h.parseUUID(*req.TemplateID)
		if err != nil {
			h.BadRequest(w, "invalid template_id")
			return
		}
		templateID = &tid
	}

	input := models.SyncBulkInput{
		ContainerIDs: req.ContainerIDs,
		TemplateID:   templateID,
		Variables:    req.Variables,
		Force:        req.Force,
	}

	results, err := h.syncService.BulkSync(ctx, input, hostID, &userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]SyncResponse, len(results))
	for i, r := range results {
		resp[i] = toSyncResponse(r)
	}

	h.OK(w, resp)
}

// ListOutdatedSyncs returns containers with outdated configuration.
// GET /api/v1/config/sync/outdated
func (h *ConfigHandler) ListOutdatedSyncs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var hostID *uuid.UUID
	if hid := h.QueryParam(r, "host_id"); hid != "" {
		parsed, err := h.parseUUID(hid)
		if err != nil {
			h.BadRequest(w, "invalid host_id")
			return
		}
		hostID = &parsed
	}

	syncs, err := h.syncService.ListOutdated(ctx, hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]SyncStatusResponse, len(syncs))
	for i, s := range syncs {
		resp[i] = toSyncStatusResponse(s)
	}

	h.OK(w, resp)
}

// GetSyncStats returns sync statistics.
// GET /api/v1/config/sync/stats
func (h *ConfigHandler) GetSyncStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var hostID *uuid.UUID
	if hid := h.QueryParam(r, "host_id"); hid != "" {
		parsed, err := h.parseUUID(hid)
		if err != nil {
			h.BadRequest(w, "invalid host_id")
			return
		}
		hostID = &parsed
	}

	stats, err := h.syncService.GetSyncStats(ctx, hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, SyncStatsResponse{
		Total:    stats["total"],
		Synced:   stats["synced"],
		Pending:  stats["pending"],
		Failed:   stats["failed"],
		Outdated: stats["outdated"],
	})
}

// GetSyncStatus returns sync status for a specific container.
// GET /api/v1/config/sync/{hostID}/{containerID}
func (h *ConfigHandler) GetSyncStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	containerID := chi.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "container_id is required")
		return
	}

	sync, err := h.syncService.GetSyncStatus(ctx, hostID, containerID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if sync == nil {
		h.NotFound(w, "sync status")
		return
	}

	h.OK(w, toSyncStatusResponse(sync))
}

// RemoveSync removes sync tracking for a container.
// DELETE /api/v1/config/sync/{hostID}/{containerID}
func (h *ConfigHandler) RemoveSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	containerID := chi.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "container_id is required")
		return
	}

	if err := h.syncService.RemoveSync(ctx, hostID, containerID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// ============================================================================
// Sync Helpers
// ============================================================================

func (h *ConfigHandler) parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

func toSyncResponse(r *config.SyncResult) SyncResponse {
	resp := SyncResponse{
		Success:         r.Success,
		ContainerID:     r.ContainerID,
		ContainerName:   r.ContainerName,
		TemplateName:    r.TemplateName,
		VariablesHash:   r.VariablesHash,
		RequiresRestart: r.RequiresRestart,
		ErrorMessage:    r.ErrorMessage,
	}

	if r.Diff != nil {
		resp.Diff = &ConfigDiffResponse{
			ContainerID:     r.Diff.ContainerID,
			ContainerName:   r.Diff.ContainerName,
			RequiresRestart: r.Diff.RequiresRestart,
			Added:           make([]DiffEntryResponse, len(r.Diff.Added)),
			Modified:        make([]DiffEntryResponse, len(r.Diff.Modified)),
			Removed:         make([]DiffEntryResponse, len(r.Diff.Removed)),
		}
		for i, e := range r.Diff.Added {
			resp.Diff.Added[i] = DiffEntryResponse{
				Name:     e.Name,
				NewValue: e.NewValue,
				IsSecret: e.IsSecret,
			}
		}
		for i, e := range r.Diff.Modified {
			resp.Diff.Modified[i] = DiffEntryResponse{
				Name:     e.Name,
				OldValue: e.OldValue,
				NewValue: e.NewValue,
				IsSecret: e.IsSecret,
			}
		}
		for i, e := range r.Diff.Removed {
			resp.Diff.Removed[i] = DiffEntryResponse{
				Name:     e.Name,
				OldValue: e.OldValue,
				IsSecret: e.IsSecret,
			}
		}
	}

	if len(r.Variables) > 0 {
		resp.Variables = make([]VariableResponse, len(r.Variables))
		for i, v := range r.Variables {
			resp.Variables[i] = toVariableResponse(v)
		}
	}

	return resp
}

func toSyncStatusResponse(s *models.ConfigSync) SyncStatusResponse {
	resp := SyncStatusResponse{
		ID:            s.ID.String(),
		HostID:        s.HostID.String(),
		ContainerID:   s.ContainerID,
		ContainerName: s.ContainerName,
		Status:        s.Status,
		VariablesHash: s.VariablesHash,
		ErrorMessage:  s.ErrorMessage,
		CreatedAt:     s.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     s.UpdatedAt.Format(time.RFC3339),
	}

	if s.TemplateID != nil {
		tid := s.TemplateID.String()
		resp.TemplateID = &tid
	}
	resp.TemplateName = s.TemplateName

	if s.SyncedAt != nil {
		ls := s.SyncedAt.Format(time.RFC3339)
		resp.LastSyncedAt = &ls
	}

	return resp
}
