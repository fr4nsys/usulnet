// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/update"
)

// UpdateHandler handles update management endpoints.
type UpdateHandler struct {
	BaseHandler
	updateService *update.Service
}

// NewUpdateHandler creates a new UpdateHandler.
func NewUpdateHandler(updateService *update.Service, log *logger.Logger) *UpdateHandler {
	return &UpdateHandler{
		BaseHandler:   NewBaseHandler(log),
		updateService: updateService,
	}
}

// Routes returns the router for update endpoints.
func (h *UpdateHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Check for updates
	r.Post("/check/{hostID}", h.CheckForUpdates)
	r.Post("/check/{hostID}/{containerID}", h.CheckContainerForUpdate)

	// Apply update
	r.Post("/apply/{hostID}", h.ApplyUpdate)

	// Rollback
	r.Post("/rollback", h.RollbackUpdate)

	// History
	r.Get("/", h.ListUpdates)
	r.Get("/history/{hostID}", h.GetHistory)
	r.Get("/history/{hostID}/{targetID}", h.GetTargetHistory)
	r.Get("/stats", h.GetStats)
	r.Get("/stats/{hostID}", h.GetHostStats)

	// Policies
	r.Route("/policies", func(r chi.Router) {
		r.Get("/", h.ListPolicies)
		r.Get("/{hostID}", h.ListHostPolicies)
		r.Post("/{hostID}", h.CreatePolicy)
		r.Get("/{hostID}/{policyID}", h.GetPolicy)
		r.Put("/{hostID}/{policyID}", h.UpdatePolicy)
		r.Delete("/{hostID}/{policyID}", h.DeletePolicy)
	})

	// Webhooks
	r.Route("/webhooks", func(r chi.Router) {
		r.Get("/{hostID}", h.ListWebhooks)
		r.Post("/{hostID}", h.CreateWebhook)
		r.Delete("/{hostID}/{webhookID}", h.DeleteWebhook)
	})

	return r
}

// ============================================================================
// Request/Response types
// ============================================================================

// CheckForUpdatesRequest represents a request to check for updates.
type CheckForUpdatesRequest struct {
	// No body needed - hostID from URL
}

// ApplyUpdateRequest represents a request to apply an update.
type ApplyUpdateRequest struct {
	ContainerID     string `json:"container_id" validate:"required"`
	TargetVersion   string `json:"target_version,omitempty"`
	ForcePull       bool   `json:"force_pull,omitempty"`
	BackupVolumes   bool   `json:"backup_volumes"`
	SecurityScan    bool   `json:"security_scan"`
	HealthCheckWait int    `json:"health_check_wait,omitempty"` // seconds
	MaxRetries      int    `json:"max_retries,omitempty"`
	DryRun          bool   `json:"dry_run,omitempty"`
}

// RollbackRequest represents a request to rollback an update.
type RollbackRequest struct {
	UpdateID      string `json:"update_id" validate:"required"`
	RestoreBackup bool   `json:"restore_backup"`
	Reason        string `json:"reason,omitempty"`
}

// CreatePolicyRequest represents a request to create an update policy.
type CreatePolicyRequest struct {
	TargetType        string  `json:"target_type" validate:"required,oneof=container stack service"`
	TargetID          string  `json:"target_id" validate:"required"`
	AutoUpdate        bool    `json:"auto_update"`
	AutoBackup        bool    `json:"auto_backup"`
	IncludePrerelease bool    `json:"include_prerelease"`
	Schedule          *string `json:"schedule,omitempty"`
	NotifyOnUpdate    bool    `json:"notify_on_update"`
	NotifyOnFailure   bool    `json:"notify_on_failure"`
	MaxRetries        int     `json:"max_retries,omitempty"`
	HealthCheckWait   int     `json:"health_check_wait,omitempty"`
}

// UpdatePolicyRequest represents a request to update an existing policy.
type UpdatePolicyRequest struct {
	IsEnabled         *bool   `json:"is_enabled,omitempty"`
	AutoUpdate        *bool   `json:"auto_update,omitempty"`
	AutoBackup        *bool   `json:"auto_backup,omitempty"`
	IncludePrerelease *bool   `json:"include_prerelease,omitempty"`
	Schedule          *string `json:"schedule,omitempty"`
	NotifyOnUpdate    *bool   `json:"notify_on_update,omitempty"`
	NotifyOnFailure   *bool   `json:"notify_on_failure,omitempty"`
	MaxRetries        *int    `json:"max_retries,omitempty"`
	HealthCheckWait   *int    `json:"health_check_wait,omitempty"`
}

// CreateWebhookRequest represents a request to create a webhook.
type CreateWebhookRequest struct {
	TargetType string `json:"target_type" validate:"required,oneof=container stack service"`
	TargetID   string `json:"target_id" validate:"required"`
}

// ============================================================================
// Handlers
// ============================================================================

// CheckForUpdates checks all containers on a host for available updates.
// POST /api/v1/updates/check/{hostID}
func (h *UpdateHandler) CheckForUpdates(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	result, err := h.updateService.CheckForUpdates(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, result)
}

// CheckContainerForUpdate checks a specific container for available updates.
// POST /api/v1/updates/check/{hostID}/{containerID}
func (h *UpdateHandler) CheckContainerForUpdate(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	containerID := h.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "container ID is required")
		return
	}

	result, err := h.updateService.CheckContainerForUpdate(r.Context(), hostID, containerID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, result)
}

// ApplyUpdate applies an update to a container.
// POST /api/v1/updates/apply/{hostID}
func (h *UpdateHandler) ApplyUpdate(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	var req ApplyUpdateRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.BadRequest(w, err.Error())
		return
	}

	if req.ContainerID == "" {
		h.BadRequest(w, "container_id is required")
		return
	}

	// Get user ID from context
	var createdBy *uuid.UUID
	userID, err := h.GetUserID(r)
	if err == nil {
		createdBy = &userID
	}

	healthWait := 30 * time.Second
	if req.HealthCheckWait > 0 {
		healthWait = time.Duration(req.HealthCheckWait) * time.Second
	}

	opts := &models.UpdateOptions{
		ContainerID:     req.ContainerID,
		TargetVersion:   req.TargetVersion,
		ForcePull:       req.ForcePull,
		BackupVolumes:   req.BackupVolumes,
		SecurityScan:    req.SecurityScan,
		HealthCheckWait: healthWait,
		MaxRetries:      req.MaxRetries,
		DryRun:          req.DryRun,
		CreatedBy:       createdBy,
	}

	result, err := h.updateService.UpdateContainer(r.Context(), hostID, opts)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, result)
}

// RollbackUpdate rolls back a previously applied update.
// POST /api/v1/updates/rollback
func (h *UpdateHandler) RollbackUpdate(w http.ResponseWriter, r *http.Request) {
	var req RollbackRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.BadRequest(w, err.Error())
		return
	}

	updateID, err := uuid.Parse(req.UpdateID)
	if err != nil {
		h.BadRequest(w, "invalid update_id")
		return
	}

	opts := &models.RollbackOptions{
		UpdateID:      updateID,
		RestoreBackup: req.RestoreBackup,
		Reason:        req.Reason,
	}

	result, err := h.updateService.RollbackUpdate(r.Context(), opts)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, result)
}

// ListUpdates returns all updates with filtering.
// GET /api/v1/updates?host_id=&target_id=&status=&trigger=&limit=&offset=
func (h *UpdateHandler) ListUpdates(w http.ResponseWriter, r *http.Request) {
	pagination := h.GetPagination(r)

	opts := models.UpdateListOptions{
		Limit:  pagination.PerPage,
		Offset: pagination.Offset,
	}

	// Optional filters
	if hostIDStr := h.QueryParam(r, "host_id"); hostIDStr != "" {
		hostID, err := uuid.Parse(hostIDStr)
		if err != nil {
			h.BadRequest(w, "invalid host_id")
			return
		}
		opts.HostID = &hostID
	}
	if targetID := h.QueryParam(r, "target_id"); targetID != "" {
		opts.TargetID = &targetID
	}
	if statusStr := h.QueryParam(r, "status"); statusStr != "" {
		status := models.UpdateStatus(statusStr)
		opts.Status = &status
	}
	if triggerStr := h.QueryParam(r, "trigger"); triggerStr != "" {
		trigger := models.UpdateTrigger(triggerStr)
		opts.Trigger = &trigger
	}

	updates, total, err := h.updateService.ListUpdates(r.Context(), opts)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, NewPaginatedResponse(updates, total, pagination))
}

// GetHistory returns update history for a host.
// GET /api/v1/updates/history/{hostID}
func (h *UpdateHandler) GetHistory(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	limit := h.QueryParamInt(r, "limit", 50)

	updates, err := h.updateService.GetHistory(r.Context(), hostID, "", limit)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, updates)
}

// GetTargetHistory returns update history for a specific target (container/stack).
// GET /api/v1/updates/history/{hostID}/{targetID}
func (h *UpdateHandler) GetTargetHistory(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	targetID := h.URLParam(r, "targetID")
	if targetID == "" {
		h.BadRequest(w, "target ID is required")
		return
	}

	limit := h.QueryParamInt(r, "limit", 50)

	updates, err := h.updateService.GetHistory(r.Context(), hostID, targetID, limit)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, updates)
}

// GetStats returns global update statistics.
// GET /api/v1/updates/stats
func (h *UpdateHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.updateService.GetStats(r.Context(), nil)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, stats)
}

// GetHostStats returns update statistics for a specific host.
// GET /api/v1/updates/stats/{hostID}
func (h *UpdateHandler) GetHostStats(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	stats, err := h.updateService.GetStats(r.Context(), &hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, stats)
}

// ============================================================================
// Policy Handlers
// ============================================================================

// ListPolicies returns all update policies.
// GET /api/v1/updates/policies
func (h *UpdateHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := h.updateService.ListPolicies(r.Context(), nil)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, policies)
}

// ListHostPolicies returns update policies for a specific host.
// GET /api/v1/updates/policies/{hostID}
func (h *UpdateHandler) ListHostPolicies(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	policies, err := h.updateService.ListPolicies(r.Context(), &hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, policies)
}

// CreatePolicy creates a new update policy.
// POST /api/v1/updates/policies/{hostID}
func (h *UpdateHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	var req CreatePolicyRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.BadRequest(w, err.Error())
		return
	}

	policy := &models.UpdatePolicy{
		ID:                uuid.New(),
		HostID:            hostID,
		TargetType:        models.UpdateType(req.TargetType),
		TargetID:          req.TargetID,
		IsEnabled:         true,
		AutoUpdate:        req.AutoUpdate,
		AutoBackup:        req.AutoBackup,
		IncludePrerelease: req.IncludePrerelease,
		Schedule:          req.Schedule,
		NotifyOnUpdate:    req.NotifyOnUpdate,
		NotifyOnFailure:   req.NotifyOnFailure,
		MaxRetries:        req.MaxRetries,
		HealthCheckWait:   req.HealthCheckWait,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	if err := h.updateService.SetPolicy(r.Context(), policy); err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, policy)
}

// GetPolicy returns a specific update policy.
// GET /api/v1/updates/policies/{hostID}/{policyID}
func (h *UpdateHandler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	policyID, err := h.URLParamUUID(r, "policyID")
	if err != nil {
		h.BadRequest(w, "invalid policy ID")
		return
	}

	policy, err := h.updateService.GetPolicyByID(r.Context(), policyID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if policy.HostID != hostID {
		h.NotFound(w, "policy")
		return
	}

	h.OK(w, policy)
}

// UpdatePolicy updates an existing update policy.
// PUT /api/v1/updates/policies/{hostID}/{policyID}
func (h *UpdateHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	policyID, err := h.URLParamUUID(r, "policyID")
	if err != nil {
		h.BadRequest(w, "invalid policy ID")
		return
	}

	// Get existing policy
	policy, err := h.updateService.GetPolicyByID(r.Context(), policyID)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	if policy.HostID != hostID {
		h.NotFound(w, "policy")
		return
	}

	var req UpdatePolicyRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.BadRequest(w, err.Error())
		return
	}

	// Apply partial updates
	if req.IsEnabled != nil {
		policy.IsEnabled = *req.IsEnabled
	}
	if req.AutoUpdate != nil {
		policy.AutoUpdate = *req.AutoUpdate
	}
	if req.AutoBackup != nil {
		policy.AutoBackup = *req.AutoBackup
	}
	if req.IncludePrerelease != nil {
		policy.IncludePrerelease = *req.IncludePrerelease
	}
	if req.Schedule != nil {
		policy.Schedule = req.Schedule
	}
	if req.NotifyOnUpdate != nil {
		policy.NotifyOnUpdate = *req.NotifyOnUpdate
	}
	if req.NotifyOnFailure != nil {
		policy.NotifyOnFailure = *req.NotifyOnFailure
	}
	if req.MaxRetries != nil {
		policy.MaxRetries = *req.MaxRetries
	}
	if req.HealthCheckWait != nil {
		policy.HealthCheckWait = *req.HealthCheckWait
	}
	policy.UpdatedAt = time.Now()

	if err := h.updateService.SetPolicy(r.Context(), policy); err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, policy)
}

// DeletePolicy deletes an update policy.
// DELETE /api/v1/updates/policies/{hostID}/{policyID}
func (h *UpdateHandler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	_, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	policyID, err := h.URLParamUUID(r, "policyID")
	if err != nil {
		h.BadRequest(w, "invalid policy ID")
		return
	}

	if err := h.updateService.DeletePolicy(r.Context(), policyID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// ============================================================================
// Webhook Handlers
// ============================================================================

// ListWebhooks returns webhooks for a host.
// GET /api/v1/updates/webhooks/{hostID}
func (h *UpdateHandler) ListWebhooks(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	webhooks, err := h.updateService.ListWebhooks(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, webhooks)
}

// CreateWebhook creates a new update webhook.
// POST /api/v1/updates/webhooks/{hostID}
func (h *UpdateHandler) CreateWebhook(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	var req CreateWebhookRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.BadRequest(w, err.Error())
		return
	}

	webhook, err := h.updateService.CreateWebhook(
		r.Context(),
		hostID,
		models.UpdateType(req.TargetType),
		req.TargetID,
	)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, webhook)
}

// DeleteWebhook deletes a webhook.
// DELETE /api/v1/updates/webhooks/{hostID}/{webhookID}
func (h *UpdateHandler) DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	_, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.BadRequest(w, "invalid host ID")
		return
	}

	webhookID, err := h.URLParamUUID(r, "webhookID")
	if err != nil {
		h.BadRequest(w, "invalid webhook ID")
		return
	}

	if err := h.updateService.DeleteWebhook(r.Context(), webhookID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// TriggerWebhook triggers an update via webhook token (public endpoint).
// POST /api/v1/webhooks/update/{token}
func (h *UpdateHandler) TriggerWebhook(w http.ResponseWriter, r *http.Request) {
	token := h.URLParam(r, "token")
	if token == "" {
		h.BadRequest(w, "webhook token is required")
		return
	}

	result, err := h.updateService.TriggerWebhook(r.Context(), token)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, result)
}
