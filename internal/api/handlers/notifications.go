// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/notification"
	"github.com/fr4nsys/usulnet/internal/services/notification/channels"
)

// NotificationHandler handles notification-related HTTP requests.
type NotificationHandler struct {
	BaseHandler
	notificationService *notification.Service
	licenseProvider     middleware.LicenseProvider
}

// NewNotificationHandler creates a new notification handler.
func NewNotificationHandler(notificationService *notification.Service, log *logger.Logger) *NotificationHandler {
	return &NotificationHandler{
		BaseHandler:         NewBaseHandler(log),
		notificationService: notificationService,
	}
}

// SetLicenseProvider sets the license provider for feature gating.
func (h *NotificationHandler) SetLicenseProvider(provider middleware.LicenseProvider) {
	h.licenseProvider = provider
}

// Routes returns the router for notification endpoints.
func (h *NotificationHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Channels
	r.Get("/channels", h.ListChannels)
	r.Delete("/channels/{channelName}", h.RemoveChannel)
	r.Post("/channels/{channelName}/test", h.TestChannel)

	// Channel registration enforces MaxNotificationChannels limit
	r.Group(func(r chi.Router) {
		if h.licenseProvider != nil {
			r.Use(middleware.RequireLimit(
				h.licenseProvider,
				"notification channels",
				func(r *http.Request) int {
					return len(h.notificationService.ListChannels())
				},
				func(l license.Limits) int { return l.MaxNotificationChannels },
			))
		}
		r.Post("/channels", h.RegisterChannel)
	})

	// Send notification
	r.Post("/send", h.SendNotification)

	// Stats and logs
	r.Get("/stats", h.GetStats)
	r.Get("/logs", h.GetLogs)
	r.Get("/throttle-stats", h.GetThrottleStats)
	r.Post("/throttle/reset", h.ResetThrottle)

	return r
}

// ============================================================================
// Request/Response types
// ============================================================================

// SendNotificationRequest represents a send notification request.
type SendNotificationRequest struct {
	Type     string                 `json:"type"`
	Title    string                 `json:"title,omitempty"`
	Body     string                 `json:"body,omitempty"`
	Priority string                 `json:"priority,omitempty"`
	Data     map[string]interface{} `json:"data,omitempty"`
	Channels []string               `json:"channels,omitempty"`
	Async    bool                   `json:"async,omitempty"`
}

// RegisterChannelRequest represents a channel registration request.
type RegisterChannelRequest struct {
	Type     string                 `json:"type"`
	Name     string                 `json:"name"`
	Enabled  bool                   `json:"enabled"`
	Settings map[string]interface{} `json:"settings,omitempty"`
}

// NotificationStatsResponse represents notification statistics.
type NotificationStatsResponse struct {
	Total       int64            `json:"total"`
	Sent        int64            `json:"sent"`
	Failed      int64            `json:"failed"`
	Throttled   int64            `json:"throttled"`
	ByType      map[string]int64 `json:"by_type"`
	ByChannel   map[string]int64 `json:"by_channel"`
	SuccessRate float64          `json:"success_rate"`
}

// NotificationLogResponse represents a notification log entry.
type NotificationLogResponse struct {
	ID           string                  `json:"id"`
	Type         string                  `json:"type"`
	Priority     string                  `json:"priority"`
	Title        string                  `json:"title"`
	Body         string                  `json:"body"`
	Channels     []string                `json:"channels"`
	Results      []DeliveryResultResponse `json:"results"`
	Throttled    bool                    `json:"throttled"`
	SuccessCount int                     `json:"success_count"`
	FailedCount  int                     `json:"failed_count"`
	CreatedAt    string                  `json:"created_at"`
}

// DeliveryResultResponse represents a delivery result.
type DeliveryResultResponse struct {
	ChannelName string `json:"channel_name"`
	Success     bool   `json:"success"`
	Error       string `json:"error,omitempty"`
	Timestamp   string `json:"timestamp"`
}

// ThrottleStatsResponse represents throttle statistics.
type ThrottleStatsResponse struct {
	GlobalCount int                           `json:"global_count"`
	GlobalLimit int                           `json:"global_limit"`
	TypeCounts  map[string]TypeThrottleResponse `json:"type_counts"`
}

// TypeThrottleResponse represents per-type throttle stats.
type TypeThrottleResponse struct {
	Count int `json:"count"`
	Limit int `json:"limit"`
}

// ============================================================================
// Handlers
// ============================================================================

// ListChannels returns all registered channels.
// GET /api/v1/notifications/channels
func (h *NotificationHandler) ListChannels(w http.ResponseWriter, r *http.Request) {
	channelNames := h.notificationService.ListChannels()

	h.OK(w, map[string][]string{"channels": channelNames})
}

// RegisterChannel registers a new notification channel.
// POST /api/v1/notifications/channels
func (h *NotificationHandler) RegisterChannel(w http.ResponseWriter, r *http.Request) {
	var req RegisterChannelRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Type == "" {
		h.BadRequest(w, "type is required")
		return
	}
	if req.Name == "" {
		h.BadRequest(w, "name is required")
		return
	}

	config := &channels.ChannelConfig{
		Type:     req.Type,
		Name:     req.Name,
		Enabled:  req.Enabled,
		Settings: req.Settings,
	}

	if err := h.notificationService.RegisterChannel(req.Name, config); err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, map[string]string{"message": "channel registered"})
}

// RemoveChannel removes a notification channel.
// DELETE /api/v1/notifications/channels/{channelName}
func (h *NotificationHandler) RemoveChannel(w http.ResponseWriter, r *http.Request) {
	channelName := h.URLParam(r, "channelName")
	if channelName == "" {
		h.BadRequest(w, "channelName is required")
		return
	}

	if err := h.notificationService.RemoveChannel(channelName); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// TestChannel tests a notification channel.
// POST /api/v1/notifications/channels/{channelName}/test
func (h *NotificationHandler) TestChannel(w http.ResponseWriter, r *http.Request) {
	channelName := h.URLParam(r, "channelName")
	if channelName == "" {
		h.BadRequest(w, "channelName is required")
		return
	}

	if err := h.notificationService.TestChannel(r.Context(), channelName); err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]string{"message": "test notification sent"})
}

// SendNotification sends a notification.
// POST /api/v1/notifications/send
func (h *NotificationHandler) SendNotification(w http.ResponseWriter, r *http.Request) {
	var req SendNotificationRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Type == "" {
		h.BadRequest(w, "type is required")
		return
	}

	msg := notification.Message{
		Type:     channels.NotificationType(req.Type),
		Title:    req.Title,
		Body:     req.Body,
		Data:     req.Data,
		Channels: req.Channels,
	}

	if req.Priority != "" {
		msg.Priority = channels.PriorityFromString(req.Priority)
	}

	var err error
	if req.Async {
		err = h.notificationService.SendAsync(r.Context(), msg)
	} else {
		err = h.notificationService.Send(r.Context(), msg)
	}

	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]string{"message": "notification sent"})
}

// GetStats returns notification statistics.
// GET /api/v1/notifications/stats
func (h *NotificationHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	// Default to last 24 hours
	since := time.Now().Add(-24 * time.Hour)
	if sinceStr := h.QueryParam(r, "since"); sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = t
		}
	}

	stats, err := h.notificationService.GetStats(r.Context(), since)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, NotificationStatsResponse{
		Total:       stats.Total,
		Sent:        stats.Sent,
		Failed:      stats.Failed,
		Throttled:   stats.Throttled,
		ByType:      stats.ByType,
		ByChannel:   stats.ByChannel,
		SuccessRate: stats.SuccessRate,
	})
}

// GetLogs returns notification logs.
// GET /api/v1/notifications/logs
func (h *NotificationHandler) GetLogs(w http.ResponseWriter, r *http.Request) {
	pagination := h.GetPagination(r)

	filter := notification.LogFilter{
		Limit:  pagination.PerPage,
		Offset: pagination.Offset,
	}

	// Optional filters
	if notifType := h.QueryParam(r, "type"); notifType != "" {
		filter.Types = []channels.NotificationType{channels.NotificationType(notifType)}
	}
	if channel := h.QueryParam(r, "channel"); channel != "" {
		filter.Channels = []string{channel}
	}
	if onlyFailed := h.QueryParamBool(r, "only_failed", false); onlyFailed {
		filter.OnlyFailed = true
	}
	if sinceStr := h.QueryParam(r, "since"); sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			filter.Since = &t
		}
	}
	if untilStr := h.QueryParam(r, "until"); untilStr != "" {
		if t, err := time.Parse(time.RFC3339, untilStr); err == nil {
			filter.Until = &t
		}
	}

	logs, err := h.notificationService.GetLogs(r.Context(), filter)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]NotificationLogResponse, len(logs))
	for i, log := range logs {
		results := make([]DeliveryResultResponse, len(log.Results))
		for j, r := range log.Results {
			results[j] = DeliveryResultResponse{
				ChannelName: r.ChannelName,
				Success:     r.Success,
				Error:       r.Error,
				Timestamp:   r.Timestamp.Format(time.RFC3339),
			}
		}

		resp[i] = NotificationLogResponse{
			ID:           log.ID.String(),
			Type:         string(log.Type),
			Priority:     log.Priority.String(),
			Title:        log.Title,
			Body:         log.Body,
			Channels:     log.Channels,
			Results:      results,
			Throttled:    log.Throttled,
			SuccessCount: log.SuccessCount,
			FailedCount:  log.FailedCount,
			CreatedAt:    log.CreatedAt.Format(time.RFC3339),
		}
	}

	h.OK(w, resp)
}

// GetThrottleStats returns throttle statistics.
// GET /api/v1/notifications/throttle-stats
func (h *NotificationHandler) GetThrottleStats(w http.ResponseWriter, r *http.Request) {
	stats := h.notificationService.GetThrottleStats()

	typeCounts := make(map[string]TypeThrottleResponse)
	for t, s := range stats.TypeCounts {
		typeCounts[string(t)] = TypeThrottleResponse{
			Count: s.Count,
			Limit: s.Limit,
		}
	}

	h.OK(w, ThrottleStatsResponse{
		GlobalCount: stats.GlobalCount,
		GlobalLimit: stats.GlobalLimit,
		TypeCounts:  typeCounts,
	})
}

// ResetThrottle resets the throttle counters.
// POST /api/v1/notifications/throttle/reset
func (h *NotificationHandler) ResetThrottle(w http.ResponseWriter, r *http.Request) {
	h.notificationService.ResetThrottle()

	h.OK(w, map[string]string{"message": "throttle counters reset"})
}
