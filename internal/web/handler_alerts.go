// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/alerts"
)

// AlertsService is the interface for alert operations.
type AlertsService interface {
	ListRules(ctx context.Context, opts models.AlertListOptions) ([]*models.AlertRule, int64, error)
	GetRule(ctx context.Context, id uuid.UUID) (*models.AlertRule, error)
	CreateRule(ctx context.Context, input models.CreateAlertRuleInput, createdBy *uuid.UUID) (*models.AlertRule, error)
	UpdateRule(ctx context.Context, id uuid.UUID, input models.UpdateAlertRuleInput) (*models.AlertRule, error)
	DeleteRule(ctx context.Context, id uuid.UUID) error
	ListEvents(ctx context.Context, opts models.AlertEventListOptions) ([]*models.AlertEvent, int64, error)
	AcknowledgeEvent(ctx context.Context, id uuid.UUID, userID uuid.UUID) error
	ListSilences(ctx context.Context) ([]*models.AlertSilence, error)
	CreateSilence(ctx context.Context, input models.CreateAlertSilenceInput, createdBy *uuid.UUID) (*models.AlertSilence, error)
	DeleteSilence(ctx context.Context, id uuid.UUID) error
	GetStats(ctx context.Context) (*models.AlertStats, error)
}

// ============================================================================
// Alerts List
// ============================================================================

func (h *Handler) AlertsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Alerts", "alerts")
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "rules"
	}

	var ruleItems []alerts.AlertRuleItem
	var eventItems []alerts.AlertEventItem
	var silenceItems []alerts.AlertSilenceItem
	var stats alerts.AlertStats

	// Get alert service from handler (we'll add this interface)
	alertSvc := h.getAlertService()
	if alertSvc == nil {
		// Alert service not available
		data := alerts.AlertsData{
			PageData: pageData,
			Tab:      tab,
		}
		h.renderTempl(w, r, alerts.List(data))
		return
	}

	// Fetch rules
	rules, total, err := alertSvc.ListRules(ctx, models.AlertListOptions{Limit: 100})
	if err != nil {
		slog.Error("Failed to list alert rules", "error", err)
	} else {
		stats.TotalRules = int(total)
		for _, rule := range rules {
			item := alerts.AlertRuleItem{
				ID:          rule.ID.String(),
				Name:        rule.Name,
				Description: rule.Description,
				Metric:      string(rule.Metric),
				MetricLabel: alertMetricLabel(rule.Metric),
				Operator:    string(rule.Operator),
				Threshold:   rule.Threshold,
				Severity:    string(rule.Severity),
				State:       string(rule.State),
				IsEnabled:   rule.IsEnabled,
				Duration:    rule.Duration,
				Cooldown:    rule.Cooldown,
			}

			if rule.HostID != nil {
				item.HostID = rule.HostID.String()
				// Try to get host name
				if host, err := h.services.Hosts().Get(ctx, rule.HostID.String()); err == nil && host != nil {
					item.HostName = host.Name
				}
			}

			if rule.ContainerID != nil {
				item.ContainerID = *rule.ContainerID
			}

			if rule.LastEvaluated != nil {
				item.LastEvaluated = rule.LastEvaluated.Format("2006-01-02 15:04")
			}

			if rule.LastFiredAt != nil {
				item.LastFiredAt = rule.LastFiredAt.Format("2006-01-02 15:04")
			}

			if rule.FiringValue != nil {
				item.FiringValue = *rule.FiringValue
			}

			if rule.IsEnabled {
				stats.EnabledRules++
			}
			if rule.State == models.AlertStateFiring {
				stats.FiringRules++
			}
			if rule.Severity == models.AlertSeverityCritical {
				stats.Critical++
			} else if rule.Severity == models.AlertSeverityWarning {
				stats.Warning++
			}

			ruleItems = append(ruleItems, item)
		}
	}

	// Fetch events
	events, _, err := alertSvc.ListEvents(ctx, models.AlertEventListOptions{Limit: 50})
	if err != nil {
		slog.Error("Failed to list alert events", "error", err)
	} else {
		for _, event := range events {
			item := alerts.AlertEventItem{
				ID:        event.ID.String(),
				AlertID:   event.AlertID.String(),
				State:     string(event.State),
				Value:     event.Value,
				Threshold: event.Threshold,
				Message:   event.Message,
				FiredAt:   event.FiredAt.Format("2006-01-02 15:04"),
			}

			// Get alert name
			if rule, err := alertSvc.GetRule(ctx, event.AlertID); err == nil && rule != nil {
				item.AlertName = rule.Name
				item.Severity = string(rule.Severity)
			}

			if event.HostID != uuid.Nil {
				item.HostID = event.HostID.String()
				if host, err := h.services.Hosts().Get(ctx, event.HostID.String()); err == nil && host != nil {
					item.HostName = host.Name
				}
			}

			if event.ContainerID != nil {
				item.ContainerID = *event.ContainerID
			}

			if event.ResolvedAt != nil {
				item.ResolvedAt = event.ResolvedAt.Format("2006-01-02 15:04")
			} else {
				stats.ActiveEvents++
			}

			if event.AcknowledgedAt != nil {
				item.AcknowledgedAt = event.AcknowledgedAt.Format("2006-01-02 15:04")
			}

			eventItems = append(eventItems, item)
		}
	}

	// Fetch silences
	silences, err := alertSvc.ListSilences(ctx)
	if err != nil {
		slog.Error("Failed to list alert silences", "error", err)
	} else {
		for _, silence := range silences {
			item := alerts.AlertSilenceItem{
				ID:        silence.ID.String(),
				Reason:    silence.Reason,
				StartsAt:  silence.StartsAt.Format("2006-01-02 15:04"),
				EndsAt:    silence.EndsAt.Format("2006-01-02 15:04"),
				CreatedAt: silence.CreatedAt.Format("2006-01-02 15:04"),
				IsActive:  silence.IsActive(),
			}

			if silence.AlertID != nil {
				item.AlertID = silence.AlertID.String()
				if rule, err := alertSvc.GetRule(ctx, *silence.AlertID); err == nil && rule != nil {
					item.AlertName = rule.Name
				}
			}

			if silence.HostID != nil {
				item.HostID = silence.HostID.String()
				if host, err := h.services.Hosts().Get(ctx, silence.HostID.String()); err == nil && host != nil {
					item.HostName = host.Name
				}
			}

			if silence.IsActive() {
				stats.ActiveSilences++
			}

			silenceItems = append(silenceItems, item)
		}
	}

	// Fetch hosts for dropdowns
	var hostOptions []alerts.HostOption
	if hostList, err := h.services.Hosts().List(ctx); err == nil {
		for _, h := range hostList {
			hostOptions = append(hostOptions, alerts.HostOption{
				ID:   h.ID,
				Name: h.Name,
			})
		}
	}

	data := alerts.AlertsData{
		PageData: pageData,
		Rules:    ruleItems,
		Events:   eventItems,
		Silences: silenceItems,
		Stats:    stats,
		Tab:      tab,
		Hosts:    hostOptions,
	}
	h.renderTempl(w, r, alerts.List(data))
}

// ============================================================================
// Alert Rule CRUD
// ============================================================================

func (h *Handler) AlertEditTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")
	pageData := h.prepareTemplPageData(r, "Edit Alert", "alerts")

	alertSvc := h.getAlertService()
	if alertSvc == nil {
		h.RenderErrorTempl(w, r, http.StatusServiceUnavailable, "Service Unavailable", "Alert service not available")
		return
	}

	ruleID, err := uuid.Parse(idStr)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The alert rule ID is not valid.")
		return
	}

	rule, err := alertSvc.GetRule(ctx, ruleID)
	if err != nil || rule == nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Alert rule not found.")
		return
	}

	item := alerts.AlertRuleItem{
		ID:          rule.ID.String(),
		Name:        rule.Name,
		Description: rule.Description,
		Metric:      string(rule.Metric),
		Operator:    string(rule.Operator),
		Threshold:   rule.Threshold,
		Severity:    string(rule.Severity),
		IsEnabled:   rule.IsEnabled,
		Duration:    rule.Duration,
		Cooldown:    rule.Cooldown,
	}

	if rule.HostID != nil {
		item.HostID = rule.HostID.String()
	}

	// Fetch hosts
	var hostOptions []alerts.HostOption
	if hostList, err := h.services.Hosts().List(ctx); err == nil {
		for _, h := range hostList {
			hostOptions = append(hostOptions, alerts.HostOption{
				ID:   h.ID,
				Name: h.Name,
			})
		}
	}

	data := alerts.AlertEditData{
		PageData: pageData,
		Rule:     item,
		Hosts:    hostOptions,
	}
	h.renderTempl(w, r, alerts.Edit(data))
}

func (h *Handler) AlertCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	alertSvc := h.getAlertService()
	if alertSvc == nil {
		h.redirect(w, r, "/alerts")
		return
	}

	if err := r.ParseForm(); err != nil {
		slog.Error("Failed to parse form", "error", err)
		h.redirect(w, r, "/alerts")
		return
	}

	name := r.FormValue("name")
	description := r.FormValue("description")
	metric := r.FormValue("metric")
	operator := r.FormValue("operator")
	thresholdStr := r.FormValue("threshold")
	severity := r.FormValue("severity")
	durationStr := r.FormValue("duration")
	cooldownStr := r.FormValue("cooldown")
	hostIDStr := r.FormValue("host_id")

	threshold, _ := strconv.ParseFloat(thresholdStr, 64)
	duration, _ := strconv.Atoi(durationStr)
	cooldown, _ := strconv.Atoi(cooldownStr)

	input := models.CreateAlertRuleInput{
		Name:            name,
		Description:     description,
		Metric:          models.AlertMetric(metric),
		Operator:        models.AlertOperator(operator),
		Threshold:       threshold,
		Severity:        models.AlertSeverity(severity),
		DurationSeconds: duration,
		CooldownSeconds: cooldown,
		IsEnabled:       true,
	}

	if hostIDStr != "" {
		hostID, err := uuid.Parse(hostIDStr)
		if err == nil {
			input.HostID = &hostID
		}
	}

	var createdBy *uuid.UUID
	if user := GetUserFromContext(ctx); user != nil {
		if uid, err := uuid.Parse(user.ID); err == nil {
			createdBy = &uid
		}
	}

	_, err := alertSvc.CreateRule(ctx, input, createdBy)
	if err != nil {
		slog.Error("Failed to create alert rule", "name", name, "error", err)
	}

	h.redirect(w, r, "/alerts")
}

func (h *Handler) AlertUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	alertSvc := h.getAlertService()
	if alertSvc == nil {
		h.redirect(w, r, "/alerts")
		return
	}

	ruleID, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/alerts")
		return
	}

	if err := r.ParseForm(); err != nil {
		slog.Error("Failed to parse form", "error", err)
		h.redirect(w, r, "/alerts/"+idStr)
		return
	}

	name := r.FormValue("name")
	description := r.FormValue("description")
	thresholdStr := r.FormValue("threshold")
	severity := r.FormValue("severity")
	durationStr := r.FormValue("duration")
	cooldownStr := r.FormValue("cooldown")
	isEnabled := r.FormValue("is_enabled") == "on"

	threshold, _ := strconv.ParseFloat(thresholdStr, 64)
	duration, _ := strconv.Atoi(durationStr)
	cooldown, _ := strconv.Atoi(cooldownStr)

	severityVal := models.AlertSeverity(severity)

	input := models.UpdateAlertRuleInput{
		Name:            &name,
		Description:     &description,
		Threshold:       &threshold,
		Severity:        &severityVal,
		DurationSeconds: &duration,
		CooldownSeconds: &cooldown,
		IsEnabled:       &isEnabled,
	}

	_, err = alertSvc.UpdateRule(ctx, ruleID, input)
	if err != nil {
		slog.Error("Failed to update alert rule", "id", ruleID, "error", err)
	}

	h.redirect(w, r, "/alerts")
}

func (h *Handler) AlertDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	alertSvc := h.getAlertService()
	if alertSvc == nil {
		h.redirect(w, r, "/alerts")
		return
	}

	ruleID, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/alerts")
		return
	}

	if err := alertSvc.DeleteRule(ctx, ruleID); err != nil {
		slog.Error("Failed to delete alert rule", "id", ruleID, "error", err)
	}

	h.redirect(w, r, "/alerts")
}

func (h *Handler) AlertEnable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	alertSvc := h.getAlertService()
	if alertSvc == nil {
		h.redirect(w, r, "/alerts")
		return
	}

	ruleID, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/alerts")
		return
	}

	enabled := true
	input := models.UpdateAlertRuleInput{IsEnabled: &enabled}

	_, err = alertSvc.UpdateRule(ctx, ruleID, input)
	if err != nil {
		slog.Error("Failed to enable alert rule", "id", ruleID, "error", err)
	}

	h.redirect(w, r, "/alerts")
}

func (h *Handler) AlertDisable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	alertSvc := h.getAlertService()
	if alertSvc == nil {
		h.redirect(w, r, "/alerts")
		return
	}

	ruleID, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/alerts")
		return
	}

	enabled := false
	input := models.UpdateAlertRuleInput{IsEnabled: &enabled}

	_, err = alertSvc.UpdateRule(ctx, ruleID, input)
	if err != nil {
		slog.Error("Failed to disable alert rule", "id", ruleID, "error", err)
	}

	h.redirect(w, r, "/alerts")
}

// ============================================================================
// Event Operations
// ============================================================================

func (h *Handler) AlertEventAck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	alertSvc := h.getAlertService()
	if alertSvc == nil {
		h.redirect(w, r, "/alerts?tab=events")
		return
	}

	eventID, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/alerts?tab=events")
		return
	}

	var userID uuid.UUID
	if user := GetUserFromContext(ctx); user != nil {
		userID, _ = uuid.Parse(user.ID)
	}

	if err := alertSvc.AcknowledgeEvent(ctx, eventID, userID); err != nil {
		slog.Error("Failed to acknowledge alert event", "id", eventID, "error", err)
	}

	h.redirect(w, r, "/alerts?tab=events")
}

// ============================================================================
// Silence Operations
// ============================================================================

func (h *Handler) AlertSilenceCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	alertSvc := h.getAlertService()
	if alertSvc == nil {
		h.redirect(w, r, "/alerts?tab=silences")
		return
	}

	if err := r.ParseForm(); err != nil {
		slog.Error("Failed to parse form", "error", err)
		h.redirect(w, r, "/alerts?tab=silences")
		return
	}

	hostIDStr := r.FormValue("host_id")
	durationStr := r.FormValue("duration")
	reason := r.FormValue("reason")

	// Parse duration
	now := time.Now()
	var endsAt time.Time
	switch durationStr {
	case "1h":
		endsAt = now.Add(time.Hour)
	case "4h":
		endsAt = now.Add(4 * time.Hour)
	case "8h":
		endsAt = now.Add(8 * time.Hour)
	case "24h":
		endsAt = now.Add(24 * time.Hour)
	case "7d":
		endsAt = now.Add(7 * 24 * time.Hour)
	default:
		endsAt = now.Add(time.Hour)
	}

	input := models.CreateAlertSilenceInput{
		Reason:   reason,
		StartsAt: now,
		EndsAt:   endsAt,
	}

	if hostIDStr != "" {
		hostID, err := uuid.Parse(hostIDStr)
		if err == nil {
			input.HostID = &hostID
		}
	}

	var createdBy *uuid.UUID
	if user := GetUserFromContext(ctx); user != nil {
		if uid, err := uuid.Parse(user.ID); err == nil {
			createdBy = &uid
		}
	}

	_, err := alertSvc.CreateSilence(ctx, input, createdBy)
	if err != nil {
		slog.Error("Failed to create alert silence", "error", err)
	}

	h.redirect(w, r, "/alerts?tab=silences")
}

func (h *Handler) AlertSilenceDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	alertSvc := h.getAlertService()
	if alertSvc == nil {
		h.redirect(w, r, "/alerts?tab=silences")
		return
	}

	silenceID, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/alerts?tab=silences")
		return
	}

	if err := alertSvc.DeleteSilence(ctx, silenceID); err != nil {
		slog.Error("Failed to delete alert silence", "id", silenceID, "error", err)
	}

	h.redirect(w, r, "/alerts?tab=silences")
}

// ============================================================================
// Helper Functions
// ============================================================================

func (h *Handler) getAlertService() AlertsService {
	if h.services != nil {
		return h.services.Alerts()
	}
	return nil
}

func alertMetricLabel(metric models.AlertMetric) string {
	labels := map[models.AlertMetric]string{
		"cpu_percent":       "CPU %",
		"memory_percent":    "Memory %",
		"disk_percent":      "Disk %",
		"network_rx_rate":   "Network RX",
		"network_tx_rate":   "Network TX",
		"container_count":   "Container Count",
		"container_cpu":     "Container CPU %",
		"container_memory":  "Container Memory %",
	}
	if label, ok := labels[metric]; ok {
		return label
	}
	return string(metric)
}
