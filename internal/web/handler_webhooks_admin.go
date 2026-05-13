// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/webhooks"
)

// WebhooksTempl renders the webhooks & auto-deploy management page.
func (h *Handler) WebhooksTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Webhooks", "webhooks")
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "webhooks"
	}

	var whItems []webhooks.WebhookItem
	var deliveryItems []webhooks.DeliveryItem
	var autoDeployItems []webhooks.AutoDeployItem

	if h.webhookRepo != nil {
		whs, err := h.webhookRepo.List(r.Context())
		if err != nil {
			slog.Error("Failed to list webhooks", "error", err)
		} else {
			for _, wh := range whs {
				whItems = append(whItems, webhooks.WebhookItem{
					ID:          wh.ID.String(),
					Name:        wh.Name,
					URL:         wh.URL,
					Events:      wh.Events,
					IsEnabled:   wh.IsEnabled,
					RetryCount:  wh.RetryCount,
					TimeoutSecs: wh.TimeoutSecs,
					CreatedAt:   wh.CreatedAt.Format("2006-01-02 15:04"),
				})
			}
		}

		// Fetch recent deliveries
		if tab == "deliveries" {
			deliveries, _, err := h.webhookRepo.ListDeliveries(r.Context(), models.WebhookDeliveryListOptions{Limit: 50})
			if err != nil {
				slog.Error("Failed to list deliveries", "error", err)
			} else {
				for _, d := range deliveries {
					item := webhooks.DeliveryItem{
						ID:       d.ID.String(),
						Event:    d.Event,
						Status:   d.Status,
						Duration: d.Duration,
						Attempt:  d.Attempt,
					}
					if d.ResponseCode != nil {
						item.ResponseCode = *d.ResponseCode
					}
					if d.Error != nil {
						item.Error = *d.Error
					}
					if d.DeliveredAt != nil {
						item.DeliveredAt = d.DeliveredAt.Format("2006-01-02 15:04:05")
					}
					// Get webhook name
					if wh, err := h.webhookRepo.GetByID(r.Context(), d.WebhookID); err == nil {
						item.WebhookName = wh.Name
					}
					deliveryItems = append(deliveryItems, item)
				}
			}
		}
	}

	// Fetch auto-deploy rules
	if h.autoDeployRepo != nil && tab == "autodeploy" {
		rules, err := h.autoDeployRepo.List(r.Context())
		if err != nil {
			slog.Error("Failed to list auto-deploy rules", "error", err)
		} else {
			for _, rule := range rules {
				item := webhooks.AutoDeployItem{
					ID:         rule.ID.String(),
					Name:       rule.Name,
					SourceType: rule.SourceType,
					SourceRepo: rule.SourceRepo,
					Action:     rule.Action,
					IsEnabled:  rule.IsEnabled,
				}
				if rule.SourceBranch != nil {
					item.SourceBranch = *rule.SourceBranch
				}
				if rule.TargetStackID != nil {
					item.TargetStack = *rule.TargetStackID
				}
				if rule.TargetService != nil {
					item.TargetService = *rule.TargetService
				}
				if rule.LastTriggeredAt != nil {
					item.LastTriggered = rule.LastTriggeredAt.Format("2006-01-02 15:04")
				}
				autoDeployItems = append(autoDeployItems, item)
			}
		}
	}

	data := webhooks.WebhooksData{
		PageData:   pageData,
		Webhooks:   whItems,
		Deliveries: deliveryItems,
		AutoDeploy: autoDeployItems,
		Tab:        tab,
	}
	h.renderTempl(w, r, webhooks.List(data))
}

// WebhookCreate handles creation of a new outgoing webhook.
func (h *Handler) WebhookCreate(w http.ResponseWriter, r *http.Request) {
	if h.webhookRepo == nil {
		h.setFlash(w, r, "error", "Webhook service not configured")
		h.redirect(w, r, "/webhooks")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		h.redirect(w, r, "/webhooks")
		return
	}

	name := r.FormValue("name")
	webhookURL := r.FormValue("url")
	if name == "" || webhookURL == "" {
		h.setFlash(w, r, "error", "Name and URL are required")
		h.redirect(w, r, "/webhooks")
		return
	}

	events := strings.Split(r.FormValue("events"), ",")
	for i := range events {
		events[i] = strings.TrimSpace(events[i])
	}

	retryCount := 3
	if rc := r.FormValue("retry_count"); rc != "" {
		if v, err := strconv.Atoi(rc); err == nil && v >= 0 && v <= 10 {
			retryCount = v
		}
	}
	timeoutSecs := 10
	if ts := r.FormValue("timeout_secs"); ts != "" {
		if v, err := strconv.Atoi(ts); err == nil && v >= 1 && v <= 60 {
			timeoutSecs = v
		}
	}

	wh := &models.OutgoingWebhook{
		Name:        name,
		URL:         webhookURL,
		Events:      events,
		IsEnabled:   r.FormValue("is_enabled") == "on",
		RetryCount:  retryCount,
		TimeoutSecs: timeoutSecs,
	}

	if secret := r.FormValue("secret"); secret != "" {
		wh.Secret = &secret
	}

	if headersStr := r.FormValue("headers"); headersStr != "" {
		var check map[string]string
		if json.Unmarshal([]byte(headersStr), &check) == nil {
			wh.Headers = json.RawMessage(headersStr)
		}
	}

	if user := GetUserFromContext(r.Context()); user != nil {
		if uid, err := uuid.Parse(user.ID); err == nil {
			wh.CreatedBy = &uid
		}
	}

	if err := h.webhookRepo.Create(r.Context(), wh); err != nil {
		slog.Error("Failed to create webhook", "name", wh.Name, "error", err)
		h.setFlash(w, r, "error", "Failed to create webhook: "+err.Error())
		h.redirect(w, r, "/webhooks")
		return
	}

	h.setFlash(w, r, "success", "Webhook created successfully")
	h.redirect(w, r, "/webhooks")
}

// WebhookUpdate handles updating an existing outgoing webhook.
func (h *Handler) WebhookUpdate(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/webhooks")
		return
	}

	if h.webhookRepo == nil {
		h.setFlash(w, r, "error", "Webhook service not configured")
		h.redirect(w, r, "/webhooks")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		h.redirect(w, r, "/webhooks")
		return
	}

	// Fetch existing to preserve fields not in the form
	existing, err := h.webhookRepo.GetByID(r.Context(), id)
	if err != nil {
		h.setFlash(w, r, "error", "Webhook not found")
		h.redirect(w, r, "/webhooks")
		return
	}

	name := r.FormValue("name")
	webhookURL := r.FormValue("url")
	if name == "" || webhookURL == "" {
		h.setFlash(w, r, "error", "Name and URL are required")
		h.redirect(w, r, "/webhooks")
		return
	}

	events := strings.Split(r.FormValue("events"), ",")
	for i := range events {
		events[i] = strings.TrimSpace(events[i])
	}

	retryCount := existing.RetryCount
	if rc := r.FormValue("retry_count"); rc != "" {
		if v, err := strconv.Atoi(rc); err == nil && v >= 0 && v <= 10 {
			retryCount = v
		}
	}
	timeoutSecs := existing.TimeoutSecs
	if ts := r.FormValue("timeout_secs"); ts != "" {
		if v, err := strconv.Atoi(ts); err == nil && v >= 1 && v <= 60 {
			timeoutSecs = v
		}
	}

	existing.Name = name
	existing.URL = webhookURL
	existing.Events = events
	existing.IsEnabled = r.FormValue("is_enabled") == "on"
	existing.RetryCount = retryCount
	existing.TimeoutSecs = timeoutSecs

	// Update secret only if provided
	if secret := r.FormValue("secret"); secret != "" {
		existing.Secret = &secret
	}

	if headersStr := r.FormValue("headers"); headersStr != "" {
		var check map[string]string
		if json.Unmarshal([]byte(headersStr), &check) == nil {
			existing.Headers = json.RawMessage(headersStr)
		}
	}

	if err := h.webhookRepo.Update(r.Context(), existing); err != nil {
		slog.Error("Failed to update webhook", "id", id, "error", err)
		h.setFlash(w, r, "error", "Failed to update webhook: "+err.Error())
		h.redirect(w, r, "/webhooks")
		return
	}

	h.setFlash(w, r, "success", "Webhook updated successfully")
	h.redirect(w, r, "/webhooks")
}

// WebhookDelete handles deletion of an outgoing webhook.
func (h *Handler) WebhookDelete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/webhooks")
		return
	}

	if h.webhookRepo != nil {
		if err := h.webhookRepo.Delete(r.Context(), id); err != nil {
			slog.Error("Failed to delete webhook", "id", id, "error", err)
			h.setFlash(w, r, "error", "Failed to delete webhook: "+err.Error())
			h.redirect(w, r, "/webhooks")
			return
		}
	}

	h.setFlash(w, r, "success", "Webhook deleted")
	h.redirect(w, r, "/webhooks")
}

// AutoDeployCreate handles creation of a new auto-deploy rule.
func (h *Handler) AutoDeployCreate(w http.ResponseWriter, r *http.Request) {
	if h.autoDeployRepo == nil {
		h.setFlash(w, r, "error", "Auto-deploy service not configured")
		h.redirect(w, r, "/webhooks?tab=autodeploy")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		h.redirect(w, r, "/webhooks?tab=autodeploy")
		return
	}

	name := r.FormValue("name")
	sourceRepo := r.FormValue("source_repo")
	if name == "" || sourceRepo == "" {
		h.setFlash(w, r, "error", "Name and source repository are required")
		h.redirect(w, r, "/webhooks?tab=autodeploy")
		return
	}

	rule := &models.AutoDeployRule{
		Name:       name,
		SourceType: r.FormValue("source_type"),
		SourceRepo: sourceRepo,
		Action:     r.FormValue("action"),
		IsEnabled:  r.FormValue("is_enabled") == "on",
	}

	if branch := r.FormValue("source_branch"); branch != "" {
		rule.SourceBranch = &branch
	}
	if stackID := r.FormValue("target_stack_id"); stackID != "" {
		rule.TargetStackID = &stackID
	}
	if service := r.FormValue("target_service"); service != "" {
		rule.TargetService = &service
	}

	if user := GetUserFromContext(r.Context()); user != nil {
		if uid, err := uuid.Parse(user.ID); err == nil {
			rule.CreatedBy = &uid
		}
	}

	if err := h.autoDeployRepo.Create(r.Context(), rule); err != nil {
		slog.Error("Failed to create auto-deploy rule", "name", rule.Name, "error", err)
		h.setFlash(w, r, "error", "Failed to create auto-deploy rule: "+err.Error())
		h.redirect(w, r, "/webhooks?tab=autodeploy")
		return
	}

	h.setFlash(w, r, "success", "Auto-deploy rule created successfully")
	h.redirect(w, r, "/webhooks?tab=autodeploy")
}

// AutoDeployDelete handles deletion of an auto-deploy rule.
func (h *Handler) AutoDeployDelete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/webhooks?tab=autodeploy")
		return
	}

	if h.autoDeployRepo != nil {
		if err := h.autoDeployRepo.Delete(r.Context(), id); err != nil {
			slog.Error("Failed to delete auto-deploy rule", "id", id, "error", err)
			h.setFlash(w, r, "error", "Failed to delete auto-deploy rule: "+err.Error())
			h.redirect(w, r, "/webhooks?tab=autodeploy")
			return
		}
	}

	h.setFlash(w, r, "success", "Auto-deploy rule deleted")
	h.redirect(w, r, "/webhooks?tab=autodeploy")
}
