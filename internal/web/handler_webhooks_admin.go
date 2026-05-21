// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
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
// webhookForm captures the outgoing-webhook inputs shared
// between Create and Update. events is a comma-separated list
// split into a slice after binding; headers is a raw JSON
// payload validated by json.Unmarshal before being stored.
type webhookForm struct {
	Name        string `form:"name" validate:"required"`
	URL         string `form:"url" validate:"required"`
	Events      string `form:"events"`
	IsEnabled   bool   `form:"is_enabled"`
	RetryCount  int    `form:"retry_count" validate:"gte=0,lte=10"`
	TimeoutSecs int    `form:"timeout_secs" validate:"gte=0,lte=60"`
	Secret      string `form:"secret"`
	Headers     string `form:"headers"`
}

func (h *Handler) WebhookCreate(w http.ResponseWriter, r *http.Request) {
	if h.webhookRepo == nil {
		h.setFlash(w, r, "error", "Webhook service not configured")
		h.redirect(w, r, "/webhooks")
		return
	}

	var form webhookForm
	if msg := BindForm(r, &form); msg != "" {
		h.setFlash(w, r, "error", msg)
		h.redirect(w, r, "/webhooks")
		return
	}

	events := strings.Split(form.Events, ",")
	for i := range events {
		events[i] = strings.TrimSpace(events[i])
	}

	retryCount := form.RetryCount
	if retryCount == 0 {
		retryCount = 3
	}
	timeoutSecs := form.TimeoutSecs
	if timeoutSecs == 0 {
		timeoutSecs = 10
	}

	wh := &models.OutgoingWebhook{
		Name:        form.Name,
		URL:         form.URL,
		Events:      events,
		IsEnabled:   form.IsEnabled,
		RetryCount:  retryCount,
		TimeoutSecs: timeoutSecs,
	}

	if form.Secret != "" {
		secret := form.Secret
		wh.Secret = &secret
	}

	if form.Headers != "" {
		var check map[string]string
		if json.Unmarshal([]byte(form.Headers), &check) == nil {
			wh.Headers = json.RawMessage(form.Headers)
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

	var form webhookForm
	if msg := BindForm(r, &form); msg != "" {
		h.setFlash(w, r, "error", msg)
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

	events := strings.Split(form.Events, ",")
	for i := range events {
		events[i] = strings.TrimSpace(events[i])
	}

	retryCount := existing.RetryCount
	if form.RetryCount > 0 {
		retryCount = form.RetryCount
	}
	timeoutSecs := existing.TimeoutSecs
	if form.TimeoutSecs > 0 {
		timeoutSecs = form.TimeoutSecs
	}

	existing.Name = form.Name
	existing.URL = form.URL
	existing.Events = events
	existing.IsEnabled = form.IsEnabled
	existing.RetryCount = retryCount
	existing.TimeoutSecs = timeoutSecs

	// Update secret only if provided
	if form.Secret != "" {
		secret := form.Secret
		existing.Secret = &secret
	}

	if form.Headers != "" {
		var check map[string]string
		if json.Unmarshal([]byte(form.Headers), &check) == nil {
			existing.Headers = json.RawMessage(form.Headers)
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

// autoDeployForm captures the auto-deploy rule inputs.
type autoDeployForm struct {
	Name          string `form:"name" validate:"required"`
	SourceType    string `form:"source_type"`
	SourceRepo    string `form:"source_repo" validate:"required"`
	SourceBranch  string `form:"source_branch"`
	TargetStackID string `form:"target_stack_id"`
	TargetService string `form:"target_service"`
	Action        string `form:"action"`
	IsEnabled     bool   `form:"is_enabled"`
}

// AutoDeployCreate handles creation of a new auto-deploy rule.
func (h *Handler) AutoDeployCreate(w http.ResponseWriter, r *http.Request) {
	if h.autoDeployRepo == nil {
		h.setFlash(w, r, "error", "Auto-deploy service not configured")
		h.redirect(w, r, "/webhooks?tab=autodeploy")
		return
	}

	var form autoDeployForm
	if msg := BindForm(r, &form); msg != "" {
		h.setFlash(w, r, "error", msg)
		h.redirect(w, r, "/webhooks?tab=autodeploy")
		return
	}

	rule := &models.AutoDeployRule{
		Name:       form.Name,
		SourceType: form.SourceType,
		SourceRepo: form.SourceRepo,
		Action:     form.Action,
		IsEnabled:  form.IsEnabled,
	}

	if form.SourceBranch != "" {
		b := form.SourceBranch
		rule.SourceBranch = &b
	}
	if form.TargetStackID != "" {
		s := form.TargetStackID
		rule.TargetStackID = &s
	}
	if form.TargetService != "" {
		s := form.TargetService
		rule.TargetService = &s
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
