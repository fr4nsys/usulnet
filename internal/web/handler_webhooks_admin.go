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
		h.redirect(w, r, "/webhooks")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.redirect(w, r, "/webhooks")
		return
	}

	events := strings.Split(r.FormValue("events"), ",")
	for i := range events {
		events[i] = strings.TrimSpace(events[i])
	}

	wh := &models.OutgoingWebhook{
		Name:        r.FormValue("name"),
		URL:         r.FormValue("url"),
		Events:      events,
		IsEnabled:   r.FormValue("is_enabled") == "on",
		RetryCount:  3,
		TimeoutSecs: 10,
	}

	if secret := r.FormValue("secret"); secret != "" {
		wh.Secret = &secret
	}

	// Custom headers as JSON
	if headersStr := r.FormValue("headers"); headersStr != "" {
		wh.Headers = json.RawMessage(headersStr)
	}

	if user := GetUserFromContext(r.Context()); user != nil {
		if uid, err := uuid.Parse(user.ID); err == nil {
			wh.CreatedBy = &uid
		}
	}

	if err := h.webhookRepo.Create(r.Context(), wh); err != nil {
		slog.Error("Failed to create webhook", "name", wh.Name, "error", err)
	}

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
		}
	}

	h.redirect(w, r, "/webhooks")
}

// AutoDeployCreate handles creation of a new auto-deploy rule.
func (h *Handler) AutoDeployCreate(w http.ResponseWriter, r *http.Request) {
	if h.autoDeployRepo == nil {
		h.redirect(w, r, "/webhooks?tab=autodeploy")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.redirect(w, r, "/webhooks?tab=autodeploy")
		return
	}

	rule := &models.AutoDeployRule{
		Name:       r.FormValue("name"),
		SourceType: r.FormValue("source_type"),
		SourceRepo: r.FormValue("source_repo"),
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
	}

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
		}
	}

	h.redirect(w, r, "/webhooks?tab=autodeploy")
}
