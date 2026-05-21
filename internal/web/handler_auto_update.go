// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	updatestmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/updates"
)

// AutoUpdatePoliciesTempl renders the auto-update policies page.
func (h *Handler) AutoUpdatePoliciesTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	updatesSvc := h.services.Updates()

	// Get policies
	var policies []UpdatePolicyView
	if updatesSvc != nil {
		policies, _ = updatesSvc.ListPolicies(ctx)
	}

	// Get containers for adding new policies
	var containers []updatestmpl.ContainerBasic
	containerSvc := h.services.Containers()
	if containerSvc != nil {
		if list, err := containerSvc.List(ctx, nil); err == nil {
			for _, c := range list {
				name := c.Name
				if len(name) > 0 && name[0] == '/' {
					name = name[1:]
				}
				containers = append(containers, updatestmpl.ContainerBasic{
					ID:   c.ID,
					Name: name,
				})
			}
		}
	}

	// Convert policies to template view
	var policyItems []updatestmpl.PolicyItem
	for _, p := range policies {
		policyItems = append(policyItems, updatestmpl.PolicyItem{
			ID:                p.ID,
			TargetName:        p.TargetName,
			TargetID:          p.TargetID,
			IsEnabled:         p.IsEnabled,
			AutoUpdate:        p.AutoUpdate,
			AutoBackup:        p.AutoBackup,
			Schedule:          p.Schedule,
			IncludePrerelease: p.IncludePrerelease,
			NotifyOnUpdate:    p.NotifyOnUpdate,
			NotifyOnFailure:   p.NotifyOnFailure,
			MaxRetries:        p.MaxRetries,
			HealthCheckWait:   p.HealthCheckWait,
		})
	}

	// Get update history and available for full page context
	var available []UpdateView
	var history []UpdateHistoryView
	if updatesSvc != nil {
		available, _ = updatesSvc.ListAvailable(ctx)
		history, _ = updatesSvc.GetHistory(ctx)
	}

	p := h.preparePageData(r, "Auto-Update", "updates")
	data := ToTemplUpdatesListData(p, available, history)
	data.Containers = containers
	data.Policies = policyItems
	data.ActiveTab = "policies"

	h.renderTempl(w, r, updatestmpl.List(data))
}

// AutoUpdatePolicyCreate creates a new auto-update policy.
func (h *Handler) AutoUpdatePolicyCreate(w http.ResponseWriter, r *http.Request) {
	updatesSvc := h.services.Updates()
	if updatesSvc == nil {
		h.setFlash(w, r, "error", "Updates service is not configured")
		http.Redirect(w, r, "/updates?tab=policies", http.StatusSeeOther)
		return
	}

	var form autoUpdatePolicyForm
	if msg := BindForm(r, &form); msg != "" {
		h.setFlash(w, r, "error", msg)
		http.Redirect(w, r, "/updates?tab=policies", http.StatusSeeOther)
		return
	}

	maxRetries := form.MaxRetries
	if maxRetries == 0 {
		maxRetries = 3
	}
	healthCheckWait := form.HealthCheckWait
	if healthCheckWait == 0 {
		healthCheckWait = 30
	}

	policy := UpdatePolicyView{
		TargetType:        "container",
		TargetID:          form.ContainerID,
		TargetName:        form.ContainerName,
		IsEnabled:         true,
		AutoUpdate:        form.AutoUpdate,
		AutoBackup:        form.AutoBackup,
		IncludePrerelease: form.IncludePrerelease,
		Schedule:          form.Schedule,
		NotifyOnUpdate:    form.NotifyUpdate,
		NotifyOnFailure:   form.NotifyFailure,
		MaxRetries:        maxRetries,
		HealthCheckWait:   healthCheckWait,
	}

	if err := updatesSvc.SetPolicy(r.Context(), policy); err != nil {
		h.logger.Error("failed to create auto-update policy", "error", err)
		h.setFlash(w, r, "error", "Failed to create policy: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Auto-update policy created for "+form.ContainerName)
	}

	http.Redirect(w, r, "/updates?tab=policies", http.StatusSeeOther)
}

// autoUpdatePolicyForm captures the create-policy inputs.
// max_retries / health_check_wait default to 3 / 30 when blank;
// the substitution lives in the handler because the validator
// cannot express "0 means use this default".
type autoUpdatePolicyForm struct {
	ContainerID       string `form:"container_id" validate:"required"`
	ContainerName     string `form:"container_name"`
	MaxRetries        int    `form:"max_retries" validate:"gte=0"`
	HealthCheckWait   int    `form:"health_check_wait" validate:"gte=0"`
	AutoUpdate        bool   `form:"auto_update"`
	AutoBackup        bool   `form:"auto_backup"`
	IncludePrerelease bool   `form:"include_prerelease"`
	Schedule          string `form:"schedule"`
	NotifyUpdate      bool   `form:"notify_update"`
	NotifyFailure     bool   `form:"notify_failure"`
}

// AutoUpdatePolicyToggle toggles an auto-update policy on/off.
func (h *Handler) AutoUpdatePolicyToggle(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	updatesSvc := h.services.Updates()
	if updatesSvc != nil {
		policies, _ := updatesSvc.ListPolicies(r.Context())
		for _, p := range policies {
			if p.ID == id {
				p.IsEnabled = !p.IsEnabled
				if err := updatesSvc.SetPolicy(r.Context(), p); err != nil {
					h.setFlash(w, r, "error", "Failed to toggle policy")
				} else {
					status := "disabled"
					if p.IsEnabled {
						status = "enabled"
					}
					h.setFlash(w, r, "success", "Policy "+status+" for "+p.TargetName)
				}
				break
			}
		}
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/updates?tab=policies")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/updates?tab=policies", http.StatusSeeOther)
}

// AutoUpdatePolicyDelete deletes an auto-update policy.
func (h *Handler) AutoUpdatePolicyDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if updatesSvc := h.services.Updates(); updatesSvc != nil {
		if err := updatesSvc.DeletePolicy(r.Context(), id); err != nil {
			h.setFlash(w, r, "error", "Failed to delete policy: "+err.Error())
		} else {
			h.setFlash(w, r, "success", "Auto-update policy removed")
		}
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/updates?tab=policies")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/updates?tab=policies", http.StatusSeeOther)
}
