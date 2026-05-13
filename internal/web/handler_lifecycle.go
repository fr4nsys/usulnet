// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	lifecycletmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/lifecycle"
)

// LifecyclePoliciesTempl renders the lifecycle policies page.
func (h *Handler) LifecyclePoliciesTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Lifecycle Policies", "lifecycle")

	// Collect cleanup stats from Docker
	var stats lifecycletmpl.CleanupStatsView

	containerSvc := h.services.Containers()
	imageSvc := h.services.Images()
	volumeSvc := h.services.Volumes()
	networkSvc := h.services.Networks()

	// Count dangling images
	if imageSvc != nil {
		if images, err := imageSvc.List(ctx); err == nil {
			for _, img := range images {
				if !img.InUse && len(img.Tags) == 0 {
					stats.DanglingImages++
				}
			}
		}
	}

	// Count stopped containers
	if containerSvc != nil {
		if containers, err := containerSvc.List(ctx, nil); err == nil {
			for _, c := range containers {
				if c.State == "exited" || c.State == "dead" {
					stats.StoppedContainers++
				}
			}
		}
	}

	// Count unused volumes
	if volumeSvc != nil {
		if volumes, err := volumeSvc.List(ctx); err == nil {
			for _, v := range volumes {
				if !v.InUse {
					stats.UnusedVolumes++
				}
			}
		}
	}

	// Count unused networks (non-system with no containers)
	if networkSvc != nil {
		if networks, err := networkSvc.List(ctx); err == nil {
			for _, n := range networks {
				if n.Name != "bridge" && n.Name != "host" && n.Name != "none" && n.ContainerCount == 0 {
					stats.UnusedNetworks++
				}
			}
		}
	}

	var policies []lifecycletmpl.PolicyView
	var history []lifecycletmpl.CleanupHistoryItem

	if h.lifecycleRepo != nil {
		// Build policy views from DB
		dbPolicies, err := h.lifecycleRepo.ListPolicies(ctx)
		if err == nil {
			for _, p := range dbPolicies {
				pv := lifecycletmpl.PolicyView{
					ID:           p.ID.String(),
					Name:         p.Name,
					Description:  p.Description,
					ResourceType: p.ResourceType,
					Action:       p.Action,
					Schedule:     p.Schedule,
					IsEnabled:    p.IsEnabled,
					CreatedAt:    p.CreatedAt.Format("Jan 02 15:04"),
					LastResult:   p.LastResult,
					Conditions: lifecycletmpl.PolicyConditions{
						MaxAgeDays:    p.MaxAgeDays,
						OnlyDangling:  p.OnlyDangling,
						OnlyStopped:   p.OnlyStopped,
						OnlyUnused:    p.OnlyUnused,
						ExcludeLabels: p.ExcludeLabels,
						IncludeLabels: p.IncludeLabels,
						KeepLatest:    p.KeepLatest,
					},
				}
				if p.LastExecutedAt != nil {
					pv.LastExecutedAt = p.LastExecutedAt.Format("Jan 02 15:04")
				}
				if p.IsEnabled {
					stats.ActivePolicies++
				}
				policies = append(policies, pv)
			}
			stats.TotalPolicies = len(dbPolicies)
		}

		// Build history from DB
		dbHistory, err := h.lifecycleRepo.ListHistory(ctx, 100)
		if err == nil {
			for _, entry := range dbHistory {
				history = append(history, lifecycletmpl.CleanupHistoryItem{
					ID:           entry.ID.String(),
					PolicyName:   entry.PolicyName,
					ResourceType: entry.ResourceType,
					Action:       entry.Action,
					ItemsRemoved: entry.ItemsRemoved,
					SpaceFreed:   formatBytes(entry.SpaceFreed),
					Status:       entry.Status,
					ExecutedAt:   entry.ExecutedAt.Format("Jan 02 15:04"),
					Duration:     (time.Duration(entry.DurationMs) * time.Millisecond).String(),
					Error:        entry.ErrorMessage,
				})
				stats.TotalCleanups++
				stats.ItemsRemoved += entry.ItemsRemoved
			}
		}

		totalReclaimed, err := h.lifecycleRepo.TotalSpaceReclaimed(ctx)
		if err == nil {
			stats.SpaceReclaimed = formatBytes(totalReclaimed)
		} else {
			stats.SpaceReclaimed = "Unavailable"
		}
	} else {
		stats.SpaceReclaimed = "—"
	}

	data := lifecycletmpl.LifecycleData{
		PageData: pageData,
		Policies: policies,
		Stats:    stats,
		History:  history,
	}

	h.renderTempl(w, r, lifecycletmpl.Lifecycle(data))
}

// LifecyclePolicyCreate creates a new lifecycle policy.
func (h *Handler) LifecyclePolicyCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		http.Redirect(w, r, "/lifecycle", http.StatusSeeOther)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		h.setFlash(w, r, "error", "Policy name is required")
		http.Redirect(w, r, "/lifecycle", http.StatusSeeOther)
		return
	}

	maxAgeDays, _ := strconv.Atoi(r.FormValue("max_age_days"))
	keepLatest, _ := strconv.Atoi(r.FormValue("keep_latest"))

	if h.lifecycleRepo != nil {
		p := &LifecyclePolicyRecord{
			ID:            uuid.New(),
			Name:          name,
			Description:   strings.TrimSpace(r.FormValue("description")),
			ResourceType:  r.FormValue("resource_type"),
			Action:        r.FormValue("action"),
			Schedule:      r.FormValue("schedule"),
			IsEnabled:     true,
			OnlyDangling:  r.FormValue("only_dangling") == "on",
			OnlyStopped:   r.FormValue("only_stopped") == "on",
			OnlyUnused:    r.FormValue("only_unused") == "on",
			MaxAgeDays:    maxAgeDays,
			KeepLatest:    keepLatest,
			ExcludeLabels: strings.TrimSpace(r.FormValue("exclude_labels")),
			IncludeLabels: strings.TrimSpace(r.FormValue("include_labels")),
		}
		if err := h.lifecycleRepo.CreatePolicy(r.Context(), p); err != nil {
			h.setFlash(w, r, "error", "Failed to create policy: "+err.Error())
			http.Redirect(w, r, "/lifecycle", http.StatusSeeOther)
			return
		}
	}

	h.setFlash(w, r, "success", "Lifecycle policy '"+name+"' created")
	http.Redirect(w, r, "/lifecycle", http.StatusSeeOther)
}

// LifecyclePolicyToggle toggles a policy enabled/disabled.
func (h *Handler) LifecyclePolicyToggle(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if h.lifecycleRepo != nil {
		uid, err := uuid.Parse(id)
		if err == nil {
			newState, err := h.lifecycleRepo.TogglePolicy(r.Context(), uid)
			if err == nil {
				status := "disabled"
				if newState {
					status = "enabled"
				}
				h.setFlash(w, r, "success", "Policy "+status)
			} else {
				h.setFlash(w, r, "error", "Policy not found")
			}
		}
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/lifecycle")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/lifecycle", http.StatusSeeOther)
}

// LifecyclePolicyDelete deletes a lifecycle policy.
func (h *Handler) LifecyclePolicyDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if h.lifecycleRepo != nil {
		uid, err := uuid.Parse(id)
		if err == nil {
			h.lifecycleRepo.DeletePolicy(r.Context(), uid)
		}
	}

	h.setFlash(w, r, "success", "Lifecycle policy deleted")

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/lifecycle")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/lifecycle", http.StatusSeeOther)
}

// LifecyclePolicyExecute executes a lifecycle policy immediately.
func (h *Handler) LifecyclePolicyExecute(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx := r.Context()

	if h.lifecycleRepo == nil {
		h.setFlash(w, r, "error", "Lifecycle repository unavailable")
		http.Redirect(w, r, "/lifecycle", http.StatusSeeOther)
		return
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		h.setFlash(w, r, "error", "Invalid policy ID")
		http.Redirect(w, r, "/lifecycle", http.StatusSeeOther)
		return
	}

	p, err := h.lifecycleRepo.GetPolicy(ctx, uid)
	if err != nil {
		h.setFlash(w, r, "error", "Policy not found")
		http.Redirect(w, r, "/lifecycle", http.StatusSeeOther)
		return
	}

	start := time.Now()
	var itemsRemoved int64
	var spaceFreed int64
	var execErr error

	switch p.ResourceType {
	case "image":
		if imageSvc := h.services.Images(); imageSvc != nil {
			freed, err := imageSvc.Prune(ctx)
			if err != nil {
				execErr = err
			} else {
				spaceFreed = freed
				itemsRemoved = 1
			}
		}
	case "volume":
		if volumeSvc := h.services.Volumes(); volumeSvc != nil {
			freed, err := volumeSvc.Prune(ctx)
			if err != nil {
				execErr = err
			} else {
				spaceFreed = freed
				itemsRemoved = 1
			}
		}
	case "network":
		if networkSvc := h.services.Networks(); networkSvc != nil {
			freed, err := networkSvc.Prune(ctx)
			if err != nil {
				execErr = err
			} else {
				_ = freed
				itemsRemoved = 1
			}
		}
	case "container":
		if containerSvc := h.services.Containers(); containerSvc != nil {
			containers, err := containerSvc.List(ctx, nil)
			if err == nil {
				for _, c := range containers {
					if c.State == "exited" || c.State == "dead" {
						if err := containerSvc.Remove(ctx, c.ID, true); err == nil {
							itemsRemoved++
						}
					}
				}
			}
		}
	}

	duration := time.Since(start)

	status := "success"
	errMsg := ""
	if execErr != nil {
		status = "failed"
		errMsg = execErr.Error()
	}

	// Record history in DB
	policyID := p.ID
	entry := &LifecycleHistoryRecord{
		ID:           uuid.New(),
		PolicyID:     &policyID,
		PolicyName:   p.Name,
		ResourceType: p.ResourceType,
		Action:       p.Action,
		ItemsRemoved: itemsRemoved,
		SpaceFreed:   spaceFreed,
		Status:       status,
		DurationMs:   int(duration.Milliseconds()),
		ErrorMessage: errMsg,
		ExecutedAt:   time.Now(),
	}
	h.lifecycleRepo.CreateHistoryEntry(ctx, entry)
	h.lifecycleRepo.UpdateLastExecution(ctx, uid, time.Now(), status)

	if execErr != nil {
		h.setFlash(w, r, "error", "Policy execution failed: "+execErr.Error())
	} else {
		h.setFlash(w, r, "success", fmt.Sprintf("Policy executed: %d items removed, %s freed", itemsRemoved, formatBytes(spaceFreed)))
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/lifecycle")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/lifecycle", http.StatusSeeOther)
}
