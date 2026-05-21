// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	mnttmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/maintenance"
)

// maintenanceActions defines the actions for a maintenance window.
type maintenanceActions struct {
	StopContainers    bool `json:"stop_containers"`
	PruneImages       bool `json:"prune_images"`
	PruneVolumes      bool `json:"prune_volumes"`
	PruneNetworks     bool `json:"prune_networks"`
	RestartContainers bool `json:"restart_containers"`
	UpdateImages      bool `json:"update_images"`
	BackupFirst       bool `json:"backup_first"`
}

// MaintenanceTempl renders the maintenance windows page.
func (h *Handler) MaintenanceTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Maintenance Windows", "maintenance")

	// Get hosts for dropdown
	var hosts []mnttmpl.HostOption
	if hostSvc := h.services.Hosts(); hostSvc != nil {
		if hostList, err := hostSvc.List(ctx); err == nil {
			for _, host := range hostList {
				name := host.DisplayName
				if name == "" {
					name = host.ID
				}
				hosts = append(hosts, mnttmpl.HostOption{
					ID:   host.ID,
					Name: name,
				})
			}
		}
	}

	var windows []mnttmpl.MaintenanceWindowView
	stats := mnttmpl.MaintenanceStats{}

	if h.maintenanceRepo != nil {
		dbWindows, err := h.maintenanceRepo.List(ctx)
		if err == nil {
			for _, mw := range dbWindows {
				var actions maintenanceActions
				if len(mw.Actions) > 0 {
					_ = json.Unmarshal(mw.Actions, &actions) // best-effort decode; zero-value defaults are acceptable for render
				}

				wv := mnttmpl.MaintenanceWindowView{
					ID:              mw.ID.String(),
					Name:            mw.Name,
					Description:     mw.Description,
					HostID:          mw.HostID,
					HostName:        mw.HostName,
					Schedule:        mw.Schedule,
					ScheduleHuman:   cronToHuman(mw.Schedule),
					Duration:        formatMinutes(mw.DurationMinutes),
					DurationMinutes: mw.DurationMinutes,
					Actions: mnttmpl.MaintenanceActions{
						StopContainers:    actions.StopContainers,
						PruneImages:       actions.PruneImages,
						PruneVolumes:      actions.PruneVolumes,
						PruneNetworks:     actions.PruneNetworks,
						RestartContainers: actions.RestartContainers,
						UpdateImages:      actions.UpdateImages,
						BackupFirst:       actions.BackupFirst,
					},
					IsEnabled:  mw.IsEnabled,
					IsActive:   mw.IsActive,
					LastStatus: mw.LastStatus,
					CreatedAt:  mw.CreatedAt.Format("Jan 02 15:04"),
				}
				if mw.LastRunAt != nil {
					wv.LastRunAt = mw.LastRunAt.Format("Jan 02 15:04")
				}
				windows = append(windows, wv)
				stats.TotalWindows++
				if mw.IsEnabled {
					stats.ActiveWindows++
				}
				if mw.IsActive {
					stats.ScheduledToday++
				}
			}
		}
	}

	data := mnttmpl.MaintenanceData{
		PageData: pageData,
		Windows:  windows,
		Hosts:    hosts,
		Stats:    stats,
	}

	h.renderTempl(w, r, mnttmpl.Maintenance(data))
}

// MaintenanceCreate creates a new maintenance window.
// maintenanceCreateForm captures the maintenance-window inputs.
// The action_* fields are individual checkboxes that map to
// maintenanceActions.
type maintenanceCreateForm struct {
	Name                    string `form:"name" validate:"required"`
	Description             string `form:"description"`
	HostID                  string `form:"host_id"`
	Schedule                string `form:"schedule"`
	DurationMinutes         int    `form:"duration_minutes" validate:"gte=0"`
	ActionStopContainers    bool   `form:"action_stop_containers"`
	ActionRestartContainers bool   `form:"action_restart_containers"`
	ActionPruneImages       bool   `form:"action_prune_images"`
	ActionPruneVolumes      bool   `form:"action_prune_volumes"`
	ActionPruneNetworks     bool   `form:"action_prune_networks"`
	ActionUpdateImages      bool   `form:"action_update_images"`
	ActionBackupFirst       bool   `form:"action_backup_first"`
}

func (h *Handler) MaintenanceCreate(w http.ResponseWriter, r *http.Request) {
	var form maintenanceCreateForm
	if msg := BindForm(r, &form); msg != "" {
		h.setFlash(w, r, "error", msg)
		http.Redirect(w, r, "/maintenance", http.StatusSeeOther)
		return
	}

	durationMinutes := form.DurationMinutes
	if durationMinutes < 5 {
		durationMinutes = 60
	}

	hostID := form.HostID
	hostName := "All Hosts"
	if hostID != "all" {
		if hostSvc := h.services.Hosts(); hostSvc != nil {
			if host, err := hostSvc.Get(r.Context(), hostID); err == nil {
				hostName = host.DisplayName
				if hostName == "" {
					hostName = hostID
				}
			}
		}
	} else {
		hostID = ""
	}

	actions := maintenanceActions{
		StopContainers:    form.ActionStopContainers,
		RestartContainers: form.ActionRestartContainers,
		PruneImages:       form.ActionPruneImages,
		PruneVolumes:      form.ActionPruneVolumes,
		PruneNetworks:     form.ActionPruneNetworks,
		UpdateImages:      form.ActionUpdateImages,
		BackupFirst:       form.ActionBackupFirst,
	}

	actionsJSON, _ := json.Marshal(actions)

	if h.maintenanceRepo != nil {
		mw := &MaintenanceWindowRecord{
			ID:              uuid.New(),
			Name:            form.Name,
			Description:     form.Description,
			HostID:          hostID,
			HostName:        hostName,
			Schedule:        form.Schedule,
			DurationMinutes: durationMinutes,
			Actions:         actionsJSON,
			IsEnabled:       true,
		}
		if err := h.maintenanceRepo.Create(r.Context(), mw); err != nil {
			h.setFlash(w, r, "error", "Failed to create maintenance window: "+err.Error())
			http.Redirect(w, r, "/maintenance", http.StatusSeeOther)
			return
		}
	}

	h.setFlash(w, r, "success", "Maintenance window '"+form.Name+"' created")
	http.Redirect(w, r, "/maintenance", http.StatusSeeOther)
}

// MaintenanceToggle toggles a maintenance window enabled/disabled.
func (h *Handler) MaintenanceToggle(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if h.maintenanceRepo != nil {
		uid, err := uuid.Parse(id)
		if err == nil {
			newState, err := h.maintenanceRepo.Toggle(r.Context(), uid)
			if err == nil {
				status := "disabled"
				if newState {
					status = "enabled"
				}
				h.setFlash(w, r, "success", "Maintenance window "+status)
			} else {
				h.setFlash(w, r, "error", "Maintenance window not found")
			}
		}
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/maintenance")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/maintenance", http.StatusSeeOther)
}

// MaintenanceDelete deletes a maintenance window.
func (h *Handler) MaintenanceDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if h.maintenanceRepo != nil {
		uid, err := uuid.Parse(id)
		if err == nil {
			if err := h.maintenanceRepo.Delete(r.Context(), uid); err != nil {
				h.logger.Warn("failed to delete maintenance window", "id", uid, "error", err)
			}
		}
	}

	h.setFlash(w, r, "success", "Maintenance window deleted")

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/maintenance")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/maintenance", http.StatusSeeOther)
}

// MaintenanceExecute manually triggers a maintenance window.
func (h *Handler) MaintenanceExecute(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx := r.Context()

	if h.maintenanceRepo == nil {
		h.setFlash(w, r, "error", "Maintenance repository unavailable")
		http.Redirect(w, r, "/maintenance", http.StatusSeeOther)
		return
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		h.setFlash(w, r, "error", "Invalid window ID")
		http.Redirect(w, r, "/maintenance", http.StatusSeeOther)
		return
	}

	mw, err := h.maintenanceRepo.GetByID(ctx, uid)
	if err != nil {
		h.setFlash(w, r, "error", "Maintenance window not found")
		http.Redirect(w, r, "/maintenance", http.StatusSeeOther)
		return
	}

	var actions maintenanceActions
	if len(mw.Actions) > 0 {
		_ = json.Unmarshal(mw.Actions, &actions) // best-effort decode; zero-value defaults are acceptable
	}

	// Mark as active
	if err := h.maintenanceRepo.SetActive(ctx, uid, true); err != nil {
		h.logger.Warn("failed to mark maintenance window active", "id", uid, "error", err)
	}

	var actionsPerformed []string
	var execErr error

	containerSvc := h.services.Containers()
	imageSvc := h.services.Images()
	volumeSvc := h.services.Volumes()
	networkSvc := h.services.Networks()

	// 1. Stop containers if requested
	if actions.StopContainers && containerSvc != nil {
		if containers, err := containerSvc.List(ctx, nil); err == nil {
			stopped := 0
			for _, c := range containers {
				if c.State == "running" {
					if err := containerSvc.Stop(ctx, c.ID); err == nil {
						stopped++
					}
				}
			}
			actionsPerformed = append(actionsPerformed, fmt.Sprintf("stopped %d containers", stopped))
		}
	}

	// 2. Prune images. This is the first error-producing step; execErr
	// is still its zero value, so the "keep the first" guard collapses
	// to an unconditional assignment here.
	if actions.PruneImages && imageSvc != nil {
		if freed, err := imageSvc.Prune(ctx); err == nil {
			actionsPerformed = append(actionsPerformed, fmt.Sprintf("pruned images (%s freed)", formatBytes(freed)))
		} else {
			execErr = err
		}
	}

	// 3. Prune volumes
	if actions.PruneVolumes && volumeSvc != nil {
		if freed, err := volumeSvc.Prune(ctx); err == nil {
			actionsPerformed = append(actionsPerformed, fmt.Sprintf("pruned volumes (%s freed)", formatBytes(freed)))
		} else if execErr == nil {
			execErr = err
		}
	}

	// 4. Prune networks
	if actions.PruneNetworks && networkSvc != nil {
		if _, err := networkSvc.Prune(ctx); err == nil {
			actionsPerformed = append(actionsPerformed, "pruned networks")
		} else if execErr == nil {
			execErr = err
		}
	}

	// 5. Restart containers
	if actions.RestartContainers && containerSvc != nil {
		if containers, err := containerSvc.List(ctx, nil); err == nil {
			restarted := 0
			for _, c := range containers {
				if c.State == "running" {
					if err := containerSvc.Restart(ctx, c.ID); err == nil {
						restarted++
					}
				}
			}
			actionsPerformed = append(actionsPerformed, fmt.Sprintf("restarted %d containers", restarted))
		}
	}

	// Mark as complete
	now := time.Now()
	status := "success"
	if execErr != nil {
		status = "partial"
	}

	h.maintenanceRepo.SetActive(ctx, uid, false)
	h.maintenanceRepo.UpdateLastRun(ctx, uid, now, status)

	if len(actionsPerformed) > 0 {
		h.setFlash(w, r, "success", "Maintenance completed: "+strings.Join(actionsPerformed, ", "))
	} else {
		h.setFlash(w, r, "info", "Maintenance window executed with no actions")
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/maintenance")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/maintenance", http.StatusSeeOther)
}

// cronToHuman converts a cron expression to a human-readable string.
func cronToHuman(cron string) string {
	switch cron {
	case "0 2 * * 0":
		return "Weekly (Sunday 2 AM)"
	case "0 3 * * *":
		return "Daily (3 AM)"
	case "0 2 1 * *":
		return "Monthly (1st at 2 AM)"
	case "0 4 * * 6":
		return "Weekly (Saturday 4 AM)"
	case "0 0 * * *":
		return "Daily (Midnight)"
	default:
		return cron
	}
}

// formatMinutes formats minutes into a readable duration string.
func formatMinutes(minutes int) string {
	if minutes < 60 {
		return fmt.Sprintf("%dm", minutes)
	}
	hours := minutes / 60
	remaining := minutes % 60
	if remaining == 0 {
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dh %dm", hours, remaining)
}
