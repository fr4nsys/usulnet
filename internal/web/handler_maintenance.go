// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
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
					json.Unmarshal(mw.Actions, &actions)
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
func (h *Handler) MaintenanceCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		http.Redirect(w, r, "/maintenance", http.StatusSeeOther)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		h.setFlash(w, r, "error", "Window name is required")
		http.Redirect(w, r, "/maintenance", http.StatusSeeOther)
		return
	}

	durationMinutes, _ := strconv.Atoi(r.FormValue("duration_minutes"))
	if durationMinutes < 5 {
		durationMinutes = 60
	}

	hostID := r.FormValue("host_id")
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
		StopContainers:    r.FormValue("action_stop_containers") == "on",
		RestartContainers: r.FormValue("action_restart_containers") == "on",
		PruneImages:       r.FormValue("action_prune_images") == "on",
		PruneVolumes:      r.FormValue("action_prune_volumes") == "on",
		PruneNetworks:     r.FormValue("action_prune_networks") == "on",
		UpdateImages:      r.FormValue("action_update_images") == "on",
		BackupFirst:       r.FormValue("action_backup_first") == "on",
	}

	actionsJSON, _ := json.Marshal(actions)

	if h.maintenanceRepo != nil {
		mw := &MaintenanceWindowRecord{
			ID:              uuid.New(),
			Name:            name,
			Description:     strings.TrimSpace(r.FormValue("description")),
			HostID:          hostID,
			HostName:        hostName,
			Schedule:        r.FormValue("schedule"),
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

	h.setFlash(w, r, "success", "Maintenance window '"+name+"' created")
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
			h.maintenanceRepo.Delete(r.Context(), uid)
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
		json.Unmarshal(mw.Actions, &actions)
	}

	// Mark as active
	h.maintenanceRepo.SetActive(ctx, uid, true)

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

	// 2. Prune images
	if actions.PruneImages && imageSvc != nil {
		if freed, err := imageSvc.Prune(ctx); err == nil {
			actionsPerformed = append(actionsPerformed, fmt.Sprintf("pruned images (%s freed)", formatBytes(freed)))
		} else if execErr == nil {
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
