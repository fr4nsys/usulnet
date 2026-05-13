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

	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	quotastmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/quotas"
)

// QuotasTempl renders the resource quotas page.
func (h *Handler) QuotasTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Resource Quotas", "quotas")

	// Get current resource usage
	usage := quotastmpl.ResourceUsageView{}
	var alerts []quotastmpl.QuotaAlertView

	containerSvc := h.services.Containers()
	imageSvc := h.services.Images()
	volumeSvc := h.services.Volumes()

	// Container stats
	if containerSvc != nil {
		if containers, err := containerSvc.List(ctx, nil); err == nil {
			usage.ContainersTotal = len(containers)
			for _, c := range containers {
				switch c.State {
				case "running":
					usage.ContainersRunning++
				default:
					usage.ContainersStopped++
				}
			}
		}
	}

	// Image stats
	if imageSvc != nil {
		if images, err := imageSvc.List(ctx); err == nil {
			usage.ImagesTotal = len(images)
			var totalSize int64
			for _, img := range images {
				totalSize += img.Size
			}
			usage.ImagesSize = formatBytes(totalSize)
		}
	}

	// Volume stats
	if volumeSvc != nil {
		if volumes, err := volumeSvc.List(ctx); err == nil {
			usage.VolumesTotal = len(volumes)
			var totalSize int64
			for _, v := range volumes {
				if v.InUse {
					usage.VolumesInUse++
				}
				totalSize += v.Size
			}
			usage.VolumesSize = formatBytes(totalSize)
		}
	}

	// Host resource info
	hostSvc := h.services.Hosts()
	if hostSvc != nil {
		if info, err := hostSvc.GetDockerInfo(ctx); err == nil && info != nil {
			usage.CPUCores = info.NCPU
			usage.MemoryTotal = formatBytes(info.MemTotal)
			usage.MemoryTotalBytes = info.MemTotal
			usage.MemoryUsed = "—"
			usage.DiskTotal = "—"
			usage.DiskUsed = "—"
		}
	}

	// Fetch real memory/disk usage from Docker if available
	if cli, err := h.getDockerClient(r); err == nil {
		// Memory: aggregate container memory usage
		if runningContainers, err := cli.ContainerList(ctx, container.ListOptions{All: false}); err == nil {
			var memUsed uint64
			for _, c := range runningContainers {
				statsResp, err := cli.ContainerStats(ctx, c.ID, false)
				if err == nil {
					var stat container.StatsResponse
					if decErr := json.NewDecoder(statsResp.Body).Decode(&stat); decErr == nil {
						memUsed += stat.MemoryStats.Usage
					}
					statsResp.Body.Close()
				}
			}
			usage.MemoryUsed = formatBytes(int64(memUsed))
			usage.MemoryUsedBytes = int64(memUsed)
			if usage.MemoryTotalBytes > 0 {
				usage.MemoryPercent = float64(memUsed) / float64(usage.MemoryTotalBytes) * 100
			}
		}

		// Disk: use Docker system df
		if du, err := cli.DiskUsage(ctx, dockertypes.DiskUsageOptions{}); err == nil {
			var diskUsed int64
			for _, img := range du.Images {
				diskUsed += img.Size
			}
			for _, v := range du.Volumes {
				if v.UsageData != nil && v.UsageData.Size > 0 {
					diskUsed += v.UsageData.Size
				}
			}
			for _, bc := range du.Containers {
				diskUsed += bc.SizeRw
			}
			usage.DiskUsed = formatBytes(diskUsed)
			usage.DiskUsedBytes = diskUsed
			usage.DiskTotal = usage.DiskUsed
		}
	}

	// Build quota views and check for alerts
	var quotaViews []quotastmpl.QuotaView

	if h.resourceQuotaRepo != nil {
		dbQuotas, err := h.resourceQuotaRepo.List(ctx)
		if err == nil {
			for _, q := range dbQuotas {
				currentUsage := getQuotaCurrentUsage(q.ResourceType, q.LimitValue, usage)
				usagePercent := float64(0)
				if q.LimitValue > 0 {
					usagePercent = float64(currentUsage) / float64(q.LimitValue) * 100
				}

				qv := quotastmpl.QuotaView{
					ID:           q.ID.String(),
					Name:         q.Name,
					Scope:        q.Scope,
					ScopeName:    q.ScopeName,
					ResourceType: q.ResourceType,
					Limit:        q.LimitValue,
					LimitHuman:   formatQuotaValue(q.ResourceType, q.LimitValue),
					CurrentUsage: currentUsage,
					UsageHuman:   formatQuotaValue(q.ResourceType, currentUsage),
					UsagePercent: usagePercent,
					IsEnabled:    q.IsEnabled,
					AlertAt:      q.AlertAt,
					CreatedAt:    q.CreatedAt.Format("Jan 02 15:04"),
				}
				quotaViews = append(quotaViews, qv)

				// Check for alerts
				if q.IsEnabled && q.AlertAt > 0 && usagePercent >= float64(q.AlertAt) {
					severity := "warning"
					if usagePercent >= 95 {
						severity = "critical"
					}
					alerts = append(alerts, quotastmpl.QuotaAlertView{
						QuotaName:    q.Name,
						ResourceType: q.ResourceType,
						ScopeName:    q.ScopeName,
						CurrentUsage: formatQuotaValue(q.ResourceType, currentUsage),
						Limit:        formatQuotaValue(q.ResourceType, q.LimitValue),
						UsagePercent: usagePercent,
						Severity:     severity,
						TriggeredAt:  time.Now().Format("Jan 02 15:04"),
					})
				}
			}
		}
	}

	// Get hosts for scope dropdown
	var hosts []quotastmpl.HostBasic
	if hostSvc != nil {
		if hostList, err := hostSvc.List(ctx); err == nil {
			for _, host := range hostList {
				hosts = append(hosts, quotastmpl.HostBasic{
					ID:   host.ID,
					Name: host.DisplayName,
				})
			}
		}
	}

	data := quotastmpl.QuotasData{
		PageData: pageData,
		Quotas:   quotaViews,
		Usage:    usage,
		Alerts:   alerts,
		Hosts:    hosts,
	}

	h.renderTempl(w, r, quotastmpl.Quotas(data))
}

// QuotaCreate creates a new resource quota.
func (h *Handler) QuotaCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		http.Redirect(w, r, "/quotas", http.StatusSeeOther)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		h.setFlash(w, r, "error", "Quota name is required")
		http.Redirect(w, r, "/quotas", http.StatusSeeOther)
		return
	}

	limitValue, _ := strconv.ParseInt(r.FormValue("limit_value"), 10, 64)
	if limitValue <= 0 {
		h.setFlash(w, r, "error", "Limit must be greater than 0")
		http.Redirect(w, r, "/quotas", http.StatusSeeOther)
		return
	}

	alertAt, _ := strconv.Atoi(r.FormValue("alert_at"))
	if alertAt <= 0 {
		alertAt = 80
	}

	scope := r.FormValue("scope")
	scopeName := "Global"
	if scope != "global" {
		if hostSvc := h.services.Hosts(); hostSvc != nil {
			if host, err := hostSvc.Get(r.Context(), scope); err == nil {
				scopeName = host.DisplayName
			}
		}
	}

	resourceType := r.FormValue("resource_type")

	// Convert memory/disk values from MB to bytes
	if resourceType == "memory" || resourceType == "disk" {
		limitValue = limitValue * 1024 * 1024
	}

	if h.resourceQuotaRepo != nil {
		q := &ResourceQuotaRecord{
			ID:           uuid.New(),
			Name:         name,
			Scope:        scope,
			ScopeName:    scopeName,
			ResourceType: resourceType,
			LimitValue:   limitValue,
			AlertAt:      alertAt,
			IsEnabled:    true,
		}
		if err := h.resourceQuotaRepo.Create(r.Context(), q); err != nil {
			h.setFlash(w, r, "error", "Failed to create quota: "+err.Error())
			http.Redirect(w, r, "/quotas", http.StatusSeeOther)
			return
		}
	}

	h.setFlash(w, r, "success", "Resource quota '"+name+"' created")
	http.Redirect(w, r, "/quotas", http.StatusSeeOther)
}

// QuotaToggle toggles a quota enabled/disabled.
func (h *Handler) QuotaToggle(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if h.resourceQuotaRepo != nil {
		uid, err := uuid.Parse(id)
		if err == nil {
			newState, err := h.resourceQuotaRepo.Toggle(r.Context(), uid)
			if err == nil {
				status := "disabled"
				if newState {
					status = "enabled"
				}
				h.setFlash(w, r, "success", "Quota "+status)
			} else {
				h.setFlash(w, r, "error", "Quota not found")
			}
		}
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/quotas")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/quotas", http.StatusSeeOther)
}

// QuotaDelete deletes a resource quota.
func (h *Handler) QuotaDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if h.resourceQuotaRepo == nil {
		h.setFlash(w, r, "error", "Quota service not configured")
		h.redirectQuotas(w, r)
		return
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		h.setFlash(w, r, "error", "Invalid quota ID")
		h.redirectQuotas(w, r)
		return
	}

	if err := h.resourceQuotaRepo.Delete(r.Context(), uid); err != nil {
		h.setFlash(w, r, "error", "Failed to delete quota: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Resource quota deleted")
	}

	h.redirectQuotas(w, r)
}

func (h *Handler) redirectQuotas(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/quotas")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/quotas", http.StatusSeeOther)
}

// getQuotaCurrentUsage computes current usage for a given resource type.
func getQuotaCurrentUsage(resourceType string, limit int64, usage quotastmpl.ResourceUsageView) int64 {
	switch resourceType {
	case "cpu":
		return int64(usage.CPUCores)
	case "memory":
		return usage.MemoryUsedBytes
	case "containers":
		return int64(usage.ContainersTotal)
	case "images":
		return int64(usage.ImagesTotal)
	case "volumes":
		return int64(usage.VolumesTotal)
	case "disk":
		return usage.DiskUsedBytes
	default:
		return 0
	}
}

// formatQuotaValue formats a quota value based on its resource type.
func formatQuotaValue(resourceType string, value int64) string {
	switch resourceType {
	case "memory", "disk":
		return formatBytes(value)
	case "cpu":
		return fmt.Sprintf("%d cores", value)
	default:
		return fmt.Sprintf("%d", value)
	}
}
