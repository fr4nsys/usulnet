// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"fmt"
	"net/http"
	"sort"

	"github.com/fr4nsys/usulnet/internal/models"
	overviewtmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/overview"
)

// OverviewTempl renders the multi-node aggregate dashboard.
func (h *Handler) OverviewTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Infrastructure Overview", "overview")

	data := overviewtmpl.OverviewData{
		PageData: pageData,
	}

	// Track service errors for dashboard degradation indicator
	var serviceErrors []string

	// Aggregate data across all hosts
	hostSvc := h.services.Hosts()
	if hostSvc != nil {
		hosts, err := hostSvc.List(ctx)
		if err != nil {
			serviceErrors = append(serviceErrors, "hosts")
			h.logger.Error("overview: failed to list hosts", "error", err)
		} else {
			var totalContainers, totalRunning, totalStopped, totalImages int
			var onlineNodes, offlineNodes int

			for _, host := range hosts {
				node := overviewtmpl.NodeSummary{
					ID:                host.ID,
					Name:              host.DisplayName,
					Status:            host.Status,
					Endpoint:          host.Endpoint,
					EndpointType:      host.EndpointType,
					DockerVersion:     host.DockerVersion,
					OS:                host.OS,
					Arch:              host.Arch,
					CPUs:              host.CPUs,
					Memory:            host.MemoryHuman,
					Containers:        host.Containers,
					ContainersRunning: host.ContainersRunning,
					Images:            host.Images,
					LastSeen:          host.LastSeenHuman,
				}

				if host.Status == "online" {
					onlineNodes++
				} else {
					offlineNodes++
				}

				totalContainers += host.Containers
				totalRunning += host.ContainersRunning
				totalStopped += host.Containers - host.ContainersRunning
				totalImages += host.Images

				data.Nodes = append(data.Nodes, node)
			}

			data.TotalNodes = len(hosts)
			data.OnlineNodes = onlineNodes
			data.OfflineNodes = offlineNodes
			data.TotalContainers = totalContainers
			data.TotalRunning = totalRunning
			data.TotalStopped = totalStopped
			data.TotalImages = totalImages

			// Sort nodes: online first, then by containers descending
			sort.Slice(data.Nodes, func(i, j int) bool {
				if data.Nodes[i].Status != data.Nodes[j].Status {
					return data.Nodes[i].Status == "online"
				}
				return data.Nodes[i].Containers > data.Nodes[j].Containers
			})
		}
	}

	// Get updates available count
	updateSvc := h.services.Updates()
	if updateSvc != nil {
		if available, err := updateSvc.ListAvailable(ctx); err != nil {
			serviceErrors = append(serviceErrors, "updates")
			h.logger.Error("overview: failed to list available updates", "error", err)
		} else {
			data.UpdatesAvailable = len(available)
		}
	}

	// Get security info
	secSvc := h.services.Security()
	if secSvc != nil {
		if overview, err := secSvc.GetOverview(ctx); err != nil {
			serviceErrors = append(serviceErrors, "security")
			h.logger.Error("overview: failed to get security overview", "error", err)
		} else {
			data.SecurityScore = int(overview.AverageScore)
			data.SecurityIssues = overview.CriticalCount + overview.HighCount + overview.MediumCount
			// Determine grade from average score
			switch {
			case overview.AverageScore >= 90:
				data.SecurityGrade = "A"
			case overview.AverageScore >= 80:
				data.SecurityGrade = "B"
			case overview.AverageScore >= 70:
				data.SecurityGrade = "C"
			case overview.AverageScore >= 60:
				data.SecurityGrade = "D"
			default:
				data.SecurityGrade = "F"
			}
		}
	}

	// Set degraded status if any service errors occurred
	if len(serviceErrors) > 0 {
		data.HasServiceErrors = true
	}

	// Get recent alerts
	alertSvc := h.getAlertService()
	if alertSvc != nil {
		events, _, err := alertSvc.ListEvents(ctx, models.AlertEventListOptions{Limit: 5})
		if err != nil {
			h.logger.Error("overview: failed to list alert events", "error", err)
		} else {
			for _, e := range events {
				data.RecentAlerts = append(data.RecentAlerts, overviewtmpl.AlertSummary{
					RuleName:  fmt.Sprintf("Alert %s", e.AlertID.String()[:8]),
					State:     string(e.State),
					Value:     fmt.Sprintf("%.2f", e.Value),
					Threshold: fmt.Sprintf("%.2f", e.Threshold),
					FiredAt:   e.FiredAt.Format("Jan 02 15:04"),
				})
			}
		}
	}

	h.renderTempl(w, r, overviewtmpl.Overview(data))
}
