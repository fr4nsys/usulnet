// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	dockertypes "github.com/docker/docker/api/types"

	hdtmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/healthdash"
)

// HealthDashTempl renders the container health check dashboard.
func (h *Handler) HealthDashTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Health Dashboard", "health")

	containerSvc := h.services.Containers()
	if containerSvc == nil {
		h.renderTempl(w, r, hdtmpl.HealthDashboard(hdtmpl.HealthDashData{
			PageData: pageData,
		}))
		return
	}

	containers, err := containerSvc.List(ctx, nil)
	if err != nil {
		h.renderTempl(w, r, hdtmpl.HealthDashboard(hdtmpl.HealthDashData{
			PageData: pageData,
		}))
		return
	}

	// Try to get Docker client for detailed health check info
	dockerClient, _ := containerSvc.GetDockerClient(ctx)

	// Pre-fetch all running container inspections in parallel to avoid N+1 sequential calls
	inspectCache := make(map[string]dockertypes.ContainerJSON)
	if dockerClient != nil {
		var runningIDs []string
		for _, c := range containers {
			if c.State == "running" {
				runningIDs = append(runningIDs, c.ID)
			}
		}
		if len(runningIDs) > 0 {
			var mu sync.Mutex
			var wg sync.WaitGroup
			sem := make(chan struct{}, 10) // limit concurrent Docker API calls
			for _, id := range runningIDs {
				wg.Add(1)
				go func(containerID string) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					data, err := dockerClient.ContainerInspectRaw(ctx, containerID)
					if err == nil {
						mu.Lock()
						inspectCache[containerID] = data
						mu.Unlock()
					}
				}(id)
			}
			wg.Wait()
		}
	}

	stats := hdtmpl.HealthStats{
		TotalContainers: len(containers),
	}

	var healthContainers []hdtmpl.HealthContainerView
	for _, c := range containers {
		hc := hdtmpl.HealthContainerView{
			ID:     c.ID,
			Name:   c.Name,
			Image:  c.Image,
			State:  c.State,
			Health: c.Health,
		}

		// Count by health status
		switch c.Health {
		case "healthy":
			stats.Healthy++
		case "unhealthy":
			stats.Unhealthy++
		case "starting":
			stats.Starting++
		default:
			stats.NoHealthCheck++
		}

		// Use pre-fetched inspect data for detailed health check info
		if inspectData, ok := inspectCache[c.ID]; ok {
			// Extract health check config
			if inspectData.Config != nil && inspectData.Config.Healthcheck != nil {
				hcConfig := inspectData.Config.Healthcheck
				hc.HealthCheck = hdtmpl.HealthCheckConfig{
					IsConfigured: true,
					Retries:      hcConfig.Retries,
				}
				if len(hcConfig.Test) > 0 {
					// First element is the check type (CMD, CMD-SHELL, NONE)
					if hcConfig.Test[0] == "CMD-SHELL" && len(hcConfig.Test) > 1 {
						hc.HealthCheck.Test = hcConfig.Test[1]
					} else if hcConfig.Test[0] == "CMD" && len(hcConfig.Test) > 1 {
						hc.HealthCheck.Test = strings.Join(hcConfig.Test[1:], " ")
					} else {
						hc.HealthCheck.Test = strings.Join(hcConfig.Test, " ")
					}
				}
				if hcConfig.Interval > 0 {
					hc.HealthCheck.Interval = formatHealthDuration(hcConfig.Interval)
				}
				if hcConfig.Timeout > 0 {
					hc.HealthCheck.Timeout = formatHealthDuration(hcConfig.Timeout)
				}
				if hcConfig.StartPeriod > 0 {
					hc.HealthCheck.StartPeriod = formatHealthDuration(hcConfig.StartPeriod)
				}
			}

			// Extract health check logs
			if inspectData.State != nil && inspectData.State.Health != nil {
				hc.FailingStreak = inspectData.State.Health.FailingStreak
				for _, logEntry := range inspectData.State.Health.Log {
					entry := hdtmpl.HealthLogEntry{
						ExitCode: logEntry.ExitCode,
						Output:   truncateHealthOutput(logEntry.Output),
					}
					if !logEntry.Start.IsZero() {
						entry.Start = logEntry.Start.Format("Jan 02 15:04:05")
					}
					if !logEntry.End.IsZero() {
						entry.End = logEntry.End.Format("Jan 02 15:04:05")
					}
					hc.HealthLogs = append(hc.HealthLogs, entry)
				}
				// Show most recent logs first
				for i, j := 0, len(hc.HealthLogs)-1; i < j; i, j = i+1, j-1 {
					hc.HealthLogs[i], hc.HealthLogs[j] = hc.HealthLogs[j], hc.HealthLogs[i]
				}
				if len(hc.HealthLogs) > 0 {
					hc.LastCheckedAt = hc.HealthLogs[0].Start
				}
			}
		} else if c.Health != "" && c.Health != "none" {
			hc.HealthCheck.IsConfigured = true
		}

		healthContainers = append(healthContainers, hc)
	}

	// Calculate health rate
	withCheck := stats.TotalContainers - stats.NoHealthCheck
	if withCheck > 0 {
		stats.HealthRate = fmt.Sprintf("%.0f%%", float64(stats.Healthy)/float64(withCheck)*100)
	} else {
		stats.HealthRate = "N/A"
	}

	// Sort: unhealthy first, then starting, then healthy, then no check
	sortHealthContainers(healthContainers)

	data := hdtmpl.HealthDashData{
		PageData:   pageData,
		Containers: healthContainers,
		Stats:      stats,
	}

	h.renderTempl(w, r, hdtmpl.HealthDashboard(data))
}

// formatHealthDuration formats a time.Duration to a human-readable string.
func formatHealthDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}

// truncateHealthOutput truncates health check output to prevent huge logs.
func truncateHealthOutput(output string) string {
	output = strings.TrimSpace(output)
	if len(output) > 500 {
		return output[:500] + "..."
	}
	return output
}

// sortHealthContainers sorts containers by health priority: unhealthy > starting > healthy > none.
func sortHealthContainers(containers []hdtmpl.HealthContainerView) {
	// Simple bubble sort for readability (small N)
	for i := 0; i < len(containers); i++ {
		for j := i + 1; j < len(containers); j++ {
			if healthPriority(containers[j].Health) > healthPriority(containers[i].Health) {
				containers[i], containers[j] = containers[j], containers[i]
			}
		}
	}
}

func healthPriority(health string) int {
	switch health {
	case "unhealthy":
		return 3
	case "starting":
		return 2
	case "healthy":
		return 1
	default:
		return 0
	}
}
