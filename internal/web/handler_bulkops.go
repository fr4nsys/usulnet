// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"net/http"
	"sync"

	bulktmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/bulkops"
)

// In-memory last bulk result tracking (for result display).
var (
	lastBulkResult   *bulktmpl.BulkResultView
	lastBulkResultMu sync.RWMutex
)

// BulkOpsTempl renders the bulk operations page.
func (h *Handler) BulkOpsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Bulk Operations", "bulk-ops")

	containerSvc := h.services.Containers()
	if containerSvc == nil {
		h.renderTempl(w, r, bulktmpl.BulkOps(bulktmpl.BulkOpsData{
			PageData: pageData,
		}))
		return
	}

	containers, err := containerSvc.List(ctx, nil)
	if err != nil {
		h.renderTempl(w, r, bulktmpl.BulkOps(bulktmpl.BulkOpsData{
			PageData: pageData,
		}))
		return
	}

	stats := bulktmpl.BulkStats{
		Total: len(containers),
	}

	var bulkContainers []bulktmpl.BulkContainerView
	for _, c := range containers {
		bc := bulktmpl.BulkContainerView{
			ID:        c.ID,
			Name:      c.Name,
			Image:     c.Image,
			State:     c.State,
			Status:    c.Status,
			Health:    c.Health,
			Stack:     c.Stack,
			CreatedAt: c.CreatedHuman,
		}
		bulkContainers = append(bulkContainers, bc)

		switch c.State {
		case "running":
			stats.Running++
		case "exited", "dead":
			stats.Stopped++
		case "paused":
			stats.Paused++
		}
	}

	// Get last result
	lastBulkResultMu.RLock()
	result := lastBulkResult
	lastBulkResultMu.RUnlock()

	data := bulktmpl.BulkOpsData{
		PageData:   pageData,
		Containers: bulkContainers,
		Stats:      stats,
		LastResult: result,
	}

	h.renderTempl(w, r, bulktmpl.BulkOps(data))
}

// BulkOpsAction handles bulk operations from the dedicated page and stores results.
func (h *Handler) BulkOpsAction(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		http.Redirect(w, r, "/bulk-ops", http.StatusSeeOther)
		return
	}

	containerIDs := r.Form["container_ids"]
	if len(containerIDs) == 0 {
		h.setFlash(w, r, "error", "No containers selected")
		http.Redirect(w, r, "/bulk-ops", http.StatusSeeOther)
		return
	}

	action := r.URL.Query().Get("action")
	if action == "" {
		// Try extracting from path
		h.setFlash(w, r, "error", "No action specified")
		http.Redirect(w, r, "/bulk-ops", http.StatusSeeOther)
		return
	}

	ctx := r.Context()
	containerSvc := h.services.Containers()
	if containerSvc == nil {
		h.setFlash(w, r, "error", "Container service unavailable")
		http.Redirect(w, r, "/bulk-ops", http.StatusSeeOther)
		return
	}

	var results *BulkOperationResults
	var execErr error

	switch action {
	case "start":
		results, execErr = containerSvc.BulkStart(ctx, containerIDs)
	case "stop":
		results, execErr = containerSvc.BulkStop(ctx, containerIDs)
	case "restart":
		results, execErr = containerSvc.BulkRestart(ctx, containerIDs)
	case "pause":
		results, execErr = containerSvc.BulkPause(ctx, containerIDs)
	case "unpause":
		results, execErr = containerSvc.BulkUnpause(ctx, containerIDs)
	case "kill":
		results, execErr = containerSvc.BulkKill(ctx, containerIDs)
	case "remove":
		force := r.FormValue("force") == "true"
		results, execErr = containerSvc.BulkRemove(ctx, containerIDs, force)
	default:
		h.setFlash(w, r, "error", "Unknown action: "+action)
		http.Redirect(w, r, "/bulk-ops", http.StatusSeeOther)
		return
	}

	if execErr != nil {
		h.setFlash(w, r, "error", "Bulk operation failed: "+execErr.Error())
		http.Redirect(w, r, "/bulk-ops", http.StatusSeeOther)
		return
	}

	// Store result for display
	if results != nil {
		resultView := &bulktmpl.BulkResultView{
			Action:     action,
			Total:      results.Total,
			Successful: results.Successful,
			Failed:     results.Failed,
		}
		for _, r := range results.Results {
			resultView.Results = append(resultView.Results, bulktmpl.BulkItemResult{
				ContainerID: r.ContainerID,
				Name:        r.Name,
				Success:     r.Success,
				Error:       r.Error,
			})
		}
		lastBulkResultMu.Lock()
		lastBulkResult = resultView
		lastBulkResultMu.Unlock()
	}

	http.Redirect(w, r, "/bulk-ops", http.StatusSeeOther)
}
