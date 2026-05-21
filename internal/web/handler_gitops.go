// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	gitopstmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/gitops"
)

// GitOpsTempl renders the GitOps pipelines page.
func (h *Handler) GitOpsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "GitOps Pipelines", "gitops")

	var pipelines []gitopstmpl.PipelineView
	var deployments []gitopstmpl.DeploymentView
	stats := gitopstmpl.PipelineStats{}

	if h.gitOpsRepo != nil {
		dbPipelines, err := h.gitOpsRepo.ListPipelines(ctx)
		if err == nil {
			for _, p := range dbPipelines {
				pv := gitopstmpl.PipelineView{
					ID:            p.ID.String(),
					Name:          p.Name,
					Repository:    p.Repository,
					Branch:        p.Branch,
					Provider:      p.Provider,
					TargetStack:   p.TargetStack,
					TargetService: p.TargetService,
					Action:        p.Action,
					TriggerType:   p.TriggerType,
					Schedule:      p.Schedule,
					IsEnabled:     p.IsEnabled,
					AutoRollback:  p.AutoRollback,
					DeployCount:   p.DeployCount,
					LastStatus:    p.LastStatus,
					CreatedAt:     p.CreatedAt.Format("Jan 02 15:04"),
				}
				if p.LastDeployAt != nil {
					pv.LastDeployAt = p.LastDeployAt.Format("Jan 02 15:04")
				}
				pipelines = append(pipelines, pv)
				stats.TotalPipelines++
				if p.IsEnabled {
					stats.ActivePipelines++
				}
			}
		}

		dbDeployments, err := h.gitOpsRepo.ListDeployments(ctx, 100)
		if err == nil {
			for _, d := range dbDeployments {
				dv := gitopstmpl.DeploymentView{
					ID:           d.ID.String(),
					PipelineName: d.PipelineName,
					Repository:   d.Repository,
					Branch:       d.Branch,
					CommitSHA:    d.CommitSHA,
					CommitMsg:    d.CommitMsg,
					Action:       d.Action,
					Status:       d.Status,
					Duration:     (time.Duration(d.DurationMs) * time.Millisecond).Round(time.Millisecond).String(),
					StartedAt:    d.StartedAt.Format("Jan 02 15:04"),
					TriggeredBy:  d.TriggeredBy,
					Error:        d.ErrorMessage,
				}
				if d.FinishedAt != nil {
					dv.FinishedAt = d.FinishedAt.Format("Jan 02 15:04")
				}
				deployments = append(deployments, dv)
				stats.TotalDeploys++
				switch d.Status {
				case "success":
					stats.SuccessDeploys++
				case "failed":
					stats.FailedDeploys++
				}
			}
		}
	}

	if stats.TotalDeploys > 0 {
		stats.SuccessRate = fmt.Sprintf("%.0f%%", float64(stats.SuccessDeploys)/float64(stats.TotalDeploys)*100)
	} else {
		stats.SuccessRate = "N/A"
	}

	data := gitopstmpl.GitOpsData{
		PageData:    pageData,
		Pipelines:   pipelines,
		Deployments: deployments,
		Stats:       stats,
		ActiveTab:   r.URL.Query().Get("tab"),
	}

	h.renderTempl(w, r, gitopstmpl.GitOps(data))
}

// GitOpsPipelineCreate creates a new GitOps pipeline.
// gitOpsPipelineCreateForm captures the pipeline-create inputs.
// Branch defaults to "main" after binding when blank.
type gitOpsPipelineCreateForm struct {
	Name          string `form:"name" validate:"required"`
	Repository    string `form:"repository" validate:"required"`
	Branch        string `form:"branch"`
	Provider      string `form:"provider"`
	TargetStack   string `form:"target_stack"`
	TargetService string `form:"target_service"`
	Action        string `form:"action"`
	TriggerType   string `form:"trigger_type"`
	Schedule      string `form:"schedule"`
	AutoRollback  bool   `form:"auto_rollback"`
}

func (h *Handler) GitOpsPipelineCreate(w http.ResponseWriter, r *http.Request) {
	var form gitOpsPipelineCreateForm
	if msg := BindForm(r, &form); msg != "" {
		h.setFlash(w, r, "error", msg)
		http.Redirect(w, r, "/gitops", http.StatusSeeOther)
		return
	}

	branch := form.Branch
	if branch == "" {
		branch = "main"
	}

	if h.gitOpsRepo != nil {
		p := &GitOpsPipelineRecord{
			ID:            uuid.New(),
			Name:          form.Name,
			Repository:    form.Repository,
			Branch:        branch,
			Provider:      form.Provider,
			TargetStack:   form.TargetStack,
			TargetService: form.TargetService,
			Action:        form.Action,
			TriggerType:   form.TriggerType,
			Schedule:      form.Schedule,
			IsEnabled:     true,
			AutoRollback:  form.AutoRollback,
		}
		if err := h.gitOpsRepo.CreatePipeline(r.Context(), p); err != nil {
			h.setFlash(w, r, "error", "Failed to create pipeline: "+err.Error())
			http.Redirect(w, r, "/gitops", http.StatusSeeOther)
			return
		}
	}

	h.setFlash(w, r, "success", "GitOps pipeline '"+form.Name+"' created")
	http.Redirect(w, r, "/gitops", http.StatusSeeOther)
}

// GitOpsPipelineToggle toggles a pipeline enabled/disabled.
func (h *Handler) GitOpsPipelineToggle(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if h.gitOpsRepo != nil {
		uid, err := uuid.Parse(id)
		if err == nil {
			newState, err := h.gitOpsRepo.TogglePipeline(r.Context(), uid)
			if err == nil {
				status := "disabled"
				if newState {
					status = "enabled"
				}
				h.setFlash(w, r, "success", "Pipeline "+status)
			} else {
				h.setFlash(w, r, "error", "Pipeline not found")
			}
		}
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/gitops")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/gitops", http.StatusSeeOther)
}

// GitOpsPipelineDelete deletes a pipeline.
func (h *Handler) GitOpsPipelineDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if h.gitOpsRepo != nil {
		uid, err := uuid.Parse(id)
		if err == nil {
			h.gitOpsRepo.DeletePipeline(r.Context(), uid)
		}
	}

	h.setFlash(w, r, "success", "Pipeline deleted")

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/gitops")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/gitops", http.StatusSeeOther)
}

// GitOpsPipelineDeploy triggers a manual deployment for a pipeline.
func (h *Handler) GitOpsPipelineDeploy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx := r.Context()

	if h.gitOpsRepo == nil {
		h.setFlash(w, r, "error", "GitOps repository unavailable")
		http.Redirect(w, r, "/gitops", http.StatusSeeOther)
		return
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		h.setFlash(w, r, "error", "Invalid pipeline ID")
		http.Redirect(w, r, "/gitops", http.StatusSeeOther)
		return
	}

	p, err := h.gitOpsRepo.GetPipeline(ctx, uid)
	if err != nil {
		h.setFlash(w, r, "error", "Pipeline not found")
		http.Redirect(w, r, "/gitops", http.StatusSeeOther)
		return
	}

	start := time.Now()
	var deployErr error
	status := "success"

	// Execute deployment based on action
	switch p.Action {
	case "redeploy":
		if stackSvc := h.services.Stacks(); stackSvc != nil {
			if err := stackSvc.Restart(ctx, p.TargetStack); err != nil {
				deployErr = err
			}
		}
	case "pull_and_redeploy":
		if h.services.Images() != nil {
			if stackSvc := h.services.Stacks(); stackSvc != nil {
				if err := stackSvc.Restart(ctx, p.TargetStack); err != nil {
					deployErr = err
				}
			}
		}
	case "update_image":
		if h.services.Images() != nil {
			if stackSvc := h.services.Stacks(); stackSvc != nil {
				if err := stackSvc.Restart(ctx, p.TargetStack); err != nil {
					deployErr = err
				}
			}
		}
	}

	duration := time.Since(start)
	if deployErr != nil {
		status = "failed"
	}

	// Record deployment in DB
	now := time.Now()
	pipelineID := p.ID
	deployment := &GitOpsDeploymentRecord{
		ID:           uuid.New(),
		PipelineID:   &pipelineID,
		PipelineName: p.Name,
		Repository:   p.Repository,
		Branch:       p.Branch,
		Action:       p.Action,
		Status:       status,
		DurationMs:   int(duration.Milliseconds()),
		StartedAt:    start,
		FinishedAt:   &now,
		TriggeredBy:  "manual",
	}
	if deployErr != nil {
		deployment.ErrorMessage = deployErr.Error()
	}

	h.gitOpsRepo.CreateDeployment(ctx, deployment)
	h.gitOpsRepo.IncrementDeployCount(ctx, uid, now, status)

	if deployErr != nil {
		h.setFlash(w, r, "error", "Deployment failed: "+deployErr.Error())
	} else {
		h.setFlash(w, r, "success", fmt.Sprintf("Deployment successful for '%s' (%s)", p.Name, duration.Round(time.Millisecond)))
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/gitops?tab=deployments")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/gitops?tab=deployments", http.StatusSeeOther)
}
