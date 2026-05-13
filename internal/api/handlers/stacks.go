// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/services/stack"
)

// StackHandler handles stack-related HTTP requests.
type StackHandler struct {
	BaseHandler
	stackService *stack.Service
}

// NewStackHandler creates a new stack handler.
func NewStackHandler(stackService *stack.Service, log *logger.Logger) *StackHandler {
	return &StackHandler{
		BaseHandler:  NewBaseHandler(log),
		stackService: stackService,
	}
}

// Routes returns the router for stack endpoints.
func (h *StackHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Read-only (viewer+)
	r.Get("/", h.ListStacks)

	// Operator+ for creation and validation
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireOperator)
		r.Post("/", h.CreateStack)
		r.Post("/validate", h.ValidateCompose)
		r.Post("/dry-run", h.DryRunContent)
	})

	r.Route("/{stackID}", func(r chi.Router) {
		// Read-only (viewer+)
		r.Get("/", h.GetStack)
		r.Get("/status", h.GetStatus)
		r.Get("/containers", h.GetContainers)
		r.Get("/compose", h.GetComposeConfig)
		r.Get("/versions", h.ListVersions)
		r.Get("/versions/{version}", h.GetVersion)
		r.Get("/versions/{fromVersion}/diff/{toVersion}", h.DiffVersions)
		r.Get("/dependencies", h.ListDependencies)
		r.Get("/dependents", h.GetDependents)
		r.Get("/services/{serviceName}/logs", h.GetServiceLogs)

		// Operator+ for mutations
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireOperator)
			r.Put("/", h.UpdateStack)
			r.Delete("/", h.DeleteStack)
			r.Post("/deploy", h.DeployStack)
			r.Post("/redeploy", h.RedeployStack)
			r.Post("/start", h.StartStack)
			r.Post("/stop", h.StopStack)
			r.Post("/restart", h.RestartStack)
			r.Post("/pull", h.PullStack)
			r.Post("/versions", h.CreateVersion)
			r.Post("/versions/{version}/restore", h.RestoreVersion)
			r.Post("/dry-run", h.DryRun)
			r.Post("/dependencies", h.AddDependency)
			r.Delete("/dependencies/{dependsOnID}", h.RemoveDependency)
			r.Post("/services/{serviceName}/scale", h.ScaleService)
			r.Post("/services/{serviceName}/restart", h.RestartService)
		})
	})

	return r
}

// ============================================================================
// Request/Response types
// ============================================================================

// CreateStackRequest represents a stack creation request.
type CreateStackRequest struct {
	Name        string            `json:"name"`
	ComposeFile string            `json:"compose_file"`
	EnvFile     string            `json:"env_file,omitempty"`
	Variables   map[string]string `json:"variables,omitempty"`
	ProjectDir  string            `json:"project_dir,omitempty"`
	AutoStart   bool              `json:"auto_start,omitempty"`
	HostID      string            `json:"host_id"`
}

// UpdateStackRequest represents a stack update request.
type UpdateStackRequest struct {
	ComposeFile string            `json:"compose_file,omitempty"`
	EnvFile     string            `json:"env_file,omitempty"`
	Variables   map[string]string `json:"variables,omitempty"`
}

// ValidateComposeRequest represents a compose validation request.
type ValidateComposeRequest struct {
	HostID  string `json:"host_id"`
	Content string `json:"content"`
}

// ScaleServiceRequest represents a scale service request.
type ScaleServiceRequest struct {
	Replicas int `json:"replicas"`
}

// StackResponse represents a stack in API responses.
type StackResponse struct {
	ID             string                 `json:"id"`
	HostID         string                 `json:"host_id"`
	Name           string                 `json:"name"`
	Type           string                 `json:"type"`
	Status         string                 `json:"status"`
	ProjectDir     string                 `json:"project_dir"`
	EnvFile        string                 `json:"env_file,omitempty"`
	Variables      map[string]string      `json:"variables,omitempty"`
	Services       []StackServiceResponse `json:"services,omitempty"`
	ServiceCount   int                    `json:"service_count"`
	RunningCount   int                    `json:"running_count"`
	GitRepo        string                 `json:"git_repo,omitempty"`
	GitBranch      string                 `json:"git_branch,omitempty"`
	GitCommit      string                 `json:"git_commit,omitempty"`
	LastDeployedAt string                 `json:"last_deployed_at,omitempty"`
	LastDeployedBy string                 `json:"last_deployed_by,omitempty"`
	CreatedAt      string                 `json:"created_at"`
	UpdatedAt      string                 `json:"updated_at"`
}

// StackServiceResponse represents a service in a stack.
type StackServiceResponse struct {
	Name            string   `json:"name"`
	Image           string   `json:"image"`
	ContainerID     string   `json:"container_id,omitempty"`
	ContainerName   string   `json:"container_name,omitempty"`
	Status          string   `json:"status"`
	State           string   `json:"state"`
	Replicas        int      `json:"replicas"`
	RunningReplicas int      `json:"running_replicas"`
	Ports           []string `json:"ports,omitempty"`
	Volumes         []string `json:"volumes,omitempty"`
	Networks        []string `json:"networks,omitempty"`
	DependsOn       []string `json:"depends_on,omitempty"`
	HealthStatus    string   `json:"health_status,omitempty"`
}

// StackStatusResponse represents stack status.
type StackStatusAPIResponse struct {
	StackID      string                       `json:"stack_id"`
	Status       string                       `json:"status"`
	Services     []StackServiceStatusResponse `json:"services"`
	ServiceCount int                          `json:"service_count"`
	RunningCount int                          `json:"running_count"`
}

// StackServiceStatusResponse represents service status.
type StackServiceStatusResponse struct {
	Name    string `json:"name"`
	Running int    `json:"running"`
	Desired int    `json:"desired"`
	Healthy int    `json:"healthy,omitempty"`
	Exited  int    `json:"exited,omitempty"`
	Status  string `json:"status"`
}

// DeployResponse represents deploy result.
type DeployResponse struct {
	StackID    string `json:"stack_id"`
	Success    bool   `json:"success"`
	Output     string `json:"output,omitempty"`
	Error      string `json:"error,omitempty"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
}

// ValidateResponse represents validation result.
type ValidateResponse struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Services []string `json:"services,omitempty"`
}

// ============================================================================
// Handlers
// ============================================================================

// ListStacks returns all stacks.
// GET /api/v1/stacks
func (h *StackHandler) ListStacks(w http.ResponseWriter, r *http.Request) {
	pagination := h.GetPagination(r)

	opts := postgres.StackListOptions{
		Page:    pagination.Page,
		PerPage: pagination.PerPage,
	}

	// Optional filters
	if hostID := h.QueryParamUUID(r, "host_id"); hostID != nil {
		opts.HostID = hostID
	}
	if status := h.QueryParam(r, "status"); status != "" {
		s := models.StackStatus(status)
		opts.Status = &s
	}
	if search := h.QueryParam(r, "search"); search != "" {
		opts.Search = search
	}

	stacks, total, err := h.stackService.List(r.Context(), opts)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]StackResponse, len(stacks))
	for i, s := range stacks {
		resp[i] = toStackResponse(s)
	}

	h.OK(w, NewPaginatedResponse(resp, total, pagination))
}

// CreateStack creates a new stack.
// POST /api/v1/stacks
func (h *StackHandler) CreateStack(w http.ResponseWriter, r *http.Request) {
	var req CreateStackRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Name == "" {
		h.BadRequest(w, "name is required")
		return
	}
	if req.ComposeFile == "" {
		h.BadRequest(w, "compose_file is required")
		return
	}
	if req.HostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}

	hostID, err := uuid.Parse(req.HostID)
	if err != nil {
		h.BadRequest(w, "invalid host_id")
		return
	}

	input := &models.CreateStackInput{
		Name:        req.Name,
		ComposeFile: req.ComposeFile,
		Variables:   req.Variables,
		ProjectDir:  req.ProjectDir,
		AutoStart:   req.AutoStart,
	}
	if req.EnvFile != "" {
		input.EnvFile = &req.EnvFile
	}

	stk, err := h.stackService.Create(r.Context(), hostID, input)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, toStackResponse(stk))
}

// GetStack returns a specific stack.
// GET /api/v1/stacks/{stackID}
func (h *StackHandler) GetStack(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	stk, err := h.stackService.Get(r.Context(), stackID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toStackResponse(stk))
}

// UpdateStack updates a stack.
// PUT /api/v1/stacks/{stackID}
func (h *StackHandler) UpdateStack(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req UpdateStackRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	input := &models.UpdateStackInput{
		Variables: req.Variables,
	}
	if req.ComposeFile != "" {
		input.ComposeFile = &req.ComposeFile
	}
	if req.EnvFile != "" {
		input.EnvFile = &req.EnvFile
	}

	stk, err := h.stackService.Update(r.Context(), stackID, input)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toStackResponse(stk))
}

// DeleteStack deletes a stack.
// DELETE /api/v1/stacks/{stackID}
func (h *StackHandler) DeleteStack(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	removeVolumes := h.QueryParamBool(r, "volumes", false)

	if err := h.stackService.Delete(r.Context(), stackID, removeVolumes); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// DeployStack deploys a stack.
// POST /api/v1/stacks/{stackID}/deploy
func (h *StackHandler) DeployStack(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	result, err := h.stackService.Deploy(r.Context(), stackID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, DeployResponse{
		StackID:    result.StackID.String(),
		Success:    result.Success,
		Output:     result.Output,
		Error:      result.Error,
		StartedAt:  result.StartedAt.Format(time.RFC3339),
		FinishedAt: result.FinishedAt.Format(time.RFC3339),
	})
}

// RedeployStack redeploys a stack with optional updates.
// POST /api/v1/stacks/{stackID}/redeploy
func (h *StackHandler) RedeployStack(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req UpdateStackRequest
	h.ParseJSON(r, &req) // Optional body

	var input *models.UpdateStackInput
	if req.ComposeFile != "" || req.EnvFile != "" || len(req.Variables) > 0 {
		input = &models.UpdateStackInput{
			Variables: req.Variables,
		}
		if req.ComposeFile != "" {
			input.ComposeFile = &req.ComposeFile
		}
		if req.EnvFile != "" {
			input.EnvFile = &req.EnvFile
		}
	}

	result, err := h.stackService.Redeploy(r.Context(), stackID, input)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, DeployResponse{
		StackID:    result.StackID.String(),
		Success:    result.Success,
		Output:     result.Output,
		Error:      result.Error,
		StartedAt:  result.StartedAt.Format(time.RFC3339),
		FinishedAt: result.FinishedAt.Format(time.RFC3339),
	})
}

// StartStack starts a stack.
// POST /api/v1/stacks/{stackID}/start
func (h *StackHandler) StartStack(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.stackService.Start(r.Context(), stackID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// StopStack stops a stack.
// POST /api/v1/stacks/{stackID}/stop
func (h *StackHandler) StopStack(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	removeVolumes := h.QueryParamBool(r, "volumes", false)

	if err := h.stackService.Stop(r.Context(), stackID, removeVolumes); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// RestartStack restarts a stack.
// POST /api/v1/stacks/{stackID}/restart
func (h *StackHandler) RestartStack(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.stackService.Restart(r.Context(), stackID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// PullStack pulls images for a stack.
// POST /api/v1/stacks/{stackID}/pull
func (h *StackHandler) PullStack(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	output, err := h.stackService.Pull(r.Context(), stackID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]string{"output": output})
}

// GetStatus returns stack status.
// GET /api/v1/stacks/{stackID}/status
func (h *StackHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	status, err := h.stackService.GetStatus(r.Context(), stackID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := StackStatusAPIResponse{
		StackID:      status.StackID.String(),
		Status:       string(status.Status),
		ServiceCount: status.ServiceCount,
		RunningCount: status.RunningCount,
	}

	resp.Services = make([]StackServiceStatusResponse, len(status.Services))
	for i, svc := range status.Services {
		resp.Services[i] = StackServiceStatusResponse{
			Name:    svc.Name,
			Running: svc.Running,
			Desired: svc.Desired,
			Healthy: svc.Healthy,
			Exited:  svc.Exited,
			Status:  svc.Status,
		}
	}

	h.OK(w, resp)
}

// GetContainers returns containers in a stack.
// GET /api/v1/stacks/{stackID}/containers
func (h *StackHandler) GetContainers(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	containers, err := h.stackService.GetContainers(r.Context(), stackID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]ContainerResponse, len(containers))
	for i, c := range containers {
		resp[i] = toContainerResponse(c)
	}

	h.OK(w, resp)
}

// GetComposeConfig returns the compose file content.
// GET /api/v1/stacks/{stackID}/compose
func (h *StackHandler) GetComposeConfig(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	content, err := h.stackService.GetComposeConfig(r.Context(), stackID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]string{"content": content})
}

// ScaleService scales a service in a stack.
// POST /api/v1/stacks/{stackID}/services/{serviceName}/scale
func (h *StackHandler) ScaleService(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	serviceName := h.URLParam(r, "serviceName")
	if serviceName == "" {
		h.BadRequest(w, "serviceName is required")
		return
	}

	var req ScaleServiceRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.stackService.ScaleService(r.Context(), stackID, serviceName, req.Replicas); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// RestartService restarts a service in a stack.
// POST /api/v1/stacks/{stackID}/services/{serviceName}/restart
func (h *StackHandler) RestartService(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	serviceName := h.URLParam(r, "serviceName")
	if serviceName == "" {
		h.BadRequest(w, "serviceName is required")
		return
	}

	if err := h.stackService.RestartService(r.Context(), stackID, serviceName); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// GetServiceLogs returns logs for a service.
// GET /api/v1/stacks/{stackID}/services/{serviceName}/logs
func (h *StackHandler) GetServiceLogs(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	serviceName := h.URLParam(r, "serviceName")
	if serviceName == "" {
		h.BadRequest(w, "serviceName is required")
		return
	}

	tail := h.QueryParamInt(r, "tail", 100)

	logs, err := h.stackService.GetServiceLogs(r.Context(), stackID, serviceName, tail)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]string{"logs": logs})
}

// ValidateCompose validates a compose file.
// POST /api/v1/stacks/validate
func (h *StackHandler) ValidateCompose(w http.ResponseWriter, r *http.Request) {
	var req ValidateComposeRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Content == "" {
		h.BadRequest(w, "content is required")
		return
	}
	if req.HostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}

	hostID, err := uuid.Parse(req.HostID)
	if err != nil {
		h.BadRequest(w, "invalid host_id")
		return
	}

	result, err := h.stackService.ValidateCompose(r.Context(), hostID, req.Content)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, ValidateResponse{
		Valid:    result.Valid,
		Errors:   result.Errors,
		Warnings: result.Warnings,
		Services: result.Services,
	})
}

// ============================================================================
// Helpers
// ============================================================================

func toStackResponse(s *models.Stack) StackResponse {
	resp := StackResponse{
		ID:           s.ID.String(),
		HostID:       s.HostID.String(),
		Name:         s.Name,
		Type:         string(s.Type),
		Status:       string(s.Status),
		ProjectDir:   s.ProjectDir,
		Variables:    s.Variables,
		ServiceCount: s.ServiceCount,
		RunningCount: s.RunningCount,
		CreatedAt:    s.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    s.UpdatedAt.Format(time.RFC3339),
	}

	if s.EnvFile != nil {
		resp.EnvFile = *s.EnvFile
	}
	if s.GitRepo != nil {
		resp.GitRepo = *s.GitRepo
	}
	if s.GitBranch != nil {
		resp.GitBranch = *s.GitBranch
	}
	if s.GitCommit != nil {
		resp.GitCommit = *s.GitCommit
	}
	if s.LastDeployedAt != nil {
		resp.LastDeployedAt = s.LastDeployedAt.Format(time.RFC3339)
	}
	if s.LastDeployedBy != nil {
		resp.LastDeployedBy = s.LastDeployedBy.String()
	}

	// Services
	if len(s.Services) > 0 {
		resp.Services = make([]StackServiceResponse, len(s.Services))
		for i, svc := range s.Services {
			svcResp := StackServiceResponse{
				Name:            svc.Name,
				Image:           svc.Image,
				Status:          svc.Status,
				State:           string(svc.State),
				Replicas:        svc.Replicas,
				RunningReplicas: svc.RunningReplicas,
				Volumes:         svc.Volumes,
				Networks:        svc.Networks,
				DependsOn:       svc.DependsOn,
			}
			if svc.ContainerID != nil {
				svcResp.ContainerID = *svc.ContainerID
			}
			if svc.ContainerName != nil {
				svcResp.ContainerName = *svc.ContainerName
			}
			if svc.HealthStatus != nil {
				svcResp.HealthStatus = *svc.HealthStatus
			}
			// Convert ports
			if len(svc.Ports) > 0 {
				svcResp.Ports = make([]string, len(svc.Ports))
				for j, p := range svc.Ports {
					svcResp.Ports[j] = formatPort(p)
				}
			}
			resp.Services[i] = svcResp
		}
	}

	return resp
}

func formatPort(p models.PortMapping) string {
	if p.PublicPort > 0 {
		if p.IP != "" {
			return p.IP + ":" + strconv.Itoa(int(p.PublicPort)) + ":" + strconv.Itoa(int(p.PrivatePort)) + "/" + p.Type
		}
		return strconv.Itoa(int(p.PublicPort)) + ":" + strconv.Itoa(int(p.PrivatePort)) + "/" + p.Type
	}
	return strconv.Itoa(int(p.PrivatePort)) + "/" + p.Type
}

// ============================================================================
// Versioning Handlers
// ============================================================================

// StackVersionResponse represents a stack version in API responses.
type StackVersionResponse struct {
	ID          string  `json:"id"`
	StackID     string  `json:"stack_id"`
	Version     int     `json:"version"`
	ComposeFile string  `json:"compose_file"`
	EnvFile     *string `json:"env_file,omitempty"`
	Comment     string  `json:"comment"`
	CreatedBy   *string `json:"created_by,omitempty"`
	CreatedAt   string  `json:"created_at"`
	DeployedAt  *string `json:"deployed_at,omitempty"`
	IsDeployed  bool    `json:"is_deployed"`
}

// CreateVersionRequest represents a create version request.
type CreateVersionRequest struct {
	Comment string `json:"comment"`
}

// DiffResponse represents a diff between versions.
type DiffResponse struct {
	FromVersion    int                 `json:"from_version"`
	ToVersion      int                 `json:"to_version"`
	ComposeChanges []DiffLineResponse  `json:"compose_changes"`
	EnvChanges     []DiffLineResponse  `json:"env_changes,omitempty"`
	Summary        DiffSummaryResponse `json:"summary"`
}

// DiffLineResponse represents a line in a diff.
type DiffLineResponse struct {
	Type    string `json:"type"`
	Content string `json:"content"`
	OldLine int    `json:"old_line,omitempty"`
	NewLine int    `json:"new_line,omitempty"`
}

// DiffSummaryResponse represents a summary of changes.
type DiffSummaryResponse struct {
	LinesAdded       int      `json:"lines_added"`
	LinesRemoved     int      `json:"lines_removed"`
	ServicesAdded    []string `json:"services_added,omitempty"`
	ServicesRemoved  []string `json:"services_removed,omitempty"`
	ServicesModified []string `json:"services_modified,omitempty"`
}

// DryRunRequest represents a dry-run request.
type DryRunContentRequest struct {
	ComposeContent string `json:"compose_content"`
	EnvContent     string `json:"env_content,omitempty"`
}

// ListVersions lists all versions of a stack.
// GET /api/v1/stacks/{stackID}/versions
func (h *StackHandler) ListVersions(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	versions, err := h.stackService.ListVersions(r.Context(), stackID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]StackVersionResponse, len(versions))
	for i, v := range versions {
		resp[i] = toStackVersionResponse(v)
	}

	h.OK(w, resp)
}

// CreateVersion creates a new version of a stack.
// POST /api/v1/stacks/{stackID}/versions
func (h *StackHandler) CreateVersion(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req CreateVersionRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	var userID *uuid.UUID
	if uid, err := h.GetUserID(r); err == nil {
		userID = &uid
	}

	version, err := h.stackService.CreateVersion(r.Context(), stackID, req.Comment, userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, toStackVersionResponse(version))
}

// GetVersion gets a specific version of a stack.
// GET /api/v1/stacks/{stackID}/versions/{version}
func (h *StackHandler) GetVersion(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	versionNum, err := strconv.Atoi(chi.URLParam(r, "version"))
	if err != nil {
		h.BadRequest(w, "invalid version number")
		return
	}

	version, err := h.stackService.GetVersion(r.Context(), stackID, versionNum)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toStackVersionResponse(version))
}

// DiffVersions compares two versions of a stack.
// GET /api/v1/stacks/{stackID}/versions/{fromVersion}/diff/{toVersion}
func (h *StackHandler) DiffVersions(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	fromVersion, err := strconv.Atoi(chi.URLParam(r, "fromVersion"))
	if err != nil {
		h.BadRequest(w, "invalid from version")
		return
	}

	toVersion, err := strconv.Atoi(chi.URLParam(r, "toVersion"))
	if err != nil {
		h.BadRequest(w, "invalid to version")
		return
	}

	diff, err := h.stackService.DiffVersions(r.Context(), stackID, fromVersion, toVersion)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toDiffResponse(diff))
}

// RestoreVersion restores a stack to a previous version.
// POST /api/v1/stacks/{stackID}/versions/{version}/restore
func (h *StackHandler) RestoreVersion(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	versionNum, err := strconv.Atoi(chi.URLParam(r, "version"))
	if err != nil {
		h.BadRequest(w, "invalid version number")
		return
	}

	var userID *uuid.UUID
	if uid, err := h.GetUserID(r); err == nil {
		userID = &uid
	}

	stack, err := h.stackService.RestoreVersion(r.Context(), stackID, versionNum, "Restored via API", userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toStackResponse(stack))
}

// DryRun validates a stack without deploying.
// POST /api/v1/stacks/{stackID}/dry-run
func (h *StackHandler) DryRun(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	result, err := h.stackService.DryRun(r.Context(), stackID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, result)
}

// DryRunContent validates compose content without creating a stack.
// POST /api/v1/stacks/dry-run
func (h *StackHandler) DryRunContent(w http.ResponseWriter, r *http.Request) {
	var req DryRunContentRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.ComposeContent == "" {
		h.BadRequest(w, "compose_content is required")
		return
	}

	result, err := h.stackService.DryRunContent(r.Context(), req.ComposeContent, req.EnvContent)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, result)
}

func toStackVersionResponse(v *models.StackVersion) StackVersionResponse {
	resp := StackVersionResponse{
		ID:          v.ID.String(),
		StackID:     v.StackID.String(),
		Version:     v.Version,
		ComposeFile: v.ComposeFile,
		EnvFile:     v.EnvFile,
		Comment:     v.Comment,
		CreatedAt:   v.CreatedAt.Format(time.RFC3339),
		IsDeployed:  v.IsDeployed,
	}
	if v.CreatedBy != nil {
		s := v.CreatedBy.String()
		resp.CreatedBy = &s
	}
	if v.DeployedAt != nil {
		s := v.DeployedAt.Format(time.RFC3339)
		resp.DeployedAt = &s
	}
	return resp
}

func toDiffResponse(d *models.StackVersionDiff) DiffResponse {
	resp := DiffResponse{
		FromVersion: d.FromVersion,
		ToVersion:   d.ToVersion,
		Summary: DiffSummaryResponse{
			LinesAdded:       d.Summary.LinesAdded,
			LinesRemoved:     d.Summary.LinesRemoved,
			ServicesAdded:    d.Summary.ServicesAdded,
			ServicesRemoved:  d.Summary.ServicesRemoved,
			ServicesModified: d.Summary.ServicesModified,
		},
	}

	resp.ComposeChanges = make([]DiffLineResponse, len(d.ComposeChanges))
	for i, c := range d.ComposeChanges {
		resp.ComposeChanges[i] = DiffLineResponse{
			Type:    string(c.Type),
			Content: c.Content,
			OldLine: c.OldLine,
			NewLine: c.NewLine,
		}
	}

	if len(d.EnvChanges) > 0 {
		resp.EnvChanges = make([]DiffLineResponse, len(d.EnvChanges))
		for i, c := range d.EnvChanges {
			resp.EnvChanges[i] = DiffLineResponse{
				Type:    string(c.Type),
				Content: c.Content,
				OldLine: c.OldLine,
				NewLine: c.NewLine,
			}
		}
	}

	return resp
}

// ============================================================================
// Dependency Handlers
// ============================================================================

// DependencyResponse represents a stack dependency in API responses.
type DependencyResponse struct {
	ID            string `json:"id"`
	StackID       string `json:"stack_id"`
	DependsOnID   string `json:"depends_on_id"`
	DependsOnName string `json:"depends_on_name"`
	Condition     string `json:"condition"`
	Optional      bool   `json:"optional"`
	CreatedAt     string `json:"created_at"`
}

// AddDependencyRequest represents an add dependency request.
type AddDependencyRequest struct {
	DependsOnID string `json:"depends_on_id"`
	Condition   string `json:"condition,omitempty"` // "started", "healthy", "completed"
	Optional    bool   `json:"optional,omitempty"`
}

// ListDependencies lists all dependencies for a stack.
// GET /api/v1/stacks/{stackID}/dependencies
func (h *StackHandler) ListDependencies(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	deps, err := h.stackService.ListDependencies(r.Context(), stackID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]DependencyResponse, len(deps))
	for i, d := range deps {
		resp[i] = DependencyResponse{
			ID:            d.ID.String(),
			StackID:       d.StackID.String(),
			DependsOnID:   d.DependsOnID.String(),
			DependsOnName: d.DependsOnName,
			Condition:     d.Condition,
			Optional:      d.Optional,
			CreatedAt:     d.CreatedAt.Format(time.RFC3339),
		}
	}

	h.OK(w, resp)
}

// AddDependency adds a dependency to a stack.
// POST /api/v1/stacks/{stackID}/dependencies
func (h *StackHandler) AddDependency(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req AddDependencyRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	dependsOnID, err := uuid.Parse(req.DependsOnID)
	if err != nil {
		h.BadRequest(w, "invalid depends_on_id")
		return
	}

	dep, err := h.stackService.AddDependency(r.Context(), stackID, dependsOnID, req.Condition, req.Optional)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, DependencyResponse{
		ID:            dep.ID.String(),
		StackID:       dep.StackID.String(),
		DependsOnID:   dep.DependsOnID.String(),
		DependsOnName: dep.DependsOnName,
		Condition:     dep.Condition,
		Optional:      dep.Optional,
		CreatedAt:     dep.CreatedAt.Format(time.RFC3339),
	})
}

// RemoveDependency removes a dependency from a stack.
// DELETE /api/v1/stacks/{stackID}/dependencies/{dependsOnID}
func (h *StackHandler) RemoveDependency(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	dependsOnID, err := uuid.Parse(chi.URLParam(r, "dependsOnID"))
	if err != nil {
		h.BadRequest(w, "invalid depends_on_id")
		return
	}

	if err := h.stackService.RemoveDependency(r.Context(), stackID, dependsOnID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// GetDependents returns stacks that depend on the given stack.
// GET /api/v1/stacks/{stackID}/dependents
func (h *StackHandler) GetDependents(w http.ResponseWriter, r *http.Request) {
	stackID, err := h.URLParamUUID(r, "stackID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	deps, err := h.stackService.GetDependents(r.Context(), stackID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]DependencyResponse, len(deps))
	for i, d := range deps {
		resp[i] = DependencyResponse{
			ID:            d.ID.String(),
			StackID:       d.StackID.String(),
			DependsOnID:   d.DependsOnID.String(),
			DependsOnName: d.DependsOnName,
			Condition:     d.Condition,
			Optional:      d.Optional,
			CreatedAt:     d.CreatedAt.Format(time.RFC3339),
		}
	}

	h.OK(w, resp)
}
