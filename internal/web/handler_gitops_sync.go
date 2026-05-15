// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	gitprovider "github.com/fr4nsys/usulnet/internal/integrations/git"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/ephemeral"
	"github.com/fr4nsys/usulnet/internal/services/gitsync"
	"github.com/fr4nsys/usulnet/internal/services/manifest"
)

// ============================================================================
// Bidirectional Git Sync Handlers
// ============================================================================

// GitSyncConfigsJSON returns all git sync configurations.
func (h *Handler) GitSyncConfigsJSON(w http.ResponseWriter, r *http.Request) {
	if h.gitSyncSvc == nil {
		h.jsonError(w, "git sync service unavailable", http.StatusServiceUnavailable)
		return
	}

	configs, err := h.gitSyncSvc.ListConfigs(r.Context())
	if err != nil {
		h.jsonError(w, "failed to list sync configs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(configs) //nolint:errcheck
}

// GitSyncConfigCreate creates a new sync configuration.
func (h *Handler) GitSyncConfigCreate(w http.ResponseWriter, r *http.Request) {
	if h.gitSyncSvc == nil {
		h.jsonError(w, "git sync service unavailable", http.StatusServiceUnavailable)
		return
	}

	var input gitsync.CreateSyncInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	cfg, err := h.gitSyncSvc.CreateSyncConfig(r.Context(), input)
	if err != nil {
		h.jsonError(w, "failed to create sync config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(cfg) //nolint:errcheck
}

// GitSyncConfigGet returns a single sync configuration.
func (h *Handler) GitSyncConfigGet(w http.ResponseWriter, r *http.Request) {
	if h.gitSyncSvc == nil {
		h.jsonError(w, "git sync service unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid config ID", http.StatusBadRequest)
		return
	}

	cfg, err := h.gitSyncSvc.GetConfig(r.Context(), id)
	if err != nil {
		h.jsonError(w, "config not found: "+err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg) //nolint:errcheck
}

// GitSyncConfigDelete deletes a sync configuration.
func (h *Handler) GitSyncConfigDelete(w http.ResponseWriter, r *http.Request) {
	if h.gitSyncSvc == nil {
		h.jsonError(w, "git sync service unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid config ID", http.StatusBadRequest)
		return
	}

	if err := h.gitSyncSvc.DeleteConfig(r.Context(), id); err != nil {
		h.jsonError(w, "failed to delete config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GitSyncConfigToggle toggles a sync configuration enabled/disabled.
func (h *Handler) GitSyncConfigToggle(w http.ResponseWriter, r *http.Request) {
	if h.gitSyncSvc == nil {
		h.jsonError(w, "git sync service unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid config ID", http.StatusBadRequest)
		return
	}

	newState, err := h.gitSyncSvc.ToggleConfig(r.Context(), id)
	if err != nil {
		h.jsonError(w, "failed to toggle config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"enabled": newState}) //nolint:errcheck
}

// GitSyncEventsJSON returns sync events for a configuration.
func (h *Handler) GitSyncEventsJSON(w http.ResponseWriter, r *http.Request) {
	if h.gitSyncSvc == nil {
		h.jsonError(w, "git sync service unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid config ID", http.StatusBadRequest)
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	events, err := h.gitSyncSvc.GetSyncEvents(r.Context(), id, limit)
	if err != nil {
		h.jsonError(w, "failed to list events: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events) //nolint:errcheck
}

// GitSyncConflictsJSON returns conflicts for a configuration.
func (h *Handler) GitSyncConflictsJSON(w http.ResponseWriter, r *http.Request) {
	if h.gitSyncSvc == nil {
		h.jsonError(w, "git sync service unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid config ID", http.StatusBadRequest)
		return
	}

	resolution := r.URL.Query().Get("resolution")

	conflicts, err := h.gitSyncSvc.ListConflicts(r.Context(), id, resolution)
	if err != nil {
		h.jsonError(w, "failed to list conflicts: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(conflicts) //nolint:errcheck
}

// GitSyncConflictResolve resolves a sync conflict.
func (h *Handler) GitSyncConflictResolve(w http.ResponseWriter, r *http.Request) {
	if h.gitSyncSvc == nil {
		h.jsonError(w, "git sync service unavailable", http.StatusServiceUnavailable)
		return
	}

	conflictID, err := uuid.Parse(chi.URLParam(r, "conflictId"))
	if err != nil {
		h.jsonError(w, "invalid conflict ID", http.StatusBadRequest)
		return
	}

	var body struct {
		Resolution    models.ConflictResolution `json:"resolution"`
		MergedContent *string                   `json:"merged_content,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Extract resolved_by from the authenticated user context, not from the
	// client body, to ensure the audit trail is always accurate.
	var resolvedBy uuid.UUID
	if uid := h.getUserID(r); uid != nil {
		resolvedBy = *uid
	}

	if err := h.gitSyncSvc.ResolveConflict(r.Context(), conflictID, body.Resolution, resolvedBy, body.MergedContent); err != nil {
		h.jsonError(w, "failed to resolve conflict: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GitSyncStatsJSON returns aggregated sync statistics.
func (h *Handler) GitSyncStatsJSON(w http.ResponseWriter, r *http.Request) {
	if h.gitSyncSvc == nil {
		h.jsonError(w, "git sync service unavailable", http.StatusServiceUnavailable)
		return
	}

	stats, err := h.gitSyncSvc.GetSyncStats(r.Context())
	if err != nil {
		h.jsonError(w, "failed to get sync stats: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats) //nolint:errcheck
}

// GitSyncTrigger manually triggers a sync operation for a configuration.
func (h *Handler) GitSyncTrigger(w http.ResponseWriter, r *http.Request) {
	if h.gitSyncSvc == nil {
		h.jsonError(w, "git sync service unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid config ID", http.StatusBadRequest)
		return
	}

	// Fetch the config to get connection ID and direction.
	cfg, err := h.gitSyncSvc.GetConfig(r.Context(), id)
	if err != nil {
		h.jsonError(w, "config not found: "+err.Error(), http.StatusNotFound)
		return
	}

	if !cfg.IsEnabled {
		h.jsonError(w, "sync config is disabled", http.StatusConflict)
		return
	}

	// Build git provider from the connection.
	if h.gitSvcFull == nil {
		h.jsonError(w, "git service not configured — cannot resolve git provider", http.StatusServiceUnavailable)
		return
	}

	rawProvider, err := h.gitSvcFull.GetProviderForConnection(r.Context(), cfg.ConnectionID)
	if err != nil {
		h.jsonError(w, "failed to resolve git provider: "+err.Error(), http.StatusInternalServerError)
		return
	}

	gitProv := &gitSyncGitAdapter{provider: rawProvider}
	stackProv := &gitSyncStackAdapter{stacks: h.services.Stacks()}

	var result *gitsync.SyncResult

	switch cfg.SyncDirection {
	case models.SyncDirectionToGit:
		result, err = h.gitSyncSvc.SyncToGit(r.Context(), id, gitProv, stackProv)
	case models.SyncDirectionFromGit:
		result, err = h.gitSyncSvc.SyncFromGit(r.Context(), id, gitProv, stackProv)
	case models.SyncDirectionBidirectional:
		result, err = h.gitSyncSvc.SyncBidirectional(r.Context(), id, gitProv, stackProv)
	default:
		h.jsonError(w, "unknown sync direction: "+string(cfg.SyncDirection), http.StatusBadRequest)
		return
	}

	if err != nil {
		h.jsonError(w, "sync failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result) //nolint:errcheck
}

// ============================================================================
// Git Sync Provider Adapters
// ============================================================================

// gitSyncGitAdapter bridges git.Provider → gitsync.GitProvider.
type gitSyncGitAdapter struct {
	provider gitprovider.Provider
}

func (a *gitSyncGitAdapter) GetFileContent(ctx context.Context, repoFullName, path, ref string) (*models.GitFileContent, error) {
	return a.provider.GetFileContent(ctx, repoFullName, path, ref)
}

func (a *gitSyncGitAdapter) CreateOrUpdateFile(ctx context.Context, repoFullName, path string, content []byte, message, branch, sha string) error {
	return a.provider.CreateOrUpdateFile(ctx, repoFullName, path, gitprovider.UpdateFileOptions{
		Branch:  branch,
		Message: message,
		Content: content,
		SHA:     sha,
	})
}

func (a *gitSyncGitAdapter) ListTree(ctx context.Context, repoFullName, path, ref string) ([]models.GitTreeEntry, error) {
	return a.provider.ListTree(ctx, repoFullName, path, ref)
}

func (a *gitSyncGitAdapter) GetLatestCommit(ctx context.Context, repoFullName, branch string) (*models.GitCommit, error) {
	commits, err := a.provider.ListCommits(ctx, repoFullName, gitprovider.ListCommitsOptions{
		SHA:     branch,
		PerPage: 1,
	})
	if err != nil {
		return nil, err
	}
	if len(commits) == 0 {
		return nil, nil
	}
	return &commits[0], nil
}

// gitSyncStackAdapter bridges web.StackService → gitsync.StackProvider.
type gitSyncStackAdapter struct {
	stacks StackService
}

func (a *gitSyncStackAdapter) GetStackCompose(ctx context.Context, stackName string) (string, error) {
	return a.stacks.GetComposeConfig(ctx, stackName)
}

func (a *gitSyncStackAdapter) DeployStack(ctx context.Context, stackName string, composeContent string) error {
	return a.stacks.Deploy(ctx, stackName, composeContent)
}

func (a *gitSyncStackAdapter) ListStacks(ctx context.Context) ([]string, error) {
	views, err := a.stacks.List(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(views))
	for i, v := range views {
		names[i] = v.Name
	}
	return names, nil
}

// ============================================================================
// Ephemeral Environment Adapters
// ============================================================================

// ephemeralStackAdapter bridges web.StackService → ephemeral.StackDeployer.
type ephemeralStackAdapter struct {
	stacks StackService
}

func (a *ephemeralStackAdapter) DeployStack(ctx context.Context, stackName string, composeContent string, env map[string]string) error {
	// The web-layer StackService.Deploy does not accept env vars — the env
	// is baked into the compose content by the ephemeral service before calling.
	return a.stacks.Deploy(ctx, stackName, composeContent)
}

func (a *ephemeralStackAdapter) RemoveStack(ctx context.Context, stackName string) error {
	return a.stacks.Remove(ctx, stackName)
}

func (a *ephemeralStackAdapter) GetStackStatus(ctx context.Context, stackName string) (string, error) {
	sv, err := a.stacks.Get(ctx, stackName)
	if err != nil {
		return "", err
	}
	return sv.Status, nil
}

// ============================================================================
// Ephemeral Environments Handlers
// ============================================================================

// EphemeralEnvsJSON returns all ephemeral environments.
func (h *Handler) EphemeralEnvsJSON(w http.ResponseWriter, r *http.Request) {
	if h.ephemeralSvc == nil {
		h.jsonError(w, "ephemeral environments service unavailable", http.StatusServiceUnavailable)
		return
	}

	opts := models.EphemeralEnvListOptions{
		Status: r.URL.Query().Get("status"),
		Branch: r.URL.Query().Get("branch"),
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			opts.Limit = parsed
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			opts.Offset = parsed
		}
	}

	envs, err := h.ephemeralSvc.ListEnvironments(r.Context(), opts)
	if err != nil {
		h.jsonError(w, "failed to list environments: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(envs) //nolint:errcheck
}

// EphemeralEnvCreate creates a new ephemeral environment.
func (h *Handler) EphemeralEnvCreate(w http.ResponseWriter, r *http.Request) {
	if h.ephemeralSvc == nil {
		h.jsonError(w, "ephemeral environments service unavailable", http.StatusServiceUnavailable)
		return
	}

	var input ephemeral.CreateEnvInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	env, err := h.ephemeralSvc.CreateEnvironment(r.Context(), input)
	if err != nil {
		h.jsonError(w, "failed to create environment: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(env) //nolint:errcheck
}

// EphemeralEnvProvision provisions a pending ephemeral environment by deploying
// its stack. Requires compose content to have been set at creation time.
// POST /ephemeral-envs/{id}/provision
func (h *Handler) EphemeralEnvProvision(w http.ResponseWriter, r *http.Request) {
	if h.ephemeralSvc == nil {
		h.jsonError(w, "ephemeral environments service unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid environment ID", http.StatusBadRequest)
		return
	}

	deployer := &ephemeralStackAdapter{stacks: h.services.Stacks()}

	// Build git provider if the environment has a connection (for fetching compose from Git).
	var gitProv ephemeral.GitFileProvider
	if h.gitSvcFull != nil {
		env, err := h.ephemeralSvc.GetEnvironment(r.Context(), id)
		if err == nil && env.ConnectionID != nil {
			if rawProv, provErr := h.gitSvcFull.GetProviderForConnection(r.Context(), *env.ConnectionID); provErr == nil {
				gitProv = &gitSyncGitAdapter{provider: rawProv}
			}
		}
	}

	if err := h.ephemeralSvc.ProvisionEnvironment(r.Context(), id, gitProv, deployer); err != nil {
		h.jsonError(w, "failed to provision environment: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

// EphemeralEnvGet returns a single ephemeral environment.
func (h *Handler) EphemeralEnvGet(w http.ResponseWriter, r *http.Request) {
	if h.ephemeralSvc == nil {
		h.jsonError(w, "ephemeral environments service unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid environment ID", http.StatusBadRequest)
		return
	}

	env, err := h.ephemeralSvc.GetEnvironment(r.Context(), id)
	if err != nil {
		h.jsonError(w, "environment not found: "+err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(env) //nolint:errcheck
}

// EphemeralEnvStop stops a running ephemeral environment.
func (h *Handler) EphemeralEnvStop(w http.ResponseWriter, r *http.Request) {
	if h.ephemeralSvc == nil {
		h.jsonError(w, "ephemeral environments service unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid environment ID", http.StatusBadRequest)
		return
	}

	deployer := &ephemeralStackAdapter{stacks: h.services.Stacks()}
	if err := h.ephemeralSvc.StopEnvironment(r.Context(), id, deployer); err != nil {
		h.jsonError(w, "failed to stop environment: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// EphemeralEnvDestroy destroys an ephemeral environment.
func (h *Handler) EphemeralEnvDestroy(w http.ResponseWriter, r *http.Request) {
	if h.ephemeralSvc == nil {
		h.jsonError(w, "ephemeral environments service unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid environment ID", http.StatusBadRequest)
		return
	}

	deployer := &ephemeralStackAdapter{stacks: h.services.Stacks()}
	if err := h.ephemeralSvc.DestroyEnvironment(r.Context(), id, deployer); err != nil {
		h.jsonError(w, "failed to destroy environment: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// EphemeralEnvExtendTTL extends the TTL of an ephemeral environment.
func (h *Handler) EphemeralEnvExtendTTL(w http.ResponseWriter, r *http.Request) {
	if h.ephemeralSvc == nil {
		h.jsonError(w, "ephemeral environments service unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid environment ID", http.StatusBadRequest)
		return
	}

	var body struct {
		AdditionalMinutes int `json:"additional_minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.ephemeralSvc.ExtendTTL(r.Context(), id, body.AdditionalMinutes); err != nil {
		h.jsonError(w, "failed to extend TTL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// EphemeralEnvLogsJSON returns logs for an ephemeral environment.
func (h *Handler) EphemeralEnvLogsJSON(w http.ResponseWriter, r *http.Request) {
	if h.ephemeralSvc == nil {
		h.jsonError(w, "ephemeral environments service unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid environment ID", http.StatusBadRequest)
		return
	}

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	logs, err := h.ephemeralSvc.GetLogs(r.Context(), id, limit)
	if err != nil {
		h.jsonError(w, "failed to get logs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs) //nolint:errcheck
}

// EphemeralEnvDashboardJSON returns ephemeral environment dashboard data.
func (h *Handler) EphemeralEnvDashboardJSON(w http.ResponseWriter, r *http.Request) {
	if h.ephemeralSvc == nil {
		h.jsonError(w, "ephemeral environments service unavailable", http.StatusServiceUnavailable)
		return
	}

	dashboard, err := h.ephemeralSvc.GetDashboard(r.Context())
	if err != nil {
		h.jsonError(w, "failed to get dashboard: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dashboard) //nolint:errcheck
}

// ============================================================================
// Manifest Builder Handlers
// ============================================================================

// ManifestTemplatesJSON returns all manifest templates.
func (h *Handler) ManifestTemplatesJSON(w http.ResponseWriter, r *http.Request) {
	if h.manifestSvc == nil {
		h.jsonError(w, "manifest builder service unavailable", http.StatusServiceUnavailable)
		return
	}

	format := r.URL.Query().Get("format")
	category := r.URL.Query().Get("category")

	templates, err := h.manifestSvc.ListTemplates(r.Context(), format, category)
	if err != nil {
		h.jsonError(w, "failed to list templates: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(templates) //nolint:errcheck
}

// ManifestTemplateCreate creates a new manifest template.
func (h *Handler) ManifestTemplateCreate(w http.ResponseWriter, r *http.Request) {
	if h.manifestSvc == nil {
		h.jsonError(w, "manifest builder service unavailable", http.StatusServiceUnavailable)
		return
	}

	var input manifest.CreateTemplateInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	tmpl, err := h.manifestSvc.CreateTemplate(r.Context(), input)
	if err != nil {
		h.jsonError(w, "failed to create template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(tmpl) //nolint:errcheck
}

// ManifestTemplateGet returns a single manifest template.
func (h *Handler) ManifestTemplateGet(w http.ResponseWriter, r *http.Request) {
	if h.manifestSvc == nil {
		h.jsonError(w, "manifest builder service unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid template ID", http.StatusBadRequest)
		return
	}

	tmpl, err := h.manifestSvc.GetTemplate(r.Context(), id)
	if err != nil {
		h.jsonError(w, "template not found: "+err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tmpl) //nolint:errcheck
}

// ManifestTemplateDelete deletes a manifest template.
func (h *Handler) ManifestTemplateDelete(w http.ResponseWriter, r *http.Request) {
	if h.manifestSvc == nil {
		h.jsonError(w, "manifest builder service unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid template ID", http.StatusBadRequest)
		return
	}

	if err := h.manifestSvc.DeleteTemplate(r.Context(), id); err != nil {
		h.jsonError(w, "failed to delete template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ManifestTemplateRender renders a template with provided variables.
func (h *Handler) ManifestTemplateRender(w http.ResponseWriter, r *http.Request) {
	if h.manifestSvc == nil {
		h.jsonError(w, "manifest builder service unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid template ID", http.StatusBadRequest)
		return
	}

	var body struct {
		Variables map[string]string `json:"variables"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	rendered, err := h.manifestSvc.RenderTemplate(r.Context(), id, body.Variables)
	if err != nil {
		h.jsonError(w, "failed to render template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"content": rendered}) //nolint:errcheck
}

// ManifestTemplateCategoriesJSON returns available template categories.
func (h *Handler) ManifestTemplateCategoriesJSON(w http.ResponseWriter, r *http.Request) {
	if h.manifestSvc == nil {
		h.jsonError(w, "manifest builder service unavailable", http.StatusServiceUnavailable)
		return
	}

	categories, err := h.manifestSvc.ListCategories(r.Context())
	if err != nil {
		h.jsonError(w, "failed to list categories: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(categories) //nolint:errcheck
}

// ManifestSessionsJSON returns all builder sessions for the current user.
func (h *Handler) ManifestSessionsJSON(w http.ResponseWriter, r *http.Request) {
	if h.manifestSvc == nil {
		h.jsonError(w, "manifest builder service unavailable", http.StatusServiceUnavailable)
		return
	}

	userID := h.getUserID(r)
	if userID == nil {
		h.jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	sessions, err := h.manifestSvc.ListSessions(r.Context(), *userID)
	if err != nil {
		h.jsonError(w, "failed to list sessions: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions) //nolint:errcheck
}

// ManifestSessionCreate creates a new builder session.
func (h *Handler) ManifestSessionCreate(w http.ResponseWriter, r *http.Request) {
	if h.manifestSvc == nil {
		h.jsonError(w, "manifest builder service unavailable", http.StatusServiceUnavailable)
		return
	}

	userID := h.getUserID(r)
	if userID == nil {
		h.jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		Name   string                `json:"name"`
		Format models.ManifestFormat `json:"format"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if body.Name == "" {
		body.Name = "Untitled"
	}
	if body.Format == "" {
		body.Format = models.ManifestFormatCompose
	}

	session, err := h.manifestSvc.CreateSession(r.Context(), *userID, body.Name, body.Format)
	if err != nil {
		h.jsonError(w, "failed to create session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(session) //nolint:errcheck
}

// ManifestSessionGet returns a single builder session.
func (h *Handler) ManifestSessionGet(w http.ResponseWriter, r *http.Request) {
	if h.manifestSvc == nil {
		h.jsonError(w, "manifest builder service unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid session ID", http.StatusBadRequest)
		return
	}

	session, err := h.manifestSvc.GetSession(r.Context(), id)
	if err != nil {
		h.jsonError(w, "session not found: "+err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session) //nolint:errcheck
}

// ManifestSessionUpdate updates a builder session's canvas state and services.
func (h *Handler) ManifestSessionUpdate(w http.ResponseWriter, r *http.Request) {
	if h.manifestSvc == nil {
		h.jsonError(w, "manifest builder service unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid session ID", http.StatusBadRequest)
		return
	}

	var body struct {
		CanvasState json.RawMessage               `json:"canvas_state"`
		Services    []models.ManifestServiceBlock `json:"services"`
		Networks    json.RawMessage               `json:"networks"`
		Volumes     json.RawMessage               `json:"volumes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.manifestSvc.UpdateSessionCanvas(r.Context(), id, body.CanvasState, body.Services, body.Networks, body.Volumes); err != nil {
		h.jsonError(w, "failed to update session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ManifestSessionDelete deletes a builder session.
func (h *Handler) ManifestSessionDelete(w http.ResponseWriter, r *http.Request) {
	if h.manifestSvc == nil {
		h.jsonError(w, "manifest builder service unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid session ID", http.StatusBadRequest)
		return
	}

	if err := h.manifestSvc.DeleteSession(r.Context(), id); err != nil {
		h.jsonError(w, "failed to delete session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ManifestSessionSave marks a builder session as saved.
func (h *Handler) ManifestSessionSave(w http.ResponseWriter, r *http.Request) {
	if h.manifestSvc == nil {
		h.jsonError(w, "manifest builder service unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid session ID", http.StatusBadRequest)
		return
	}

	if err := h.manifestSvc.SaveSession(r.Context(), id); err != nil {
		h.jsonError(w, "failed to save session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ManifestGenerateJSON generates a manifest from service blocks.
func (h *Handler) ManifestGenerateJSON(w http.ResponseWriter, r *http.Request) {
	if h.manifestSvc == nil {
		h.jsonError(w, "manifest builder service unavailable", http.StatusServiceUnavailable)
		return
	}

	var body struct {
		Services []models.ManifestServiceBlock `json:"services"`
		Networks json.RawMessage               `json:"networks"`
		Volumes  json.RawMessage               `json:"volumes"`
		Version  string                        `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if body.Version == "" {
		body.Version = "3.8"
	}

	content, errors := h.manifestSvc.GenerateCompose(body.Services, body.Networks, body.Volumes, body.Version)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"content": content,
		"errors":  errors,
	})
}

// ManifestValidateJSON validates a manifest.
func (h *Handler) ManifestValidateJSON(w http.ResponseWriter, r *http.Request) {
	if h.manifestSvc == nil {
		h.jsonError(w, "manifest builder service unavailable", http.StatusServiceUnavailable)
		return
	}

	var body struct {
		Content string                `json:"content"`
		Format  models.ManifestFormat `json:"format"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if body.Format == "" {
		body.Format = models.ManifestFormatCompose
	}

	errors := h.manifestSvc.ValidateManifest(body.Content, body.Format)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"valid":  len(errors) == 0,
		"errors": errors,
	})
}

// ManifestComponentsJSON returns available builder components.
func (h *Handler) ManifestComponentsJSON(w http.ResponseWriter, r *http.Request) {
	if h.manifestSvc == nil {
		h.jsonError(w, "manifest builder service unavailable", http.StatusServiceUnavailable)
		return
	}

	category := r.URL.Query().Get("category")

	components, err := h.manifestSvc.ListComponents(r.Context(), category)
	if err != nil {
		h.jsonError(w, "failed to list components: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(components) //nolint:errcheck
}

// ManifestSeedJSON seeds builtin templates and components.
func (h *Handler) ManifestSeedJSON(w http.ResponseWriter, r *http.Request) {
	if h.manifestSvc == nil {
		h.jsonError(w, "manifest builder service unavailable", http.StatusServiceUnavailable)
		return
	}

	ctx := r.Context()

	if err := h.manifestSvc.SeedBuiltinComponents(ctx); err != nil {
		h.jsonError(w, "failed to seed components: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := h.manifestSvc.SeedBuiltinTemplates(ctx); err != nil {
		h.jsonError(w, "failed to seed templates: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "seeded"}) //nolint:errcheck
}
