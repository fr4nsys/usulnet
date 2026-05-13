// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	dashboardsvc "github.com/fr4nsys/usulnet/internal/services/dashboard"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/enterprise"
)

// ============================================================================
// Compliance Frameworks
// ============================================================================

// ComplianceFrameworksTempl returns the list of compliance frameworks as JSON.
func (h *Handler) ComplianceFrameworksTempl(w http.ResponseWriter, r *http.Request) {
	if h.complianceFrameworkSvc == nil {
		h.jsonError(w, "Compliance frameworks not configured", http.StatusServiceUnavailable)
		return
	}

	frameworks, err := h.complianceFrameworkSvc.ListFrameworks(r.Context())
	if err != nil {
		h.jsonError(w, "Failed to list frameworks: "+err.Error(), http.StatusInternalServerError)
		return
	}

	type frameworkView struct {
		ID          string  `json:"id"`
		Name        string  `json:"name"`
		DisplayName string  `json:"display_name"`
		Description string  `json:"description"`
		Version     string  `json:"version"`
		IsEnabled   bool    `json:"is_enabled"`
		Score       float64 `json:"score"`
		Controls    int     `json:"controls"`
	}

	views := make([]frameworkView, 0, len(frameworks))
	for _, f := range frameworks {
		views = append(views, frameworkView{
			ID:          f.ID.String(),
			Name:        f.Name,
			DisplayName: f.DisplayName,
			Description: f.Description,
			Version:     f.Version,
			IsEnabled:   f.IsEnabled,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(views) //nolint:errcheck
}

// ComplianceFrameworkAssess runs an assessment for a framework.
func (h *Handler) ComplianceFrameworkAssess(w http.ResponseWriter, r *http.Request) {
	if h.complianceFrameworkSvc == nil {
		h.jsonError(w, "Compliance frameworks not configured", http.StatusServiceUnavailable)
		return
	}

	frameworkID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "Invalid framework ID", http.StatusBadRequest)
		return
	}

	userID := h.getUserID(r)
	assessment, err := h.complianceFrameworkSvc.RunAssessment(r.Context(), frameworkID, userID)
	if err != nil {
		h.jsonError(w, "Assessment failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(assessment) //nolint:errcheck
}

// ComplianceFrameworkReport generates a compliance report.
func (h *Handler) ComplianceFrameworkReport(w http.ResponseWriter, r *http.Request) {
	if h.complianceFrameworkSvc == nil {
		h.jsonError(w, "Compliance frameworks not configured", http.StatusServiceUnavailable)
		return
	}

	assessmentID, err := uuid.Parse(chi.URLParam(r, "assessmentId"))
	if err != nil {
		h.jsonError(w, "Invalid assessment ID", http.StatusBadRequest)
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	data, err := h.complianceFrameworkSvc.GenerateReport(r.Context(), assessmentID, format)
	if err != nil {
		h.jsonError(w, "Report generation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	switch format {
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="compliance-report.html"`)
	case "pdf":
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="compliance-report.pdf"`)
	default:
		w.Header().Set("Content-Type", "application/json")
	}
	w.Write(data) //nolint:errcheck
}

// ComplianceFrameworkSeed seeds default frameworks.
func (h *Handler) ComplianceFrameworkSeed(w http.ResponseWriter, r *http.Request) {
	if h.complianceFrameworkSvc == nil {
		h.jsonError(w, "Compliance frameworks not configured", http.StatusServiceUnavailable)
		return
	}

	if err := h.complianceFrameworkSvc.SeedFrameworks(r.Context()); err != nil {
		h.jsonError(w, "Failed to seed frameworks: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Frameworks seeded successfully"}) //nolint:errcheck
}

// ============================================================================
// OPA Policies
// ============================================================================

// OPAPoliciesJSON returns OPA policies as JSON.
func (h *Handler) OPAPoliciesJSON(w http.ResponseWriter, r *http.Request) {
	if h.opaSvc == nil {
		h.jsonError(w, "OPA policy engine not configured", http.StatusServiceUnavailable)
		return
	}

	category := r.URL.Query().Get("category")
	policies, err := h.opaSvc.ListPolicies(r.Context(), category)
	if err != nil {
		h.jsonError(w, "Failed to list policies: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policies) //nolint:errcheck
}

// OPAPolicyEvaluateContainer evaluates OPA policies against a container.
func (h *Handler) OPAPolicyEvaluateContainer(w http.ResponseWriter, r *http.Request) {
	if h.opaSvc == nil {
		h.jsonError(w, "OPA policy engine not configured", http.StatusServiceUnavailable)
		return
	}

	if h.services == nil {
		h.jsonError(w, "Service registry not configured", http.StatusServiceUnavailable)
		return
	}

	containerID := chi.URLParam(r, "id")
	if containerID == "" {
		h.jsonError(w, "Container ID required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	container, err := h.services.Containers().Get(ctx, containerID)
	if err != nil {
		h.jsonError(w, "Failed to get container: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Build the base input map from the ContainerView.
	inputData := map[string]interface{}{
		"id":    container.ID,
		"name":  container.Name,
		"image": container.Image,
		"state": container.State,
	}

	// Parse image tag from image reference.
	imageTag := "latest"
	if idx := strings.LastIndex(container.Image, ":"); idx != -1 {
		imageTag = container.Image[idx+1:]
	}
	inputData["image_tag"] = imageTag

	// Include labels from the ContainerView.
	if container.Labels != nil {
		labelsMap := make(map[string]interface{}, len(container.Labels))
		for k, v := range container.Labels {
			labelsMap[k] = v
		}
		inputData["labels"] = labelsMap
	} else {
		inputData["labels"] = map[string]interface{}{}
	}

	// Enrich with Docker inspect details when available. These fields are
	// required by the seeded OPA policies (privileged, network_mode, etc.).
	dockerClient, err := h.services.Containers().GetDockerClient(ctx)
	if err == nil {
		details, err := dockerClient.ContainerGet(ctx, containerID)
		if err == nil {
			// Host config fields.
			if details.HostConfig != nil {
				hc := details.HostConfig
				inputData["privileged"] = hc.Privileged
				inputData["network_mode"] = hc.NetworkMode
				inputData["pid_mode"] = hc.PidMode
				inputData["read_only_rootfs"] = hc.ReadonlyRootfs

				// Capabilities.
				capAdd := make([]interface{}, 0, len(hc.CapAdd))
				for _, c := range hc.CapAdd {
					capAdd = append(capAdd, c)
				}
				inputData["capabilities"] = map[string]interface{}{
					"add": capAdd,
				}

				// Resource limits.
				inputData["resources"] = map[string]interface{}{
					"memory_limit": hc.Resources.Memory,
					"cpu_limit":    hc.Resources.NanoCPUs,
				}
			}

			// Container config fields.
			if details.Config != nil {
				cfg := details.Config
				inputData["config"] = map[string]interface{}{
					"user": cfg.User,
				}

				// Healthcheck.
				if cfg.Healthcheck != nil {
					testSlice := make([]interface{}, 0, len(cfg.Healthcheck.Test))
					for _, t := range cfg.Healthcheck.Test {
						testSlice = append(testSlice, t)
					}
					inputData["healthcheck"] = map[string]interface{}{
						"test": testSlice,
					}
				}
			}

			// Top-level network mode from ContainerDetails.
			if details.NetworkMode != "" {
				inputData["network_mode"] = details.NetworkMode
			}
		}
	}

	results, err := h.opaSvc.EvaluateContainer(ctx, inputData)
	if err != nil {
		h.jsonError(w, "Policy evaluation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results) //nolint:errcheck
}

// OPAPolicySeed seeds default OPA policies.
func (h *Handler) OPAPolicySeed(w http.ResponseWriter, r *http.Request) {
	if h.opaSvc == nil {
		h.jsonError(w, "OPA policy engine not configured", http.StatusServiceUnavailable)
		return
	}

	if err := h.opaSvc.SeedDefaultPolicies(r.Context()); err != nil {
		h.jsonError(w, "Failed to seed OPA policies: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "OPA policies seeded"}) //nolint:errcheck
}

// ============================================================================
// Log Aggregation & Search
// ============================================================================

// LogSearchJSON handles log search requests.
func (h *Handler) LogSearchJSON(w http.ResponseWriter, r *http.Request) {
	if h.logAggSvc == nil {
		h.jsonError(w, "Log aggregation not configured", http.StatusServiceUnavailable)
		return
	}

	query := r.URL.Query().Get("q")
	containerID := r.URL.Query().Get("container_id")
	source := r.URL.Query().Get("source")
	severity := r.URL.Query().Get("severity")
	limitStr := r.URL.Query().Get("limit")

	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	opts := models.AggregatedLogSearchOptions{
		Query:       query,
		ContainerID: containerID,
		Source:      source,
		Severity:    severity,
		Limit:       limit,
	}

	logs, total, err := h.logAggSvc.Search(r.Context(), opts)
	if err != nil {
		h.jsonError(w, "Log search failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":  logs,
		"total": total,
	}) //nolint:errcheck
}

// LogStatsJSON returns log aggregation statistics.
func (h *Handler) LogStatsJSON(w http.ResponseWriter, r *http.Request) {
	if h.logAggSvc == nil {
		h.jsonError(w, "Log aggregation not configured", http.StatusServiceUnavailable)
		return
	}

	since := time.Now().Add(-24 * time.Hour)
	if s := r.URL.Query().Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}

	stats, err := h.logAggSvc.GetStats(r.Context(), since)
	if err != nil {
		h.jsonError(w, "Failed to get log stats: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats) //nolint:errcheck
}

// ============================================================================
// Image Signing & Verification
// ============================================================================

// ImageSignaturesJSON returns signatures for an image.
func (h *Handler) ImageSignaturesJSON(w http.ResponseWriter, r *http.Request) {
	if h.imageSignSvc == nil {
		h.jsonError(w, "Image signing not configured", http.StatusServiceUnavailable)
		return
	}

	imageRef := r.URL.Query().Get("image")
	if imageRef == "" {
		h.jsonError(w, "image parameter required", http.StatusBadRequest)
		return
	}

	sigs, err := h.imageSignSvc.GetImageSignatures(r.Context(), imageRef)
	if err != nil {
		h.jsonError(w, "Failed to get signatures: "+err.Error(), apperrors.HTTPStatusCode(err))
		return
	}

	if sigs == nil {
		sigs = []*models.ImageSignature{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"signatures": sigs}) //nolint:errcheck
}

// ImageVerifyJSON verifies an image's signatures against trust policies.
func (h *Handler) ImageVerifyJSON(w http.ResponseWriter, r *http.Request) {
	if h.imageSignSvc == nil {
		h.jsonError(w, "Image signing not configured", http.StatusServiceUnavailable)
		return
	}

	imageRef := r.URL.Query().Get("image")
	if imageRef == "" {
		h.jsonError(w, "image parameter required", http.StatusBadRequest)
		return
	}

	result, err := h.imageSignSvc.VerifyImageAgainstPolicies(r.Context(), imageRef)
	if err != nil {
		h.jsonError(w, "Verification failed: "+err.Error(), apperrors.HTTPStatusCode(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result) //nolint:errcheck
}

// ImageTrustPoliciesJSON lists trust policies.
func (h *Handler) ImageTrustPoliciesJSON(w http.ResponseWriter, r *http.Request) {
	if h.imageSignSvc == nil {
		h.jsonError(w, "Image signing not configured", http.StatusServiceUnavailable)
		return
	}

	policies, err := h.imageSignSvc.ListTrustPolicies(r.Context())
	if err != nil {
		h.jsonError(w, "Failed to list trust policies: "+err.Error(), apperrors.HTTPStatusCode(err))
		return
	}

	if policies == nil {
		policies = []*models.ImageTrustPolicy{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"policies": policies}) //nolint:errcheck
}

// ImageSignSeed seeds default trust policies.
func (h *Handler) ImageSignSeed(w http.ResponseWriter, r *http.Request) {
	if h.imageSignSvc == nil {
		h.jsonError(w, "Image signing not configured", http.StatusServiceUnavailable)
		return
	}

	if err := h.imageSignSvc.SeedDefaultPolicies(r.Context()); err != nil {
		h.jsonError(w, "Failed to seed trust policies: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Trust policies seeded"}) //nolint:errcheck
}

// ============================================================================
// Runtime Threat Detection
// ============================================================================

// RuntimeEventsJSON lists runtime security events.
func (h *Handler) RuntimeEventsJSON(w http.ResponseWriter, r *http.Request) {
	if h.runtimeSecSvc == nil {
		h.jsonError(w, "Runtime security not configured", http.StatusServiceUnavailable)
		return
	}

	containerID := r.URL.Query().Get("container_id")
	severity := r.URL.Query().Get("severity")
	eventType := r.URL.Query().Get("event_type")
	limitStr := r.URL.Query().Get("limit")

	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	events, total, err := h.runtimeSecSvc.ListEvents(r.Context(), postgres.RuntimeEventListOptions{
		ContainerID: containerID,
		Severity:    severity,
		EventType:   eventType,
		Limit:       limit,
	})
	if err != nil {
		h.jsonError(w, "Failed to list events: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"total":  total,
	}) //nolint:errcheck
}

// RuntimeDashboardJSON returns the runtime security dashboard data.
func (h *Handler) RuntimeDashboardJSON(w http.ResponseWriter, r *http.Request) {
	if h.runtimeSecSvc == nil {
		h.jsonError(w, "Runtime security not configured", http.StatusServiceUnavailable)
		return
	}

	dashboard, err := h.runtimeSecSvc.GetDashboardData(r.Context())
	if err != nil {
		h.jsonError(w, "Failed to get dashboard: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dashboard) //nolint:errcheck
}

// RuntimeRulesJSON lists runtime detection rules.
func (h *Handler) RuntimeRulesJSON(w http.ResponseWriter, r *http.Request) {
	if h.runtimeSecSvc == nil {
		h.jsonError(w, "Runtime security not configured", http.StatusServiceUnavailable)
		return
	}

	rules, err := h.runtimeSecSvc.ListRules(r.Context())
	if err != nil {
		h.jsonError(w, "Failed to list rules: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules) //nolint:errcheck
}

// RuntimeEventAcknowledge acknowledges a runtime event.
func (h *Handler) RuntimeEventAcknowledge(w http.ResponseWriter, r *http.Request) {
	if h.runtimeSecSvc == nil {
		h.jsonError(w, "Runtime security not configured", http.StatusServiceUnavailable)
		return
	}

	eventIDStr := chi.URLParam(r, "id")
	eventID, err := strconv.ParseInt(eventIDStr, 10, 64)
	if err != nil {
		h.jsonError(w, "Invalid event ID", http.StatusBadRequest)
		return
	}

	userID := h.getUserID(r)
	if userID == nil {
		h.jsonError(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	if err := h.runtimeSecSvc.AcknowledgeEvent(r.Context(), eventID, *userID); err != nil {
		h.jsonError(w, "Failed to acknowledge event: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"}) //nolint:errcheck
}

// RuntimeSeedRules seeds default detection rules.
func (h *Handler) RuntimeSeedRules(w http.ResponseWriter, r *http.Request) {
	if h.runtimeSecSvc == nil {
		h.jsonError(w, "Runtime security not configured", http.StatusServiceUnavailable)
		return
	}

	if err := h.runtimeSecSvc.SeedDefaultRules(r.Context()); err != nil {
		h.jsonError(w, "Failed to seed rules: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Runtime rules seeded"}) //nolint:errcheck
}

// RuntimeMonitorAll triggers runtime monitoring for all containers.
func (h *Handler) RuntimeMonitorAll(w http.ResponseWriter, r *http.Request) {
	if h.runtimeSecSvc == nil {
		h.jsonError(w, "Runtime security not configured", http.StatusServiceUnavailable)
		return
	}

	hostID := h.services.Containers().GetHostID()
	if err := h.runtimeSecSvc.MonitorAllContainers(r.Context(), hostID); err != nil {
		h.jsonError(w, "Monitoring failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Monitoring completed"}) //nolint:errcheck
}

// ============================================================================
// Dashboard Layouts
// ============================================================================

// DashboardLayoutsJSON returns the user's dashboard layouts.
func (h *Handler) DashboardLayoutsJSON(w http.ResponseWriter, r *http.Request) {
	if h.dashboardSvc == nil {
		h.jsonError(w, "dashboard service not available", http.StatusNotImplemented)
		return
	}

	userID := h.getUserID(r)
	if userID == nil {
		h.jsonError(w, "authentication required", http.StatusUnauthorized)
		return
	}

	layouts, err := h.dashboardSvc.ListLayouts(r.Context(), *userID)
	if err != nil {
		h.jsonError(w, err.Error(), apperrors.HTTPStatusCode(err))
		return
	}

	if layouts == nil {
		layouts = []*models.DashboardLayout{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(layouts) //nolint:errcheck
}

// DashboardLayoutCreateJSON creates a new dashboard layout.
func (h *Handler) DashboardLayoutCreateJSON(w http.ResponseWriter, r *http.Request) {
	if h.dashboardSvc == nil {
		h.jsonError(w, "dashboard service not available", http.StatusNotImplemented)
		return
	}

	userID := h.getUserID(r)
	if userID == nil {
		h.jsonError(w, "authentication required", http.StatusUnauthorized)
		return
	}

	var input dashboardsvc.CreateLayoutInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	layout, err := h.dashboardSvc.CreateLayout(r.Context(), *userID, &input)
	if err != nil {
		h.jsonError(w, err.Error(), apperrors.HTTPStatusCode(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(layout) //nolint:errcheck
}

// DashboardLayoutGetJSON returns a single dashboard layout by ID.
func (h *Handler) DashboardLayoutGetJSON(w http.ResponseWriter, r *http.Request) {
	if h.dashboardSvc == nil {
		h.jsonError(w, "dashboard service not available", http.StatusNotImplemented)
		return
	}

	userID := h.getUserID(r)
	if userID == nil {
		h.jsonError(w, "authentication required", http.StatusUnauthorized)
		return
	}

	layoutID, err := uuid.Parse(chi.URLParam(r, "layoutID"))
	if err != nil {
		h.jsonError(w, "invalid layout ID", http.StatusBadRequest)
		return
	}

	layout, err := h.dashboardSvc.GetLayout(r.Context(), *userID, layoutID)
	if err != nil {
		h.jsonError(w, err.Error(), apperrors.HTTPStatusCode(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(layout) //nolint:errcheck
}

// DashboardLayoutUpdateJSON updates a dashboard layout.
func (h *Handler) DashboardLayoutUpdateJSON(w http.ResponseWriter, r *http.Request) {
	if h.dashboardSvc == nil {
		h.jsonError(w, "dashboard service not available", http.StatusNotImplemented)
		return
	}

	userID := h.getUserID(r)
	if userID == nil {
		h.jsonError(w, "authentication required", http.StatusUnauthorized)
		return
	}

	layoutID, err := uuid.Parse(chi.URLParam(r, "layoutID"))
	if err != nil {
		h.jsonError(w, "invalid layout ID", http.StatusBadRequest)
		return
	}

	var input dashboardsvc.UpdateLayoutInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	layout, err := h.dashboardSvc.UpdateLayout(r.Context(), *userID, layoutID, &input)
	if err != nil {
		h.jsonError(w, err.Error(), apperrors.HTTPStatusCode(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(layout) //nolint:errcheck
}

// DashboardLayoutDeleteJSON deletes a dashboard layout.
func (h *Handler) DashboardLayoutDeleteJSON(w http.ResponseWriter, r *http.Request) {
	if h.dashboardSvc == nil {
		h.jsonError(w, "dashboard service not available", http.StatusNotImplemented)
		return
	}

	userID := h.getUserID(r)
	if userID == nil {
		h.jsonError(w, "authentication required", http.StatusUnauthorized)
		return
	}

	layoutID, err := uuid.Parse(chi.URLParam(r, "layoutID"))
	if err != nil {
		h.jsonError(w, "invalid layout ID", http.StatusBadRequest)
		return
	}

	if err := h.dashboardSvc.DeleteLayout(r.Context(), *userID, layoutID); err != nil {
		h.jsonError(w, err.Error(), apperrors.HTTPStatusCode(err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ============================================================================
// Dashboard Widgets
// ============================================================================

// DashboardWidgetsJSON returns all widgets for a layout.
func (h *Handler) DashboardWidgetsJSON(w http.ResponseWriter, r *http.Request) {
	if h.dashboardSvc == nil {
		h.jsonError(w, "dashboard service not available", http.StatusNotImplemented)
		return
	}

	userID := h.getUserID(r)
	if userID == nil {
		h.jsonError(w, "authentication required", http.StatusUnauthorized)
		return
	}

	layoutID, err := uuid.Parse(chi.URLParam(r, "layoutID"))
	if err != nil {
		h.jsonError(w, "invalid layout ID", http.StatusBadRequest)
		return
	}

	widgets, err := h.dashboardSvc.GetLayoutWidgets(r.Context(), *userID, layoutID)
	if err != nil {
		h.jsonError(w, err.Error(), apperrors.HTTPStatusCode(err))
		return
	}

	if widgets == nil {
		widgets = []*models.DashboardWidget{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(widgets) //nolint:errcheck
}

// DashboardWidgetCreateJSON adds a widget to a layout.
func (h *Handler) DashboardWidgetCreateJSON(w http.ResponseWriter, r *http.Request) {
	if h.dashboardSvc == nil {
		h.jsonError(w, "dashboard service not available", http.StatusNotImplemented)
		return
	}

	userID := h.getUserID(r)
	if userID == nil {
		h.jsonError(w, "authentication required", http.StatusUnauthorized)
		return
	}

	layoutID, err := uuid.Parse(chi.URLParam(r, "layoutID"))
	if err != nil {
		h.jsonError(w, "invalid layout ID", http.StatusBadRequest)
		return
	}

	var input dashboardsvc.AddWidgetInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	widget, err := h.dashboardSvc.AddWidget(r.Context(), *userID, layoutID, &input)
	if err != nil {
		h.jsonError(w, err.Error(), apperrors.HTTPStatusCode(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(widget) //nolint:errcheck
}

// DashboardWidgetUpdateJSON updates a widget.
func (h *Handler) DashboardWidgetUpdateJSON(w http.ResponseWriter, r *http.Request) {
	if h.dashboardSvc == nil {
		h.jsonError(w, "dashboard service not available", http.StatusNotImplemented)
		return
	}

	userID := h.getUserID(r)
	if userID == nil {
		h.jsonError(w, "authentication required", http.StatusUnauthorized)
		return
	}

	widgetID, err := uuid.Parse(chi.URLParam(r, "widgetID"))
	if err != nil {
		h.jsonError(w, "invalid widget ID", http.StatusBadRequest)
		return
	}

	var input dashboardsvc.UpdateWidgetInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	widget, err := h.dashboardSvc.UpdateWidget(r.Context(), *userID, widgetID, &input)
	if err != nil {
		h.jsonError(w, err.Error(), apperrors.HTTPStatusCode(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(widget) //nolint:errcheck
}

// DashboardWidgetDeleteJSON removes a widget.
func (h *Handler) DashboardWidgetDeleteJSON(w http.ResponseWriter, r *http.Request) {
	if h.dashboardSvc == nil {
		h.jsonError(w, "dashboard service not available", http.StatusNotImplemented)
		return
	}

	userID := h.getUserID(r)
	if userID == nil {
		h.jsonError(w, "authentication required", http.StatusUnauthorized)
		return
	}

	widgetID, err := uuid.Parse(chi.URLParam(r, "widgetID"))
	if err != nil {
		h.jsonError(w, "invalid widget ID", http.StatusBadRequest)
		return
	}

	if err := h.dashboardSvc.RemoveWidget(r.Context(), *userID, widgetID); err != nil {
		h.jsonError(w, err.Error(), apperrors.HTTPStatusCode(err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ============================================================================
// Helper: getUserID extracts the user UUID from the request context.
// ============================================================================

func (h *Handler) getUserID(r *http.Request) *uuid.UUID {
	user := GetUserFromContext(r.Context())
	if user == nil || user.ID == "" {
		return nil
	}
	id, err := uuid.Parse(user.ID)
	if err != nil {
		return nil
	}
	return &id
}

// ============================================================================
// Compliance Frameworks — Phase 1 endpoints
// ============================================================================

// ComplianceFrameworkStatus returns the compliance posture for a single framework.
func (h *Handler) ComplianceFrameworkStatus(w http.ResponseWriter, r *http.Request) {
	if h.complianceFrameworkSvc == nil {
		h.jsonError(w, "Compliance frameworks not configured", http.StatusServiceUnavailable)
		return
	}

	frameworkID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "Invalid framework ID", http.StatusBadRequest)
		return
	}

	status, err := h.complianceFrameworkSvc.GetFrameworkStatus(r.Context(), frameworkID)
	if err != nil {
		h.jsonError(w, "Failed to get framework status: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status) //nolint:errcheck
}

// ComplianceFrameworkControls returns all controls for a framework.
func (h *Handler) ComplianceFrameworkControls(w http.ResponseWriter, r *http.Request) {
	if h.complianceFrameworkSvc == nil {
		h.jsonError(w, "Compliance frameworks not configured", http.StatusServiceUnavailable)
		return
	}

	frameworkID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "Invalid framework ID", http.StatusBadRequest)
		return
	}

	controls, err := h.complianceFrameworkSvc.ListControls(r.Context(), frameworkID)
	if err != nil {
		h.jsonError(w, "Failed to list controls: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if controls == nil {
		controls = []*models.ComplianceControl{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(controls) //nolint:errcheck
}

// ComplianceFrameworkAssessments returns all assessments for a framework.
func (h *Handler) ComplianceFrameworkAssessments(w http.ResponseWriter, r *http.Request) {
	if h.complianceFrameworkSvc == nil {
		h.jsonError(w, "Compliance frameworks not configured", http.StatusServiceUnavailable)
		return
	}

	frameworkID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "Invalid framework ID", http.StatusBadRequest)
		return
	}

	assessments, err := h.complianceFrameworkSvc.ListAssessments(r.Context(), frameworkID)
	if err != nil {
		h.jsonError(w, "Failed to list assessments: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if assessments == nil {
		assessments = []*models.ComplianceAssessment{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(assessments) //nolint:errcheck
}

// ComplianceControlUpdateStatus updates a control's implementation status.
func (h *Handler) ComplianceControlUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if h.complianceFrameworkSvc == nil {
		h.jsonError(w, "Compliance frameworks not configured", http.StatusServiceUnavailable)
		return
	}

	controlID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "Invalid control ID", http.StatusBadRequest)
		return
	}

	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.jsonError(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if err := h.complianceFrameworkSvc.UpdateControlStatus(r.Context(), controlID, body.Status); err != nil {
		h.jsonError(w, "Failed to update control status: "+err.Error(), apperrors.HTTPStatusCode(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"}) //nolint:errcheck
}

// ComplianceEvidenceCreate creates a new evidence entry for an assessment.
func (h *Handler) ComplianceEvidenceCreate(w http.ResponseWriter, r *http.Request) {
	if h.complianceFrameworkSvc == nil {
		h.jsonError(w, "Compliance frameworks not configured", http.StatusServiceUnavailable)
		return
	}

	assessmentID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "Invalid assessment ID", http.StatusBadRequest)
		return
	}

	var body struct {
		ControlID    string          `json:"control_id"`
		EvidenceType string          `json:"evidence_type"`
		Title        string          `json:"title"`
		Description  string          `json:"description"`
		Data         json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.jsonError(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	controlUUID, err := uuid.Parse(body.ControlID)
	if err != nil {
		h.jsonError(w, "Invalid control_id", http.StatusBadRequest)
		return
	}

	userID := h.getUserID(r)

	evidence := &models.ComplianceEvidence{
		ID:           uuid.New(),
		AssessmentID: assessmentID,
		ControlID:    controlUUID,
		EvidenceType: body.EvidenceType,
		Title:        body.Title,
		Description:  body.Description,
		Data:         body.Data,
		Status:       "collected",
		CollectedAt:  time.Now(),
		CreatedBy:    userID,
	}

	if err := h.complianceFrameworkSvc.CreateEvidence(r.Context(), evidence); err != nil {
		h.jsonError(w, "Failed to create evidence: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(evidence) //nolint:errcheck
}

// ComplianceEvidenceList returns all evidence for an assessment.
func (h *Handler) ComplianceEvidenceList(w http.ResponseWriter, r *http.Request) {
	if h.complianceFrameworkSvc == nil {
		h.jsonError(w, "Compliance frameworks not configured", http.StatusServiceUnavailable)
		return
	}

	assessmentID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "Invalid assessment ID", http.StatusBadRequest)
		return
	}

	evidence, err := h.complianceFrameworkSvc.ListEvidence(r.Context(), assessmentID)
	if err != nil {
		h.jsonError(w, "Failed to list evidence: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if evidence == nil {
		evidence = []*models.ComplianceEvidence{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(evidence) //nolint:errcheck
}

// ============================================================================
// Enterprise Page Handlers (render HTML pages for enterprise features)
// ============================================================================

// OPAPoliciesPageTempl renders the OPA policies management page.
func (h *Handler) OPAPoliciesPageTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "OPA Policies", "opa-policies")
	data := enterprise.OPAPoliciesData{PageData: pageData}
	enterprise.OPAPolicies(data).Render(r.Context(), w) //nolint:errcheck
}

// RuntimeSecurityPageTempl renders the runtime security page.
func (h *Handler) RuntimeSecurityPageTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Runtime Security", "runtime-security")
	data := enterprise.RuntimeSecurityData{PageData: pageData}
	enterprise.RuntimeSecurity(data).Render(r.Context(), w) //nolint:errcheck
}

// ImageSigningPageTempl renders the image signing page.
func (h *Handler) ImageSigningPageTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Image Signing", "image-signing")
	data := enterprise.ImageSigningData{PageData: pageData}
	enterprise.ImageSigning(data).Render(r.Context(), w) //nolint:errcheck
}

// CustomDashboardsPageTempl renders the custom dashboards page.
func (h *Handler) CustomDashboardsPageTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Custom Dashboards", "custom-dashboards")
	data := enterprise.CustomDashboardsData{PageData: pageData}
	enterprise.CustomDashboards(data).Render(r.Context(), w) //nolint:errcheck
}

// GitSyncPageTempl renders the Git sync page.
func (h *Handler) GitSyncPageTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Git Sync", "git-sync")
	data := enterprise.GitSyncData{PageData: pageData}
	enterprise.GitSync(data).Render(r.Context(), w) //nolint:errcheck
}

// EphemeralEnvsPageTempl renders the ephemeral environments page.
func (h *Handler) EphemeralEnvsPageTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Ephemeral Environments", "ephemeral-envs")
	data := enterprise.EphemeralEnvsData{PageData: pageData}
	enterprise.EphemeralEnvs(data).Render(r.Context(), w) //nolint:errcheck
}

// ManifestBuilderPageTempl renders the manifest builder page.
func (h *Handler) ManifestBuilderPageTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Manifest Builder", "manifest-builder")
	data := enterprise.ManifestBuilderData{PageData: pageData}
	enterprise.ManifestBuilder(data).Render(r.Context(), w) //nolint:errcheck
}

// ComplianceFrameworksPageTempl renders the compliance frameworks page.
func (h *Handler) ComplianceFrameworksPageTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Compliance Frameworks", "compliance-frameworks")
	data := enterprise.ComplianceFrameworksData{PageData: pageData}
	enterprise.ComplianceFrameworks(data).Render(r.Context(), w) //nolint:errcheck
}
