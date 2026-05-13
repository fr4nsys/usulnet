// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"encoding/json"
	"html"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/services/deploy"
)

// DeployService defines the interface for agent deployment operations.
type DeployService interface {
	Deploy(ctx context.Context, req deploy.DeployRequest) (string, error)
	GetDeployment(id string) (*deploy.DeployResult, bool)
	ListDeployments() []*deploy.DeployResult
}

// AgentDeployTempl handles POST /nodes/{id}/deploy - starts agent deployment.
func (h *Handler) AgentDeployTempl(w http.ResponseWriter, r *http.Request) {
	if h.deployService == nil {
		http.Error(w, "Deploy service not available", http.StatusServiceUnavailable)
		return
	}

	ctx := r.Context()
	hostIDStr := chi.URLParam(r, "id")
	hostID, err := uuid.Parse(hostIDStr)
	if err != nil {
		http.Error(w, "Invalid host ID", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// Get host info
	host, err := h.services.Hosts().Get(ctx, hostIDStr)
	if err != nil || host == nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Host Not Found", "The host could not be found.")
		return
	}

	sshHost := r.FormValue("ssh_host")
	sshUser := r.FormValue("ssh_user")
	sshPassword := r.FormValue("ssh_password")
	sshAuthType := r.FormValue("ssh_auth_type")
	sshPrivateKey := r.FormValue("ssh_private_key")
	agentToken := r.FormValue("agent_token")
	gatewayURL := r.FormValue("gateway_url")
	agentImage := r.FormValue("agent_image")

	if sshHost == "" {
		sshHost = host.Endpoint
	}

	// Auto-generate token if not provided (user may have revisited page)
	if agentToken == "" {
		token, err := h.services.Hosts().GenerateAgentToken(ctx, hostIDStr)
		if err != nil {
			http.Error(w, "Failed to generate agent token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		agentToken = token
	}
	if sshAuthType == "" {
		sshAuthType = "password"
	}
	if agentImage == "" {
		agentImage = "usulnet-agent:latest"
	}

	req := deploy.DeployRequest{
		HostID:        hostID,
		HostName:      host.Name,
		SSHHost:       sshHost,
		SSHPort:       22,
		SSHUser:       sshUser,
		SSHAuthType:   sshAuthType,
		SSHPassword:   sshPassword,
		SSHPrivateKey: sshPrivateKey,
		AgentToken:    agentToken,
		GatewayURL:    gatewayURL,
		AgentImage:    agentImage,
	}

	deployID, err := h.deployService.Deploy(ctx, req)
	if err != nil {
		// For HTMX, return error fragment
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`<div class="text-red-500">Deploy failed: ` + html.EscapeString(err.Error()) + `</div>`))
			return
		}
		http.Error(w, "Deploy failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	// For HTMX, redirect to status page or return deploy ID
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("HX-Redirect", "/nodes/"+hostIDStr+"/deploy/"+deployID)
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Redirect(w, r, "/nodes/"+hostIDStr+"/deploy/"+deployID, http.StatusSeeOther)
}

// AgentDeployStatusTempl handles GET /nodes/{id}/deploy/{deployID} - shows deployment status.
func (h *Handler) AgentDeployStatusTempl(w http.ResponseWriter, r *http.Request) {
	if h.deployService == nil {
		http.Error(w, "Deploy service not available", http.StatusServiceUnavailable)
		return
	}

	deployID := chi.URLParam(r, "deployID")

	result, ok := h.deployService.GetDeployment(deployID)
	if !ok {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Deployment Not Found", "The deployment could not be found.")
		return
	}

	// Return JSON for API/HTMX polling requests
	if r.Header.Get("Accept") == "application/json" || r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
		return
	}

	// For HTMX partial updates, return just the status fragment
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html")
		writeDeployStatusHTML(w, result)
		return
	}

	// Full page render
	w.Header().Set("Content-Type", "text/html")
	writeDeployPageHTML(w, result)
}

// AgentDeployStatusJSON handles GET /api/deploy/{deployID} - JSON deployment status.
func (h *Handler) AgentDeployStatusJSON(w http.ResponseWriter, r *http.Request) {
	if h.deployService == nil {
		http.Error(w, "Deploy service not available", http.StatusServiceUnavailable)
		return
	}

	deployID := chi.URLParam(r, "deployID")
	result, ok := h.deployService.GetDeployment(deployID)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "deployment not found"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// writeDeployStatusHTML writes the deployment status as an HTML fragment (for HTMX polling).
func writeDeployStatusHTML(w http.ResponseWriter, result *deploy.DeployResult) {
	statusColor := "text-yellow-500"
	switch result.Status {
	case deploy.StatusComplete:
		statusColor = "text-green-500"
	case deploy.StatusFailed:
		statusColor = "text-red-500"
	}

	w.Write([]byte(`<div id="deploy-status" class="space-y-4">`))
	w.Write([]byte(`<div class="flex items-center gap-2">`))
	w.Write([]byte(`<span class="font-medium ` + statusColor + `">` + html.EscapeString(string(result.Status)) + `</span>`))
	if result.Step != "" {
		w.Write([]byte(` - <span class="text-gray-400">` + html.EscapeString(result.Step) + `</span>`))
	}
	w.Write([]byte(`</div>`))

	// Logs
	w.Write([]byte(`<div class="bg-dark-800 rounded p-4 max-h-96 overflow-y-auto font-mono text-sm">`))
	for _, log := range result.Logs {
		w.Write([]byte(`<div class="text-gray-300">` + html.EscapeString(log) + `</div>`))
	}
	w.Write([]byte(`</div>`))

	if result.Error != "" {
		w.Write([]byte(`<div class="text-red-500 font-medium">Error: ` + html.EscapeString(result.Error) + `</div>`))
	}

	// Auto-refresh while in progress
	if result.Status != deploy.StatusComplete && result.Status != deploy.StatusFailed {
		w.Write([]byte(`<div hx-get="" hx-trigger="every 2s" hx-swap="outerHTML" hx-target="#deploy-status"></div>`))
	}

	w.Write([]byte(`</div>`))
}

// writeDeployPageHTML writes a full deployment status page.
func writeDeployPageHTML(w http.ResponseWriter, result *deploy.DeployResult) {
	w.Write([]byte(`<!DOCTYPE html><html><head><title>Agent Deployment</title>
<script src="/static/vendor/js/htmx-2.0.4.min.js"></script>
<link href="/static/css/style.css" rel="stylesheet">
</head><body class="bg-dark-900 text-white p-8">
<div class="max-w-3xl mx-auto">
<h1 class="text-2xl font-bold mb-4">Agent Deployment: ` + html.EscapeString(result.HostName) + `</h1>
<div id="deploy-container">`))

	writeDeployStatusHTML(w, result)

	w.Write([]byte(`</div>
<div class="mt-4">
<a href="/nodes" class="text-primary-400 hover:underline">Back to Nodes</a>
</div>
</div></body></html>`))
}
