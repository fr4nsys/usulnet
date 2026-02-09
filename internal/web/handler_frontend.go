// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/docker"
	totppkg "github.com/fr4nsys/usulnet/internal/pkg/totp"
	"github.com/fr4nsys/usulnet/internal/web/templates/components"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/containers"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/images"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/networks"
	securitytmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/security"
	updatestmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/updates"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/volumes"
)

// ============================================================================
// Templ Rendering Helpers
// ============================================================================

// renderTempl renders a templ component to the response writer.
func (h *Handler) renderTempl(w http.ResponseWriter, r *http.Request, component templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := component.Render(r.Context(), w)
	if err != nil {
		http.Error(w, "Template rendering error: "+err.Error(), http.StatusInternalServerError)
	}
}

// renderTemplWithStatus renders a templ component with a specific status code.
func (h *Handler) renderTemplWithStatus(w http.ResponseWriter, r *http.Request, status int, component templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	err := component.Render(r.Context(), w)
	if err != nil {
		http.Error(w, "Template rendering error: "+err.Error(), http.StatusInternalServerError)
	}
}

// preparePageData creates base PageData with context injections.
func (h *Handler) preparePageData(r *http.Request, title, active string) *PageData {
	data := &PageData{
		Title:  title,
		Active: active,
	}
	
	// Inject common data from context
	data.User = GetUserFromContext(r.Context())
	data.Theme = GetThemeFromContext(r.Context())
	data.CSRFToken = GetCSRFTokenFromContext(r.Context())
	data.Stats = GetStatsFromContext(r.Context())
	data.Flash = GetFlashFromContext(r.Context())
	data.Version = h.version
	
	return data
}

// ============================================================================
// Auth Handlers (Templ)
// ============================================================================

// LoginPageTempl renders the login page using Templ.
func (h *Handler) LoginPageTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.preparePageData(r, "Login", "")
	
	// Get error from query params (e.g., after failed login)
	errorMsg := r.URL.Query().Get("error")
	username := r.URL.Query().Get("username")
	returnURL := r.URL.Query().Get("return")
	
	// TODO: Get from settings
	ldapEnabled := false
	oauthEnabled := false
	oauthProvider := ""
	
	loginData := ToTemplLoginData(pageData, errorMsg, username, returnURL, ldapEnabled, oauthEnabled, oauthProvider)
	h.renderTempl(w, r, pages.Login(loginData))
}

// ============================================================================
// TOTP 2FA Handlers
// ============================================================================

// TOTPVerifyPageTempl renders the TOTP code input page during login.
func (h *Handler) TOTPVerifyPageTempl(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	returnURL := r.URL.Query().Get("return")
	errorMsg := r.URL.Query().Get("error")

	if token == "" {
		h.redirect(w, r, "/login")
		return
	}

	// Validate token is still valid (don't consume it, just check)
	if len(h.totpSigningKey) == 0 {
		h.redirect(w, r, "/login?error=2FA+not+configured")
		return
	}
	_, err := totppkg.ValidatePendingToken(token, h.totpSigningKey)
	if err != nil {
		h.redirect(w, r, "/login?error=Session+expired,+please+login+again")
		return
	}

	data := pages.TOTPVerifyData{
		Error:     errorMsg,
		CSRFToken: GetCSRFTokenFromContext(r.Context()),
		ReturnURL: returnURL,
		Token:     token,
		Version:   h.version,
	}
	h.renderTempl(w, r, pages.TOTPVerify(data))
}

// TOTPVerifySubmit handles TOTP code verification during login.
func (h *Handler) TOTPVerifySubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.redirect(w, r, "/login?error=Invalid+form+data")
		return
	}

	token := r.FormValue("totp_token")
	code := r.FormValue("totp_code")
	returnURL := r.FormValue("return_url")

	if token == "" || code == "" {
		h.redirect(w, r, "/login?error=Invalid+request")
		return
	}

	// Validate pending token
	userID, err := totppkg.ValidatePendingToken(token, h.totpSigningKey)
	if err != nil {
		h.redirect(w, r, "/login?error=Session+expired,+please+login+again")
		return
	}

	// Validate TOTP code
	valid, err := h.services.Users().ValidateTOTPCode(r.Context(), userID, code)
	if err != nil || !valid {
		// Redirect back to TOTP page with error
		redirectURL := "/login/totp?token=" + token + "&error=Invalid+code,+please+try+again"
		if returnURL != "" {
			redirectURL += "&return=" + returnURL
		}
		h.redirect(w, r, redirectURL)
		return
	}

	// TOTP valid — create full session (backend + cookie)
	userCtx, err := h.services.Auth().CreateSessionForUser(r.Context(), userID, r.UserAgent(), getClientIP(r))
	if err != nil {
		h.redirect(w, r, "/login?error=Session+creation+failed")
		return
	}

	session := &Session{
		UserID:   userCtx.ID,
		Username: userCtx.Username,
		Role:     userCtx.Role,
	}

	if err := h.sessionStore.Save(r, w, session); err != nil {
		h.redirect(w, r, "/login?error=Session+creation+failed")
		return
	}

	if returnURL != "" && returnURL != "/login" && strings.HasPrefix(returnURL, "/") && !strings.HasPrefix(returnURL, "//") {
		h.redirect(w, r, returnURL)
		return
	}
	h.redirect(w, r, "/")
}

// TOTPSetupPageTempl renders the 2FA setup/manage page.
func (h *Handler) TOTPSetupPageTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := GetUserFromContext(ctx)
	if user == nil {
		h.redirect(w, r, "/login")
		return
	}

	successMsg := r.URL.Query().Get("success")
	errorMsg := r.URL.Query().Get("error")

	hasTOTP, _ := h.services.Users().HasTOTP(ctx, user.ID)

	data := pages.TOTPSetupData{
		PageData:  h.prepareTemplPageData(r, "Two-Factor Authentication", "settings"),
		Error:     errorMsg,
		Success:   successMsg,
		CSRFToken: GetCSRFTokenFromContext(ctx),
		Username:  user.Username,
		Enabled:   hasTOTP,
	}

	if !hasTOTP {
		// Generate new secret for setup
		secret, qrURI, err := h.services.Users().SetupTOTP(ctx, user.ID)
		if err != nil {
			data.Error = "Failed to generate 2FA secret: " + err.Error()
		} else {
			data.Secret = secret
			data.QRCodeURI = qrURI
		}
	}

	h.renderTempl(w, r, pages.TOTPSetup(data))
}

// TOTPVerifySetupSubmit handles verifying the first TOTP code to enable 2FA.
func (h *Handler) TOTPVerifySetupSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.redirect(w, r, "/settings/totp?error=Invalid+form+data")
		return
	}

	ctx := r.Context()
	user := GetUserFromContext(ctx)
	if user == nil {
		h.redirect(w, r, "/login")
		return
	}

	code := r.FormValue("totp_code")
	if code == "" {
		h.redirect(w, r, "/settings/totp?error=Please+enter+a+code")
		return
	}

	if err := h.services.Users().VerifyAndEnableTOTP(ctx, user.ID, code); err != nil {
		h.redirect(w, r, "/settings/totp?error=Invalid+code.+Make+sure+your+authenticator+app+is+synced")
		return
	}

	h.redirect(w, r, "/settings/totp?success=Two-factor+authentication+enabled+successfully")
}

// TOTPDisableSubmit handles disabling 2FA.
func (h *Handler) TOTPDisableSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.redirect(w, r, "/settings/totp?error=Invalid+form+data")
		return
	}

	ctx := r.Context()
	user := GetUserFromContext(ctx)
	if user == nil {
		h.redirect(w, r, "/login")
		return
	}

	code := r.FormValue("totp_code")
	if code == "" {
		h.redirect(w, r, "/settings/totp?error=Please+enter+your+current+TOTP+code")
		return
	}

	if err := h.services.Users().DisableTOTP(ctx, user.ID, code); err != nil {
		h.redirect(w, r, "/settings/totp?error=Invalid+code.+Cannot+disable+2FA")
		return
	}

	h.redirect(w, r, "/settings/totp?success=Two-factor+authentication+disabled")
}

// ============================================================================
// Dashboard Handlers (Templ)
// ============================================================================

// DashboardTempl renders the main dashboard using Templ.
func (h *Handler) DashboardTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.preparePageData(r, "Dashboard", "dashboard")

	// Get containers
	containersList, _ := h.services.Containers().List(ctx, nil)
	
	// Get events
	eventsList, _ := h.services.Events().List(ctx, 10)
	
	// Get system info (if available)
	var sysInfo *SystemInfoView
	if statsService := h.services.Stats(); statsService != nil {
		// TODO: Implement GetSystemInfo in StatsService
		sysInfo = nil
	}
	
	// Calculate stopped containers
	if pageData.Stats != nil {
		pageData.Stats.ContainersStopped = pageData.Stats.ContainersTotal - pageData.Stats.ContainersRunning
	}
	
	dashboardData := ToTemplDashboardData(pageData, containersList, eventsList, sysInfo)
	h.renderTempl(w, r, pages.Dashboard(dashboardData))
}

// ============================================================================
// Container Handlers (Templ)
// ============================================================================

// ContainersTempl lists all containers using Templ.
func (h *Handler) ContainersTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.preparePageData(r, "Containers", "containers")
	
	// Parse filters
	filters := map[string]string{
		"state":  GetQueryParam(r, "state", ""),
		"stack":  GetQueryParam(r, "stack", ""),
		"search": GetQueryParam(r, "search", ""),
	}
	pageData.Filters = filters
	pageData.SortBy = GetQueryParam(r, "sort", "name")
	pageData.SortOrder = GetQueryParam(r, "dir", "asc")
	
	// Get containers
	containersList, err := h.services.Containers().List(ctx, filters)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", err.Error())
		return
	}
	
	// Pagination
	page := GetQueryParamInt(r, "page", 1)
	perPage := GetQueryParamInt(r, "per_page", 20)
	total := int64(len(containersList))
	pageData.Pagination = NewPagination(total, page, perPage)
	
	// Paginate results
	start := (page - 1) * perPage
	end := start + perPage
	if start > len(containersList) {
		start = len(containersList)
	}
	if end > len(containersList) {
		end = len(containersList)
	}
	paginatedList := containersList[start:end]
	
	listData := ToTemplContainersListData(pageData, paginatedList)
	h.renderTempl(w, r, containers.ContainersList(listData))
}

// ContainerDetailTempl shows container details using Templ.
func (h *Handler) ContainerDetailTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	container, err := h.services.Containers().Get(ctx, id)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Container not found")
		return
	}

	pageData := h.preparePageData(r, container.Name, "containers")
	tab := GetQueryParam(r, "tab", "overview")
	
	detailData := ToTemplContainerDetailData(pageData, container, tab)
	h.renderTempl(w, r, containers.ContainerDetail(detailData))
}

// ContainerLogsTempl shows container logs using Templ.
func (h *Handler) ContainerLogsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	container, err := h.services.Containers().Get(ctx, id)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Container not found")
		return
	}

	pageData := h.preparePageData(r, "Logs: "+container.Name, "logs")
	
	tail := GetQueryParamInt(r, "tail", 500)
	since := GetQueryParam(r, "since", "")
	follow := GetQueryParam(r, "follow", "true") == "true"
	
	logsData := ToTemplContainerLogsData(pageData, container, tail, since, follow)
	h.renderTempl(w, r, containers.ContainerLogs(logsData))
}

// ContainerExecTempl provides exec interface using Templ.
func (h *Handler) ContainerExecTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	container, err := h.services.Containers().Get(ctx, id)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Container not found")
		return
	}

	pageData := h.preparePageData(r, "Terminal: "+container.Name, "containers")
	
	shell := GetQueryParam(r, "shell", "/bin/sh")
	
	terminalData := ToTemplContainerTerminalData(pageData, container, shell)
	h.renderTempl(w, r, containers.ContainerTerminal(terminalData))
}

// ContainerStatsTempl shows container resource stats using Templ.
func (h *Handler) ContainerStatsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	container, err := h.services.Containers().Get(ctx, id)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Container not found")
		return
	}

	pageData := h.preparePageData(r, "Stats: "+container.Name, "containers")
	statsData := ToTemplContainerStatsData(pageData, container)
	h.renderTempl(w, r, containers.ContainerStats(statsData))
}

// ContainerInspectTempl shows container inspect JSON using Templ.
func (h *Handler) ContainerInspectTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	container, err := h.services.Containers().Get(ctx, id)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Container not found")
		return
	}

	// Get raw inspect JSON from Docker
	inspectJSON := "{}"
	dockerClient, err := h.services.Containers().GetDockerClient(ctx)
	if err == nil {
		details, err := dockerClient.ContainerGet(ctx, id)
		if err == nil {
			jsonBytes, err := json.MarshalIndent(details, "", "  ")
			if err == nil {
				inspectJSON = string(jsonBytes)
			}
		}
	}

	pageData := h.preparePageData(r, "Inspect: "+container.Name, "containers")
	inspectData := ToTemplContainerInspectData(pageData, container, inspectJSON)
	h.renderTempl(w, r, containers.ContainerInspect(inspectData))
}

// ContainerFilesTempl shows container file browser using Templ.
func (h *Handler) ContainerFilesTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	container, err := h.services.Containers().Get(ctx, id)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Container not found")
		return
	}

	// Get path from wildcard or default to /
	path := chi.URLParam(r, "*")
	if path == "" {
		path = "/"
	}

	pageData := h.preparePageData(r, "Files: "+container.Name, "containers")
	filesData := ToTemplContainerFilesData(pageData, container, path)
	h.renderTempl(w, r, containers.ContainerFiles(filesData))
}

// ContainerSettingsTempl shows container settings page using Templ.
func (h *Handler) ContainerSettingsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	container, err := h.services.Containers().Get(ctx, id)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Container not found")
		return
	}

	// Get available networks for dropdown
	var networkNames []string
	if netList, err := h.services.Networks().List(ctx); err == nil {
		for _, net := range netList {
			networkNames = append(networkNames, net.Name)
		}
	}

	// Get detailed info from Docker inspect
	var details *ContainerSettingsDetails
	dockerClient, err := h.services.Containers().GetDockerClient(ctx)
	if err == nil {
		inspectData, err := dockerClient.ContainerGet(ctx, id)
		if err == nil {
			details = &ContainerSettingsDetails{
				NetworkMode: inspectData.NetworkMode,
			}
			if inspectData.HostConfig != nil {
				details.NetworkMode = inspectData.HostConfig.NetworkMode
				details.Privileged = inspectData.HostConfig.Privileged
				details.CPUShares = inspectData.HostConfig.Resources.CPUShares
				details.NanoCPUs = inspectData.HostConfig.Resources.NanoCPUs
				details.MemoryLimit = inspectData.HostConfig.Resources.Memory
				details.CapAdd = inspectData.HostConfig.CapAdd
				details.CapDrop = inspectData.HostConfig.CapDrop
				details.RestartPolicy = inspectData.HostConfig.RestartPolicy.Name
				// Devices
				for _, d := range inspectData.HostConfig.Devices {
					details.Devices = append(details.Devices, containers.DeviceSettingInfo{
						HostPath:      d.PathOnHost,
						ContainerPath: d.PathInContainer,
					})
				}
				// Port bindings from Docker inspect
				for portKey, bindings := range inspectData.HostConfig.PortBindings {
					// portKey format: "80/tcp" or "8080/udp"
					containerPort := portKey
					protocol := "tcp"
					if idx := strings.Index(portKey, "/"); idx > 0 {
						containerPort = portKey[:idx]
						protocol = portKey[idx+1:]
					}
					for _, b := range bindings {
						details.Ports = append(details.Ports, containers.PortSettingInfo{
							HostPort:      b.HostPort,
							ContainerPort: containerPort,
							Protocol:      protocol,
						})
					}
				}
			}
			if inspectData.Config != nil {
				details.Hostname = inspectData.Config.Hostname
			}
		}
	}

	pageData := h.preparePageData(r, "Settings: "+container.Name, "containers")
	settingsData := ToTemplContainerSettingsData(pageData, container, networkNames, details)
	h.renderTempl(w, r, containers.ContainerSettings(settingsData))
}

// ContainerSettingsUpdate handles the POST to save container settings.
func (h *Handler) ContainerSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	// Get the current container to check state
	container, err := h.services.Containers().Get(ctx, id)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Container not found")
		return
	}
	wasRunning := container.State == "running"

	// Parse form fields
	image := r.FormValue("image")
	tag := r.FormValue("tag")
	if tag == "" {
		tag = "latest"
	}
	fullImage := image + ":" + tag

	name := r.FormValue("name")
	hostname := r.FormValue("hostname")
	command := r.FormValue("command")
	networkMode := r.FormValue("network_mode")
	restartPolicy := r.FormValue("restart_policy")
	privileged := r.FormValue("privileged") == "true"

	// Resource limits
	memoryMB, _ := strconv.ParseInt(r.FormValue("memory_limit"), 10, 64)
	memoryBytes := memoryMB * 1024 * 1024
	cpuShares, _ := strconv.ParseInt(r.FormValue("cpu_shares"), 10, 64)
	nanoCPUsFloat, _ := strconv.ParseFloat(r.FormValue("nano_cpus"), 64)
	nanoCPUs := int64(nanoCPUsFloat * 1e9)

	// Parse JSON arrays from hidden fields
	var ports []struct {
		Host      string `json:"host"`
		Container string `json:"container"`
		Protocol  string `json:"protocol"`
	}
	if portsJSON := r.FormValue("ports_json"); portsJSON != "" {
		json.Unmarshal([]byte(portsJSON), &ports)
	}

	var volumes []struct {
		Host      string `json:"host"`
		Container string `json:"container"`
		RW        bool   `json:"rw"`
	}
	if volJSON := r.FormValue("volumes_json"); volJSON != "" {
		json.Unmarshal([]byte(volJSON), &volumes)
	}

	var envVars []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if envJSON := r.FormValue("env_json"); envJSON != "" {
		json.Unmarshal([]byte(envJSON), &envVars)
	}

	var devices []struct {
		Host      string `json:"host"`
		Container string `json:"container"`
	}
	if devJSON := r.FormValue("devices_json"); devJSON != "" {
		json.Unmarshal([]byte(devJSON), &devices)
	}

	var caps []struct {
		Value string `json:"value"`
	}
	if capsJSON := r.FormValue("caps_json"); capsJSON != "" {
		json.Unmarshal([]byte(capsJSON), &caps)
	}

	// Build Docker create options
	dockerClient, err := h.services.Containers().GetDockerClient(ctx)
	if err != nil {
		h.setFlash(w, r, "error", "Docker client unavailable: "+err.Error())
		http.Redirect(w, r, "/containers/"+id+"/settings", http.StatusFound)
		return
	}

	// Build environment variables
	var env []string
	for _, e := range envVars {
		if e.Key != "" {
			env = append(env, e.Key+"="+e.Value)
		}
	}

	// Build binds (volumes)
	var binds []string
	for _, v := range volumes {
		if v.Host != "" && v.Container != "" {
			bind := v.Host + ":" + v.Container
			if !v.RW {
				bind += ":ro"
			}
			binds = append(binds, bind)
		}
	}

	// Build port bindings
	portBindings := make(map[string][]docker.PortBinding)
	for _, p := range ports {
		if p.Container != "" {
			proto := p.Protocol
			if proto == "" {
				proto = "tcp"
			}
			key := p.Container + "/" + proto
			portBindings[key] = append(portBindings[key], docker.PortBinding{
				HostIP:   "0.0.0.0",
				HostPort: p.Host,
			})
		}
	}

	// Build capabilities
	var capAdd []string
	for _, c := range caps {
		if c.Value != "" {
			capAdd = append(capAdd, c.Value)
		}
	}

	// Build command
	var cmd []string
	if command != "" {
		cmd = strings.Fields(command)
	}

	// Build labels (preserve existing, add webui/icon)
	labels := make(map[string]string)
	if container.Labels != nil {
		for k, v := range container.Labels {
			labels[k] = v
		}
	}
	// Set usulnet-specific labels
	setOrDeleteLabel(labels, "usulnet.webui.protocol", r.FormValue("webui_protocol"))
	setOrDeleteLabel(labels, "usulnet.webui.host", r.FormValue("webui_host"))
	setOrDeleteLabel(labels, "usulnet.webui.port", r.FormValue("webui_port"))
	setOrDeleteLabel(labels, "usulnet.webui.path", r.FormValue("webui_path"))

	// Stop the old container
	if wasRunning {
		if err := dockerClient.ContainerStop(ctx, id, nil); err != nil {
			h.setFlash(w, r, "error", "Failed to stop container: "+err.Error())
			http.Redirect(w, r, "/containers/"+id+"/settings", http.StatusFound)
			return
		}
	}

	// Remove the old container
	if err := dockerClient.ContainerRemove(ctx, id, true, false); err != nil {
		h.setFlash(w, r, "error", "Failed to remove old container: "+err.Error())
		http.Redirect(w, r, "/containers/"+id+"/settings", http.StatusFound)
		return
	}

	// Build device mappings
	var deviceMappings []docker.DeviceMapping
	for _, d := range devices {
		if d.Host != "" && d.Container != "" {
			deviceMappings = append(deviceMappings, docker.DeviceMapping{
				PathOnHost:        d.Host,
				PathInContainer:   d.Container,
				CgroupPermissions: "rwm",
			})
		}
	}

	// Build Docker restart policy
	dockerRestartPolicy := docker.RestartPolicy{Name: restartPolicy}

	// Create new container via Docker client
	createOpts := docker.ContainerCreateOptions{
		Name:          name,
		Hostname:      hostname,
		Image:         fullImage,
		Cmd:           cmd,
		Env:           env,
		Labels:        labels,
		Binds:         binds,
		PortBindings:  portBindings,
		NetworkMode:   networkMode,
		RestartPolicy: dockerRestartPolicy,
		Privileged:    privileged,
		CapAdd:        capAdd,
		Devices:       deviceMappings,
		Memory:        memoryBytes,
		CPUShares:     cpuShares,
		NanoCPUs:      nanoCPUs,
	}

	newID, err := dockerClient.ContainerCreate(ctx, createOpts)
	if err != nil {
		h.setFlash(w, r, "error", "Failed to create container: "+err.Error())
		http.Redirect(w, r, "/containers", http.StatusFound)
		return
	}

	// Start if was running
	if wasRunning {
		if err := dockerClient.ContainerStart(ctx, newID); err != nil {
			h.setFlash(w, r, "warning", "Container created but failed to start: "+err.Error())
			http.Redirect(w, r, "/containers/"+newID, http.StatusFound)
			return
		}
	}

	h.setFlash(w, r, "success", "Container settings updated successfully")
	http.Redirect(w, r, "/containers/"+newID, http.StatusFound)
}

// ContainerSettingsSummary returns an HTMX fragment with read-only container config summary.
func (h *Handler) ContainerSettingsSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	container, err := h.services.Containers().Get(ctx, id)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<div class="p-4 text-gray-500 text-sm">Container not found or not running</div>`))
		return
	}

	// Get inspect details
	var details *ContainerSettingsDetails
	dockerClient, err := h.services.Containers().GetDockerClient(ctx)
	if err == nil {
		inspectData, err := dockerClient.ContainerGet(ctx, id)
		if err == nil {
			details = &ContainerSettingsDetails{
				NetworkMode: inspectData.NetworkMode,
			}
			if inspectData.HostConfig != nil {
				details.NetworkMode = inspectData.HostConfig.NetworkMode
				details.Privileged = inspectData.HostConfig.Privileged
				details.CPUShares = inspectData.HostConfig.Resources.CPUShares
				details.NanoCPUs = inspectData.HostConfig.Resources.NanoCPUs
				details.MemoryLimit = inspectData.HostConfig.Resources.Memory
				details.RestartPolicy = inspectData.HostConfig.RestartPolicy.Name
				details.CapAdd = inspectData.HostConfig.CapAdd
				details.CapDrop = inspectData.HostConfig.CapDrop
				// Port bindings from Docker inspect
				for portKey, bindings := range inspectData.HostConfig.PortBindings {
					containerPort := portKey
					protocol := "tcp"
					if idx := strings.Index(portKey, "/"); idx > 0 {
						containerPort = portKey[:idx]
						protocol = portKey[idx+1:]
					}
					for _, b := range bindings {
						details.Ports = append(details.Ports, containers.PortSettingInfo{
							HostPort:      b.HostPort,
							ContainerPort: containerPort,
							Protocol:      protocol,
						})
					}
				}
			}
			if inspectData.Config != nil {
				details.Hostname = inspectData.Config.Hostname
			}
		}
	}

	pageData := h.preparePageData(r, "", "")
	settingsData := ToTemplContainerSettingsData(pageData, container, nil, details)
	h.renderTempl(w, r, containers.ContainerSettingsSummary(settingsData))
}

func setOrDeleteLabel(labels map[string]string, key, value string) {
	if value != "" {
		labels[key] = value
	} else {
		delete(labels, key)
	}
}

// ============================================================================
// Error Handlers (Templ)
// ============================================================================

// RenderErrorTempl renders an error page using Templ.
func (h *Handler) RenderErrorTempl(w http.ResponseWriter, r *http.Request, code int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	
	errorData := pages.ErrorData{
		Code:    code,
		Title:   title,
		Message: message,
		Version: h.version,
	}
	
	err := pages.Error(errorData).Render(r.Context(), w)
	if err != nil {
		// Fallback to simple error if template fails
		http.Error(w, message, code)
	}
}

// RenderServiceNotConfigured renders a user-friendly "service not configured"
// page using the reusable templ component. Use this for full-page HTML handlers
// where a service is nil; for JSON/API endpoints use renderJSONError instead.
func (h *Handler) RenderServiceNotConfigured(w http.ResponseWriter, r *http.Request, serviceName, configHint string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = components.ServiceNotConfigured(serviceName, configHint).Render(r.Context(), w)
}

// ============================================================================
// Partial Handlers (Templ) - For HTMX requests
// ============================================================================

// ContainersPartialTempl renders just the container table for HTMX requests.
func (h *Handler) ContainersPartialTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	limit := GetQueryParamInt(r, "limit", 5)
	
	containersList, err := h.services.Containers().List(ctx, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	// Limit results
	if limit > 0 && len(containersList) > limit {
		containersList = containersList[:limit]
	}
	
	// Render partial HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	
	for _, c := range containersList {
		// Generate row HTML
		stateClass := "bg-red-500"
		if c.State == "running" {
			stateClass = "bg-green-500"
		} else if c.State == "paused" {
			stateClass = "bg-yellow-500"
		}
		
		html := `<div class="flex items-center gap-4 p-4 hover:bg-dark-700/50 transition-colors">
			<div class="w-2.5 h-2.5 rounded-full flex-shrink-0 ` + stateClass + `"></div>
			<div class="flex-1 min-w-0">
				<div class="flex items-center gap-2">
					<a href="/containers/` + c.ID + `" class="font-medium text-white hover:text-primary-400 truncate">` + c.Name + `</a>
				</div>
				<p class="text-sm text-gray-500 truncate">` + c.Image + `</p>
			</div>
		</div>`
		w.Write([]byte(html))
	}
}

// EventsPartialTempl renders recent events for HTMX requests.
func (h *Handler) EventsPartialTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	limit := GetQueryParamInt(r, "limit", 10)
	
	eventsList, err := h.services.Events().List(ctx, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	
	if len(eventsList) == 0 {
		html := `<div class="p-8 text-center text-gray-500">
			<i class="fas fa-stream text-3xl mb-3 opacity-50"></i>
			<p>No recent events</p>
		</div>`
		w.Write([]byte(html))
		return
	}
	
	for _, e := range eventsList {
		// Determine icon and color
		iconClass := "fa-info"
		colorClass := "bg-gray-500/20 text-gray-400"
		
		switch e.Action {
		case "start":
			iconClass = "fa-play"
			colorClass = "bg-green-500/20 text-green-400"
		case "stop":
			iconClass = "fa-stop"
			colorClass = "bg-red-500/20 text-red-400"
		case "create":
			iconClass = "fa-plus"
			colorClass = "bg-green-500/20 text-green-400"
		case "destroy":
			iconClass = "fa-trash"
			colorClass = "bg-red-500/20 text-red-400"
		case "restart":
			iconClass = "fa-redo"
			colorClass = "bg-yellow-500/20 text-yellow-400"
		case "pull":
			iconClass = "fa-download"
			colorClass = "bg-blue-500/20 text-blue-400"
		}
		
		html := `<div class="flex items-start gap-3 p-3 hover:bg-dark-700/50 transition-colors">
			<div class="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 ` + colorClass + `">
				<i class="fas ` + iconClass + ` text-xs"></i>
			</div>
			<div class="flex-1 min-w-0">
				<p class="text-sm text-white">
					<span class="font-medium">` + e.Action + `</span>
					<span class="text-gray-400"> ` + e.ActorName + `</span>
				</p>
				<p class="text-xs text-gray-500">` + e.TimeHuman + `</p>
			</div>
		</div>`
		w.Write([]byte(html))
	}
}

// NotificationsPartialTempl renders notifications dropdown content.
func (h *Handler) NotificationsPartialTempl(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement notifications service
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	
	html := `<div class="p-4 text-center text-gray-500">
		<i class="fas fa-bell-slash text-2xl mb-2 opacity-50"></i>
		<p class="text-sm">No new notifications</p>
	</div>`
	w.Write([]byte(html))
}

// SearchPartialTempl handles search results for the header search.
func (h *Handler) SearchPartialTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query().Get("q")
	
	if query == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		return
	}
	
	// Search containers
	filters := map[string]string{"search": query}
	containersList, _ := h.services.Containers().List(ctx, filters)
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	
	if len(containersList) == 0 {
		html := `<div class="absolute top-full left-0 right-0 mt-2 bg-dark-800 rounded-lg border border-dark-600 shadow-xl p-4 text-center text-gray-500 text-sm">
			No results found for "` + query + `"
		</div>`
		w.Write([]byte(html))
		return
	}
	
	html := `<div class="absolute top-full left-0 right-0 mt-2 bg-dark-800 rounded-lg border border-dark-600 shadow-xl overflow-hidden max-h-80 overflow-y-auto">`
	
	// Limit to 5 results
	limit := 5
	if len(containersList) < limit {
		limit = len(containersList)
	}
	
	for i := 0; i < limit; i++ {
		c := containersList[i]
		stateColor := "text-red-400"
		if c.State == "running" {
			stateColor = "text-green-400"
		}
		
		html += `<a href="/containers/` + c.ID + `" class="flex items-center gap-3 p-3 hover:bg-dark-700 transition-colors">
			<i class="fas fa-cube ` + stateColor + `"></i>
			<div class="flex-1 min-w-0">
				<p class="text-sm text-white truncate">` + c.Name + `</p>
				<p class="text-xs text-gray-500 truncate">` + c.Image + `</p>
			</div>
		</a>`
	}
	
	if len(containersList) > 5 {
		html += `<a href="/containers?search=` + query + `" class="block p-3 text-center text-sm text-primary-400 hover:bg-dark-700 border-t border-dark-600">
			View all ` + strconv.Itoa(len(containersList)) + ` results
		</a>`
	}
	
	html += `</div>`
	w.Write([]byte(html))
}

// ============================================================================
// Image Handlers (Templ)
// ============================================================================

// ImagesTempl lists all images using Templ.
func (h *Handler) ImagesTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.preparePageData(r, "Images", "images")
	
	imagesList, err := h.services.Images().List(ctx)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", err.Error())
		return
	}
	
	// Calculate total size
	var totalSize int64
	for _, img := range imagesList {
		totalSize += img.Size
	}
	
	// Parse filters
	filters := images.ImageFilters{
		Search:   GetQueryParam(r, "search", ""),
		InUse:    GetQueryParam(r, "in_use", ""),
		Dangling: GetQueryParam(r, "dangling", ""),
		Sort:     GetQueryParam(r, "sort", "name"),
		Dir:      GetQueryParam(r, "dir", "asc"),
	}
	
	// Filter images
	filteredImages := filterImages(imagesList, filters)
	
	// Sort images
	sortImages(filteredImages, filters.Sort, filters.Dir)
	
	// Pagination
	page := GetQueryParamInt(r, "page", 1)
	perPage := GetQueryParamInt(r, "per_page", 20)
	total := int64(len(filteredImages))
	pageData.Pagination = NewPagination(total, page, perPage)
	
	// Paginate results
	start := (page - 1) * perPage
	end := start + perPage
	if start > len(filteredImages) {
		start = len(filteredImages)
	}
	if end > len(filteredImages) {
		end = len(filteredImages)
	}
	paginatedList := filteredImages[start:end]
	
	listData := ToTemplImagesListData(pageData, paginatedList, totalSize, filters)
	h.renderTempl(w, r, images.ImagesList(listData))
}

func filterImages(imagesList []ImageView, filters images.ImageFilters) []ImageView {
	var result []ImageView
	for _, img := range imagesList {
		// Search filter
		if filters.Search != "" {
			found := false
			for _, tag := range img.Tags {
				if containsIgnoreCase(tag, filters.Search) {
					found = true
					break
				}
			}
			if !found && !containsIgnoreCase(img.ShortID, filters.Search) {
				continue
			}
		}
		
		// In use filter
		if filters.InUse == "true" && !img.InUse {
			continue
		}
		if filters.InUse == "false" && img.InUse {
			continue
		}
		
		// Dangling filter
		if filters.Dangling == "true" && len(img.Tags) > 0 {
			continue
		}
		if filters.Dangling == "false" && len(img.Tags) == 0 {
			continue
		}
		
		result = append(result, img)
	}
	return result
}

func sortImages(imgs []ImageView, sortBy, dir string) {
	sort.Slice(imgs, func(i, j int) bool {
		var less bool
		switch sortBy {
		case "size":
			less = imgs[i].Size < imgs[j].Size
		case "created":
			less = imgs[i].Created.Before(imgs[j].Created)
		default: // name, tags
			less = strings.ToLower(imgs[i].PrimaryTag) < strings.ToLower(imgs[j].PrimaryTag)
		}
		if dir == "desc" {
			return !less
		}
		return less
	})
}

func sortVolumes(vols []VolumeView, sortBy, dir string) {
	sort.Slice(vols, func(i, j int) bool {
		var less bool
		switch sortBy {
		case "size":
			less = vols[i].Size < vols[j].Size
		case "created":
			less = vols[i].Created.Before(vols[j].Created)
		default: // name
			less = strings.ToLower(vols[i].Name) < strings.ToLower(vols[j].Name)
		}
		if dir == "desc" {
			return !less
		}
		return less
	})
}

// ============================================================================
// Volume Handlers (Templ)
// ============================================================================

// VolumesTempl lists all volumes using Templ.
func (h *Handler) VolumesTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.preparePageData(r, "Volumes", "volumes")
	
	volumesList, err := h.services.Volumes().List(ctx)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", err.Error())
		return
	}
	
	// Calculate total size
	var totalSize int64
	for _, vol := range volumesList {
		totalSize += vol.Size
	}
	
	// Parse filters
	filters := volumes.VolumeFilters{
		Search: GetQueryParam(r, "search", ""),
		Driver: GetQueryParam(r, "driver", ""),
		InUse:  GetQueryParam(r, "in_use", ""),
		Sort:   GetQueryParam(r, "sort", "name"),
		Dir:    GetQueryParam(r, "dir", "asc"),
	}
	
	// Filter volumes
	filteredVolumes := filterVolumes(volumesList, filters)
	
	// Sort volumes
	sortVolumes(filteredVolumes, filters.Sort, filters.Dir)
	
	// Pagination
	page := GetQueryParamInt(r, "page", 1)
	perPage := GetQueryParamInt(r, "per_page", 20)
	total := int64(len(filteredVolumes))
	pageData.Pagination = NewPagination(total, page, perPage)
	
	// Paginate results
	start := (page - 1) * perPage
	end := start + perPage
	if start > len(filteredVolumes) {
		start = len(filteredVolumes)
	}
	if end > len(filteredVolumes) {
		end = len(filteredVolumes)
	}
	paginatedList := filteredVolumes[start:end]
	
	listData := ToTemplVolumesListData(pageData, paginatedList, totalSize, filters)
	h.renderTempl(w, r, volumes.VolumesList(listData))
}

func filterVolumes(volumesList []VolumeView, filters volumes.VolumeFilters) []VolumeView {
	var result []VolumeView
	for _, vol := range volumesList {
		// Search filter
		if filters.Search != "" && !containsIgnoreCase(vol.Name, filters.Search) {
			continue
		}
		
		// Driver filter
		if filters.Driver != "" && vol.Driver != filters.Driver {
			continue
		}
		
		// In use filter
		if filters.InUse == "true" && !vol.InUse {
			continue
		}
		if filters.InUse == "false" && vol.InUse {
			continue
		}
		
		result = append(result, vol)
	}
	return result
}

// ============================================================================
// Network Handlers (Templ)
// ============================================================================

// NetworksTempl lists all networks using Templ.
func (h *Handler) NetworksTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.preparePageData(r, "Networks", "networks")
	
	networksList, err := h.services.Networks().List(ctx)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", err.Error())
		return
	}
	
	// Parse filters
	filters := networks.NetworkFilters{
		Search: GetQueryParam(r, "search", ""),
		Driver: GetQueryParam(r, "driver", ""),
		Scope:  GetQueryParam(r, "scope", ""),
	}
	
	// Filter networks
	filteredNetworks := filterNetworks(networksList, filters)
	
	// Pagination
	page := GetQueryParamInt(r, "page", 1)
	perPage := GetQueryParamInt(r, "per_page", 20)
	total := int64(len(filteredNetworks))
	pageData.Pagination = NewPagination(total, page, perPage)
	
	// Paginate results
	start := (page - 1) * perPage
	end := start + perPage
	if start > len(filteredNetworks) {
		start = len(filteredNetworks)
	}
	if end > len(filteredNetworks) {
		end = len(filteredNetworks)
	}
	paginatedList := filteredNetworks[start:end]
	
	listData := ToTemplNetworksListData(pageData, paginatedList, filters)
	h.renderTempl(w, r, networks.NetworksList(listData))
}

func filterNetworks(networksList []NetworkView, filters networks.NetworkFilters) []NetworkView {
	var result []NetworkView
	for _, net := range networksList {
		// Search filter
		if filters.Search != "" && !containsIgnoreCase(net.Name, filters.Search) {
			continue
		}
		
		// Driver filter
		if filters.Driver != "" && net.Driver != filters.Driver {
			continue
		}
		
		// Scope filter
		if filters.Scope != "" && net.Scope != filters.Scope {
			continue
		}
		
		result = append(result, net)
	}
	return result
}

// ============================================================================
// Helper Functions
// ============================================================================

func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) && 
		(s == substr || 
		 len(substr) == 0 ||
		 (len(s) > 0 && containsLower(toLower(s), toLower(substr))))
}

func containsLower(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

// ============================================================================
// Security Handlers (Templ)
// ============================================================================

// SecurityTempl renders the security overview page.
func (h *Handler) SecurityTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.preparePageData(r, "Security", "security")

	overview, err := h.services.Security().GetOverview(ctx)
	if err != nil {
		h.logger.Warn("Failed to get security overview", "error", err)
	}
	containers, err := h.services.Security().ListContainersWithSecurity(ctx)
	if err != nil {
		h.logger.Warn("Failed to list containers with security", "error", err)
	}
	scans, err := h.services.Security().ListScans(ctx)
	if err != nil {
		h.logger.Warn("Failed to list security scans", "error", err)
	}

	data := ToTemplSecurityListData(pageData, overview, containers, scans)
	h.renderTempl(w, r, securitytmpl.List(data))
}

// SecurityContainerTempl renders the security detail page for a container.
func (h *Handler) SecurityContainerTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	pageData := h.preparePageData(r, "Container Security", "security")

	scan, _ := h.services.Security().GetScan(ctx, id)

	// Issues come from the scan itself (GetScan loads them)
	var containerIssues []IssueView
	if scan != nil {
		containerIssues = scan.Issues
	}

	data := ToTemplSecurityContainerData(pageData, scan, containerIssues)
	h.renderTempl(w, r, securitytmpl.Container(data))
}

// SecurityScanTempl triggers a full security scan and redirects.
func (h *Handler) SecurityScanTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_ = h.services.Security().ScanAll(ctx)
	h.redirect(w, r, "/security")
}

// SecurityScanContainerTempl scans a specific container and redirects.
func (h *Handler) SecurityScanContainerTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	_, _ = h.services.Security().Scan(ctx, id)

	// If HTMX request, redirect to refresh the security list
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/security")
		w.WriteHeader(http.StatusOK)
		return
	}
	h.redirect(w, r, "/security")
}

// SecurityIssueIgnoreTempl marks an issue as ignored.
func (h *Handler) SecurityIssueIgnoreTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	_ = h.services.Security().IgnoreIssue(ctx, id)
	h.redirect(w, r, "/security")
}

// SecurityIssueResolveTempl marks an issue as resolved.
func (h *Handler) SecurityIssueResolveTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	_ = h.services.Security().ResolveIssue(ctx, id)
	h.redirect(w, r, "/security")
}

// SecurityTrendsTempl renders the security trends page.
func (h *Handler) SecurityTrendsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	daysStr := r.URL.Query().Get("days")
	days := 30
	if daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 365 {
			days = d
		}
	}

	trendsData, err := h.services.Security().GetTrends(ctx, days)
	if err != nil {
		trendsData = &SecurityTrendsViewData{Days: days}
	}
	if trendsData == nil {
		trendsData = &SecurityTrendsViewData{Days: days}
	}

	p := h.preparePageData(r, "Security Trends", "security")
	data := ToTemplSecurityTrendsData(p, trendsData)

	h.renderTempl(w, r, securitytmpl.Trends(data))
}

// SecurityReportTempl generates and serves a security report.
func (h *Handler) SecurityReportTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "html"
	}

	reportData, contentType, err := h.services.Security().GenerateReport(ctx, format)
	if err != nil {
		http.Error(w, "Failed to generate report", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", contentType)
	if format != "html" {
		w.Header().Set("Content-Disposition", "attachment; filename=security-report."+format)
	}
	w.Write(reportData)
}

// ============================================================================
// Updates Templ Handlers
// ============================================================================

// UpdatesTempl renders the updates list page with available updates and history.
func (h *Handler) UpdatesTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	available, _ := h.services.Updates().ListAvailable(ctx)
	history, _ := h.services.Updates().GetHistory(ctx)

	// Get containers for manual update dropdown
	var containers []updatestmpl.ContainerBasic
	containerSvc := h.services.Containers()
	if containerSvc != nil {
		if list, err := containerSvc.List(ctx, nil); err == nil {
			for _, c := range list {
				name := c.Name
				if len(name) > 0 && name[0] == '/' {
					name = name[1:]
				}
				containers = append(containers, updatestmpl.ContainerBasic{
					ID:   c.ID,
					Name: name,
				})
			}
		}
	}

	p := h.preparePageData(r, "Updates", "updates")
	data := ToTemplUpdatesListData(p, available, history)
	data.Containers = containers

	h.renderTempl(w, r, updatestmpl.List(data))
}

// UpdatesCheckTempl triggers a check for all available updates.
func (h *Handler) UpdatesCheckTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_ = h.services.Updates().CheckAll(ctx)

	// If HTMX request with hx-swap="none", send HX-Redirect
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/updates")
		w.WriteHeader(http.StatusOK)
		return
	}
	h.redirect(w, r, "/updates")
}

// UpdateApplyTempl applies an update to a specific container.
func (h *Handler) UpdateApplyTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	backup := r.FormValue("backup") != "false"
	targetVersion := strings.TrimSpace(r.FormValue("target_version"))
	if err := h.services.Updates().Apply(ctx, id, backup, targetVersion); err != nil {
		h.logger.Error("failed to apply update", "container", id, "error", err)
		h.setFlash(w, r, "error", "Update failed: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Update started successfully")
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/updates")
		w.WriteHeader(http.StatusOK)
		return
	}
	h.redirect(w, r, "/updates")
}

// UpdateManual handles manual update of a container to a specific version.
func (h *Handler) UpdateManual(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	containerID := r.FormValue("container_id")
	targetVersion := strings.TrimSpace(r.FormValue("target_version"))
	backup := r.FormValue("backup") == "true"

	if containerID == "" || targetVersion == "" {
		h.setFlash(w, r, "error", "Container and target version are required")
		http.Redirect(w, r, "/updates", http.StatusSeeOther)
		return
	}

	if err := h.services.Updates().Apply(ctx, containerID, backup, targetVersion); err != nil {
		h.logger.Error("failed to apply manual update", "container", containerID, "version", targetVersion, "error", err)
		h.setFlash(w, r, "error", "Update failed: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Manual update to "+targetVersion+" started successfully")
	}

	http.Redirect(w, r, "/updates", http.StatusSeeOther)
}

// UpdateRollbackTempl rolls back a previous update.
func (h *Handler) UpdateRollbackTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	_ = h.services.Updates().Rollback(ctx, id)

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/updates")
		w.WriteHeader(http.StatusOK)
		return
	}
	h.redirect(w, r, "/updates")
}
