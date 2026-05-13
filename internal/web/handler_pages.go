// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/web/templates/components"
	"github.com/fr4nsys/usulnet/internal/web/templates/layouts"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/backups"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/config"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/containers"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/hosts"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/networks"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/proxy"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/stacks"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/users"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/volumes"
	"github.com/fr4nsys/usulnet/internal/web/templates/types"
)

// ============================================================================
// Stacks Handlers
// ============================================================================

func (h *Handler) StacksTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Stacks", "stacks")

	stacksList, err := h.services.Stacks().List(ctx)
	if err != nil {
		h.renderTempl(w, r, stacks.List(stacks.StacksData{
			PageData: pageData,
			Stacks:   []stacks.StackItem{},
		}))
		return
	}

	var items []stacks.StackItem
	for _, s := range stacksList {
		items = append(items, stacks.StackItem{
			Name:           s.Name,
			Status:         s.Status,
			Services:       s.ServiceCount,
			Running:        s.RunningCount,
			Path:           s.Path,
			CreatedAt:      s.CreatedHuman,
			UpdatedAt:      s.UpdatedHuman,
			ContainerNames: s.ContainerNames,
			IsExternal:     s.IsExternal,
		})
	}

	data := stacks.StacksData{
		PageData: pageData,
		Stacks:   items,
	}
	h.renderTempl(w, r, stacks.List(data))
}

func (h *Handler) StackDetailTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := chi.URLParam(r, "name")

	stack, err := h.services.Stacks().Get(ctx, name)
	if err != nil || stack == nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Stack Not Found", "The stack '"+name+"' could not be found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Stack: "+stack.Name, "stacks")

	// Get services
	var services []stacks.ServiceInfo
	svcList, err := h.services.Stacks().GetServices(ctx, name)
	if err == nil {
		for _, svc := range svcList {
			services = append(services, stacks.ServiceInfo{
				Name:        svc.Name,
				Image:       svc.Image,
				Status:      svc.State,
				ContainerID: svc.ContainerID,
				Ports:       svc.Ports,
				Replicas:    svc.Replicas,
			})
		}
	}

	// Get compose content
	composeYML := stack.ComposeFile
	if config, err := h.services.Stacks().GetComposeConfig(ctx, name); err == nil && config != "" {
		composeYML = config
	}

	// Get version history
	var versions []stacks.VersionInfo
	if versionList, err := h.services.Stacks().ListVersions(ctx, name); err == nil {
		for _, v := range versionList {
			versions = append(versions, stacks.VersionInfo{
				Version:    v.Version,
				Comment:    v.Comment,
				CreatedAt:  v.CreatedAt,
				CreatedBy:  v.CreatedBy,
				IsDeployed: v.IsDeployed,
			})
		}
	}

	data := stacks.StackDetailData{
		PageData: pageData,
		Stack: stacks.StackInfo{
			ID:        stack.ID,
			Name:      stack.Name,
			Status:    stack.Status,
			Path:      stack.Path,
			CreatedAt: stack.CreatedHuman,
			UpdatedAt: stack.UpdatedHuman,
		},
		Services:   services,
		ComposeYML: composeYML,
		Versions:   versions,
	}
	h.renderTempl(w, r, stacks.Detail(data))
}

// StackEditTempl redirects to the stack detail page with the compose editor tab active.
func (h *Handler) StackEditTempl(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	http.Redirect(w, r, "/stacks/"+name+"#compose", http.StatusSeeOther)
}

func (h *Handler) StackNewTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "New Stack", "stacks")
	data := stacks.StackNewData{PageData: pageData}
	h.renderTempl(w, r, stacks.New(data))
}

func (h *Handler) StackCatalogTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Apps", "stacks")

	apps := GetCatalogApps()
	var items []stacks.CatalogAppItem
	for _, app := range apps {
		items = append(items, stacks.CatalogAppItem{
			Slug:        app.Slug,
			Name:        app.Name,
			Description: app.Description,
			Icon:        app.Icon,
			IconColor:   app.IconColor,
			Category:    app.Category,
			Version:     app.Version,
			Website:     app.Website,
		})
	}

	data := stacks.CatalogData{
		PageData:   pageData,
		Apps:       items,
		Categories: GetCatalogCategories(),
	}
	h.renderTempl(w, r, stacks.Catalog(data))
}

func (h *Handler) StackCatalogDeployTempl(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	app := GetCatalogApp(slug)
	if app == nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "App Not Found", "The application '"+slug+"' does not exist in the catalog.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Install "+app.Name, "stacks")
	data := stacks.CatalogDeployData{
		PageData:   pageData,
		App:        catalogAppToDetail(app),
		Values:     app.GetDefaultValues(),
		ComposeTPL: app.ComposeTPL,
	}
	h.renderTempl(w, r, stacks.CatalogDeploy(data))
}

func (h *Handler) StackCatalogDeploySubmit(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("PANIC in StackCatalogDeploySubmit",
				"panic", fmt.Sprintf("%v", rec),
				"stack", string(debug.Stack()),
			)
			http.Error(w, "Internal server error (panic recovered)", http.StatusInternalServerError)
		}
	}()

	slug := chi.URLParam(r, "slug")
	app := GetCatalogApp(slug)
	if app == nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "App Not Found", "The application '"+slug+"' does not exist in the catalog.")
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	// Collect form values
	values := make(map[string]string)
	for _, f := range app.Fields {
		values[f.Key] = r.FormValue(f.Key)
	}

	// Validate
	if validationErrors := app.Validate(values); len(validationErrors) > 0 {
		h.renderCatalogDeployError(w, r, app, "", validationErrors, values)
		return
	}

	// Render compose and deploy
	stackName := values["STACK_NAME"]
	if stackName == "" {
		stackName = app.Slug
	}
	composeContent := app.RenderCompose(values)

	ctx := r.Context()
	if err := h.services.Stacks().Deploy(ctx, stackName, composeContent); err != nil {
		slog.Error("catalog deploy failed", "app", slug, "stack", stackName, "error", err)
		h.renderCatalogDeployError(w, r, app, "Error al desplegar: "+err.Error(), nil, values)
		return
	}

	h.redirect(w, r, "/stacks/"+stackName)
}

// renderCatalogDeployError re-renders the catalog deploy form preserving user values.
func (h *Handler) renderCatalogDeployError(w http.ResponseWriter, r *http.Request, app *CatalogApp, errMsg string, validationErrors []string, values map[string]string) {
	pageData := h.prepareTemplPageData(r, "Install "+app.Name, "stacks")
	data := stacks.CatalogDeployData{
		PageData:   pageData,
		App:        catalogAppToDetail(app),
		Error:      errMsg,
		Errors:     validationErrors,
		Values:     values,
		ComposeTPL: app.ComposeTPL,
	}
	h.renderTempl(w, r, stacks.CatalogDeploy(data))
}

// catalogAppToDetail converts a CatalogApp to the template detail struct.
func catalogAppToDetail(app *CatalogApp) stacks.CatalogAppDetail {
	var fields []stacks.CatalogFieldItem
	for _, f := range app.Fields {
		fields = append(fields, stacks.CatalogFieldItem{
			Key:         f.Key,
			Label:       f.Label,
			Description: f.Description,
			Type:        string(f.Type),
			Default:     f.Default,
			Required:    f.Required,
			Options:     f.Options,
			Placeholder: f.Placeholder,
			Pattern:     f.Pattern,
		})
	}
	return stacks.CatalogAppDetail{
		Slug:        app.Slug,
		Name:        app.Name,
		Description: app.Description,
		Icon:        app.Icon,
		IconColor:   app.IconColor,
		Category:    app.Category,
		Version:     app.Version,
		Website:     app.Website,
		Source:      app.Source,
		Notes:       app.Notes,
		Fields:      fields,
	}
}

// ============================================================================
// Backups Handlers
// ============================================================================

func (h *Handler) BackupsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Backups", "backups")

	var warningMsg string
	if h.encryptor == nil {
		warningMsg = "Backup service requires an encryption key. Set security.config_encryption_key in config.yaml to enable backups."
	}

	var items []backups.BackupItem
	var stats backups.BackupStats
	var scheduleCount int
	filterType := r.URL.Query().Get("type")
	filterStatus := r.URL.Query().Get("status")

	if warningMsg == "" && h.services.Backups() != nil {
		// Fetch backups with optional filtering
		containerID := ""
		if bkps, err := h.services.Backups().List(ctx, containerID); err == nil {
			for _, b := range bkps {
				// Apply client-side filters
				if filterType != "" && b.Type != filterType {
					continue
				}
				if filterStatus != "" && b.Status != filterStatus {
					continue
				}
				items = append(items, backups.BackupItem{
					ID:            b.ID,
					ContainerName: b.ContainerName,
					Type:          b.Type,
					Path:          b.Path,
					Size:          b.SizeHuman,
					Trigger:       b.Trigger,
					Status:        b.Status,
					Compression:   b.Compression,
					Encrypted:     b.Encrypted,
					CreatedAt:     b.CreatedHuman,
				})
			}
		}

		// Fetch stats
		if st, err := h.services.Backups().GetStats(ctx); err == nil && st != nil {
			stats = backups.BackupStats{
				Total:     st.TotalBackups,
				Completed: st.CompletedBackups,
				Failed:    st.FailedBackups,
				TotalSize: st.TotalSizeHuman,
			}
		}

		// Fetch schedule count
		if schedules, err := h.services.Backups().ListSchedules(ctx); err == nil {
			scheduleCount = len(schedules)
		}
	}

	data := backups.BackupsData{
		PageData:       pageData,
		Backups:        items,
		Stats:          stats,
		BackupCount:    len(items),
		ScheduleCount:  scheduleCount,
		WarningMessage: warningMsg,
		FilterType:     filterType,
		FilterStatus:   filterStatus,
	}
	h.renderTempl(w, r, backups.List(data))
}

func (h *Handler) BackupNewTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "New Backup", "backups")

	data := backups.CreateData{
		PageData: pageData,
	}

	// Fetch containers for target selection
	if containerSvc := h.services.Containers(); containerSvc != nil {
		if containers, err := containerSvc.List(ctx, nil); err == nil {
			for _, c := range containers {
				data.Containers = append(data.Containers, backups.TargetOption{
					ID:   c.ID,
					Name: c.Name,
				})
			}
		}
	}

	// Fetch volumes
	if volumeSvc := h.services.Volumes(); volumeSvc != nil {
		if volumes, err := volumeSvc.List(ctx); err == nil {
			for _, v := range volumes {
				data.Volumes = append(data.Volumes, backups.TargetOption{
					ID:   v.Name,
					Name: v.Name,
				})
			}
		}
	}

	// Fetch stacks
	if stackSvc := h.services.Stacks(); stackSvc != nil {
		if stacks, err := stackSvc.List(ctx); err == nil {
			for _, s := range stacks {
				data.Stacks = append(data.Stacks, backups.TargetOption{
					ID:   s.Name,
					Name: s.Name,
				})
			}
		}
	}

	h.renderTempl(w, r, backups.Create(data))
}

func (h *Handler) BackupDetailTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)

	backupsSvc := h.services.Backups()
	if backupsSvc == nil {
		h.setFlash(w, r, "error", "Backup service is not configured")
		http.Redirect(w, r, "/backups", http.StatusSeeOther)
		return
	}
	b, err := backupsSvc.Get(ctx, id)
	if err != nil || b == nil {
		h.setFlash(w, r, "error", "Backup not found")
		http.Redirect(w, r, "/backups", http.StatusSeeOther)
		return
	}

	pageData := h.prepareTemplPageData(r, "Backup: "+b.ContainerName, "backups")

	data := backups.DetailData{
		PageData: pageData,
		Backup: backups.BackupDetail{
			ID:           b.ID,
			Type:         b.Type,
			TargetID:     b.ContainerID,
			TargetName:   b.ContainerName,
			Status:       b.Status,
			Trigger:      b.Trigger,
			Size:         b.SizeHuman,
			Compression:  b.Compression,
			Encrypted:    b.Encrypted,
			Verified:     b.Verified,
			Checksum:     b.Checksum,
			Path:         b.Path,
			ErrorMessage: b.ErrorMessage,
			CreatedAt:    b.CreatedHuman,
			CompletedAt:  b.CompletedAt,
			Duration:     b.Duration,
			ExpiresAt:    b.ExpiresAt,
		},
	}
	h.renderTempl(w, r, backups.Detail(data))
}

func (h *Handler) BackupSchedulesTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Backup Schedules", "backups")

	data := backups.SchedulesData{
		PageData: pageData,
	}

	// Fetch schedules
	if backupsSvc := h.services.Backups(); backupsSvc != nil {
		if schedules, err := backupsSvc.ListSchedules(ctx); err == nil {
			for _, s := range schedules {
				data.Schedules = append(data.Schedules, backups.ScheduleItem{
					ID:            s.ID,
					Type:          s.Type,
					TargetName:    s.TargetName,
					Schedule:      s.Schedule,
					Compression:   s.Compression,
					Encrypted:     s.Encrypted,
					RetentionDays: s.RetentionDays,
					MaxBackups:    s.MaxBackups,
					IsEnabled:     s.IsEnabled,
					LastRunAt:     s.LastRunAt,
					LastRunStatus: s.LastRunStatus,
					NextRunAt:     s.NextRunAt,
				})
			}
		}
	}

	// Fetch target lists for the create modal
	if containerSvc := h.services.Containers(); containerSvc != nil {
		if containers, err := containerSvc.List(ctx, nil); err == nil {
			for _, c := range containers {
				data.Containers = append(data.Containers, backups.TargetOption{ID: c.ID, Name: c.Name})
			}
		}
	}
	if volumeSvc := h.services.Volumes(); volumeSvc != nil {
		if volumes, err := volumeSvc.List(ctx); err == nil {
			for _, v := range volumes {
				data.Volumes = append(data.Volumes, backups.TargetOption{ID: v.Name, Name: v.Name})
			}
		}
	}
	if stackSvc := h.services.Stacks(); stackSvc != nil {
		if stacks, err := stackSvc.List(ctx); err == nil {
			for _, s := range stacks {
				data.Stacks = append(data.Stacks, backups.TargetOption{ID: s.Name, Name: s.Name})
			}
		}
	}

	h.renderTempl(w, r, backups.Schedules(data))
}

// ============================================================================
// Config Handlers
// ============================================================================

func (h *Handler) ConfigTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Configuration", "config")

	var warningMsg string
	if h.encryptor == nil {
		warningMsg = "Configuration service requires an encryption key. Set security.config_encryption_key in config.yaml to enable secret management."
	}

	var variables []config.Variable
	if warningMsg == "" {
		if vars, err := h.services.Config().ListVariables(ctx, "", ""); err == nil {
			for _, v := range vars {
				variables = append(variables, config.Variable{
					ID:        v.ID,
					Name:      v.Name,
					Value:     v.Value,
					IsSecret:  v.IsSecret,
					Scope:     v.Scope,
					ScopeID:   v.ScopeID,
					UsedBy:    v.UsedByCount,
					UpdatedAt: v.UpdatedAt,
				})
			}
		}
	}

	var templates []config.Template
	if warningMsg == "" {
		if tmpls, err := h.services.Config().ListTemplates(ctx); err == nil {
			for _, t := range tmpls {
				// ListTemplates returns []interface{}, try type assertion
				if m, ok := t.(map[string]interface{}); ok {
					tmpl := config.Template{}
					if v, ok := m["id"].(string); ok {
						tmpl.ID = v
					}
					if v, ok := m["name"].(string); ok {
						tmpl.Name = v
					}
					if v, ok := m["description"].(string); ok {
						tmpl.Description = v
					}
					if v, ok := m["var_count"].(int); ok {
						tmpl.VarCount = v
					} else if v, ok := m["var_count"].(float64); ok {
						tmpl.VarCount = int(v)
					}
					templates = append(templates, tmpl)
				}
			}
		}
	}

	data := config.ConfigData{
		PageData:       pageData,
		Variables:      variables,
		Templates:      templates,
		WarningMessage: warningMsg,
	}
	h.renderTempl(w, r, config.List(data))
}

// ============================================================================
// Hosts Handlers
// ============================================================================

func (h *Handler) HostsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Nodes", "nodes")

	var items []hosts.HostItem
	if hostList, err := h.services.Hosts().List(ctx); err == nil {
		for _, ho := range hostList {
			memStr := ""
			if ho.Memory > 0 {
				memStr = humanSize(ho.Memory)
			}
			items = append(items, hosts.HostItem{
				ID:                ho.ID,
				Name:              ho.Name,
				URL:               ho.Endpoint,
				EndpointType:      ho.EndpointType,
				Status:            ho.Status,
				Containers:        ho.Containers,
				ContainersRunning: ho.ContainersRunning,
				Images:            ho.Images,
				CPUs:              ho.CPUs,
				MemTotalStr:       memStr,
				DockerVersion:     ho.DockerVersion,
				KernelVersion:     ho.KernelVersion,
				OS:                ho.OS,
				Architecture:      ho.Arch,
				LastSeen:          ho.LastSeenHuman,
			})
		}
	}

	data := hosts.HostsData{
		PageData: pageData,
		Hosts:    items,
	}
	h.renderTempl(w, r, hosts.List(data))
}

func (h *Handler) HostDetailTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	// Validate the host ID format
	if _, err := uuid.Parse(idStr); err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid Host ID", "The host ID format is invalid.")
		return
	}

	host, err := h.services.Hosts().Get(ctx, idStr)
	if err != nil || host == nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Host Not Found", "The host could not be found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Node: "+host.Name, "nodes")

	// Build the detail data
	detail := hosts.HostDetail{
		ID:            host.ID,
		Name:          host.Name,
		Status:        host.Status,
		EndpointType:  host.EndpointType,
		EndpointURL:   host.Endpoint,
		TLSEnabled:    host.TLSEnabled,
		LastSeenHuman: host.LastSeenHuman,
	}
	// Set basic fields from HostView
	if !host.LastSeen.IsZero() {
		detail.LastSeen = host.LastSeen.Format("2006-01-02 15:04:05")
	}
	detail.DockerVersion = host.DockerVersion
	detail.OSType = host.OS
	detail.Architecture = host.Arch
	detail.CPUs = host.CPUs
	detail.MemTotal = host.Memory
	if host.Memory > 0 {
		detail.MemTotalStr = humanSize(host.Memory)
	}

	// Agent-specific fields
	if host.EndpointType == "agent" {
		detail.AgentConnected = host.Status == "online"
	}

	// Basic container count from HostView
	detail.ContainersTotal = host.Containers

	// Fetch Docker Engine info for this specific host (inject host ID into context)
	hostCtx := context.WithValue(ctx, ContextKeyActiveHost, idStr)
	if dockerInfo, err := h.services.Hosts().GetDockerInfo(hostCtx); err == nil && dockerInfo != nil {
		detail.DockerAPI = dockerInfo.APIVersion
		detail.DockerRootDir = dockerInfo.DockerRootDir
		detail.DockerID = dockerInfo.ID
		detail.Hostname = dockerInfo.Name
		detail.OS = dockerInfo.OS
		detail.KernelVersion = dockerInfo.KernelVersion
		detail.StorageDriver = dockerInfo.StorageDriver
		detail.LoggingDriver = dockerInfo.LoggingDriver
		detail.CgroupDriver = dockerInfo.CgroupDriver
		detail.CgroupVersion = dockerInfo.CgroupVersion
		detail.DefaultRuntime = dockerInfo.DefaultRuntime
		detail.SecurityOpts = dockerInfo.SecurityOptions
		detail.Runtimes = dockerInfo.Runtimes
		detail.SwarmActive = dockerInfo.Swarm
		detail.ContainersTotal = dockerInfo.Containers
		detail.ContainersRunning = dockerInfo.ContainersRunning
		detail.ContainersStopped = dockerInfo.ContainersStopped
		detail.ContainersPaused = dockerInfo.ContainersPaused
		detail.ImagesTotal = dockerInfo.Images
		// Use live Docker info as fallback for fields that may be empty in the DB
		if detail.DockerVersion == "" {
			detail.DockerVersion = dockerInfo.ServerVersion
		}
		if detail.OSType == "" {
			detail.OSType = dockerInfo.OSType
		}
		if detail.Architecture == "" {
			detail.Architecture = dockerInfo.Architecture
		}
		if detail.CPUs == 0 {
			detail.CPUs = dockerInfo.NCPU
		}
		if detail.MemTotal == 0 {
			detail.MemTotal = dockerInfo.MemTotal
		}
		if detail.MemTotal > 0 && detail.MemTotalStr == "" {
			detail.MemTotalStr = humanSize(detail.MemTotal)
		}
	}

	// Fetch host resource metrics (disk, memory usage, etc.)
	if metrics, err := h.services.Hosts().GetMetrics(ctx, idStr); err == nil && metrics != nil {
		detail.MemUsed = metrics.MemoryUsed
		detail.MemUsedStr = metrics.MemoryUsedStr
		detail.MemPercent = metrics.MemoryPercent
		detail.DiskUsed = metrics.DiskUsedStr
		detail.DiskTotal = metrics.DiskTotalStr
		detail.DiskPercent = metrics.DiskPercent
		detail.CPUPercent = metrics.CPUPercent
		detail.NetworkRxStr = metrics.NetworkRxStr
		detail.NetworkTxStr = metrics.NetworkTxStr
	}

	hostData := hosts.HostDetailData{
		PageData: pageData,
		Host:     detail,
	}
	h.renderTempl(w, r, hosts.Detail(hostData))
}

// findChar finds the first occurrence of a character in a string
func findChar(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// ============================================================================
// Proxy Handlers
// ============================================================================

func (h *Handler) ProxyTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Reverse Proxy", "proxy")

	var connected bool
	var proxyHosts []proxy.ProxyHost

	proxySvc := h.services.Proxy()
	if proxySvc != nil {
		connected = proxySvc.IsConnected(ctx)
		if connected {
			if hostList, err := proxySvc.ListHosts(ctx); err == nil {
				for _, ph := range hostList {
					proxyHosts = append(proxyHosts, proxy.ProxyHost{
						ID:            strconv.Itoa(ph.ID),
						DomainName:    ph.Domain,
						ForwardHost:   ph.ForwardHost,
						ForwardPort:   ph.ForwardPort,
						SSLEnabled:    ph.SSLEnabled,
						SSLForced:     ph.SSLForced,
						Enabled:       ph.Enabled,
						ContainerName: ph.Container,
						LastSync:      ph.ModifiedOn,
					})
				}
			}
		}
	}

	data := proxy.ProxyData{
		PageData:   pageData,
		Connected:  connected,
		ProxyHosts: proxyHosts,
	}
	h.renderTempl(w, r, proxy.List(data))
}

// ============================================================================
// Users Handlers
// ============================================================================

func (h *Handler) UsersTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Users", "users")

	filter := r.URL.Query().Get("filter")
	if filter == "" {
		filter = "all"
	}

	var items []users.UserItem
	if userList, _, err := h.services.Users().List(ctx, "", ""); err == nil {
		for _, u := range userList {
			// Apply filter
			if filter == "local" && u.IsLDAP {
				continue
			}
			if filter == "ldap" && !u.IsLDAP {
				continue
			}

			item := users.UserItem{
				ID:       u.ID,
				Username: u.Username,
				Email:    u.Email,
				Role:     u.Role,
				RoleName: u.Role,
				IsActive: u.IsActive,
				IsLDAP:   u.IsLDAP,
				LDAPDN:   u.LDAPDN,
				IsLocked: u.IsLocked,
			}
			if u.LastLogin != nil {
				item.LastLogin = u.LastLogin.Format("2006-01-02 15:04")
			}
			item.CreatedAt = u.CreatedAt.Format("2006-01-02 15:04")
			items = append(items, item)
		}
	}

	var statsView users.UserStats
	if st, err := h.services.Users().GetStats(ctx); err == nil && st != nil {
		statsView = users.UserStats{
			Total:    st.Total,
			Active:   st.Active,
			Inactive: st.Inactive,
			LDAP:     st.LDAP,
			Local:    st.Local,
			Locked:   st.Locked,
			Admins:   st.Admins,
		}
	}

	data := users.UsersData{
		PageData: pageData,
		Users:    items,
		Stats:    statsView,
		Filter:   filter,
	}
	h.renderTempl(w, r, users.List(data))
}

func (h *Handler) UserNewTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "New User", "users")
	data := users.UserNewData{PageData: pageData}

	// Load roles for dropdown
	if h.roleRepo != nil {
		if roles, err := h.roleRepo.GetAll(r.Context()); err == nil {
			for _, role := range roles {
				data.Roles = append(data.Roles, users.RoleOption{
					ID:          role.ID.String(),
					Name:        role.Name,
					DisplayName: role.DisplayName,
					Description: ptrToString(role.Description),
					IsSystem:    role.IsSystem,
				})
			}
		}
	}

	// Fallback: always ensure the built-in system roles are available
	if len(data.Roles) == 0 {
		data.Roles = builtinRoleOptions()
	}

	h.renderTempl(w, r, users.New(data))
}

// UserEditTempl shows user edit page using Templ.
func (h *Handler) UserEditTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	user, err := h.services.Users().Get(ctx, id)
	if err != nil || user == nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "User not found")
		return
	}

	pageData := h.prepareTemplPageData(r, "Edit User", "users")
	data := users.UserEditData{
		PageData: pageData,
		User: users.UserItem{
			ID:       user.ID,
			Username: user.Username,
			Email:    user.Email,
			Role:     user.Role,
			RoleName: user.Role,
			IsActive: user.IsActive,
			IsLDAP:   user.IsLDAP,
			LDAPDN:   user.LDAPDN,
			IsLocked: user.IsLocked,
		},
	}
	if user.LastLogin != nil {
		data.User.LastLogin = user.LastLogin.Format("2006-01-02 15:04")
	}
	data.User.CreatedAt = user.CreatedAt.Format("2006-01-02 15:04")

	// Load roles for dropdown and match current user's role to get RoleID
	if h.roleRepo != nil {
		if roles, err := h.roleRepo.GetAll(ctx); err == nil {
			for _, role := range roles {
				data.Roles = append(data.Roles, users.RoleOption{
					ID:          role.ID.String(),
					Name:        role.Name,
					DisplayName: role.DisplayName,
					Description: ptrToString(role.Description),
					IsSystem:    role.IsSystem,
				})
				// Match role name to populate RoleID for dropdown pre-selection
				if role.Name == user.Role {
					data.User.RoleID = role.ID.String()
				}
			}
		}
	}

	// Fallback: always ensure the built-in system roles are available
	if len(data.Roles) == 0 {
		data.Roles = builtinRoleOptions()
	}

	h.renderTempl(w, r, users.Edit(data))
}

// ============================================================================
// Settings Handler
// ============================================================================

func (h *Handler) SettingsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Settings", "settings")

	// Load settings from config service variables (scope=global)
	cfg := pages.SettingsConfig{
		SiteName:         "usulnet",
		BackupPath:       "/app/backups",
		BackupRetention:  30,
		ScanInterval:     6,
		UpdateCheckHours: 6,
	}

	// Use "global" scope for application-wide settings
	if vars, err := h.services.Config().ListVariables(ctx, "global", ""); err == nil {
		for _, v := range vars {
			switch v.Name {
			// General
			case "settings.app_name":
				if v.Value != "" {
					cfg.SiteName = v.Value
				}

			// Backups
			case "backup.path":
				if v.Value != "" {
					cfg.BackupPath = v.Value
				}
			case "backup.retention_days":
				if n, err := strconv.Atoi(v.Value); err == nil && n > 0 {
					cfg.BackupRetention = n
				}

			// Security / Maintenance
			case "security.scan_interval_hours":
				if n, err := strconv.Atoi(v.Value); err == nil && n > 0 {
					cfg.ScanInterval = n
				}
			case "system.update_check_hours":
				if n, err := strconv.Atoi(v.Value); err == nil && n > 0 {
					cfg.UpdateCheckHours = n
				}

			// S3
			case "backup.s3.enabled":
				cfg.S3Enabled = v.Value == "true"
			case "backup.s3.bucket":
				cfg.S3Bucket = v.Value
			case "backup.s3.region":
				cfg.S3Region = v.Value

			// SMTP
			case "notifications.smtp.enabled":
				cfg.SMTPEnabled = v.Value == "true"
			case "notifications.smtp.host":
				cfg.SMTPHost = v.Value
			case "notifications.smtp.port":
				if n, err := strconv.Atoi(v.Value); err == nil && n > 0 {
					cfg.SMTPPort = n
				}
			}
		}
	}

	// Build sidebar config from current user's prefs
	sidebarPrefs := pageData.SidebarPrefs
	if sidebarPrefs == nil {
		sidebarPrefs = types.DefaultSidebarPreferences()
	}
	sidebarConfig := buildSidebarConfig(sidebarPrefs)

	data := pages.SettingsData{
		PageData:      pageData,
		Settings:      cfg,
		SidebarConfig: sidebarConfig,
	}
	h.renderTempl(w, r, pages.Settings(data))
}

func (h *Handler) SettingsUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		slog.Error("Failed to parse settings form", "error", err)
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	// Map form fields to config variable names (namespaced keys)
	fields := map[string]string{
		"settings.app_name":          r.FormValue("site_name"),
		"backup.path":                r.FormValue("backup_path"),
		"backup.retention_days":      r.FormValue("backup_retention"),
		"security.scan_interval_hours": r.FormValue("scan_interval"),
		"system.update_check_hours":  r.FormValue("update_check_hours"),
		
		// S3
		"backup.s3.enabled":          formatCheckbox(r.FormValue("s3_enabled")),
		"backup.s3.bucket":           r.FormValue("s3_bucket"),
		"backup.s3.region":           r.FormValue("s3_region"),

		// SMTP
		"notifications.smtp.enabled": formatCheckbox(r.FormValue("smtp_enabled")),
		"notifications.smtp.host":    r.FormValue("smtp_host"),
		"notifications.smtp.port":    r.FormValue("smtp_port"),
	}

	var failedFields []string
	for name, value := range fields {
		// For checkboxes/booleans, we always want to save the state even if empty/false (handled by formatCheckbox)
		// For strings, we might want to allow empty values to clear settings? 
		// For now, we save everything present in the map.
		
		v := &ConfigVarView{
			Name:    name,
			Value:   value,
			VarType: "string", // Everything is stored as string
			Scope:   "global",
		}
		
		if err := h.services.Config().CreateVariable(ctx, v); err != nil {
			slog.Error("Failed to save setting", "name", name, "error", err)
			failedFields = append(failedFields, name)
		}
	}

	if len(failedFields) > 0 {
		h.setFlash(w, r, "error", fmt.Sprintf("Failed to save settings: %s", strings.Join(failedFields, ", ")))
	} else {
		h.setFlash(w, r, "success", "Settings saved successfully")
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// Helper for checkbox values
func formatCheckbox(val string) string {
	if val == "on" || val == "true" || val == "1" {
		return "true"
	}
	return "false"
}

// ============================================================================
// Profile Handler
// ============================================================================

func (h *Handler) ProfileTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Profile", "profile")
	user := GetUserFromContext(r.Context())
	profileUser := pages.ProfileUser{}
	if user != nil {
		profileUser.Username = user.Username
		profileUser.Email = user.Email
		profileUser.Role = user.Role
	}
	data := pages.ProfileData{
		PageData: pageData,
		User:     profileUser,
	}
	h.renderTempl(w, r, pages.Profile(data))
}

// ============================================================================
// Events Handler
// ============================================================================

func (h *Handler) EventsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Events", "events")

	var items []pages.EventItem
	if evts, err := h.services.Events().List(ctx, 100); err == nil {
		for _, e := range evts {
			items = append(items, pages.EventItem{
				ID:        e.ID,
				Type:      e.Type,
				Action:    e.Action,
				Actor:     e.ActorName,
				ActorType: e.ActorType,
				Message:   e.Message,
				Timestamp: e.TimeHuman,
			})
		}
	}

	data := pages.EventsData{
		PageData: pageData,
		Events:   items,
	}
	h.renderTempl(w, r, pages.Events(data))
}

// ============================================================================
// Ports Handler
// ============================================================================

func (h *Handler) PortsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Port Management", "ports")

	var portMappings []pages.PortMapping
	var conflicts []pages.PortConflict
	var recommendations []pages.PortRecommendation
	var portError string

	// Derive port data from containers
	type portBindKey struct {
		port     int
		protocol string
		hostIP   string
	}
	portUsage := make(map[portBindKey][]string) // (port, protocol, hostIP) -> containerNames
	containerList, err := h.services.Containers().List(ctx, nil)
	if err != nil {
		h.logger.Error("ports: failed to list containers", "error", err)
		portError = "Could not retrieve container data: " + err.Error()
	}
	if err == nil {
		for _, c := range containerList {
			for _, p := range c.Ports {
				if p.HostPort == 0 {
					continue
				}
				hostIP := p.HostIP
				if hostIP == "" {
					hostIP = "0.0.0.0"
				}
				protocol := p.Protocol
				if protocol == "" {
					protocol = "tcp"
				}
				exposureLevel := "internal"
				isRisky := false
				if hostIP == "0.0.0.0" {
					exposureLevel = "internet"
					isRisky = true
				} else if hostIP == "127.0.0.1" {
					exposureLevel = "localhost"
				}

				portMappings = append(portMappings, pages.PortMapping{
					ContainerID:   c.ID,
					ContainerName: c.Name,
					InternalPort:  p.ContainerPort,
					ExternalPort:  p.HostPort,
					Protocol:      protocol,
					HostBind:      hostIP,
					ExposureLevel: exposureLevel,
					IsRisky:       isRisky,
				})

				key := portBindKey{port: p.HostPort, protocol: protocol, hostIP: hostIP}
				portUsage[key] = append(portUsage[key], c.Name)

				// Security recommendations for exposed ports
				if hostIP == "0.0.0.0" {
					recommendations = append(recommendations, pages.PortRecommendation{
						ContainerID:   c.ID,
						ContainerName: c.Name,
						Port:          p.HostPort,
						Issue:         "Port exposed to all interfaces",
						Suggestion:    "Bind to 127.0.0.1 if only local access needed",
					})
				}
			}
		}
	}

	// Detect port conflicts (same port + protocol + host IP used by multiple containers)
	for key, names := range portUsage {
		if len(names) > 1 {
			conflicts = append(conflicts, pages.PortConflict{
				Port:       key.port,
				Protocol:   key.protocol,
				Containers: names,
			})
		}
	}

	data := pages.PortsData{
		PageData:        pageData,
		Ports:           portMappings,
		Conflicts:       conflicts,
		Recommendations: recommendations,
		Error:           portError,
	}
	h.renderTempl(w, r, pages.Ports(data))
}

// ============================================================================
// Topology Handler
// ============================================================================

func (h *Handler) TopologyTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Network Topology", "topology")

	var networkTopos []pages.NetworkTopology
	var containerNodes []pages.ContainerNode

	// Use full network list for detailed info (driver, subnet, gateway, containers)
	if networks, err := h.services.Networks().List(ctx); err == nil {
		containerNetworks := make(map[string][]string)

		for _, net := range networks {
			nt := pages.NetworkTopology{
				ID:         net.ID,
				Name:       net.Name,
				Driver:     net.Driver,
				Subnet:     net.Subnet,
				Gateway:    net.Gateway,
				Scope:      net.Scope,
				Internal:   net.Internal,
				Containers: net.Containers,
			}
			networkTopos = append(networkTopos, nt)

			for _, cName := range net.Containers {
				containerNetworks[cName] = append(containerNetworks[cName], net.Name)
			}
		}

		// Build container nodes from topology data
		if topo, err := h.services.Networks().GetTopology(ctx); err == nil && topo != nil {
			seen := make(map[string]bool)
			for _, node := range topo.Nodes {
				if node.Type == "container" && !seen[node.ID] {
					seen[node.ID] = true
					containerNodes = append(containerNodes, pages.ContainerNode{
						ID:       node.ID,
						Name:     node.Label,
						Status:   node.State,
						Networks: containerNetworks[node.Label],
					})
				}
			}
		}
	}

	data := pages.TopologyData{
		PageData:   pageData,
		Networks:   networkTopos,
		Containers: containerNodes,
	}
	h.renderTempl(w, r, pages.Topology(data))
}

// ============================================================================
// Notifications Handler
// ============================================================================

func (h *Handler) NotificationsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Notifications", "notifications")

	var items []pages.NotificationItem
	var unreadCount int

	// Generate notifications from recent alert events
	alertSvc := h.getAlertService()
	if alertSvc != nil {
		events, _, err := alertSvc.ListEvents(ctx, models.AlertEventListOptions{Limit: 50})
		if err == nil {
			for _, event := range events {
				nType := "info"
				if event.State == "firing" {
					nType = "warning"
				}
				// Get rule name for better notification title
				title := "Alert Event"
				if rule, err := alertSvc.GetRule(ctx, event.AlertID); err == nil && rule != nil {
					title = rule.Name
					if rule.Severity == "critical" {
						nType = "error"
					}
				}

				item := pages.NotificationItem{
					ID:        event.ID.String(),
					Type:      nType,
					Title:     title,
					Message:   event.Message,
					Link:      "/alerts?tab=events",
					Read:      event.AcknowledgedAt != nil,
					CreatedAt: event.FiredAt.Format("2006-01-02 15:04"),
				}
				if event.AcknowledgedAt == nil {
					unreadCount++
				}
				items = append(items, item)
			}
		}
	}

	data := pages.NotificationsData{
		PageData:      pageData,
		Notifications: items,
		UnreadCount:   unreadCount,
	}
	h.renderTempl(w, r, pages.Notifications(data))
}

func (h *Handler) NotificationsMarkAllRead(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	alertSvc := h.getAlertService()
	if alertSvc != nil {
		var userID uuid.UUID
		if user := GetUserFromContext(ctx); user != nil {
			userID, _ = uuid.Parse(user.ID)
		}
		events, _, err := alertSvc.ListEvents(ctx, models.AlertEventListOptions{Limit: 100})
		if err == nil {
			for _, event := range events {
				if event.AcknowledgedAt == nil {
					_ = alertSvc.AcknowledgeEvent(ctx, event.ID, userID)
				}
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) NotificationMarkRead(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	alertSvc := h.getAlertService()
	if alertSvc != nil {
		if eventID, err := uuid.Parse(idStr); err == nil {
			var userID uuid.UUID
			if user := GetUserFromContext(ctx); user != nil {
				userID, _ = uuid.Parse(user.ID)
			}
			_ = alertSvc.AcknowledgeEvent(ctx, eventID, userID)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) NotificationDelete(w http.ResponseWriter, r *http.Request) {
	// Alert events cannot be deleted, but we acknowledge them to "dismiss"
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	alertSvc := h.getAlertService()
	if alertSvc != nil {
		if eventID, err := uuid.Parse(idStr); err == nil {
			var userID uuid.UUID
			if user := GetUserFromContext(ctx); user != nil {
				userID, _ = uuid.Parse(user.ID)
			}
			_ = alertSvc.AcknowledgeEvent(ctx, eventID, userID)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// ============================================================================
// Form Handlers (New)
// ============================================================================

func (h *Handler) ContainerNewTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Create Container", "containers")

	// Fetch real images
	var imageNames []string
	if imgList, err := h.services.Images().List(ctx); err == nil {
		for _, img := range imgList {
			if img.PrimaryTag != "" {
				imageNames = append(imageNames, img.PrimaryTag)
			}
		}
	}

	// Fetch real networks
	var networkNames []string
	if netList, err := h.services.Networks().List(ctx); err == nil {
		for _, net := range netList {
			networkNames = append(networkNames, net.Name)
		}
	}

	// Fetch real volumes
	var volumeNames []string
	if volList, err := h.services.Volumes().List(ctx); err == nil {
		for _, vol := range volList {
			volumeNames = append(volumeNames, vol.Name)
		}
	}

	data := containers.ContainerNewData{
		PageData: pageData,
		Images:   imageNames,
		Networks: networkNames,
		Volumes:  volumeNames,
	}
	h.renderTempl(w, r, containers.New(data))
}

func (h *Handler) ContainerCreateSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	input := &ContainerCreateInput{
		Name:          r.FormValue("name"),
		Image:         r.FormValue("image"),
		Ports:         r.Form["ports[]"],
		Environment:   r.FormValue("environment"),
		Volumes:       r.Form["volumes[]"],
		Network:       r.FormValue("network"),
		Command:       r.FormValue("command"),
		RestartPolicy: r.FormValue("restart"),
		Privileged:    r.FormValue("privileged") == "on",
		AutoRemove:    r.FormValue("auto_remove") == "on",
	}

	// Validate required fields
	if input.Name == "" || input.Image == "" {
		pageData := h.prepareTemplPageData(r, "Create Container", "containers")
		var imageNames []string
		if imgList, err := h.services.Images().List(ctx); err == nil {
			for _, img := range imgList {
				if img.PrimaryTag != "" {
					imageNames = append(imageNames, img.PrimaryTag)
				}
			}
		}
		var networkNames []string
		if netList, err := h.services.Networks().List(ctx); err == nil {
			for _, net := range netList {
				networkNames = append(networkNames, net.Name)
			}
		}
		var volumeNames []string
		if volList, err := h.services.Volumes().List(ctx); err == nil {
			for _, vol := range volList {
				volumeNames = append(volumeNames, vol.Name)
			}
		}
		data := containers.ContainerNewData{
			PageData: pageData,
			Error:    "Name and image are required",
			Images:   imageNames,
			Networks: networkNames,
			Volumes:  volumeNames,
		}
		h.renderTempl(w, r, containers.New(data))
		return
	}

	// Create container
	containerID, err := h.services.Containers().Create(ctx, input)
	if err != nil {
		slog.Error("container create failed", "name", input.Name, "error", err)
		pageData := h.prepareTemplPageData(r, "Create Container", "containers")
		var imageNames []string
		if imgList, err := h.services.Images().List(ctx); err == nil {
			for _, img := range imgList {
				if img.PrimaryTag != "" {
					imageNames = append(imageNames, img.PrimaryTag)
				}
			}
		}
		var networkNames []string
		if netList, err := h.services.Networks().List(ctx); err == nil {
			for _, net := range netList {
				networkNames = append(networkNames, net.Name)
			}
		}
		var volumeNames []string
		if volList, err := h.services.Volumes().List(ctx); err == nil {
			for _, vol := range volList {
				volumeNames = append(volumeNames, vol.Name)
			}
		}
		data := containers.ContainerNewData{
			PageData: pageData,
			Error:    "Error creating container: " + err.Error(),
			Images:   imageNames,
			Networks: networkNames,
			Volumes:  volumeNames,
		}
		h.renderTempl(w, r, containers.New(data))
		return
	}

	// Auto-start
	if err := h.services.Containers().Start(ctx, containerID); err != nil {
		slog.Warn("container created but failed to start", "id", containerID, "error", err)
	}

	h.redirect(w, r, "/containers/"+containerID)
}

func (h *Handler) VolumeNewTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Create Volume", "volumes")
	data := volumes.VolumeNewData{
		PageData: pageData,
		Drivers:  []string{"local"},
	}
	h.renderTempl(w, r, volumes.New(data))
}

func (h *Handler) NetworkNewTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Create Network", "networks")
	data := networks.NetworkNewData{PageData: pageData}
	h.renderTempl(w, r, networks.New(data))
}

// ============================================================================
// Partials
// ============================================================================

func (h *Handler) StatsPartial(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	stats := GetStatsFromContext(r.Context())
	if stats == nil {
		w.Write([]byte(`<div id="stats">No stats available</div>`))
		return
	}
	w.Write([]byte(`<div id="stats" class="flex gap-4 text-sm text-gray-400">` +
		`<span>Containers: ` + strconv.Itoa(stats.ContainersRunning) + `/` + strconv.Itoa(stats.ContainersTotal) + `</span>` +
		`<span>Images: ` + strconv.Itoa(stats.ImagesCount) + `</span>` +
		`<span>Volumes: ` + strconv.Itoa(stats.VolumesCount) + `</span>` +
		`<span>Networks: ` + strconv.Itoa(stats.NetworksCount) + `</span>` +
		`</div>`))
}

func (h *Handler) ContainerRowPartial(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	container, err := h.services.Containers().Get(ctx, id)
	if err != nil || container == nil {
		w.Write([]byte(`<tr><td colspan="6">Container not found</td></tr>`))
		return
	}
	// Return a basic table row with container data
	var portStr string
	for i, p := range container.Ports {
		if i > 0 {
			portStr += ", "
		}
		portStr += p.Display
	}
	stateClass := "text-gray-400"
	if container.State == "running" {
		stateClass = "text-green-400"
	} else if container.State == "exited" {
		stateClass = "text-red-400"
	}
	w.Write([]byte(`<tr id="container-` + container.ShortID + `">` +
		`<td class="px-4 py-3 text-sm text-gray-300">` + container.Name + `</td>` +
		`<td class="px-4 py-3 text-sm text-gray-400">` + container.ImageShort + `</td>` +
		`<td class="px-4 py-3 text-sm ` + stateClass + `">` + container.State + `</td>` +
		`<td class="px-4 py-3 text-sm text-gray-400">` + container.Status + `</td>` +
		`<td class="px-4 py-3 text-sm text-gray-400">` + portStr + `</td>` +
		`<td class="px-4 py-3 text-sm text-gray-500">` + container.CreatedHuman + `</td>` +
		`</tr>`))
}

func (h *Handler) ImagesPartial(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	imgList, err := h.services.Images().List(ctx)
	if err != nil {
		w.Write([]byte(`<div id="images" class="text-red-400 p-4">Failed to load images</div>`))
		return
	}

	var b strings.Builder
	b.WriteString(`<div id="images" class="space-y-2">`)
	if len(imgList) == 0 {
		b.WriteString(`<p class="text-gray-400 p-4">No images found</p>`)
	} else {
		for _, img := range imgList {
			tag := img.PrimaryTag
			if tag == "" && len(img.Tags) > 0 {
				tag = img.Tags[0]
			}
			if tag == "" {
				tag = img.ShortID
			}
			b.WriteString(fmt.Sprintf(
				`<div class="flex items-center justify-between p-2 rounded bg-dark-700"><span class="text-sm text-white truncate">%s</span><span class="text-xs text-gray-400">%s</span></div>`,
				tag, img.SizeHuman,
			))
		}
	}
	b.WriteString(`</div>`)
	w.Write([]byte(b.String()))
}

func (h *Handler) ImagePullSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		http.Redirect(w, r, "/images", http.StatusSeeOther)
		return
	}

	reference := r.FormValue("reference")
	if reference == "" {
		reference = r.FormValue("image")
	}
	if reference == "" {
		h.setFlash(w, r, "error", "Image reference is required")
		http.Redirect(w, r, "/images", http.StatusSeeOther)
		return
	}

	// Resolve registry credentials for the image reference
	auth := h.resolveRegistryAuth(r.Context(), reference)

	if auth != nil {
		if err := h.services.Images().PullWithAuth(r.Context(), reference, auth); err != nil {
			h.setFlash(w, r, "error", "Failed to pull image: "+err.Error())
		} else {
			h.setFlash(w, r, "success", "Image "+reference+" pulled successfully")
		}
	} else {
		if err := h.services.Images().Pull(r.Context(), reference); err != nil {
			h.setFlash(w, r, "error", "Failed to pull image: "+err.Error())
		} else {
			h.setFlash(w, r, "success", "Image "+reference+" pulled successfully")
		}
	}

	http.Redirect(w, r, "/images", http.StatusSeeOther)
}

// ============================================================================
// Helper
// ============================================================================

func (h *Handler) prepareTemplPageData(r *http.Request, title, active string) layouts.PageData {
	user := GetUserFromContext(r.Context())
	stats := GetStatsFromContext(r.Context())
	flash := GetFlashFromContext(r.Context())

	var userData *layouts.UserData
	if user != nil {
		userData = &layouts.UserData{
			ID:       user.ID,
			Username: user.Username,
			Role:     user.Role,
			Email:    user.Email,
		}
	}

	var statsData *layouts.StatsData
	if stats != nil {
		statsData = &layouts.StatsData{
			ContainersRunning: stats.ContainersRunning,
			ContainersTotal:   stats.ContainersTotal,
			ImagesCount:       stats.ImagesCount,
			VolumesCount:      stats.VolumesCount,
			NetworksCount:     stats.NetworksCount,
		}
	}

	var flashData *layouts.FlashData
	if flash != nil {
		flashData = &layouts.FlashData{
			Type:    flash.Type,
			Message: flash.Message,
		}
	}

	// Host selector data for the header
	var hostItems []types.HostSelectorItem
	activeHostID := GetActiveHostIDFromContext(r.Context())
	activeHostName := "Local"

	if hostsSvc := h.services.Hosts(); hostsSvc != nil {
		if hostList, err := hostsSvc.List(r.Context()); err == nil {
			for _, ho := range hostList {
				hostItems = append(hostItems, types.HostSelectorItem{
					ID:           ho.ID,
					Name:         ho.Name,
					Status:       ho.Status,
					EndpointType: ho.EndpointType,
				})
				if ho.ID == activeHostID {
					activeHostName = ho.Name
				}
			}
		}
	}

	// Default active host to first in list if not set
	if activeHostID == "" && len(hostItems) > 0 {
		activeHostID = hostItems[0].ID
		activeHostName = hostItems[0].Name
	}

	// License edition info
	edition := "ce"
	editionName := "Community Edition"
	if h.licenseProvider != nil {
		info := h.licenseProvider.GetInfo()
		if info != nil {
			edition = string(info.Edition)
			editionName = info.EditionName()
		}
	}

	// Sidebar preferences (per-user collapse state and item visibility)
	sidebarPrefs := types.DefaultSidebarPreferences()
	if h.prefsRepo != nil && user != nil {
		if prefsJSON, err := h.prefsRepo.GetSidebarPrefs(r.Context(), user.ID); err == nil && prefsJSON != "" {
			var sp types.SidebarPreferences
			if err := json.Unmarshal([]byte(prefsJSON), &sp); err == nil {
				if sp.Collapsed == nil {
					sp.Collapsed = types.DefaultSidebarPreferences().Collapsed
				}
				if sp.Hidden == nil {
					sp.Hidden = map[string]bool{}
				}
				sidebarPrefs = &sp
			}
		}
	}

	// Recon feature flag: surface from the service registry so the
	// sidebar can hide the section when the module is off.
	reconEnabled := false
	if reg, ok := h.services.(reconAware); ok {
		if rs := reg.Recon(); rs != nil {
			reconEnabled = rs.IsEnabled()
		}
	}

	return layouts.PageData{
		Title:          title,
		Active:         active,
		ReconEnabled:   reconEnabled,
		User:           userData,
		Stats:          statsData,
		Flash:          flashData,
		Theme:          GetThemeFromContext(r.Context()),
		Version:        h.version,
		CSRFToken:      GetCSRFTokenFromContext(r.Context()),
		Hosts:          hostItems,
		ActiveHostID:   activeHostID,
		ActiveHostName: activeHostName,
		Edition:        edition,
		EditionName:    editionName,
		SidebarPrefs:   sidebarPrefs,
	}
}

// ============================================================================
// Terminal Hub Handlers
// ============================================================================

// TerminalHubTempl renders the multi-tab terminal interface.
func (h *Handler) TerminalHubTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Terminal Hub", "terminal")

	var initialTabs []components.TerminalTabConfig

	// Check if a container ID was specified to open initially
	containerID := r.URL.Query().Get("container")
	addContainerID := r.URL.Query().Get("add")

	// Get running containers for initial tabs
	if containerID != "" {
		// Single container mode
		container, err := h.services.Containers().Get(ctx, containerID)
		if err == nil && container != nil {
			name := container.Name
			if strings.HasPrefix(name, "/") {
				name = name[1:]
			}
			initialTabs = append(initialTabs, components.TerminalTabConfig{
				ID:       containerID[:12],
				Name:     name,
				Type:     "container",
				TargetID: containerID,
				Icon:     "fa-terminal",
				Active:   true,
			})
		}
	} else if addContainerID != "" {
		// Add a new tab for the specified container
		container, err := h.services.Containers().Get(ctx, addContainerID)
		if err == nil && container != nil {
			name := container.Name
			if strings.HasPrefix(name, "/") {
				name = name[1:]
			}
			initialTabs = append(initialTabs, components.TerminalTabConfig{
				ID:       addContainerID[:12],
				Name:     name,
				Type:     "container",
				TargetID: addContainerID,
				Icon:     "fa-terminal",
				Active:   true,
			})
		}
	}

	// If no specific container, show a placeholder tab
	if len(initialTabs) == 0 {
		// Get first running container
		containerList, err := h.services.Containers().List(ctx, nil)
		if err == nil && len(containerList) > 0 {
			for _, c := range containerList {
				if c.State == "running" {
					name := c.Name
					if strings.HasPrefix(name, "/") {
						name = name[1:]
					}
					initialTabs = append(initialTabs, components.TerminalTabConfig{
						ID:       c.ID[:12],
						Name:     name,
						Type:     "container",
						TargetID: c.ID,
						Icon:     "fa-terminal",
						Active:   true,
					})
					break
				}
			}
		}
	}

	data := pages.TerminalHubData{
		PageData:    pageData,
		InitialTabs: initialTabs,
	}
	h.renderTempl(w, r, pages.TerminalHub(data))
}

// TerminalPickerTempl renders the container picker for the new tab modal.
func (h *Handler) TerminalPickerTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var pickerContainers []pages.TerminalPickerContainer

	containerList, err := h.services.Containers().List(ctx, nil)
	if err == nil {
		for _, c := range containerList {
			if c.State == "running" {
				name := c.Name
				if strings.HasPrefix(name, "/") {
					name = name[1:]
				}
				pickerContainers = append(pickerContainers, pages.TerminalPickerContainer{
					ID:     c.ID,
					Name:   name,
					Image:  c.Image,
					Status: c.State,
				})
			}
		}
	}

	h.renderTempl(w, r, pages.TerminalPicker(pickerContainers))
}

// buildSidebarConfig produces the sidebar settings UI data from current prefs.
func buildSidebarConfig(prefs *types.SidebarPreferences) []pages.SidebarSectionConfig {
	vis := func(key string) bool { return !prefs.IsHidden(key) }
	return []pages.SidebarSectionConfig{
		{Label: "Overview", Items: []pages.SidebarItemOption{
			{Key: "swarm", Label: "Swarm", Icon: "fa-network-wired", Visible: vis("swarm")},
		}},
		{Label: "Resources", Items: []pages.SidebarItemOption{
			{Key: "templates", Label: "Templates", Icon: "fa-clone", Visible: vis("templates")},
			{Key: "ports", Label: "Ports", Icon: "fa-plug", Visible: vis("ports")},
		}},
		{Label: "Operations", Items: []pages.SidebarItemOption{
			{Key: "compliance", Label: "Compliance", Icon: "fa-check-double", Visible: vis("compliance")},
			{Key: "config", Label: "Config", Icon: "fa-cogs", Visible: vis("config")},
			{Key: "secrets", Label: "Secrets", Icon: "fa-lock", Visible: vis("secrets")},
			{Key: "lifecycle", Label: "Lifecycle", Icon: "fa-recycle", Visible: vis("lifecycle")},
			{Key: "maintenance", Label: "Maintenance", Icon: "fa-wrench", Visible: vis("maintenance")},
		}},
		{Label: "Connections", Items: []pages.SidebarItemOption{
			{Key: "databases", Label: "Databases", Icon: "fa-database", Visible: vis("databases")},
			{Key: "ldap", Label: "LDAP", Icon: "fa-sitemap", Visible: vis("ldap")},
			{Key: "rdp", Label: "RDP", Icon: "fa-desktop", Visible: vis("rdp")},
		}},
		{Label: "Tools", Items: []pages.SidebarItemOption{
			{Key: "ansible", Label: "Ansible", Icon: "fa-cogs", Visible: vis("ansible")},
			{Key: "capture", Label: "Packet Capture", Icon: "fa-satellite-dish", Visible: vis("capture")},
		}},
		{Label: "Integrations", Items: []pages.SidebarItemOption{
			{Key: "proxy", Label: "Reverse Proxy", Icon: "fa-random", Visible: vis("proxy")},
			{Key: "repositories", Label: "Repositories", Icon: "fa-code-branch", Visible: vis("repositories")},
			{Key: "gitops", Label: "GitOps", Icon: "fa-code-branch", Visible: vis("gitops")},
		}},
		{Label: "Monitoring", Items: []pages.SidebarItemOption{
			{Key: "metrics", Label: "Metrics", Icon: "fa-chart-line", Visible: vis("metrics")},
			{Key: "health", Label: "Health", Icon: "fa-heartbeat", Visible: vis("health")},
			{Key: "log-management", Label: "Log Analysis", Icon: "fa-search-plus", Visible: vis("log-management")},
			{Key: "dependencies", Label: "Dependencies", Icon: "fa-sitemap", Visible: vis("dependencies")},
		}},
		{Label: "Admin", Items: []pages.SidebarItemOption{
			{Key: "oauth", Label: "OAuth", Icon: "fa-sign-in-alt", Visible: vis("oauth")},
			{Key: "ldap-providers", Label: "LDAP Providers", Icon: "fa-address-book", Visible: vis("ldap-providers")},
			{Key: "channels", Label: "Channels", Icon: "fa-paper-plane", Visible: vis("channels")},
			{Key: "quotas", Label: "Quotas", Icon: "fa-tachometer-alt", Visible: vis("quotas")},
			{Key: "webhooks", Label: "Webhooks", Icon: "fa-plug", Visible: vis("webhooks")},
			{Key: "runbooks", Label: "Runbooks", Icon: "fa-book-open", Visible: vis("runbooks")},
			{Key: "registries", Label: "Registries", Icon: "fa-box", Visible: vis("registries")},
		}},
	}
}

// builtinRoleOptions returns the three built-in system roles for use in
// user create/edit forms when no custom roles are configured.
func builtinRoleOptions() []users.RoleOption {
	return []users.RoleOption{
		{Name: "admin", DisplayName: "Admin", Description: "Full system access", IsSystem: true},
		{Name: "operator", DisplayName: "Operator", Description: "Operational access (create, start, stop)", IsSystem: true},
		{Name: "viewer", DisplayName: "Viewer", Description: "Read-only access", IsSystem: true},
	}
}
