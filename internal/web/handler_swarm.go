// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	swarmtpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/swarm"
)

// SwarmClusterTempl renders the Swarm cluster page.
func (h *Handler) SwarmClusterTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Swarm Cluster", "swarm")

	hostID := h.resolveHostID(r)

	data := swarmtpl.ClusterData{
		PageData: pageData,
		HostID:   hostID.String(),
	}

	if h.swarmService == nil {
		h.renderTempl(w, r, swarmtpl.Cluster(data))
		return
	}

	info, err := h.swarmService.GetClusterInfo(ctx, hostID)
	if err != nil {
		h.logger.Warn("Failed to get Swarm info", "error", err)
		h.renderTempl(w, r, swarmtpl.Cluster(data))
		return
	}

	data.Active = info.Active
	data.ClusterID = info.ClusterID
	data.ManagerNodes = info.ManagerNodes
	data.WorkerNodes = info.WorkerNodes
	data.TotalNodes = info.TotalNodes
	data.ServiceCount = info.ServiceCount
	data.JoinTokenWorker = info.JoinTokenWorker
	data.JoinTokenManager = info.JoinTokenManager
	data.ManagerAddr = info.ManagerAddr

	for _, n := range info.Nodes {
		data.Nodes = append(data.Nodes, swarmtpl.NodeItem{
			ID:            n.ID,
			Hostname:      n.Hostname,
			Role:          n.Role,
			Status:        n.Status,
			Availability:  n.Availability,
			EngineVersion: n.EngineVersion,
			Address:       n.Address,
			IsLeader:      n.IsLeader,
			NCPU:          n.NCPU,
			MemoryMB:      n.MemoryBytes / (1024 * 1024),
		})
	}

	// Get services
	services, svcErr := h.swarmService.ListServices(ctx, hostID)
	if svcErr == nil {
		for _, svc := range services {
			portsStr := ""
			for i, p := range svc.Ports {
				if i > 0 {
					portsStr += ", "
				}
				portsStr += fmt.Sprintf("%d:%d/%s", p.PublishedPort, p.TargetPort, p.Protocol)
			}
			data.Services = append(data.Services, swarmtpl.ServiceItem{
				ID:              svc.ID,
				Name:            svc.Name,
				Image:           svc.Image,
				Mode:            svc.Mode,
				ReplicasDesired: svc.ReplicasDesired,
				ReplicasRunning: svc.ReplicasRunning,
				Ports:           portsStr,
			})
		}
	}

	h.renderTempl(w, r, swarmtpl.Cluster(data))
}

// SwarmInitTempl handles POST /swarm/init - initializes Docker Swarm.
func (h *Handler) SwarmInitTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := h.resolveHostID(r)

	if h.swarmService == nil {
		h.setFlash(w, r, "error", "Swarm service not available")
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	input := &models.SwarmInitInput{
		AdvertiseAddr: r.FormValue("advertise_addr"),
		ListenAddr:    r.FormValue("listen_addr"),
	}

	_, err := h.swarmService.InitSwarm(ctx, hostID, input)
	if err != nil {
		h.setFlash(w, r, "error", "Failed to initialize Swarm: "+err.Error())
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	h.setFlash(w, r, "success", "Swarm cluster initialized successfully")
	http.Redirect(w, r, "/swarm", http.StatusSeeOther)
}

// SwarmLeaveTempl handles POST /swarm/leave - leaves the Swarm cluster.
func (h *Handler) SwarmLeaveTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := h.resolveHostID(r)

	if h.swarmService == nil {
		h.setFlash(w, r, "error", "Swarm service not available")
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	if err := h.swarmService.LeaveSwarm(ctx, hostID, true); err != nil {
		h.setFlash(w, r, "error", "Failed to leave Swarm: "+err.Error())
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	h.setFlash(w, r, "success", "Left Swarm cluster successfully")
	http.Redirect(w, r, "/swarm", http.StatusSeeOther)
}

// SwarmNodeRemoveTempl handles DELETE /swarm/nodes/{nodeID}.
func (h *Handler) SwarmNodeRemoveTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := h.resolveHostID(r)
	nodeID := chi.URLParam(r, "nodeID")

	if h.swarmService == nil {
		http.Error(w, "Swarm service not available", http.StatusServiceUnavailable)
		return
	}

	if err := h.swarmService.RemoveNode(ctx, hostID, nodeID, true); err != nil {
		h.setFlash(w, r, "error", "Failed to remove node: "+err.Error())
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	h.setFlash(w, r, "success", "Node removed from cluster")
	http.Redirect(w, r, "/swarm", http.StatusSeeOther)
}

// SwarmServiceCreateFormTempl renders the create service form.
func (h *Handler) SwarmServiceCreateFormTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Create Swarm Service", "swarm")
	data := swarmtpl.ServiceCreateData{
		PageData: pageData,
	}
	h.renderTempl(w, r, swarmtpl.ServiceCreateForm(data))
}

// SwarmServiceCreateTempl handles POST /swarm/services/create.
func (h *Handler) SwarmServiceCreateTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := h.resolveHostID(r)

	if h.swarmService == nil {
		h.setFlash(w, r, "error", "Swarm service not available")
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		http.Redirect(w, r, "/swarm/services/new", http.StatusSeeOther)
		return
	}

	replicas, _ := strconv.Atoi(r.FormValue("replicas"))
	if replicas < 1 {
		replicas = 1
	}

	input := &models.CreateSwarmServiceInput{
		Name:     r.FormValue("name"),
		Image:    r.FormValue("image"),
		Replicas: replicas,
	}

	// Parse ports
	publishedPort, _ := strconv.ParseUint(r.FormValue("published_port"), 10, 32)
	targetPort, _ := strconv.ParseUint(r.FormValue("target_port"), 10, 32)
	if publishedPort > 0 && targetPort > 0 {
		input.Ports = []models.SwarmPort{{
			Protocol:      "tcp",
			TargetPort:    uint32(targetPort),
			PublishedPort: uint32(publishedPort),
			PublishMode:   "ingress",
		}}
	}

	// Parse env
	envStr := strings.TrimSpace(r.FormValue("env"))
	if envStr != "" {
		for _, line := range strings.Split(envStr, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && strings.Contains(line, "=") {
				input.Env = append(input.Env, line)
			}
		}
	}

	_, err := h.swarmService.CreateService(ctx, hostID, input)
	if err != nil {
		h.setFlash(w, r, "error", "Failed to create service: "+err.Error())
		http.Redirect(w, r, "/swarm/services/new", http.StatusSeeOther)
		return
	}

	h.setFlash(w, r, "success", fmt.Sprintf("Service '%s' created with %d replicas", input.Name, replicas))
	http.Redirect(w, r, "/swarm", http.StatusSeeOther)
}

// SwarmServiceRemoveTempl handles DELETE /swarm/services/{serviceID}.
func (h *Handler) SwarmServiceRemoveTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := h.resolveHostID(r)
	serviceID := chi.URLParam(r, "serviceID")

	if h.swarmService == nil {
		http.Error(w, "Swarm service not available", http.StatusServiceUnavailable)
		return
	}

	if err := h.swarmService.RemoveService(ctx, hostID, serviceID); err != nil {
		h.setFlash(w, r, "error", "Failed to remove service: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Service removed")
	}

	http.Redirect(w, r, "/swarm", http.StatusSeeOther)
}

// SwarmServiceScaleTempl handles POST /swarm/services/{serviceID}/scale.
func (h *Handler) SwarmServiceScaleTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := h.resolveHostID(r)
	serviceID := chi.URLParam(r, "serviceID")

	if h.swarmService == nil {
		http.Error(w, "Swarm service not available", http.StatusServiceUnavailable)
		return
	}

	replicas, _ := strconv.Atoi(r.FormValue("replicas"))
	if replicas < 0 {
		replicas = 0
	}

	if err := h.swarmService.ScaleService(ctx, hostID, serviceID, replicas); err != nil {
		h.setFlash(w, r, "error", "Failed to scale service: "+err.Error())
	} else {
		h.setFlash(w, r, "success", fmt.Sprintf("Service scaled to %d replicas", replicas))
	}

	http.Redirect(w, r, "/swarm", http.StatusSeeOther)
}

// SwarmConvertContainerTempl handles POST /swarm/convert - converts container to HA service.
func (h *Handler) SwarmConvertContainerTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := h.resolveHostID(r)

	if h.swarmService == nil {
		h.setFlash(w, r, "error", "Swarm service not available")
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	replicas, _ := strconv.Atoi(r.FormValue("replicas"))
	if replicas < 1 {
		replicas = 2
	}

	input := &models.ConvertToServiceInput{
		ContainerID: r.FormValue("container_id"),
		Replicas:    replicas,
		ServiceName: r.FormValue("service_name"),
	}

	_, err := h.swarmService.ConvertContainerToService(ctx, hostID, input)
	if err != nil {
		h.setFlash(w, r, "error", "Failed to convert container: "+err.Error())
		http.Redirect(w, r, "/containers", http.StatusSeeOther)
		return
	}

	h.setFlash(w, r, "success", fmt.Sprintf("Container converted to Swarm service with %d replicas", replicas))
	http.Redirect(w, r, "/swarm", http.StatusSeeOther)
}

// resolveHostID gets the current active host UUID from context or query parameter.
func (h *Handler) resolveHostID(r *http.Request) uuid.UUID {
	// First check explicit query parameter
	if hostIDStr := r.URL.Query().Get("host_id"); hostIDStr != "" {
		if id, err := uuid.Parse(hostIDStr); err == nil {
			return id
		}
	}

	// Check session-based active host (set by host selector in the UI)
	if activeHostID := GetActiveHostIDFromContext(r.Context()); activeHostID != "" {
		if id, err := uuid.Parse(activeHostID); err == nil {
			return id
		}
	}

	// Default to local host sentinel
	return uuid.MustParse("00000000-0000-0000-0000-000000000001")
}
