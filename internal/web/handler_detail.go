// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/web/templates/layouts"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/images"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/networks"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/volumes"
)

// ============================================================================
// Image Detail Handler (Templ)
// ============================================================================

// ImageDetailTempl renders the image detail page using templ
func (h *Handler) ImageDetailTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	tab := r.URL.Query().Get("tab")

	image, err := h.services.Images().Get(ctx, id)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Image Not Found", "The requested image could not be found.")
		return
	}

	// Convert to template data using available fields
	imgData := images.ImageFull{
		ID:           image.ID,
		ShortID:      image.ShortID,
		Tags:         image.Tags,
		PrimaryTag:   image.PrimaryTag,
		Size:         image.Size,
		SizeHuman:    image.SizeHuman,
		Created:      image.Created.Format(time.RFC3339),
		CreatedAgo:   image.CreatedHuman,
		Architecture: h.getHostArch(ctx),
		OS:           h.getHostOS(ctx),
		Labels:       make(map[string]string),
		InUse:        image.InUse,
	}

	// Populate container names that use this image
	if image.Containers > 0 {
		if cSvc := h.services.Containers(); cSvc != nil {
			if containers, err := cSvc.List(ctx, nil); err == nil {
				for _, c := range containers {
					match := c.Image == image.PrimaryTag
					if !match {
						for _, tag := range image.Tags {
							if c.Image == tag {
								match = true
								break
							}
						}
					}
					if match {
						name := c.Name
						if len(name) > 0 && name[0] == '/' {
							name = name[1:]
						}
						imgData.Containers = append(imgData.Containers, name)
					}
				}
			}
		}
		// If no containers found by lookup, show count as placeholder
		if len(imgData.Containers) == 0 {
			imgData.Containers = []string{fmt.Sprintf("(%d containers)", image.Containers)}
		}
	}

	data := images.ImageDetailData{
		PageData: h.prepareTemplPageData(r, imgData.PrimaryTag, "images"),
		Image:    imgData,
		Tab:      tab,
	}

	component := images.ImageDetail(data)
	component.Render(ctx, w)
}

// ============================================================================
// Volume Detail Handler (Templ)
// ============================================================================

// VolumeDetailTempl renders the volume detail page using templ
func (h *Handler) VolumeDetailTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := chi.URLParam(r, "name")
	tab := r.URL.Query().Get("tab")

	volume, err := h.services.Volumes().Get(ctx, name)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Volume Not Found", "The requested volume could not be found.")
		return
	}

	// Convert to template data
	volData := volumes.VolumeFull{
		Name:       volume.Name,
		Driver:     volume.Driver,
		Mountpoint: volume.Mountpoint,
		Scope:      volume.Scope,
		Created:    volume.Created.Format(time.RFC3339),
		CreatedAgo: volume.CreatedHuman,
		Labels:     volume.Labels,
		Options:    make(map[string]string),
		InUse:      volume.InUse,
		Size:       volume.Size,
		SizeHuman:  volume.SizeHuman,
	}

	// Convert UsedBy to container list with real state lookup.
	// volume.UsedBy contains container names, not IDs. List all containers
	// once and match by name rather than calling Get(id) which expects an ID.
	containerSvc := h.services.Containers()
	var allContainers []ContainerView
	if containerSvc != nil {
		allContainers, _ = containerSvc.List(ctx, nil)
	}
	containerStateByName := make(map[string]string, len(allContainers))
	for _, c := range allContainers {
		cName := c.Name
		if len(cName) > 0 && cName[0] == '/' {
			cName = cName[1:]
		}
		containerStateByName[cName] = c.State
	}
	for _, containerName := range volume.UsedBy {
		state := "attached"
		if s, ok := containerStateByName[containerName]; ok {
			state = s
		}
		volData.Containers = append(volData.Containers, volumes.VolumeContainer{
			Name:      containerName,
			State:     state,
			MountPath: volume.Mountpoint,
			Mode:      "rw",
		})
	}

	data := volumes.VolumeDetailData{
		PageData: h.prepareTemplPageData(r, volume.Name, "volumes"),
		Volume:   volData,
		Tab:      tab,
	}

	component := volumes.VolumeDetail(data)
	component.Render(ctx, w)
}

// ============================================================================
// Network Detail Handler (Templ)
// ============================================================================

// NetworkDetailTempl renders the network detail page using templ
func (h *Handler) NetworkDetailTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	tab := r.URL.Query().Get("tab")

	network, err := h.services.Networks().Get(ctx, id)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Network Not Found", "The requested network could not be found.")
		return
	}

	// Convert to template data
	netData := networks.NetworkFull{
		ID:             network.ID,
		ShortID:        network.ShortID,
		Name:           network.Name,
		Driver:         network.Driver,
		Scope:          network.Scope,
		Internal:       network.Internal,
		Attachable:     network.Attachable,
		Created:        network.Created.Format(time.RFC3339),
		CreatedAgo:     network.CreatedHuman,
		Options:        make(map[string]string),
		Labels:         make(map[string]string),
		ContainerCount: network.ContainerCount,
	}

	// Setup IPAM config from basic fields
	if network.Subnet != "" || network.Gateway != "" {
		netData.IPAM = networks.IPAMConfig{
			Driver: "default",
			Config: []networks.IPAMPool{
				{
					Subnet:  network.Subnet,
					Gateway: network.Gateway,
				},
			},
		}
	}

	// Convert container data from network view
	// network.Containers has names but we need full data from the model
	// Get the actual network to access container map with IDs and IPs
	containerSvc := h.services.Containers()
	if netModel, err := h.services.Networks().GetModel(ctx, id); err == nil && netModel != nil {
		for containerID, info := range netModel.Containers {
			name := info.Name
			if name == "" {
				name = shortID(containerID)
			}
			state := "connected"
			if containerSvc != nil {
				if c, cErr := containerSvc.Get(ctx, containerID); cErr == nil && c != nil {
					state = c.State
				}
			}
			netData.Containers = append(netData.Containers, networks.NetworkContainer{
				ID:          containerID,
				Name:        name,
				State:       state,
				IPv4Address: info.IPv4Address,
				IPv6Address: info.IPv6Address,
				MacAddress:  info.MacAddress,
			})
		}
	} else {
		// Fallback to simple name list
		for _, containerName := range network.Containers {
			netData.Containers = append(netData.Containers, networks.NetworkContainer{
				Name:  containerName,
				State: "connected",
			})
		}
	}

	data := networks.NetworkDetailData{
		PageData: h.prepareTemplPageData(r, network.Name, "networks"),
		Network:  netData,
		Tab:      tab,
	}

	component := networks.NetworkDetail(data)
	component.Render(ctx, w)
}

// ============================================================================
// User and Stats Data Helpers
// ============================================================================

// getUserData extracts user data from the request context
func (h *Handler) getUserData(r *http.Request) *layouts.UserData {
	// Get user from session/context (set by AuthRequired middleware)
	user := GetUserFromContext(r.Context())
	if user == nil {
		// Fallback for unauthenticated requests (shouldn't happen in protected routes)
		return nil
	}
	return &layouts.UserData{
		ID:       user.ID,
		Username: user.Username,
		Role:     user.Role,
		RoleID:   user.RoleID,
		Email:    user.Email,
	}
}

// getStatsData gets system stats for the sidebar
func (h *Handler) getStatsData(ctx context.Context) *layouts.StatsData {
	// Try to get stats from services
	stats := &layouts.StatsData{
		ContainersTotal:   0,
		ContainersRunning: 0,
		SecurityIssues:    0,
		UpdatesAvailable:  0,
	}

	// Get container counts
	if containers, err := h.services.Containers().List(ctx, nil); err == nil {
		stats.ContainersTotal = len(containers)
		for _, c := range containers {
			if c.State == "running" {
				stats.ContainersRunning++
			}
		}
	}

	return stats
}

// ============================================================================
// Formatting Helper Functions
// ============================================================================

// formatBytes formats bytes to human readable string
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), []string{"KB", "MB", "GB", "TB"}[exp])
}

// truncateID returns the first 12 characters of an ID
func truncateID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// getHostArch returns the Docker host architecture (e.g., "amd64", "arm64")
func (h *Handler) getHostArch(ctx context.Context) string {
	if hostSvc := h.services.Hosts(); hostSvc != nil {
		if info, err := hostSvc.GetDockerInfo(ctx); err == nil && info != nil && info.Architecture != "" {
			return info.Architecture
		}
	}
	return "amd64"
}

// getHostOS returns the Docker host OS (e.g., "linux")
func (h *Handler) getHostOS(ctx context.Context) string {
	if hostSvc := h.services.Hosts(); hostSvc != nil {
		if info, err := hostSvc.GetDockerInfo(ctx); err == nil && info != nil && info.OSType != "" {
			return info.OSType
		}
	}
	return "linux"
}
