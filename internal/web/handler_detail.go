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
		Architecture: "amd64", // Default, not in basic view
		OS:           "linux", // Default, not in basic view
		Labels:       make(map[string]string),
		InUse:        image.InUse,
	}

	// Convert containers count to list
	if image.Containers > 0 {
		imgData.Containers = make([]string, image.Containers)
	}

	data := images.ImageDetailData{
		PageData: layouts.PageData{
			Title:     imgData.PrimaryTag,
			Active:    "images",
			User:      h.getUserData(r),
			Stats:     h.getStatsData(ctx),
			CSRFToken: GetCSRFTokenFromContext(ctx),
		},
		Image: imgData,
		Tab:   tab,
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

	// Convert UsedBy to container list
	for _, containerName := range volume.UsedBy {
		volData.Containers = append(volData.Containers, volumes.VolumeContainer{
			Name:      containerName,
			State:     "unknown",
			MountPath: volume.Mountpoint,
			Mode:      "rw",
		})
	}

	data := volumes.VolumeDetailData{
		PageData: layouts.PageData{
			Title:     volume.Name,
			Active:    "volumes",
			User:      h.getUserData(r),
			Stats:     h.getStatsData(ctx),
			CSRFToken: GetCSRFTokenFromContext(ctx),
		},
		Volume: volData,
		Tab:    tab,
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
	if netModel, err := h.services.Networks().GetModel(ctx, id); err == nil && netModel != nil {
		for containerID, info := range netModel.Containers {
			name := info.Name
			if name == "" {
				name = shortID(containerID)
			}
			netData.Containers = append(netData.Containers, networks.NetworkContainer{
				ID:          containerID,
				Name:        name,
				State:       "running",
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
				State: "unknown",
			})
		}
	}

	data := networks.NetworkDetailData{
		PageData: layouts.PageData{
			Title:     network.Name,
			Active:    "networks",
			User:      h.getUserData(r),
			Stats:     h.getStatsData(ctx),
			CSRFToken: GetCSRFTokenFromContext(ctx),
		},
		Network: netData,
		Tab:     tab,
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
