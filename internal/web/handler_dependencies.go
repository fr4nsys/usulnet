// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"fmt"
	"net/http"
	"strings"

	depstmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/dependencies"
)

// DependenciesTempl renders the dependency graph page.
func (h *Handler) DependenciesTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Dependency Graph", "dependencies")

	var containers []depstmpl.ContainerDep
	var networks []depstmpl.NetworkDep
	var volumes []depstmpl.VolumeDep
	var images []depstmpl.ImageDep
	var warnings []depstmpl.DepWarning
	stats := depstmpl.DepStats{}

	containerSvc := h.services.Containers()
	networkSvc := h.services.Networks()
	volumeSvc := h.services.Volumes()
	imageSvc := h.services.Images()

	// Build network-to-containers mapping
	networkContainers := make(map[string][]string) // network name -> container names

	if networkSvc != nil {
		if netList, err := networkSvc.List(ctx); err == nil {
			for _, net := range netList {
				nd := depstmpl.NetworkDep{
					ID:         net.ID,
					Name:       net.Name,
					Driver:     net.Driver,
					Subnet:     net.Subnet,
					Scope:      net.Scope,
					Internal:   net.Internal,
					Containers: net.Containers,
				}
				networks = append(networks, nd)
				stats.TotalNetworks++

				networkContainers[net.Name] = net.Containers

				if len(net.Containers) > 1 {
					stats.SharedNetworks++
				}
			}
		}
	}

	// Build volume-to-containers mapping
	volumeContainers := make(map[string][]string) // volume name -> container names

	if volumeSvc != nil {
		if volList, err := volumeSvc.List(ctx); err == nil {
			for _, vol := range volList {
				vd := depstmpl.VolumeDep{
					Name:       vol.Name,
					Driver:     vol.Driver,
					Size:       vol.SizeHuman,
					InUse:      vol.InUse,
					Containers: vol.UsedBy,
				}
				volumes = append(volumes, vd)
				stats.TotalVolumes++

				if vol.InUse {
					volumeContainers[vol.Name] = vol.UsedBy
					if len(vol.UsedBy) > 1 {
						stats.SharedVolumes++
					}
				} else {
					stats.OrphanedVolumes++
					warnings = append(warnings, depstmpl.DepWarning{
						Severity: "info",
						Category: "orphan",
						Title:    "Orphaned volume: " + truncateStr(vol.Name, 30),
						Message:  "This volume is not mounted by any container and could be cleaned up",
						Resource: vol.Name,
					})
				}
			}
		}
	}

	// Build container dependencies
	if containerSvc != nil {
		if containerList, err := containerSvc.List(ctx, nil); err == nil {
			for _, c := range containerList {
				name := c.Name
				if len(name) > 0 && name[0] == '/' {
					name = name[1:]
				}

				// Collect volume names from mounts
				var volumeNames []string
				for _, m := range c.Mounts {
					if m.Type == "volume" {
						volumeNames = append(volumeNames, m.Source)
					}
				}

				// Collect port strings
				var ports []string
				for _, p := range c.Ports {
					ports = append(ports, p.Display)
				}

				cd := depstmpl.ContainerDep{
					ID:       c.ID,
					Name:     name,
					Image:    c.Image,
					State:    c.State,
					Networks: c.Networks,
					Volumes:  volumeNames,
					Ports:    ports,
				}

				containers = append(containers, cd)
				stats.TotalContainers++

				if len(c.Networks) == 0 {
					stats.IsolatedContainers++
				}
			}
		}
	}

	// Compute container dependency relationships (shared network = potential dependency)
	containerIndex := make(map[string]int)
	for i, c := range containers {
		containerIndex[c.Name] = i
	}

	for _, net := range networks {
		if len(net.Containers) > 1 {
			// All containers on same network can communicate
			for i := 0; i < len(net.Containers); i++ {
				for j := i + 1; j < len(net.Containers); j++ {
					nameA := net.Containers[i]
					nameB := net.Containers[j]
					if idxA, ok := containerIndex[nameA]; ok {
						containers[idxA].DependsOn = appendUnique(containers[idxA].DependsOn, nameB)
					}
					if idxB, ok := containerIndex[nameB]; ok {
						containers[idxB].DependedBy = appendUnique(containers[idxB].DependedBy, nameA)
					}
				}
			}
		}
	}

	// Image stats
	if imageSvc != nil {
		if imgList, err := imageSvc.List(ctx); err == nil {
			for _, img := range imgList {
				id := depstmpl.ImageDep{
					ID:         img.ID,
					Tag:        img.PrimaryTag,
					Size:       img.SizeHuman,
					Containers: img.Containers,
				}
				images = append(images, id)
				stats.TotalImages++

				if img.Containers == 0 {
					stats.OrphanedImages++
				}
			}
		}
	}

	// Generate warnings for isolated containers
	if stats.IsolatedContainers > 0 {
		warnings = append([]depstmpl.DepWarning{{
			Severity: "warning",
			Category: "isolation",
			Title:    fmt.Sprintf("%d isolated container(s)", stats.IsolatedContainers),
			Message:  "These containers have no network connections and cannot communicate with other containers",
		}}, warnings...)
	}

	// Generate warnings for orphaned images
	if stats.OrphanedImages > 5 {
		warnings = append(warnings, depstmpl.DepWarning{
			Severity: "info",
			Category: "orphan",
			Title:    fmt.Sprintf("%d unused images", stats.OrphanedImages),
			Message:  "Consider pruning unused images to free disk space",
		})
	}

	// Limit warnings to top 10
	if len(warnings) > 10 {
		warnings = warnings[:10]
	}

	data := depstmpl.DependencyData{
		PageData:   pageData,
		Containers: containers,
		Networks:   networks,
		Volumes:    volumes,
		Images:     images,
		Stats:      stats,
		Warnings:   warnings,
	}

	h.renderTempl(w, r, depstmpl.Dependencies(data))
}

// appendUnique appends a string to a slice only if not already present.
func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

// truncateStr truncates a string to maxLen with ellipsis.
func truncateStr(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}

// cleanContainerName removes leading "/" from container names.
func cleanContainerName(name string) string {
	return strings.TrimPrefix(name, "/")
}
