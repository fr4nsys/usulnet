// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"fmt"
	"strings"

	"github.com/fr4nsys/usulnet/internal/web/templates/layouts"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/containers"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/images"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/networks"
	securitytmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/security"
	updatestmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/updates"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/volumes"
)

// ============================================================================
// Layout Adapters
// ============================================================================

// ToTemplPageData converts web.PageData to layouts.PageData
func ToTemplPageData(p *PageData) layouts.PageData {
	if p == nil {
		return layouts.PageData{}
	}

	data := layouts.PageData{
		Title:              p.Title,
		Description:        p.Description,
		Active:             p.Active,
		CSRFToken:          p.CSRFToken,
		Theme:              p.Theme,
		Version:            p.Version,
		NotificationsCount: p.NotificationsCount,
	}

	// Convert user
	if p.User != nil {
		data.User = &layouts.UserData{
			ID:       p.User.ID,
			Username: p.User.Username,
			Role:     p.User.Role,
			RoleID:   p.User.RoleID,
			Email:    p.User.Email,
		}
	}

	// Convert stats
	if p.Stats != nil {
		data.Stats = &layouts.StatsData{
			ContainersRunning: p.Stats.ContainersRunning,
			ContainersTotal:   p.Stats.ContainersTotal,
			ImagesCount:       p.Stats.ImagesCount,
			VolumesCount:      p.Stats.VolumesCount,
			NetworksCount:     p.Stats.NetworksCount,
			SecurityIssues:    p.Stats.SecurityIssues,
			UpdatesAvailable:  p.Stats.UpdatesAvailable,
		}
	}

	// Convert flash
	if p.Flash != nil {
		data.Flash = &layouts.FlashData{
			Type:    p.Flash.Type,
			Message: p.Flash.Message,
		}
	}

	return data
}

// ============================================================================
// Login Page Adapter
// ============================================================================

// ToTemplLoginData converts PageData to pages.LoginData
func ToTemplLoginData(p *PageData, error, username, returnURL string, ldapEnabled, oauthEnabled bool, oauthProvider string) pages.LoginData {
	return pages.LoginData{
		Error:         error,
		Username:      username,
		CSRFToken:     p.CSRFToken,
		ReturnURL:     returnURL,
		LDAPEnabled:   ldapEnabled,
		OAuthEnabled:  oauthEnabled,
		OAuthProvider: oauthProvider,
		Version:       p.Version,
	}
}

// ============================================================================
// Dashboard Adapters
// ============================================================================

// ToTemplDashboardData converts data for dashboard page
func ToTemplDashboardData(p *PageData, containersList []ContainerView, eventsList []EventView, sysInfo *SystemInfoView) pages.DashboardData {
	data := pages.DashboardData{
		PageData: ToTemplPageData(p),
	}

	// Stats from global stats
	if p.Stats != nil {
		data.ContainersTotal = p.Stats.ContainersTotal
		data.ContainersRunning = p.Stats.ContainersRunning
		data.ContainersStopped = p.Stats.ContainersStopped
		data.ContainersPaused = p.Stats.ContainersPaused
		data.ImagesCount = p.Stats.ImagesCount
		data.VolumesCount = p.Stats.VolumesCount
		data.NetworksCount = p.Stats.NetworksCount
		data.SecurityScore = p.Stats.SecurityScore
		data.SecurityGrade = p.Stats.SecurityGrade
		data.SecurityIssues = p.Stats.SecurityIssues
		data.UpdatesAvailable = p.Stats.UpdatesAvailable
	}

	// Recent containers (limit to 5)
	for i, c := range containersList {
		if i >= 5 {
			break
		}
		data.RecentContainers = append(data.RecentContainers, toTemplContainerSummary(c))
	}

	// Recent events (limit to 10)
	for i, e := range eventsList {
		if i >= 10 {
			break
		}
		data.RecentEvents = append(data.RecentEvents, toTemplEventSummary(e))
	}

	// System info
	if sysInfo != nil {
		data.SystemInfo = &pages.SystemInfo{
			DockerVersion: sysInfo.DockerVersion,
			APIVersion:    sysInfo.APIVersion,
			OS:            sysInfo.OS,
			Arch:          sysInfo.Arch,
			CPUs:          sysInfo.CPUs,
			Memory:        sysInfo.MemoryHuman,
			Hostname:      sysInfo.Hostname,
		}
	}

	return data
}

func toTemplContainerSummary(c ContainerView) pages.ContainerSummary {
	portsStr := ""
	if len(c.Ports) > 0 {
		portsStr = c.Ports[0].Display
	}

	return pages.ContainerSummary{
		ID:        c.ID,
		Name:      c.Name,
		Image:     c.Image,
		State:     c.State,
		Status:    c.Status,
		CreatedAt: c.Created.Format("2006-01-02 15:04"),
		Ports:     portsStr,
	}
}

func toTemplEventSummary(e EventView) pages.EventSummary {
	return pages.EventSummary{
		Type:    e.Type,
		Action:  e.Action,
		Actor:   e.ActorName,
		Time:    e.Timestamp.Format("15:04:05"),
		TimeAgo: e.TimeHuman,
	}
}

// ============================================================================
// Container Adapters
// ============================================================================

// ToTemplContainersListData converts data for containers list page
func ToTemplContainersListData(p *PageData, containersList []ContainerView) containers.ContainersListData {
	data := containers.ContainersListData{
		PageData: ToTemplPageData(p),
		Filters: containers.ContainerFilters{
			Search: getFilterValue(p.Filters, "search"),
			State:  getFilterValue(p.Filters, "state"),
			Sort:   p.SortBy,
			Dir:    p.SortOrder,
		},
	}

	// Convert pagination
	if p.Pagination != nil {
		data.Pagination = containers.PaginationData{
			CurrentPage: p.Pagination.CurrentPage,
			TotalPages:  p.Pagination.TotalPages,
			TotalItems:  int(p.Pagination.TotalItems),
			PerPage:     p.Pagination.ItemsPerPage,
		}
	}

	// Convert containers
	for _, c := range containersList {
		data.Containers = append(data.Containers, toTemplContainer(c))
	}

	return data
}

// ToTemplContainerDetailData converts data for container detail page
func ToTemplContainerDetailData(p *PageData, c *ContainerView, tab string) containers.ContainerDetailData {
	data := containers.ContainerDetailData{
		PageData: ToTemplPageData(p),
		Tab:      tab,
	}

	if c != nil {
		data.Container = toTemplContainerFull(*c)
	}

	return data
}

// ToTemplContainerLogsData converts data for container logs page
func ToTemplContainerLogsData(p *PageData, c *ContainerView, tail int, since string, follow bool) containers.ContainerLogsData {
	data := containers.ContainerLogsData{
		PageData: ToTemplPageData(p),
		Tail:     tail,
		Since:    since,
		Follow:   follow,
	}

	if c != nil {
		data.ContainerID = c.ID
		data.Name = c.Name
		data.State = c.State
	}

	return data
}

// ToTemplContainerTerminalData converts data for container terminal page
func ToTemplContainerTerminalData(p *PageData, c *ContainerView, shell string) containers.ContainerTerminalData {
	data := containers.ContainerTerminalData{
		PageData: ToTemplPageData(p),
		Shell:    shell,
	}

	if shell == "" {
		data.Shell = "/bin/sh"
	}

	if c != nil {
		data.ContainerID = c.ID
		data.Name = c.Name
		data.State = c.State
	}

	return data
}

// ToTemplContainerStatsData converts data for container stats page
func ToTemplContainerStatsData(p *PageData, c *ContainerView) containers.ContainerStatsData {
	data := containers.ContainerStatsData{
		PageData: ToTemplPageData(p),
	}

	if c != nil {
		data.ContainerID = c.ID
		data.Name = c.Name
		data.State = c.State
		data.Image = c.Image
	}

	return data
}

// ToTemplContainerInspectData converts data for container inspect page
func ToTemplContainerInspectData(p *PageData, c *ContainerView, inspectJSON string) containers.ContainerInspectData {
	data := containers.ContainerInspectData{
		PageData:    ToTemplPageData(p),
		InspectJSON: inspectJSON,
	}

	if c != nil {
		data.ContainerID = c.ID
		data.Name = c.Name
		data.State = c.State
		data.Image = c.Image
	}

	return data
}

// ToTemplContainerFilesData converts data for container file browser page
func ToTemplContainerFilesData(p *PageData, c *ContainerView, path string) containers.ContainerFilesData {
	data := containers.ContainerFilesData{
		PageData:    ToTemplPageData(p),
		CurrentPath: path,
	}

	if c != nil {
		data.ContainerID = c.ID
		data.Name = c.Name
		data.State = c.State
		data.Image = c.Image
		data.HostID = c.HostID
	}

	return data
}

func toTemplContainer(c ContainerView) containers.Container {
	container := containers.Container{
		ID:            c.ID,
		Name:          c.Name,
		Image:         c.Image,
		ImageID:       c.ShortID,
		State:         c.State,
		Status:        c.Status,
		Created:       c.Created.Format("2006-01-02 15:04"),
		CreatedAgo:    c.CreatedHuman,
		Networks:      c.Networks,
		Mounts:        len(c.Mounts),
		Labels:        c.Labels,
		SecurityScore: c.SecurityScore,
		HasUpdates:    false, // TODO: Get from updates service
	}

	// Convert ports
	for _, p := range c.Ports {
		container.Ports = append(container.Ports, containers.PortMapping{
			Internal: p.ContainerPort,
			External: p.HostPort,
			Protocol: p.Protocol,
			IP:       p.HostIP,
		})
	}

	return container
}

func toTemplContainerFull(c ContainerView) containers.ContainerFull {
	full := containers.ContainerFull{
		ID:            c.ID,
		Name:          c.Name,
		Image:         c.Image,
		ImageID:       c.ShortID,
		State:         c.State,
		Status:        c.Status,
		Created:       c.Created.Format("2006-01-02 15:04:05"),
		CreatedAgo:    c.CreatedHuman,
		CPUShares:     0,
		Memory:        c.MemoryLimit,
		CPUs:          c.CPUPercent,
		Hostname:      c.Name, // Default
		SecurityScore: c.SecurityScore,
		SecurityGrade: c.SecurityGrade,
		Labels:        c.Labels,
	}

	// Convert ports
	for _, p := range c.Ports {
		full.Ports = append(full.Ports, containers.PortMapping{
			Internal: p.ContainerPort,
			External: p.HostPort,
			Protocol: p.Protocol,
			IP:       p.HostIP,
		})
	}

	// Convert mounts
	for _, m := range c.Mounts {
		full.Mounts = append(full.Mounts, containers.MountInfo{
			Type:        m.Type,
			Source:      m.Source,
			Destination: m.Destination,
			Mode:        m.Mode,
			RW:          m.RW,
		})
	}

	// Convert networks with full details
	for _, nd := range c.NetworkDetails {
		full.Networks = append(full.Networks, containers.NetworkInfo{
			Name:       nd.NetworkName,
			ID:         nd.NetworkID,
			IPAddress:  nd.IPAddress,
			Gateway:    nd.Gateway,
			MacAddress: nd.MacAddress,
			Aliases:    nd.Aliases,
		})
	}

	return full
}

// ToTemplContainerSettingsData converts data for container settings page
func ToTemplContainerSettingsData(p *PageData, c *ContainerView, networks []string, details *ContainerSettingsDetails) containers.ContainerSettingsData {
	data := containers.ContainerSettingsData{
		PageData: ToTemplPageData(p),
		Networks: networks,
	}

	if c != nil {
		info := containers.ContainerSettingsInfo{
			ID:    c.ID,
			Name:  c.Name,
			Image: c.Image,
			State: c.State,
		}

		// Parse image and tag
		if idx := strings.LastIndex(c.Image, ":"); idx > 0 && idx < len(c.Image)-1 {
			// Make sure the colon is not part of a registry URL
			if slashIdx := strings.LastIndex(c.Image, "/"); slashIdx < idx {
				info.Image = c.Image[:idx]
				info.Tag = c.Image[idx+1:]
			}
		}
		if info.Tag == "" {
			info.Tag = "latest"
		}

		// Environment variables
		for _, e := range c.Env {
			info.EnvVars = append(info.EnvVars, containers.EnvSettingInfo{
				Key:   e.Key,
				Value: e.Value,
			})
		}

		// Ports
		for _, p := range c.Ports {
			info.Ports = append(info.Ports, containers.PortSettingInfo{
				HostPort:      intToStr(p.HostPort),
				ContainerPort: intToStr(p.ContainerPort),
				Protocol:      p.Protocol,
			})
		}

		// Mounts
		for _, m := range c.Mounts {
			mode := "rw"
			if m.Mode != "" {
				mode = m.Mode
			}
			info.Volumes = append(info.Volumes, containers.VolumeSettingInfo{
				HostPath:      m.Source,
				ContainerPath: m.Destination,
				Mode:          mode,
			})
		}

		// Command
		info.Command = c.Command

		// Restart policy
		info.RestartPolicy = c.RestartPolicy

		// Memory
		info.MemoryLimit = c.MemoryLimit

		// Labels for WebUI and Icon
		if c.Labels != nil {
			info.IconURL = c.Labels["usulnet.icon"]
			info.WebUIProtocol = c.Labels["usulnet.webui.protocol"]
			info.WebUIHost = c.Labels["usulnet.webui.host"]
			info.WebUIPort = c.Labels["usulnet.webui.port"]
			info.WebUIPath = c.Labels["usulnet.webui.path"]
		}

		// Fill from Docker inspect details if available (always more accurate than ContainerView)
		if details != nil {
			info.NetworkMode = details.NetworkMode
			info.Hostname = details.Hostname
			info.Privileged = details.Privileged
			info.CPUShares = details.CPUShares
			info.NanoCPUs = details.NanoCPUs
			info.CapAdd = details.CapAdd
			info.CapDrop = details.CapDrop
			info.Devices = details.Devices
			if details.MemoryLimit > 0 {
				info.MemoryLimit = details.MemoryLimit
			}
			if details.RestartPolicy != "" {
				info.RestartPolicy = details.RestartPolicy
			}
			// Use port bindings from Docker inspect as fallback when ContainerView has no ports
			if len(info.Ports) == 0 && len(details.Ports) > 0 {
				info.Ports = details.Ports
			}
		}

		data.Container = info
	}

	return data
}

// ContainerSettingsDetails holds extra details from Docker inspect needed for settings
type ContainerSettingsDetails struct {
	NetworkMode   string
	Hostname      string
	Privileged    bool
	CPUShares     int64
	NanoCPUs      int64
	MemoryLimit   int64
	RestartPolicy string
	CapAdd        []string
	CapDrop       []string
	Devices       []containers.DeviceSettingInfo
	Ports         []containers.PortSettingInfo // Port bindings from Docker inspect
}

func intToStr(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%d", n)
}

// ============================================================================
// Helper Functions
// ============================================================================

func getFilterValue(filters map[string]string, key string) string {
	if filters == nil {
		return ""
	}
	return filters[key]
}

// ============================================================================
// Additional View Types for Dashboard
// ============================================================================

// SystemInfoView contains Docker system information
type SystemInfoView struct {
	DockerVersion string
	APIVersion    string
	OS            string
	Arch          string
	CPUs          int
	Memory        int64
	MemoryHuman   string
	Hostname      string
}

// ============================================================================
// Image Adapters
// ============================================================================

// ToTemplImagesListData converts data for images list page
func ToTemplImagesListData(p *PageData, imagesList []ImageView, totalSize int64, filters images.ImageFilters) images.ImagesListData {
	data := images.ImagesListData{
		PageData:  ToTemplPageData(p),
		TotalSize: formatBytes(totalSize),
		Filters:   filters,
	}

	// Convert pagination
	if p.Pagination != nil {
		data.Pagination = images.PaginationData{
			CurrentPage: p.Pagination.CurrentPage,
			TotalPages:  p.Pagination.TotalPages,
			TotalItems:  int(p.Pagination.TotalItems),
			PerPage:     p.Pagination.ItemsPerPage,
		}
	}

	// Convert images
	for _, img := range imagesList {
		data.Images = append(data.Images, toTemplImage(img))
	}

	return data
}

func toTemplImage(img ImageView) images.Image {
	return images.Image{
		ID:           img.ID,
		ShortID:      img.ShortID,
		Tags:         img.Tags,
		PrimaryTag:   img.PrimaryTag,
		Size:         img.Size,
		SizeHuman:    img.SizeHuman,
		Created:      img.Created.Format("2006-01-02 15:04"),
		CreatedAgo:   img.CreatedHuman,
		InUse:        img.InUse,
		Containers:   img.Containers,
		Architecture: "", // Not available in ImageView
		OS:           "", // Not available in ImageView
	}
}

// ============================================================================
// Volume Adapters
// ============================================================================

// ToTemplVolumesListData converts data for volumes list page
func ToTemplVolumesListData(p *PageData, volumesList []VolumeView, totalSize int64, filters volumes.VolumeFilters) volumes.VolumesListData {
	data := volumes.VolumesListData{
		PageData:  ToTemplPageData(p),
		TotalSize: formatBytes(totalSize),
		Filters:   filters,
	}

	// Convert pagination
	if p.Pagination != nil {
		data.Pagination = volumes.PaginationData{
			CurrentPage: p.Pagination.CurrentPage,
			TotalPages:  p.Pagination.TotalPages,
			TotalItems:  int(p.Pagination.TotalItems),
			PerPage:     p.Pagination.ItemsPerPage,
		}
	}

	// Convert volumes
	for _, vol := range volumesList {
		data.Volumes = append(data.Volumes, toTemplVolume(vol))
	}

	return data
}

func toTemplVolume(vol VolumeView) volumes.Volume {
	return volumes.Volume{
		Name:       vol.Name,
		Driver:     vol.Driver,
		Mountpoint: vol.Mountpoint,
		Scope:      vol.Scope,
		Labels:     vol.Labels,
		Created:    vol.Created.Format("2006-01-02 15:04"),
		CreatedAgo: vol.CreatedHuman,
		InUse:      vol.InUse,
		Size:       vol.Size,
		SizeHuman:  vol.SizeHuman,
		Containers: len(vol.UsedBy),
	}
}

// ============================================================================
// Network Adapters
// ============================================================================

// ToTemplNetworksListData converts data for networks list page
func ToTemplNetworksListData(p *PageData, networksList []NetworkView, filters networks.NetworkFilters) networks.NetworksListData {
	data := networks.NetworksListData{
		PageData: ToTemplPageData(p),
		Filters:  filters,
	}

	// Convert pagination
	if p.Pagination != nil {
		data.Pagination = networks.PaginationData{
			CurrentPage: p.Pagination.CurrentPage,
			TotalPages:  p.Pagination.TotalPages,
			TotalItems:  int(p.Pagination.TotalItems),
			PerPage:     p.Pagination.ItemsPerPage,
		}
	}

	// Convert networks
	for _, net := range networksList {
		data.Networks = append(data.Networks, toTemplNetwork(net))
	}

	return data
}

func toTemplNetwork(net NetworkView) networks.Network {
	return networks.Network{
		ID:             net.ID,
		ShortID:        net.ShortID,
		Name:           net.Name,
		Driver:         net.Driver,
		Scope:          net.Scope,
		Internal:       net.Internal,
		Attachable:     net.Attachable,
		Subnet:         net.Subnet,
		Gateway:        net.Gateway,
		Created:        net.Created.Format("2006-01-02 15:04"),
		CreatedAgo:     net.CreatedHuman,
		ContainerCount: net.ContainerCount,
		Containers:     net.Containers,
	}
}

// ============================================================================
// Security Page Adapters
// ============================================================================

// ToTemplSecurityListData converts SecurityOverviewData and containers to template data.
func ToTemplSecurityListData(p *PageData, overview *SecurityOverviewData, containers []ContainerSecurityView, scans []SecurityScanView) securitytmpl.SecurityData {
	data := securitytmpl.SecurityData{
		PageData: ToTemplPageData(p),
	}

	if overview != nil {
		data.TrivyAvailable = overview.TrivyAvailable
		data.Overview = securitytmpl.SecurityOverview{
			TotalContainers: overview.TotalScanned,
			GradeA:          overview.GradeA,
			GradeB:          overview.GradeB,
			GradeC:          overview.GradeC,
			GradeD:          overview.GradeD,
			GradeF:          overview.GradeF,
			CriticalIssues:  overview.CriticalCount,
			HighIssues:      overview.HighCount,
			MediumIssues:    overview.MediumCount,
			LowIssues:       overview.LowCount,
			AverageScore:    int(overview.AverageScore),
		}
	}

	// Convert containers to ContainerSecurity list (includes all containers with scan status)
	data.Containers = make([]securitytmpl.ContainerSecurity, 0, len(containers))
	for _, c := range containers {
		data.Containers = append(data.Containers, securitytmpl.ContainerSecurity{
			ID:          c.ID,
			Name:        c.Name,
			Image:       c.Image,
			State:       c.State,
			HasScan:     c.HasScan,
			Score:       c.Score,
			Grade:       c.Grade,
			Issues:      c.IssueCount,
			LastScanned: c.LastScanned,
		})
	}

	// Recent scans (only scanned containers)
	data.RecentScans = make([]securitytmpl.ScanResult, 0, len(scans))
	for _, s := range scans {
		data.RecentScans = append(data.RecentScans, securitytmpl.ScanResult{
			ContainerName: s.ContainerName,
			Score:         s.Score,
			Grade:         s.Grade,
			ScannedAt:     s.ScannedHuman,
		})
	}

	return data
}

// ToTemplSecurityContainerData converts scan data for a single container.
func ToTemplSecurityContainerData(p *PageData, scan *SecurityScanView, issues []IssueView) securitytmpl.ContainerSecurityData {
	data := securitytmpl.ContainerSecurityData{
		PageData: ToTemplPageData(p),
	}

	if scan != nil {
		data.Container = securitytmpl.ContainerInfo{
			ID:          scan.ContainerID,
			Name:        scan.ContainerName,
			Image:       scan.Image,
			Score:       scan.Score,
			Grade:       scan.Grade,
			LastScanned: scan.ScannedHuman,
			CVECount:    scan.CVECount,
			IncludedCVE: scan.IncludedCVE,
		}
	}

	data.Issues = make([]securitytmpl.SecurityIssue, 0, len(issues))
	data.CVEs = make([]securitytmpl.CVEInfo, 0)

	// Build severity summary
	summary := securitytmpl.IssueSummary{}

	for _, i := range issues {
		// Count severity
		switch i.Severity {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		case "info":
			summary.Info++
		}

		data.Issues = append(data.Issues, securitytmpl.SecurityIssue{
			ID:          i.ID,
			Severity:    i.Severity,
			Category:    i.Category,
			Title:       i.Title,
			Description: i.Message,
			FixCommand:  i.FixCommand,
			DocURL:      i.Documentation,
			Status:      i.Status,
		})

		// Extract CVE entries from vulnerability issues
		if i.Category == "vulnerability" && i.CVEID != "" {
			cve := securitytmpl.CVEInfo{
				ID:          i.CVEID,
				Severity:    i.Severity,
				Description: i.Message,
				CVSSScore:   i.CVSSScore,
			}

			// Parse package name from Title ("CVE: CVE-xxx in pkg-name")
			if parts := strings.SplitN(i.Title, " in ", 2); len(parts) == 2 {
				cve.Package = parts[1]
			}

			// Parse versions from Recommendation ("Update pkg from ver1 to ver2")
			if strings.HasPrefix(i.Recommendation, "Update ") {
				rec := strings.TrimPrefix(i.Recommendation, "Update ")
				if fromIdx := strings.Index(rec, " from "); fromIdx >= 0 {
					rest := rec[fromIdx+6:]
					if toIdx := strings.Index(rest, " to "); toIdx >= 0 {
						cve.Version = rest[:toIdx]
						cve.FixedIn = rest[toIdx+4:]
					}
				}
			}

			data.CVEs = append(data.CVEs, cve)
		}
	}

	data.Summary = summary

	return data
}

// ============================================================================
// Updates Adapters
// ============================================================================

// ToTemplUpdatesListData converts UpdateView slices to the template data type.
// ToTemplSecurityTrendsData converts trends data to the templ template type.
func ToTemplSecurityTrendsData(p *PageData, trends *SecurityTrendsViewData) securitytmpl.TrendsData {
	data := securitytmpl.TrendsData{
		PageData: ToTemplPageData(p),
		Days:     trends.Days,
	}

	data.Overview = securitytmpl.SecurityOverview{
		TotalContainers: trends.Overview.TotalScanned,
		AverageScore:    int(trends.Overview.AverageScore),
		GradeA:          trends.Overview.GradeA,
		GradeB:          trends.Overview.GradeB,
		GradeC:          trends.Overview.GradeC,
		GradeD:          trends.Overview.GradeD,
		GradeF:          trends.Overview.GradeF,
		CriticalIssues:  trends.Overview.CriticalCount,
		HighIssues:      trends.Overview.HighCount,
	}

	data.ScoreHistory = make([]securitytmpl.TrendPointView, 0, len(trends.ScoreHistory))
	for _, p := range trends.ScoreHistory {
		data.ScoreHistory = append(data.ScoreHistory, securitytmpl.TrendPointView{
			Date:  p.Date,
			Score: p.Score,
		})
	}

	data.ContainerTrends = make([]securitytmpl.ContainerTrendView, 0, len(trends.ContainerTrends))
	for _, ct := range trends.ContainerTrends {
		data.ContainerTrends = append(data.ContainerTrends, securitytmpl.ContainerTrendView{
			Name:          ct.Name,
			CurrentScore:  ct.CurrentScore,
			CurrentGrade:  ct.CurrentGrade,
			PreviousScore: ct.PreviousScore,
			Change:        ct.Change,
		})
	}

	return data
}

func ToTemplUpdatesListData(p *PageData, available []UpdateView, history []UpdateHistoryView) updatestmpl.UpdatesData {
	data := updatestmpl.UpdatesData{
		PageData: ToTemplPageData(p),
	}

	data.Available = make([]updatestmpl.UpdateItem, 0, len(available))
	for _, u := range available {
		// Build image references properly
		currentImage := u.Image
		if currentImage == "" {
			if u.CurrentVersion != "" {
				currentImage = u.ContainerName + ":" + u.CurrentVersion
			} else {
				currentImage = u.ContainerName
			}
		}

		// Extract base image name (without tag or digest) to build latest image
		imageName := currentImage
		if atIdx := strings.Index(imageName, "@"); atIdx != -1 {
			// Digest reference: image@sha256:abc → image
			imageName = imageName[:atIdx]
		} else {
			// Tag reference: find the last colon after the last slash
			// to avoid matching port colons (e.g. registry:5000/image:tag)
			lastSlash := strings.LastIndex(imageName, "/")
			searchFrom := 0
			if lastSlash != -1 {
				searchFrom = lastSlash
			}
			if colonIdx := strings.LastIndex(imageName[searchFrom:], ":"); colonIdx != -1 {
				imageName = imageName[:searchFrom+colonIdx]
			}
		}
		latestImage := imageName + ":" + u.LatestVersion

		data.Available = append(data.Available, updatestmpl.UpdateItem{
			ContainerID:    u.ContainerID,
			ContainerName:  u.ContainerName,
			CurrentVersion: u.CurrentVersion,
			LatestVersion:  u.LatestVersion,
			CurrentImage:   currentImage,
			LatestImage:    latestImage,
			Changelog:      u.Changelog,
			ReleaseDate:    u.CheckedAt,
		})
	}

	data.History = make([]updatestmpl.UpdateHistoryItem, 0, len(history))
	for _, h := range history {
		data.History = append(data.History, updatestmpl.UpdateHistoryItem{
			ContainerName: h.ContainerName,
			FromVersion:   h.FromVersion,
			ToVersion:     h.ToVersion,
			Status:        h.Status,
			Duration:      h.Duration,
			UpdatedAt:     h.UpdatedAt,
		})
	}

	return data
}
