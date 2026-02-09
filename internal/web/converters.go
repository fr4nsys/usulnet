// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"fmt"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ============================================================================
// Container Conversions
// ============================================================================

func containerToView(c *models.Container) ContainerView {
	if c == nil {
		return ContainerView{}
	}

	// Get created time
	created := c.CreatedAt
	if c.CreatedAtDocker != nil {
		created = *c.CreatedAtDocker
	}

	// Convert networks to string slice and detailed view
	var networks []string
	var networkDetails []NetworkAttachmentView
	for _, n := range c.Networks {
		networks = append(networks, n.NetworkName)
		networkDetails = append(networkDetails, NetworkAttachmentView{
			NetworkID:   n.NetworkID,
			NetworkName: n.NetworkName,
			IPAddress:   n.IPAddress,
			Gateway:     n.Gateway,
			MacAddress:  n.MacAddress,
			Aliases:     n.Aliases,
		})
	}

	// Get restart policy
	restartPolicy := ""
	if c.RestartPolicy != nil {
		restartPolicy = *c.RestartPolicy
	}

	view := ContainerView{
		ID:            c.ID,
		ShortID:       shortID(c.ID),
		HostID:        c.HostID.String(),
		Name:          c.Name,
		Image:         c.Image,
		ImageShort:    shortImage(c.Image),
		State:         string(c.State),
		Status:        c.Status,
		Health:        "", // Not in model
		Created:       created,
		CreatedHuman:  humanTime(created),
		Networks:       networks,
		NetworkDetails: networkDetails,
		Labels:         c.Labels,
		Stack:         "", // Not directly in model
		RestartPolicy: restartPolicy,
		Command:       "", // Not in model
		SecurityScore: c.SecurityScore,
		SecurityGrade: c.SecurityGrade,
	}

	// Ports
	for _, p := range c.Ports {
		view.Ports = append(view.Ports, PortView{
			ContainerPort: int(p.PrivatePort),
			HostPort:      int(p.PublicPort),
			HostIP:        p.IP,
			Protocol:      p.Type,
			Display:       formatPortMapping(p),
		})
	}

	// Mounts
	for _, m := range c.Mounts {
		view.Mounts = append(view.Mounts, MountView{
			Source:      m.Source,
			Destination: m.Destination,
			Type:        m.Type,
			Mode:        m.Mode,
			RW:          m.RW,
		})
	}

	return view
}

// ============================================================================
// Image Conversions
// ============================================================================

func imageToView(img *models.Image) ImageView {
	if img == nil {
		return ImageView{}
	}

	primaryTag := ""
	if len(img.RepoTags) > 0 {
		primaryTag = img.RepoTags[0]
	}

	return ImageView{
		ID:           img.ID,
		ShortID:      shortID(img.ID),
		Tags:         img.RepoTags,
		PrimaryTag:   primaryTag,
		Size:         img.Size,
		SizeHuman:    humanSize(img.Size),
		Created:      img.CreatedAt,
		CreatedHuman: humanTime(img.CreatedAt),
		InUse:        img.Containers > 0,
		Containers:   int(img.Containers),
	}
}

// ============================================================================
// Volume Conversions
// ============================================================================

func volumeToView(v *models.Volume) VolumeView {
	if v == nil {
		return VolumeView{}
	}

	var size int64
	inUse := false
	if v.UsageData != nil {
		size = v.UsageData.Size
		inUse = v.UsageData.RefCount > 0
	}

	return VolumeView{
		Name:         v.Name,
		Driver:       v.Driver,
		Mountpoint:   v.Mountpoint,
		Scope:        string(v.Scope),
		Labels:       v.Labels,
		Created:      v.CreatedAt,
		CreatedHuman: humanTime(v.CreatedAt),
		InUse:        inUse,
		Size:         size,
		SizeHuman:    humanSize(size),
	}
}

// ============================================================================
// Network Conversions
// ============================================================================

func networkToView(n *models.Network) NetworkView {
	if n == nil {
		return NetworkView{}
	}

	// Get subnet and gateway from IPAM
	subnet := ""
	gateway := ""
	if len(n.IPAM.Config) > 0 {
		subnet = n.IPAM.Config[0].Subnet
		gateway = n.IPAM.Config[0].Gateway
	}

	// Get container names from map (keys are IDs, values have names)
	var containerNames []string
	for id, info := range n.Containers {
		name := info.Name
		if name == "" {
			name = shortID(id)
		}
		containerNames = append(containerNames, name)
	}

	return NetworkView{
		ID:             n.ID,
		ShortID:        shortID(n.ID),
		Name:           n.Name,
		Driver:         n.Driver,
		Scope:          string(n.Scope),
		Internal:       n.Internal,
		Attachable:     n.Attachable,
		Subnet:         subnet,
		Gateway:        gateway,
		Created:        n.CreatedAt,
		CreatedHuman:   humanTime(n.CreatedAt),
		ContainerCount: len(n.Containers),
		Containers:     containerNames,
	}
}

// ============================================================================
// Stack Conversions
// ============================================================================

func stackToView(s *models.Stack) StackView {
	if s == nil {
		return StackView{}
	}

	return StackView{
		ID:           s.ID.String(),
		Name:         s.Name,
		Status:       string(s.Status),
		ServiceCount: s.ServiceCount,
		RunningCount: s.RunningCount,
		Path:         s.ProjectDir,
		ComposeFile:  s.ComposeFile,
		Created:      s.CreatedAt,
		CreatedHuman: humanTime(s.CreatedAt),
		UpdatedHuman: humanTime(s.UpdatedAt),
	}
}

// ============================================================================
// Backup Conversions
// ============================================================================

func backupToView(b *models.Backup) BackupView {
	if b == nil {
		return BackupView{}
	}

	view := BackupView{
		ID:            b.ID.String(),
		HostID:        b.HostID.String(),
		ContainerID:   b.TargetID,
		ContainerName: b.TargetName,
		Type:          string(b.Type),
		Status:        string(b.Status),
		Trigger:       string(b.Trigger),
		Size:          b.SizeBytes,
		SizeHuman:     humanSize(b.SizeBytes),
		Compression:   string(b.Compression),
		Encrypted:     b.Encrypted,
		Verified:      b.Verified,
		Path:          b.Path,
		Created:       b.CreatedAt,
		CreatedHuman:  humanTime(b.CreatedAt),
	}

	if b.Checksum != nil {
		view.Checksum = *b.Checksum
	}
	if b.ErrorMessage != nil {
		view.ErrorMessage = *b.ErrorMessage
	}
	if b.CompletedAt != nil {
		view.CompletedAt = humanTime(*b.CompletedAt)
	}
	if b.ExpiresAt != nil {
		view.ExpiresAt = humanTime(*b.ExpiresAt)
	}
	if d := b.Duration(); d > 0 {
		view.Duration = d.Round(time.Millisecond).String()
	}

	return view
}

// ============================================================================
// Security Conversions
// ============================================================================

func securityScanToView(s *models.SecurityScan) SecurityScanView {
	if s == nil {
		return SecurityScanView{}
	}

	view := SecurityScanView{
		ContainerID:   s.ContainerID,
		ContainerName: s.ContainerName,
		Image:         s.Image,
		Score:         s.Score,
		Grade:         string(s.Grade),
		IssueCount:    s.IssueCount,
		CriticalCount: s.CriticalCount,
		HighCount:     s.HighCount,
		MediumCount:   s.MediumCount,
		LowCount:      s.LowCount,
		CVECount:      s.CVECount,
		IncludedCVE:   s.IncludeCVE,
		ScannedAt:     s.CompletedAt,
		ScannedHuman:  humanTime(s.CompletedAt),
	}

	if len(s.Issues) > 0 {
		view.Issues = make([]IssueView, len(s.Issues))
		for i := range s.Issues {
			view.Issues[i] = issueToView(&s.Issues[i])
		}
	}

	return view
}

func issueToView(i *models.SecurityIssue) IssueView {
	if i == nil {
		return IssueView{}
	}

	v := IssueView{
		ID:             fmt.Sprintf("%d", i.ID),
		Severity:       string(i.Severity),
		Category:       string(i.Category),
		Title:          i.Title,
		Message:        i.Description,
		Recommendation: i.Recommendation,
		Status:         string(i.Status),
	}

	if i.FixCommand != nil {
		v.FixCommand = *i.FixCommand
	}
	if i.DocumentationURL != nil {
		v.Documentation = *i.DocumentationURL
	}
	if i.CVEID != nil {
		v.CVEID = *i.CVEID
	}
	if i.CVSSScore != nil {
		v.CVSSScore = *i.CVSSScore
	}

	return v
}

// ============================================================================
// Helper Functions
// ============================================================================

func shortID(id string) string {
	// Remove sha256: prefix if present
	if strings.HasPrefix(id, "sha256:") {
		id = id[7:]
	}
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func shortImage(image string) string {
	// Remove registry prefix if present
	parts := strings.Split(image, "/")
	name := parts[len(parts)-1]

	// Truncate if too long
	if len(name) > 40 {
		return name[:37] + "..."
	}
	return name
}

func humanTime(t time.Time) string {
	if t.IsZero() {
		return "N/A"
	}

	now := time.Now()
	diff := now.Sub(t)

	switch {
	case diff < time.Minute:
		return "just now"
	case diff < time.Hour:
		mins := int(diff.Minutes())
		if mins == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", mins)
	case diff < 24*time.Hour:
		hours := int(diff.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	case diff < 7*24*time.Hour:
		days := int(diff.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	case diff < 30*24*time.Hour:
		weeks := int(diff.Hours() / 24 / 7)
		if weeks == 1 {
			return "1 week ago"
		}
		return fmt.Sprintf("%d weeks ago", weeks)
	case diff < 365*24*time.Hour:
		months := int(diff.Hours() / 24 / 30)
		if months == 1 {
			return "1 month ago"
		}
		return fmt.Sprintf("%d months ago", months)
	default:
		years := int(diff.Hours() / 24 / 365)
		if years == 1 {
			return "1 year ago"
		}
		return fmt.Sprintf("%d years ago", years)
	}
}

func humanSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)

	switch {
	case bytes >= TB:
		return fmt.Sprintf("%.2f TB", float64(bytes)/TB)
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func scoreToGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func formatPortMapping(p models.PortMapping) string {
	if p.PublicPort > 0 {
		if p.IP != "" && p.IP != "0.0.0.0" {
			return fmt.Sprintf("%s:%d->%d/%s", p.IP, p.PublicPort, p.PrivatePort, p.Type)
		}
		return fmt.Sprintf("%d->%d/%s", p.PublicPort, p.PrivatePort, p.Type)
	}
	return fmt.Sprintf("%d/%s", p.PrivatePort, p.Type)
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	// Remove empty trailing line
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}


