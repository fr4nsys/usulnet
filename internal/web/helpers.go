// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TemplateHelpers provides helper functions for use in templates.
type TemplateHelpers struct{}

// NewTemplateHelpers creates a new TemplateHelpers instance.
func NewTemplateHelpers() *TemplateHelpers {
	return &TemplateHelpers{}
}

// FormatBytes formats bytes as human-readable string.
func (h *TemplateHelpers) FormatBytes(bytes int64) string {
	if bytes == 0 {
		return "0 B"
	}
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	i := 0
	size := float64(bytes)
	for size >= 1024 && i < len(units)-1 {
		size /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", bytes)
	}
	return fmt.Sprintf("%.1f %s", size, units[i])
}

// FormatDuration formats seconds as human-readable duration.
func (h *TemplateHelpers) FormatDuration(seconds int) string {
	if seconds < 0 {
		return "0s"
	}
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		m := seconds / 60
		s := seconds % 60
		if s == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm %ds", m, s)
	}
	hours := seconds / 3600
	mins := (seconds % 3600) / 60
	if mins == 0 {
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dh %dm", hours, mins)
}

// TimeAgo returns human-readable relative time.
func (h *TemplateHelpers) TimeAgo(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return timeAgo(t)
}

// TruncateString truncates a string to max length with ellipsis.
func (h *TemplateHelpers) TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// ShortID returns first 12 characters of a Docker ID.
func (h *TemplateHelpers) ShortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// ShortImage returns shortened image name (without registry prefix).
func (h *TemplateHelpers) ShortImage(image string) string {
	// Remove registry prefix if present
	parts := strings.Split(image, "/")
	if len(parts) > 2 {
		image = strings.Join(parts[len(parts)-2:], "/")
	}
	// Truncate if still too long
	if len(image) > 50 {
		return image[:47] + "..."
	}
	return image
}

// StatusColor returns CSS class for container status.
func (h *TemplateHelpers) StatusColor(status string) string {
	switch strings.ToLower(status) {
	case "running":
		return "text-green-400"
	case "exited", "dead":
		return "text-red-400"
	case "paused":
		return "text-yellow-400"
	case "restarting":
		return "text-blue-400"
	case "created":
		return "text-gray-400"
	default:
		return "text-gray-500"
	}
}

// StatusBadge returns badge CSS classes for container status.
func (h *TemplateHelpers) StatusBadge(status string) string {
	switch strings.ToLower(status) {
	case "running":
		return "badge-success"
	case "exited", "dead":
		return "badge-danger"
	case "paused":
		return "badge-warning"
	case "restarting":
		return "badge-info"
	default:
		return "badge-neutral"
	}
}

// HealthColor returns CSS class for health status.
func (h *TemplateHelpers) HealthColor(health string) string {
	switch strings.ToLower(health) {
	case "healthy":
		return "text-green-400"
	case "unhealthy":
		return "text-red-400"
	case "starting":
		return "text-yellow-400"
	default:
		return "text-gray-500"
	}
}

// GradeColor returns CSS classes for security grade.
func (h *TemplateHelpers) GradeColor(grade string) string {
	switch strings.ToUpper(grade) {
	case "A":
		return "text-green-400 bg-green-500/10"
	case "B":
		return "text-blue-400 bg-blue-500/10"
	case "C":
		return "text-yellow-400 bg-yellow-500/10"
	case "D":
		return "text-orange-400 bg-orange-500/10"
	case "F":
		return "text-red-400 bg-red-500/10"
	default:
		return "text-gray-400 bg-gray-500/10"
	}
}

// SeverityColor returns CSS classes for severity level.
func (h *TemplateHelpers) SeverityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "text-red-500 bg-red-500/10 border-red-500/20"
	case "high":
		return "text-orange-400 bg-orange-500/10 border-orange-500/20"
	case "medium":
		return "text-yellow-400 bg-yellow-500/10 border-yellow-500/20"
	case "low":
		return "text-blue-400 bg-blue-500/10 border-blue-500/20"
	case "info":
		return "text-gray-400 bg-gray-500/10 border-gray-500/20"
	default:
		return "text-gray-400 bg-gray-500/10"
	}
}

// SeverityBadge returns badge CSS for severity.
func (h *TemplateHelpers) SeverityBadge(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "badge-danger"
	case "high":
		return "badge-warning"
	case "medium":
		return "badge-info"
	case "low":
		return "badge-neutral"
	default:
		return "badge-neutral"
	}
}

// PortDisplay formats a port mapping for display.
func (h *TemplateHelpers) PortDisplay(hostIP string, hostPort, containerPort int, protocol string) string {
	if hostPort == 0 {
		return fmt.Sprintf("%d/%s", containerPort, protocol)
	}
	if hostIP == "" || hostIP == "0.0.0.0" {
		return fmt.Sprintf("%d:%d/%s", hostPort, containerPort, protocol)
	}
	return fmt.Sprintf("%s:%d:%d/%s", hostIP, hostPort, containerPort, protocol)
}

// MaskSecret masks a secret value showing first/last 4 chars.
func (h *TemplateHelpers) MaskSecret(value string) string {
	if len(value) <= 8 {
		return "********"
	}
	return value[:4] + "****" + value[len(value)-4:]
}

// Pluralize returns plural suffix if count != 1.
func (h *TemplateHelpers) Pluralize(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	if plural == "" {
		return singular + "s"
	}
	return plural
}

// YesNo returns "Yes" or "No" based on boolean.
func (h *TemplateHelpers) YesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// Percentage formats a float as percentage.
func (h *TemplateHelpers) Percentage(value float64, decimals int) string {
	format := fmt.Sprintf("%%.%df%%%%", decimals)
	return fmt.Sprintf(format, value)
}

// SafeHTML marks string as safe HTML (use with caution).
func (h *TemplateHelpers) SafeHTML(s string) template.HTML {
	return template.HTML(s)
}

// SafeURL marks string as safe URL.
func (h *TemplateHelpers) SafeURL(s string) template.URL {
	return template.URL(s)
}

// QueryEscape URL-encodes a string.
func (h *TemplateHelpers) QueryEscape(s string) string {
	return url.QueryEscape(s)
}

// BuildURL builds a URL with query parameters.
func (h *TemplateHelpers) BuildURL(base string, params map[string]string) string {
	if len(params) == 0 {
		return base
	}
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Contains checks if slice contains string.
func (h *TemplateHelpers) Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Join joins strings with separator.
func (h *TemplateHelpers) Join(items []string, sep string) string {
	return strings.Join(items, sep)
}

// Split splits string by separator.
func (h *TemplateHelpers) Split(s, sep string) []string {
	return strings.Split(s, sep)
}

// First returns first element of slice or empty string.
func (h *TemplateHelpers) First(items []string) string {
	if len(items) > 0 {
		return items[0]
	}
	return ""
}

// Seq generates a sequence of integers from start to end.
func (h *TemplateHelpers) Seq(start, end int) []int {
	if start > end {
		return nil
	}
	result := make([]int, end-start+1)
	for i := range result {
		result[i] = start + i
	}
	return result
}

// Add adds two integers.
func (h *TemplateHelpers) Add(a, b int) int {
	return a + b
}

// Sub subtracts b from a.
func (h *TemplateHelpers) Sub(a, b int) int {
	return a - b
}

// Mul multiplies two integers.
func (h *TemplateHelpers) Mul(a, b int) int {
	return a * b
}

// Div divides a by b.
func (h *TemplateHelpers) Div(a, b int) int {
	if b == 0 {
		return 0
	}
	return a / b
}

// GetQueryParam extracts query parameter from request.
func GetQueryParam(r *http.Request, key string, defaultValue string) string {
	value := r.URL.Query().Get(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// GetQueryParamInt extracts integer query parameter.
func GetQueryParamInt(r *http.Request, key string, defaultValue int) int {
	value := r.URL.Query().Get(key)
	if value == "" {
		return defaultValue
	}
	i, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	return i
}

// GenerateCSRFToken generates a random CSRF token.
func GenerateCSRFToken() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// FormatPortMappings formats a list of port mappings for display.
func FormatPortMappings(ports []PortView) string {
	if len(ports) == 0 {
		return "-"
	}
	displays := make([]string, 0, len(ports))
	for _, p := range ports {
		if p.Display != "" {
			displays = append(displays, p.Display)
		} else if p.HostPort > 0 {
			displays = append(displays, fmt.Sprintf("%d:%d", p.HostPort, p.ContainerPort))
		}
	}
	if len(displays) == 0 {
		return "-"
	}
	return strings.Join(displays, ", ")
}

// CalculateScoreFromIssues calculates security score from issues.
func CalculateScoreFromIssues(issues []IssueView) int {
	score := 100
	for _, issue := range issues {
		switch strings.ToLower(issue.Severity) {
		case "critical":
			score -= 25
		case "high":
			score -= 15
		case "medium":
			score -= 10
		case "low":
			score -= 5
		}
	}
	if score < 0 {
		return 0
	}
	return score
}

// ScoreToGrade converts numeric score to letter grade.
func ScoreToGrade(score int) string {
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

// ContainerStateIcon returns the icon class for container state.
func ContainerStateIcon(state string) string {
	switch strings.ToLower(state) {
	case "running":
		return "fa-play-circle text-green-400"
	case "exited", "dead":
		return "fa-stop-circle text-red-400"
	case "paused":
		return "fa-pause-circle text-yellow-400"
	case "restarting":
		return "fa-sync text-blue-400"
	case "created":
		return "fa-plus-circle text-gray-400"
	default:
		return "fa-question-circle text-gray-500"
	}
}

// NetworkDriverIcon returns icon class for network driver.
func NetworkDriverIcon(driver string) string {
	switch strings.ToLower(driver) {
	case "bridge":
		return "fa-project-diagram"
	case "host":
		return "fa-server"
	case "overlay":
		return "fa-cloud"
	case "macvlan":
		return "fa-ethernet"
	case "none":
		return "fa-ban"
	default:
		return "fa-network-wired"
	}
}

// VolumeDriverIcon returns icon class for volume driver.
func VolumeDriverIcon(driver string) string {
	switch strings.ToLower(driver) {
	case "local":
		return "fa-hdd"
	case "nfs":
		return "fa-folder-open"
	default:
		return "fa-database"
	}
}

// IsInternalNetwork checks if a network name is an internal Docker network.
func IsInternalNetwork(name string) bool {
	internalNetworks := []string{"bridge", "host", "none"}
	for _, n := range internalNetworks {
		if strings.EqualFold(name, n) {
			return true
		}
	}
	return false
}

// timeAgo returns a human-readable relative time string.
func timeAgo(t time.Time) string {
	now := time.Now()
	diff := now.Sub(t)

	if diff < 0 {
		return "in the future"
	}

	seconds := int(diff.Seconds())

	intervals := []struct {
		label   string
		seconds int
	}{
		{"year", 31536000},
		{"month", 2592000},
		{"week", 604800},
		{"day", 86400},
		{"hour", 3600},
		{"minute", 60},
	}

	for _, interval := range intervals {
		count := seconds / interval.seconds
		if count >= 1 {
			if count == 1 {
				return fmt.Sprintf("1 %s ago", interval.label)
			}
			return fmt.Sprintf("%d %ss ago", count, interval.label)
		}
	}

	if seconds <= 5 {
		return "just now"
	}
	return fmt.Sprintf("%d seconds ago", seconds)
}

// ExtractStackName extracts stack name from container labels.
func ExtractStackName(labels map[string]string) string {
	// Docker Compose v2
	if stack, ok := labels["com.docker.compose.project"]; ok {
		return stack
	}
	// Docker Compose v1
	if stack, ok := labels["com.docker.compose.project.name"]; ok {
		return stack
	}
	return ""
}
