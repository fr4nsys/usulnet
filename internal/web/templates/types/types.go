// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package types contains shared types for templates
package types

// PageData contains common data for all pages
type PageData struct {
	Title              string
	Description        string
	Active             string
	User               *UserData
	Stats              *StatsData
	CSRFToken          string
	Theme              string
	Version            string
	NotificationsCount int
	Flash              *FlashData
	FullScreen         bool // For editors - removes main padding wrapper
	// Edition / EditionName tag the support tier carried on an optional
	// commercial license token. They are display-only and the AGPL build
	// never branches on them (principle 2 in docs/0526/x/principles.md).
	Edition        string
	EditionName    string
	Hosts          []HostSelectorItem
	ActiveHostID   string
	ActiveHostName string
	SidebarPrefs   *SidebarPreferences
	// ReconEnabled controls visibility of the v26.5.0 Privacy & Recon
	// sidebar section. The flag mirrors cfg.Recon.Enabled — see
	// docs/v26.5/technical-notes.md "Feature flag".
	ReconEnabled bool
}

// SidebarPreferences controls per-user sidebar collapse state and item visibility.
type SidebarPreferences struct {
	// Collapsed tracks which collapsible sections are collapsed.
	// Keys: "operations", "connections", "tools", "integrations", "monitoring"
	Collapsed map[string]bool `json:"collapsed"`

	// Hidden tracks which individual nav items the user has hidden.
	// Keys match the sidebar item identifiers (e.g. "swarm", "capture").
	Hidden map[string]bool `json:"hidden"`
}

// DefaultSidebarPreferences returns the default sidebar configuration.
func DefaultSidebarPreferences() *SidebarPreferences {
	return &SidebarPreferences{
		Collapsed: map[string]bool{
			"tools":        true,
			"integrations": true,
			"monitoring":   true,
		},
		Hidden: map[string]bool{},
	}
}

// IsCollapsed returns true if the given section should be collapsed.
func (p *SidebarPreferences) IsCollapsed(section string) bool {
	if p == nil || p.Collapsed == nil {
		// Apply defaults for unset prefs
		switch section {
		case "tools", "integrations", "monitoring":
			return true
		}
		return false
	}
	return p.Collapsed[section]
}

// IsHidden returns true if the given nav item should be hidden.
func (p *SidebarPreferences) IsHidden(item string) bool {
	if p == nil || p.Hidden == nil {
		return false
	}
	return p.Hidden[item]
}

// HostSelectorItem represents a host in the header dropdown selector
type HostSelectorItem struct {
	ID           string
	Name         string
	Status       string // online, offline, error, connecting
	EndpointType string // local, tcp, agent
}

// UserData contains user information
type UserData struct {
	ID       string
	Username string
	Role     string // Display name of the role
	RoleID   string // UUID of the role for permission checking
	Email    string
}

// StatsData contains dashboard statistics
type StatsData struct {
	ContainersRunning int
	ContainersTotal   int
	ImagesCount       int
	VolumesCount      int
	NetworksCount     int
	SecurityIssues    int
	UpdatesAvailable  int
}

// FlashData contains flash message data
type FlashData struct {
	Type    string // success, error, warning, info
	Message string
}
