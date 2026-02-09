// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/json"
	"time"
)

// ============================================================================
// User Preferences — persisted per-user, applied via middleware
// ============================================================================

// Theme represents the UI theme preference.
type Theme string

const (
	ThemeDark   Theme = "dark"
	ThemeLight  Theme = "light"
	ThemeSystem Theme = "system"
)

// DateFormat represents how dates are displayed.
type DateFormat string

const (
	DateFormatISO    DateFormat = "2006-01-02"          // ISO 8601
	DateFormatEU     DateFormat = "02/01/2006"          // DD/MM/YYYY
	DateFormatUS     DateFormat = "01/02/2006"          // MM/DD/YYYY
	DateFormatHuman  DateFormat = "02 Jan 2006"         // 02 Jan 2006
	DateFormatFull   DateFormat = "Monday, 02 Jan 2006" // Full
)

// TimeFormat represents 12h vs 24h clock.
type TimeFormat string

const (
	TimeFormat24h TimeFormat = "15:04"    // 24h
	TimeFormat12h TimeFormat = "03:04 PM" // 12h
)

// ViewMode represents the default container list view mode.
type ViewMode string

const (
	ViewModeTable ViewMode = "table"
	ViewModeGrid  ViewMode = "grid"
)

// LogLineCount represents how many log lines to show by default.
type LogLineCount int

const (
	LogLines100  LogLineCount = 100
	LogLines250  LogLineCount = 250
	LogLines500  LogLineCount = 500
	LogLines1000 LogLineCount = 1000
	LogLines5000 LogLineCount = 5000
)

// RefreshInterval represents the dashboard auto-refresh interval in seconds.
type RefreshInterval int

const (
	RefreshOff RefreshInterval = 0
	Refresh5s  RefreshInterval = 5
	Refresh10s RefreshInterval = 10
	Refresh30s RefreshInterval = 30
	Refresh60s RefreshInterval = 60
)

// UserPreferences holds all configurable preferences for a user.
type UserPreferences struct {
	// Appearance
	Theme    Theme  `json:"theme"`
	Language string `json:"language"` // ISO 639-1 (en, es, de, fr, pt, ja, zh)

	// Regional
	Timezone   string     `json:"timezone"`    // IANA timezone (Europe/Madrid, America/New_York, etc.)
	DateFormat DateFormat `json:"date_format"` // Date display format
	TimeFormat TimeFormat `json:"time_format"` // 12h/24h

	// Dashboard & UI
	ContainerView   ViewMode        `json:"container_view"`   // table or grid
	DefaultLogLines LogLineCount    `json:"default_log_lines"`
	RefreshInterval RefreshInterval `json:"refresh_interval"` // seconds, 0=off
	ShowStoppedContainers bool      `json:"show_stopped_containers"`

	// Notifications (in-app)
	NotifyUpdates   bool `json:"notify_updates"`    // Update available alerts
	NotifySecurity  bool `json:"notify_security"`   // Security score changes
	NotifyBackups   bool `json:"notify_backups"`    // Backup completion/failure
	NotifyContainer bool `json:"notify_container"`  // Container state changes

	// Editor
	EditorMode     string `json:"editor_mode"`      // monaco or nvim
	EditorFontSize int    `json:"editor_font_size"` // px
	EditorTabSize  int    `json:"editor_tab_size"`
}

// DefaultPreferences returns sensible defaults for new users.
func DefaultPreferences() UserPreferences {
	return UserPreferences{
		Theme:                 ThemeDark,
		Language:              "en",
		Timezone:              "UTC",
		DateFormat:            DateFormatISO,
		TimeFormat:            TimeFormat24h,
		ContainerView:         ViewModeTable,
		DefaultLogLines:       LogLines500,
		RefreshInterval:       Refresh10s,
		ShowStoppedContainers: true,
		NotifyUpdates:         true,
		NotifySecurity:        true,
		NotifyBackups:         true,
		NotifyContainer:       false,
		EditorMode:            "monaco",
		EditorFontSize:        14,
		EditorTabSize:         4,
	}
}

// Merge applies non-zero values from partial onto the receiver.
// Used when updating preferences from a form (only submitted fields change).
func (p *UserPreferences) Merge(partial UserPreferences) {
	if partial.Theme != "" {
		p.Theme = partial.Theme
	}
	if partial.Language != "" {
		p.Language = partial.Language
	}
	if partial.Timezone != "" {
		p.Timezone = partial.Timezone
	}
	if partial.DateFormat != "" {
		p.DateFormat = partial.DateFormat
	}
	if partial.TimeFormat != "" {
		p.TimeFormat = partial.TimeFormat
	}
	if partial.ContainerView != "" {
		p.ContainerView = partial.ContainerView
	}
	if partial.DefaultLogLines > 0 {
		p.DefaultLogLines = partial.DefaultLogLines
	}
	if partial.RefreshInterval >= 0 {
		p.RefreshInterval = partial.RefreshInterval
	}
	if partial.EditorMode != "" {
		p.EditorMode = partial.EditorMode
	}
	if partial.EditorFontSize > 0 {
		p.EditorFontSize = partial.EditorFontSize
	}
	if partial.EditorTabSize > 0 {
		p.EditorTabSize = partial.EditorTabSize
	}
	// Booleans are always set explicitly (checkboxes: present=true, absent=false)
	p.ShowStoppedContainers = partial.ShowStoppedContainers
	p.NotifyUpdates = partial.NotifyUpdates
	p.NotifySecurity = partial.NotifySecurity
	p.NotifyBackups = partial.NotifyBackups
	p.NotifyContainer = partial.NotifyContainer
}

// ToJSON serializes preferences for database storage.
func (p UserPreferences) ToJSON() (string, error) {
	b, err := json.Marshal(p)
	return string(b), err
}

// PreferencesFromJSON deserializes preferences from database storage.
// Returns defaults if data is empty or invalid.
func PreferencesFromJSON(data string) UserPreferences {
	if data == "" {
		return DefaultPreferences()
	}
	prefs := DefaultPreferences()
	if err := json.Unmarshal([]byte(data), &prefs); err != nil {
		return DefaultPreferences()
	}
	return prefs
}

// FormatTime formats a time.Time using the user's timezone and format preferences.
func (p UserPreferences) FormatTime(t time.Time) string {
	loc, err := time.LoadLocation(p.Timezone)
	if err != nil {
		loc = time.UTC
	}
	local := t.In(loc)
	return local.Format(string(p.DateFormat) + " " + string(p.TimeFormat))
}

// FormatDate formats a time.Time using only the date portion.
func (p UserPreferences) FormatDate(t time.Time) string {
	loc, err := time.LoadLocation(p.Timezone)
	if err != nil {
		loc = time.UTC
	}
	return t.In(loc).Format(string(p.DateFormat))
}

// ============================================================================
// Available options (for template dropdowns)
// ============================================================================

type SelectOption struct {
	Value string
	Label string
}

// AvailableTimezones returns common IANA timezones for the preferences UI.
func AvailableTimezones() []SelectOption {
	return []SelectOption{
		{"UTC", "UTC"},
		{"Europe/London", "London (GMT/BST)"},
		{"Europe/Madrid", "Madrid (CET/CEST)"},
		{"Europe/Paris", "Paris (CET/CEST)"},
		{"Europe/Berlin", "Berlin (CET/CEST)"},
		{"Europe/Rome", "Rome (CET/CEST)"},
		{"Europe/Amsterdam", "Amsterdam (CET/CEST)"},
		{"Europe/Zurich", "Zurich (CET/CEST)"},
		{"Europe/Stockholm", "Stockholm (CET/CEST)"},
		{"Europe/Moscow", "Moscow (MSK)"},
		{"Europe/Istanbul", "Istanbul (TRT)"},
		{"America/New_York", "New York (EST/EDT)"},
		{"America/Chicago", "Chicago (CST/CDT)"},
		{"America/Denver", "Denver (MST/MDT)"},
		{"America/Los_Angeles", "Los Angeles (PST/PDT)"},
		{"America/Sao_Paulo", "São Paulo (BRT)"},
		{"America/Argentina/Buenos_Aires", "Buenos Aires (ART)"},
		{"America/Mexico_City", "Mexico City (CST)"},
		{"America/Bogota", "Bogotá (COT)"},
		{"America/Santiago", "Santiago (CLT)"},
		{"Asia/Tokyo", "Tokyo (JST)"},
		{"Asia/Shanghai", "Shanghai (CST)"},
		{"Asia/Hong_Kong", "Hong Kong (HKT)"},
		{"Asia/Singapore", "Singapore (SGT)"},
		{"Asia/Seoul", "Seoul (KST)"},
		{"Asia/Kolkata", "Mumbai (IST)"},
		{"Asia/Dubai", "Dubai (GST)"},
		{"Australia/Sydney", "Sydney (AEST/AEDT)"},
		{"Australia/Melbourne", "Melbourne (AEST/AEDT)"},
		{"Pacific/Auckland", "Auckland (NZST/NZDT)"},
	}
}

// AvailableLanguages returns supported UI languages.
func AvailableLanguages() []SelectOption {
	return []SelectOption{
		{"en", "English"},
		{"es", "Español"},
		{"de", "Deutsch"},
		{"fr", "Français"},
		{"pt", "Português"},
		{"ja", "日本語"},
		{"zh", "中文"},
	}
}
