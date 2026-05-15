// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// MarketplaceAppCategory represents the category of a marketplace app.
type MarketplaceAppCategory string

const (
	MarketplaceAppCategoryNetworking    MarketplaceAppCategory = "networking"
	MarketplaceAppCategoryStorage       MarketplaceAppCategory = "storage"
	MarketplaceAppCategoryDevelopment   MarketplaceAppCategory = "development"
	MarketplaceAppCategoryMonitoring    MarketplaceAppCategory = "monitoring"
	MarketplaceAppCategorySecurity      MarketplaceAppCategory = "security"
	MarketplaceAppCategoryCommunication MarketplaceAppCategory = "communication"
	MarketplaceAppCategoryProductivity  MarketplaceAppCategory = "productivity"
	MarketplaceAppCategoryDatabase      MarketplaceAppCategory = "database"
	MarketplaceAppCategoryOther         MarketplaceAppCategory = "other"
)

// MarketplaceInstallationStatus represents the lifecycle status of an
// installation. The constants are namespaced to avoid colliding with
// other modules that use words like "installed" or "running".
type MarketplaceInstallationStatus string

const (
	MarketplaceInstallationStatusInstalled   MarketplaceInstallationStatus = "installed"
	MarketplaceInstallationStatusRunning     MarketplaceInstallationStatus = "running"
	MarketplaceInstallationStatusStopped     MarketplaceInstallationStatus = "stopped"
	MarketplaceInstallationStatusError       MarketplaceInstallationStatus = "error"
	MarketplaceInstallationStatusUninstalled MarketplaceInstallationStatus = "uninstalled"
)

// MarketplaceApp represents an application available in the marketplace.
type MarketplaceApp struct {
	ID              uuid.UUID              `json:"id" db:"id"`
	Slug            string                 `json:"slug" db:"slug"`
	Name            string                 `json:"name" db:"name"`
	Description     string                 `json:"description" db:"description"`
	LongDescription string                 `json:"long_description" db:"long_description"`
	Icon            string                 `json:"icon" db:"icon"`
	IconColor       string                 `json:"icon_color" db:"icon_color"`
	IconSVG         string                 `json:"icon_svg,omitempty" db:"icon_svg"`
	Category        MarketplaceAppCategory `json:"category" db:"category"`
	Version         string                 `json:"version" db:"version"`
	ManifestVersion int                    `json:"manifest_version" db:"manifest_version"`
	Website         string                 `json:"website" db:"website"`
	Source          string                 `json:"source" db:"source"`
	Author          string                 `json:"author" db:"author"`
	License         string                 `json:"license" db:"license"`
	ComposeTemplate string                 `json:"compose_template" db:"compose_template"`
	Fields          json.RawMessage        `json:"fields" db:"fields"`
	Tags            []string               `json:"tags" db:"tags"`
	MinMemoryMB     int                    `json:"min_memory_mb" db:"min_memory_mb"`
	MinCPUCores     float64                `json:"min_cpu_cores" db:"min_cpu_cores"`
	IsOfficial      bool                   `json:"is_official" db:"is_official"`
	IsVerified      bool                   `json:"is_verified" db:"is_verified"`
	Featured        bool                   `json:"featured" db:"featured"`
	BuiltIn         bool                   `json:"built_in" db:"built_in"`
	InstallCount    int                    `json:"install_count" db:"install_count"`
	AvgRating       float64                `json:"avg_rating" db:"avg_rating"`
	RatingCount     int                    `json:"rating_count" db:"rating_count"`
	CreatedBy       *uuid.UUID             `json:"created_by,omitempty" db:"created_by"`
	CreatedAt       time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at" db:"updated_at"`
}

// MarketplaceField describes a configurable field in a marketplace app template.
type MarketplaceField struct {
	Key         string   `json:"key" yaml:"key"`
	Label       string   `json:"label" yaml:"label"`
	Description string   `json:"description" yaml:"description"`
	Type        string   `json:"type" yaml:"type"`
	Default     string   `json:"default" yaml:"default"`
	Required    bool     `json:"required" yaml:"required"`
	Options     []string `json:"options" yaml:"options"`
	Placeholder string   `json:"placeholder" yaml:"placeholder"`
}

// MarketplaceInstallation represents an installed marketplace app on a host.
type MarketplaceInstallation struct {
	ID           uuid.UUID                     `json:"id" db:"id"`
	AppID        uuid.UUID                     `json:"app_id" db:"app_id"`
	HostID       uuid.UUID                     `json:"host_id" db:"host_id"`
	StackID      *uuid.UUID                    `json:"stack_id,omitempty" db:"stack_id"`
	Name         string                        `json:"name" db:"name"`
	Status       MarketplaceInstallationStatus `json:"status" db:"status"`
	Version      string                        `json:"version" db:"version"`
	ConfigValues json.RawMessage               `json:"config_values" db:"config_values"`
	Notes        string                        `json:"notes" db:"notes"`
	InstalledBy  *uuid.UUID                    `json:"installed_by,omitempty" db:"installed_by"`
	InstalledAt  time.Time                     `json:"installed_at" db:"installed_at"`
	UpdatedAt    time.Time                     `json:"updated_at" db:"updated_at"`
}

// MarketplaceReview represents a user review of a marketplace app.
// One review per (user, app) is enforced by a unique constraint in the
// migration; the service relies on that rather than racing a read-modify-write
// in application code.
type MarketplaceReview struct {
	ID        uuid.UUID `json:"id" db:"id"`
	AppID     uuid.UUID `json:"app_id" db:"app_id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
	Rating    int       `json:"rating" db:"rating"`
	Title     string    `json:"title" db:"title"`
	Comment   string    `json:"comment" db:"comment"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// MarketplaceStats holds aggregate marketplace statistics.
type MarketplaceStats struct {
	TotalApps          int              `json:"total_apps"`
	TotalInstallations int              `json:"total_installations"`
	OfficialApps       int              `json:"official_apps"`
	CommunityApps      int              `json:"community_apps"`
	Categories         int              `json:"categories"`
	TopApps            []MarketplaceApp `json:"top_apps"`
}

// MarketplaceSearchResult holds paginated marketplace search results.
type MarketplaceSearchResult struct {
	Apps  []*MarketplaceApp `json:"apps"`
	Total int               `json:"total"`
}
