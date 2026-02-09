// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// ShortcutType represents the type of shortcut.
type ShortcutType string

const (
	ShortcutTypeWeb      ShortcutType = "web"      // External web URL
	ShortcutTypeInternal ShortcutType = "internal" // Internal usulnet page
	ShortcutTypeSSH      ShortcutType = "ssh"      // SSH connection shortcut
	ShortcutTypeDB       ShortcutType = "db"       // Database connection shortcut
)

// WebShortcut represents a bookmark/shortcut to an external or internal resource.
type WebShortcut struct {
	ID          uuid.UUID    `db:"id" json:"id"`
	Name        string       `db:"name" json:"name"`
	Description string       `db:"description" json:"description,omitempty"`
	URL         string       `db:"url" json:"url"`
	Type        ShortcutType `db:"type" json:"type"`
	Icon        string       `db:"icon" json:"icon,omitempty"`         // URL to icon or FontAwesome class
	IconType    string       `db:"icon_type" json:"icon_type"`         // "url", "fa", "emoji", "upload"
	Color       string       `db:"color" json:"color,omitempty"`       // Hex color for background
	Category    string       `db:"category" json:"category,omitempty"` // User-defined category
	SortOrder   int          `db:"sort_order" json:"sort_order"`
	OpenInNew   bool         `db:"open_in_new" json:"open_in_new"`     // Open in new tab
	ShowInMenu  bool         `db:"show_in_menu" json:"show_in_menu"`   // Show in sidebar menu
	IsPublic    bool         `db:"is_public" json:"is_public"`         // Visible to all users
	CreatedBy   uuid.UUID    `db:"created_by" json:"created_by"`
	CreatedAt   time.Time    `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time    `db:"updated_at" json:"updated_at"`

	// Relations (not stored)
	CreatedByUser *User `db:"-" json:"created_by_user,omitempty"`
}

// ShortcutCategory represents a category for organizing shortcuts.
type ShortcutCategory struct {
	ID        uuid.UUID `db:"id" json:"id"`
	Name      string    `db:"name" json:"name"`
	Icon      string    `db:"icon" json:"icon,omitempty"`
	Color     string    `db:"color" json:"color,omitempty"`
	SortOrder int       `db:"sort_order" json:"sort_order"`
	IsDefault bool      `db:"is_default" json:"is_default"` // Default category for new shortcuts
	CreatedBy uuid.UUID `db:"created_by" json:"created_by"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// CreateWebShortcutInput is the input for creating a shortcut.
type CreateWebShortcutInput struct {
	Name        string       `json:"name" validate:"required,max=100"`
	Description string       `json:"description,omitempty" validate:"max=500"`
	URL         string       `json:"url" validate:"required,url"`
	Type        ShortcutType `json:"type" validate:"required,oneof=web internal ssh db"`
	Icon        string       `json:"icon,omitempty"`
	IconType    string       `json:"icon_type,omitempty" validate:"omitempty,oneof=url fa emoji upload"`
	Color       string       `json:"color,omitempty" validate:"omitempty,hexcolor"`
	Category    string       `json:"category,omitempty" validate:"max=50"`
	SortOrder   int          `json:"sort_order,omitempty"`
	OpenInNew   bool         `json:"open_in_new"`
	ShowInMenu  bool         `json:"show_in_menu"`
	IsPublic    bool         `json:"is_public"`
}

// UpdateWebShortcutInput is the input for updating a shortcut.
type UpdateWebShortcutInput struct {
	Name        *string       `json:"name,omitempty" validate:"omitempty,max=100"`
	Description *string       `json:"description,omitempty" validate:"omitempty,max=500"`
	URL         *string       `json:"url,omitempty" validate:"omitempty,url"`
	Type        *ShortcutType `json:"type,omitempty" validate:"omitempty,oneof=web internal ssh db"`
	Icon        *string       `json:"icon,omitempty"`
	IconType    *string       `json:"icon_type,omitempty" validate:"omitempty,oneof=url fa emoji upload"`
	Color       *string       `json:"color,omitempty" validate:"omitempty,hexcolor"`
	Category    *string       `json:"category,omitempty" validate:"omitempty,max=50"`
	SortOrder   *int          `json:"sort_order,omitempty"`
	OpenInNew   *bool         `json:"open_in_new,omitempty"`
	ShowInMenu  *bool         `json:"show_in_menu,omitempty"`
	IsPublic    *bool         `json:"is_public,omitempty"`
}

// CreateCategoryInput is the input for creating a category.
type CreateCategoryInput struct {
	Name      string `json:"name" validate:"required,max=50"`
	Icon      string `json:"icon,omitempty"`
	Color     string `json:"color,omitempty" validate:"omitempty,hexcolor"`
	SortOrder int    `json:"sort_order,omitempty"`
	IsDefault bool   `json:"is_default"`
}
