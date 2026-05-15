// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

// CatalogTemplate represents a template from the embedded catalog.
type CatalogTemplate struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Description   string            `json:"description"`
	Category      string            `json:"category"`
	Logo          string            `json:"logo,omitempty"`
	Platform      string            `json:"platform"`
	Type          string            `json:"type"` // "container" or "stack"
	Image         string            `json:"image,omitempty"`
	Compose       string            `json:"compose,omitempty"` // for stack type
	Ports         []string          `json:"ports,omitempty"`
	Volumes       []TemplateVolume  `json:"volumes,omitempty"`
	Env           []TemplateEnv     `json:"env,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	RestartPolicy string            `json:"restart_policy,omitempty"`
	Note          string            `json:"note,omitempty"`
	Network       string            `json:"network,omitempty"`
	Command       string            `json:"command,omitempty"`
}

// TemplateVolume represents a volume mapping in a catalog template.
type TemplateVolume struct {
	Container string `json:"container"`
	Bind      string `json:"bind,omitempty"`
	ReadOnly  bool   `json:"readonly,omitempty"`
}

// TemplateEnv represents an environment variable in a catalog template.
type TemplateEnv struct {
	Name     string   `json:"name"`
	Label    string   `json:"label,omitempty"`
	Default  string   `json:"default,omitempty"`
	Required bool     `json:"required,omitempty"`
	Type     string   `json:"type,omitempty"`    // "text", "password", "select"
	Options  []string `json:"options,omitempty"` // for select type
}

// CatalogFile represents the JSON structure of an embedded template file.
type CatalogFile struct {
	Templates []CatalogTemplate `json:"templates"`
}
