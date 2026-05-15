// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package catalog

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ExportFormat defines the format for template export/import.
type ExportFormat struct {
	Version   int                      `json:"version"`
	Source    string                   `json:"source"`
	Templates []models.CatalogTemplate `json:"templates"`
}

// Export serializes templates to JSON in the usulnet export format.
func Export(templates []models.CatalogTemplate) ([]byte, error) {
	export := ExportFormat{
		Version:   1,
		Source:    "usulnet",
		Templates: templates,
	}
	return json.MarshalIndent(export, "", "  ")
}

// ExportByID exports a single template by ID.
func ExportByID(id string) ([]byte, error) {
	tmpl, err := ByID(id)
	if err != nil {
		return nil, err
	}
	return Export([]models.CatalogTemplate{*tmpl})
}

// ExportByCategory exports all templates in a category.
func ExportByCategory(category string) ([]byte, error) {
	templates, err := ByCategory(category)
	if err != nil {
		return nil, err
	}
	if len(templates) == 0 {
		return nil, fmt.Errorf("no templates found for category %q", category)
	}
	return Export(templates)
}

// ExportAll exports the entire catalog.
func ExportAll() ([]byte, error) {
	templates, err := Load()
	if err != nil {
		return nil, err
	}
	return Export(templates)
}

// Import parses templates from JSON data. Supports three formats:
//  1. usulnet native format (ExportFormat with version field)
//  2. Simple CatalogFile format ({"templates": [...]})
//  3. Portainer v2 format (array of objects with title/image fields)
func Import(data []byte) ([]models.CatalogTemplate, error) {
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 {
		return nil, fmt.Errorf("empty import data")
	}

	// Try usulnet native format first.
	var native ExportFormat
	if err := json.Unmarshal(data, &native); err == nil && native.Version > 0 {
		return validateImported(native.Templates)
	}

	// Try CatalogFile format.
	var catalogFile models.CatalogFile
	if err := json.Unmarshal(data, &catalogFile); err == nil && len(catalogFile.Templates) > 0 {
		return validateImported(catalogFile.Templates)
	}

	// Try Portainer v2 template format (array of objects).
	var portainerTemplates []portainerTemplate
	if err := json.Unmarshal(data, &portainerTemplates); err == nil && len(portainerTemplates) > 0 {
		return convertPortainer(portainerTemplates)
	}

	return nil, fmt.Errorf("unrecognized template format")
}

// portainerTemplate represents a Portainer v2 app template.
type portainerTemplate struct {
	Type        int               `json:"type"` // 1=container, 3=stack
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Image       string            `json:"image"`
	Logo        string            `json:"logo"`
	Categories  []string          `json:"categories"`
	Platform    string            `json:"platform"`
	Ports       []string          `json:"ports"`
	Volumes     []portainerVolume `json:"volumes"`
	Env         []portainerEnv    `json:"env"`
	Labels      []portainerLabel  `json:"labels"`
	Note        string            `json:"note"`
	Restart     string            `json:"restart_policy"`
	Command     string            `json:"command"`
	Network     string            `json:"network"`
	Repository  *portainerRepo    `json:"repository"`
}

type portainerVolume struct {
	Container string `json:"container"`
	Bind      string `json:"bind"`
	ReadOnly  bool   `json:"readonly"`
}

type portainerEnv struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Default     string `json:"default"`
	Description string `json:"description"`
	Preset      bool   `json:"preset"`
	Select      []struct {
		Text    string `json:"text"`
		Value   string `json:"value"`
		Default bool   `json:"default"`
	} `json:"select"`
}

type portainerLabel struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type portainerRepo struct {
	URL       string `json:"url"`
	Stackfile string `json:"stackfile"`
}

func convertPortainer(pts []portainerTemplate) ([]models.CatalogTemplate, error) {
	var result []models.CatalogTemplate

	for _, pt := range pts {
		if pt.Title == "" {
			continue
		}

		t := models.CatalogTemplate{
			ID:          strings.ToLower(strings.ReplaceAll(pt.Title, " ", "-")),
			Name:        pt.Title,
			Description: pt.Description,
			Image:       pt.Image,
			Logo:        pt.Logo,
			Platform:    pt.Platform,
			Note:        pt.Note,
			Command:     pt.Command,
			Network:     pt.Network,
		}

		// Type: Portainer type 1=container, 3=stack
		switch pt.Type {
		case 3:
			t.Type = "stack"
			if pt.Repository != nil {
				t.Note = fmt.Sprintf("Stack from %s (file: %s). %s",
					pt.Repository.URL, pt.Repository.Stackfile, t.Note)
			}
		default:
			t.Type = "container"
		}

		// Category
		if len(pt.Categories) > 0 {
			t.Category = strings.ToLower(pt.Categories[0])
		} else {
			t.Category = "other"
		}

		// Platform default
		if t.Platform == "" {
			t.Platform = "linux"
		}

		// Restart policy
		if pt.Restart != "" {
			t.RestartPolicy = pt.Restart
		} else {
			t.RestartPolicy = "unless-stopped"
		}

		// Ports
		t.Ports = pt.Ports

		// Volumes
		for _, v := range pt.Volumes {
			t.Volumes = append(t.Volumes, models.TemplateVolume{
				Container: v.Container,
				Bind:      v.Bind,
				ReadOnly:  v.ReadOnly,
			})
		}

		// Env
		for _, e := range pt.Env {
			env := models.TemplateEnv{
				Name:    e.Name,
				Label:   e.Label,
				Default: e.Default,
			}
			if env.Label == "" {
				env.Label = e.Description
			}
			if len(e.Select) > 0 {
				env.Type = "select"
				for _, opt := range e.Select {
					env.Options = append(env.Options, opt.Value)
					if opt.Default && env.Default == "" {
						env.Default = opt.Value
					}
				}
			}
			t.Env = append(t.Env, env)
		}

		// Labels
		if len(pt.Labels) > 0 {
			t.Labels = make(map[string]string)
			for _, l := range pt.Labels {
				t.Labels[l.Name] = l.Value
			}
		}

		result = append(result, t)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no valid templates found in Portainer format")
	}
	return result, nil
}

func validateImported(templates []models.CatalogTemplate) ([]models.CatalogTemplate, error) {
	var valid []models.CatalogTemplate
	for i := range templates {
		t := &templates[i]
		if t.Name == "" {
			continue
		}
		// Assign defaults for missing fields.
		if t.ID == "" {
			t.ID = strings.ToLower(strings.ReplaceAll(t.Name, " ", "-"))
		}
		if t.Platform == "" {
			t.Platform = "linux"
		}
		if t.Type == "" {
			t.Type = "container"
		}
		if t.RestartPolicy == "" {
			t.RestartPolicy = "unless-stopped"
		}
		if t.Category == "" {
			t.Category = "other"
		}
		valid = append(valid, *t)
	}
	if len(valid) == 0 {
		return nil, fmt.Errorf("no valid templates found in import data")
	}
	return valid, nil
}
