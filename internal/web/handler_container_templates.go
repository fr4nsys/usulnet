// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	tmplpkg "github.com/fr4nsys/usulnet/internal/web/templates/pages/templates"
)

// templateEnvVar represents an environment variable in a container template.
type templateEnvVar struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// ContainerTemplatesTempl renders the container templates page.
func (h *Handler) ContainerTemplatesTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Container Templates", "container-templates")

	var templates []tmplpkg.ContainerTemplateView
	stats := tmplpkg.TemplateStats{}
	var categories []string

	if h.containerTemplateRepo != nil {
		dbTemplates, err := h.containerTemplateRepo.List(ctx)
		if err == nil {
			categorySet := make(map[string]bool)
			for _, t := range dbTemplates {
				var envVars []tmplpkg.EnvVarView
				if len(t.EnvVars) > 0 {
					var evList []templateEnvVar
					if json.Unmarshal(t.EnvVars, &evList) == nil {
						for _, ev := range evList {
							envVars = append(envVars, tmplpkg.EnvVarView{
								Key:         ev.Key,
								Value:       ev.Value,
								Description: ev.Description,
								Required:    ev.Required,
							})
						}
					}
				}

				tv := tmplpkg.ContainerTemplateView{
					ID:            t.ID.String(),
					Name:          t.Name,
					Description:   t.Description,
					Category:      t.Category,
					Image:         t.Image,
					Tag:           t.Tag,
					Ports:         t.Ports,
					Volumes:       t.Volumes,
					EnvVars:       envVars,
					Network:       t.Network,
					RestartPolicy: t.RestartPolicy,
					Command:       t.Command,
					IsPublic:      t.IsPublic,
					UsageCount:    t.UsageCount,
					CreatedAt:     t.CreatedAt.Format("Jan 02 15:04"),
				}
				if t.CreatedBy != nil {
					tv.CreatedBy = t.CreatedBy.String()
				}
				templates = append(templates, tv)
				stats.TotalTemplates++
				if t.IsPublic {
					stats.PublicTemplates++
				}
				stats.TotalDeploys += t.UsageCount
				categorySet[t.Category] = true
			}

			for cat := range categorySet {
				categories = append(categories, cat)
			}
			stats.Categories = len(categories)
		}
	}

	data := tmplpkg.ContainerTemplatesData{
		PageData:   pageData,
		Templates:  templates,
		Categories: categories,
		Stats:      stats,
	}

	h.renderTempl(w, r, tmplpkg.ContainerTemplates(data))
}

// ContainerTemplateCreate creates a new container template.
// containerTemplateCreateForm captures the inputs of the create
// template form. Ports / Volumes / EnvVars come in as one entry per
// line in a textarea so they stay as raw strings here and are
// post-processed below — BindForm only handles single-value scalar
// conversions, not arbitrary text-to-slice parsing.
type containerTemplateCreateForm struct {
	Name          string `form:"name" validate:"required,min=1,max=200"`
	Description   string `form:"description"`
	Category      string `form:"category"`
	Image         string `form:"image" validate:"required"`
	Tag           string `form:"tag"`
	PortsRaw      string `form:"ports"`
	VolumesRaw    string `form:"volumes"`
	EnvVarsRaw    string `form:"env_vars"`
	Network       string `form:"network"`
	RestartPolicy string `form:"restart_policy"`
	Command       string `form:"command"`
	IsPublic      bool   `form:"is_public"`
}

func (h *Handler) ContainerTemplateCreate(w http.ResponseWriter, r *http.Request) {
	var form containerTemplateCreateForm
	if msg := BindForm(r, &form); msg != "" {
		h.setFlash(w, r, "error", msg)
		http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
		return
	}

	tag := form.Tag
	if tag == "" {
		tag = "latest"
	}

	ports := splitNonEmptyLines(form.PortsRaw)
	volumes := splitNonEmptyLines(form.VolumesRaw)
	envVars := parseEnvVarLines(form.EnvVarsRaw)
	envVarsJSON, _ := json.Marshal(envVars)

	if h.containerTemplateRepo != nil {
		t := &ContainerTemplateRecord{
			ID:            uuid.New(),
			Name:          form.Name,
			Description:   form.Description,
			Category:      form.Category,
			Image:         form.Image,
			Tag:           tag,
			Ports:         ports,
			Volumes:       volumes,
			EnvVars:       envVarsJSON,
			Network:       form.Network,
			RestartPolicy: form.RestartPolicy,
			Command:       form.Command,
			IsPublic:      form.IsPublic,
		}
		if err := h.containerTemplateRepo.Create(r.Context(), t); err != nil {
			h.setFlash(w, r, "error", "Failed to create template: "+err.Error())
			http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
			return
		}
	}

	h.setFlash(w, r, "success", "Container template '"+form.Name+"' created")
	http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
}

// splitNonEmptyLines breaks a textarea value into trimmed, non-empty
// lines. Used by handlers whose forms render one-entry-per-line
// textareas (ports, volumes, command args, etc.). Distinct from
// the splitLines helper in converters.go, which preserves
// whitespace for diff-style display.
func splitNonEmptyLines(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// parseEnvVarLines parses a textarea value of KEY=VALUE lines into
// templateEnvVar records. Lines without `=` keep their key with an
// empty value (operators sometimes paste a bare KEY expecting the
// host environment to populate it).
func parseEnvVarLines(raw string) []templateEnvVar {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []templateEnvVar
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		ev := templateEnvVar{Key: parts[0]}
		if len(parts) > 1 {
			ev.Value = parts[1]
		}
		out = append(out, ev)
	}
	return out
}

// ContainerTemplateDelete deletes a container template.
func (h *Handler) ContainerTemplateDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if h.containerTemplateRepo != nil {
		uid, err := uuid.Parse(id)
		if err == nil {
			h.containerTemplateRepo.Delete(r.Context(), uid)
		}
	}

	h.setFlash(w, r, "success", "Container template deleted")

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/container-templates")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
}

// ContainerTemplateDeploy deploys a container from a template.
func (h *Handler) ContainerTemplateDeploy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx := r.Context()

	if h.containerTemplateRepo == nil {
		h.setFlash(w, r, "error", "Template repository unavailable")
		http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
		return
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		h.setFlash(w, r, "error", "Invalid template ID")
		http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
		return
	}

	t, err := h.containerTemplateRepo.GetByID(ctx, uid)
	if err != nil {
		h.setFlash(w, r, "error", "Template not found")
		http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
		return
	}

	// Deploy the container using the container service
	containerSvc := h.services.Containers()
	if containerSvc == nil {
		h.setFlash(w, r, "error", "Container service unavailable")
		http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
		return
	}

	// Build environment variables as KEY=value lines
	var envLines []string
	if len(t.EnvVars) > 0 {
		var evList []templateEnvVar
		if json.Unmarshal(t.EnvVars, &evList) == nil {
			for _, ev := range evList {
				envLines = append(envLines, ev.Key+"="+ev.Value)
			}
		}
	}

	// Create container using the service
	containerName := strings.ReplaceAll(strings.ToLower(t.Name), " ", "-")
	imageRef := t.Image + ":" + t.Tag

	input := &ContainerCreateInput{
		Name:          containerName,
		Image:         imageRef,
		Ports:         t.Ports,
		Volumes:       t.Volumes,
		Environment:   strings.Join(envLines, "\n"),
		Network:       t.Network,
		Command:       t.Command,
		RestartPolicy: t.RestartPolicy,
	}

	containerID, err := containerSvc.Create(ctx, input)
	if err != nil {
		h.setFlash(w, r, "error", "Failed to create container: "+err.Error())
		http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
		return
	}

	// Start the container
	if err := containerSvc.Start(ctx, containerID); err != nil {
		h.setFlash(w, r, "warning", fmt.Sprintf("Container created (%s) but failed to start: %s", containerID[:12], err.Error()))
		http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
		return
	}

	// Increment usage count in DB
	h.containerTemplateRepo.IncrementUsage(ctx, uid)

	h.setFlash(w, r, "success", fmt.Sprintf("Container '%s' deployed from template '%s'", containerName, t.Name))

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/containers")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/containers", http.StatusSeeOther)
}
