// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"net/http"

	yarasvc "github.com/fr4nsys/usulnet/internal/services/yara"
	yaratpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/yara"
)

// requireYARASvc returns the yara service or renders a "not
// configured" error. Same nil-safe pattern as the rest of the v26.5.x
// modules.
func (h *Handler) requireYARASvc(w http.ResponseWriter, r *http.Request) *yarasvc.Service {
	if reg, ok := h.services.(*ServiceRegistry); ok && reg.yaraSvc != nil {
		return reg.yaraSvc
	}
	h.RenderErrorTempl(w, r, http.StatusServiceUnavailable,
		"YARA Scanner Not Configured",
		"The YARA scanner is not enabled in this build. It requires the recon-toolkit image.")
	return nil
}

// yaraToolkitImage returns the configured toolkit image name for the
// info panel.
func (h *Handler) yaraToolkitImage() string {
	if reg, ok := h.services.(*ServiceRegistry); ok {
		return reg.yaraToolkitImage
	}
	return ""
}

// YARAScanTempl renders /scan/yara. GET shows the form; POST submits
// a scan and renders the result inline.
func (h *Handler) YARAScanTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireYARASvc(w, r)
	if svc == nil {
		return
	}

	rulesets, err := yarasvc.ListRulesets()
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError,
			"Error", "Failed to list YARA rulesets: "+err.Error())
		return
	}

	pageData := h.prepareTemplPageData(r, "YARA Scanner", "yara")
	view := yaratpl.PageData{
		PageData:     pageData,
		Rulesets:     rulesets,
		Form:         yaratpl.FormView{Mode: "host"},
		ToolkitImage: h.yaraToolkitImage(),
	}

	if r.Method == http.MethodPost {
		h.runYARAScan(svc, r, &view)
	}

	h.renderTempl(w, r, yaratpl.Scan(view))
}

// runYARAScan executes the scan and mutates view to contain either the
// result, an error, or nothing (form re-render). The handler always
// re-renders the page after the scan — there is no redirect because
// results live with the request, not in the DB.
func (h *Handler) runYARAScan(svc *yarasvc.Service, r *http.Request, view *yaratpl.PageData) {
	if err := r.ParseForm(); err != nil {
		view.Error = "Failed to parse form: " + err.Error()
		return
	}
	view.Form = yaratpl.FormView{
		Ruleset:     r.FormValue("ruleset"),
		Mode:        r.FormValue("mode"),
		HostPath:    r.FormValue("host_path"),
		ContainerID: r.FormValue("container_id"),
		Path:        r.FormValue("path"),
	}

	target := yarasvc.ScanTarget{}
	switch view.Form.Mode {
	case "container":
		target.ContainerID = view.Form.ContainerID
		target.Path = view.Form.Path
	default:
		target.HostPath = view.Form.HostPath
	}

	res, err := svc.Scan(r.Context(), target, view.Form.Ruleset)
	if err != nil {
		view.Error = "Scan failed: " + err.Error()
		return
	}

	matchViews := make([]yaratpl.MatchView, len(res.Matches))
	for i, m := range res.Matches {
		matchViews[i] = yaratpl.MatchView{
			Rule:      m.Rule,
			Namespace: m.Namespace,
			Tags:      m.Tags,
			Target:    m.Target,
		}
	}
	view.Result = &yaratpl.ResultView{
		Ruleset:   res.Ruleset,
		Target:    res.Target,
		Duration:  res.Duration,
		StartedAt: res.StartedAt.Format("2006-01-02 15:04:05"),
		Matches:   matchViews,
	}
}
