// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	comptmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/compliance"
)

// ruleDescriptions maps rule identifiers to human-readable descriptions.
var ruleDescriptions = map[string]string{
	"no_root":                "Containers must not run as root user",
	"require_healthcheck":    "Containers must define a healthcheck",
	"no_privileged":          "Containers cannot run in privileged mode",
	"require_memory_limit":   "Containers must have memory limits set",
	"require_cpu_limit":      "Containers must have CPU limits set",
	"no_host_network":        "Containers cannot use host network mode",
	"no_host_pid":            "Containers cannot use host PID namespace",
	"no_secrets_env":         "Environment variables must not contain secrets",
	"require_readonly_fs":    "Container root filesystem must be read-only",
	"no_cap_add":             "Containers cannot add Linux capabilities",
	"require_labels":         "Containers must have required labels",
	"image_allowlist":        "Only approved images can be used",
	"no_latest_tag":          "Containers must use specific image tags",
	"require_restart_policy": "Containers must have a restart policy",
}

// ComplianceTempl renders the compliance policies page.
func (h *Handler) ComplianceTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Compliance Policies", "compliance")

	var policies []comptmpl.CompliancePolicyView
	var violations []comptmpl.ViolationView
	stats := comptmpl.ComplianceStats{}

	if h.complianceRepo != nil {
		dbPolicies, err := h.complianceRepo.ListPolicies(ctx)
		if err == nil {
			for _, p := range dbPolicies {
				violationCount, _ := h.complianceRepo.CountViolationsByPolicy(ctx, p.ID)
				pv := comptmpl.CompliancePolicyView{
					ID:          p.ID.String(),
					Name:        p.Name,
					Description: p.Description,
					Category:    p.Category,
					Severity:    p.Severity,
					Rule:        p.Rule,
					RuleConfig:  ruleDescriptions[p.Rule],
					IsEnabled:   p.IsEnabled,
					IsEnforced:  p.IsEnforced,
					Violations:  violationCount,
					CreatedAt:   p.CreatedAt.Format("Jan 02 15:04"),
				}
				if p.LastCheckAt != nil {
					pv.LastCheckAt = p.LastCheckAt.Format("Jan 02 15:04")
				}
				policies = append(policies, pv)
				stats.TotalPolicies++
				if p.IsEnabled {
					stats.EnabledPolicies++
				}
				if p.IsEnforced {
					stats.EnforcedPolicies++
				}
			}
		}

		dbViolations, err := h.complianceRepo.ListViolations(ctx, nil)
		if err == nil {
			for _, v := range dbViolations {
				violations = append(violations, comptmpl.ViolationView{
					ID:            v.ID.String(),
					PolicyID:      v.PolicyID.String(),
					PolicyName:    v.PolicyName,
					ContainerID:   v.ContainerID,
					ContainerName: v.ContainerName,
					Severity:      v.Severity,
					Message:       v.Message,
					Details:       v.Details,
					Status:        v.Status,
					DetectedAt:    v.DetectedAt.Format("Jan 02 15:04"),
				})
				stats.TotalViolations++
				if v.Status == "open" {
					stats.OpenViolations++
				}
			}
		}
	}

	if stats.TotalPolicies > 0 {
		compliant := stats.TotalPolicies - stats.OpenViolations
		if compliant < 0 {
			compliant = 0
		}
		stats.ComplianceRate = fmt.Sprintf("%.0f%%", float64(compliant)/float64(stats.TotalPolicies)*100)
	} else {
		stats.ComplianceRate = "N/A"
	}

	data := comptmpl.ComplianceData{
		PageData:   pageData,
		Policies:   policies,
		Violations: violations,
		Stats:      stats,
		ActiveTab:  r.URL.Query().Get("tab"),
	}

	h.renderTempl(w, r, comptmpl.Compliance(data))
}

// CompliancePolicyCreate creates a new compliance policy.
func (h *Handler) CompliancePolicyCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		http.Redirect(w, r, "/compliance", http.StatusSeeOther)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		h.setFlash(w, r, "error", "Policy name is required")
		http.Redirect(w, r, "/compliance", http.StatusSeeOther)
		return
	}

	if h.complianceRepo != nil {
		p := &CompliancePolicyRecord{
			ID:          uuid.New(),
			Name:        name,
			Description: strings.TrimSpace(r.FormValue("description")),
			Category:    r.FormValue("category"),
			Severity:    r.FormValue("severity"),
			Rule:        r.FormValue("rule"),
			IsEnabled:   true,
			IsEnforced:  r.FormValue("is_enforced") == "on",
		}
		if err := h.complianceRepo.CreatePolicy(r.Context(), p); err != nil {
			h.setFlash(w, r, "error", "Failed to create policy: "+err.Error())
			http.Redirect(w, r, "/compliance", http.StatusSeeOther)
			return
		}
	}

	h.setFlash(w, r, "success", "Compliance policy '"+name+"' created")
	http.Redirect(w, r, "/compliance", http.StatusSeeOther)
}

// CompliancePolicyToggle toggles a policy enabled/disabled.
func (h *Handler) CompliancePolicyToggle(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if h.complianceRepo != nil {
		uid, err := uuid.Parse(id)
		if err == nil {
			newState, err := h.complianceRepo.TogglePolicy(r.Context(), uid)
			if err == nil {
				status := "disabled"
				if newState {
					status = "enabled"
				}
				h.setFlash(w, r, "success", "Policy "+status)
			} else {
				h.setFlash(w, r, "error", "Policy not found")
			}
		}
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/compliance")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/compliance", http.StatusSeeOther)
}

// CompliancePolicyDelete deletes a compliance policy.
func (h *Handler) CompliancePolicyDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if h.complianceRepo != nil {
		uid, err := uuid.Parse(id)
		if err == nil {
			h.complianceRepo.DeletePolicy(r.Context(), uid)
		}
	}

	h.setFlash(w, r, "success", "Policy deleted")

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/compliance")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/compliance", http.StatusSeeOther)
}

// ComplianceScan runs a compliance check against all running containers.
func (h *Handler) ComplianceScan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	containerSvc := h.services.Containers()
	if containerSvc == nil {
		h.setFlash(w, r, "error", "Container service unavailable")
		http.Redirect(w, r, "/compliance", http.StatusSeeOther)
		return
	}

	containers, err := containerSvc.List(ctx, nil)
	if err != nil {
		h.setFlash(w, r, "error", "Failed to list containers: "+err.Error())
		http.Redirect(w, r, "/compliance", http.StatusSeeOther)
		return
	}

	newViolations := 0

	if h.complianceRepo != nil {
		now := time.Now()
		dbPolicies, err := h.complianceRepo.ListPolicies(ctx)
		if err == nil {
			for _, p := range dbPolicies {
				if !p.IsEnabled {
					continue
				}
				h.complianceRepo.UpdateLastCheck(ctx, p.ID, now)

				for _, c := range containers {
					violation := checkCompliance(&compliancePolicy{
						Rule:     p.Rule,
						Severity: p.Severity,
						Name:     p.Name,
					}, &c)
					if violation != "" {
						exists, _ := h.complianceRepo.ViolationExistsForPolicy(ctx, p.ID, c.ID)
						if !exists {
							v := &ComplianceViolationRecord{
								PolicyID:      p.ID,
								PolicyName:    p.Name,
								ContainerID:   c.ID,
								ContainerName: c.Name,
								Severity:      p.Severity,
								Message:       violation,
								Status:        "open",
								DetectedAt:    now,
							}
							if err := h.complianceRepo.CreateViolation(ctx, v); err == nil {
								newViolations++
							}
						}
					}
				}
			}
		}
	}

	h.setFlash(w, r, "success", fmt.Sprintf("Compliance scan complete: %d containers checked, %d new violations", len(containers), newViolations))

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/compliance?tab=violations")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/compliance?tab=violations", http.StatusSeeOther)
}

// ComplianceViolationAcknowledge acknowledges a violation.
func (h *Handler) ComplianceViolationAcknowledge(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.updateComplianceViolationStatus(r, id, "acknowledged"); err != nil {
		h.setFlash(w, r, "error", "Failed to acknowledge violation: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Violation acknowledged")
	}
	redirectCompliance(w, r)
}

// ComplianceViolationResolve marks a violation as resolved.
func (h *Handler) ComplianceViolationResolve(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.updateComplianceViolationStatus(r, id, "resolved"); err != nil {
		h.setFlash(w, r, "error", "Failed to resolve violation: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Violation resolved")
	}
	redirectCompliance(w, r)
}

// ComplianceViolationExempt marks a violation as exempted.
func (h *Handler) ComplianceViolationExempt(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.updateComplianceViolationStatus(r, id, "exempted"); err != nil {
		h.setFlash(w, r, "error", "Failed to exempt violation: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Violation exempted")
	}
	redirectCompliance(w, r)
}

func (h *Handler) updateComplianceViolationStatus(r *http.Request, id, status string) error {
	if h.complianceRepo == nil {
		return fmt.Errorf("compliance service not configured")
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid violation ID")
	}
	var resolvedBy *uuid.UUID
	if status == "resolved" || status == "exempted" {
		if user := GetUserFromContext(r.Context()); user != nil {
			if userID, parseErr := uuid.Parse(user.ID); parseErr == nil {
				resolvedBy = &userID
			}
		}
	}
	return h.complianceRepo.UpdateViolationStatus(r.Context(), uid, status, resolvedBy)
}

func redirectCompliance(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/compliance?tab=violations")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/compliance?tab=violations", http.StatusSeeOther)
}

// compliancePolicy is a minimal struct used for rule checking.
type compliancePolicy struct {
	Rule     string
	Severity string
	Name     string
}

// checkCompliance checks a container against a policy rule.
func checkCompliance(p *compliancePolicy, c *ContainerView) string {
	switch p.Rule {
	case "require_healthcheck":
		if c.Health == "" || c.Health == "none" {
			return fmt.Sprintf("Container '%s' has no healthcheck defined", c.Name)
		}
	case "require_memory_limit":
		if c.MemoryLimit == 0 {
			return fmt.Sprintf("Container '%s' has no memory limit set", c.Name)
		}
	case "no_host_network":
		for _, net := range c.Networks {
			if net == "host" {
				return fmt.Sprintf("Container '%s' is using host network mode", c.Name)
			}
		}
	case "no_latest_tag":
		if strings.HasSuffix(c.Image, ":latest") || !strings.Contains(c.Image, ":") {
			return fmt.Sprintf("Container '%s' uses 'latest' or untagged image: %s", c.Name, c.Image)
		}
	case "require_restart_policy":
		if c.RestartPolicy == "" || c.RestartPolicy == "no" {
			return fmt.Sprintf("Container '%s' has no restart policy set", c.Name)
		}
	case "require_labels":
		if len(c.Labels) == 0 {
			return fmt.Sprintf("Container '%s' has no labels defined", c.Name)
		}
	case "no_secrets_env":
		for _, env := range c.Env {
			key := strings.ToLower(env.Key)
			if strings.Contains(key, "password") || strings.Contains(key, "secret") || strings.Contains(key, "api_key") || strings.Contains(key, "token") {
				if env.Value != "" && !strings.HasPrefix(env.Value, "${") {
					return fmt.Sprintf("Container '%s' has potential secret in env var: %s", c.Name, env.Key)
				}
			}
		}
	case "no_privileged":
		if c.SecurityScore > 0 && c.SecurityScore < 30 {
			return fmt.Sprintf("Container '%s' has critically low security score (%d) - may be running in privileged mode", c.Name, c.SecurityScore)
		}
	case "no_root", "require_cpu_limit", "no_host_pid", "require_readonly_fs", "no_cap_add":
		if c.SecurityScore > 0 && c.SecurityScore < 50 {
			return fmt.Sprintf("Container '%s' has low security score (%d) - review security scan details", c.Name, c.SecurityScore)
		}
	case "image_allowlist":
		if !strings.Contains(c.Image, "/") && !strings.Contains(c.Image, ":") {
			return fmt.Sprintf("Container '%s' uses unqualified image: %s", c.Name, c.Image)
		}
	}
	return ""
}
