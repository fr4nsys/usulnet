// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package analyzer

import (
	"context"
	"strings"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/security"
)

// UserAnalyzer checks if containers run as non-root user
type UserAnalyzer struct {
	security.BaseAnalyzer
}

// NewUserAnalyzer creates a new user analyzer
func NewUserAnalyzer() *UserAnalyzer {
	return &UserAnalyzer{
		BaseAnalyzer: security.NewBaseAnalyzer(
			"user",
			"Checks if container runs as non-root user for security isolation",
		),
	}
}

// Analyze checks the container for user-related security issues
func (a *UserAnalyzer) Analyze(ctx context.Context, data *security.ContainerData) ([]security.Issue, error) {
	if !a.IsEnabled() {
		return nil, nil
	}

	var issues []security.Issue

	// Get the check definition
	checks := models.DefaultSecurityChecks()
	var userCheck models.SecurityCheck
	for _, c := range checks {
		if c.ID == models.CheckRootUser {
			userCheck = c
			break
		}
	}

	// Check if running as root
	if isRootUser(data.User) {
		issues = append(issues, security.NewIssue(userCheck,
			"Container is running as root user (UID 0). Running as root "+
				"increases the risk of container escape vulnerabilities and "+
				"gives the process unnecessary privileges.").
			WithDetail("container", data.Name).
			WithDetail("user", normalizeUserDisplay(data.User)).
			WithDetail("recommendation", "Add USER instruction in Dockerfile or --user flag"))
	}

	return issues, nil
}

// isRootUser checks if the user specification indicates root
func isRootUser(user string) bool {
	// Empty user means root (default)
	if user == "" {
		return true
	}

	// Trim whitespace
	user = strings.TrimSpace(user)

	// Check common root specifications
	switch strings.ToLower(user) {
	case "root", "0", "0:0":
		return true
	}

	// Check for UID 0 in various formats
	// Format can be: user, user:group, uid, uid:gid
	parts := strings.Split(user, ":")
	if len(parts) > 0 {
		uid := strings.TrimSpace(parts[0])
		if uid == "0" || strings.ToLower(uid) == "root" {
			return true
		}
	}

	return false
}

// normalizeUserDisplay returns a display string for the user
func normalizeUserDisplay(user string) string {
	if user == "" {
		return "root (default)"
	}
	return user
}

// KnownNonRootImages contains images that are known to run as non-root by default
// This can be used to reduce false positives
var KnownNonRootImages = map[string]bool{
	"nginx":       false, // runs as root by default
	"redis":       false, // runs as root by default
	"postgres":    false, // runs as root, switches to postgres
	"mysql":       false, // runs as root, switches to mysql
	"mongo":       false, // runs as root by default
	"node":        false, // runs as root by default
	"python":      false, // runs as root by default
	"golang":      false, // runs as root by default
	"alpine":      false, // runs as root by default
	"ubuntu":      false, // runs as root by default
	"debian":      false, // runs as root by default
	"bitnami/":    true,  // bitnami images run as non-root (1001)
	"grafana/":    true,  // grafana runs as grafana user (472)
	"prom/":       true,  // prometheus images run as nobody
	"gcr.io/distroless/": true, // distroless runs as nonroot
}
