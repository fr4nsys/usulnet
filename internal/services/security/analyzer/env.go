// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package analyzer

import (
	"context"
	"regexp"
	"strings"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/security"
)

// EnvAnalyzer checks for secrets exposed in environment variables
type EnvAnalyzer struct {
	security.BaseAnalyzer

	// SecretPatterns are patterns that indicate a secret variable
	secretPatterns []*regexp.Regexp

	// KnownSafePatterns are patterns that look like secrets but are safe
	safePatterns []*regexp.Regexp
}

// NewEnvAnalyzer creates a new environment analyzer
func NewEnvAnalyzer() *EnvAnalyzer {
	a := &EnvAnalyzer{
		BaseAnalyzer: security.NewBaseAnalyzer(
			"env",
			"Checks for secrets and sensitive data exposed in environment variables",
		),
	}

	// Compile secret patterns
	for _, pattern := range security.SecretPatterns {
		// Case insensitive match
		re, err := regexp.Compile("(?i)" + pattern)
		if err == nil {
			a.secretPatterns = append(a.secretPatterns, re)
		}
	}

	// Known safe patterns (variables that look like secrets but are safe)
	safePatterns := []string{
		`^PATH$`,
		`^HOME$`,
		`^USER$`,
		`^HOSTNAME$`,
		`^TERM$`,
		`^SHELL$`,
		`^PWD$`,
		`^LANG$`,
		`^LC_`,
		`^TZ$`,
		`^GOPATH$`,
		`^NODE_ENV$`,
		`^RAILS_ENV$`,
		`^ENVIRONMENT$`,
		`^ENV$`,
		`_FILE$`, // Docker secrets convention: *_FILE points to file with secret
	}
	for _, pattern := range safePatterns {
		re, err := regexp.Compile("(?i)" + pattern)
		if err == nil {
			a.safePatterns = append(a.safePatterns, re)
		}
	}

	return a
}

// Analyze checks the container for secrets in environment variables
func (a *EnvAnalyzer) Analyze(ctx context.Context, data *security.ContainerData) ([]security.Issue, error) {
	if !a.IsEnabled() {
		return nil, nil
	}

	var issues []security.Issue

	// Get the check definition
	checks := models.DefaultSecurityChecks()
	var secretCheck models.SecurityCheck
	for _, c := range checks {
		if c.ID == models.CheckSecretsInEnv {
			secretCheck = c
			break
		}
	}

	// Track suspicious variables
	suspiciousVars := make([]suspiciousEnvVar, 0)

	for _, env := range data.Env {
		// Parse NAME=VALUE
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		name := parts[0]
		value := parts[1]

		// Skip empty values
		if value == "" {
			continue
		}

		// Skip safe patterns
		if a.isSafeVariable(name) {
			continue
		}

		// Check if variable name suggests it's a secret
		if a.isSecretVariableName(name) {
			// Check if the value looks like a real secret
			if a.looksLikeSecret(value) {
				suspiciousVars = append(suspiciousVars, suspiciousEnvVar{
					Name:       name,
					Reason:     "Variable name suggests secret and value appears to be sensitive",
					Severity:   models.IssueSeverityHigh,
					Confidence: "high",
				})
			} else {
				// Name suggests secret but value might be a placeholder or reference
				suspiciousVars = append(suspiciousVars, suspiciousEnvVar{
					Name:       name,
					Reason:     "Variable name suggests it may contain sensitive data",
					Severity:   models.IssueSeverityMedium,
					Confidence: "medium",
				})
			}
		} else if a.looksLikeSecret(value) {
			// Value looks like a secret even if name doesn't indicate it
			suspiciousVars = append(suspiciousVars, suspiciousEnvVar{
				Name:       name,
				Reason:     "Value appears to be a secret (high entropy or matches secret patterns)",
				Severity:   models.IssueSeverityMedium,
				Confidence: "low",
			})
		}
	}

	// Report issues
	if len(suspiciousVars) > 0 {
		// Group by severity
		highSeverity := make([]string, 0)
		mediumSeverity := make([]string, 0)

		for _, v := range suspiciousVars {
			if v.Severity == models.IssueSeverityHigh {
				highSeverity = append(highSeverity, v.Name)
			} else {
				mediumSeverity = append(mediumSeverity, v.Name)
			}
		}

		// Report high severity issues
		if len(highSeverity) > 0 {
			issues = append(issues, security.NewIssue(secretCheck,
				"Container has environment variables that appear to contain plaintext secrets. "+
					"Secrets in environment variables are visible in process listings, logs, and docker inspect output.").
				WithDetail("container", data.Name).
				WithDetail("suspicious_variables", highSeverity).
				WithDetail("recommendation", "Use Docker secrets, mounted secret files, or a secrets manager"))
		}

		// Report medium severity issues separately with lower penalty
		if len(mediumSeverity) > 0 && len(highSeverity) == 0 {
			issues = append(issues, security.Issue{
				CheckID:     models.CheckSecretsInEnv,
				Severity:    models.IssueSeverityMedium,
				Category:    models.IssueCategorySecurity,
				Title:       "Possible Secrets in Environment",
				Description: "Container has environment variables that may contain sensitive data. Review to ensure no secrets are exposed.",
				Recommendation: "If these contain secrets, use Docker secrets or mounted secret files instead.",
				Penalty:     10,
			}.WithDetail("container", data.Name).
				WithDetail("variables_to_review", mediumSeverity))
		}
	}

	return issues, nil
}

// suspiciousEnvVar holds information about a potentially dangerous env var
type suspiciousEnvVar struct {
	Name       string
	Reason     string
	Severity   models.IssueSeverity
	Confidence string // high, medium, low
}

// isSafeVariable checks if a variable name is known to be safe
func (a *EnvAnalyzer) isSafeVariable(name string) bool {
	for _, pattern := range a.safePatterns {
		if pattern.MatchString(name) {
			return true
		}
	}
	return false
}

// isSecretVariableName checks if a variable name suggests it contains a secret
func (a *EnvAnalyzer) isSecretVariableName(name string) bool {
	name = strings.ToLower(name)

	for _, pattern := range a.secretPatterns {
		if pattern.MatchString(name) {
			return true
		}
	}
	return false
}

// looksLikeSecret checks if a value looks like an actual secret
func (a *EnvAnalyzer) looksLikeSecret(value string) bool {
	// Skip obviously non-secret values
	if value == "" || value == "true" || value == "false" {
		return false
	}

	// Skip single words (likely configuration values)
	if !strings.ContainsAny(value, "0123456789!@#$%^&*") && len(value) < 12 {
		return false
	}

	// Skip if it looks like a URL without credentials
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		if !strings.Contains(value, "@") {
			return false
		}
	}

	// Check for common placeholder patterns
	placeholders := []string{
		"changeme",
		"CHANGE_ME",
		"your-",
		"your_",
		"xxx",
		"***",
		"example",
		"placeholder",
		"REPLACE",
		"INSERT",
		"<",
		">",
		"${",
		"{{",
	}
	valueLower := strings.ToLower(value)
	for _, p := range placeholders {
		if strings.Contains(valueLower, strings.ToLower(p)) {
			return false
		}
	}

	// Check for high entropy (random-looking strings)
	if len(value) >= 16 && hasHighEntropy(value) {
		return true
	}

	// Check for common secret patterns
	secretPatterns := []*regexp.Regexp{
		// API keys
		regexp.MustCompile(`^[A-Za-z0-9]{32,}$`),
		// UUID-like
		regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
		// Base64 encoded (at least 20 chars)
		regexp.MustCompile(`^[A-Za-z0-9+/]{20,}={0,2}$`),
		// JWT tokens
		regexp.MustCompile(`^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`),
		// AWS access keys
		regexp.MustCompile(`^AKIA[0-9A-Z]{16}$`),
		// Private keys
		regexp.MustCompile(`-----BEGIN .* PRIVATE KEY-----`),
	}

	for _, pattern := range secretPatterns {
		if pattern.MatchString(value) {
			return true
		}
	}

	return false
}

// hasHighEntropy checks if a string has high entropy (appears random)
func hasHighEntropy(s string) bool {
	if len(s) < 8 {
		return false
	}

	// Count character types
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSpecial := false
	uniqueChars := make(map[rune]bool)

	for _, c := range s {
		uniqueChars[c] = true
		switch {
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}

	// Calculate diversity score
	typeCount := 0
	if hasLower {
		typeCount++
	}
	if hasUpper {
		typeCount++
	}
	if hasDigit {
		typeCount++
	}
	if hasSpecial {
		typeCount++
	}

	// High entropy if:
	// - At least 3 character types
	// - High ratio of unique characters
	uniqueRatio := float64(len(uniqueChars)) / float64(len(s))
	return typeCount >= 3 && uniqueRatio > 0.5
}
