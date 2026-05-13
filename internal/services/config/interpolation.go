// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package config

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
)

// Interpolator handles variable interpolation
type Interpolator struct {
	maxDepth int
}

// NewInterpolator creates a new Interpolator
func NewInterpolator() *Interpolator {
	return &Interpolator{
		maxDepth: 10, // Maximum recursion depth for nested interpolation
	}
}

// varPattern matches ${VAR_NAME} or $VAR_NAME patterns
var varPattern = regexp.MustCompile(`\$\{([A-Z][A-Z0-9_]*)\}|\$([A-Z][A-Z0-9_]*)`)

// Interpolate resolves variable references in a value
// Supports: ${VAR_NAME}, ${VAR_NAME:-default}, ${VAR_NAME:?error message}
func (i *Interpolator) Interpolate(ctx context.Context, value string, variables map[string]string) (string, []string, error) {
	return i.interpolateWithDepth(ctx, value, variables, 0, nil)
}

// interpolateWithDepth handles recursive interpolation with cycle detection
func (i *Interpolator) interpolateWithDepth(ctx context.Context, value string, variables map[string]string, depth int, visited []string) (string, []string, error) {
	if depth > i.maxDepth {
		return "", nil, errors.InvalidInput("maximum interpolation depth exceeded - possible circular reference")
	}

	var references []string
	result := value

	// Find all variable references
	matches := findAllVariables(value)
	if len(matches) == 0 {
		return value, nil, nil
	}

	for _, match := range matches {
		varName := match.Name
		references = append(references, varName)

		// Check for circular reference
		for _, v := range visited {
			if v == varName {
				return "", references, errors.InvalidInput(fmt.Sprintf("circular reference detected: %s", strings.Join(append(visited, varName), " -> ")))
			}
		}

		// Get variable value
		varValue, exists := variables[varName]
		if !exists {
			// Handle default value syntax: ${VAR:-default}
			if match.Default != "" {
				varValue = match.Default
			} else if match.Required {
				// Handle required syntax: ${VAR:?error}
				errMsg := match.ErrorMsg
				if errMsg == "" {
					errMsg = fmt.Sprintf("variable %s is required but not set", varName)
				}
				return "", references, errors.InvalidInput(errMsg)
			} else {
				// Variable not found and no default, leave as is or use empty
				varValue = ""
			}
		}

		// Recursively interpolate the value
		newVisited := append(visited, varName)
		interpolatedValue, nestedRefs, err := i.interpolateWithDepth(ctx, varValue, variables, depth+1, newVisited)
		if err != nil {
			return "", references, err
		}

		references = append(references, nestedRefs...)
		result = strings.Replace(result, match.Full, interpolatedValue, 1)
	}

	return result, unique(references), nil
}

// InterpolateAll interpolates all variables and returns results
func (i *Interpolator) InterpolateAll(ctx context.Context, variables []*models.ConfigVariable) (*models.InterpolateResult, error) {
	// Build variable map
	varMap := make(map[string]string)
	for _, v := range variables {
		varMap[v.Name] = v.Value
	}

	result := &models.InterpolateResult{
		Values:       make([]models.InterpolatedValue, 0, len(variables)),
		Errors:       []string{},
		CircularRefs: []string{},
	}

	// Interpolate each variable
	for _, v := range variables {
		resolved, refs, err := i.Interpolate(ctx, v.Value, varMap)

		iv := models.InterpolatedValue{
			Name:          v.Name,
			OriginalValue: v.Value,
			ResolvedValue: resolved,
			IsSecret:      v.Type == models.VariableTypeSecret,
			References:    refs,
		}

		if err != nil {
			if strings.Contains(err.Error(), "circular reference") {
				result.CircularRefs = append(result.CircularRefs, v.Name)
			}
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", v.Name, err.Error()))
			iv.ResolvedValue = v.Value // Use original on error
		}

		result.Values = append(result.Values, iv)
	}

	return result, nil
}

// ValidateInterpolation checks if all variable references can be resolved
func (i *Interpolator) ValidateInterpolation(ctx context.Context, value string, variables map[string]string) error {
	_, _, err := i.Interpolate(ctx, value, variables)
	return err
}

// ExtractReferences extracts all variable names referenced in a value
func (i *Interpolator) ExtractReferences(value string) []string {
	matches := findAllVariables(value)
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m.Name)
	}
	return unique(names)
}

// HasReferences checks if a value contains variable references
func (i *Interpolator) HasReferences(value string) bool {
	return varPattern.MatchString(value)
}

// ============================================================================
// Variable Match Types
// ============================================================================

// varMatch represents a parsed variable reference
type varMatch struct {
	Full     string // Full match: ${VAR:-default}
	Name     string // Variable name: VAR
	Default  string // Default value (if any)
	Required bool   // Whether variable is required (:?)
	ErrorMsg string // Custom error message for required
}

// advancedVarPattern matches ${VAR}, ${VAR:-default}, ${VAR:?error}
var advancedVarPattern = regexp.MustCompile(`\$\{([A-Z][A-Z0-9_]*)(?:(:[-?])([^}]*))?\}|\$([A-Z][A-Z0-9_]*)`)

// findAllVariables finds all variable references in a string
func findAllVariables(value string) []varMatch {
	matches := advancedVarPattern.FindAllStringSubmatch(value, -1)
	result := make([]varMatch, 0, len(matches))

	for _, match := range matches {
		vm := varMatch{
			Full: match[0],
		}

		// Check which pattern matched
		if match[1] != "" {
			// ${VAR} or ${VAR:-default} or ${VAR:?error}
			vm.Name = match[1]
			if match[2] == ":-" {
				vm.Default = match[3]
			} else if match[2] == ":?" {
				vm.Required = true
				vm.ErrorMsg = match[3]
			}
		} else if match[4] != "" {
			// $VAR
			vm.Name = match[4]
		}

		if vm.Name != "" {
			result = append(result, vm)
		}
	}

	return result
}

// unique returns unique strings from a slice
func unique(strs []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(strs))
	for _, s := range strs {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// ============================================================================
// Environment File Generation
// ============================================================================

// GenerateEnvFile generates .env file content from variables
func GenerateEnvFile(variables []*models.ConfigVariable) string {
	var sb strings.Builder

	sb.WriteString("# Generated by usulnet Config Manager\n")
	sb.WriteString("# Do not edit manually - changes will be overwritten\n\n")

	for _, v := range variables {
		// Add description as comment if present
		if v.Description != nil && *v.Description != "" {
			sb.WriteString("# ")
			sb.WriteString(*v.Description)
			sb.WriteString("\n")
		}

		// Write variable
		sb.WriteString(v.Name)
		sb.WriteString("=")

		// Quote value if it contains special characters
		value := v.Value
		if needsQuoting(value) {
			value = fmt.Sprintf(`"%s"`, escapeValue(value))
		}
		sb.WriteString(value)
		sb.WriteString("\n")
	}

	return sb.String()
}

// GenerateDockerEnv generates environment for Docker container
func GenerateDockerEnv(variables []*models.ConfigVariable) []string {
	result := make([]string, 0, len(variables))
	for _, v := range variables {
		result = append(result, fmt.Sprintf("%s=%s", v.Name, v.Value))
	}
	return result
}

// GenerateDockerLabels generates labels for tracking config
func GenerateDockerLabels(templateName string, hash string) map[string]string {
	return map[string]string{
		"usulnet.config.managed":  "true",
		"usulnet.config.template": templateName,
		"usulnet.config.hash":     hash,
	}
}

// needsQuoting checks if a value needs to be quoted
func needsQuoting(value string) bool {
	// Quote if contains spaces, special chars, or starts/ends with whitespace
	if strings.ContainsAny(value, " \t\n\"'\\$#") {
		return true
	}
	if len(value) > 0 && (value[0] == ' ' || value[len(value)-1] == ' ') {
		return true
	}
	return false
}

// escapeValue escapes special characters for quoted strings
func escapeValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	value = strings.ReplaceAll(value, "\t", `\t`)
	return value
}

// ============================================================================
// Compose File Processing
// ============================================================================

// ProcessComposeEnvironment processes environment variables in compose format
func ProcessComposeEnvironment(env interface{}, variables map[string]string, interpolator *Interpolator) ([]string, error) {
	ctx := context.Background()
	var result []string

	switch e := env.(type) {
	case []interface{}:
		// Array format: ["VAR=value", "VAR2"]
		for _, item := range e {
			str, ok := item.(string)
			if !ok {
				continue
			}

			// Check if it's KEY=VALUE or just KEY
			if strings.Contains(str, "=") {
				parts := strings.SplitN(str, "=", 2)
				value, _, err := interpolator.Interpolate(ctx, parts[1], variables)
				if err != nil {
					return nil, err
				}
				result = append(result, fmt.Sprintf("%s=%s", parts[0], value))
			} else {
				// Just a key, look up in variables
				if val, ok := variables[str]; ok {
					result = append(result, fmt.Sprintf("%s=%s", str, val))
				}
			}
		}

	case map[string]interface{}:
		// Map format: {VAR: value}
		for key, value := range e {
			if value == nil {
				// Key only, look up in variables
				if val, ok := variables[key]; ok {
					result = append(result, fmt.Sprintf("%s=%s", key, val))
				}
			} else {
				str, ok := value.(string)
				if !ok {
					str = fmt.Sprintf("%v", value)
				}
				interpolated, _, err := interpolator.Interpolate(ctx, str, variables)
				if err != nil {
					return nil, err
				}
				result = append(result, fmt.Sprintf("%s=%s", key, interpolated))
			}
		}
	}

	return result, nil
}
