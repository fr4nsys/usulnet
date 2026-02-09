// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package utils

import (
	"regexp"
	"strings"
	"unicode"
)

// Truncate truncates a string to the specified length with ellipsis
func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// TruncateMiddle truncates a string in the middle
func TruncateMiddle(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 5 {
		return s[:maxLen]
	}
	half := (maxLen - 3) / 2
	return s[:half] + "..." + s[len(s)-half:]
}

// Slugify converts a string to a URL-friendly slug
func Slugify(s string) string {
	s = strings.ToLower(s)
	s = strings.TrimSpace(s)

	// Replace spaces and underscores with hyphens
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "_", "-")

	// Remove non-alphanumeric characters except hyphens
	reg := regexp.MustCompile(`[^a-z0-9-]+`)
	s = reg.ReplaceAllString(s, "")

	// Remove consecutive hyphens
	reg = regexp.MustCompile(`-+`)
	s = reg.ReplaceAllString(s, "-")

	// Trim hyphens from edges
	s = strings.Trim(s, "-")

	return s
}

// Contains checks if a slice contains a string
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ContainsIgnoreCase checks if a slice contains a string (case-insensitive)
func ContainsIgnoreCase(slice []string, item string) bool {
	item = strings.ToLower(item)
	for _, s := range slice {
		if strings.ToLower(s) == item {
			return true
		}
	}
	return false
}

// Unique returns a slice with duplicate strings removed
func Unique(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// Filter filters a slice based on a predicate
func Filter(slice []string, predicate func(string) bool) []string {
	result := make([]string, 0)
	for _, s := range slice {
		if predicate(s) {
			result = append(result, s)
		}
	}
	return result
}

// Map applies a function to each element of a slice
func Map(slice []string, f func(string) string) []string {
	result := make([]string, len(slice))
	for i, s := range slice {
		result[i] = f(s)
	}
	return result
}

// SplitAndTrim splits a string and trims whitespace from each part
func SplitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// FirstNonEmpty returns the first non-empty string from the arguments
func FirstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// DefaultString returns the default value if s is empty
func DefaultString(s, defaultValue string) string {
	if s == "" {
		return defaultValue
	}
	return s
}

// IsEmpty checks if a string is empty or only whitespace
func IsEmpty(s string) bool {
	return strings.TrimSpace(s) == ""
}

// IsNotEmpty checks if a string is not empty
func IsNotEmpty(s string) bool {
	return !IsEmpty(s)
}

// PadLeft pads a string on the left with a specified character
func PadLeft(s string, length int, pad rune) string {
	if len(s) >= length {
		return s
	}
	return strings.Repeat(string(pad), length-len(s)) + s
}

// PadRight pads a string on the right with a specified character
func PadRight(s string, length int, pad rune) string {
	if len(s) >= length {
		return s
	}
	return s + strings.Repeat(string(pad), length-len(s))
}

// Capitalize capitalizes the first letter of a string
func Capitalize(s string) string {
	if s == "" {
		return s
	}
	runes := []rune(s)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

// ToCamelCase converts a string to camelCase
func ToCamelCase(s string) string {
	words := regexp.MustCompile(`[-_\s]+`).Split(s, -1)
	for i := 1; i < len(words); i++ {
		words[i] = Capitalize(strings.ToLower(words[i]))
	}
	words[0] = strings.ToLower(words[0])
	return strings.Join(words, "")
}

// ToSnakeCase converts a string to snake_case
func ToSnakeCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) {
			if i > 0 {
				result.WriteRune('_')
			}
			result.WriteRune(unicode.ToLower(r))
		} else if r == '-' || r == ' ' {
			result.WriteRune('_')
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// MaskString masks part of a string (useful for secrets)
func MaskString(s string, visibleStart, visibleEnd int) string {
	if len(s) <= visibleStart+visibleEnd {
		return strings.Repeat("*", len(s))
	}
	masked := s[:visibleStart] + strings.Repeat("*", len(s)-visibleStart-visibleEnd) + s[len(s)-visibleEnd:]
	return masked
}

// MaskEmail masks an email address
func MaskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return MaskString(email, 1, 1)
	}
	local := parts[0]
	domain := parts[1]
	if len(local) <= 2 {
		return local + "@" + domain
	}
	return local[:1] + strings.Repeat("*", len(local)-2) + local[len(local)-1:] + "@" + domain
}

// RemovePrefix removes a prefix from a string if present
func RemovePrefix(s, prefix string) string {
	return strings.TrimPrefix(s, prefix)
}

// RemoveSuffix removes a suffix from a string if present
func RemoveSuffix(s, suffix string) string {
	return strings.TrimSuffix(s, suffix)
}

// ExtractBetween extracts text between two delimiters
func ExtractBetween(s, start, end string) string {
	startIdx := strings.Index(s, start)
	if startIdx == -1 {
		return ""
	}
	startIdx += len(start)
	endIdx := strings.Index(s[startIdx:], end)
	if endIdx == -1 {
		return ""
	}
	return s[startIdx : startIdx+endIdx]
}
