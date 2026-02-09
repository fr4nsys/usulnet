// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package update

import (
	"regexp"
	"strconv"
	"strings"
)

// extractVariant extracts the variant suffix from a Docker tag.
// Examples:
//   - "7-alpine" → "alpine"
//   - "1.25.3-bookworm" → "bookworm"
//   - "3.2.100-windowsservercore" → "windowsservercore"
//   - "7.4.2" → ""
//   - "latest" → ""
func extractVariant(tag string) string {
	// Remove leading version numbers and dots
	// Pattern: optional "v", then digits/dots, then optional "-suffix"
	re := regexp.MustCompile(`^v?[\d]+(?:\.[\d]+)*(?:-(.*?))?$`)
	matches := re.FindStringSubmatch(tag)
	if len(matches) >= 2 && matches[1] != "" {
		return matches[1]
	}

	// Handle tags like "alpine3.19" or "7-alpine3.19"
	// First strip leading version
	stripped := tag
	versionPrefixRe := regexp.MustCompile(`^v?[\d]+(?:\.[\d]+)*-`)
	stripped = versionPrefixRe.ReplaceAllString(stripped, "")

	// If what remains is purely numeric or has dots only, no variant
	if stripped == tag {
		// No version prefix found, check if it's a bare variant like "alpine"
		if !regexp.MustCompile(`^v?[\d]`).MatchString(tag) {
			return tag // The whole tag is a variant (e.g., "alpine", "slim")
		}
		return ""
	}

	// Strip trailing version from variant (e.g., "alpine3.19" → "alpine")
	variantRe := regexp.MustCompile(`^([a-zA-Z]+)[\d.]*$`)
	variantMatches := variantRe.FindStringSubmatch(stripped)
	if len(variantMatches) >= 2 {
		return variantMatches[1]
	}

	return stripped
}

// extractMajorVersion extracts the major version number from a tag.
// Examples:
//   - "7-alpine" → 7
//   - "1.25.3" → 1
//   - "v2.1.0" → 2
//   - "latest" → -1
//   - "alpine" → -1
func extractMajorVersion(tag string) int {
	re := regexp.MustCompile(`^v?([\d]+)`)
	matches := re.FindStringSubmatch(tag)
	if len(matches) >= 2 {
		if v, err := strconv.Atoi(matches[1]); err == nil {
			return v
		}
	}
	return -1
}

// findHighestSemverTag finds the highest semver tag that matches the given
// variant and major version channel. Pass "" for variant to match tags without
// variant. Pass -1 for majorVersion to match any major version.
func findHighestSemverTag(tags []string, variant string, majorVersion int) string {
	var best string
	var bestParts []int

	for _, tag := range tags {
		if tag == "latest" || strings.HasPrefix(tag, "sha256:") {
			continue
		}

		tagVariant := extractVariant(tag)
		tagMajor := extractMajorVersion(tag)

		// Must match variant
		if tagVariant != variant {
			continue
		}

		// Must match major version channel if specified
		if majorVersion >= 0 && tagMajor != majorVersion {
			continue
		}

		// Must have some version numbers
		if tagMajor < 0 {
			continue
		}

		parts := extractVersionParts(tag)
		if len(parts) == 0 {
			continue
		}

		if best == "" || compareParts(parts, bestParts) > 0 {
			best = tag
			bestParts = parts
		}
	}

	return best
}

// isNewerTag returns true if candidateTag represents a newer version than currentTag.
func isNewerTag(candidateTag, currentTag string) bool {
	candidateParts := extractVersionParts(candidateTag)
	currentParts := extractVersionParts(currentTag)

	if len(candidateParts) == 0 || len(currentParts) == 0 {
		return candidateTag != currentTag
	}

	return compareParts(candidateParts, currentParts) > 0
}

// extractVersionParts extracts numeric version parts from a tag.
// "7.4.2-alpine" → [7, 4, 2]
// "1.25" → [1, 25]
// "v2.1.0-rc1" → [2, 1, 0]
func extractVersionParts(tag string) []int {
	// Strip leading "v"
	s := strings.TrimPrefix(tag, "v")

	// Extract the numeric-dot prefix
	re := regexp.MustCompile(`^([\d]+(?:\.[\d]+)*)`)
	matches := re.FindStringSubmatch(s)
	if len(matches) < 2 {
		return nil
	}

	parts := strings.Split(matches[1], ".")
	result := make([]int, 0, len(parts))
	for _, p := range parts {
		if v, err := strconv.Atoi(p); err == nil {
			result = append(result, v)
		}
	}
	return result
}

// compareParts compares two version part slices.
// Returns >0 if a > b, <0 if a < b, 0 if equal.
func compareParts(a, b []int) int {
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}

	for i := 0; i < maxLen; i++ {
		va, vb := 0, 0
		if i < len(a) {
			va = a[i]
		}
		if i < len(b) {
			vb = b[i]
		}
		if va != vb {
			return va - vb
		}
	}
	return 0
}
