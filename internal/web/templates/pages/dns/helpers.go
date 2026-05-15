// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package dns

import "fmt"

// initialConfigValue returns the value the new/edit form should show
// for a configuration field. The web handler pre-populates
// ProviderFormData.Provider.Description but the config map lives
// elsewhere; this helper is used only when the caller did not
// supply a value, so the field-level default is shown.
func initialConfigValue(_ ProviderFormData, _ string, def any) string {
	if def == nil {
		return ""
	}
	switch v := def.(type) {
	case string:
		return v
	case int:
		return fmt.Sprintf("%d", v)
	case float64:
		return fmt.Sprintf("%g", v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", v)
	}
}

// stateBadgeClass maps an ACME order state to a tailwind class string.
func stateBadgeClass(state string) string {
	switch state {
	case "completed":
		return "badge badge-success"
	case "failed":
		return "badge badge-danger"
	case "ready":
		return "badge badge-info"
	default:
		return "badge badge-warning"
	}
}
