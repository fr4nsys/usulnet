// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"strings"
	"testing"

	"github.com/fr4nsys/usulnet/internal/web/templates/components"
)

// TestEmptyStateCatalog_AllEntriesValid asserts every catalog entry
// declares the required fields (Title, What, Why, Icon, ≥1 CTA).
// This is the v26.5.2 session 05 contract: empty-states must be
// informative, not skeletons. Catches drift if someone adds a
// catalog function that omits required copy.
func TestEmptyStateCatalog_AllEntriesValid(t *testing.T) {
	entries := map[string]components.EmptyStateData{
		"Backups":         EmptyStateCatalogBackups(),
		"BackupVerify":    EmptyStateCatalogBackupVerify(),
		"Calendar":        EmptyStateCatalogCalendar(),
		"Crontab":         EmptyStateCatalogCrontab(),
		"DNS":             EmptyStateCatalogDNS(),
		"Firewall":        EmptyStateCatalogFirewall(),
		"ImageBuilder":    EmptyStateCatalogImageBuilder(),
		"Marketplace":     EmptyStateCatalogMarketplace(),
		"Proxy":           EmptyStateCatalogProxy(),
		"Rollback":        EmptyStateCatalogRollback(),
		"SSLObservatory":  EmptyStateCatalogSSLObservatory(),
		"WireGuard":       EmptyStateCatalogWireGuard(),
	}

	for name, data := range entries {
		t.Run(name, func(t *testing.T) {
			if data.Icon == "" {
				t.Error("Icon empty — every empty-state needs a Font Awesome class")
			}
			if !strings.HasPrefix(data.Icon, "fa-") {
				t.Errorf("Icon %q should be a bare fa-* class without the family prefix", data.Icon)
			}
			if data.Title == "" {
				t.Error("Title empty — module noun in title case is required")
			}
			if data.What == "" {
				t.Error("What empty — module mechanics description required")
			}
			if data.Why == "" {
				t.Error("Why empty — operator-value explanation required")
			}
			if len(data.CTAs) == 0 {
				t.Error("CTAs empty — every empty-state needs at least one primary action")
			}

			// Exactly one primary action per the catalog convention.
			primaries := 0
			for _, c := range data.CTAs {
				if c.Primary {
					primaries++
				}
				if c.Label == "" {
					t.Error("CTA Label empty")
				}
				if c.Href == "" {
					t.Errorf("CTA %q Href empty", c.Label)
				}
				// No external links per the spec (in-app or docs/* only).
				if strings.HasPrefix(c.Href, "http://") || strings.HasPrefix(c.Href, "https://") {
					t.Errorf("CTA %q points to external URL %q; spec forbids external links from empty-states", c.Label, c.Href)
				}
			}
			if primaries != 1 {
				t.Errorf("expected exactly 1 primary CTA, got %d", primaries)
			}
		})
	}
}
