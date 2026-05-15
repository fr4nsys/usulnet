// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package marketplace

import (
	"fmt"

	templates "github.com/fr4nsys/usulnet/internal/templates/marketplace"
)

// EmbeddedCatalog wraps the offline catalog baked into the
// binary. It satisfies the CatalogSource interface and is the only
// CatalogSource implementation registered by app wiring.
//
// Audit guarantee: this type never reads from a network source. The
// underlying templates package only knows how to read from an embed.FS
// — see internal/templates/marketplace/catalog.go. A unit test in this
// package asserts that the catalog loader does not issue any
// outbound HTTP requests.
type EmbeddedCatalog struct{}

// NewEmbeddedCatalog returns an EmbeddedCatalog ready for use.
func NewEmbeddedCatalog() *EmbeddedCatalog {
	return &EmbeddedCatalog{}
}

// Load implements CatalogSource.
func (EmbeddedCatalog) Load() ([]CatalogEntry, error) {
	entries, err := templates.Load()
	if err != nil {
		return nil, fmt.Errorf("load embedded marketplace catalog: %w", err)
	}
	out := make([]CatalogEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, CatalogEntry{
			Slug:            e.Slug,
			Name:            e.Name,
			Description:     e.Description,
			LongDescription: e.LongDescription,
			Category:        e.Category,
			Icon:            e.Icon,
			IconColor:       e.IconColor,
			IconSVG:         e.IconSVG,
			Version:         e.Version,
			ManifestVersion: e.ManifestVersion,
			Website:         e.Website,
			Source:          e.Source,
			Author:          e.Author,
			License:         e.License,
			Tags:            e.Tags,
			MinMemoryMB:     e.MinMemoryMB,
			MinCPUCores:     e.MinCPUCores,
			IsOfficial:      e.IsOfficial,
			IsVerified:      e.IsVerified,
			Featured:        e.Featured,
			Fields:          e.Fields,
			Compose:         e.Compose,
		})
	}
	return out, nil
}
