// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package marketplace provides the offline, embedded marketplace
// catalog.
//
// The catalog is baked into the usulnet binary at build time via an
// embedded filesystem (the go:embed directive on catalogFS below).
// There is no network fetch, no central registry, and no call-home:
// the entire catalog ships with the release and can be audited in git.
//
// Layout (one directory per app):
//
//	internal/templates/marketplace/<slug>/
//	    manifest.yaml   metadata + configurable fields
//	    compose.yaml    docker-compose template with {{KEY}} placeholders
//	    icon.svg        small monochrome icon (≤ 16 KiB)
//
// LICENSES.md alongside this file documents the upstream image
// licenses for every shipped template. Adding an app means adding a
// directory and a line to LICENSES.md; both are reviewed in the same PR.
package marketplace

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/fr4nsys/usulnet/internal/models"
)

// catalogFS is the embedded catalog. Tests in this package walk this
// FS to verify every entry has a valid manifest + compose + icon.
//
//go:embed all:apps
var catalogFS embed.FS

// catalogRoot is the directory inside catalogFS that holds <slug>/ dirs.
const catalogRoot = "apps"

// Manifest is the on-disk schema for each app's manifest.yaml. The
// fields mirror models.MarketplaceApp closely but keep YAML-friendly
// names so hand-edited manifests stay readable.
type Manifest struct {
	Slug            string                    `yaml:"slug"`
	Name            string                    `yaml:"name"`
	Description     string                    `yaml:"description"`
	LongDescription string                    `yaml:"long_description"`
	Category        string                    `yaml:"category"`
	Icon            string                    `yaml:"icon"`
	IconColor       string                    `yaml:"icon_color"`
	Version         string                    `yaml:"version"`
	ManifestVersion int                       `yaml:"manifest_version"`
	Website         string                    `yaml:"website"`
	Source          string                    `yaml:"source"`
	Author          string                    `yaml:"author"`
	License         string                    `yaml:"license"`
	Tags            []string                  `yaml:"tags"`
	MinMemoryMB     int                       `yaml:"min_memory_mb"`
	MinCPUCores     float64                   `yaml:"min_cpu_cores"`
	IsOfficial      bool                      `yaml:"is_official"`
	IsVerified      bool                      `yaml:"is_verified"`
	Featured        bool                      `yaml:"featured"`
	Fields          []models.MarketplaceField `yaml:"fields"`
}

// Entry is a fully-resolved catalog template: manifest + compose body
// + inline SVG icon. The service hydrates rows in marketplace_apps from
// this struct on first boot and on manifest-version bumps.
type Entry struct {
	Slug            string
	Name            string
	Description     string
	LongDescription string
	Category        string
	Icon            string
	IconColor       string
	IconSVG         string
	Version         string
	ManifestVersion int
	Website         string
	Source          string
	Author          string
	License         string
	Tags            []string
	MinMemoryMB     int
	MinCPUCores     float64
	IsOfficial      bool
	IsVerified      bool
	Featured        bool
	Fields          []models.MarketplaceField
	Compose         string
}

// Load reads every entry under the embedded apps/ tree, verifies the
// required files are present, and returns the entries sorted by slug
// for deterministic iteration.
//
// The returned slice is fresh on every call so callers cannot mutate
// shared state. Cost is small (≤ ~10 apps shipped) so we don't cache.
func Load() ([]Entry, error) {
	dir, err := fs.ReadDir(catalogFS, catalogRoot)
	if err != nil {
		return nil, fmt.Errorf("read marketplace catalog root: %w", err)
	}
	entries := make([]Entry, 0, len(dir))
	for _, d := range dir {
		if !d.IsDir() {
			continue
		}
		slug := d.Name()
		entry, err := loadEntry(slug)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", slug, err)
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Slug < entries[j].Slug })
	return entries, nil
}

// LoadEntry returns a single entry by slug. Returns an error matching
// errors.Is(fs.ErrNotExist) when the slug is unknown.
func LoadEntry(slug string) (Entry, error) {
	if !isValidSlug(slug) {
		return Entry{}, fmt.Errorf("invalid marketplace slug %q", slug)
	}
	return loadEntry(slug)
}

func loadEntry(slug string) (Entry, error) {
	base := path.Join(catalogRoot, slug)

	mBytes, err := fs.ReadFile(catalogFS, path.Join(base, "manifest.yaml"))
	if err != nil {
		return Entry{}, fmt.Errorf("read manifest: %w", err)
	}
	var m Manifest
	if err := yaml.Unmarshal(mBytes, &m); err != nil {
		return Entry{}, fmt.Errorf("parse manifest: %w", err)
	}
	if m.Slug == "" {
		m.Slug = slug
	}
	if m.Slug != slug {
		return Entry{}, fmt.Errorf("manifest slug %q does not match directory %q", m.Slug, slug)
	}
	if err := validateManifest(&m); err != nil {
		return Entry{}, err
	}

	compose, err := fs.ReadFile(catalogFS, path.Join(base, "compose.yaml"))
	if err != nil {
		return Entry{}, fmt.Errorf("read compose: %w", err)
	}

	icon, err := fs.ReadFile(catalogFS, path.Join(base, "icon.svg"))
	if err != nil {
		return Entry{}, fmt.Errorf("read icon: %w", err)
	}

	if m.ManifestVersion == 0 {
		m.ManifestVersion = 1
	}
	if m.Icon == "" {
		m.Icon = "fa-cube"
	}
	if m.IconColor == "" {
		m.IconColor = "#6c757d"
	}

	return Entry{
		Slug:            m.Slug,
		Name:            m.Name,
		Description:     m.Description,
		LongDescription: m.LongDescription,
		Category:        m.Category,
		Icon:            m.Icon,
		IconColor:       m.IconColor,
		IconSVG:         string(icon),
		Version:         m.Version,
		ManifestVersion: m.ManifestVersion,
		Website:         m.Website,
		Source:          m.Source,
		Author:          m.Author,
		License:         m.License,
		Tags:            m.Tags,
		MinMemoryMB:     m.MinMemoryMB,
		MinCPUCores:     m.MinCPUCores,
		IsOfficial:      m.IsOfficial,
		IsVerified:      m.IsVerified,
		Featured:        m.Featured,
		Fields:          m.Fields,
		Compose:         string(compose),
	}, nil
}

func validateManifest(m *Manifest) error {
	if m.Name == "" {
		return errors.New("manifest: name is required")
	}
	if m.Description == "" {
		return errors.New("manifest: description is required")
	}
	if m.Category == "" {
		return errors.New("manifest: category is required")
	}
	if m.License == "" {
		return errors.New("manifest: license is required (must be AGPL-compatible — see LICENSES.md)")
	}
	if !validCategories[m.Category] {
		return fmt.Errorf("manifest: unknown category %q", m.Category)
	}
	return nil
}

// validCategories mirrors models.MarketplaceAppCategory.
var validCategories = map[string]bool{
	"networking":    true,
	"storage":       true,
	"development":   true,
	"monitoring":    true,
	"security":      true,
	"communication": true,
	"productivity":  true,
	"database":      true,
	"other":         true,
}

// isValidSlug enforces the slug shape that we expect on disk. The same
// regex pattern is enforced in the marketplace service for user-submitted
// apps; centralizing it here means the embedded catalog cannot ship
// a slug the service would refuse to accept.
func isValidSlug(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return false
		}
	}
	return !strings.HasPrefix(s, "-") && !strings.HasSuffix(s, "-")
}
