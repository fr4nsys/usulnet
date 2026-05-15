// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package marketplace

import (
	"strings"
	"testing"
)

func TestLoad_AllEntriesValid(t *testing.T) {
	entries, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no catalog entries — apps/ directory is empty")
	}

	for _, e := range entries {
		t.Run(e.Slug, func(t *testing.T) {
			if e.Slug == "" {
				t.Error("empty slug")
			}
			if e.Name == "" {
				t.Error("empty name")
			}
			if e.Description == "" {
				t.Error("empty description")
			}
			if e.Category == "" {
				t.Error("empty category")
			}
			if !validCategories[e.Category] {
				t.Errorf("invalid category %q", e.Category)
			}
			if e.License == "" {
				t.Error("empty license — see LICENSES.md")
			}
			if e.Compose == "" {
				t.Error("empty compose body")
			}
			if !strings.Contains(e.Compose, "services:") {
				t.Errorf("compose missing 'services:' section: %s", e.Compose)
			}
			if e.IconSVG == "" {
				t.Error("empty icon.svg")
			}
			if !strings.Contains(e.IconSVG, "<svg") {
				t.Error("icon.svg missing <svg element")
			}
			if e.ManifestVersion < 1 {
				t.Errorf("manifest_version must be >= 1, got %d", e.ManifestVersion)
			}
		})
	}
}

func TestLoadEntry_InvalidSlug(t *testing.T) {
	cases := []string{
		"",
		"../etc/passwd",
		"UPPER",
		"with space",
		"-leading",
		"trailing-",
		"with_underscore",
	}
	for _, s := range cases {
		if _, err := LoadEntry(s); err == nil {
			t.Errorf("expected error for slug %q", s)
		}
	}
}

func TestLoadEntry_Found(t *testing.T) {
	entries, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(entries) == 0 {
		t.Skip("no entries to test")
	}
	got, err := LoadEntry(entries[0].Slug)
	if err != nil {
		t.Fatalf("LoadEntry(%q): %v", entries[0].Slug, err)
	}
	if got.Slug != entries[0].Slug {
		t.Errorf("slug mismatch: got %q, want %q", got.Slug, entries[0].Slug)
	}
}

func TestLoadEntry_NotFound(t *testing.T) {
	if _, err := LoadEntry("does-not-exist-12345"); err == nil {
		t.Error("expected error for unknown slug")
	}
}

func TestValidateManifest(t *testing.T) {
	cases := []struct {
		name string
		m    Manifest
		ok   bool
	}{
		{"missing name", Manifest{Description: "d", Category: "other", License: "MIT"}, false},
		{"missing desc", Manifest{Name: "n", Category: "other", License: "MIT"}, false},
		{"missing cat", Manifest{Name: "n", Description: "d", License: "MIT"}, false},
		{"missing license", Manifest{Name: "n", Description: "d", Category: "other"}, false},
		{"unknown cat", Manifest{Name: "n", Description: "d", Category: "blockchain", License: "MIT"}, false},
		{"valid", Manifest{Name: "n", Description: "d", Category: "other", License: "MIT"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateManifest(&c.m)
			if c.ok && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !c.ok && err == nil {
				t.Error("expected error")
			}
		})
	}
}
