// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoad_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("USULNET_CLIENT_CONFIG", filepath.Join(dir, "config.yaml"))

	in := &File{
		DefaultContext: "prod",
		Contexts: map[string]Context{
			"prod":  {URL: "https://prod.example.com:7443", Token: "k1", Insecure: false},
			"local": {URL: "https://localhost:7443", Token: "k2", Insecure: true},
		},
	}
	if err := Save(in); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.DefaultContext != "prod" {
		t.Errorf("default_context: want prod, got %q", got.DefaultContext)
	}
	if got.Contexts["prod"].URL != "https://prod.example.com:7443" {
		t.Errorf("prod url mismatch")
	}
	if !got.Contexts["local"].Insecure {
		t.Errorf("local.insecure should be true")
	}
}

func TestLoad_MissingFile_ReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("USULNET_CLIENT_CONFIG", filepath.Join(dir, "nope.yaml"))

	got, err := Load()
	if err != nil {
		t.Fatalf("Load missing file should not error: %v", err)
	}
	if got == nil {
		t.Fatal("Load returned nil File")
	}
	if len(got.Contexts) != 0 {
		t.Errorf("missing file should yield empty contexts, got %d", len(got.Contexts))
	}
}

func TestSave_Mode0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	t.Setenv("USULNET_CLIENT_CONFIG", path)

	f := &File{Contexts: map[string]Context{"a": {URL: "https://x"}}}
	if err := Save(f); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perm: want 0600, got %o", info.Mode().Perm())
	}
}

func TestActive_PrecedenceOrder(t *testing.T) {
	f := &File{
		DefaultContext: "prod",
		Contexts: map[string]Context{
			"prod":    {URL: "https://prod"},
			"staging": {URL: "https://staging"},
		},
	}

	// (1) env var wins
	t.Setenv("USULNET_CONTEXT", "staging")
	name, c, err := f.Active()
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if name != "staging" || c.URL != "https://staging" {
		t.Errorf("env precedence: got %s/%s", name, c.URL)
	}

	// (2) default_context wins when env unset
	t.Setenv("USULNET_CONTEXT", "")
	name, c, err = f.Active()
	if err != nil {
		t.Fatalf("Active default: %v", err)
	}
	if name != "prod" || c.URL != "https://prod" {
		t.Errorf("default precedence: got %s/%s", name, c.URL)
	}

	// (3) single context fallback
	f.DefaultContext = ""
	delete(f.Contexts, "staging")
	name, c, err = f.Active()
	if err != nil {
		t.Fatalf("Active single: %v", err)
	}
	if name != "prod" {
		t.Errorf("single-context fallback: got %s", name)
	}

	// (4) no contexts = error
	f.Contexts = map[string]Context{}
	if _, _, err := f.Active(); err == nil {
		t.Errorf("no contexts should error")
	}
}

func TestActive_BadEnvVar(t *testing.T) {
	f := &File{Contexts: map[string]Context{"prod": {URL: "https://x"}}}
	t.Setenv("USULNET_CONTEXT", "nonexistent")
	if _, _, err := f.Active(); err == nil {
		t.Errorf("bad env context should error")
	}
}

func TestSetRemove(t *testing.T) {
	f := &File{Contexts: map[string]Context{}}
	f.Set("a", Context{URL: "https://a"})
	if f.DefaultContext != "a" {
		t.Errorf("first set should become default; got %q", f.DefaultContext)
	}
	f.Set("b", Context{URL: "https://b"})
	if f.DefaultContext != "a" {
		t.Errorf("second set should NOT change default; got %q", f.DefaultContext)
	}
	if err := f.Remove("a"); err != nil {
		t.Fatalf("Remove a: %v", err)
	}
	if f.DefaultContext != "" {
		t.Errorf("removing default should clear DefaultContext; got %q", f.DefaultContext)
	}
	if err := f.Remove("nonexistent"); err == nil {
		t.Errorf("removing missing should error")
	}
}
