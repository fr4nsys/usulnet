// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package config handles client-side context storage for the host CLI.
//
// Layout (XDG):
//
//	$XDG_CONFIG_HOME/usulnet/config.yaml   (defaults to ~/.config/usulnet/)
//
// Schema:
//
//	default_context: prod
//	contexts:
//	  prod:
//	    url: https://prod.example.com:7443
//	    token: <api-key>
//	    insecure: false
//	  local:
//	    url: https://localhost:7443
//	    token: ...
//	    insecure: true
//
// File mode is enforced to 0600 on read and write so credentials never
// leak through a permissive umask.
package config

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Context is one stored installation entry.
type Context struct {
	URL      string `yaml:"url"`
	Token    string `yaml:"token,omitempty"`
	Insecure bool   `yaml:"insecure,omitempty"`
}

// File is the full on-disk schema.
type File struct {
	DefaultContext string             `yaml:"default_context,omitempty"`
	Contexts       map[string]Context `yaml:"contexts,omitempty"`
}

// Path returns the resolved config file path, honouring XDG_CONFIG_HOME.
func Path() (string, error) {
	if env := os.Getenv("USULNET_CLIENT_CONFIG"); env != "" {
		return env, nil
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("locating home dir: %w", err)
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "usulnet", "config.yaml"), nil
}

// Load reads the config file. Returns an empty File (not an error) when
// the file does not exist — first-run is a normal state.
func Load() (*File, error) {
	p, err := Path()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p) //nolint:gosec // user-owned config file by design
	if err != nil {
		if os.IsNotExist(err) {
			return &File{Contexts: map[string]Context{}}, nil
		}
		return nil, fmt.Errorf("reading %s: %w", p, err)
	}
	var f File
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", p, err)
	}
	if f.Contexts == nil {
		f.Contexts = map[string]Context{}
	}
	return &f, nil
}

// Save writes the config file with mode 0600. Creates the parent dir
// (mode 0700) if missing.
func Save(f *File) error {
	p, err := Path()
	if err != nil {
		return err
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	data, err := yaml.Marshal(f)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	// Write atomically: write to tmp then rename.
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, p); err != nil {
		return fmt.Errorf("renaming %s -> %s: %w", tmp, p, err)
	}
	return nil
}

// Active returns the currently active context. Resolution order:
//
//  1. $USULNET_CONTEXT env var.
//  2. f.DefaultContext field.
//  3. The single context if exactly one is configured.
//
// Returns nil + error if no context can be resolved.
func (f *File) Active() (string, *Context, error) {
	if env := strings.TrimSpace(os.Getenv("USULNET_CONTEXT")); env != "" {
		c, ok := f.Contexts[env]
		if !ok {
			return "", nil, fmt.Errorf("USULNET_CONTEXT=%q but no such context configured", env)
		}
		return env, &c, nil
	}
	if f.DefaultContext != "" {
		c, ok := f.Contexts[f.DefaultContext]
		if !ok {
			return "", nil, fmt.Errorf("default_context=%q but no such context in file", f.DefaultContext)
		}
		return f.DefaultContext, &c, nil
	}
	if len(f.Contexts) == 1 {
		for name, c := range f.Contexts {
			return name, &c, nil
		}
	}
	return "", nil, fmt.Errorf("no active context; run `usulnet login <url> --token <key>` first")
}

// Set adds or replaces a context. If first context, also sets default.
func (f *File) Set(name string, c Context) {
	if f.Contexts == nil {
		f.Contexts = map[string]Context{}
	}
	f.Contexts[name] = c
	if f.DefaultContext == "" {
		f.DefaultContext = name
	}
}

// Remove deletes a context. If it was the default, the default is
// cleared (the user must `contexts use <name>` to re-pick one).
func (f *File) Remove(name string) error {
	if _, ok := f.Contexts[name]; !ok {
		return fmt.Errorf("context %q does not exist", name)
	}
	delete(f.Contexts, name)
	if f.DefaultContext == name {
		f.DefaultContext = ""
	}
	return nil
}

// EnforceMode tightens the file to mode 0600 if it exists and is more
// permissive. Logs to stderr if it had to change.
func EnforceMode() error {
	p, err := Path()
	if err != nil {
		return err
	}
	info, err := os.Stat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	want := fs.FileMode(0o600)
	if info.Mode().Perm() != want {
		if err := os.Chmod(p, want); err != nil {
			return fmt.Errorf("chmod %s -> 0600: %w", p, err)
		}
		fmt.Fprintf(os.Stderr, "usulnet: tightened %s permissions to 0600\n", p)
	}
	return nil
}
