// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package dns

import (
	"fmt"
	"sort"
	"sync"

	"github.com/fr4nsys/usulnet/internal/models"
)

// Registry holds the set of DNS provider plugins available to the
// service. Registration is explicit (no init() side effects in plugin
// packages); the wiring layer constructs a Registry, registers each
// plugin, and passes it to the service. This avoids the v26.2.7 drift
// where adding a provider also required remembering to import the
// package somewhere.
type Registry struct {
	mu      sync.RWMutex
	entries map[models.DNSProviderKind]registryEntry
}

type registryEntry struct {
	factory      Factory
	capabilities Capabilities
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{entries: make(map[models.DNSProviderKind]registryEntry)}
}

// Register adds a plugin to the registry. Calling Register twice with
// the same kind returns an error rather than silently overwriting; the
// caller is expected to wire each plugin exactly once.
func (r *Registry) Register(kind models.DNSProviderKind, factory Factory, caps Capabilities) error {
	if factory == nil {
		return fmt.Errorf("dns registry: factory for %q is nil", kind)
	}
	if kind == "" {
		return fmt.Errorf("dns registry: empty provider kind")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[kind]; exists {
		return fmt.Errorf("dns registry: provider %q already registered", kind)
	}
	caps.Kind = kind
	r.entries[kind] = registryEntry{factory: factory, capabilities: caps}
	return nil
}

// MustRegister panics on registration failure. Convenience for the
// wiring layer where double-registration is a programmer bug.
func (r *Registry) MustRegister(kind models.DNSProviderKind, factory Factory, caps Capabilities) {
	if err := r.Register(kind, factory, caps); err != nil {
		panic(err)
	}
}

// Factory returns the factory for a given provider kind, or
// ErrProviderNotFound if no plugin is registered.
func (r *Registry) Factory(kind models.DNSProviderKind) (Factory, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.entries[kind]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrProviderNotFound, kind)
	}
	return entry.factory, nil
}

// Capabilities returns the static capabilities of every registered
// plugin, sorted alphabetically by kind. Used by
// /api/v1/dns/supported-providers.
func (r *Registry) Capabilities() []Capabilities {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Capabilities, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e.capabilities)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

// Has reports whether a kind is registered. Useful for handler-level
// validation before constructing a provider row.
func (r *Registry) Has(kind models.DNSProviderKind) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.entries[kind]
	return ok
}

// Kinds returns the registered provider kinds, sorted.
func (r *Registry) Kinds() []models.DNSProviderKind {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]models.DNSProviderKind, 0, len(r.entries))
	for k := range r.entries {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
