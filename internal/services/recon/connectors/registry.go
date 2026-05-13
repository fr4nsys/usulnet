// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package connectors holds the recon module's optional external-API
// integrations. Each connector is a small, self-contained package
// implementing recon.Connector (Kind / Enabled / HealthCheck) plus
// whatever per-connector lookup surface the engines call. The registry
// in this file is the connector service consumed by the API handler:
// it lists every registered connector's kind/enabled/health and writes
// credential updates through to a persistence sink supplied at
// construction time.
//
// The registry deliberately keeps the public surface narrow. There is
// no global state, no init() registration, and no reflection — each
// connector is wired explicitly in internal/app/app.go behind its own
// `cfg.Recon.Connectors.<kind>.Enabled` gate.
package connectors

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// Info is the API-shaped view of one registered connector. It mirrors
// internal/api/handlers.ReconConnectorInfo verbatim — duplicating the
// type here is intentional so the connectors package does not depend
// on the handlers package (which already imports this one).
type Info struct {
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`
	Healthy bool   `json:"healthy"`
}

// CredentialStore persists / retrieves the encrypted credential blob
// for a connector. Implementations live in internal/repository/postgres;
// nil is permitted at construction time (the registry then refuses
// SetConnector / DeleteConnector calls with ErrNoCredentialStore).
type CredentialStore interface {
	Save(ctx context.Context, kind string, creds map[string]string, enabled bool) error
	Delete(ctx context.Context, kind string) error
}

// ErrNoCredentialStore is returned by SetConnector / DeleteConnector
// when the registry has no persistence sink wired. The API layer
// surfaces this as a 501 not_implemented.
var ErrNoCredentialStore = errors.New("connectors: no credential store wired")

// ErrUnknownKind is returned for SetConnector calls naming a connector
// that has not been registered.
var ErrUnknownKind = errors.New("connectors: unknown connector kind")

// Registry implements the handler-facing connector service. It holds a
// snapshot of every connector wired at startup and proxies persistence
// writes through CredentialStore.
//
// The Registry is safe for concurrent use. Connectors must be added
// during startup; runtime registration is not supported in v26.5.0.
type Registry struct {
	mu    sync.RWMutex
	items map[string]recon.Connector
	store CredentialStore
	log   *logger.Logger
}

// NewRegistry constructs a Registry. A nil store is permitted — the
// registry then refuses SetConnector calls but still serves ListConnectors.
func NewRegistry(store CredentialStore, log *logger.Logger) *Registry {
	if log == nil {
		log = logger.Nop()
	}
	return &Registry{
		items: make(map[string]recon.Connector),
		store: store,
		log:   log.Named("recon.connectors"),
	}
}

// Register adds c to the registry. Duplicate kinds are rejected so a
// typo at startup fails loudly. The registry takes ownership of c's
// lifetime; callers should not call HealthCheck directly afterward.
func (r *Registry) Register(c recon.Connector) error {
	if c == nil {
		return errors.New("connectors: nil connector")
	}
	kind := c.Kind()
	if kind == "" {
		return errors.New("connectors: connector has empty kind")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[kind]; exists {
		return fmt.Errorf("connectors: %q already registered", kind)
	}
	r.items[kind] = c
	return nil
}

// Get returns the connector registered for kind, or false. Used by
// engines that need to call a connector directly (e.g., the toolkit
// engine's HIBP fallback when SpiderFoot's sfp_haveibeen module has
// no upstream key configured).
func (r *Registry) Get(kind string) (recon.Connector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.items[kind]
	return c, ok
}

// ListConnectors implements handlers.ReconConnectorService. It calls
// HealthCheck on every enabled connector and reports the result. Each
// HealthCheck invocation uses the caller's context budget; a slow
// provider therefore back-pressures the API call rather than running
// in the background.
func (r *Registry) ListConnectors(ctx context.Context) ([]Info, error) {
	r.mu.RLock()
	keys := make([]string, 0, len(r.items))
	byKind := make(map[string]recon.Connector, len(r.items))
	for k, c := range r.items {
		keys = append(keys, k)
		byKind[k] = c
	}
	r.mu.RUnlock()

	sort.Strings(keys)

	out := make([]Info, 0, len(keys))
	for _, k := range keys {
		c := byKind[k]
		info := Info{
			Kind:    k,
			Enabled: c.Enabled(),
		}
		if c.Enabled() {
			err := c.HealthCheck(ctx)
			info.Healthy = err == nil
			if err != nil {
				r.log.Debug("connector unhealthy",
					"kind", k,
					"error", err,
				)
			}
		}
		out = append(out, info)
	}
	return out, nil
}

// SetConnector implements handlers.ReconConnectorService. Credentials
// are passed through to the persistence sink as a flat map; the sink
// is responsible for encrypting them at rest. The registry does not
// hot-reload — operators must restart usulnet (or call back into the
// wiring layer) for a key change to affect HealthCheck results.
func (r *Registry) SetConnector(ctx context.Context, kind string, creds map[string]string, enabled bool) error {
	r.mu.RLock()
	_, ok := r.items[kind]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownKind, kind)
	}
	if r.store == nil {
		return ErrNoCredentialStore
	}
	return r.store.Save(ctx, kind, creds, enabled)
}

// DeleteConnector removes the persisted credentials row for kind. The
// in-memory connector keeps running until the next process start; the
// surface contract is therefore "credentials wiped on disk, current
// in-memory state preserved until restart" — same hot-reload posture
// as SetConnector.
func (r *Registry) DeleteConnector(ctx context.Context, kind string) error {
	r.mu.RLock()
	_, ok := r.items[kind]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownKind, kind)
	}
	if r.store == nil {
		return ErrNoCredentialStore
	}
	return r.store.Delete(ctx, kind)
}
