// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package dns

import (
	"context"
	"errors"

	"github.com/fr4nsys/usulnet/internal/models"
)

// Sentinel errors returned by provider plugins. The service maps them
// onto user-facing copy and audit log entries.
var (
	// ErrProviderNotFound is returned when a record CRUD targets a
	// provider kind that has no registered plugin (e.g. the binary
	// was built without it).
	ErrProviderNotFound = errors.New("dns: provider not registered")

	// ErrInvalidCredentials is returned when a plugin can decode the
	// blob but the upstream rejects the credentials at first call.
	ErrInvalidCredentials = errors.New("dns: invalid provider credentials")

	// ErrZoneNotFound is returned when a record name does not match
	// any zone the credentialed account can write to.
	ErrZoneNotFound = errors.New("dns: zone not found for record")

	// ErrRecordNotFound is returned when a provider record id no
	// longer exists upstream (drifted state).
	ErrRecordNotFound = errors.New("dns: record not found upstream")

	// ErrPropagationTimeout is returned when the ACME state machine
	// gives up waiting for the TXT record to be observable.
	ErrPropagationTimeout = errors.New("dns: propagation timeout")

	// ErrStateConflict is returned by the ACME state machine when a
	// transition is not legal from the current state.
	ErrStateConflict = errors.New("dns: invalid acme state transition")
)

// ProviderRecord is the wire-shape passed between the service and a
// provider plugin. Distinct from models.DNSRecord so the plugin layer
// is free of database concerns. ID is the provider-side identifier
// (Cloudflare uuid, Route53 change id, etc.) — empty on Create until
// the plugin returns it.
type ProviderRecord struct {
	ID      string
	Name    string
	Type    models.DNSRecordType
	Content string
	TTL     int
}

// Provider is the contract every DNS plugin satisfies. The service
// looks plugins up by kind via the Registry and never depends on a
// concrete implementation.
type Provider interface {
	// Kind returns the provider identifier (e.g. "cloudflare").
	Kind() models.DNSProviderKind

	// CreateRecord adds a record. The returned ProviderRecord carries
	// the provider-assigned ID in its ID field.
	CreateRecord(ctx context.Context, rec ProviderRecord) (ProviderRecord, error)

	// DeleteRecord removes a record by provider-side ID. If the
	// upstream has already removed the record, ErrRecordNotFound is
	// returned and the service treats it as success.
	DeleteRecord(ctx context.Context, id string, rec ProviderRecord) error

	// ListRecords lists records currently visible to the credential.
	// Used by the UI for drift detection. May return an empty slice
	// without error when filtering yields nothing.
	ListRecords(ctx context.Context, zone string) ([]ProviderRecord, error)

	// VerifyCredentials performs a low-cost authenticated round-trip
	// (typically "list zones" or "user/me") so the operator gets a
	// clear error at provider creation time instead of at first
	// record write.
	VerifyCredentials(ctx context.Context) error

	// Close releases any resources held by the plugin (HTTP client
	// pools, connection caches). Safe to call repeatedly.
	Close() error
}

// Factory builds a Provider from the decrypted credential JSON and the
// stored, non-secret config map. Each plugin package exports a Factory
// and the wiring layer registers it via Registry.Register.
type Factory func(ctx context.Context, credentials []byte, config map[string]any) (Provider, error)

// SupportedRecord describes which RR types a plugin can write. The
// REST endpoint /api/v1/dns/supported-providers turns this into the
// "Capability matrix" tab in the UI.
type SupportedRecord struct {
	Type      models.DNSRecordType `json:"type"`
	Read      bool                 `json:"read"`
	Write     bool                 `json:"write"`
	UpdateTTL bool                 `json:"update_ttl"`
}

// Capabilities is the static description a plugin advertises so the UI
// can render the "supported providers" matrix without spinning up a
// real Provider.
type Capabilities struct {
	Kind        models.DNSProviderKind `json:"kind"`
	DisplayName string                 `json:"display_name"`
	Description string                 `json:"description"`
	Records     []SupportedRecord      `json:"records"`
	// CredentialFields documents the credential JSON fields the
	// plugin expects. The web "new provider" form is built from this
	// array so the user knows what to paste.
	CredentialFields []CredentialField `json:"credential_fields"`
	// ConfigFields documents the non-secret config knobs (default
	// zone, propagation timeout, ...).
	ConfigFields []ConfigField `json:"config_fields"`
}

// CredentialField describes one field in the credential JSON blob.
type CredentialField struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Required    bool   `json:"required"`
	Secret      bool   `json:"secret"`
	Description string `json:"description,omitempty"`
}

// ConfigField describes one field in the non-secret config map.
type ConfigField struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Type        string `json:"type"` // "string" | "int" | "bool"
	Default     any    `json:"default,omitempty"`
	Description string `json:"description,omitempty"`
}
