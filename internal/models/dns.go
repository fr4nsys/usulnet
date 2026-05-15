// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// DNSProviderKind identifies the upstream DNS-as-a-service provider.
// Adding a new kind requires a matching plugin under
// internal/services/dns/providers/<kind>/ and an explicit registration
// call from the bootstrap (no init() drift).
type DNSProviderKind string

const (
	DNSProviderKindCloudflare   DNSProviderKind = "cloudflare"
	DNSProviderKindRoute53      DNSProviderKind = "route53"
	DNSProviderKindDigitalOcean DNSProviderKind = "digitalocean"
	DNSProviderKindRFC2136      DNSProviderKind = "rfc2136"
)

// DNSRecordType is the wire-level DNS RR type the platform writes
// through a provider plugin. Limited to types that have meaningful
// CRUD across the four providers we ship.
type DNSRecordType string

const (
	DNSRecordTypeA     DNSRecordType = "A"
	DNSRecordTypeAAAA  DNSRecordType = "AAAA"
	DNSRecordTypeCNAME DNSRecordType = "CNAME"
	DNSRecordTypeMX    DNSRecordType = "MX"
	DNSRecordTypeTXT   DNSRecordType = "TXT"
	DNSRecordTypeNS    DNSRecordType = "NS"
	DNSRecordTypeSRV   DNSRecordType = "SRV"
	DNSRecordTypePTR   DNSRecordType = "PTR"
	DNSRecordTypeCAA   DNSRecordType = "CAA"
)

// DNSProvider is a configured DNS-as-a-service backend (Cloudflare,
// Route53, DigitalOcean, RFC 2136) attached to a host. Credentials
// live in Credentials as AES-256-GCM ciphertext (base64-encoded). The
// service layer encrypts on write and decrypts only when a plugin
// needs to authenticate to the upstream.
type DNSProvider struct {
	ID           uuid.UUID       `json:"id"            db:"id"`
	HostID       uuid.UUID       `json:"host_id"       db:"host_id"`
	Name         string          `json:"name"          db:"name"`
	ProviderKind DNSProviderKind `json:"provider_kind" db:"provider_kind"`
	Enabled      bool            `json:"enabled"       db:"enabled"`
	Description  string          `json:"description"   db:"description"`

	// Credentials is the AES-encrypted, base64-encoded JSON blob.
	// JSON-redacted from API responses. The web handler exposes it
	// only on the "edit" page when the operator explicitly asks to
	// rotate.
	Credentials string `json:"-" db:"credentials"`

	// Config holds non-secret, provider-specific knobs (default zone,
	// propagation timeout in seconds, RFC 2136 server, etc.). It is
	// stored as JSONB and exposed as-is.
	Config map[string]any `json:"config" db:"-"`

	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`
	CreatedAt time.Time  `json:"created_at"           db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"           db:"updated_at"`
}

// DNSRecord is a record the platform owns through a provider. The
// content of "discovery" or "acme" managed records is reconciled by
// the corresponding subsystem and should not be hand-edited.
type DNSRecord struct {
	ID               uuid.UUID     `json:"id"                  db:"id"`
	ProviderID       uuid.UUID     `json:"provider_id"         db:"provider_id"`
	HostID           uuid.UUID     `json:"host_id"             db:"host_id"`
	Name             string        `json:"name"                db:"name"`
	Type             DNSRecordType `json:"type"                db:"type"`
	Content          string        `json:"content"             db:"content"`
	TTL              int           `json:"ttl"                 db:"ttl"`
	ProviderRecordID string        `json:"provider_record_id"  db:"provider_record_id"`
	ManagedBy        string        `json:"managed_by"          db:"managed_by"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// IsManual reports whether the record is hand-managed (vs created by
// the ACME or service-discovery subsystems).
func (r DNSRecord) IsManual() bool { return r.ManagedBy == "" || r.ManagedBy == "manual" }

// ACMEOrderState enumerates valid states of the DNS-01 state machine.
// Transitions are linear with one branch (failed) and one cleanup tail.
type ACMEOrderState string

const (
	// ACMEOrderStatePending is the initial state — recorded the
	// moment the proxy module asks for a DNS-01 challenge.
	ACMEOrderStatePending ACMEOrderState = "pending"
	// ACMEOrderStateDropping means usulnet is calling the provider
	// to drop the TXT record.
	ACMEOrderStateDropping ACMEOrderState = "dropping"
	// ACMEOrderStatePropagating means the TXT record is created and
	// usulnet is polling resolvers to confirm propagation.
	ACMEOrderStatePropagating ACMEOrderState = "propagating"
	// ACMEOrderStateReady means propagation has been confirmed and the
	// proxy backend can ask the CA to finalize the order.
	ACMEOrderStateReady ACMEOrderState = "ready"
	// ACMEOrderStateCompleting means the CA validation succeeded and
	// usulnet is cleaning up.
	ACMEOrderStateCompleting ACMEOrderState = "completing"
	// ACMEOrderStateCompleted is the terminal happy state.
	ACMEOrderStateCompleted ACMEOrderState = "completed"
	// ACMEOrderStateFailed is the terminal sad state. The error_msg
	// column carries the diagnostic.
	ACMEOrderStateFailed ACMEOrderState = "failed"
)

// IsTerminal reports whether the state is a final state of the
// state machine.
func (s ACMEOrderState) IsTerminal() bool {
	return s == ACMEOrderStateCompleted || s == ACMEOrderStateFailed
}

// DNSACMEOrder captures the full lifecycle of a single DNS-01
// challenge for a host. It is durable so the state machine survives
// usulnet restarts mid-order — on boot the service resumes any orders
// not in a terminal state.
type DNSACMEOrder struct {
	ID                    uuid.UUID      `json:"id"                       db:"id"`
	HostID                uuid.UUID      `json:"host_id"                  db:"host_id"`
	ProviderID            uuid.UUID      `json:"provider_id"              db:"provider_id"`
	Domain                string         `json:"domain"                   db:"domain"`
	ChallengeFQDN         string         `json:"challenge_fqdn"           db:"challenge_fqdn"`
	ChallengeValue        string         `json:"challenge_value"          db:"challenge_value"`
	State                 ACMEOrderState `json:"state"                    db:"state"`
	ErrorMsg              string         `json:"error_msg"                db:"error_msg"`
	RecordID              *uuid.UUID     `json:"record_id,omitempty"      db:"record_id"`
	PropagationCheckCount int            `json:"propagation_check_count"  db:"propagation_check_count"`
	LastCheckAt           *time.Time     `json:"last_check_at,omitempty"  db:"last_check_at"`
	CompletedAt           *time.Time     `json:"completed_at,omitempty"   db:"completed_at"`
	CreatedAt             time.Time      `json:"created_at"               db:"created_at"`
	UpdatedAt             time.Time      `json:"updated_at"               db:"updated_at"`
}

// DNSAuditLog records DNS provider/record operations and ACME state
// transitions for the audit page.
type DNSAuditLog struct {
	ID           uuid.UUID  `json:"id"                  db:"id"`
	HostID       uuid.UUID  `json:"host_id"             db:"host_id"`
	UserID       *uuid.UUID `json:"user_id,omitempty"   db:"user_id"`
	Action       string     `json:"action"              db:"action"`
	ResourceType string     `json:"resource_type"       db:"resource_type"`
	ResourceID   uuid.UUID  `json:"resource_id"         db:"resource_id"`
	ResourceName string     `json:"resource_name"       db:"resource_name"`
	Details      string     `json:"details"             db:"details"`
	CreatedAt    time.Time  `json:"created_at"          db:"created_at"`
}
