// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package recon defines the contracts for the OSINT / privacy recon module
// introduced in usulnet v26.5.0. See docs/recon.md for the full RFC.
//
// This file contains only the public domain types and interfaces. The
// implementation lands in a subsequent PR per the RFC's rollout plan.
package recon

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// TargetType enumerates the identifiers a user can scan.
type TargetType string

const (
	TargetEmail    TargetType = "email"
	TargetPhone    TargetType = "phone"
	TargetUsername TargetType = "username"
	TargetDomain   TargetType = "domain"
	TargetIP       TargetType = "ip"
	TargetIPRange  TargetType = "ip_range"
)

// OwnershipMethod enumerates how a target's ownership is proven.
type OwnershipMethod string

const (
	OwnershipDNSTXT      OwnershipMethod = "dns_txt"
	OwnershipEmailLink   OwnershipMethod = "email_link"
	OwnershipRDAPMatch   OwnershipMethod = "rdap_match"
	OwnershipAdminAttest OwnershipMethod = "admin_attest"
	OwnershipSelfAssert  OwnershipMethod = "self_assert"
)

// OwnershipStatus tracks the lifecycle of an ownership proof.
type OwnershipStatus string

const (
	OwnershipPending  OwnershipStatus = "pending"
	OwnershipVerified OwnershipStatus = "verified"
	OwnershipFailed   OwnershipStatus = "failed"
	OwnershipRevoked  OwnershipStatus = "revoked"
)

// ScanStatus is the lifecycle of a scan.
type ScanStatus string

const (
	ScanQueued    ScanStatus = "queued"
	ScanRunning   ScanStatus = "running"
	ScanCompleted ScanStatus = "completed"
	ScanFailed    ScanStatus = "failed"
	ScanCancelled ScanStatus = "canceled"
)

// Severity classifies a finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Target is an identifier the operator owns and wants to scan.
type Target struct {
	ID        uuid.UUID
	Type      TargetType
	Value     string
	ValueHash []byte
	Label     string
	CreatedBy *uuid.UUID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// OwnershipProof records a verification attempt for a Target.
type OwnershipProof struct {
	ID         uuid.UUID
	TargetID   uuid.UUID
	Method     OwnershipMethod
	Status     OwnershipStatus
	Challenge  string
	Evidence   map[string]any
	VerifiedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Profile is a curated set of recon modules for a given target type.
type Profile struct {
	ID          uuid.UUID
	Name        string
	Description string
	Kind        string
	TargetTypes []TargetType
	Modules     []string
	Options     map[string]any
	CreatedBy   *uuid.UUID
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Scan is one execution of a Profile against a Target.
type Scan struct {
	ID          uuid.UUID
	TargetID    uuid.UUID
	ProfileID   uuid.UUID
	Status      ScanStatus
	Engine      string
	EngineRunID string
	Error       string
	StartedAt   *time.Time
	FinishedAt  *time.Time
	CreatedBy   *uuid.UUID
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Finding is a normalized result from a scan.
type Finding struct {
	ID         uuid.UUID
	ScanID     uuid.UUID
	TargetID   uuid.UUID
	Module     string
	Category   string
	Severity   Severity
	Value      string
	ValueHash  []byte
	Source     string
	Confidence int
	FirstSeen  time.Time
	LastSeen   time.Time
}

// ScanSummary is the aggregate view of one completed scan.
type ScanSummary struct {
	ScanID       uuid.UUID
	Counts       map[string]int
	Grade        string
	Correlations []map[string]any
	GeneratedAt  time.Time
}

// Service is the entry point for recon operations. It is consumed by the
// web/API/CLI layers and by scheduler workers. All methods are
// context-aware and return either a domain error or a typed result.
type Service interface {
	// Targets

	CreateTarget(ctx context.Context, in CreateTargetInput) (*Target, error)
	GetTarget(ctx context.Context, id uuid.UUID) (*Target, error)
	ListTargets(ctx context.Context, filter ListTargetsFilter) ([]Target, error)
	DeleteTarget(ctx context.Context, id uuid.UUID) error

	// Ownership

	StartOwnershipProof(ctx context.Context, targetID uuid.UUID, method OwnershipMethod) (*OwnershipProof, error)
	VerifyOwnershipProof(ctx context.Context, proofID uuid.UUID) (*OwnershipProof, error)

	// Profiles

	ListProfiles(ctx context.Context) ([]Profile, error)
	GetProfile(ctx context.Context, id uuid.UUID) (*Profile, error)
	CreateProfile(ctx context.Context, in CreateProfileInput) (*Profile, error)
	UpdateProfile(ctx context.Context, id uuid.UUID, in UpdateProfileInput) (*Profile, error)
	DeleteProfile(ctx context.Context, id uuid.UUID) error

	// Scans

	StartScan(ctx context.Context, in StartScanInput) (*Scan, error)
	GetScan(ctx context.Context, id uuid.UUID) (*Scan, error)
	ListScans(ctx context.Context, filter ListScansFilter) ([]Scan, error)
	CancelScan(ctx context.Context, id uuid.UUID) error

	// Findings & reports

	ListFindings(ctx context.Context, filter ListFindingsFilter) ([]Finding, error)
	GetScanSummary(ctx context.Context, scanID uuid.UUID) (*ScanSummary, error)
}

// CreateTargetInput is the request to create a Target. Value is normalized
// (lowercased, trimmed) by the Service before persistence.
type CreateTargetInput struct {
	Type      TargetType
	Value     string
	Label     string
	CreatedBy *uuid.UUID
}

// CreateProfileInput is the request to create a user-defined Profile.
// The resulting row's Kind is always "custom"; built-in profiles are
// seeded by migration 044 and are not creatable through this API.
type CreateProfileInput struct {
	Name        string
	Description string
	TargetTypes []TargetType
	Modules     []string
	Options     map[string]any
	CreatedBy   *uuid.UUID
}

// UpdateProfileInput is the request to update a user-defined Profile.
// Only the mutable fields are exposed; Kind and CreatedBy are immutable
// after creation. UpdateProfile rejects ErrProfileBuiltin when the
// target row's Kind is "builtin".
type UpdateProfileInput struct {
	Name        string
	Description string
	TargetTypes []TargetType
	Modules     []string
	Options     map[string]any
}

// StartScanInput requests a new scan run.
type StartScanInput struct {
	TargetID  uuid.UUID
	ProfileID uuid.UUID
	CreatedBy *uuid.UUID
}

// ListTargetsFilter is the filter struct for ListTargets.
type ListTargetsFilter struct {
	Type      *TargetType
	CreatedBy *uuid.UUID
	Limit     int
	Offset    int
}

// ListScansFilter is the filter struct for ListScans.
type ListScansFilter struct {
	TargetID *uuid.UUID
	Status   *ScanStatus
	Limit    int
	Offset   int
}

// ListFindingsFilter is the filter struct for ListFindings.
type ListFindingsFilter struct {
	ScanID   *uuid.UUID
	TargetID *uuid.UUID
	Severity *Severity
	Module   string
	Category string
	Limit    int
	Offset   int
}

// Repository abstracts persistence for the recon module. Implemented in
// internal/repository/postgres/recon_repo.go in the follow-up PR.
type Repository interface {
	// Targets
	InsertTarget(ctx context.Context, t *Target) error
	GetTargetByID(ctx context.Context, id uuid.UUID) (*Target, error)
	GetTargetByHash(ctx context.Context, typ TargetType, hash []byte) (*Target, error)
	ListTargets(ctx context.Context, filter ListTargetsFilter) ([]Target, error)
	DeleteTarget(ctx context.Context, id uuid.UUID) error

	// Ownership
	InsertOwnershipProof(ctx context.Context, p *OwnershipProof) error
	UpdateOwnershipProof(ctx context.Context, p *OwnershipProof) error
	GetOwnershipProofByID(ctx context.Context, id uuid.UUID) (*OwnershipProof, error)
	LatestVerifiedOwnership(ctx context.Context, targetID uuid.UUID) (*OwnershipProof, error)

	// Profiles
	GetProfileByID(ctx context.Context, id uuid.UUID) (*Profile, error)
	GetProfileByName(ctx context.Context, name string) (*Profile, error)
	ListProfiles(ctx context.Context) ([]Profile, error)
	InsertProfile(ctx context.Context, p *Profile) error
	UpdateProfile(ctx context.Context, p *Profile) error
	DeleteProfile(ctx context.Context, id uuid.UUID) error

	// Scans
	InsertScan(ctx context.Context, s *Scan) error
	UpdateScan(ctx context.Context, s *Scan) error
	GetScanByID(ctx context.Context, id uuid.UUID) (*Scan, error)
	ListScans(ctx context.Context, filter ListScansFilter) ([]Scan, error)

	// Findings
	UpsertFinding(ctx context.Context, f *Finding, rawEngine string, rawPayload []byte) error
	ListFindings(ctx context.Context, filter ListFindingsFilter) ([]Finding, error)

	// Summary
	UpsertScanSummary(ctx context.Context, s *ScanSummary) error
	GetScanSummary(ctx context.Context, scanID uuid.UUID) (*ScanSummary, error)

	// Audit
	AppendAudit(ctx context.Context, entry AuditEntry) error
}

// AuditAction values are the canonical strings the audit log carries.
// They appear in recon_audit_log.action and in API responses, so they
// are part of the public contract.
const (
	AuditActionModuleEnabled     = "module.enabled"
	AuditActionTargetCreated     = "target.created"
	AuditActionTargetDeleted     = "target.deleted"
	AuditActionOwnershipVerified = "ownership.verified"
	AuditActionScanStarted       = "scan.start"
	AuditActionScanCancelled     = "scan.cancelled"
	AuditActionRetentionDelete   = "retention.delete"
	AuditActionConnectorUpdated  = "connector.updated"
	AuditActionProfileCreated    = "profile.created"
	AuditActionProfileUpdated    = "profile.updated"
	AuditActionProfileDeleted    = "profile.deleted"
)

// AuditEntry is one row in the append-only audit log.
type AuditEntry struct {
	ActorID  *uuid.UUID
	Action   string
	TargetID *uuid.UUID
	ScanID   *uuid.UUID
	IP       string
	Details  map[string]any
}

// Engine drives an external recon backend (SpiderFoot in v26.5.0).
// Workers consume this to start, poll, and stop scans.
type Engine interface {
	// Name returns the engine's stable identifier (e.g., "spiderfoot").
	Name() string

	// Start kicks off a scan and returns the engine-side run ID.
	Start(ctx context.Context, req EngineStartRequest) (string, error)

	// Events streams findings as the scan progresses. The channel is
	// closed when the engine reports the scan has terminated.
	Events(ctx context.Context, runID string) (<-chan EngineEvent, error)

	// Cancel stops a running scan.
	Cancel(ctx context.Context, runID string) error

	// Status reports current scan state from the engine's perspective.
	Status(ctx context.Context, runID string) (EngineStatus, error)
}

// EngineStartRequest is the engine-agnostic payload to start a scan.
type EngineStartRequest struct {
	Target  Target
	Profile Profile
}

// EngineEvent is a single finding emitted by an engine.
type EngineEvent struct {
	Module     string
	Category   string
	Severity   Severity
	Value      string
	Source     string
	Confidence int
	RawPayload []byte
}

// EngineStatus is the engine's view of a scan run.
type EngineStatus struct {
	Status   ScanStatus
	Progress int // 0-100
	Error    string
}

// Connector represents an optional external API integration (HIBP, Shodan,
// etc.). Implementations are looked up by kind.
type Connector interface {
	Kind() string
	Enabled() bool
	HealthCheck(ctx context.Context) error
}

// ContainerLauncher is the abstraction over the local Docker engine used to
// run engine and toolkit containers. It is satisfied by the existing
// internal/docker client in the implementation PR.
type ContainerLauncher interface {
	EnsureRunning(ctx context.Context, spec ContainerSpec) (containerID string, err error)
	RunOnce(ctx context.Context, spec ContainerSpec) (output []byte, exitCode int, err error)

	// RunOnceWithCopy starts a one-shot container exactly like RunOnce,
	// then before removing it copies a single file out of the
	// container's filesystem (typically a tmpfs artifact written by the
	// command). It is used by the metadata stripper to retrieve the
	// cleaned file produced by mat2 in the toolkit container.
	RunOnceWithCopy(ctx context.Context, spec ContainerSpec, copyPath string) (output []byte, copied []byte, exitCode int, err error)

	Stop(ctx context.Context, containerID string) error
}

// ContainerSpec describes a container the recon module wants to run.
type ContainerSpec struct {
	Image       string
	Command     []string
	Env         map[string]string
	Mounts      []ContainerMount
	NetworkMode string
	ReadOnlyFS  bool
	NoNetwork   bool
	Timeout     time.Duration
	Labels      map[string]string
}

// ContainerMount mounts a host path into the container, always read-only by
// default for recon jobs.
type ContainerMount struct {
	Source   string
	Target   string
	ReadOnly bool
}
