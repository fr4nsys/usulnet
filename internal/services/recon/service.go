// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package recon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// tracerName is the OpenTelemetry tracer the Service uses. All spans
// the Service opens are named `recon.service.<method>` so log/trace
// correlation is consistent.
const tracerName = "github.com/fr4nsys/usulnet/internal/services/recon"

// tracer is the package-level tracer handle. otel.Tracer is safe to
// call repeatedly; the otel SDK memoises the lookup.
func tracer() trace.Tracer { return otel.Tracer(tracerName) }

// Clock abstracts time.Now so unit tests can pin the clock without
// race-prone monkey patching. Service uses Now() for CreatedAt /
// UpdatedAt / StartedAt / FinishedAt and audit-entry timestamps.
type Clock interface {
	Now() time.Time
}

// realClock is the production Clock — wraps time.Now in UTC. The
// recon module persists everything in UTC so wall-clock skew between
// the API host and the database host does not produce relative
// timestamps that go backwards.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

// DefaultClock returns a Clock backed by time.Now() in UTC.
func DefaultClock() Clock { return realClock{} }

// Config captures the Service's tunables. Zero-valued fields fall back
// to safe defaults (see NewService).
type Config struct {
	// DefaultEngine is the engine name to use when a profile has no
	// engine selector. Defaults to "spiderfoot" when empty.
	DefaultEngine string

	// FindingsBufferSize is the channel buffer the engine event loop
	// uses to absorb bursts. Defaults to 16 when zero.
	FindingsBufferSize int
}

// Service is the concrete implementation of the recon.Service
// interface. It is constructed by the recon wiring package and
// consumed by the API handler, the web layer, and the recon-scan
// worker.
//
// All methods are context-aware, open an OpenTelemetry span, log
// entry with structured fields (scan_id/target_id/etc.) and wrap
// errors as `recon service: <verb>: %w`. None of them ever logs raw
// target values; only HexPrefix(value_hash, 8) appears in logs so PII
// does not leak through structured-log pipelines.
type Implementation struct {
	repo      Repository
	engines   map[string]Engine
	verifiers map[OwnershipMethod]OwnershipVerifier
	clock     Clock
	cfg       Config
	log       *logger.Logger
}

// Compile-time guarantee that *Implementation satisfies the
// recon.Service interface declared in recon.go.
var _ Service = (*Implementation)(nil)

// NewService constructs a Service. repo must be non-nil. engines may
// be empty — every per-scan path that depends on an engine returns
// ErrEngineUnavailable in that case so callers can keep ListTargets /
// ListScans serving even when no engine is wired (e.g., a worker
// host without Docker). verifiers must contain at least one
// OwnershipMethod or StartOwnershipProof always returns
// ErrOwnershipMethodUnknown. clock and log default to UTC time.Now
// and logger.Nop() respectively when nil.
func NewService(
	repo Repository,
	engines map[string]Engine,
	verifiers map[OwnershipMethod]OwnershipVerifier,
	clock Clock,
	cfg Config,
	log *logger.Logger,
) (*Implementation, error) {
	if repo == nil {
		return nil, errors.New("recon service: repo is required")
	}
	if engines == nil {
		engines = map[string]Engine{}
	}
	if verifiers == nil {
		verifiers = map[OwnershipMethod]OwnershipVerifier{}
	}
	if clock == nil {
		clock = DefaultClock()
	}
	if log == nil {
		log = logger.Nop()
	}
	if cfg.DefaultEngine == "" {
		cfg.DefaultEngine = ProfileKindSpiderFoot
	}
	if cfg.FindingsBufferSize <= 0 {
		cfg.FindingsBufferSize = 16
	}
	return &Implementation{
		repo:      repo,
		engines:   engines,
		verifiers: verifiers,
		clock:     clock,
		cfg:       cfg,
		log:       log.Named("recon.service"),
	}, nil
}

// ============================================================================
// Targets
// ============================================================================

// CreateTarget normalizes the value, hashes it, persists the target,
// and appends an audit entry. The handler maps ErrTargetExists to 409
// and ErrTargetTypeUnsupported / ErrTargetValueInvalid to 400.
func (s *Implementation) CreateTarget(ctx context.Context, in CreateTargetInput) (*Target, error) {
	ctx, span := tracer().Start(ctx, "recon.service.CreateTarget", trace.WithAttributes(
		attribute.String("target_type", string(in.Type)),
	))
	defer span.End()

	if !isKnownTargetType(in.Type) {
		return nil, fmt.Errorf("recon service: create target: %w", ErrTargetTypeUnsupported)
	}
	value := NormalizeValue(in.Value)
	if value == "" {
		return nil, fmt.Errorf("recon service: create target: %w", ErrTargetValueInvalid)
	}
	hash := HashValue(value)

	// Reject duplicates up-front so the handler can surface 409 without
	// surfacing a generic DB unique-violation. The repo layer also has
	// a unique index, so this is best-effort dedup not a guarantee.
	if existing, err := s.repo.GetTargetByHash(ctx, in.Type, hash); err == nil && existing != nil {
		s.log.Info("create target: duplicate",
			"target_type", string(in.Type),
			"value_hash", HexPrefix(hash, 8),
		)
		return nil, fmt.Errorf("recon service: create target: %w", ErrTargetExists)
	}

	now := s.clock.Now()
	t := &Target{
		ID:        uuid.New(),
		Type:      in.Type,
		Value:     value,
		ValueHash: hash,
		Label:     strings.TrimSpace(in.Label),
		CreatedBy: in.CreatedBy,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.repo.InsertTarget(ctx, t); err != nil {
		return nil, fmt.Errorf("recon service: create target: %w", err)
	}

	s.appendAudit(ctx, newAuditEntry(AuditActionTargetCreated).
		Actor(in.CreatedBy).
		Target(t.ID).
		WithDetail("target_type", string(t.Type)).
		WithDetail("value_hash", HexPrefix(hash, 8)).
		Build())

	s.log.Info("target created",
		"target_id", t.ID,
		"target_type", string(t.Type),
		"value_hash", HexPrefix(hash, 8),
	)
	return t, nil
}

// GetTarget returns a target by ID.
func (s *Implementation) GetTarget(ctx context.Context, id uuid.UUID) (*Target, error) {
	ctx, span := tracer().Start(ctx, "recon.service.GetTarget", trace.WithAttributes(
		attribute.String("target_id", id.String()),
	))
	defer span.End()

	t, err := s.repo.GetTargetByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("recon service: get target: %w", ErrTargetNotFound)
		}
		return nil, fmt.Errorf("recon service: get target: %w", err)
	}
	return t, nil
}

// ListTargets paginates targets, optionally filtered by type or
// creator. An unset Limit defaults to 50; values >200 are clamped.
func (s *Implementation) ListTargets(ctx context.Context, filter ListTargetsFilter) ([]Target, error) {
	ctx, span := tracer().Start(ctx, "recon.service.ListTargets")
	defer span.End()

	filter = clampPagination(filter, listTargetsPager{}).(ListTargetsFilter)

	targets, err := s.repo.ListTargets(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("recon service: list targets: %w", err)
	}
	return targets, nil
}

// DeleteTarget removes a target row. Deleting a target that does not
// exist returns ErrTargetNotFound so the handler can surface 404
// rather than 500.
func (s *Implementation) DeleteTarget(ctx context.Context, id uuid.UUID) error {
	ctx, span := tracer().Start(ctx, "recon.service.DeleteTarget", trace.WithAttributes(
		attribute.String("target_id", id.String()),
	))
	defer span.End()

	t, err := s.repo.GetTargetByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("recon service: delete target: %w", ErrTargetNotFound)
		}
		return fmt.Errorf("recon service: delete target: %w", err)
	}

	if err := s.repo.DeleteTarget(ctx, id); err != nil {
		return fmt.Errorf("recon service: delete target: %w", err)
	}

	s.appendAudit(ctx, newAuditEntry(AuditActionTargetDeleted).
		Target(t.ID).
		WithDetail("target_type", string(t.Type)).
		WithDetail("value_hash", HexPrefix(t.ValueHash, 8)).
		Build())

	s.log.Info("target deleted",
		"target_id", t.ID,
		"target_type", string(t.Type),
	)
	return nil
}

// ============================================================================
// Ownership
// ============================================================================

// StartOwnershipProof creates a fresh proof row for the (target,
// method) pair and lets the matching verifier populate Challenge /
// Evidence. The proof persists with whatever Status the verifier sets
// — self-assert flips it to verified immediately; DNS / email leave
// it pending until Verify runs.
func (s *Implementation) StartOwnershipProof(ctx context.Context, targetID uuid.UUID, method OwnershipMethod) (*OwnershipProof, error) {
	ctx, span := tracer().Start(ctx, "recon.service.StartOwnershipProof", trace.WithAttributes(
		attribute.String("target_id", targetID.String()),
		attribute.String("method", string(method)),
	))
	defer span.End()

	verifier, ok := s.verifiers[method]
	if !ok {
		return nil, fmt.Errorf("recon service: start ownership: %w", ErrOwnershipMethodUnknown)
	}

	target, err := s.repo.GetTargetByID(ctx, targetID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("recon service: start ownership: %w", ErrTargetNotFound)
		}
		return nil, fmt.Errorf("recon service: start ownership: %w", err)
	}

	now := s.clock.Now()
	proof := &OwnershipProof{
		ID:        uuid.New(),
		TargetID:  target.ID,
		Method:    method,
		Status:    OwnershipPending,
		Evidence:  map[string]any{},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := verifier.Start(ctx, target, proof); err != nil {
		return nil, fmt.Errorf("recon service: start ownership: %w", err)
	}

	if err := s.repo.InsertOwnershipProof(ctx, proof); err != nil {
		return nil, fmt.Errorf("recon service: start ownership: %w", err)
	}

	s.log.Info("ownership proof started",
		"target_id", target.ID,
		"proof_id", proof.ID,
		"method", string(method),
		"status", string(proof.Status),
	)
	return proof, nil
}

// VerifyOwnershipProof runs the registered verifier against an
// existing proof. The verifier mutates proof.Status / VerifiedAt /
// Evidence in place; this method persists the result and writes an
// audit row when the proof flips to verified.
func (s *Implementation) VerifyOwnershipProof(ctx context.Context, proofID uuid.UUID) (*OwnershipProof, error) {
	ctx, span := tracer().Start(ctx, "recon.service.VerifyOwnershipProof", trace.WithAttributes(
		attribute.String("proof_id", proofID.String()),
	))
	defer span.End()

	proof, err := s.repo.GetOwnershipProofByID(ctx, proofID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("recon service: verify ownership: %w", ErrOwnershipProofNotFound)
		}
		return nil, fmt.Errorf("recon service: verify ownership: %w", err)
	}

	verifier, ok := s.verifiers[proof.Method]
	if !ok {
		return proof, fmt.Errorf("recon service: verify ownership: %w", ErrOwnershipMethodUnknown)
	}

	target, err := s.repo.GetTargetByID(ctx, proof.TargetID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return proof, fmt.Errorf("recon service: verify ownership: %w", ErrTargetNotFound)
		}
		return proof, fmt.Errorf("recon service: verify ownership: %w", err)
	}

	verifyErr := verifier.Verify(ctx, target, proof, nil)
	proof.UpdatedAt = s.clock.Now()

	if updateErr := s.repo.UpdateOwnershipProof(ctx, proof); updateErr != nil {
		s.log.Warn("ownership proof update failed",
			"proof_id", proof.ID,
			"error", updateErr,
		)
		// Prefer surfacing the verification error to the caller;
		// the update failure is a separate operational concern.
		if verifyErr != nil {
			return proof, fmt.Errorf("recon service: verify ownership: %w", verifyErr)
		}
		return proof, fmt.Errorf("recon service: verify ownership: persist: %w", updateErr)
	}

	if verifyErr != nil {
		return proof, fmt.Errorf("recon service: verify ownership: %w", verifyErr)
	}

	if proof.Status == OwnershipVerified {
		s.appendAudit(ctx, newAuditEntry(AuditActionOwnershipVerified).
			Target(target.ID).
			WithDetail("method", string(proof.Method)).
			WithDetail("proof_id", proof.ID.String()).
			Build())
		s.log.Info("ownership proof verified",
			"target_id", target.ID,
			"proof_id", proof.ID,
			"method", string(proof.Method),
		)
	}
	return proof, nil
}

// ============================================================================
// Profiles
// ============================================================================

// ListProfiles returns every recon profile seeded in the database.
// Profiles are static for v26.5.0 (user-defined profiles land in
// v26.5.1) so no pagination is required.
func (s *Implementation) ListProfiles(ctx context.Context) ([]Profile, error) {
	ctx, span := tracer().Start(ctx, "recon.service.ListProfiles")
	defer span.End()

	profiles, err := s.repo.ListProfiles(ctx)
	if err != nil {
		return nil, fmt.Errorf("recon service: list profiles: %w", err)
	}
	return profiles, nil
}

// CreateProfile persists a new user-defined profile. The resulting
// row's Kind is always "custom". Validation rejects blank names, an
// empty TargetTypes slice, target types outside the closed enum,
// empty module lists, and modules outside the KnownModules catalog.
// Duplicate names surface as ErrProfileExists.
func (s *Implementation) CreateProfile(ctx context.Context, in CreateProfileInput) (*Profile, error) {
	ctx, span := tracer().Start(ctx, "recon.service.CreateProfile")
	defer span.End()

	name := strings.TrimSpace(in.Name)
	if err := validateProfileFields(name, in.TargetTypes, in.Modules); err != nil {
		return nil, fmt.Errorf("recon service: create profile: %w", err)
	}

	now := s.clock.Now()
	p := &Profile{
		ID:          uuid.New(),
		Name:        name,
		Description: strings.TrimSpace(in.Description),
		Kind:        "custom",
		TargetTypes: append([]TargetType(nil), in.TargetTypes...),
		Modules:     append([]string(nil), in.Modules...),
		Options:     in.Options,
		CreatedBy:   in.CreatedBy,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.repo.InsertProfile(ctx, p); err != nil {
		if errors.Is(err, ErrProfileExists) {
			return nil, fmt.Errorf("recon service: create profile: %w", err)
		}
		return nil, fmt.Errorf("recon service: create profile: %w", err)
	}

	s.appendAudit(ctx, newAuditEntry(AuditActionProfileCreated).
		Actor(in.CreatedBy).
		WithDetail("profile_id", p.ID.String()).
		WithDetail("name", p.Name).
		Build())

	s.log.Info("profile created",
		"profile_id", p.ID,
		"name", p.Name,
		"target_types", in.TargetTypes,
	)
	return p, nil
}

// UpdateProfile mutates a user-defined profile. Builtin rows are
// rejected with ErrProfileBuiltin; missing rows with ErrProfileNotFound.
// Validation rules mirror CreateProfile.
func (s *Implementation) UpdateProfile(ctx context.Context, id uuid.UUID, in UpdateProfileInput) (*Profile, error) {
	ctx, span := tracer().Start(ctx, "recon.service.UpdateProfile", trace.WithAttributes(
		attribute.String("profile_id", id.String()),
	))
	defer span.End()

	existing, err := s.repo.GetProfileByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("recon service: update profile: %w", ErrProfileNotFound)
		}
		return nil, fmt.Errorf("recon service: update profile: %w", err)
	}
	if existing.Kind != "custom" {
		return nil, fmt.Errorf("recon service: update profile: %w", ErrProfileBuiltin)
	}

	name := strings.TrimSpace(in.Name)
	if err := validateProfileFields(name, in.TargetTypes, in.Modules); err != nil {
		return nil, fmt.Errorf("recon service: update profile: %w", err)
	}

	existing.Name = name
	existing.Description = strings.TrimSpace(in.Description)
	existing.TargetTypes = append([]TargetType(nil), in.TargetTypes...)
	existing.Modules = append([]string(nil), in.Modules...)
	existing.Options = in.Options

	if err := s.repo.UpdateProfile(ctx, existing); err != nil {
		if errors.Is(err, ErrProfileExists) {
			return nil, fmt.Errorf("recon service: update profile: %w", err)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			// Row was deleted (or flipped to builtin, which the schema
			// disallows but be defensive) between the read and the
			// write. Surface as not-found.
			return nil, fmt.Errorf("recon service: update profile: %w", ErrProfileNotFound)
		}
		return nil, fmt.Errorf("recon service: update profile: %w", err)
	}

	s.appendAudit(ctx, newAuditEntry(AuditActionProfileUpdated).
		WithDetail("profile_id", existing.ID.String()).
		WithDetail("name", existing.Name).
		Build())

	s.log.Info("profile updated",
		"profile_id", existing.ID,
		"name", existing.Name,
	)
	return existing, nil
}

// DeleteProfile removes a user-defined profile. Builtin rows return
// ErrProfileBuiltin; missing rows return ErrProfileNotFound. The FK
// recon_scans.profile_id ON DELETE RESTRICT surfaces as
// ErrProfileInUse — operators must delete (or wait out retention of)
// the referencing scans before removing the profile.
func (s *Implementation) DeleteProfile(ctx context.Context, id uuid.UUID) error {
	ctx, span := tracer().Start(ctx, "recon.service.DeleteProfile", trace.WithAttributes(
		attribute.String("profile_id", id.String()),
	))
	defer span.End()

	existing, err := s.repo.GetProfileByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("recon service: delete profile: %w", ErrProfileNotFound)
		}
		return fmt.Errorf("recon service: delete profile: %w", err)
	}
	if existing.Kind != "custom" {
		return fmt.Errorf("recon service: delete profile: %w", ErrProfileBuiltin)
	}

	if err := s.repo.DeleteProfile(ctx, id); err != nil {
		if errors.Is(err, ErrProfileInUse) {
			return fmt.Errorf("recon service: delete profile: %w", err)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("recon service: delete profile: %w", ErrProfileNotFound)
		}
		return fmt.Errorf("recon service: delete profile: %w", err)
	}

	s.appendAudit(ctx, newAuditEntry(AuditActionProfileDeleted).
		WithDetail("profile_id", existing.ID.String()).
		WithDetail("name", existing.Name).
		Build())

	s.log.Info("profile deleted",
		"profile_id", existing.ID,
		"name", existing.Name,
	)
	return nil
}

// validateProfileFields applies the rules shared by CreateProfile and
// UpdateProfile. All failures return ErrProfileInvalid wrapped with
// the offending field so the handler can surface a usable message.
func validateProfileFields(name string, targetTypes []TargetType, modules []string) error {
	if name == "" {
		return fmt.Errorf("%w: name is required", ErrProfileInvalid)
	}
	if len(name) > 128 {
		return fmt.Errorf("%w: name must be <= 128 characters", ErrProfileInvalid)
	}
	if len(targetTypes) == 0 {
		return fmt.Errorf("%w: target_types is required", ErrProfileInvalid)
	}
	seenTypes := make(map[TargetType]struct{}, len(targetTypes))
	for _, tt := range targetTypes {
		if !isKnownTargetType(tt) {
			return fmt.Errorf("%w: unsupported target type %q", ErrProfileInvalid, tt)
		}
		if _, dup := seenTypes[tt]; dup {
			return fmt.Errorf("%w: duplicate target type %q", ErrProfileInvalid, tt)
		}
		seenTypes[tt] = struct{}{}
	}
	if len(modules) == 0 {
		return fmt.Errorf("%w: modules is required", ErrProfileInvalid)
	}
	seenModules := make(map[string]struct{}, len(modules))
	for _, m := range modules {
		if !isKnownModule(m) {
			return fmt.Errorf("%w: unknown module %q", ErrProfileInvalid, m)
		}
		if _, dup := seenModules[m]; dup {
			return fmt.Errorf("%w: duplicate module %q", ErrProfileInvalid, m)
		}
		seenModules[m] = struct{}{}
	}
	return nil
}

// GetProfile returns one profile by ID, or ErrProfileNotFound.
func (s *Implementation) GetProfile(ctx context.Context, id uuid.UUID) (*Profile, error) {
	ctx, span := tracer().Start(ctx, "recon.service.GetProfile", trace.WithAttributes(
		attribute.String("profile_id", id.String()),
	))
	defer span.End()

	p, err := s.repo.GetProfileByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("recon service: get profile: %w", ErrProfileNotFound)
		}
		return nil, fmt.Errorf("recon service: get profile: %w", err)
	}
	return p, nil
}

// ============================================================================
// Scans
// ============================================================================

// StartScan validates the (target, profile) pair, enforces the
// ownership requirement for the closed set of "must-own" target
// types, persists the scan row in `queued` state, and returns the
// scan to the caller. The actual engine call happens later in
// RunScan, driven by the recon-scan worker.
func (s *Implementation) StartScan(ctx context.Context, in StartScanInput) (*Scan, error) {
	ctx, span := tracer().Start(ctx, "recon.service.StartScan", trace.WithAttributes(
		attribute.String("target_id", in.TargetID.String()),
		attribute.String("profile_id", in.ProfileID.String()),
	))
	defer span.End()

	target, err := s.repo.GetTargetByID(ctx, in.TargetID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("recon service: start scan: %w", ErrTargetNotFound)
		}
		return nil, fmt.Errorf("recon service: start scan: %w", err)
	}

	profile, err := s.repo.GetProfileByID(ctx, in.ProfileID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("recon service: start scan: %w", ErrProfileNotFound)
		}
		return nil, fmt.Errorf("recon service: start scan: %w", err)
	}

	if !profileSupportsTargetType(profile, target.Type) {
		return nil, fmt.Errorf("recon service: start scan: %w", ErrTargetTypeUnsupported)
	}

	if requiresOwnershipProof(target.Type) {
		if _, err := s.repo.LatestVerifiedOwnership(ctx, target.ID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, fmt.Errorf("recon service: start scan: %w", ErrOwnershipRequired)
			}
			return nil, fmt.Errorf("recon service: start scan: %w", err)
		}
	}

	engineName := profile.Kind
	if engineName == "" {
		engineName = s.cfg.DefaultEngine
	}

	now := s.clock.Now()
	scan := &Scan{
		ID:        uuid.New(),
		TargetID:  target.ID,
		ProfileID: profile.ID,
		Status:    ScanQueued,
		Engine:    engineName,
		CreatedBy: in.CreatedBy,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.repo.InsertScan(ctx, scan); err != nil {
		return nil, fmt.Errorf("recon service: start scan: %w", err)
	}

	s.appendAudit(ctx, newAuditEntry(AuditActionScanStarted).
		Actor(in.CreatedBy).
		Target(target.ID).
		Scan(scan.ID).
		WithDetail("profile_id", profile.ID.String()).
		WithDetail("engine", engineName).
		Build())

	s.log.Info("scan queued",
		"scan_id", scan.ID,
		"target_id", target.ID,
		"profile_id", profile.ID,
		"engine", engineName,
	)
	return scan, nil
}

// GetScan returns one scan row, or ErrScanNotFound.
func (s *Implementation) GetScan(ctx context.Context, id uuid.UUID) (*Scan, error) {
	ctx, span := tracer().Start(ctx, "recon.service.GetScan", trace.WithAttributes(
		attribute.String("scan_id", id.String()),
	))
	defer span.End()

	scan, err := s.repo.GetScanByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("recon service: get scan: %w", ErrScanNotFound)
		}
		return nil, fmt.Errorf("recon service: get scan: %w", err)
	}
	return scan, nil
}

// ListScans paginates scans, optionally filtered by target or
// status. Limit defaults to 50; values >200 are clamped.
func (s *Implementation) ListScans(ctx context.Context, filter ListScansFilter) ([]Scan, error) {
	ctx, span := tracer().Start(ctx, "recon.service.ListScans")
	defer span.End()

	filter = clampPagination(filter, listScansPager{}).(ListScansFilter)

	scans, err := s.repo.ListScans(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("recon service: list scans: %w", err)
	}
	return scans, nil
}

// CancelScan flips a queued or running scan to canceled. Terminal
// scans (completed / failed / canceled) return ErrScanInvalidState.
// The engine is signaled to stop only if the scan was running and an
// EngineRunID is recorded; engines that no longer know the run ID
// simply ignore the call.
func (s *Implementation) CancelScan(ctx context.Context, id uuid.UUID) error {
	ctx, span := tracer().Start(ctx, "recon.service.CancelScan", trace.WithAttributes(
		attribute.String("scan_id", id.String()),
	))
	defer span.End()

	scan, err := s.repo.GetScanByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("recon service: cancel scan: %w", ErrScanNotFound)
		}
		return fmt.Errorf("recon service: cancel scan: %w", err)
	}

	switch scan.Status {
	case ScanCompleted, ScanFailed, ScanCancelled:
		return fmt.Errorf("recon service: cancel scan: %w", ErrScanInvalidState)
	}

	if scan.Status == ScanRunning && scan.EngineRunID != "" {
		if engine, ok := s.engines[scan.Engine]; ok {
			if err := engine.Cancel(ctx, scan.EngineRunID); err != nil {
				s.log.Warn("engine cancel returned error",
					"scan_id", scan.ID,
					"engine", scan.Engine,
					"run_id", scan.EngineRunID,
					"error", err,
				)
			}
		}
	}

	now := s.clock.Now()
	scan.Status = ScanCancelled
	scan.FinishedAt = &now
	scan.UpdatedAt = now
	if err := s.repo.UpdateScan(ctx, scan); err != nil {
		return fmt.Errorf("recon service: cancel scan: %w", err)
	}

	s.appendAudit(ctx, newAuditEntry(AuditActionScanCancelled).
		Target(scan.TargetID).
		Scan(scan.ID).
		Build())

	s.log.Info("scan canceled",
		"scan_id", scan.ID,
		"target_id", scan.TargetID,
		"engine", scan.Engine,
	)
	return nil
}

// ============================================================================
// Findings & reports
// ============================================================================

// ListFindings paginates findings. ScanID and TargetID filters
// compose with AND semantics; both nil returns the full set
// (paginated). Limit defaults to 50; values >500 are clamped (this
// surface drives report tables that can carry more rows than the
// scan/target lists).
func (s *Implementation) ListFindings(ctx context.Context, filter ListFindingsFilter) ([]Finding, error) {
	ctx, span := tracer().Start(ctx, "recon.service.ListFindings")
	defer span.End()

	filter = clampPagination(filter, listFindingsPager{}).(ListFindingsFilter)

	findings, err := s.repo.ListFindings(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("recon service: list findings: %w", err)
	}
	return findings, nil
}

// GetScanSummary returns the persisted summary for a completed scan.
// Scans that have not produced a summary yet return ErrScanNotFound
// (handler turns that into 404). For ongoing scans the API surface
// should consult GetScan + ListFindings instead.
func (s *Implementation) GetScanSummary(ctx context.Context, scanID uuid.UUID) (*ScanSummary, error) {
	ctx, span := tracer().Start(ctx, "recon.service.GetScanSummary", trace.WithAttributes(
		attribute.String("scan_id", scanID.String()),
	))
	defer span.End()

	summary, err := s.repo.GetScanSummary(ctx, scanID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("recon service: get scan summary: %w", ErrScanNotFound)
		}
		return nil, fmt.Errorf("recon service: get scan summary: %w", err)
	}
	return summary, nil
}

// ============================================================================
// RunScan — driven by the recon-scan worker (workers.ReconScanService)
// ============================================================================

// RunScan drives one queued scan to its terminal state. It is called
// by the scheduler worker after a queued scan job is dequeued; it
// must NEVER be called from request-handling goroutines because the
// engine event loop blocks for the duration of the scan.
//
// The control flow mirrors the contract in docs/recon.md §6.2:
//
//  1. Look up the scan row and assert it is queued.
//  2. Look up the matching engine; if unwired, mark the scan failed
//     with `engine_unavailable` and return ErrEngineUnavailable.
//  3. Load the profile + target.
//  4. Flip the scan to running, record StartedAt, persist.
//  5. Engine.Start → engineRunID, write engineRunID back to the row.
//  6. Engine.Events → stream; per event:
//     - build a Finding, hash the value, call Repository.UpsertFinding
//     with the raw payload.
//     - bump counts in a local map keyed by Severity.
//  7. On channel close: flip the scan to completed, write
//     ScanSummary with the counts and a coarse Grade.
//  8. On ctx.Done: try Engine.Cancel, flip the scan to canceled.
//
// Failure surfaces from RunScan are recorded against the scan row by
// the Service itself; the worker does NOT mutate the row. The
// returned error is the engine's last error wrapped with
// `recon service: run scan: %w`.
func (s *Implementation) RunScan(ctx context.Context, scanID uuid.UUID) error {
	ctx, span := tracer().Start(ctx, "recon.service.RunScan", trace.WithAttributes(
		attribute.String("scan_id", scanID.String()),
	))
	defer span.End()

	scan, err := s.repo.GetScanByID(ctx, scanID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("recon service: run scan: %w", ErrScanNotFound)
		}
		return fmt.Errorf("recon service: run scan: %w", err)
	}
	if scan.Status != ScanQueued {
		return fmt.Errorf("recon service: run scan: %w", ErrScanInvalidState)
	}

	engine, ok := s.engines[scan.Engine]
	if !ok {
		return s.markScanFailed(ctx, scan, ErrEngineUnavailable)
	}

	target, err := s.repo.GetTargetByID(ctx, scan.TargetID)
	if err != nil {
		return s.markScanFailed(ctx, scan, fmt.Errorf("load target: %w", err))
	}
	profile, err := s.repo.GetProfileByID(ctx, scan.ProfileID)
	if err != nil {
		return s.markScanFailed(ctx, scan, fmt.Errorf("load profile: %w", err))
	}

	if err := s.transitionScanRunning(ctx, scan); err != nil {
		return err
	}

	runID, err := engine.Start(ctx, EngineStartRequest{Target: *target, Profile: *profile})
	if err != nil {
		return s.markScanFailed(ctx, scan, fmt.Errorf("engine start: %w", err))
	}
	scan.EngineRunID = runID
	scan.UpdatedAt = s.clock.Now()
	if err := s.repo.UpdateScan(ctx, scan); err != nil {
		// Persisting the runID is best-effort; we keep going so the
		// engine's work is not lost just because the row update raced
		// with another writer.
		s.log.Warn("scan run id persist failed",
			"scan_id", scan.ID,
			"engine_run_id", runID,
			"error", err,
		)
	}

	events, err := engine.Events(ctx, runID)
	if err != nil {
		return s.markScanFailed(ctx, scan, fmt.Errorf("engine events: %w", err))
	}

	counts := make(map[string]int, 5)
	for {
		select {
		case <-ctx.Done():
			// Cooperative cancellation: signal the engine, persist the
			// canceled status, and return the context error. The
			// caller (worker) records the cancellation against the job.
			if cancelErr := engine.Cancel(context.Background(), runID); cancelErr != nil {
				s.log.Warn("engine cancel during context cancel failed",
					"scan_id", scan.ID,
					"engine_run_id", runID,
					"error", cancelErr,
				)
			}
			return s.transitionScanCancelled(ctx, scan)
		case event, more := <-events:
			if !more {
				return s.completeScan(ctx, scan, target, counts)
			}
			s.persistEventAsFinding(ctx, scan, target, event, counts)
		}
	}
}

// persistEventAsFinding builds a Finding from an EngineEvent and
// writes it through the repository. Repository errors are logged but
// do not abort the scan — losing one finding is preferable to losing
// the rest of the run. counts is bumped for the event's severity.
func (s *Implementation) persistEventAsFinding(
	ctx context.Context,
	scan *Scan,
	target *Target,
	event EngineEvent,
	counts map[string]int,
) {
	now := s.clock.Now()
	finding := &Finding{
		ID:         uuid.New(),
		ScanID:     scan.ID,
		TargetID:   target.ID,
		Module:     event.Module,
		Category:   event.Category,
		Severity:   event.Severity,
		Value:      event.Value,
		ValueHash:  HashValue(event.Value),
		Source:     event.Source,
		Confidence: event.Confidence,
		FirstSeen:  now,
		LastSeen:   now,
	}
	if err := s.repo.UpsertFinding(ctx, finding, scan.Engine, event.RawPayload); err != nil {
		s.log.Warn("finding upsert failed",
			"scan_id", scan.ID,
			"module", event.Module,
			"category", event.Category,
			"error", err,
		)
		return
	}
	if string(event.Severity) == "" {
		counts[string(SeverityInfo)]++
	} else {
		counts[string(event.Severity)]++
	}
}

// transitionScanRunning flips a queued scan to running. The clock is
// the Service's clock so tests can pin StartedAt deterministically.
func (s *Implementation) transitionScanRunning(ctx context.Context, scan *Scan) error {
	now := s.clock.Now()
	scan.Status = ScanRunning
	scan.StartedAt = &now
	scan.UpdatedAt = now
	if err := s.repo.UpdateScan(ctx, scan); err != nil {
		return fmt.Errorf("recon service: run scan: persist running: %w", err)
	}
	s.log.Info("scan running",
		"scan_id", scan.ID,
		"engine", scan.Engine,
	)
	return nil
}

// completeScan writes the scan summary and flips the scan to
// completed. The summary's Grade is derived from the count of
// findings at high/critical severity: any critical → "F", any high
// → "C", otherwise "A". v26.5.1 introduces a richer grader.
func (s *Implementation) completeScan(ctx context.Context, scan *Scan, target *Target, counts map[string]int) error {
	now := s.clock.Now()
	summary := &ScanSummary{
		ScanID:      scan.ID,
		Counts:      counts,
		Grade:       grade(counts),
		GeneratedAt: now,
	}
	if err := s.repo.UpsertScanSummary(ctx, summary); err != nil {
		s.log.Warn("scan summary persist failed",
			"scan_id", scan.ID,
			"error", err,
		)
	}

	scan.Status = ScanCompleted
	scan.FinishedAt = &now
	scan.UpdatedAt = now
	if err := s.repo.UpdateScan(ctx, scan); err != nil {
		return fmt.Errorf("recon service: run scan: persist completed: %w", err)
	}

	s.log.Info("scan completed",
		"scan_id", scan.ID,
		"target_id", target.ID,
		"engine", scan.Engine,
		"counts", counts,
		"grade", summary.Grade,
	)
	return nil
}

// transitionScanCancelled writes a canceled status row. The caller
// already signaled the engine.
func (s *Implementation) transitionScanCancelled(ctx context.Context, scan *Scan) error {
	now := s.clock.Now()
	scan.Status = ScanCancelled
	scan.FinishedAt = &now
	scan.UpdatedAt = now
	if err := s.repo.UpdateScan(ctx, scan); err != nil {
		return fmt.Errorf("recon service: run scan: persist canceled: %w", err)
	}
	return fmt.Errorf("recon service: run scan: %w", context.Canceled)
}

// markScanFailed persists a failed status with the error message and
// returns the wrapped error so callers can surface the same string
// to the worker.
func (s *Implementation) markScanFailed(ctx context.Context, scan *Scan, cause error) error {
	now := s.clock.Now()
	scan.Status = ScanFailed
	scan.FinishedAt = &now
	scan.UpdatedAt = now
	scan.Error = cause.Error()
	if err := s.repo.UpdateScan(ctx, scan); err != nil {
		s.log.Warn("scan failure persist failed",
			"scan_id", scan.ID,
			"error", err,
			"cause", cause,
		)
	}
	s.log.Warn("scan failed",
		"scan_id", scan.ID,
		"engine", scan.Engine,
		"cause", cause,
	)
	return fmt.Errorf("recon service: run scan: %w", cause)
}

// grade returns the coarse scan grade as documented in the RFC:
// critical → F, high → C, else A. The map keys are Severity strings.
func grade(counts map[string]int) string {
	if counts[string(SeverityCritical)] > 0 {
		return "F"
	}
	if counts[string(SeverityHigh)] > 0 {
		return "C"
	}
	return "A"
}

// ============================================================================
// Pagination clamps
// ============================================================================

// listTargetsPager / listScansPager / listFindingsPager satisfy a
// minimal interface so clampPagination can be one function instead of
// three. The compiler erases the boxing because all sites use
// concrete filter types.

const (
	defaultPageLimit   = 50
	maxPageLimitList   = 200
	maxPageLimitFinds  = 500
	minPaginationLimit = 1
)

type pager interface {
	clamp(int, int) any
}

type listTargetsPager struct{}

func (listTargetsPager) clamp(limit, offset int) any {
	return ListTargetsFilter{Limit: limit, Offset: offset}
}

type listScansPager struct{}

func (listScansPager) clamp(limit, offset int) any {
	return ListScansFilter{Limit: limit, Offset: offset}
}

type listFindingsPager struct{}

func (listFindingsPager) clamp(limit, offset int) any {
	return ListFindingsFilter{Limit: limit, Offset: offset}
}

// clampPagination is a type-agnostic pagination defaulter. It returns
// the filter struct it was passed with Limit / Offset clamped to safe
// values: empty Limit → defaultPageLimit, negative Limit → 1,
// Limit > max → max. The max comes from the pager (200 for
// targets/scans, 500 for findings); offset is clamped to >= 0.
func clampPagination(filter any, p pager) any {
	switch f := filter.(type) {
	case ListTargetsFilter:
		l, o := clampLimits(f.Limit, f.Offset, maxPageLimitList)
		f.Limit, f.Offset = l, o
		return f
	case ListScansFilter:
		l, o := clampLimits(f.Limit, f.Offset, maxPageLimitList)
		f.Limit, f.Offset = l, o
		return f
	case ListFindingsFilter:
		l, o := clampLimits(f.Limit, f.Offset, maxPageLimitFinds)
		f.Limit, f.Offset = l, o
		return f
	}
	return filter
}

func clampLimits(limit, offset, max int) (int, int) {
	switch {
	case limit == 0:
		limit = defaultPageLimit
	case limit < minPaginationLimit:
		limit = minPaginationLimit
	case limit > max:
		limit = max
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
