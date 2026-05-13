// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package recon

import "errors"

// Sentinel errors returned by Service. Handlers switch on these with
// errors.Is to translate to the right HTTP status. They are part of the
// public contract: do not change the underlying error.New strings without
// a coordinated handler update.
var (
	// ErrTargetNotFound is returned when a target lookup misses.
	ErrTargetNotFound = errors.New("recon: target not found")

	// ErrTargetExists is returned by CreateTarget when (type, value_hash)
	// already exists. The handler maps this to 409 Conflict.
	ErrTargetExists = errors.New("recon: target already exists")

	// ErrTargetTypeUnsupported is returned when a caller asks for a
	// target type outside the closed TargetType set, or for a scan
	// against a profile whose target_types does not include the target's
	// type.
	ErrTargetTypeUnsupported = errors.New("recon: target type unsupported")

	// ErrTargetValueInvalid is returned when CreateTarget receives an
	// empty or malformed value after normalization.
	ErrTargetValueInvalid = errors.New("recon: target value invalid")

	// ErrOwnershipProofNotFound is returned when VerifyOwnershipProof is
	// called with an unknown proof id.
	ErrOwnershipProofNotFound = errors.New("recon: ownership proof not found")

	// ErrOwnershipMethodUnknown is returned when StartOwnershipProof gets
	// a method that is not registered with the service. (Different from
	// ErrOwnershipUnsupported, which signals that the method does not
	// support the target's type.)
	ErrOwnershipMethodUnknown = errors.New("recon: ownership method unknown")

	// ErrOwnershipRequired is returned by StartScan when the target's
	// type is in {email, domain, ip, ip_range} and there is no current
	// verified ownership proof.
	ErrOwnershipRequired = errors.New("recon: ownership required")

	// ErrProfileNotFound is returned when a profile lookup misses.
	ErrProfileNotFound = errors.New("recon: profile not found")

	// ErrScanNotFound is returned when a scan lookup misses.
	ErrScanNotFound = errors.New("recon: scan not found")

	// ErrScanInvalidState is returned by CancelScan when the scan is
	// already in a terminal state, and by RunScan when called against a
	// scan that is not queued.
	ErrScanInvalidState = errors.New("recon: scan invalid state")

	// ErrEngineUnavailable is returned when the service was constructed
	// without any engine, or when the profile selects an engine that is
	// not registered.
	ErrEngineUnavailable = errors.New("recon: engine unavailable")

	// ErrProfileExists is returned by CreateProfile when a profile with
	// the same name already exists. The handler maps this to 409.
	ErrProfileExists = errors.New("recon: profile already exists")

	// ErrProfileBuiltin is returned by UpdateProfile / DeleteProfile when
	// the target row's kind is 'builtin'. Built-in profiles ship with the
	// migration and are immutable. The handler maps this to 403.
	ErrProfileBuiltin = errors.New("recon: profile is builtin and immutable")

	// ErrProfileInUse is returned by DeleteProfile when the FK
	// recon_scans.profile_id (ON DELETE RESTRICT) blocks removal because
	// existing scans reference the profile. The handler maps this to 409.
	ErrProfileInUse = errors.New("recon: profile is referenced by existing scans")

	// ErrProfileInvalid is returned by CreateProfile / UpdateProfile when
	// validation fails: blank name, empty target_types, target_types not
	// in the closed enum, empty modules, or modules outside the known
	// catalog. The handler maps this to 400.
	ErrProfileInvalid = errors.New("recon: profile invalid")
)
