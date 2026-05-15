// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package recon

// Built-in profile kinds. The migration seeds rows whose `kind` matches
// one of these so the Service can pick an engine implementation without
// any extra metadata column.
const (
	ProfileKindSpiderFoot = "spiderfoot"
	ProfileKindToolkit    = "toolkit"
	ProfileKindStub       = "stub"
)

// profileSupportsTargetType reports whether the profile's TargetTypes
// list includes the given target type. The check is intentionally O(n)
// — the list is bounded by the closed TargetType set and the seeded
// profiles each list at most a handful of types.
func profileSupportsTargetType(p *Profile, t TargetType) bool {
	if p == nil {
		return false
	}
	for _, allowed := range p.TargetTypes {
		if allowed == t {
			return true
		}
	}
	return false
}

// requiresOwnershipProof reports whether the given target type cannot
// be scanned without a verified ownership proof. The closed set comes
// straight from docs/recon.md §7.1: identifiers that are scoped to a
// real-world resource the user has to demonstrate control of. Username
// and phone fall under self-assert and need no separate proof.
func requiresOwnershipProof(t TargetType) bool {
	switch t {
	case TargetEmail, TargetDomain, TargetIP, TargetIPRange:
		return true
	default:
		return false
	}
}

// isKnownTargetType returns true for any value in the closed
// TargetType enum. Used by CreateTarget to reject unknown types
// before they reach the repository.
func isKnownTargetType(t TargetType) bool {
	switch t {
	case TargetEmail, TargetPhone, TargetUsername, TargetDomain, TargetIP, TargetIPRange:
		return true
	default:
		return false
	}
}

// KnownModules is the closed catalog of recon modules a custom profile
// may reference. It is the union of every module ID that appears in
// the v26.5.0 builtin profile seed (migration 044) plus the engine
// stub used in tests. Custom profiles whose module list contains an
// identifier outside this set are rejected with ErrProfileInvalid so
// engines never receive instructions they cannot honor.
//
// The set is intentionally hard-coded rather than introspected at
// runtime from `recon_profiles` because: (a) builtin rows can be
// renamed/disabled by an operator without invalidating custom profiles
// that referenced their modules, and (b) the engine adapter for each
// module ships in code, not data — adding `sfp_newthing` is a code
// change that adds the line here and the matching adapter in the same
// PR.
var KnownModules = map[string]struct{}{
	// SpiderFoot modules — match the names emitted by upstream
	// SpiderFoot so the adapter does not have to translate.
	"sfp_haveibeen":      {},
	"sfp_hunter":         {},
	"sfp_emailrep":       {},
	"sfp_gravatar":       {},
	"sfp_dnsresolve":     {},
	"sfp_crt":            {},
	"sfp_subdomain_enum": {},
	"sfp_dnsbrute":       {},
	"sfp_sherlock":       {},
	"sfp_socialprofiles": {},

	// Toolkit modules — toolkit: prefix is what the toolkit container
	// adapter dispatches on internally.
	"toolkit:holehe":      {},
	"toolkit:subfinder":   {},
	"toolkit:phoneinfoga": {},

	// Stub module used by the in-process engine for tests.
	"stub-module": {},
}

// isKnownModule reports whether the module ID is in the closed
// KnownModules catalog. Validation for CreateProfile / UpdateProfile.
func isKnownModule(m string) bool {
	_, ok := KnownModules[m]
	return ok
}
