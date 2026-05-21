// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"path"
	"time"

	"github.com/google/uuid"
)

// EgressPolicy is one allow- or deny-rule for the L7 egress forward
// proxy at internal/services/egress. Policies are scoped per host and
// matched against the outbound request's target hostname (port stripped).
// Evaluation order is created_at ascending; first match wins. When a host
// has at least one policy and none match, the request is denied — see
// migration 058 for the full rationale.
type EgressPolicy struct {
	ID         uuid.UUID `json:"id" db:"id"`
	HostID     uuid.UUID `json:"host_id" db:"host_id"`
	TargetGlob string    `json:"target_glob" db:"target_glob"`
	Allow      bool      `json:"allow" db:"allow"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`
}

// CreateEgressPolicyInput is the write surface for POST /egress/policies.
type CreateEgressPolicyInput struct {
	TargetGlob string `json:"target_glob"`
	Allow      bool   `json:"allow"`
}

// EgressAuditLog is one denied-request record. Allowed requests are not
// recorded — the operator privacy / log volume tradeoff favors dropping
// the success path.
type EgressAuditLog struct {
	ID        uuid.UUID `json:"id" db:"id"`
	HostID    uuid.UUID `json:"host_id" db:"host_id"`
	Target    string    `json:"target" db:"target"`
	Method    string    `json:"method" db:"method"`
	Decision  string    `json:"decision" db:"decision"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// EgressMatch tests whether a target hostname matches a glob pattern.
// Uses path.Match semantics — '*' matches any sequence of characters in
// a single segment, '?' matches any single character. Hostnames have no
// '/' separator so path.Match's segment rule does not restrict matching.
// Comparison is case-insensitive: hostnames are case-insensitive per
// RFC 1035 §2.3.3, and operators expect 'Github.com' to match 'github.com'.
func EgressMatch(pattern, host string) bool {
	matched, err := path.Match(lowerASCII(pattern), lowerASCII(host))
	if err != nil {
		return false
	}
	return matched
}

// lowerASCII lowercases ASCII letters without allocating for non-ASCII
// inputs that are already lower. Hostnames are ASCII per IDN-to-Punycode
// (the DNS lookup later does the same), so the simple branch is enough.
func lowerASCII(s string) string {
	needs := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			needs = true
			break
		}
	}
	if !needs {
		return s
	}
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
