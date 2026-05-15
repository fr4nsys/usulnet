// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet
//
// Access-list rule evaluation. Used by the proxy service to enforce the
// precedence contract (explicit deny > explicit allow > default) and by
// unit tests that pin the rule semantics independent of the backend.

package proxy

import (
	"net"
	"strings"

	"github.com/fr4nsys/usulnet/internal/models"
)

// AccessDecision describes the outcome of an access-list evaluation
// for a single request.
type AccessDecision int

const (
	// AccessDenied — at least one explicit deny rule matched the client.
	AccessDenied AccessDecision = iota
	// AccessAllowed — at least one explicit allow rule matched (and no
	// deny rule matched).
	AccessAllowed
	// AccessDefault — no client rule matched; the access decision falls
	// through to the auth items.
	AccessDefault
)

// EvaluateClientAccess returns the access decision for a client address
// against an access list.
//
// Precedence (top wins):
//  1. explicit deny  — any matching client with directive="deny"
//  2. explicit allow — any matching client with directive="allow"
//  3. default        — no client rule matches
//
// This is deliberately separated from auth-item evaluation: the result
// of EvaluateClientAccess is fed to higher-level logic that decides
// whether to require basic auth (AccessDefault → require auth;
// AccessAllowed with SatisfyAny=true → no auth required, etc.).
//
// The clientAddr is a literal IP (no port). The rule address may be:
//   - a single IPv4/IPv6 literal ("203.0.113.5")
//   - a CIDR range ("203.0.113.0/24")
//   - the value "all" (matches everything)
func EvaluateClientAccess(list *models.ProxyAccessList, clientAddr string) AccessDecision {
	if list == nil || len(list.Clients) == 0 {
		return AccessDefault
	}

	ip := net.ParseIP(strings.TrimSpace(clientAddr))

	// First pass: explicit deny wins
	for _, c := range list.Clients {
		if c.Directive != models.AccessDirectiveDeny {
			continue
		}
		if matchesClientRule(c.Address, ip, clientAddr) {
			return AccessDenied
		}
	}

	// Second pass: explicit allow
	for _, c := range list.Clients {
		if c.Directive != models.AccessDirectiveAllow {
			continue
		}
		if matchesClientRule(c.Address, ip, clientAddr) {
			return AccessAllowed
		}
	}

	return AccessDefault
}

// matchesClientRule reports whether the rule address matches the client.
// The literal "all" matches everything; otherwise the rule is parsed as
// a CIDR if it contains "/", otherwise as a single IP literal.
func matchesClientRule(rule string, clientIP net.IP, clientLiteral string) bool {
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return false
	}
	if rule == "all" {
		return true
	}

	if strings.Contains(rule, "/") {
		_, network, err := net.ParseCIDR(rule)
		if err != nil || clientIP == nil {
			return false
		}
		return network.Contains(clientIP)
	}

	// Literal IP comparison. Parse both sides so the comparison
	// is canonical (e.g. trailing whitespace, IPv4-mapped IPv6).
	ruleIP := net.ParseIP(rule)
	if ruleIP != nil && clientIP != nil {
		return ruleIP.Equal(clientIP)
	}
	// Fall back to exact string match for non-IP addresses (e.g.
	// hostnames a user may have entered — nginx supports them but
	// our matcher cannot resolve them without DNS).
	return rule == clientLiteral
}
