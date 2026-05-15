// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package proxy

import (
	"testing"

	"github.com/fr4nsys/usulnet/internal/models"
)

// TestAccessListPrecedence pins the precedence contract:
//
//	explicit deny > explicit allow > default
//
// Each case constructs a single access list with the relevant client
// rules and asserts the AccessDecision for a fixed client IP.
//
// This is the v26.5.1 enforcement contract — backends must honor it
// when translating access lists, and the service must surface it
// independently of the backend.
func TestAccessListPrecedence(t *testing.T) {
	const clientIP = "203.0.113.5"

	tests := []struct {
		name    string
		clients []models.ProxyAccessListClient
		want    AccessDecision
	}{
		{
			name:    "empty list falls through to default",
			clients: nil,
			want:    AccessDefault,
		},
		{
			name: "no matching rule falls through to default",
			clients: []models.ProxyAccessListClient{
				{Address: "10.0.0.0/8", Directive: models.AccessDirectiveAllow},
			},
			want: AccessDefault,
		},
		{
			name: "explicit allow matches the client IP",
			clients: []models.ProxyAccessListClient{
				{Address: "203.0.113.0/24", Directive: models.AccessDirectiveAllow},
			},
			want: AccessAllowed,
		},
		{
			name: "explicit deny matches the client IP",
			clients: []models.ProxyAccessListClient{
				{Address: "203.0.113.5", Directive: models.AccessDirectiveDeny},
			},
			want: AccessDenied,
		},
		{
			name: "deny beats allow when both match (precedence rule 1)",
			clients: []models.ProxyAccessListClient{
				{Address: "203.0.113.0/24", Directive: models.AccessDirectiveAllow},
				{Address: "203.0.113.5", Directive: models.AccessDirectiveDeny},
			},
			want: AccessDenied,
		},
		{
			name: "deny beats allow even when allow listed first",
			clients: []models.ProxyAccessListClient{
				{Address: "203.0.113.5", Directive: models.AccessDirectiveAllow},
				{Address: "203.0.113.0/24", Directive: models.AccessDirectiveDeny},
			},
			want: AccessDenied,
		},
		{
			name: "allow is honored when no deny rule matches",
			clients: []models.ProxyAccessListClient{
				{Address: "10.0.0.0/8", Directive: models.AccessDirectiveDeny},
				{Address: "203.0.113.0/24", Directive: models.AccessDirectiveAllow},
			},
			want: AccessAllowed,
		},
		{
			name: "literal 'all' allow matches anyone",
			clients: []models.ProxyAccessListClient{
				{Address: "all", Directive: models.AccessDirectiveAllow},
			},
			want: AccessAllowed,
		},
		{
			name: "literal 'all' deny rejects anyone",
			clients: []models.ProxyAccessListClient{
				{Address: "all", Directive: models.AccessDirectiveDeny},
			},
			want: AccessDenied,
		},
		{
			name: "non-matching deny does not affect allow",
			clients: []models.ProxyAccessListClient{
				{Address: "198.51.100.0/24", Directive: models.AccessDirectiveDeny},
				{Address: "203.0.113.5", Directive: models.AccessDirectiveAllow},
			},
			want: AccessAllowed,
		},
		{
			name: "invalid CIDR rule does not crash, treated as no-match",
			clients: []models.ProxyAccessListClient{
				{Address: "not-a-cidr/99", Directive: models.AccessDirectiveDeny},
			},
			want: AccessDefault,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list := &models.ProxyAccessList{Clients: tt.clients}
			got := EvaluateClientAccess(list, clientIP)
			if got != tt.want {
				t.Fatalf("EvaluateClientAccess(%q) = %d, want %d", clientIP, got, tt.want)
			}
		})
	}
}

// TestAccessListNil checks the nil-safe behavior of the evaluator.
func TestAccessListNil(t *testing.T) {
	if got := EvaluateClientAccess(nil, "203.0.113.5"); got != AccessDefault {
		t.Fatalf("EvaluateClientAccess(nil) = %d, want AccessDefault", got)
	}
}

// TestAccessListIPv6Match exercises CIDR + literal matching for IPv6.
func TestAccessListIPv6Match(t *testing.T) {
	const clientIP = "2001:db8::1"

	list := &models.ProxyAccessList{
		Clients: []models.ProxyAccessListClient{
			{Address: "2001:db8::/32", Directive: models.AccessDirectiveAllow},
		},
	}
	if got := EvaluateClientAccess(list, clientIP); got != AccessAllowed {
		t.Fatalf("EvaluateClientAccess(IPv6 CIDR) = %d, want AccessAllowed", got)
	}

	list = &models.ProxyAccessList{
		Clients: []models.ProxyAccessListClient{
			{Address: "2001:db8::1", Directive: models.AccessDirectiveDeny},
		},
	}
	if got := EvaluateClientAccess(list, clientIP); got != AccessDenied {
		t.Fatalf("EvaluateClientAccess(IPv6 literal) = %d, want AccessDenied", got)
	}
}
