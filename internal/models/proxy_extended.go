// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// ---- Proxy Redirection ----

// ProxyRedirection represents a redirect-only proxy host (no upstream, just 3xx redirect).
type ProxyRedirection struct {
	ID              uuid.UUID    `json:"id" db:"id"`
	HostID          uuid.UUID    `json:"host_id" db:"host_id"`
	Domains         []string     `json:"domains" db:"domains"`
	ForwardScheme   string       `json:"forward_scheme" db:"forward_scheme"`
	ForwardDomain   string       `json:"forward_domain" db:"forward_domain"`
	ForwardHTTPCode int          `json:"forward_http_code" db:"forward_http_code"`
	PreservePath    bool         `json:"preserve_path" db:"preserve_path"`
	SSLMode         ProxySSLMode `json:"ssl_mode" db:"ssl_mode"`
	SSLForceHTTPS   bool         `json:"ssl_force_https" db:"ssl_force_https"`
	CertificateID   *uuid.UUID   `json:"certificate_id,omitempty" db:"certificate_id"`
	Enabled         bool         `json:"enabled" db:"enabled"`
	CreatedAt       time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time    `json:"updated_at" db:"updated_at"`
}

// ---- Proxy Stream (TCP/UDP) ----

// ProxyStream represents a TCP/UDP stream forwarding rule (nginx stream module).
// Streams are unsupported by the Caddy backend; callers should expect
// ErrFeatureNotSupported when applying streams against a Caddy-backed proxy.
type ProxyStream struct {
	ID             uuid.UUID `json:"id" db:"id"`
	HostID         uuid.UUID `json:"host_id" db:"host_id"`
	IncomingPort   int       `json:"incoming_port" db:"incoming_port"`
	ForwardingHost string    `json:"forwarding_host" db:"forwarding_host"`
	ForwardingPort int       `json:"forwarding_port" db:"forwarding_port"`
	TCPForwarding  bool      `json:"tcp_forwarding" db:"tcp_forwarding"`
	UDPForwarding  bool      `json:"udp_forwarding" db:"udp_forwarding"`
	Enabled        bool      `json:"enabled" db:"enabled"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

// ---- Proxy Dead Host (404) ----

// ProxyDeadHost represents a domain that should always return 404.
type ProxyDeadHost struct {
	ID            uuid.UUID    `json:"id" db:"id"`
	HostID        uuid.UUID    `json:"host_id" db:"host_id"`
	Domains       []string     `json:"domains" db:"domains"`
	SSLMode       ProxySSLMode `json:"ssl_mode" db:"ssl_mode"`
	SSLForceHTTPS bool         `json:"ssl_force_https" db:"ssl_force_https"`
	CertificateID *uuid.UUID   `json:"certificate_id,omitempty" db:"certificate_id"`
	Enabled       bool         `json:"enabled" db:"enabled"`
	CreatedAt     time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time    `json:"updated_at" db:"updated_at"`
}

// ---- Proxy Access List ----

// ProxyAccessList represents an access control list (HTTP basic auth + IP allow/deny).
//
// Rule evaluation precedence (enforced by the proxy service):
//  1. explicit deny    — any matching client with directive="deny" rejects the request
//  2. explicit allow   — any matching client with directive="allow" admits the request
//  3. default          — if no client rule matches, the auth items decide
//     (SatisfyAny=false → all items required; SatisfyAny=true → any single match suffices)
type ProxyAccessList struct {
	ID         uuid.UUID `json:"id" db:"id"`
	HostID     uuid.UUID `json:"host_id" db:"host_id"`
	Name       string    `json:"name" db:"name"`
	SatisfyAny bool      `json:"satisfy_any" db:"satisfy_any"`
	PassAuth   bool      `json:"pass_auth" db:"pass_auth"`
	Enabled    bool      `json:"enabled" db:"enabled"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`
	// Loaded relations
	Items   []ProxyAccessListAuth   `json:"items,omitempty" db:"-"`
	Clients []ProxyAccessListClient `json:"clients,omitempty" db:"-"`
}

// ProxyAccessListAuth is a username/password entry in an access list.
type ProxyAccessListAuth struct {
	ID           uuid.UUID `json:"id" db:"id"`
	AccessListID uuid.UUID `json:"access_list_id" db:"access_list_id"`
	Username     string    `json:"username" db:"username"`
	PasswordHash string    `json:"-" db:"password_hash"`
}

// ProxyAccessListClient is an IP/CIDR allow/deny entry in an access list.
type ProxyAccessListClient struct {
	ID           uuid.UUID `json:"id" db:"id"`
	AccessListID uuid.UUID `json:"access_list_id" db:"access_list_id"`
	Address      string    `json:"address" db:"address"`
	Directive    string    `json:"directive" db:"directive"` // "allow" or "deny"
}

// AccessDirective enumerates the allowed values for ProxyAccessListClient.Directive.
const (
	AccessDirectiveAllow = "allow"
	AccessDirectiveDeny  = "deny"
)

// ---- Proxy Location (per-path routing) ----

// ProxyLocation represents a custom location block within a proxy host.
type ProxyLocation struct {
	ID             uuid.UUID `json:"id" db:"id"`
	ProxyHostID    uuid.UUID `json:"proxy_host_id" db:"proxy_host_id"`
	Path           string    `json:"path" db:"path"`
	UpstreamScheme string    `json:"upstream_scheme" db:"upstream_scheme"`
	UpstreamHost   string    `json:"upstream_host" db:"upstream_host"`
	UpstreamPort   int       `json:"upstream_port" db:"upstream_port"`
	Enabled        bool      `json:"enabled" db:"enabled"`
}
