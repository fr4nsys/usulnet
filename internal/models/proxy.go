// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// ProxySSLMode represents the SSL/TLS mode for a proxy host.
type ProxySSLMode string

const (
	ProxySSLModeNone     ProxySSLMode = "none"      // No TLS
	ProxySSLModeAuto     ProxySSLMode = "auto"      // Let's Encrypt HTTP challenge
	ProxySSLModeDNS      ProxySSLMode = "dns"       // Let's Encrypt DNS challenge (supports wildcards)
	ProxySSLModeCustom   ProxySSLMode = "custom"    // User-provided certificate
	ProxySSLModeInternal ProxySSLMode = "internal"  // Caddy's internal CA (self-signed, trusted locally)
)

// ProxyHostStatus represents the current status of a proxy host.
type ProxyHostStatus string

const (
	ProxyHostStatusActive   ProxyHostStatus = "active"
	ProxyHostStatusDisabled ProxyHostStatus = "disabled"
	ProxyHostStatusError    ProxyHostStatus = "error"
	ProxyHostStatusPending  ProxyHostStatus = "pending" // Waiting for cert
)

// ProxyUpstreamScheme is the scheme used to connect to the upstream.
type ProxyUpstreamScheme string

const (
	ProxyUpstreamHTTP  ProxyUpstreamScheme = "http"
	ProxyUpstreamHTTPS ProxyUpstreamScheme = "https"
	ProxyUpstreamH2C   ProxyUpstreamScheme = "h2c" // HTTP/2 cleartext
)

// ProxyHost represents a reverse proxy host configuration.
type ProxyHost struct {
	ID        uuid.UUID       `json:"id" db:"id"`
	HostID    uuid.UUID       `json:"host_id" db:"host_id"` // usulnet host (multi-host support)
	Name      string          `json:"name" db:"name"`       // Human-friendly label
	Domains   []string        `json:"domains" db:"domains"` // e.g. ["example.com", "www.example.com"]
	Enabled   bool            `json:"enabled" db:"enabled"`
	Status    ProxyHostStatus `json:"status" db:"status"`
	StatusMsg string          `json:"status_message,omitempty" db:"status_message"`

	// Upstream configuration
	UpstreamScheme  ProxyUpstreamScheme `json:"upstream_scheme" db:"upstream_scheme"`
	UpstreamHost    string              `json:"upstream_host" db:"upstream_host"`       // IP, hostname, or Docker container name
	UpstreamPort    int                 `json:"upstream_port" db:"upstream_port"`
	UpstreamPath    string              `json:"upstream_path,omitempty" db:"upstream_path"` // Path prefix to strip/add

	// TLS
	SSLMode          ProxySSLMode `json:"ssl_mode" db:"ssl_mode"`
	SSLForceHTTPS    bool         `json:"ssl_force_https" db:"ssl_force_https"`
	CertificateID    *uuid.UUID   `json:"certificate_id,omitempty" db:"certificate_id"` // For custom certs
	DNSProviderID    *uuid.UUID   `json:"dns_provider_id,omitempty" db:"dns_provider_id"` // For DNS challenge

	// Headers & behaviour
	EnableWebSocket   bool   `json:"enable_websocket" db:"enable_websocket"`
	EnableCompression bool   `json:"enable_compression" db:"enable_compression"` // gzip + zstd
	EnableHSTS        bool   `json:"enable_hsts" db:"enable_hsts"`
	EnableHTTP2       bool   `json:"enable_http2" db:"enable_http2"`
	CustomHeaders     []ProxyHeader `json:"custom_headers,omitempty" db:"-"`

	// Health check
	HealthCheckEnabled  bool   `json:"health_check_enabled" db:"health_check_enabled"`
	HealthCheckPath     string `json:"health_check_path,omitempty" db:"health_check_path"`
	HealthCheckInterval int    `json:"health_check_interval,omitempty" db:"health_check_interval"` // seconds

	// Container link (optional auto-proxy)
	ContainerID   string `json:"container_id,omitempty" db:"container_id"`
	ContainerName string `json:"container_name,omitempty" db:"container_name"`
	AutoCreated   bool   `json:"auto_created" db:"auto_created"`

	// Metadata
	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
}

// ProxyHeader represents a custom header to add/set.
type ProxyHeader struct {
	ID          uuid.UUID `json:"id" db:"id"`
	ProxyHostID uuid.UUID `json:"proxy_host_id" db:"proxy_host_id"`
	Direction   string    `json:"direction" db:"direction"` // "request" or "response"
	Operation   string    `json:"operation" db:"operation"` // "set", "add", "delete"
	Name        string    `json:"name" db:"name"`
	Value       string    `json:"value,omitempty" db:"value"`
}

// ProxyCertificate represents a user-uploaded or managed certificate.
type ProxyCertificate struct {
	ID           uuid.UUID   `json:"id" db:"id"`
	HostID       uuid.UUID   `json:"host_id" db:"host_id"`
	Name         string      `json:"name" db:"name"`
	Domains      []string    `json:"domains" db:"domains"`
	Provider     string      `json:"provider" db:"provider"` // "letsencrypt", "custom", "internal"
	CertPEM      string      `json:"-" db:"cert_pem"`        // Never expose in JSON
	KeyPEM       string      `json:"-" db:"key_pem"`
	ChainPEM     string      `json:"-" db:"chain_pem"`
	ExpiresAt    *time.Time  `json:"expires_at,omitempty" db:"expires_at"`
	IsWildcard   bool        `json:"is_wildcard" db:"is_wildcard"`
	AutoRenew    bool        `json:"auto_renew" db:"auto_renew"`
	LastRenewed  *time.Time  `json:"last_renewed,omitempty" db:"last_renewed"`
	ErrorMessage *string     `json:"error_message,omitempty" db:"error_message"`
	CreatedAt    time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at" db:"updated_at"`
}

// ProxyDNSProvider stores DNS API credentials for ACME DNS-01 challenges (wildcards).
type ProxyDNSProvider struct {
	ID           uuid.UUID `json:"id" db:"id"`
	HostID       uuid.UUID `json:"host_id" db:"host_id"`
	Name         string    `json:"name" db:"name"`           // User label
	Provider     string    `json:"provider" db:"provider"`   // "cloudflare", "route53", "duckdns", etc.
	APIToken     string    `json:"-" db:"api_token"`         // Encrypted at rest
	APITokenHint string    `json:"api_token_hint" db:"-"`    // Last 4 chars for display
	Zone         string    `json:"zone,omitempty" db:"zone"` // Optional zone/domain filter
	Propagation  int       `json:"propagation,omitempty" db:"propagation"` // seconds to wait
	IsDefault    bool      `json:"is_default" db:"is_default"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// ProxyAuditLog records changes to proxy configuration.
type ProxyAuditLog struct {
	ID          uuid.UUID `json:"id" db:"id"`
	HostID      uuid.UUID `json:"host_id" db:"host_id"`
	UserID      *uuid.UUID `json:"user_id,omitempty" db:"user_id"`
	Action      string    `json:"action" db:"action"`           // "create", "update", "delete", "enable", "disable", "sync"
	ResourceType string   `json:"resource_type" db:"resource_type"` // "proxy_host", "certificate", "dns_provider"
	ResourceID  uuid.UUID `json:"resource_id" db:"resource_id"`
	ResourceName string   `json:"resource_name" db:"resource_name"`
	Details     string    `json:"details,omitempty" db:"details"` // JSON string
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// ---- Input types for create/update ----

// CreateProxyHostInput is the input for creating a new proxy host.
type CreateProxyHostInput struct {
	Name             string              `json:"name" validate:"required,max=255"`
	Domains          []string            `json:"domains" validate:"required,min=1,dive,required"`
	UpstreamScheme   ProxyUpstreamScheme `json:"upstream_scheme" validate:"required,oneof=http https h2c"`
	UpstreamHost     string              `json:"upstream_host" validate:"required"`
	UpstreamPort     int                 `json:"upstream_port" validate:"required,min=1,max=65535"`
	UpstreamPath     string              `json:"upstream_path,omitempty"`
	SSLMode          ProxySSLMode        `json:"ssl_mode" validate:"required,oneof=none auto dns custom internal"`
	SSLForceHTTPS    bool                `json:"ssl_force_https"`
	CertificateID    *uuid.UUID          `json:"certificate_id,omitempty"`
	DNSProviderID    *uuid.UUID          `json:"dns_provider_id,omitempty"`
	EnableWebSocket  bool                `json:"enable_websocket"`
	EnableCompression bool               `json:"enable_compression"`
	EnableHSTS       bool                `json:"enable_hsts"`
	EnableHTTP2      bool                `json:"enable_http2"`
	HealthCheckEnabled  bool             `json:"health_check_enabled"`
	HealthCheckPath     string           `json:"health_check_path,omitempty"`
	HealthCheckInterval int              `json:"health_check_interval,omitempty"`
	ContainerID      string              `json:"container_id,omitempty"`
	ContainerName    string              `json:"container_name,omitempty"`
}

// UpdateProxyHostInput is the input for updating a proxy host.
type UpdateProxyHostInput struct {
	Name              *string              `json:"name,omitempty"`
	Domains           []string             `json:"domains,omitempty"`
	UpstreamScheme    *ProxyUpstreamScheme `json:"upstream_scheme,omitempty"`
	UpstreamHost      *string              `json:"upstream_host,omitempty"`
	UpstreamPort      *int                 `json:"upstream_port,omitempty"`
	UpstreamPath      *string              `json:"upstream_path,omitempty"`
	SSLMode           *ProxySSLMode        `json:"ssl_mode,omitempty"`
	SSLForceHTTPS     *bool                `json:"ssl_force_https,omitempty"`
	CertificateID     *uuid.UUID           `json:"certificate_id,omitempty"`
	DNSProviderID     *uuid.UUID           `json:"dns_provider_id,omitempty"`
	Enabled           *bool                `json:"enabled,omitempty"`
	EnableWebSocket   *bool                `json:"enable_websocket,omitempty"`
	EnableCompression *bool                `json:"enable_compression,omitempty"`
	EnableHSTS        *bool                `json:"enable_hsts,omitempty"`
	EnableHTTP2       *bool                `json:"enable_http2,omitempty"`
	HealthCheckEnabled  *bool              `json:"health_check_enabled,omitempty"`
	HealthCheckPath     *string            `json:"health_check_path,omitempty"`
	HealthCheckInterval *int               `json:"health_check_interval,omitempty"`
}

// Docker labels for Caddy auto-proxy discovery.
const (
	LabelCaddyDomain    = "usulnet.proxy.domain"
	LabelCaddyPort      = "usulnet.proxy.port"
	LabelCaddySSL       = "usulnet.proxy.ssl"
	LabelCaddyWebsocket = "usulnet.proxy.websocket"
)

// Supported DNS providers for Caddy DNS challenge.
// These correspond to caddy-dns modules that must be compiled into the Caddy binary.
var SupportedDNSProviders = map[string]string{
	"cloudflare":     "github.com/caddy-dns/cloudflare",
	"route53":        "github.com/caddy-dns/route53",
	"duckdns":        "github.com/caddy-dns/duckdns",
	"digitalocean":   "github.com/caddy-dns/digitalocean",
	"godaddy":        "github.com/caddy-dns/godaddy",
	"namecheap":      "github.com/caddy-dns/namecheap",
	"hetzner":        "github.com/caddy-dns/hetzner",
	"ovh":            "github.com/caddy-dns/ovh",
	"gandi":          "github.com/caddy-dns/gandi",
	"vultr":          "github.com/caddy-dns/vultr",
	"linode":         "github.com/caddy-dns/linode",
	"googleclouddns": "github.com/caddy-dns/googleclouddns",
	"azure":          "github.com/caddy-dns/azure",
	"porkbun":        "github.com/caddy-dns/porkbun",
}
