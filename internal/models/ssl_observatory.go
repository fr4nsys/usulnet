// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// DefaultExpiryAlertThresholds are the certificate-expiry warning
// thresholds (in days) used when a target does not specify its own.
// Notifications fire as soon as a fresh scan observes the cert crossing
// each threshold downwards.
var DefaultExpiryAlertThresholds = []int{30, 14, 7, 3, 1}

// SSLTarget represents a TLS/SSL endpoint to monitor.
//
// SNI virtual hosts: when ExtraHostnames is non-empty the scanner
// performs one TLS handshake per (Hostname + ExtraHostnames) entry,
// using each as the SNI server_name, and persists one
// SSLScanResult row per (target, hostname). The primary Hostname
// is always scanned.
type SSLTarget struct {
	ID              uuid.UUID      `json:"id" db:"id"`
	HostID          uuid.UUID      `json:"host_id" db:"host_id"`
	Name            string         `json:"name" db:"name"`
	Hostname        string         `json:"hostname" db:"hostname"`
	Port            int            `json:"port" db:"port"`
	ExtraHostnames  pq.StringArray `json:"extra_hostnames" db:"extra_hostnames"`
	AlertThresholds pq.Int64Array  `json:"alert_thresholds" db:"alert_thresholds"`
	AutoDiscovered  bool           `json:"auto_discovered" db:"auto_discovered"`
	Enabled         bool           `json:"enabled" db:"enabled"`
	CreatedAt       time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at" db:"updated_at"`
}

// EffectiveThresholds returns the configured expiry alert thresholds
// for the target, falling back to DefaultExpiryAlertThresholds when
// the per-target list is empty. The returned slice is a copy.
func (t *SSLTarget) EffectiveThresholds() []int {
	if len(t.AlertThresholds) == 0 {
		out := make([]int, len(DefaultExpiryAlertThresholds))
		copy(out, DefaultExpiryAlertThresholds)
		return out
	}
	out := make([]int, len(t.AlertThresholds))
	for i, v := range t.AlertThresholds {
		out[i] = int(v)
	}
	return out
}

// ScanHostnames returns the distinct list of hostnames the scanner
// must dial for this target. The primary Hostname is always first.
func (t *SSLTarget) ScanHostnames() []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 1+len(t.ExtraHostnames))
	if t.Hostname != "" {
		out = append(out, t.Hostname)
		seen[t.Hostname] = struct{}{}
	}
	for _, h := range t.ExtraHostnames {
		if h == "" {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}

// SSLScanResult represents the result of scanning an SSL target.
//
// One row per (TargetID, ScanHostname) per scan run. ScanHostname is
// the SNI server_name used for this handshake; for the primary
// target it equals SSLTarget.Hostname.
type SSLScanResult struct {
	ID                uuid.UUID       `json:"id" db:"id"`
	TargetID          uuid.UUID       `json:"target_id" db:"target_id"`
	ScanHostname      string          `json:"scan_hostname" db:"scan_hostname"`
	Grade             string          `json:"grade" db:"grade"`
	Score             int             `json:"score" db:"score"`
	ProtocolVersions  pq.StringArray  `json:"protocol_versions" db:"protocol_versions"`
	CipherSuites      json.RawMessage `json:"cipher_suites" db:"cipher_suites"`
	CertificateCN     string          `json:"certificate_cn" db:"certificate_cn"`
	CertificateIssuer string          `json:"certificate_issuer" db:"certificate_issuer"`
	CertificateSANs   pq.StringArray  `json:"certificate_sans" db:"certificate_sans"`
	CertNotBefore     *time.Time      `json:"cert_not_before,omitempty" db:"cert_not_before"`
	CertNotAfter      *time.Time      `json:"cert_not_after,omitempty" db:"cert_not_after"`
	CertKeyType       string          `json:"cert_key_type" db:"cert_key_type"`
	CertKeyBits       int             `json:"cert_key_bits" db:"cert_key_bits"`
	CertChainValid    bool            `json:"cert_chain_valid" db:"cert_chain_valid"`
	CertChainLength   int             `json:"cert_chain_length" db:"cert_chain_length"`
	HasHSTS           bool            `json:"has_hsts" db:"has_hsts"`
	HasOCSPStapling   bool            `json:"has_ocsp_stapling" db:"has_ocsp_stapling"`
	HasSCT            bool            `json:"has_sct" db:"has_sct"`
	Vulnerabilities   json.RawMessage `json:"vulnerabilities" db:"vulnerabilities"`
	ErrorMessage      string          `json:"error_message" db:"error_message"`
	ScanDurationMs    int             `json:"scan_duration_ms" db:"scan_duration_ms"`
	ScannedAt         time.Time       `json:"scanned_at" db:"scanned_at"`
}

// CreateSSLTargetInput is the input for creating a new SSL target.
type CreateSSLTargetInput struct {
	Name            string   `json:"name"`
	Hostname        string   `json:"hostname"`
	Port            int      `json:"port"`
	ExtraHostnames  []string `json:"extra_hostnames,omitempty"`
	AlertThresholds []int    `json:"alert_thresholds,omitempty"`
}

// UpdateSSLTargetInput patches mutable fields on an SSL target.
// nil fields are left untouched.
type UpdateSSLTargetInput struct {
	Name            *string  `json:"name,omitempty"`
	Hostname        *string  `json:"hostname,omitempty"`
	Port            *int     `json:"port,omitempty"`
	ExtraHostnames  []string `json:"extra_hostnames,omitempty"`
	AlertThresholds []int    `json:"alert_thresholds,omitempty"`
	Enabled         *bool    `json:"enabled,omitempty"`
}

// SSLDashboardStats holds aggregate statistics for the SSL observatory dashboard.
type SSLDashboardStats struct {
	TotalTargets      int            `json:"total_targets"`
	GradeDistribution map[string]int `json:"grade_distribution"`
	ExpiringSoon      int            `json:"expiring_soon"`
	LastScanTime      *time.Time     `json:"last_scan_time,omitempty"`
}
