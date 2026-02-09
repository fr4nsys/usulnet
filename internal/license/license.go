// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package license defines the usulnet edition system, feature flags,
// resource limits, and JWT license claims.
//
// Editions:
//   - CE (Community Edition): free, AGPLv3, limited resources
//   - Business: paid per-node, expanded limits
//   - Enterprise: custom pricing, unlimited
//
// License keys are JWT tokens signed with RSA-4096 (RS512).
// The public key is embedded in the binary; the private key
// exists only on the Cloudflare Worker that issues licenses.
package license

import "time"

// Edition identifies the usulnet product tier.
type Edition string

const (
	CE         Edition = "ce"
	Business   Edition = "biz"
	Enterprise Edition = "ee"
)

// Feature is a boolean capability gated by edition.
type Feature string

const (
	FeatureCustomRoles       Feature = "custom_roles"
	FeatureOAuth             Feature = "oauth"
	FeatureLDAP              Feature = "ldap"
	FeatureMultiNotification Feature = "multi_notification"
	FeatureAuditExport       Feature = "audit_export"
	FeatureMultiBackup       Feature = "multi_backup"
	FeatureAPIKeys           Feature = "api_keys"
	FeaturePrioritySupport   Feature = "priority_support"
	FeatureSSOSAML           Feature = "sso_saml"
	FeatureHAMode            Feature = "ha_mode"
	FeatureSharedTerminals   Feature = "shared_terminals"
	FeatureWhiteLabel        Feature = "white_label"
	FeatureSwarm             Feature = "swarm"
)

// AllBusinessFeatures returns every feature flag enabled in Business edition.
func AllBusinessFeatures() []Feature {
	return []Feature{
		FeatureCustomRoles,
		FeatureOAuth,
		FeatureLDAP,
		FeatureMultiNotification,
		FeatureAuditExport,
		FeatureMultiBackup,
		FeatureAPIKeys,
		FeaturePrioritySupport,
		FeatureSwarm,
	}
}

// AllEnterpriseFeatures returns every feature flag enabled in Enterprise edition.
func AllEnterpriseFeatures() []Feature {
	return []Feature{
		FeatureCustomRoles,
		FeatureOAuth,
		FeatureLDAP,
		FeatureMultiNotification,
		FeatureAuditExport,
		FeatureMultiBackup,
		FeatureAPIKeys,
		FeaturePrioritySupport,
		FeatureSwarm,
		FeatureSSOSAML,
		FeatureHAMode,
		FeatureSharedTerminals,
		FeatureWhiteLabel,
	}
}

// Limits defines numeric resource caps. Value 0 = unlimited.
type Limits struct {
	MaxNodes                int `json:"max_nodes"`
	MaxUsers                int `json:"max_users"`
	MaxTeams                int `json:"max_teams"`
	MaxCustomRoles          int `json:"max_custom_roles"`
	MaxLDAPServers          int `json:"max_ldap_servers"`
	MaxOAuthProviders       int `json:"max_oauth_providers"`
	MaxAPIKeys              int `json:"max_api_keys"`
	MaxGitConnections       int `json:"max_git_connections"`
	MaxS3Connections        int `json:"max_s3_connections"`
	MaxBackupDestinations   int `json:"max_backup_destinations"`
	MaxNotificationChannels int `json:"max_notification_channels"`
}

const (
	// CEBaseNodes is the number of nodes included free with every installation.
	// CE gets only the master/local node. Business licenses add their purchased
	// nodes on top of this base (buy 1 → get 2, buy 2 → get 3, etc.).
	CEBaseNodes = 1
)

// CELimits returns the hard-coded limits for Community Edition.
// These are the DEFAULTS when no valid license JWT is present.
func CELimits() Limits {
	return Limits{
		MaxNodes:                CEBaseNodes, // 1 — master/local node only
		MaxUsers:                3,
		MaxTeams:                1,
		MaxCustomRoles:          1,
		MaxLDAPServers:          0, // disabled entirely (no FeatureLDAP)
		MaxOAuthProviders:       0, // disabled entirely (no FeatureOAuth)
		MaxAPIKeys:              3,
		MaxGitConnections:       1,
		MaxS3Connections:        1,
		MaxBackupDestinations:   1,
		MaxNotificationChannels: 1,
	}
}

// BusinessDefaultLimits returns the default limits for a Business license.
// In practice, nod and usr come from the JWT claims.
func BusinessDefaultLimits() Limits {
	return Limits{
		MaxNodes:                0, // from JWT nod + CEBaseNodes
		MaxUsers:                0, // from JWT usr
		MaxTeams:                5,
		MaxCustomRoles:          0, // unlimited
		MaxLDAPServers:          3,
		MaxOAuthProviders:       3,
		MaxAPIKeys:              25,
		MaxGitConnections:       5,
		MaxS3Connections:        5,
		MaxBackupDestinations:   5,
		MaxNotificationChannels: 0, // unlimited
	}
}

// EnterpriseLimits returns limits for Enterprise (all unlimited).
func EnterpriseLimits() Limits {
	return Limits{} // all zeros = unlimited
}

// LimitProvider is the interface services use to check resource limits.
// Defined here so services can import license without depending on the
// full Provider implementation.
type LimitProvider interface {
	GetLimits() Limits
}

// Info holds the resolved license state at runtime.
type Info struct {
	Edition    Edition   `json:"edition"`
	Valid      bool      `json:"valid"`
	LicenseID  string   `json:"license_id,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	Features   []Feature `json:"features"`
	Limits     Limits    `json:"limits"`
	InstanceID string   `json:"instance_id,omitempty"`
}

// HasFeature returns true if the given feature is enabled.
func (i *Info) HasFeature(f Feature) bool {
	if i == nil || !i.Valid {
		return false
	}
	for _, feat := range i.Features {
		if feat == f {
			return true
		}
	}
	return false
}

// IsExpired returns true if the license has a set expiration that has passed.
func (i *Info) IsExpired() bool {
	if i == nil || i.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*i.ExpiresAt)
}

// EditionName returns the human-readable edition name.
func (i *Info) EditionName() string {
	if i == nil {
		return "Community Edition"
	}
	switch i.Edition {
	case Business:
		return "Business"
	case Enterprise:
		return "Enterprise"
	default:
		return "Community Edition"
	}
}

// NewCEInfo returns the default Community Edition info (no JWT needed).
func NewCEInfo() *Info {
	limits := CELimits()
	return &Info{
		Edition:  CE,
		Valid:    true,
		Features: nil,
		Limits:   limits,
	}
}
