// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package license defines the usulnet license system: cryptographic
// JWT validation, edition tagging, and feature/limit accessors.
//
// usulnet ships as a single AGPL build with every feature unlocked
// and no runtime caps (see CHANGELOG `[v26.5.0] → Open and unlimited`
// and `docs/0526/x/principles.md` principle 2). The module retains
// the JWT validator so an operator can attach a commercial support
// token, but the token does not unlock additional features — every
// resolved license, including the default no-token state, returns
// the full feature set and zero (unlimited) limits.
//
// License keys are JWT tokens signed with RSA-4096 (RS512). The
// public key is embedded in the binary; the private key exists only
// on the issuer's signing service. The validator is local and never
// calls home.
package license

import "time"

// Edition tags the support tier carried on a license token. It does
// not control feature availability — every edition resolves to the
// open feature set and unlimited caps. The constants are preserved
// so previously-issued tokens remain parseable.
type Edition string

const (
	CE         Edition = "ce"
	Business   Edition = "biz"
	Enterprise Edition = "ee"
)

// Feature is a feature-flag identifier. Retained so previously-issued
// JWTs that reference these names still parse; the AGPL build never
// gates on them — see AllFeatures and NewOpenInfo.
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
	// Reserved for future implementation — not included in any tier until implemented.
	FeatureSSOSAML          Feature = "sso_saml"
	FeatureHAMode           Feature = "ha_mode"
	FeatureSharedTerminals  Feature = "shared_terminals"
	FeatureWhiteLabel       Feature = "white_label"
	FeatureSwarm            Feature = "swarm"
	FeatureCompliance       Feature = "compliance"
	FeatureOPAPolicies      Feature = "opa_policies"
	FeatureImageSigning     Feature = "image_signing"
	FeatureRuntimeSecurity  Feature = "runtime_security"
	FeatureLogAggregation   Feature = "log_aggregation"
	FeatureCustomDashboards Feature = "custom_dashboards"
	FeatureTemplateCatalog  Feature = "template_catalog"
	// Phase 3: Market Expansion - GitOps
	FeatureGitSync         Feature = "git_sync"
	FeatureEphemeralEnvs   Feature = "ephemeral_envs"
	FeatureManifestBuilder Feature = "manifest_builder"
	// Phase 6: Registry browsing
	FeatureRegistryBrowsing Feature = "registry_browsing"
)

// AllFeatures returns every implemented feature flag. The AGPL build
// unlocks all of them unconditionally; this set is what NewCEInfo and
// ClaimsToInfo install on every resolved license.
//
// Reserved-but-unimplemented flags (FeatureSSOSAML, FeatureHAMode,
// FeatureSharedTerminals, FeatureWhiteLabel) are intentionally
// excluded so HasFeature does not lie about a capability the binary
// does not actually provide.
func AllFeatures() []Feature {
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
		FeatureTemplateCatalog,
		FeatureCompliance,
		FeatureOPAPolicies,
		FeatureImageSigning,
		FeatureRuntimeSecurity,
		FeatureLogAggregation,
		FeatureCustomDashboards,
		FeatureGitSync,
		FeatureEphemeralEnvs,
		FeatureManifestBuilder,
		FeatureRegistryBrowsing,
	}
}

// Limits defines numeric resource caps. Value 0 = unlimited.
// The AGPL build runs with every cap at 0; the struct remains so the
// JSON API and on-disk degradation snapshot stay backward-compatible.
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

// OpenLimits returns the unlimited-everything limit set used by the
// AGPL build. Every field is the zero value (= unlimited).
func OpenLimits() Limits {
	return Limits{}
}

// LimitProvider is the interface services use to check resource limits.
// Defined here so services can import license without depending on the
// full Provider implementation.
type LimitProvider interface {
	GetLimits() Limits
}

// Info holds the resolved license state at runtime.
type Info struct {
	Edition    Edition    `json:"edition"`
	Valid      bool       `json:"valid"`
	LicenseID  string     `json:"license_id,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	Features   []Feature  `json:"features"`
	Limits     Limits     `json:"limits"`
	InstanceID string     `json:"instance_id,omitempty"`
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

// NewOpenInfo returns the default Info for the AGPL build when no
// commercial license JWT is present. It carries every implemented
// feature and unlimited limits — the open-edition contract.
func NewOpenInfo() *Info {
	return &Info{
		Edition:  CE,
		Valid:    true,
		Features: AllFeatures(),
		Limits:   OpenLimits(),
	}
}

// NewCEInfo is an alias of NewOpenInfo kept for callers that have not
// yet migrated to the open-edition vocabulary.
func NewCEInfo() *Info {
	return NewOpenInfo()
}

// IsWithinLimit checks if a current count is within a resource limit.
// Returns true if the resource can accept more items.
// A limit of 0 means unlimited (always returns true).
func IsWithinLimit(current, limit int) bool {
	if limit <= 0 {
		return true // Unlimited
	}
	return current < limit
}

// LimitUsagePercent returns the percentage of a limit that is used.
// Returns 0 for unlimited resources (limit=0).
func LimitUsagePercent(current, limit int) float64 {
	if limit <= 0 {
		return 0 // Unlimited
	}
	return float64(current) / float64(limit) * 100
}
