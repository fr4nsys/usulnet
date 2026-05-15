// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package license

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ============================================================================
// Edition Constants
// ============================================================================

func TestEditionConstants(t *testing.T) {
	tests := []struct {
		name    string
		edition Edition
		want    string
	}{
		{"CE", CE, "ce"},
		{"Business", Business, "biz"},
		{"Enterprise", Enterprise, "ee"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.edition) != tt.want {
				t.Errorf("Edition %s = %q, want %q", tt.name, tt.edition, tt.want)
			}
		})
	}
}

// ============================================================================
// Feature Constants
// ============================================================================

func TestFeatureConstants(t *testing.T) {
	// Verify all 24 feature constants have expected string values
	features := map[Feature]string{
		FeatureCustomRoles:       "custom_roles",
		FeatureOAuth:             "oauth",
		FeatureLDAP:              "ldap",
		FeatureMultiNotification: "multi_notification",
		FeatureAuditExport:       "audit_export",
		FeatureMultiBackup:       "multi_backup",
		FeatureAPIKeys:           "api_keys",
		FeaturePrioritySupport:   "priority_support",
		FeatureSSOSAML:           "sso_saml",
		FeatureHAMode:            "ha_mode",
		FeatureSharedTerminals:   "shared_terminals",
		FeatureWhiteLabel:        "white_label",
		FeatureSwarm:             "swarm",
		FeatureTemplateCatalog:   "template_catalog",
		FeatureCompliance:        "compliance",
		FeatureOPAPolicies:       "opa_policies",
		FeatureImageSigning:      "image_signing",
		FeatureRuntimeSecurity:   "runtime_security",
		FeatureLogAggregation:    "log_aggregation",
		FeatureCustomDashboards:  "custom_dashboards",
		FeatureGitSync:           "git_sync",
		FeatureEphemeralEnvs:     "ephemeral_envs",
		FeatureManifestBuilder:   "manifest_builder",
		FeatureRegistryBrowsing:  "registry_browsing",
	}

	for feat, want := range features {
		if string(feat) != want {
			t.Errorf("Feature %q != %q", feat, want)
		}
	}
}

// ============================================================================
// AllFeatures — the open AGPL feature set
// ============================================================================

func TestAllFeatures_IncludesEveryImplementedFlag(t *testing.T) {
	// Every implemented feature flag must appear in AllFeatures so the
	// open AGPL build never denies a real capability.
	implemented := []Feature{
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

	got := make(map[Feature]bool, len(AllFeatures()))
	for _, f := range AllFeatures() {
		got[f] = true
	}

	for _, f := range implemented {
		if !got[f] {
			t.Errorf("AllFeatures() missing implemented feature %q", f)
		}
	}
}

func TestAllFeatures_ExcludesReservedUnimplemented(t *testing.T) {
	// Reserved-but-unimplemented flags are intentionally NOT in the
	// open feature set so HasFeature does not claim a capability the
	// binary does not provide.
	reserved := []Feature{
		FeatureSSOSAML,
		FeatureHAMode,
		FeatureSharedTerminals,
		FeatureWhiteLabel,
	}

	set := make(map[Feature]bool, len(AllFeatures()))
	for _, f := range AllFeatures() {
		set[f] = true
	}

	for _, f := range reserved {
		if set[f] {
			t.Errorf("AllFeatures() should NOT include reserved-but-unimplemented %q", f)
		}
	}
}

// ============================================================================
// OpenLimits — the AGPL build runs unlimited
// ============================================================================

func TestOpenLimits_AllZero(t *testing.T) {
	limits := OpenLimits()
	zero := Limits{}
	if limits != zero {
		t.Errorf("OpenLimits() = %+v, want zero value (unlimited)", limits)
	}
}

// ============================================================================
// NewCEInfo / NewOpenInfo — open edition unlocks everything
// ============================================================================

func TestNewOpenInfo_IsOpen(t *testing.T) {
	info := NewOpenInfo()

	if info == nil {
		t.Fatal("NewOpenInfo() returned nil")
	}
	if !info.Valid {
		t.Error("Valid = false, want true (open edition is always valid)")
	}
	if info.LicenseID != "" {
		t.Errorf("LicenseID = %q, want empty (no commercial token)", info.LicenseID)
	}
	if info.ExpiresAt != nil {
		t.Errorf("ExpiresAt = %v, want nil (open edition never expires)", info.ExpiresAt)
	}

	// Every implemented feature must be present.
	for _, f := range AllFeatures() {
		if !info.HasFeature(f) {
			t.Errorf("open edition HasFeature(%q) = false, want true", f)
		}
	}

	// Every limit must be zero (unlimited).
	if info.Limits != OpenLimits() {
		t.Errorf("Limits = %+v, want OpenLimits (unlimited)", info.Limits)
	}
}

func TestNewCEInfo_AliasOfOpenInfo(t *testing.T) {
	// NewCEInfo is preserved as an alias for callers that have not
	// migrated to NewOpenInfo. It must return the same open contract.
	ce := NewCEInfo()
	open := NewOpenInfo()
	if ce.Valid != open.Valid {
		t.Errorf("Valid: CE=%v, Open=%v", ce.Valid, open.Valid)
	}
	if ce.Limits != open.Limits {
		t.Errorf("Limits: CE=%+v, Open=%+v", ce.Limits, open.Limits)
	}
	if len(ce.Features) != len(open.Features) {
		t.Errorf("Features length: CE=%d, Open=%d", len(ce.Features), len(open.Features))
	}
}

// ============================================================================
// Info.HasFeature
// ============================================================================

func TestInfo_HasFeature(t *testing.T) {
	t.Run("nil info returns false", func(t *testing.T) {
		var info *Info
		if info.HasFeature(FeatureAPIKeys) {
			t.Error("nil Info.HasFeature() = true, want false")
		}
	})

	t.Run("invalid license returns false", func(t *testing.T) {
		info := &Info{
			Valid:    false,
			Features: []Feature{FeatureAPIKeys},
		}
		if info.HasFeature(FeatureAPIKeys) {
			t.Error("invalid Info.HasFeature(FeatureAPIKeys) = true, want false")
		}
	})

	t.Run("valid info with feature returns true", func(t *testing.T) {
		info := &Info{
			Valid:    true,
			Features: AllFeatures(),
		}
		for _, f := range AllFeatures() {
			if !info.HasFeature(f) {
				t.Errorf("HasFeature(%q) = false, want true", f)
			}
		}
	})

	t.Run("valid info without feature returns false", func(t *testing.T) {
		info := &Info{
			Valid:    true,
			Features: []Feature{FeatureAPIKeys},
		}
		if info.HasFeature(FeatureSSOSAML) {
			t.Error("HasFeature(FeatureSSOSAML) = true, want false")
		}
	})

	t.Run("open edition has every implemented feature", func(t *testing.T) {
		info := NewOpenInfo()
		for _, f := range AllFeatures() {
			if !info.HasFeature(f) {
				t.Errorf("open HasFeature(%q) = false, want true", f)
			}
		}
	})

	t.Run("empty features returns false", func(t *testing.T) {
		info := &Info{
			Valid:    true,
			Features: []Feature{},
		}
		if info.HasFeature(FeatureAPIKeys) {
			t.Error("empty features HasFeature() = true, want false")
		}
	})
}

// ============================================================================
// Info.IsExpired
// ============================================================================

func TestInfo_IsExpired(t *testing.T) {
	t.Run("nil info returns false", func(t *testing.T) {
		var info *Info
		if info.IsExpired() {
			t.Error("nil Info.IsExpired() = true, want false")
		}
	})

	t.Run("nil ExpiresAt returns false", func(t *testing.T) {
		info := &Info{ExpiresAt: nil}
		if info.IsExpired() {
			t.Error("nil ExpiresAt IsExpired() = true, want false")
		}
	})

	t.Run("future expiration returns false", func(t *testing.T) {
		future := time.Now().Add(24 * time.Hour)
		info := &Info{ExpiresAt: &future}
		if info.IsExpired() {
			t.Error("future expiration IsExpired() = true, want false")
		}
	})

	t.Run("past expiration returns true", func(t *testing.T) {
		past := time.Now().Add(-24 * time.Hour)
		info := &Info{ExpiresAt: &past}
		if !info.IsExpired() {
			t.Error("past expiration IsExpired() = false, want true")
		}
	})

	t.Run("open edition never expires", func(t *testing.T) {
		info := NewOpenInfo()
		if info.IsExpired() {
			t.Error("open edition IsExpired() = true, want false")
		}
	})
}

// ============================================================================
// Info.EditionName
// ============================================================================

func TestInfo_EditionName(t *testing.T) {
	tests := []struct {
		name string
		info *Info
		want string
	}{
		{"nil info", nil, "Community Edition"},
		{"CE", &Info{Edition: CE}, "Community Edition"},
		{"Business", &Info{Edition: Business}, "Business"},
		{"Enterprise", &Info{Edition: Enterprise}, "Enterprise"},
		{"unknown edition", &Info{Edition: "unknown"}, "Community Edition"},
		{"empty edition", &Info{Edition: ""}, "Community Edition"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.info.EditionName(); got != tt.want {
				t.Errorf("EditionName() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ============================================================================
// ClaimsToInfo — a commercial token resolves to the open contract
// ============================================================================

func TestClaimsToInfo_BusinessTokenStillOpen(t *testing.T) {
	expiry := time.Now().Add(365 * 24 * time.Hour)
	claims := &Claims{
		LicenseID: "USN-test-1234",
		EmailHash: "abc123",
		Edition:   Business,
		MaxNodes:  3,
		MaxUsers:  15,
	}
	claims.ExpiresAt = jwt.NewNumericDate(expiry)

	info := ClaimsToInfo(claims, "instance-abc")

	if info.Edition != Business {
		t.Errorf("Edition = %q, want %q (tag preserved)", info.Edition, Business)
	}
	if !info.Valid {
		t.Error("Valid = false, want true")
	}
	if info.LicenseID != "USN-test-1234" {
		t.Errorf("LicenseID = %q, want %q", info.LicenseID, "USN-test-1234")
	}
	if info.InstanceID != "instance-abc" {
		t.Errorf("InstanceID = %q, want %q", info.InstanceID, "instance-abc")
	}
	if info.Limits != OpenLimits() {
		t.Errorf("Limits = %+v, want OpenLimits (commercial token does not cap)", info.Limits)
	}
	for _, f := range AllFeatures() {
		if !info.HasFeature(f) {
			t.Errorf("commercial token: HasFeature(%q) = false, want true", f)
		}
	}
}

func TestClaimsToInfo_EnterpriseTokenStillOpen(t *testing.T) {
	expiry := time.Now().Add(365 * 24 * time.Hour)
	claims := &Claims{
		LicenseID: "USN-ent-5678",
		Edition:   Enterprise,
	}
	claims.ExpiresAt = jwt.NewNumericDate(expiry)

	info := ClaimsToInfo(claims, "instance-xyz")

	if info.Edition != Enterprise {
		t.Errorf("Edition = %q, want %q", info.Edition, Enterprise)
	}
	if !info.Valid {
		t.Error("Valid = false, want true")
	}
	if info.Limits != OpenLimits() {
		t.Errorf("Limits = %+v, want OpenLimits", info.Limits)
	}
	for _, f := range AllFeatures() {
		if !info.HasFeature(f) {
			t.Errorf("enterprise token: HasFeature(%q) = false, want true", f)
		}
	}
}

func TestClaimsToInfo_ExpiredTokenStillOpen(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	claims := &Claims{
		LicenseID: "USN-expired",
		Edition:   Business,
		MaxNodes:  1,
		MaxUsers:  10,
	}
	claims.ExpiresAt = jwt.NewNumericDate(past)

	info := ClaimsToInfo(claims, "inst-1")

	// Expired token should be marked invalid but the edition tag is
	// preserved for UI display. The binary still grants every feature
	// because gating no longer exists.
	if info.Valid {
		t.Error("Expired license Valid = true, want false")
	}
	if info.Edition != Business {
		t.Errorf("Expired license Edition = %q, want %q", info.Edition, Business)
	}
}

// ============================================================================
// LimitProvider interface compliance
// ============================================================================

type testLimitProvider struct {
	limits Limits
}

func (tp *testLimitProvider) GetLimits() Limits { return tp.limits }

func TestLimitProvider_InterfaceCompliance(t *testing.T) {
	// Compile-time check that testLimitProvider satisfies LimitProvider
	var _ LimitProvider = (*testLimitProvider)(nil)

	provider := &testLimitProvider{limits: OpenLimits()}
	got := provider.GetLimits()
	if got != OpenLimits() {
		t.Errorf("GetLimits() = %+v, want %+v", got, OpenLimits())
	}
}

// ============================================================================
// Open-edition contract — Session 13 (v26.5.1)
// ============================================================================

// TestOpenEdition_UnlocksEverything is the single regression test for
// principle 2 of `docs/0526/x/principles.md`: the AGPL build resolves
// to every implemented feature with no runtime caps, regardless of
// commercial license state.
func TestOpenEdition_UnlocksEverything(t *testing.T) {
	cases := []struct {
		name string
		info *Info
	}{
		{"no license", NewOpenInfo()},
		{"NewCEInfo alias", NewCEInfo()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.info.Valid {
				t.Fatalf("%s: Valid = false, want true", tc.name)
			}
			for _, f := range AllFeatures() {
				if !tc.info.HasFeature(f) {
					t.Errorf("%s: HasFeature(%q) = false, want true", tc.name, f)
				}
			}
			if tc.info.Limits != OpenLimits() {
				t.Errorf("%s: Limits = %+v, want OpenLimits (unlimited)", tc.name, tc.info.Limits)
			}
		})
	}
}
