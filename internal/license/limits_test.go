// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package license

import (
	"context"
	"testing"
)

// ============================================================================
// LimitProximityChecker tests
// ============================================================================

func TestLimitProximityChecker_AlertAt80Percent(t *testing.T) {
	notifier := &mockNotifier{}
	provider := &Provider{info: NewCEInfo()}

	checker := NewLimitProximityChecker(provider, notifier, nopLogger{}, 80)
	ctx := context.Background()

	// 8/10 = 80% - should trigger alert
	triggered := checker.CheckResourceProximity(ctx, "users", 8, 10)
	if !triggered {
		t.Error("expected alert at 80% (8/10)")
	}

	calls := notifier.limitApproachingCalls
	if len(calls) != 1 {
		t.Fatalf("expected 1 limit approaching call, got %d", len(calls))
	}
	if calls[0].Resource != "users" {
		t.Errorf("resource = %q, want %q", calls[0].Resource, "users")
	}
	if calls[0].Current != 8 {
		t.Errorf("current = %d, want 8", calls[0].Current)
	}
	if calls[0].Limit != 10 {
		t.Errorf("limit = %d, want 10", calls[0].Limit)
	}
}

func TestLimitProximityChecker_NoAlertBelow80Percent(t *testing.T) {
	notifier := &mockNotifier{}
	provider := &Provider{info: NewCEInfo()}

	checker := NewLimitProximityChecker(provider, notifier, nopLogger{}, 80)
	ctx := context.Background()

	// 7/10 = 70% - should NOT trigger alert
	triggered := checker.CheckResourceProximity(ctx, "users", 7, 10)
	if triggered {
		t.Error("should not alert at 70% (7/10)")
	}

	if len(notifier.limitApproachingCalls) != 0 {
		t.Error("expected 0 limit approaching calls")
	}
}

func TestLimitProximityChecker_AlertAt100Percent(t *testing.T) {
	notifier := &mockNotifier{}
	provider := &Provider{info: NewCEInfo()}

	checker := NewLimitProximityChecker(provider, notifier, nopLogger{}, 80)
	ctx := context.Background()

	// 10/10 = 100% - should trigger alert
	triggered := checker.CheckResourceProximity(ctx, "nodes", 10, 10)
	if !triggered {
		t.Error("expected alert at 100% (10/10)")
	}
}

func TestLimitProximityChecker_UnlimitedNeverAlerts(t *testing.T) {
	notifier := &mockNotifier{}
	provider := &Provider{info: NewCEInfo()}

	checker := NewLimitProximityChecker(provider, notifier, nopLogger{}, 80)
	ctx := context.Background()

	// limit=0 means unlimited - should never alert
	triggered := checker.CheckResourceProximity(ctx, "users", 1000, 0)
	if triggered {
		t.Error("unlimited resource (limit=0) should never trigger alert")
	}
}

func TestLimitProximityChecker_CustomThreshold(t *testing.T) {
	notifier := &mockNotifier{}
	provider := &Provider{info: NewCEInfo()}

	// Set threshold to 90%
	checker := NewLimitProximityChecker(provider, notifier, nopLogger{}, 90)
	ctx := context.Background()

	// 85/100 = 85% - below 90%, should NOT trigger
	triggered := checker.CheckResourceProximity(ctx, "api_keys", 85, 100)
	if triggered {
		t.Error("85% should not trigger at 90% threshold")
	}

	// 91/100 = 91% - above 90%, should trigger
	triggered = checker.CheckResourceProximity(ctx, "api_keys", 91, 100)
	if !triggered {
		t.Error("91% should trigger at 90% threshold")
	}
}

func TestLimitProximityChecker_InvalidThresholdDefaults(t *testing.T) {
	notifier := &mockNotifier{}
	provider := &Provider{info: NewCEInfo()}

	// Invalid threshold should default to 80%
	checker := NewLimitProximityChecker(provider, notifier, nopLogger{}, 0)
	if checker.threshold != 80 {
		t.Errorf("threshold = %f, want 80 (default)", checker.threshold)
	}

	checker = NewLimitProximityChecker(provider, notifier, nopLogger{}, -10)
	if checker.threshold != 80 {
		t.Errorf("negative threshold = %f, want 80 (default)", checker.threshold)
	}

	checker = NewLimitProximityChecker(provider, notifier, nopLogger{}, 150)
	if checker.threshold != 80 {
		t.Errorf("over-100 threshold = %f, want 80 (default)", checker.threshold)
	}
}

// ============================================================================
// Open-edition limits (the AGPL build runs unlimited)
// ============================================================================

func TestOpenEditionLimits_AllUnlimited(t *testing.T) {
	limits := OpenLimits()
	zero := Limits{}
	if limits != zero {
		t.Errorf("OpenLimits() = %+v, want zero value (unlimited)", limits)
	}
}

func TestLimits_LimitProviderReturnsOpenValues(t *testing.T) {
	provider := &testLimitProvider{limits: OpenLimits()}
	got := provider.GetLimits()
	if got != OpenLimits() {
		t.Errorf("GetLimits() = %+v, want OpenLimits", got)
	}
}

// ============================================================================
// LimitCheck helper - general purpose limit check logic
// ============================================================================

func TestLimitCheck_IsWithinLimit(t *testing.T) {
	tests := []struct {
		name    string
		current int
		limit   int
		allowed bool
	}{
		{"below limit", 2, 5, true},
		{"at limit", 5, 5, false},
		{"above limit", 6, 5, false},
		{"unlimited (0)", 1000, 0, true},
		{"zero current, zero limit (unlimited)", 0, 0, true},
		{"zero current, nonzero limit", 0, 3, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsWithinLimit(tt.current, tt.limit)
			if got != tt.allowed {
				t.Errorf("IsWithinLimit(%d, %d) = %v, want %v",
					tt.current, tt.limit, got, tt.allowed)
			}
		})
	}
}

func TestLimitUsagePercent(t *testing.T) {
	tests := []struct {
		name    string
		current int
		limit   int
		want    float64
	}{
		{"50%", 5, 10, 50.0},
		{"100%", 10, 10, 100.0},
		{"0%", 0, 10, 0.0},
		{"unlimited returns 0", 500, 0, 0.0},
		{"over 100%", 15, 10, 150.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LimitUsagePercent(tt.current, tt.limit)
			if got != tt.want {
				t.Errorf("LimitUsagePercent(%d, %d) = %f, want %f",
					tt.current, tt.limit, got, tt.want)
			}
		})
	}
}

// ============================================================================
// Notification adapter tests
// ============================================================================

func TestNotificationAdapter_NilSender(t *testing.T) {
	adapter := NewNotificationAdapter(nil)
	ctx := context.Background()

	// Should not panic with nil sender
	err := adapter.NotifyLicenseExpiring(ctx, &Info{}, 7)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = adapter.NotifyLicenseExpired(ctx, &Info{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = adapter.NotifyLimitApproaching(ctx, "users", 8, 10)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNotificationAdapter_InterfaceCompliance(t *testing.T) {
	var _ ExpirationNotifier = (*NotificationAdapter)(nil)
}
