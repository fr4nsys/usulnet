// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package license

import (
	"context"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Mock notifier for testing
// ============================================================================

type mockNotifier struct {
	mu                    sync.Mutex
	expiringCalls         []expiringCall
	expiredCalls          []expiredCall
	limitApproachingCalls []limitApproachingCall
}

type expiringCall struct {
	Info          *Info
	DaysRemaining int
}

type expiredCall struct {
	Info *Info
}

type limitApproachingCall struct {
	Resource string
	Current  int
	Limit    int
}

func (m *mockNotifier) NotifyLicenseExpiring(ctx context.Context, info *Info, daysRemaining int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expiringCalls = append(m.expiringCalls, expiringCall{Info: info, DaysRemaining: daysRemaining})
	return nil
}

func (m *mockNotifier) NotifyLicenseExpired(ctx context.Context, info *Info) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expiredCalls = append(m.expiredCalls, expiredCall{Info: info})
	return nil
}

func (m *mockNotifier) NotifyLimitApproaching(ctx context.Context, resource string, current, limit int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.limitApproachingCalls = append(m.limitApproachingCalls, limitApproachingCall{
		Resource: resource, Current: current, Limit: limit,
	})
	return nil
}

func (m *mockNotifier) getExpiringCalls() []expiringCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]expiringCall, len(m.expiringCalls))
	copy(result, m.expiringCalls)
	return result
}

func (m *mockNotifier) getExpiredCalls() []expiredCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]expiredCall, len(m.expiredCalls))
	copy(result, m.expiredCalls)
	return result
}

// mock logger
type nopLogger struct{}

func (nopLogger) Info(msg string, keysAndValues ...any)  {}
func (nopLogger) Warn(msg string, keysAndValues ...any)  {}
func (nopLogger) Error(msg string, keysAndValues ...any) {}

// ============================================================================
// DaysUntilExpiration
// ============================================================================

func TestDaysUntilExpiration(t *testing.T) {
	t.Run("nil info returns 0", func(t *testing.T) {
		if got := DaysUntilExpiration(nil); got != 0 {
			t.Errorf("DaysUntilExpiration(nil) = %d, want 0", got)
		}
	})

	t.Run("no expiration returns 0", func(t *testing.T) {
		info := NewCEInfo()
		if got := DaysUntilExpiration(info); got != 0 {
			t.Errorf("DaysUntilExpiration(CE) = %d, want 0", got)
		}
	})

	t.Run("expired returns -1", func(t *testing.T) {
		past := time.Now().Add(-48 * time.Hour)
		info := &Info{ExpiresAt: &past}
		if got := DaysUntilExpiration(info); got != -1 {
			t.Errorf("DaysUntilExpiration(expired) = %d, want -1", got)
		}
	})

	t.Run("30 days remaining", func(t *testing.T) {
		future := time.Now().Add(30 * 24 * time.Hour)
		info := &Info{ExpiresAt: &future}
		got := DaysUntilExpiration(info)
		// Allow +-1 day due to rounding
		if got < 29 || got > 31 {
			t.Errorf("DaysUntilExpiration(30d) = %d, want ~30", got)
		}
	})

	t.Run("1 day remaining", func(t *testing.T) {
		future := time.Now().Add(23 * time.Hour) // Less than 24h but should still be 1 day
		info := &Info{ExpiresAt: &future}
		got := DaysUntilExpiration(info)
		if got != 1 {
			t.Errorf("DaysUntilExpiration(23h) = %d, want 1", got)
		}
	})

	t.Run("less than 1 hour remaining", func(t *testing.T) {
		future := time.Now().Add(30 * time.Minute)
		info := &Info{ExpiresAt: &future}
		got := DaysUntilExpiration(info)
		if got != 1 {
			t.Errorf("DaysUntilExpiration(30min) = %d, want 1", got)
		}
	})
}

// ============================================================================
// GetDegradationState
// ============================================================================

func TestGetDegradationState(t *testing.T) {
	t.Run("nil info returns open state", func(t *testing.T) {
		state := GetDegradationState(nil)
		if state.IsExpired {
			t.Error("nil info should not be expired")
		}
		if state.ActiveLimits != OpenLimits() {
			t.Error("nil info should have open (unlimited) limits")
		}
	})

	t.Run("valid business token - no degradation", func(t *testing.T) {
		future := time.Now().Add(365 * 24 * time.Hour)
		info := &Info{
			Edition:   Business,
			Valid:     true,
			ExpiresAt: &future,
			Features:  AllFeatures(),
			Limits:    OpenLimits(),
		}
		state := GetDegradationState(info)
		if state.IsExpired {
			t.Error("valid license should not be expired")
		}
		if state.PreviousEdition != Business {
			t.Errorf("PreviousEdition = %q, want %q", state.PreviousEdition, Business)
		}
	})

	t.Run("expired business token - features still open", func(t *testing.T) {
		past := time.Now().Add(-24 * time.Hour)
		info := &Info{
			Edition:   Business,
			Valid:     false,
			ExpiresAt: &past,
			Features:  AllFeatures(),
			Limits:    OpenLimits(),
		}
		state := GetDegradationState(info)
		if !state.IsExpired {
			t.Error("expired license should be flagged expired")
		}
		if state.PreviousEdition != Business {
			t.Errorf("PreviousEdition = %q, want %q", state.PreviousEdition, Business)
		}
		// AGPL build never downgrades runtime capability — limits stay open
		// and no features are reported as disabled.
		if state.ActiveLimits != OpenLimits() {
			t.Error("expired license should still report open (unlimited) limits in the AGPL build")
		}
		if len(state.DisabledFeatures) != 0 {
			t.Errorf("DisabledFeatures = %v, want empty (AGPL build never gates features)", state.DisabledFeatures)
		}
	})

	t.Run("expired enterprise token - features still open", func(t *testing.T) {
		past := time.Now().Add(-24 * time.Hour)
		info := &Info{
			Edition:   Enterprise,
			Valid:     false,
			ExpiresAt: &past,
			Features:  AllFeatures(),
			Limits:    OpenLimits(),
		}
		state := GetDegradationState(info)
		if !state.IsExpired {
			t.Error("expired enterprise should be flagged expired")
		}
		if state.PreviousEdition != Enterprise {
			t.Errorf("PreviousEdition = %q, want %q", state.PreviousEdition, Enterprise)
		}
		if state.ActiveLimits != OpenLimits() {
			t.Error("expired enterprise should still report open limits")
		}
	})

	t.Run("open edition - no degradation possible", func(t *testing.T) {
		info := NewCEInfo()
		state := GetDegradationState(info)
		if state.IsExpired {
			t.Error("open edition should never be expired")
		}
	})
}

// ============================================================================
// ExpirationChecker - notification thresholds
// ============================================================================

func TestExpirationChecker_ExpiringNotification(t *testing.T) {
	notifier := &mockNotifier{}

	// Create a mock provider with a license expiring in 7 days
	expiresIn7Days := time.Now().Add(7 * 24 * time.Hour)
	provider := &Provider{
		info: &Info{
			Edition:   Business,
			Valid:     true,
			LicenseID: "USN-test-expiring",
			ExpiresAt: &expiresIn7Days,
			Features:  AllFeatures(),
			Limits:    OpenLimits(),
		},
	}

	checker := NewExpirationChecker(provider, notifier, nopLogger{}, ExpirationCheckerConfig{
		Thresholds: []int{30, 15, 7, 3, 1},
	})

	ctx := context.Background()
	checker.Check(ctx)

	calls := notifier.getExpiringCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 expiring notification, got %d", len(calls))
	}
	if calls[0].DaysRemaining > 8 || calls[0].DaysRemaining < 6 {
		t.Errorf("DaysRemaining = %d, want ~7", calls[0].DaysRemaining)
	}
	if calls[0].Info.LicenseID != "USN-test-expiring" {
		t.Errorf("LicenseID = %q, want %q", calls[0].Info.LicenseID, "USN-test-expiring")
	}
}

func TestExpirationChecker_ExpiredNotification(t *testing.T) {
	notifier := &mockNotifier{}

	// Create a mock provider with an expired license
	expiredYesterday := time.Now().Add(-24 * time.Hour)
	provider := &Provider{
		info: &Info{
			Edition:   Business,
			Valid:     false,
			LicenseID: "USN-test-expired",
			ExpiresAt: &expiredYesterday,
			Features:  AllFeatures(),
		},
	}

	checker := NewExpirationChecker(provider, notifier, nopLogger{}, ExpirationCheckerConfig{
		Thresholds: []int{30, 15, 7},
	})

	ctx := context.Background()
	checker.Check(ctx)

	expiredCalls := notifier.getExpiredCalls()
	if len(expiredCalls) != 1 {
		t.Fatalf("expected 1 expired notification, got %d", len(expiredCalls))
	}
	if expiredCalls[0].Info.LicenseID != "USN-test-expired" {
		t.Errorf("LicenseID = %q, want %q", expiredCalls[0].Info.LicenseID, "USN-test-expired")
	}

	// Expiring calls should not fire for already-expired licenses
	expiringCalls := notifier.getExpiringCalls()
	if len(expiringCalls) != 0 {
		t.Errorf("expected 0 expiring notifications for expired license, got %d", len(expiringCalls))
	}
}

func TestExpirationChecker_CESkipped(t *testing.T) {
	notifier := &mockNotifier{}

	provider := &Provider{
		info: NewCEInfo(),
	}

	checker := NewExpirationChecker(provider, notifier, nopLogger{}, DefaultExpirationCheckerConfig())

	ctx := context.Background()
	checker.Check(ctx)

	if len(notifier.getExpiringCalls()) != 0 {
		t.Error("CE should not trigger expiring notifications")
	}
	if len(notifier.getExpiredCalls()) != 0 {
		t.Error("CE should not trigger expired notifications")
	}
}

func TestExpirationChecker_NoDuplicateNotifications(t *testing.T) {
	notifier := &mockNotifier{}

	expiresIn5Days := time.Now().Add(5 * 24 * time.Hour)
	provider := &Provider{
		info: &Info{
			Edition:   Business,
			Valid:     true,
			LicenseID: "USN-test-dedup",
			ExpiresAt: &expiresIn5Days,
			Features:  AllFeatures(),
		},
	}

	checker := NewExpirationChecker(provider, notifier, nopLogger{}, ExpirationCheckerConfig{
		Thresholds: []int{30, 15, 7},
	})

	ctx := context.Background()

	// First check - should notify
	checker.Check(ctx)
	if len(notifier.getExpiringCalls()) != 1 {
		t.Fatalf("first check: expected 1 notification, got %d", len(notifier.getExpiringCalls()))
	}

	// Second check - should NOT notify again (cooldown)
	checker.Check(ctx)
	if len(notifier.getExpiringCalls()) != 1 {
		t.Errorf("second check: expected still 1 notification (dedup), got %d", len(notifier.getExpiringCalls()))
	}
}

func TestExpirationChecker_ResetNotifications(t *testing.T) {
	notifier := &mockNotifier{}

	expiresIn5Days := time.Now().Add(5 * 24 * time.Hour)
	provider := &Provider{
		info: &Info{
			Edition:   Business,
			Valid:     true,
			LicenseID: "USN-test-reset",
			ExpiresAt: &expiresIn5Days,
			Features:  AllFeatures(),
		},
	}

	checker := NewExpirationChecker(provider, notifier, nopLogger{}, ExpirationCheckerConfig{
		Thresholds: []int{30, 15, 7},
	})

	ctx := context.Background()

	// First check
	checker.Check(ctx)
	if len(notifier.getExpiringCalls()) != 1 {
		t.Fatal("expected 1 notification after first check")
	}

	// Reset and check again
	checker.ResetNotifications()
	checker.Check(ctx)
	if len(notifier.getExpiringCalls()) != 2 {
		t.Errorf("expected 2 notifications after reset, got %d", len(notifier.getExpiringCalls()))
	}
}

func TestExpirationChecker_30DayThreshold(t *testing.T) {
	notifier := &mockNotifier{}

	expiresIn25Days := time.Now().Add(25 * 24 * time.Hour)
	provider := &Provider{
		info: &Info{
			Edition:   Enterprise,
			Valid:     true,
			LicenseID: "USN-test-30d",
			ExpiresAt: &expiresIn25Days,
			Features:  AllFeatures(),
		},
	}

	checker := NewExpirationChecker(provider, notifier, nopLogger{}, ExpirationCheckerConfig{
		Thresholds: []int{30, 15, 7, 3, 1},
	})

	ctx := context.Background()
	checker.Check(ctx)

	calls := notifier.getExpiringCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 notification for 25 days remaining, got %d", len(calls))
	}
	// 25 days should trigger the 30-day threshold
	if calls[0].DaysRemaining < 24 || calls[0].DaysRemaining > 26 {
		t.Errorf("DaysRemaining = %d, want ~25", calls[0].DaysRemaining)
	}
}

func TestExpirationChecker_FarFutureLicenseNoNotification(t *testing.T) {
	notifier := &mockNotifier{}

	expiresIn365Days := time.Now().Add(365 * 24 * time.Hour)
	provider := &Provider{
		info: &Info{
			Edition:   Business,
			Valid:     true,
			LicenseID: "USN-test-far",
			ExpiresAt: &expiresIn365Days,
			Features:  AllFeatures(),
		},
	}

	checker := NewExpirationChecker(provider, notifier, nopLogger{}, ExpirationCheckerConfig{
		Thresholds: []int{30, 15, 7},
	})

	ctx := context.Background()
	checker.Check(ctx)

	if len(notifier.getExpiringCalls()) != 0 {
		t.Error("365 days remaining should not trigger any notification")
	}
}
