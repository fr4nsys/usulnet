// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package license

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"
)

// ExpirationNotifier is the callback interface for license expiration events.
// Implementations send notifications through the notification service.
type ExpirationNotifier interface {
	// NotifyLicenseExpiring is called when the license is approaching expiration.
	// daysRemaining indicates how many days until expiration.
	NotifyLicenseExpiring(ctx context.Context, info *Info, daysRemaining int) error

	// NotifyLicenseExpired is called when the license has expired.
	NotifyLicenseExpired(ctx context.Context, info *Info) error

	// NotifyLimitApproaching is called when a resource approaches its limit (80%+).
	NotifyLimitApproaching(ctx context.Context, resource string, current, limit int) error
}

// ExpirationChecker monitors license expiration and sends notifications
// at configurable thresholds (default: 30, 15, 7, 3, 1 days before expiry).
// It also triggers notifications when the license actually expires.
type ExpirationChecker struct {
	provider *Provider
	notifier ExpirationNotifier
	logger   Logger

	// thresholds are the number of days before expiration at which
	// notifications should be sent (sorted descending).
	thresholds []int

	// notifiedThresholds tracks which thresholds have already fired
	// to avoid repeated notifications. Keyed by threshold day value.
	mu                  sync.Mutex
	notifiedThresholds  map[int]time.Time
	expiredNotifiedAt   *time.Time

	// checkInterval controls how often the checker runs.
	checkInterval time.Duration
	stopCh        chan struct{}
}

// ExpirationCheckerConfig configures the expiration checker.
type ExpirationCheckerConfig struct {
	// Thresholds are the days-before-expiry at which to notify.
	// Default: [30, 15, 7, 3, 1]
	Thresholds []int

	// CheckInterval is how often to check. Default: 1 hour.
	CheckInterval time.Duration

	// NotificationCooldown is the minimum time between repeated
	// notifications for the same threshold. Default: 24 hours.
	NotificationCooldown time.Duration
}

// DefaultExpirationCheckerConfig returns the default configuration.
func DefaultExpirationCheckerConfig() ExpirationCheckerConfig {
	return ExpirationCheckerConfig{
		Thresholds:           []int{30, 15, 7, 3, 1},
		CheckInterval:        1 * time.Hour,
		NotificationCooldown: 24 * time.Hour,
	}
}

// NewExpirationChecker creates an expiration checker.
// It does NOT start automatically; call Start() to begin monitoring.
func NewExpirationChecker(
	provider *Provider,
	notifier ExpirationNotifier,
	logger Logger,
	config ExpirationCheckerConfig,
) *ExpirationChecker {
	if len(config.Thresholds) == 0 {
		config.Thresholds = []int{30, 15, 7, 3, 1}
	}
	if config.CheckInterval <= 0 {
		config.CheckInterval = 1 * time.Hour
	}

	return &ExpirationChecker{
		provider:           provider,
		notifier:           notifier,
		logger:             logger,
		thresholds:         config.Thresholds,
		notifiedThresholds: make(map[int]time.Time),
		checkInterval:      config.CheckInterval,
		stopCh:             make(chan struct{}),
	}
}

// Start begins the background monitoring loop.
func (ec *ExpirationChecker) Start() {
	go ec.run()
}

// Stop terminates the background loop.
func (ec *ExpirationChecker) Stop() {
	close(ec.stopCh)
}

// Check performs a single expiration check. Useful for testing
// or for manual/scheduler-triggered checks.
func (ec *ExpirationChecker) Check(ctx context.Context) {
	info := ec.provider.GetInfo()

	// Only check paid licenses (CE never expires)
	if info.Edition == CE {
		return
	}

	if info.ExpiresAt == nil {
		return
	}

	now := time.Now()
	expiresAt := *info.ExpiresAt

	if now.After(expiresAt) {
		// License has expired
		ec.handleExpired(ctx, info)
		return
	}

	// Calculate days remaining
	remaining := expiresAt.Sub(now)
	daysRemaining := int(math.Ceil(remaining.Hours() / 24))

	// Check each threshold
	for _, threshold := range ec.thresholds {
		if daysRemaining <= threshold {
			ec.handleThreshold(ctx, info, threshold, daysRemaining)
			break // Only notify for the most urgent (smallest matching) threshold
		}
	}
}

func (ec *ExpirationChecker) handleExpired(ctx context.Context, info *Info) {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	// Only notify once per 24 hours for expired licenses
	if ec.expiredNotifiedAt != nil {
		if time.Since(*ec.expiredNotifiedAt) < 24*time.Hour {
			return
		}
	}

	ec.logger.Warn("license: license has expired, sending notification",
		"license_id", info.LicenseID,
		"expired_at", info.ExpiresAt,
	)

	if err := ec.notifier.NotifyLicenseExpired(ctx, info); err != nil {
		ec.logger.Error("license: failed to send expiration notification", "error", err)
		return
	}

	now := time.Now()
	ec.expiredNotifiedAt = &now
}

func (ec *ExpirationChecker) handleThreshold(ctx context.Context, info *Info, threshold, daysRemaining int) {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	// Check if we already notified for this threshold recently
	if lastNotified, ok := ec.notifiedThresholds[threshold]; ok {
		if time.Since(lastNotified) < 24*time.Hour {
			return
		}
	}

	ec.logger.Info("license: expiration approaching, sending notification",
		"license_id", info.LicenseID,
		"days_remaining", daysRemaining,
		"threshold", threshold,
	)

	if err := ec.notifier.NotifyLicenseExpiring(ctx, info, daysRemaining); err != nil {
		ec.logger.Error("license: failed to send expiring notification", "error", err)
		return
	}

	ec.notifiedThresholds[threshold] = time.Now()
}

func (ec *ExpirationChecker) run() {
	// Run an initial check immediately
	ec.Check(context.Background())

	ticker := time.NewTicker(ec.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ec.stopCh:
			return
		case <-ticker.C:
			ec.Check(context.Background())
		}
	}
}

// ResetNotifications clears the notification state, allowing
// all thresholds to fire again. Useful after license renewal.
func (ec *ExpirationChecker) ResetNotifications() {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.notifiedThresholds = make(map[int]time.Time)
	ec.expiredNotifiedAt = nil
}

// DaysUntilExpiration returns the number of days until the current
// license expires, or -1 if already expired, or 0 if no expiration.
func DaysUntilExpiration(info *Info) int {
	if info == nil || info.ExpiresAt == nil {
		return 0 // No expiration (CE or perpetual)
	}

	remaining := time.Until(*info.ExpiresAt)
	if remaining <= 0 {
		return -1 // Already expired
	}

	return int(math.Ceil(remaining.Hours() / 24))
}

// GracefulDegradation describes the behavior when a license expires.
// Instead of crashing, the system downgrades to Community Edition limits
// while preserving data and basic functionality.
type GracefulDegradation struct {
	// IsExpired indicates the license has passed its expiration date.
	IsExpired bool

	// PreviousEdition is the edition before expiration.
	PreviousEdition Edition

	// ActiveLimits are the limits currently enforced.
	// When expired, these are CE limits.
	ActiveLimits Limits

	// DisabledFeatures lists features that were disabled due to expiration.
	DisabledFeatures []Feature

	// Message is a human-readable explanation of the current state.
	Message string
}

// GetDegradationState evaluates the current license and returns
// a description of any degradation in effect.
func GetDegradationState(info *Info) *GracefulDegradation {
	if info == nil {
		return &GracefulDegradation{
			IsExpired:    false,
			ActiveLimits: CELimits(),
			Message:      "Running as Community Edition",
		}
	}

	// Valid license - no degradation
	if info.Valid && !info.IsExpired() {
		return &GracefulDegradation{
			IsExpired:       false,
			PreviousEdition: info.Edition,
			ActiveLimits:    info.Limits,
			Message:         fmt.Sprintf("License active (%s)", info.EditionName()),
		}
	}

	// Expired license - graceful degradation
	if info.IsExpired() || !info.Valid {
		degraded := &GracefulDegradation{
			IsExpired:        true,
			PreviousEdition:  info.Edition,
			ActiveLimits:     CELimits(),
			DisabledFeatures: info.Features, // All features from the expired license
			Message: fmt.Sprintf(
				"License expired. System operating in Community Edition mode. "+
					"Previous edition: %s. Renew your license to restore full functionality.",
				info.EditionName(),
			),
		}
		return degraded
	}

	return &GracefulDegradation{
		IsExpired:    false,
		ActiveLimits: info.Limits,
		Message:      "License active",
	}
}
