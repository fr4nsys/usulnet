// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package license

import (
	"context"
	"fmt"
)

// NotificationSender is the minimal interface we need from the notification service.
// This avoids importing the full notification package (prevents circular dependencies).
type NotificationSender interface {
	// SendLicenseExpiring sends a notification that the license is approaching expiration.
	SendLicenseExpiring(ctx context.Context, edition, licenseID string, daysRemaining int) error

	// SendLicenseExpired sends a notification that the license has expired.
	SendLicenseExpired(ctx context.Context, edition, licenseID string) error

	// SendResourceLimitApproaching sends a notification that a resource is near its limit.
	SendResourceLimitApproaching(ctx context.Context, resource string, current, limit int, percentUsed float64) error
}

// NotificationAdapter implements ExpirationNotifier by delegating to NotificationSender.
type NotificationAdapter struct {
	sender NotificationSender
}

// NewNotificationAdapter creates a new notification adapter.
func NewNotificationAdapter(sender NotificationSender) *NotificationAdapter {
	return &NotificationAdapter{sender: sender}
}

// NotifyLicenseExpiring implements ExpirationNotifier.
func (a *NotificationAdapter) NotifyLicenseExpiring(ctx context.Context, info *Info, daysRemaining int) error {
	if a.sender == nil {
		return nil
	}
	return a.sender.SendLicenseExpiring(ctx, string(info.Edition), info.LicenseID, daysRemaining)
}

// NotifyLicenseExpired implements ExpirationNotifier.
func (a *NotificationAdapter) NotifyLicenseExpired(ctx context.Context, info *Info) error {
	if a.sender == nil {
		return nil
	}
	return a.sender.SendLicenseExpired(ctx, string(info.Edition), info.LicenseID)
}

// NotifyLimitApproaching implements ExpirationNotifier.
func (a *NotificationAdapter) NotifyLimitApproaching(ctx context.Context, resource string, current, limit int) error {
	if a.sender == nil {
		return nil
	}
	percentUsed := 0.0
	if limit > 0 {
		percentUsed = float64(current) / float64(limit) * 100
	}
	return a.sender.SendResourceLimitApproaching(ctx, resource, current, limit, percentUsed)
}

// Compile-time check that NotificationAdapter satisfies ExpirationNotifier.
var _ ExpirationNotifier = (*NotificationAdapter)(nil)

// LimitProximityChecker evaluates resource limits and reports
// when usage approaches the configured threshold.
type LimitProximityChecker struct {
	provider *Provider
	notifier ExpirationNotifier
	logger   Logger

	// threshold is the percentage (0-100) at which to start alerting.
	// Default: 80 (alert at 80% usage).
	threshold float64
}

// NewLimitProximityChecker creates a proximity checker that alerts when
// resource usage reaches the specified threshold percentage.
func NewLimitProximityChecker(
	provider *Provider,
	notifier ExpirationNotifier,
	logger Logger,
	thresholdPercent float64,
) *LimitProximityChecker {
	if thresholdPercent <= 0 || thresholdPercent > 100 {
		thresholdPercent = 80
	}
	return &LimitProximityChecker{
		provider:  provider,
		notifier:  notifier,
		logger:    logger,
		threshold: thresholdPercent,
	}
}

// CheckResourceProximity checks if a specific resource is approaching its limit.
// Returns true if the resource is at or above the threshold.
func (lpc *LimitProximityChecker) CheckResourceProximity(
	ctx context.Context,
	resource string,
	current int,
	limit int,
) bool {
	if limit <= 0 {
		return false // Unlimited
	}

	percentUsed := float64(current) / float64(limit) * 100
	if percentUsed >= lpc.threshold {
		lpc.logger.Warn(fmt.Sprintf("license: resource %q at %.0f%% capacity (%d/%d)",
			resource, percentUsed, current, limit))

		if err := lpc.notifier.NotifyLimitApproaching(ctx, resource, current, limit); err != nil {
			lpc.logger.Error("license: failed to send limit proximity notification",
				"resource", resource, "error", err)
		}
		return true
	}
	return false
}
