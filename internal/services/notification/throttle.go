// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package notification provides the notification service for USULNET.
// Department L: Notifications
package notification

import (
	"sync"
	"time"

	"github.com/fr4nsys/usulnet/internal/services/notification/channels"
)

// Throttler controls notification rate to prevent spam.
// Uses sliding window rate limiting per notification type.
type Throttler struct {
	mu       sync.RWMutex
	config   ThrottleConfig
	windows  map[channels.NotificationType]*slidingWindow
	global   *slidingWindow
}

// ThrottleConfig defines rate limiting configuration.
type ThrottleConfig struct {
	// Enabled turns throttling on/off globally.
	Enabled bool `json:"enabled"`

	// DefaultWindow is the time window for rate limiting (e.g., 1 hour).
	DefaultWindow time.Duration `json:"default_window"`

	// DefaultLimit is the max notifications per window per type.
	DefaultLimit int `json:"default_limit"`

	// GlobalLimit is the max total notifications per window across all types.
	GlobalLimit int `json:"global_limit"`

	// TypeLimits overrides limits for specific notification types.
	TypeLimits map[channels.NotificationType]int `json:"type_limits,omitempty"`

	// CriticalBypass allows critical notifications to bypass throttling.
	CriticalBypass bool `json:"critical_bypass"`

	// BurstAllowance allows brief bursts above the limit.
	BurstAllowance int `json:"burst_allowance"`
}

// DefaultThrottleConfig returns sensible defaults.
func DefaultThrottleConfig() ThrottleConfig {
	return ThrottleConfig{
		Enabled:        true,
		DefaultWindow:  time.Hour,
		DefaultLimit:   10,
		GlobalLimit:    50,
		CriticalBypass: true,
		BurstAllowance: 3,
		TypeLimits: map[channels.NotificationType]int{
			// Security alerts are important - higher limit
			channels.TypeSecurityAlert: 20,
			channels.TypeCVEDetected:   20,

			// Container issues can be frequent during problems
			channels.TypeContainerDown:     15,
			channels.TypeHealthCheckFailed: 15,

			// Updates are less frequent
			channels.TypeUpdateAvailable: 30,

			// Backups are scheduled and predictable
			channels.TypeBackupCompleted: 50,
			channels.TypeBackupFailed:    10,

			// Test messages should be unlimited during testing
			channels.TypeTestMessage: 100,
		},
	}
}

// slidingWindow tracks notification counts within a time window.
type slidingWindow struct {
	mu        sync.Mutex
	events    []time.Time
	window    time.Duration
	limit     int
	burstUsed int
}

// newSlidingWindow creates a new sliding window tracker.
func newSlidingWindow(window time.Duration, limit int) *slidingWindow {
	return &slidingWindow{
		events: make([]time.Time, 0, limit*2),
		window: window,
		limit:  limit,
	}
}

// Allow checks if a new event is allowed and records it if so.
func (sw *slidingWindow) Allow(burstAllowance int) bool {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-sw.window)

	// Remove expired events
	valid := sw.events[:0]
	for _, t := range sw.events {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	sw.events = valid

	// Check limit
	if len(sw.events) >= sw.limit {
		// Check burst allowance
		if sw.burstUsed < burstAllowance {
			sw.burstUsed++
			sw.events = append(sw.events, now)
			return true
		}
		return false
	}

	// Reset burst counter if under limit
	if len(sw.events) < sw.limit/2 {
		sw.burstUsed = 0
	}

	sw.events = append(sw.events, now)
	return true
}

// Count returns the current event count within the window.
func (sw *slidingWindow) Count() int {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-sw.window)

	count := 0
	for _, t := range sw.events {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

// NewThrottler creates a new notification throttler.
func NewThrottler(config ThrottleConfig) *Throttler {
	return &Throttler{
		config:  config,
		windows: make(map[channels.NotificationType]*slidingWindow),
		global:  newSlidingWindow(config.DefaultWindow, config.GlobalLimit),
	}
}

// Allow checks if a notification of the given type and priority can be sent.
func (t *Throttler) Allow(notifType channels.NotificationType, priority channels.Priority) bool {
	if !t.config.Enabled {
		return true
	}

	// Critical notifications bypass throttling if configured
	if t.config.CriticalBypass && priority >= channels.PriorityCritical {
		return true
	}

	t.mu.Lock()
	// Get or create window for this type
	window, exists := t.windows[notifType]
	if !exists {
		limit := t.config.DefaultLimit
		if typeLimit, ok := t.config.TypeLimits[notifType]; ok {
			limit = typeLimit
		}
		window = newSlidingWindow(t.config.DefaultWindow, limit)
		t.windows[notifType] = window
	}
	t.mu.Unlock()

	// Check type-specific limit
	if !window.Allow(t.config.BurstAllowance) {
		return false
	}

	// Check global limit
	if !t.global.Allow(t.config.BurstAllowance) {
		return false
	}

	return true
}

// Stats returns current throttling statistics.
func (t *Throttler) Stats() ThrottleStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	stats := ThrottleStats{
		GlobalCount: t.global.Count(),
		GlobalLimit: t.config.GlobalLimit,
		TypeCounts:  make(map[channels.NotificationType]TypeThrottleStats),
	}

	for notifType, window := range t.windows {
		limit := t.config.DefaultLimit
		if typeLimit, ok := t.config.TypeLimits[notifType]; ok {
			limit = typeLimit
		}

		stats.TypeCounts[notifType] = TypeThrottleStats{
			Count: window.Count(),
			Limit: limit,
		}
	}

	return stats
}

// ThrottleStats contains throttling statistics.
type ThrottleStats struct {
	GlobalCount int                                          `json:"global_count"`
	GlobalLimit int                                          `json:"global_limit"`
	TypeCounts  map[channels.NotificationType]TypeThrottleStats `json:"type_counts"`
}

// TypeThrottleStats contains per-type throttling statistics.
type TypeThrottleStats struct {
	Count int `json:"count"`
	Limit int `json:"limit"`
}

// Reset clears all throttle windows.
func (t *Throttler) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.windows = make(map[channels.NotificationType]*slidingWindow)
	t.global = newSlidingWindow(t.config.DefaultWindow, t.config.GlobalLimit)
}

// ResetType clears the throttle window for a specific type.
func (t *Throttler) ResetType(notifType channels.NotificationType) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.windows, notifType)
}

// UpdateConfig updates the throttle configuration.
func (t *Throttler) UpdateConfig(config ThrottleConfig) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.config = config
	t.global = newSlidingWindow(config.DefaultWindow, config.GlobalLimit)
	// Windows will be recreated on next use with new limits
	t.windows = make(map[channels.NotificationType]*slidingWindow)
}
