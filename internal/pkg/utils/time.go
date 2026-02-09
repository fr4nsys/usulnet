// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package utils

import (
	"fmt"
	"time"
)

// Common time formats
const (
	DateFormat     = "2006-01-02"
	TimeFormat     = "15:04:05"
	DateTimeFormat = "2006-01-02 15:04:05"
	ISO8601Format  = time.RFC3339
)

// Now returns current time in UTC
func Now() time.Time {
	return time.Now().UTC()
}

// NowPtr returns a pointer to current time in UTC
func NowPtr() *time.Time {
	t := Now()
	return &t
}

// ParseTime parses a time string with multiple format attempts
func ParseTime(s string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		DateTimeFormat,
		DateFormat,
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05Z",
		"2006/01/02",
		"02/01/2006",
		"01/02/2006",
	}

	var lastErr error
	for _, format := range formats {
		t, err := time.Parse(format, s)
		if err == nil {
			return t.UTC(), nil
		}
		lastErr = err
	}
	return time.Time{}, lastErr
}

// FormatDuration formats a duration in a human-readable way
func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		mins := int(d.Minutes())
		secs := int(d.Seconds()) % 60
		if secs == 0 {
			return fmt.Sprintf("%dm", mins)
		}
		return fmt.Sprintf("%dm %ds", mins, secs)
	}
	if d < 24*time.Hour {
		hours := int(d.Hours())
		mins := int(d.Minutes()) % 60
		if mins == 0 {
			return fmt.Sprintf("%dh", hours)
		}
		return fmt.Sprintf("%dh %dm", hours, mins)
	}

	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	if hours == 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dd %dh", days, hours)
}

// TimeAgo returns a human-readable string for how long ago a time was
func TimeAgo(t time.Time) string {
	d := time.Since(t)

	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		mins := int(d.Minutes())
		if mins == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", mins)
	}
	if d < 24*time.Hour {
		hours := int(d.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	}
	if d < 7*24*time.Hour {
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}
	if d < 30*24*time.Hour {
		weeks := int(d.Hours() / 24 / 7)
		if weeks == 1 {
			return "1 week ago"
		}
		return fmt.Sprintf("%d weeks ago", weeks)
	}
	if d < 365*24*time.Hour {
		months := int(d.Hours() / 24 / 30)
		if months == 1 {
			return "1 month ago"
		}
		return fmt.Sprintf("%d months ago", months)
	}

	years := int(d.Hours() / 24 / 365)
	if years == 1 {
		return "1 year ago"
	}
	return fmt.Sprintf("%d years ago", years)
}

// StartOfDay returns the start of day (00:00:00) for a given time
func StartOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

// EndOfDay returns the end of day (23:59:59.999999999) for a given time
func EndOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 999999999, t.Location())
}

// StartOfWeek returns the start of week (Monday 00:00:00) for a given time
func StartOfWeek(t time.Time) time.Time {
	weekday := int(t.Weekday())
	if weekday == 0 {
		weekday = 7 // Sunday
	}
	return StartOfDay(t.AddDate(0, 0, -(weekday - 1)))
}

// StartOfMonth returns the start of month for a given time
func StartOfMonth(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location())
}

// EndOfMonth returns the end of month for a given time
func EndOfMonth(t time.Time) time.Time {
	return StartOfMonth(t).AddDate(0, 1, 0).Add(-time.Nanosecond)
}

// DaysBetween returns the number of days between two times
func DaysBetween(t1, t2 time.Time) int {
	d := t2.Sub(t1)
	return int(d.Hours() / 24)
}

// IsExpired checks if a time has passed
func IsExpired(t time.Time) bool {
	return time.Now().UTC().After(t)
}

// IsExpiredWithGrace checks if a time has passed with a grace period
func IsExpiredWithGrace(t time.Time, grace time.Duration) bool {
	return time.Now().UTC().After(t.Add(grace))
}

// TimePtr returns a pointer to a time value
func TimePtr(t time.Time) *time.Time {
	return &t
}

// TimeValue returns the value of a time pointer or zero time if nil
func TimeValue(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// DurationPtr returns a pointer to a duration value
func DurationPtr(d time.Duration) *time.Duration {
	return &d
}

// DurationValue returns the value of a duration pointer or zero if nil
func DurationValue(d *time.Duration) time.Duration {
	if d == nil {
		return 0
	}
	return *d
}

// ParseDurationWithDays parses a duration string that can include days (e.g., "7d", "2d12h")
func ParseDurationWithDays(s string) (time.Duration, error) {
	// Handle day suffix
	if len(s) > 0 && s[len(s)-1] == 'd' {
		// Check if there's more after the days
		for i := 0; i < len(s)-1; i++ {
			if s[i] >= '0' && s[i] <= '9' {
				continue
			}
			// Found non-digit before 'd', parse as two parts
			return parseDurationParts(s)
		}
		// Just days
		var days int
		_, err := fmt.Sscanf(s, "%dd", &days)
		if err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func parseDurationParts(s string) (time.Duration, error) {
	// Find where days end
	for i := 0; i < len(s); i++ {
		if s[i] == 'd' {
			var days int
			_, err := fmt.Sscanf(s[:i+1], "%dd", &days)
			if err != nil {
				return 0, err
			}
			rest, err := time.ParseDuration(s[i+1:])
			if err != nil {
				return 0, err
			}
			return time.Duration(days)*24*time.Hour + rest, nil
		}
	}
	return time.ParseDuration(s)
}
