// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package backup

import (
	"testing"
	"time"
)

func TestCalculateNextRun_StandardCron(t *testing.T) {
	tests := []struct {
		name     string
		cronExpr string
		wantNil  bool
	}{
		{
			name:     "daily at 2am",
			cronExpr: "0 2 * * *",
			wantNil:  false,
		},
		{
			name:     "every 6 hours",
			cronExpr: "0 */6 * * *",
			wantNil:  false,
		},
		{
			name:     "weekly on Sunday at midnight",
			cronExpr: "0 0 * * 0",
			wantNil:  false,
		},
		{
			name:     "monthly on 1st at midnight",
			cronExpr: "0 0 1 * *",
			wantNil:  false,
		},
		{
			name:     "every minute",
			cronExpr: "* * * * *",
			wantNil:  false,
		},
		{
			name:     "every 5 minutes",
			cronExpr: "*/5 * * * *",
			wantNil:  false,
		},
		{
			name:     "weekdays at 9am",
			cronExpr: "0 9 * * 1-5",
			wantNil:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateNextRun(tt.cronExpr)
			if tt.wantNil && result != nil {
				t.Errorf("calculateNextRun(%q) = %v, want nil", tt.cronExpr, result)
			}
			if !tt.wantNil && result == nil {
				t.Errorf("calculateNextRun(%q) = nil, want non-nil", tt.cronExpr)
			}
			if result != nil {
				if result.Before(time.Now()) {
					t.Errorf("calculateNextRun(%q) = %v, want future time", tt.cronExpr, result)
				}
			}
		})
	}
}

func TestCalculateNextRun_WithSeconds(t *testing.T) {
	tests := []struct {
		name     string
		cronExpr string
		wantNil  bool
	}{
		{
			name:     "every 30 seconds",
			cronExpr: "*/30 * * * * *",
			wantNil:  false,
		},
		{
			name:     "at second 0 of every minute",
			cronExpr: "0 * * * * *",
			wantNil:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateNextRun(tt.cronExpr)
			if tt.wantNil && result != nil {
				t.Errorf("calculateNextRun(%q) = %v, want nil", tt.cronExpr, result)
			}
			if !tt.wantNil && result == nil {
				t.Errorf("calculateNextRun(%q) = nil, want non-nil", tt.cronExpr)
			}
			if result != nil {
				if result.Before(time.Now()) {
					t.Errorf("calculateNextRun(%q) = %v, want future time", tt.cronExpr, result)
				}
			}
		})
	}
}

func TestCalculateNextRun_InvalidExpression(t *testing.T) {
	tests := []struct {
		name     string
		cronExpr string
	}{
		{
			name:     "empty string",
			cronExpr: "",
		},
		{
			name:     "invalid format",
			cronExpr: "not a cron expression",
		},
		{
			name:     "too few fields",
			cronExpr: "0 2 *",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateNextRun(tt.cronExpr)
			if result != nil {
				t.Errorf("calculateNextRun(%q) = %v, want nil for invalid expression", tt.cronExpr, result)
			}
		})
	}
}

func TestCalculateNextRun_ReturnsCorrectNextTime(t *testing.T) {
	// Test that "every minute" returns a time within the next ~60 seconds
	result := calculateNextRun("* * * * *")
	if result == nil {
		t.Fatal("calculateNextRun(\"* * * * *\") = nil, want non-nil")
	}

	diff := time.Until(*result)
	if diff < 0 || diff > 61*time.Second {
		t.Errorf("calculateNextRun(\"* * * * *\") returned time %v from now, want within 61 seconds", diff)
	}
}

func TestCalculateNextRun_DailySchedule(t *testing.T) {
	// Test that daily at 2am returns a time within the next 24 hours
	result := calculateNextRun("0 2 * * *")
	if result == nil {
		t.Fatal("calculateNextRun(\"0 2 * * *\") = nil, want non-nil")
	}

	diff := time.Until(*result)
	if diff < 0 || diff > 24*time.Hour+time.Minute {
		t.Errorf("calculateNextRun(\"0 2 * * *\") returned time %v from now, want within 24 hours", diff)
	}
}

func TestCalculateNextRun_NotPlaceholder(t *testing.T) {
	// Verify that the function does NOT return a fixed 1-hour offset
	// (which was the old placeholder behavior)
	result := calculateNextRun("0 2 * * *")
	if result == nil {
		t.Fatal("calculateNextRun returned nil")
	}

	oneHourFromNow := time.Now().Add(1 * time.Hour)
	diff := result.Sub(oneHourFromNow)
	if diff > -time.Second && diff < time.Second {
		// If it's almost exactly 1 hour from now, that's suspicious
		// (unless it happens to be ~1am right now)
		now := time.Now()
		if now.Hour() != 1 {
			t.Errorf("calculateNextRun returned approximately 1 hour from now (%v), suggesting placeholder behavior", result)
		}
	}
}
