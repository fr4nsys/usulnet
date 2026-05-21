// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// looksLikeUUID — recon.go shape check
// =============================================================================

func TestLooksLikeUUID(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"canonical lowercase", "550e8400-e29b-41d4-a716-446655440000", true},
		{"canonical uppercase", "550E8400-E29B-41D4-A716-446655440000", true},
		{"too short", "550e8400-e29b-41d4-a716-44665544", false},
		{"too long", "550e8400-e29b-41d4-a716-446655440000-extra", false},
		{"missing dash at 8", "550e84000e29b-41d4-a716-446655440000", false},
		{"missing dash at 13", "550e8400-e29b041d4-a716-446655440000", false},
		{"empty string", "", false},
		{"hexless garbage same length", "not-a-uuid-but-the-exact-right-len!!", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeUUID(tc.in); got != tc.want {
				t.Errorf("looksLikeUUID(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// =============================================================================
// resolveTimeout — recon.go --timeout parser
// =============================================================================

func TestResolveTimeout(t *testing.T) {
	t.Run("empty returns the original context unchanged", func(t *testing.T) {
		base := context.Background()
		ctx, cancel, err := resolveTimeout(base, "")
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		defer cancel()
		if ctx != base {
			t.Error("expected same context returned, got a new one")
		}
		if _, ok := ctx.Deadline(); ok {
			t.Error("expected no deadline, got one")
		}
	})

	t.Run("duration form is honoured", func(t *testing.T) {
		ctx, cancel, err := resolveTimeout(context.Background(), "250ms")
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		defer cancel()
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("expected deadline to be set")
		}
		want := time.Now().Add(250 * time.Millisecond)
		if delta := deadline.Sub(want); delta > 500*time.Millisecond || delta < -500*time.Millisecond {
			t.Errorf("deadline drift too large: delta = %v", delta)
		}
	})

	t.Run("bare integer is interpreted as seconds", func(t *testing.T) {
		ctx, cancel, err := resolveTimeout(context.Background(), "5")
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		defer cancel()
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("expected deadline to be set")
		}
		want := time.Now().Add(5 * time.Second)
		if delta := deadline.Sub(want); delta > time.Second || delta < -time.Second {
			t.Errorf("deadline drift too large: delta = %v", delta)
		}
	})

	t.Run("garbage returns a usageError", func(t *testing.T) {
		_, _, err := resolveTimeout(context.Background(), "not-a-duration")
		if err == nil {
			t.Fatal("expected error for invalid timeout")
		}
		var ue *usageError
		if !errors.As(err, &ue) {
			t.Errorf("expected *usageError, got %T (%v)", err, err)
		}
	})
}

// =============================================================================
// summarizeEvent — recon.go SSE record renderer
// =============================================================================

func TestSummarizeEvent(t *testing.T) {
	cases := []struct {
		name    string
		event   string
		data    string
		wantSub string // substring the rendered line must contain
		wantOut string // exact output when applicable; "" means substring check
	}{
		{
			name:    "empty data is dropped",
			event:   "finding",
			data:    "",
			wantOut: "",
		},
		{
			name:    "well-formed finding renders severity / module / value",
			event:   "finding",
			data:    `{"severity":"high","module":"sfp_shodan","value":"203.0.113.7"}`,
			wantSub: "sfp_shodan",
		},
		{
			name:    "non-JSON data is passed through trimmed",
			event:   "finding",
			data:    `  free text not JSON  `,
			wantOut: "free text not JSON",
		},
		{
			name:    "JSON without severity / module / value surfaces the event name",
			event:   "heartbeat",
			data:    `{"ts":"2026-05-19T10:00:00Z"}`,
			wantOut: "[heartbeat]",
		},
		{
			name:    "JSON without identifying fields and no event name is empty",
			event:   "",
			data:    `{"ts":"2026-05-19T10:00:00Z"}`,
			wantOut: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := summarizeEvent(tc.event, tc.data)
			if tc.wantOut != "" {
				if got != tc.wantOut {
					t.Errorf("summarizeEvent(%q, %q) = %q, want %q",
						tc.event, tc.data, got, tc.wantOut)
				}
				return
			}
			if !strings.Contains(got, tc.wantSub) {
				t.Errorf("summarizeEvent(%q, %q) = %q, want substring %q",
					tc.event, tc.data, got, tc.wantSub)
			}
		})
	}
}
