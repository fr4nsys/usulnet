// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package calendar

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// TestRenderICSStructure verifies the RFC 5545 §3.4 envelope: a
// BEGIN:VCALENDAR / END:VCALENDAR pair with VERSION:2.0 and a PRODID,
// and every VEVENT must have UID, DTSTAMP, DTSTART, DTEND, SUMMARY.
func TestRenderICSStructure(t *testing.T) {
	events := []*models.CalendarEvent{
		{
			ID:          uuid.MustParse("8c3a9f0e-1234-4567-8901-234567890abc"),
			HostID:      uuid.New(),
			Source:      models.CalendarSourceManual,
			Kind:        models.CalendarKindMaintenance,
			Title:       "Patch window",
			Description: "Apply security patches",
			Location:    "us-east-1",
			URL:         "https://usulnet.local/runbooks/patch",
			StartsAt:    time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
			EndsAt:      time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC),
		},
	}
	body := RenderICS("-//usulnet//calendar//EN", events)

	// CRLF line endings (RFC 5545 §3.1).
	if !bytes.Contains(body, []byte("\r\n")) {
		t.Fatal("expected CRLF line endings")
	}
	if bytes.Contains(body, []byte("\r\r")) {
		t.Fatal("did not expect double CR")
	}

	lines := unfold(body)
	wantPrefixes := []string{
		"BEGIN:VCALENDAR",
		"VERSION:2.0",
		"PRODID:",
		"CALSCALE:GREGORIAN",
		"BEGIN:VEVENT",
		"UID:",
		"DTSTAMP:",
		"DTSTART:",
		"DTEND:",
		"SUMMARY:",
		"DESCRIPTION:",
		"LOCATION:",
		"URL:",
		"CATEGORIES:",
		"END:VEVENT",
		"END:VCALENDAR",
	}
	for _, want := range wantPrefixes {
		if !hasLinePrefix(lines, want) {
			t.Errorf("expected line with prefix %q, body:\n%s", want, body)
		}
	}

	// First line must be BEGIN:VCALENDAR, last END:VCALENDAR.
	if lines[0] != "BEGIN:VCALENDAR" {
		t.Errorf("first line must be BEGIN:VCALENDAR, got %q", lines[0])
	}
	// Find last non-empty line.
	last := ""
	for i := len(lines) - 1; i >= 0; i-- {
		if lines[i] != "" {
			last = lines[i]
			break
		}
	}
	if last != "END:VCALENDAR" {
		t.Errorf("last non-empty line must be END:VCALENDAR, got %q", last)
	}

	// UTC timestamps end with Z (RFC 5545 §3.3.5 form #2).
	dtstart := findLine(lines, "DTSTART:")
	if !strings.HasSuffix(dtstart, "Z") {
		t.Errorf("DTSTART must be UTC (Z suffix): %q", dtstart)
	}
	dtend := findLine(lines, "DTEND:")
	if !strings.HasSuffix(dtend, "Z") {
		t.Errorf("DTEND must be UTC (Z suffix): %q", dtend)
	}

	// VERSION must come before any VEVENT.
	verIdx := indexOfPrefix(lines, "VERSION:")
	veventIdx := indexOfPrefix(lines, "BEGIN:VEVENT")
	if verIdx < 0 || veventIdx < 0 || verIdx > veventIdx {
		t.Errorf("VERSION must precede BEGIN:VEVENT (version=%d, vevent=%d)", verIdx, veventIdx)
	}
}

// TestICSEscaping verifies RFC 5545 §3.3.11 TEXT escapes.
func TestICSEscaping(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`hello, world`, `hello\, world`},
		{`a;b`, `a\;b`},
		{`back\slash`, `back\\slash`},
		{"line1\nline2", `line1\nline2`},
	}
	for _, c := range cases {
		got := escapeICSText(c.in)
		if got != c.want {
			t.Errorf("escapeICSText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestICSLineFolding verifies §3.1 line folding: a line over 75 octets
// must be split with CRLF + space continuation.
func TestICSLineFolding(t *testing.T) {
	longTitle := strings.Repeat("A", 200)
	ev := []*models.CalendarEvent{
		{
			ID:       uuid.New(),
			HostID:   uuid.New(),
			Source:   models.CalendarSourceManual,
			Kind:     models.CalendarKindNote,
			Title:    longTitle,
			StartsAt: time.Now().UTC(),
			EndsAt:   time.Now().UTC().Add(time.Hour),
		},
	}
	body := RenderICS("-//usulnet//calendar//EN", ev)

	// No physical line on the wire may exceed 75 octets BEFORE the CRLF.
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 2048), 2048)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 75 {
			t.Errorf("physical line exceeds 75 octets (%d): %q", len(line), line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}

	// After unfolding, the SUMMARY must reconstruct to the original.
	lines := unfold(body)
	summary := findLine(lines, "SUMMARY:")
	want := "SUMMARY:" + longTitle
	if summary != want {
		t.Errorf("unfolded SUMMARY mismatch:\nwant=%q\ngot =%q", want, summary)
	}
}

// TestICSAllDayEvents verifies that all-day events use VALUE=DATE.
func TestICSAllDayEvents(t *testing.T) {
	ev := []*models.CalendarEvent{
		{
			ID:       uuid.New(),
			HostID:   uuid.New(),
			Source:   models.CalendarSourceManual,
			Kind:     models.CalendarKindMaintenance,
			Title:    "All-day note",
			AllDay:   true,
			StartsAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			EndsAt:   time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC),
		},
	}
	body := RenderICS("-//usulnet//calendar//EN", ev)
	lines := unfold(body)
	dtstart := findLine(lines, "DTSTART;VALUE=DATE:")
	if dtstart == "" {
		t.Fatal("expected DTSTART;VALUE=DATE: for all-day events")
	}
	if !strings.HasSuffix(dtstart, "20260601") {
		t.Errorf("expected DTSTART date 20260601, got %q", dtstart)
	}
	dtend := findLine(lines, "DTEND;VALUE=DATE:")
	if !strings.HasSuffix(dtend, "20260602") {
		t.Errorf("expected DTEND date 20260602, got %q", dtend)
	}
}

// TestICSEscapeAppliedToValues asserts that escaped TEXT lands in output.
func TestICSEscapeAppliedToValues(t *testing.T) {
	ev := []*models.CalendarEvent{
		{
			ID:          uuid.New(),
			HostID:      uuid.New(),
			Source:      models.CalendarSourceManual,
			Kind:        models.CalendarKindNote,
			Title:       "alpha; beta, gamma",
			Description: "line1\nline2",
			StartsAt:    time.Now().UTC(),
			EndsAt:      time.Now().UTC().Add(time.Hour),
		},
	}
	body := RenderICS("-//usulnet//calendar//EN", ev)
	if !bytes.Contains(body, []byte(`SUMMARY:alpha\; beta\, gamma`)) {
		t.Errorf("expected escaped SUMMARY in body:\n%s", body)
	}
	if !bytes.Contains(body, []byte(`DESCRIPTION:line1\nline2`)) {
		t.Errorf("expected escaped DESCRIPTION in body:\n%s", body)
	}
}

// TestUnfoldRoundTrip asserts the unfold helper is consistent with the
// renderer for a non-trivial document. This indirectly validates the
// "every produced line is parseable by a generic RFC 5545 unfolder".
func TestUnfoldRoundTrip(t *testing.T) {
	events := make([]*models.CalendarEvent, 0, 3)
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		events = append(events, &models.CalendarEvent{
			ID:       uuid.New(),
			HostID:   uuid.New(),
			Source:   models.CalendarSourceManual,
			Kind:     models.CalendarKindNote,
			Title:    "event " + strings.Repeat("x", 100) + " " + uuid.New().String(),
			StartsAt: now.Add(time.Duration(i) * time.Hour),
			EndsAt:   now.Add(time.Duration(i+1) * time.Hour),
		})
	}
	body := RenderICS("-//usulnet//calendar//EN", events)
	lines := unfold(body)
	// Expect at least: BEGIN, VERSION, PRODID, CALSCALE, METHOD + 3*VEVENT (>=7 each) + END
	if len(lines) < 5+3*7+1 {
		t.Errorf("unexpectedly few unfolded lines: %d", len(lines))
	}
	if count := countPrefix(lines, "BEGIN:VEVENT"); count != 3 {
		t.Errorf("expected 3 VEVENTs, got %d", count)
	}
	if count := countPrefix(lines, "END:VEVENT"); count != 3 {
		t.Errorf("expected 3 END:VEVENTs, got %d", count)
	}
}

// ============================================================================
// Test helpers — a minimal RFC 5545 line unfolder (§3.1)
// ============================================================================

// unfold parses the .ics body, joining continuation lines (a line that
// starts with a space or tab) onto the preceding logical line.
func unfold(body []byte) []string {
	var lines []string
	var cur strings.Builder
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 8192), 8192)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			// continuation — strip the single leading whitespace octet.
			cur.WriteString(line[1:])
			continue
		}
		if cur.Len() > 0 {
			lines = append(lines, cur.String())
			cur.Reset()
		}
		cur.WriteString(line)
	}
	if cur.Len() > 0 {
		lines = append(lines, cur.String())
	}
	return lines
}

func hasLinePrefix(lines []string, prefix string) bool {
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

func findLine(lines []string, prefix string) string {
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	return ""
}

func indexOfPrefix(lines []string, prefix string) int {
	for i, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return i
		}
	}
	return -1
}

func countPrefix(lines []string, prefix string) int {
	n := 0
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}
