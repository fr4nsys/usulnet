// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package calendar

import (
	"bytes"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/models"
)

// RFC 5545 line folding cap. Lines exceeding 75 octets are split by
// inserting CRLF followed by a single space; readers re-join folded
// continuation lines back into the logical line. See §3.1.
const icsFoldLimit = 75

// icsCRLF is the line terminator required by RFC 5545 §3.1.
const icsCRLF = "\r\n"

// icsTimeLayout matches RFC 5545 §3.3.5 (DATE-TIME, form #2: UTC time).
// The "Z" suffix marks the value as UTC; usulnet always exports UTC so
// the file is unambiguous regardless of the operator's timezone.
const icsTimeLayout = "20060102T150405Z"

// icsDateLayout matches RFC 5545 §3.3.4 (DATE).
const icsDateLayout = "20060102"

// icsDomain is the suffix appended to every UID to form a globally
// unique identifier per RFC 5545 §3.8.4.7. Using a constant suffix
// rather than the operator's hostname keeps exports reproducible.
const icsDomain = "usulnet.com"

// RenderICS renders the given events as an RFC 5545 .ics document with
// CRLF line endings and 75-octet folding. The prodID becomes PRODID.
//
// The returned bytes are deterministic for a given (prodID, events)
// pair except for the DTSTAMP value, which RFC 5545 requires to be the
// current time at export.
func RenderICS(prodID string, events []*models.CalendarEvent) []byte {
	var b bytes.Buffer
	now := time.Now().UTC()

	w := &icsWriter{buf: &b}
	w.WriteLine("BEGIN:VCALENDAR")
	w.WriteLine("VERSION:2.0")
	w.WriteLine("PRODID:" + escapeICSText(prodID))
	w.WriteLine("CALSCALE:GREGORIAN")
	w.WriteLine("METHOD:PUBLISH")

	for _, e := range events {
		w.WriteLine("BEGIN:VEVENT")
		w.WriteLine("UID:" + e.ID.String() + "@" + icsDomain)
		w.WriteLine("DTSTAMP:" + now.Format(icsTimeLayout))
		if e.AllDay {
			w.WriteLine("DTSTART;VALUE=DATE:" + e.StartsAt.UTC().Format(icsDateLayout))
			// DTEND on a VALUE=DATE event is exclusive (RFC 5545 §3.6.1).
			// Add one day so a one-day all-day event still has DTEND > DTSTART.
			end := e.EndsAt
			if !end.After(e.StartsAt) {
				end = e.StartsAt.Add(24 * time.Hour)
			}
			w.WriteLine("DTEND;VALUE=DATE:" + end.UTC().Format(icsDateLayout))
		} else {
			w.WriteLine("DTSTART:" + e.StartsAt.UTC().Format(icsTimeLayout))
			w.WriteLine("DTEND:" + e.EndsAt.UTC().Format(icsTimeLayout))
		}
		w.WriteLine("SUMMARY:" + escapeICSText(e.Title))
		if e.Description != "" {
			w.WriteLine("DESCRIPTION:" + escapeICSText(e.Description))
		}
		if e.Location != "" {
			w.WriteLine("LOCATION:" + escapeICSText(e.Location))
		}
		if e.URL != "" {
			w.WriteLine("URL:" + e.URL)
		}
		// CATEGORIES carries both the event kind and the source so
		// clients can filter on either without us inventing a custom
		// X-property name. Per RFC 5545 §3.8.1.2, CATEGORIES is a
		// comma-separated TEXT list.
		categories := strings.ToUpper(string(e.Kind)) + ",SOURCE-" + strings.ToUpper(string(e.Source))
		w.WriteLine("CATEGORIES:" + categories)
		w.WriteLine("END:VEVENT")
	}

	w.WriteLine("END:VCALENDAR")
	return b.Bytes()
}

// icsWriter applies RFC 5545 line folding and CRLF termination.
type icsWriter struct {
	buf *bytes.Buffer
}

// WriteLine writes a content line, folding it to icsFoldLimit octets
// per RFC 5545 §3.1 and terminating with CRLF.
func (w *icsWriter) WriteLine(line string) {
	// Fold conservatively at byte boundaries. RFC 5545 mandates folding
	// at UTF-8 character boundaries (§3.1) but we only emit single-byte
	// runes after escape; the safer rune-aware path is below.
	runes := []rune(line)
	if len(line) <= icsFoldLimit {
		w.buf.WriteString(line)
		w.buf.WriteString(icsCRLF)
		return
	}

	first := true
	for len(runes) > 0 {
		limit := icsFoldLimit
		if !first {
			// continuation lines are prefixed with one space, so the
			// remaining payload budget is one octet smaller.
			limit = icsFoldLimit - 1
		}
		// Count how many runes fit in `limit` octets.
		n := 0
		octets := 0
		for ; n < len(runes); n++ {
			rl := utf8RuneLen(runes[n])
			if octets+rl > limit {
				break
			}
			octets += rl
		}
		if n == 0 {
			// Single rune larger than the limit — write it anyway to
			// avoid an infinite loop. RFC 5545 callers should never
			// produce this in practice.
			n = 1
		}
		chunk := string(runes[:n])
		runes = runes[n:]
		if first {
			w.buf.WriteString(chunk)
			first = false
		} else {
			w.buf.WriteString(" ")
			w.buf.WriteString(chunk)
		}
		w.buf.WriteString(icsCRLF)
	}
}

// utf8RuneLen returns the UTF-8 byte length of r. Implemented inline so
// the .ics renderer has no extra import surface.
func utf8RuneLen(r rune) int {
	switch {
	case r < 0:
		return 1
	case r < 0x80:
		return 1
	case r < 0x800:
		return 2
	case r < 0x10000:
		return 3
	default:
		return 4
	}
}

// escapeICSText applies the TEXT escapes from RFC 5545 §3.3.11:
// backslash, semicolon, comma, and newline are escaped. CR is dropped
// to avoid mid-value CRLF that would terminate the property.
func escapeICSText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case ';':
			b.WriteString(`\;`)
		case ',':
			b.WriteString(`\,`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			// drop
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
