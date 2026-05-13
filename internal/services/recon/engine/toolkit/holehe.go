// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package toolkit

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// holeheModule is the profile module name the engine routes here.
// The full profile entry looks like "toolkit:holehe".
const holeheModule = "holehe"

// CategoryEmailExposure is the recon.Finding.Category every event
// from this wrapper carries. Exported because the dispatcher and
// tests assert on it.
const CategoryEmailExposure = "email_exposure"

// holeheJSON is the schema the entrypoint emits for the holehe
// subcommand: a JSON object with the email + raw text output.
// holehe itself does not have a stable JSON mode upstream; we parse
// the raw text on this side rather than maintaining a fork.
type holeheJSON struct {
	Email string `json:"email"`
	Raw   string `json:"raw"`
}

// holeheRunner is the moduleRunner implementation for holehe.
type holeheRunner struct{}

// Module implements moduleRunner.
func (holeheRunner) Module() string { return holeheModule }

// Run implements moduleRunner. Each "used" line from holehe becomes
// an EngineEvent at medium severity; "not used" lines stay info.
func (holeheRunner) Run(
	ctx context.Context,
	target recon.Target,
	launcher recon.ContainerLauncher,
	image string,
	timeout time.Duration,
) ([]recon.EngineEvent, error) {
	email := strings.TrimSpace(target.Value)
	if email == "" {
		return nil, fmt.Errorf("toolkit: holehe: empty target email")
	}

	cmd := []string{"holehe", "--email", email}
	var dst holeheJSON
	raw, err := runToolkitJSON(ctx, launcher, image, cmd, timeout, &dst)
	if err != nil {
		return nil, err
	}

	events := parseHoleheRaw(dst.Raw, dst.Email)
	// Stash the original JSON payload on every event so the audit
	// row carries the full upstream output.
	for i := range events {
		events[i].RawPayload = json.RawMessage(decodeJSON(raw))
	}
	return events, nil
}

// holeheLine matches one row of holehe's "--no-clear --only-used"
// text output. The CLI emits lines like:
//
//	[+] site.com
//	[-] anothersite.com
//
// We treat "[+]" as used (medium) and "[-]" as not used (info). Any
// other prefix is ignored.
var holeheLine = regexp.MustCompile(`(?m)^\s*\[([\+\-x])\]\s+(\S+)\s*$`)

// parseHoleheRaw turns the raw stdout from the toolkit container
// into one EngineEvent per matched site. The function is exported
// to package tests via the unexported package name.
func parseHoleheRaw(raw, email string) []recon.EngineEvent {
	matches := holeheLine.FindAllStringSubmatch(raw, -1)
	out := make([]recon.EngineEvent, 0, len(matches))
	for _, m := range matches {
		marker := m[1]
		site := m[2]
		sev := recon.SeverityInfo
		state := "not_used"
		if marker == "+" {
			sev = recon.SeverityMedium
			state = "used"
		}
		payload, _ := json.Marshal(map[string]string{
			"email": email,
			"site":  site,
			"state": state,
		})
		out = append(out, recon.EngineEvent{
			Module:     holeheModule,
			Category:   CategoryEmailExposure,
			Severity:   sev,
			Value:      site,
			Source:     email,
			Confidence: 80,
			RawPayload: payload,
		})
	}
	return out
}
