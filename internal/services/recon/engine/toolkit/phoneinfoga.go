// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package toolkit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// phoneinfogaModule is the profile module name the engine routes
// here. The full profile entry looks like "toolkit:phoneinfoga".
const phoneinfogaModule = "phoneinfoga"

// CategoryPhoneInfo is the recon.Finding.Category every event from
// this wrapper carries.
const CategoryPhoneInfo = "phone_info"

// phoneinfogaJSON mirrors the relevant subset of phoneinfoga's
// `scan -n <num> --output json` shape. We only consume the fields
// the mapping decisions need; unknown fields stay in the raw
// payload so the audit row preserves them.
type phoneinfogaJSON struct {
	Number        string `json:"Number"`
	Country       string `json:"Country"`
	CountryCode   string `json:"CountryCode"`
	Carrier       string `json:"Carrier"`
	LineType      string `json:"LineType"`
	Local         string `json:"LocalFormat"`
	International string `json:"InternationalFormat"`
}

// phoneinfogaRunner is the moduleRunner implementation for
// phoneinfoga.
type phoneinfogaRunner struct{}

// Module implements moduleRunner.
func (phoneinfogaRunner) Module() string { return phoneinfogaModule }

// Run implements moduleRunner. The base event is severity=info; if
// the carrier or line type indicates a VoIP / temporary number we
// also emit a severity=high event so the operator sees the risk
// inline with the rest of the scan.
func (phoneinfogaRunner) Run(
	ctx context.Context,
	target recon.Target,
	launcher recon.ContainerLauncher,
	image string,
	timeout time.Duration,
) ([]recon.EngineEvent, error) {
	phone := strings.TrimSpace(target.Value)
	if phone == "" {
		return nil, fmt.Errorf("toolkit: phoneinfoga: empty target phone")
	}

	cmd := []string{"phoneinfoga", "--phone", phone}
	var dst phoneinfogaJSON
	raw, err := runToolkitJSON(ctx, launcher, image, cmd, timeout, &dst)
	if err != nil {
		return nil, err
	}

	rawJSON := json.RawMessage(decodeJSON(raw))
	base := recon.EngineEvent{
		Module:     phoneinfogaModule,
		Category:   CategoryPhoneInfo,
		Severity:   recon.SeverityInfo,
		Value:      dst.International,
		Source:     phone,
		Confidence: 70,
		RawPayload: rawJSON,
	}
	if base.Value == "" {
		base.Value = phone
	}
	out := []recon.EngineEvent{base}

	if isVoIPCarrier(dst.Carrier) || isVoIPLineType(dst.LineType) {
		alert := base
		alert.Severity = recon.SeverityHigh
		alert.Value = fmt.Sprintf("voip:%s", strings.TrimSpace(dst.Carrier+" "+dst.LineType))
		out = append(out, alert)
	}
	return out, nil
}

// isVoIPCarrier reports whether the carrier name string indicates a
// VoIP / temporary number. Comparison is case-insensitive and based
// on the carriers that ship the bulk of disposable numbers.
func isVoIPCarrier(carrier string) bool {
	c := strings.ToLower(strings.TrimSpace(carrier))
	if c == "" {
		return false
	}
	for _, needle := range []string{"voip", "twilio", "bandwidth", "google voice", "skype", "textnow", "textfree", "vonage"} {
		if strings.Contains(c, needle) {
			return true
		}
	}
	return false
}

// isVoIPLineType reports whether phoneinfoga's LineType output
// indicates a non-residential / disposable number.
func isVoIPLineType(lineType string) bool {
	c := strings.ToLower(strings.TrimSpace(lineType))
	switch c {
	case "voip", "non-fixed-voip", "nonfixedvoip", "temporary":
		return true
	}
	return false
}
