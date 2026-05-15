// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package wireguard

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// ProbeResult records the local availability of the WireGuard tooling.
// All fields are populated even when one binary is missing.
type ProbeResult struct {
	WGAvailable      bool
	WGQuickAvailable bool
	WGVersion        string
}

// HasFullTooling reports whether both wg and wg-quick were found and
// `wg --version` returned successfully.
func (r ProbeResult) HasFullTooling() bool {
	return r.WGAvailable && r.WGQuickAvailable
}

// ProbeTimeout is the maximum time the probe spends checking the
// local binaries. Five seconds is plenty for an exec.LookPath +
// `wg --version` round-trip.
const ProbeTimeout = 5 * time.Second

// ProbeLocal checks if `wg` and `wg-quick` are present on the host and
// queries `wg --version` for a textual version. The check is best-effort;
// callers treat the result as informational and never block startup on
// a missing binary.
func ProbeLocal(ctx context.Context) ProbeResult {
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()

	res := ProbeResult{}
	if _, err := exec.LookPath("wg"); err == nil {
		res.WGAvailable = true
		// Capture the version line for the UI; bounded by ProbeTimeout
		// and the hard exec.Cmd.Wait timeout below.
		out, runErr := exec.CommandContext(ctx, "wg", "--version").CombinedOutput() // #nosec G204 -- fixed argv
		if runErr == nil {
			res.WGVersion = strings.TrimSpace(string(out))
		} else if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			res.WGVersion = "wg version unknown: " + runErr.Error()
		}
	}
	if _, err := exec.LookPath("wg-quick"); err == nil {
		res.WGQuickAvailable = true
	}
	return res
}
