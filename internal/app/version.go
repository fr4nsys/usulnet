// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"fmt"
	"runtime"
)

// Version information - set via ldflags at build time
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// PrintVersion prints version information to stdout
func PrintVersion() {
	fmt.Printf("usulnet %s\n", Version)
	fmt.Printf("  Commit:     %s\n", Commit)
	fmt.Printf("  Built:      %s\n", BuildTime)
	fmt.Printf("  Go version: %s\n", runtime.Version())
	fmt.Printf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
}

// GetVersionInfo returns version information as a map
func GetVersionInfo() map[string]string {
	return map[string]string{
		"version":    Version,
		"commit":     Commit,
		"build_time": BuildTime,
		"go_version": runtime.Version(),
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
	}
}

// VersionString returns a single-line version string
func VersionString() string {
	return fmt.Sprintf("%s (commit: %s, built: %s)", Version, Commit, BuildTime)
}
