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

// PrintVersion prints version information to stdout. It returns an error so
// callers using cobra.Command.RunE can propagate failures to the root error
// handler; the current implementation writes to os.Stdout via fmt.Printf,
// which never returns an error in practice, but the typed return future-proofs
// the contract against a writer that does.
func PrintVersion() error {
	if _, err := fmt.Printf("usulnet %s\n", Version); err != nil {
		return err
	}
	if _, err := fmt.Printf("  Commit:     %s\n", Commit); err != nil {
		return err
	}
	if _, err := fmt.Printf("  Built:      %s\n", BuildTime); err != nil {
		return err
	}
	if _, err := fmt.Printf("  Go version: %s\n", runtime.Version()); err != nil {
		return err
	}
	if _, err := fmt.Printf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH); err != nil {
		return err
	}
	return nil
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
