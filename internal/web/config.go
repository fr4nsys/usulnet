// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

// Config holds web server configuration
type Config struct {
	// StaticPath is the path to static files
	StaticPath string

	// Version is the application version
	Version string

	// Debug enables debug mode
	Debug bool
}

// DefaultConfig returns default web configuration
func DefaultConfig() *Config {
	return &Config{
		StaticPath: "./web/static",
		Version:    "dev",
		Debug:      false,
	}
}
