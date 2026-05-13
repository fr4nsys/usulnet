// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package license

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// GenerateInstanceID creates a stable fingerprint for this installation.
// It combines machine-id (if available), hostname, and a persistent salt
// that is generated once and stored on disk.
//
// In Docker, /etc/machine-id may not exist, so the salt (persisted in the
// data volume) is the primary anchor that ties a license to an installation.
func GenerateInstanceID(dataDir string) (string, error) {
	var parts []string

	// 1. machine-id (unique per Linux install, may not exist in containers)
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		parts = append(parts, strings.TrimSpace(string(data)))
	}

	// 2. hostname
	if hostname, err := os.Hostname(); err == nil {
		parts = append(parts, hostname)
	}

	// 3. persistent salt (generated once, survives container recreations)
	salt, err := getOrCreateSalt(filepath.Join(dataDir, ".instance-salt"))
	if err != nil {
		return "", fmt.Errorf("license: cannot create instance salt: %w", err)
	}
	parts = append(parts, salt)

	if len(parts) == 0 {
		return "", fmt.Errorf("license: no system identifiers available")
	}

	combined := strings.Join(parts, "|")
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:16]), nil // 32-char hex string
}

func getOrCreateSalt(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil && len(data) >= 32 {
		return strings.TrimSpace(string(data)), nil
	}

	// Generate new salt
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	salt := hex.EncodeToString(buf)

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}

	if err := os.WriteFile(path, []byte(salt+"\n"), 0600); err != nil {
		return "", err
	}

	return salt, nil
}
