// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package license

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Store handles persistence of the license JWT to the filesystem.
// The JWT is stored as a plain text file so it survives restarts.
// It is also kept in the database by the service layer for redundancy.
type Store struct {
	path string // e.g. /app/data/license.jwt
}

// NewStore creates a Store that reads/writes to the given file path.
func NewStore(dataDir string) *Store {
	return &Store{
		path: filepath.Join(dataDir, "license.jwt"),
	}
}

// Save writes the raw JWT string to disk.
func (s *Store) Save(jwt string) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return fmt.Errorf("license store: mkdir: %w", err)
	}
	if err := os.WriteFile(s.path, []byte(jwt+"\n"), 0600); err != nil {
		return fmt.Errorf("license store: write: %w", err)
	}
	return nil
}

// Load reads the stored JWT from disk. Returns empty string if not found.
func (s *Store) Load() (string, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil // no license stored, that's fine (CE)
		}
		return "", fmt.Errorf("license store: read: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

// Remove deletes the stored license file.
func (s *Store) Remove() error {
	err := os.Remove(s.path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("license store: remove: %w", err)
	}
	return nil
}

// Path returns the filesystem path to the license file.
func (s *Store) Path() string {
	return s.path
}
