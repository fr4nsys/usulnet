// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package dockerconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Read reads and parses the current daemon.json file.
//
// A missing file is a valid Docker state (the daemon falls back to its
// built-in defaults), so the caller gets back an empty DaemonConfig
// with no error.
func (s *Service) Read(_ context.Context) (*DaemonConfig, error) {
	data, err := os.ReadFile(s.cfg.ConfigPath) //nolint:gosec // operator-supplied configurable path; bounded to /etc/docker by deployment
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &DaemonConfig{}, nil
		}
		return nil, fmt.Errorf("read daemon.json: %w", err)
	}
	if len(data) == 0 {
		return &DaemonConfig{}, nil
	}

	var cfg DaemonConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse daemon.json: %w", err)
	}
	return &cfg, nil
}

// ReadRaw returns the raw daemon.json content as a pretty-printed string.
//
// When the file is missing or empty, ReadRaw returns "{}\n" so the
// Monaco editor always opens on something parseable. When the on-disk
// content is non-JSON (somebody hand-edited it badly) ReadRaw returns
// the bytes as-is so the operator can fix them in the editor — better
// to surface the broken content than to silently overwrite it.
func (s *Service) ReadRaw(_ context.Context) (string, error) {
	data, err := os.ReadFile(s.cfg.ConfigPath) //nolint:gosec // operator-supplied configurable path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "{}\n", nil
		}
		return "", fmt.Errorf("read daemon.json: %w", err)
	}
	if len(data) == 0 {
		return "{}\n", nil
	}
	var raw json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		// Intentional: surface broken JSON to the editor instead of
		// erroring so the operator can fix it in place.
		return string(data), nil //nolint:nilerr
	}
	pretty, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		// Intentional: re-format failure falls back to raw bytes.
		return string(data), nil //nolint:nilerr
	}
	return string(pretty) + "\n", nil
}

// configFileExists reports whether daemon.json is on disk and readable.
// Used by the apply path to decide whether a backup is required (no
// file → first-time write, no backup needed).
func (s *Service) configFileExists() bool {
	_, err := os.Stat(s.cfg.ConfigPath)
	return err == nil
}

// ListSnapshots returns available daemon.json snapshots, newest first.
func (s *Service) ListSnapshots(_ context.Context) ([]Snapshot, error) {
	entries, err := os.ReadDir(s.cfg.SnapshotDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read snapshot directory: %w", err)
	}

	snapshots := make([]Snapshot, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasPrefix(e.Name(), snapshotPrefix) || !strings.HasSuffix(e.Name(), snapshotSuffix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		snapshots = append(snapshots, Snapshot{
			ID:        snapshotIDFromName(e.Name()),
			Path:      filepath.Join(s.cfg.SnapshotDir, e.Name()),
			Size:      info.Size(),
			Timestamp: info.ModTime(),
		})
	}

	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Timestamp.After(snapshots[j].Timestamp)
	})

	return snapshots, nil
}

// readSnapshot reads a snapshot by its ID. Returns an error if the ID
// fails the path-traversal guard or if the file is unreadable.
func (s *Service) readSnapshot(id string) ([]byte, error) {
	path, err := s.snapshotPath(id)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) //nolint:gosec // path is constrained by snapshotPath
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	// Validate it is JSON before handing it to the apply path.
	var probe json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("snapshot is not valid JSON: %w", err)
	}
	return data, nil
}

// snapshotPath resolves a snapshot ID to a full path while rejecting
// any input that escapes the snapshot directory. Snapshot IDs follow
// the YYYYMMDD-HHMMSS-<rand6> shape produced by writer.snapshot — every
// character is in [0-9a-f-]; anything else is rejected.
func (s *Service) snapshotPath(id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("invalid snapshot id: empty")
	}
	if filepath.Base(id) != id || strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return "", fmt.Errorf("invalid snapshot id: path component")
	}
	for _, c := range id {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c == '-':
		default:
			return "", fmt.Errorf("invalid snapshot id: bad character %q", c)
		}
	}
	return filepath.Join(s.cfg.SnapshotDir, snapshotPrefix+id+snapshotSuffix), nil
}
