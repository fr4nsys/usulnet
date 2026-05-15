// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet
//
// This file owns the bytes-on-disk side of the apply cycle. It is
// deliberately decoupled from applier.go (reload + rollback) and
// reader.go (read + snapshot listing) so each leg of the cycle can be
// unit-tested in isolation.

package dockerconfig

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Snapshot file naming.
//
// Files live as <snapshotPrefix><id><snapshotSuffix>; the snapshot ID
// surfaced to the API and UI is the middle <id> portion. The ID format
// is YYYYMMDD-HHMMSS-<rand6> — sortable lexicographically, unique under
// concurrent applies, and trivial to reject in snapshotPath.
const (
	snapshotPrefix = "daemon-"
	snapshotSuffix = ".json"
)

// snapshotIDFromName extracts the ID from a snapshot file name. Returns
// the empty string when the name does not match the expected shape.
func snapshotIDFromName(name string) string {
	if !strings.HasPrefix(name, snapshotPrefix) || !strings.HasSuffix(name, snapshotSuffix) {
		return ""
	}
	return name[len(snapshotPrefix) : len(name)-len(snapshotSuffix)]
}

// newSnapshotID returns a fresh sortable snapshot ID. The 6-byte random
// suffix prevents two applies in the same wall-clock second from
// colliding and stops an attacker who can race the timestamp from
// guessing the next ID.
func newSnapshotID(now time.Time) string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand should never fail outside of catastrophic system
		// failure; degrade by returning a non-random fallback rather
		// than panicking the apply.
		return now.UTC().Format("20060102-150405") + "-000000"
	}
	return now.UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b[:])
}

// writeAtomic writes data to dst atomically.
//
// Sequence: write to dst.tmp.<random> in the same directory → fsync the
// file → rename(2) onto dst → fsync the parent directory. The rename is
// the moment of "commit"; everything before it can fail without
// corrupting the existing dst. v26.2.7 used os.WriteFile (open + write
// + close), which leaves a half-written daemon.json on disk if the
// process is killed mid-write — and a half-written daemon.json hangs
// dockerd on next start.
//
// dst's directory is created with 0o755 on demand; the file is written
// 0o644 to match Docker's expectations.
func writeAtomic(dst string, data []byte) (err error) {
	dir := filepath.Dir(dst)
	if mkdirErr := os.MkdirAll(dir, 0o755); mkdirErr != nil {
		return fmt.Errorf("create directory %s: %w", dir, mkdirErr)
	}

	// Random suffix so two concurrent writers in the same dir cannot
	// collide on the temp file and so a stale temp file from a prior
	// crash does not get overwritten before the operator notices.
	var rnd [6]byte
	if _, randErr := rand.Read(rnd[:]); randErr != nil {
		return fmt.Errorf("generate temp suffix: %w", randErr)
	}
	tmpPath := dst + ".tmp." + hex.EncodeToString(rnd[:])

	// Open exclusively so that we never adopt an existing temp file.
	tmp, openErr := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644) //nolint:gosec // 0o644 matches dockerd expectations
	if openErr != nil {
		return fmt.Errorf("create temp file: %w", openErr)
	}

	// Single named-return cleanup path. If we leave with an error and
	// the temp file is still on disk, remove it so the snapshot dir
	// does not accumulate junk after each failed apply.
	defer func() {
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, writeErr := tmp.Write(data); writeErr != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", writeErr)
	}
	if syncErr := tmp.Sync(); syncErr != nil {
		tmp.Close()
		return fmt.Errorf("fsync temp file: %w", syncErr)
	}
	if closeErr := tmp.Close(); closeErr != nil {
		return fmt.Errorf("close temp file: %w", closeErr)
	}

	if renameErr := os.Rename(tmpPath, dst); renameErr != nil {
		return fmt.Errorf("rename temp file onto %s: %w", dst, renameErr)
	}

	// fsync the parent directory so the rename survives a power loss.
	// Errors here are non-fatal on filesystems that do not support
	// directory fsync — the rename is already on disk on the kernels
	// usulnet supports — but log so an operator on an exotic FS can
	// see the warning.
	if dirFile, dirErr := os.Open(dir); dirErr == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}

	return nil
}

// snapshot writes a timestamped, atomic point-in-time copy of the
// current daemon.json into the snapshot directory and returns the
// snapshot ID. Returns ("", nil) when the daemon.json is missing — a
// first-time write has nothing to snapshot, which is not an error.
//
// The snapshot file is content-equal to daemon.json at the instant
// snapshot() runs; the rotation step at the end prunes oldest snapshots
// when the count exceeds Config.MaxSnapshots.
func (s *Service) snapshot(reason string) (string, error) {
	data, err := os.ReadFile(s.cfg.ConfigPath) //nolint:gosec // configurable operator path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("read daemon.json for snapshot: %w", err)
	}

	if mkdirErr := os.MkdirAll(s.cfg.SnapshotDir, 0o755); mkdirErr != nil {
		return "", fmt.Errorf("create snapshot directory: %w", mkdirErr)
	}

	id := newSnapshotID(time.Now())
	dst := filepath.Join(s.cfg.SnapshotDir, snapshotPrefix+id+snapshotSuffix)
	if writeErr := writeAtomic(dst, data); writeErr != nil {
		return "", fmt.Errorf("write snapshot: %w", writeErr)
	}

	if pruneErr := s.pruneSnapshots(); pruneErr != nil {
		// Pruning failure should not abort an apply — we log and
		// continue. The snapshot itself is on disk.
		s.logger.Warn("snapshot pruning failed", "error", pruneErr)
	}

	s.logger.Info("daemon.json snapshot created",
		"snapshot_id", id,
		"reason", reason,
	)
	return id, nil
}

// pruneSnapshots keeps at most cfg.MaxSnapshots snapshots, removing the
// oldest first. Snapshots are listed by Read; on a freshly-mounted
// filesystem with no snapshots yet there is nothing to do.
func (s *Service) pruneSnapshots() error {
	if s.cfg.MaxSnapshots <= 0 {
		return nil
	}
	entries, err := os.ReadDir(s.cfg.SnapshotDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	// Filter to snapshot files and stat each one to get mtime.
	type snap struct {
		name string
		mod  time.Time
	}
	snaps := make([]snap, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), snapshotPrefix) || !strings.HasSuffix(e.Name(), snapshotSuffix) {
			continue
		}
		info, infoErr := e.Info()
		if infoErr != nil {
			continue
		}
		snaps = append(snaps, snap{name: e.Name(), mod: info.ModTime()})
	}
	if len(snaps) <= s.cfg.MaxSnapshots {
		return nil
	}

	// Newest first.
	for i := 0; i < len(snaps); i++ {
		for j := i + 1; j < len(snaps); j++ {
			if snaps[j].mod.After(snaps[i].mod) {
				snaps[i], snaps[j] = snaps[j], snaps[i]
			}
		}
	}
	for _, e := range snaps[s.cfg.MaxSnapshots:] {
		_ = os.Remove(filepath.Join(s.cfg.SnapshotDir, e.name))
	}
	return nil
}

// writeConfig writes data to daemon.json atomically. Wrapper that
// names the call sites in the apply path; identical semantics to
// writeAtomic but bound to the configured ConfigPath.
func (s *Service) writeConfig(data []byte) error {
	return writeAtomic(s.cfg.ConfigPath, data)
}
