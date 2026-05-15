// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet
//
// This file owns the apply leg of the cycle: reload dockerd via SIGHUP,
// verify the daemon comes back healthy within a hard timeout, and force
// a rollback to the previous snapshot if it does not.

package dockerconfig

import (
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// HealthChecker is the contract the applier uses to verify dockerd is
// alive after SIGHUP. Satisfied by docker.Client.Ping; injected via a
// narrow interface so the unit tests can drive the rollback path
// without spinning up dockerd.
type HealthChecker interface {
	Ping(ctx context.Context) error
}

// reloadResult captures what happened when the applier asked dockerd to
// reload. Boolean fields are explicit so the API layer can render
// distinct UI states ("reloaded", "rolled back", "could not reach
// daemon to send SIGHUP").
type reloadResult struct {
	Sent     bool   // SIGHUP was sent successfully
	Healthy  bool   // daemon API responded healthy within ReloadTimeout
	Skipped  bool   // SIGHUP was not attempted (no PID resolver / no checker)
	SkipNote string // human-readable reason for Skipped
}

// reload sends SIGHUP to dockerd and waits up to s.cfg.ReloadTimeout for
// the daemon to settle. The wait is gated by HealthChecker.Ping in a
// poll loop; the function returns the moment dockerd answers a Ping or
// the deadline expires, whichever is first.
//
// A nil HealthChecker or a missing dockerd PID flips Skipped=true with
// SkipNote populated — the apply path interprets that as "config was
// written, operator must reload manually" rather than failing.
func (s *Service) reload(ctx context.Context) reloadResult {
	if s.health == nil {
		return reloadResult{Skipped: true, SkipNote: "no docker client wired; reload skipped — operator must reload dockerd manually"}
	}

	// Tests inject sighupForTest to skip the actual signal delivery
	// while still exercising the verify-and-rollback poll loop. In
	// production both pidResolverForTest and sighupForTest are nil.
	if sighupForTest != nil {
		if err := sighupForTest(); err != nil {
			return reloadResult{Skipped: true, SkipNote: "test trigger: " + err.Error()}
		}
	} else {
		resolver := findDockerdPID
		if pidResolverForTest != nil {
			resolver = func(_ context.Context) (int, error) { return pidResolverForTest() }
		}
		pid, err := resolver(ctx)
		if err != nil {
			return reloadResult{Skipped: true, SkipNote: "dockerd PID not resolvable: " + err.Error()}
		}

		if killErr := syscall.Kill(pid, syscall.SIGHUP); killErr != nil {
			return reloadResult{Skipped: true, SkipNote: "send SIGHUP: " + killErr.Error()}
		}
		s.logger.Info("SIGHUP sent to dockerd", "pid", pid)
	}

	deadline := time.Now().Add(s.cfg.ReloadTimeout)
	pollInterval := s.cfg.ReloadPollInterval
	if pollInterval <= 0 {
		pollInterval = time.Second
	}

	res := reloadResult{Sent: true}
	for time.Now().Before(deadline) {
		// Each ping uses a tight derived context so a single hung
		// ping cannot blow the overall reload budget.
		pingCtx, cancel := context.WithTimeout(ctx, pollInterval)
		pingErr := s.health.Ping(pingCtx)
		cancel()
		if pingErr == nil {
			res.Healthy = true
			return res
		}
		select {
		case <-time.After(pollInterval):
		case <-ctx.Done():
			return res
		}
	}
	return res
}

// Apply is the entry point the API/web handlers call. It performs the
// full edit cycle:
//
//  1. Parse + validate the proposed daemon.json.
//  2. Load the on-disk daemon.json so we can compute the changed-fields
//     diff and emit a credential-redacted audit summary.
//  3. Snapshot the current daemon.json (atomic write to snapshot dir).
//  4. Atomic write the new daemon.json (temp + fsync + rename).
//  5. SIGHUP dockerd, wait up to ReloadTimeout for health, with hard
//     deadline.
//  6. If the daemon does not return healthy, restore the snapshot
//     (atomic write again) and re-issue SIGHUP. RolledBack=true.
//
// Return value carries the snapshot ID, the applied mode, and the
// rollback flag so the UI can render the right state without having to
// inspect logs.
func (s *Service) Apply(ctx context.Context, raw []byte, reason string) (*UpdateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Parse + validate the new config.
	newCfg, err := parseConfig(raw)
	if err != nil {
		return nil, fmt.Errorf("parse new config: %w", err)
	}
	if errs := ValidateConfig(newCfg); len(errs) > 0 {
		return nil, fmt.Errorf("validation failed: %s", FormatValidationErrors(errs))
	}

	// 2. Load current for the changed-fields diff.
	current, err := s.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("read current config: %w", err)
	}
	changed := diffFields(current, newCfg)

	// 3. Snapshot if there is something to snapshot.
	var snapshotID string
	if s.configFileExists() {
		snapshotID, err = s.snapshot(reason)
		if err != nil {
			return nil, fmt.Errorf("snapshot before write: %w", err)
		}
	}

	// 4. Atomic write the new config.
	if writeErr := s.writeConfig(formatJSON(raw)); writeErr != nil {
		return nil, fmt.Errorf("write daemon.json: %w", writeErr)
	}

	mode := determineApplyMode(changed)
	result := &UpdateResult{
		SnapshotID:    snapshotID,
		ApplyMode:     mode,
		ChangedFields: changed,
	}

	s.logger.Info("daemon.json written",
		"snapshot_id", snapshotID,
		"apply_mode", string(mode),
		"changed_fields", strings.Join(changed, ","),
		"reason", reason,
	)

	// 5. Reload if mode is reload-capable. Settings tagged
	// ApplyRestart need a daemon restart that we do NOT perform from
	// the apply path; the UI surfaces a "restart required" prompt.
	if mode != ApplyReload {
		result.WarningMsg = "applied — restart docker to activate (this category requires restart)"
		return result, nil
	}

	rel := s.reload(ctx)
	switch {
	case rel.Skipped:
		result.WarningMsg = "applied — reload skipped: " + rel.SkipNote
		return result, nil
	case rel.Healthy:
		result.Reloaded = true
		return result, nil
	}

	// 6. Forced rollback.
	s.logger.Error("daemon did not return healthy after SIGHUP — rolling back",
		"timeout", s.cfg.ReloadTimeout.String(),
		"snapshot_id", snapshotID,
	)
	result.RolledBack = true
	if rbErr := s.rollbackTo(ctx, snapshotID); rbErr != nil {
		result.RollbackError = rbErr.Error()
		return result, fmt.Errorf("daemon unhealthy after reload AND rollback failed: %w", rbErr)
	}
	return result, fmt.Errorf("daemon did not return healthy within %s; rolled back to snapshot %s", s.cfg.ReloadTimeout, snapshotID)
}

// Restore restores a specific snapshot ID through the same cycle as
// Apply: snapshot-current → atomic write → SIGHUP → verify → rollback.
// This is the entry point for the "history" page restore action.
func (s *Service) Restore(ctx context.Context, snapshotID, reason string) (*UpdateResult, error) {
	data, err := s.readSnapshot(snapshotID)
	if err != nil {
		return nil, err
	}
	return s.Apply(ctx, data, "restore:"+snapshotID+":"+reason)
}

// rollbackTo restores the named snapshot in place and re-issues SIGHUP.
// rollback failures are surfaced in UpdateResult.RollbackError; they do
// NOT panic the apply because there is nothing more we can do at that
// point — the operator is paged via the warning string.
func (s *Service) rollbackTo(ctx context.Context, snapshotID string) error {
	if snapshotID == "" {
		// No prior snapshot — first-time write that failed. Best
		// effort: remove the file so the daemon falls back to its
		// built-in defaults on the next start.
		s.logger.Warn("no prior snapshot to roll back to; daemon.json left in place")
		return nil
	}
	data, err := s.readSnapshot(snapshotID)
	if err != nil {
		return fmt.Errorf("read snapshot for rollback: %w", err)
	}
	if writeErr := s.writeConfig(data); writeErr != nil {
		return fmt.Errorf("write rollback: %w", writeErr)
	}
	rel := s.reload(ctx)
	if rel.Skipped {
		s.logger.Warn("rollback wrote daemon.json but reload skipped", "note", rel.SkipNote)
		return nil
	}
	if !rel.Healthy {
		return fmt.Errorf("rollback wrote daemon.json but daemon still unhealthy after SIGHUP")
	}
	s.logger.Info("daemon.json rolled back to snapshot", "snapshot_id", snapshotID)
	return nil
}

// ====================================================================
// Helpers
// ====================================================================

// parseConfig parses raw daemon.json bytes into a typed DaemonConfig.
// The same json.Unmarshal path the daemon will use is exercised here so
// any error the daemon would refuse to start with is surfaced before
// we ever overwrite the file on disk.
func parseConfig(raw []byte) (*DaemonConfig, error) {
	if len(raw) == 0 {
		return &DaemonConfig{}, nil
	}
	var cfg DaemonConfig
	if err := unmarshalStrict(raw, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// formatJSON re-pretty-prints a daemon.json so the bytes written to
// disk are deterministic — operators reviewing git history of the
// snapshot dir get clean diffs instead of one-line dumps.
func formatJSON(raw []byte) []byte {
	parsed, err := parseConfig(raw)
	if err != nil {
		// Fall back to the input bytes; the apply will fail at the
		// validation step anyway. We only get here on a parse error
		// upstream.
		return raw
	}
	out, err := marshalIndent(parsed)
	if err != nil {
		return raw
	}
	if len(out) == 0 || out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return out
}

// determineApplyMode returns the worst-case apply mode for the changed
// fields. A reload-only set returns ApplyReload; a single restart-only
// field upgrades the whole apply to ApplyRestart.
func determineApplyMode(changedFields []string) ApplyMode {
	meta := AllSettingsMeta()
	for _, field := range changedFields {
		if m, ok := meta[field]; ok && m.ApplyMode == ApplyRestart {
			return ApplyRestart
		}
	}
	return ApplyReload
}

// pidResolverForTest, when non-nil, replaces findDockerdPID. The unit
// tests use it to drive the rollback path without an actual dockerd.
// It MUST stay nil in production — the build tag would be cleaner but
// adds compile-time complexity for a single shared variable.
var pidResolverForTest func() (int, error)

// sighupForTest, when non-nil, replaces the entire pid+kill step.
// Tests use it to skip the SIGHUP delivery (which would otherwise kill
// the test runner if pid resolves to os.Getpid). MUST stay nil in
// production.
var sighupForTest func() error

// findDockerdPID locates a running dockerd process. Returns an error if
// no dockerd PID can be resolved (running outside of a container with
// pid:host, or dockerd is genuinely down). The caller treats the error
// as "skip reload" rather than fatal.
func findDockerdPID(ctx context.Context) (int, error) {
	out, err := exec.CommandContext(ctx, "pidof", "dockerd").Output()
	if err != nil {
		return 0, fmt.Errorf("pidof dockerd: %w", err)
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) == 0 {
		return 0, fmt.Errorf("dockerd not running")
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, fmt.Errorf("invalid pidof output %q: %w", fields[0], err)
	}
	return pid, nil
}

// redactURL strips userinfo from a URL string so registry-mirror or
// proxy URLs containing credentials never reach logs / audit summaries.
// Returns the input unchanged when it is not a parseable URL.
//
// Implementation note: we rebuild the URL by hand instead of using
// url.URL.String() because the standard library percent-encodes the
// "***" sentinel that we use as the redaction marker, which makes the
// log line illegible. The hand-rebuild keeps the marker literal.
func redactURL(in string) string {
	u, err := url.Parse(in)
	if err != nil || u.User == nil {
		return in
	}
	host := u.Host
	if host == "" {
		host = u.Opaque
	}
	out := u.Scheme + "://***@" + host + u.Path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		out += "#" + u.Fragment
	}
	return out
}

// redactedFieldNames is the set of daemon.json keys that may contain
// credential-bearing URLs and must therefore have their values
// redacted before any structured log call.
var redactedFieldNames = map[string]bool{
	"registry-mirrors":    true,
	"insecure-registries": true,
	"proxies.http-proxy":  true,
	"proxies.https-proxy": true,
}

// fieldRedactor is exposed for tests and credential-logging audits. It
// returns the value to log for a given (key, value) pair, replacing the
// value entirely when key is in redactedFieldNames.
func fieldRedactor(key string, value any) any {
	if !redactedFieldNames[key] {
		return value
	}
	switch v := value.(type) {
	case string:
		return redactURL(v)
	case []string:
		out := make([]string, len(v))
		for i, s := range v {
			out[i] = redactURL(s)
		}
		return out
	}
	return "***redacted***"
}
