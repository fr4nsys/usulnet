// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
)

// registerWireGuardHandlers registers WireGuard-related command handlers.
//
// The agent shells out to `wg` and `wg-quick` with explicit argv slices
// (no shell strings) and a hard timeout on every invocation. Errors
// from a missing binary surface as a structured CommandError so the
// master can mark the mesh link as failed and stop retrying that node.
func (e *Executor) registerWireGuardHandlers() {
	e.handlers[protocol.CmdWireGuardApplyPeer] = e.handleWireGuardApplyPeer
	e.handlers[protocol.CmdWireGuardRemovePeer] = e.handleWireGuardRemovePeer
	e.handlers[protocol.CmdWireGuardStatus] = e.handleWireGuardStatus
	e.handlers[protocol.CmdWireGuardProbe] = e.handleWireGuardProbe
}

// wgPeerPayload mirrors the agentPeerPayload type on the master side.
type wgPeerPayload struct {
	PublicKey           string `json:"public_key"`
	PresharedKey        string `json:"preshared_key,omitempty"`
	AllowedIPs          string `json:"allowed_ips"`
	Endpoint            string `json:"endpoint,omitempty"`
	PersistentKeepalive int    `json:"persistent_keepalive"`
}

// handleWireGuardApplyPeer applies a peer entry to a local interface.
// The agent calls:
//
//	wg set <iface> peer <pubkey> [preshared-key /dev/stdin] \
//	     allowed-ips <ips> [endpoint <host:port>] [persistent-keepalive <secs>]
//
// The preshared key, if any, is piped on stdin so it never appears in
// argv (process listings).
func (e *Executor) handleWireGuardApplyPeer(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	iface := cmd.Params.WireGuardInterface
	if iface == "" {
		return wireguardFailed("invalid_input", "wireguard_interface is required")
	}
	if err := validateInterfaceName(iface); err != nil {
		return wireguardFailed("invalid_input", err.Error())
	}

	var payload wgPeerPayload
	if err := json.Unmarshal([]byte(cmd.Params.WireGuardPeer), &payload); err != nil {
		return wireguardFailed("invalid_input", fmt.Sprintf("decode peer payload: %v", err))
	}
	if payload.PublicKey == "" {
		return wireguardFailed("invalid_input", "peer public_key is required")
	}
	if err := validateBase64Key(payload.PublicKey); err != nil {
		return wireguardFailed("invalid_input", fmt.Sprintf("peer public_key: %v", err))
	}
	if payload.PresharedKey != "" {
		if err := validateBase64Key(payload.PresharedKey); err != nil {
			return wireguardFailed("invalid_input", fmt.Sprintf("preshared_key: %v", err))
		}
	}
	if err := validateAllowedIPs(payload.AllowedIPs); err != nil {
		return wireguardFailed("invalid_input", err.Error())
	}

	// Build argv. Note: we never expand env vars or use a shell.
	args := []string{"set", iface, "peer", payload.PublicKey}
	pskOnStdin := false
	if payload.PresharedKey != "" {
		args = append(args, "preshared-key", "/dev/stdin")
		pskOnStdin = true
	}
	if payload.AllowedIPs != "" {
		args = append(args, "allowed-ips", payload.AllowedIPs)
	}
	if payload.Endpoint != "" {
		if err := validateEndpoint(payload.Endpoint); err != nil {
			return wireguardFailed("invalid_input", err.Error())
		}
		args = append(args, "endpoint", payload.Endpoint)
	}
	if payload.PersistentKeepalive > 0 {
		args = append(args, "persistent-keepalive", fmt.Sprintf("%d", payload.PersistentKeepalive))
	}

	cctx, cancel := context.WithTimeout(ctx, hardTimeout(cmd, 30*time.Second))
	defer cancel()
	wgCmd := exec.CommandContext(cctx, "wg", args...) // #nosec G204 -- explicit argv, validated above
	if pskOnStdin {
		wgCmd.Stdin = strings.NewReader(payload.PresharedKey + "\n")
	}
	var out, errOut bytes.Buffer
	wgCmd.Stdout = &out
	wgCmd.Stderr = &errOut

	if err := wgCmd.Run(); err != nil {
		return wireguardFailed("wg_failed",
			fmt.Sprintf("wg set: %v: %s", err, strings.TrimSpace(errOut.String())))
	}

	e.log.Info("wireguard: peer applied",
		"interface", iface,
		"public_key", trimKey(payload.PublicKey),
		"allowed_ips", payload.AllowedIPs)

	return &protocol.CommandResult{
		Status: protocol.CommandStatusCompleted,
		Data: map[string]any{
			"interface":  iface,
			"public_key": payload.PublicKey,
			"output":     strings.TrimSpace(out.String()),
		},
	}
}

// handleWireGuardRemovePeer removes a peer entry from a local interface
// (`wg set <iface> peer <pubkey> remove`).
func (e *Executor) handleWireGuardRemovePeer(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	iface := cmd.Params.WireGuardInterface
	if iface == "" {
		return wireguardFailed("invalid_input", "wireguard_interface is required")
	}
	if err := validateInterfaceName(iface); err != nil {
		return wireguardFailed("invalid_input", err.Error())
	}

	pub := strings.TrimSpace(cmd.Params.WireGuardPeer)
	if pub == "" {
		return wireguardFailed("invalid_input", "peer public_key is required")
	}
	if err := validateBase64Key(pub); err != nil {
		return wireguardFailed("invalid_input", fmt.Sprintf("peer public_key: %v", err))
	}

	cctx, cancel := context.WithTimeout(ctx, hardTimeout(cmd, 30*time.Second))
	defer cancel()
	wgCmd := exec.CommandContext(cctx, "wg", "set", iface, "peer", pub, "remove") // #nosec G204 -- explicit argv, validated above
	var out, errOut bytes.Buffer
	wgCmd.Stdout = &out
	wgCmd.Stderr = &errOut

	if err := wgCmd.Run(); err != nil {
		return wireguardFailed("wg_failed",
			fmt.Sprintf("wg remove peer: %v: %s", err, strings.TrimSpace(errOut.String())))
	}

	e.log.Info("wireguard: peer removed",
		"interface", iface,
		"public_key", trimKey(pub))

	return &protocol.CommandResult{
		Status: protocol.CommandStatusCompleted,
		Data: map[string]any{
			"interface":  iface,
			"public_key": pub,
		},
	}
}

// handleWireGuardStatus returns the parsed `wg show <iface> dump` output
// for the master to update last_handshake / transfer stats.
func (e *Executor) handleWireGuardStatus(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	iface := cmd.Params.WireGuardInterface
	if iface != "" {
		if err := validateInterfaceName(iface); err != nil {
			return wireguardFailed("invalid_input", err.Error())
		}
	}

	cctx, cancel := context.WithTimeout(ctx, hardTimeout(cmd, 15*time.Second))
	defer cancel()
	args := []string{"show"}
	if iface != "" {
		args = append(args, iface)
	} else {
		args = append(args, "all")
	}
	args = append(args, "dump")
	wgCmd := exec.CommandContext(cctx, "wg", args...) // #nosec G204 -- explicit argv, validated above
	var out, errOut bytes.Buffer
	wgCmd.Stdout = &out
	wgCmd.Stderr = &errOut

	if err := wgCmd.Run(); err != nil {
		return wireguardFailed("wg_failed",
			fmt.Sprintf("wg show: %v: %s", err, strings.TrimSpace(errOut.String())))
	}
	return &protocol.CommandResult{
		Status: protocol.CommandStatusCompleted,
		Data: map[string]any{
			"interface": iface,
			"output":    out.String(),
		},
	}
}

// handleWireGuardProbe reports whether wg and wg-quick are present on
// this agent (non-fatal — used for diagnostics).
func (e *Executor) handleWireGuardProbe(ctx context.Context, _ *protocol.Command) *protocol.CommandResult {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	wgPath, wgErr := exec.LookPath("wg")
	wgQuickPath, wgqErr := exec.LookPath("wg-quick")

	var version string
	if wgErr == nil {
		if out, err := exec.CommandContext(cctx, "wg", "--version").CombinedOutput(); err == nil { // #nosec G204 -- fixed argv
			version = strings.TrimSpace(string(out))
		}
	}
	return &protocol.CommandResult{
		Status: protocol.CommandStatusCompleted,
		Data: map[string]any{
			"wg_available":       wgErr == nil,
			"wg_quick_available": wgqErr == nil,
			"wg_path":            wgPath,
			"wg_quick_path":      wgQuickPath,
			"wg_version":         version,
		},
	}
}

// ============================================================================
// Validation helpers (defense in depth — the master already validates,
// but the agent is the last line before argv hits the binary).
// ============================================================================

// validateInterfaceName accepts kernel-acceptable wg interface names
// (alnum + dash/underscore, max 15 chars per IFNAMSIZ-1).
func validateInterfaceName(name string) error {
	if name == "" || len(name) > 15 {
		return fmt.Errorf("interface name must be 1..15 chars")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-' || r == '_':
		default:
			return fmt.Errorf("interface name contains invalid character %q", r)
		}
	}
	return nil
}

// validateBase64Key accepts the WireGuard 32-byte base64-encoded key
// shape (44 characters of [A-Za-z0-9+/] ending in '=').
func validateBase64Key(key string) error {
	if len(key) != 44 {
		return fmt.Errorf("base64 key must be 44 chars (got %d)", len(key))
	}
	for i, r := range key {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '+' || r == '/':
		case r == '=' && i >= len(key)-2:
			// padding char
		default:
			return fmt.Errorf("base64 key contains invalid character at position %d", i)
		}
	}
	return nil
}

// validateAllowedIPs accepts the comma-separated CIDR list. We only
// check the characters; `wg` itself parses the CIDRs.
func validateAllowedIPs(ips string) error {
	if ips == "" {
		return nil
	}
	for _, r := range ips {
		switch {
		case r >= '0' && r <= '9',
			r >= 'a' && r <= 'f',
			r >= 'A' && r <= 'F',
			r == '.' || r == ':' || r == '/' || r == ',' || r == ' ':
		default:
			return fmt.Errorf("allowed_ips contains invalid character %q", r)
		}
	}
	return nil
}

// validateEndpoint accepts host:port shape (host can be DNS or IP).
// Defensive only — `wg` resolves the DNS itself.
func validateEndpoint(ep string) error {
	if !strings.Contains(ep, ":") {
		return fmt.Errorf("endpoint must be host:port")
	}
	for _, r := range ep {
		switch {
		case r >= '0' && r <= '9',
			r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r == '.' || r == ':' || r == '-' || r == '[' || r == ']':
		default:
			return fmt.Errorf("endpoint contains invalid character %q", r)
		}
	}
	return nil
}

// hardTimeout returns the timeout from the command if set, otherwise
// the supplied fallback. Ensures every wg invocation has an upper bound.
func hardTimeout(cmd *protocol.Command, fallback time.Duration) time.Duration {
	if cmd.Timeout > 0 {
		return cmd.Timeout
	}
	return fallback
}

// trimKey returns the first 10 chars of a base64 key for log lines so
// the full key never lands in agent logs.
func trimKey(k string) string {
	if len(k) <= 10 {
		return k
	}
	return k[:10] + "…"
}

// wireguardFailed builds a structured failed result for the master.
func wireguardFailed(code, msg string) *protocol.CommandResult {
	return &protocol.CommandResult{
		Status: protocol.CommandStatusFailed,
		Error: &protocol.CommandError{
			Code:    code,
			Message: msg,
		},
	}
}
