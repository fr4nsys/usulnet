// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package sandbox

import (
	"context"
	"errors"
	"fmt"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/observability"
)

// DefaultNetworkName is the default value for Config.NetworkName.
const DefaultNetworkName = "usulnet-recon"

// DefaultNetworkSubnet is the /24 the recon module pins its bridge to
// when creating the network from scratch.  Operators can override via
// Config.NetworkSubnet if it clashes with an existing subnet.
const DefaultNetworkSubnet = "172.31.42.0/24"

// ensureNetwork creates the recon network if it does not already
// exist, returning its name (callers reference the network by name
// because that is what container HostConfig.NetworkMode wants).
//
// The egress policy described in docs/v26.5/technical-notes.md
// "Container egress" requires iptables rule programming on the host.
// The existing codebase does not ship any iptables shell-out helper,
// and the session brief explicitly forbids inventing a new
// shell-out pattern, so we ONLY create the bridge network here and
// leave the strict egress allow/deny ruleset to a follow-up session
// once the launcher integrates with whichever host-firewall service
// gets introduced.  The bridge is configured with
// `com.docker.network.bridge.enable_icc=false` so containers inside
// the network cannot talk to each other laterally, which gives us
// the lateral-movement guarantee even without iptables.
func (l *Launcher) ensureNetwork(ctx context.Context) (string, error) {
	ctx, span := observability.StartSpan(ctx, "recon.sandbox.ensureNetwork")
	defer span.End()

	name := l.cfg.NetworkName
	log := l.log.With("network", name)

	existing, err := l.client.NetworkGetByName(ctx, name)
	if err == nil && existing != nil {
		log.Debug("recon network already exists", "id", existing.ID)
		return name, nil
	}

	// The docker client returns a typed not-found error for missing
	// networks; anything else is fatal here.  Treat the negative-lookup
	// case as the trigger to create.
	if err != nil && !isNotFound(err) {
		return "", fmt.Errorf("recon sandbox: inspect network: %w", err)
	}

	createOpts := docker.NetworkCreateOptions{
		Name:     name,
		Driver:   "bridge",
		Internal: false, // egress to public Internet is required (HTTP/HTTPS)
		Labels: map[string]string{
			LabelModule: LabelModuleValue,
		},
		Options: map[string]string{
			// Disable inter-container connectivity inside the recon
			// network so engines cannot pivot between sibling jobs.
			"com.docker.network.bridge.enable_icc": "false",
		},
		IPAM: &docker.IPAMConfig{
			Driver: "default",
			Config: []docker.IPAMPoolConfig{
				{Subnet: l.cfg.NetworkSubnet},
			},
		},
	}

	if _, err := l.client.NetworkCreate(ctx, createOpts); err != nil {
		return "", fmt.Errorf("recon sandbox: create network: %w", err)
	}

	if len(l.cfg.EgressAllowlist) > 0 {
		log.Warn(
			"recon sandbox: EgressAllowlist set but no iptables backend wired",
			"allowlist", l.cfg.EgressAllowlist,
		)
	}

	log.Info("recon sandbox: network created", "subnet", l.cfg.NetworkSubnet)
	return name, nil
}

// isNotFound reports whether err is a docker "not found" sentinel.
// The internal/docker package wraps such errors in its own error type;
// we look at the error string as a fallback so we stay decoupled from
// the concrete sentinel type.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	// Match the typed sentinel string used by internal/pkg/errors with
	// CodeNetworkNotFound.  Falling back to substring matching keeps
	// the sandbox package independent of that error package's import.
	msg := err.Error()
	for _, needle := range []string{"network not found", "not found", "No such"} {
		if contains(msg, needle) {
			return true
		}
	}
	return errors.Is(err, errNetworkNotFound)
}

// errNetworkNotFound is exposed only for tests that want to inject a
// typed not-found error through their fake docker client.
var errNetworkNotFound = errors.New("network not found")

// contains is a tiny stdlib-free substring check; the network module
// stays import-light to avoid pulling extra packages into the test
// build's reachability graph.
func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
