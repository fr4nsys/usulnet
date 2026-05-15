// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package sandbox launches recon engine and toolkit containers under
// the hardened defaults the recon module requires.
//
// The hardening baseline mirrors docs/v26.5/technical-notes.md
// "Sandbox defaults" verbatim: read-only root filesystem, dropped
// capabilities, non-root UID, no new privileges, default seccomp,
// pids/memory/cpu limits, and a dedicated egress-controlled network.
// Callers cannot widen these defaults via the public API; if a use
// case genuinely needs an exception it must land via an RFC update to
// docs/recon.md first.
package sandbox

import (
	"time"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// Hardening constants.  Changing any of these is an RFC-level decision.
const (
	// SandboxUser is the in-container UID/GID the launcher always uses.
	SandboxUser = "65534:65534"

	// DefaultMemoryBytes caps each sandbox container's memory.
	DefaultMemoryBytes int64 = 512 * 1024 * 1024 // 512 MiB

	// DefaultNanoCPUs caps each sandbox container's CPU usage to 1.0 CPU.
	DefaultNanoCPUs int64 = 1_000_000_000

	// DefaultPidsLimit caps the in-container PID count.
	DefaultPidsLimit int64 = 256

	// DefaultTmpfsTarget is the standard tmpfs mount path required by
	// every recon container: the rest of the FS is read-only.
	DefaultTmpfsTarget = "/tmp"

	// DefaultTmpfsOptions wires the technical-notes spec:
	// size=128m,exec (exec is required by the toolkit image since
	// mat2 writes a cleaned copy to /tmp and re-execs).
	DefaultTmpfsOptions = "size=128m,exec"

	// WorkOutTmpfsTarget is a second tmpfs mount the metadata stripper
	// uses as the destination for cleaned files; the launcher copies
	// the result back to the host via ContainerCopyFileStream before
	// removing the container.  Keeping it separate from /tmp lets
	// callers reason about output paths without ambiguity and lets the
	// stripper enforce a smaller cap on artifact size.
	WorkOutTmpfsTarget = "/work/out"

	// WorkOutTmpfsOptions sizes the artifact tmpfs.  noexec is
	// purposeful: nothing in /work/out should ever be executed; mat2
	// writes its cleaned copy and exits.
	WorkOutTmpfsOptions = "size=64m,noexec"

	// DefaultTimeout is used when ContainerSpec.Timeout is zero.
	DefaultTimeout = 15 * time.Minute

	// LabelModule marks every recon-owned container/network.
	LabelModule = "usulnet.module"

	// LabelModuleValue is the fixed value of LabelModule.
	LabelModuleValue = "recon"

	// LabelSpecHash is a derived identity label used by EnsureRunning
	// to recognize an already-running container that matches a spec.
	LabelSpecHash = "usulnet.recon.spec_hash"
)

// requiredCapDrops is the set of Linux capabilities the launcher
// always drops.  "ALL" is the only entry: docker translates it to a
// cap_drop=ALL on the container.  Anything the engine truly needs
// must be added back via CapAdd in a follow-up RFC, never silently.
var requiredCapDrops = []string{"ALL"}

// requiredSecurityOpts is the list of --security-opt flags the
// launcher always passes.  no-new-privileges blocks setuid escalation
// inside the container; seccomp=default keeps Docker's default
// syscall filter explicitly on (some daemon configurations disable
// it by default).
var requiredSecurityOpts = []string{
	"no-new-privileges:true",
	"seccomp=default",
}

// hardenSpec converts the public ContainerSpec into the docker
// create-options the launcher will hand to the docker client.  Every
// hardening flag is set here, in one place, so it is auditable in a
// single grep.
//
// The function purposely ignores any sandbox-related field the caller
// might have set (NoNetwork, etc.) when doing so would weaken the
// baseline.  Mounts the caller did pass are forced to ReadOnly=true
// regardless of what the caller set, matching the "always read-only"
// rule in technical-notes.md.
func hardenSpec(spec recon.ContainerSpec, networkName string) docker.ContainerCreateOptions {
	labels := map[string]string{LabelModule: LabelModuleValue}
	for k, v := range spec.Labels {
		labels[k] = v
	}

	// Always include the canonical module label even if the caller
	// passed a competing value.
	labels[LabelModule] = LabelModuleValue

	env := envFromMap(spec.Env)

	binds := make([]string, 0, len(spec.Mounts))
	for _, m := range spec.Mounts {
		// :ro is mandatory; we never honor ReadOnly=false from the
		// caller.  bind syntax: <host>:<container>:ro
		binds = append(binds, m.Source+":"+m.Target+":ro")
	}

	netMode := networkName
	if spec.NoNetwork {
		netMode = "none"
	}

	return docker.ContainerCreateOptions{
		Image:          spec.Image,
		Cmd:            spec.Command,
		Env:            env,
		Labels:         labels,
		Binds:          binds,
		NetworkMode:    netMode,
		User:           SandboxUser,
		Privileged:     false,
		CapDrop:        append([]string(nil), requiredCapDrops...),
		ReadonlyRootfs: true,
		SecurityOpt:    append([]string(nil), requiredSecurityOpts...),
		Tmpfs: map[string]string{
			DefaultTmpfsTarget: DefaultTmpfsOptions,
			WorkOutTmpfsTarget: WorkOutTmpfsOptions,
		},
		PidsLimit:  DefaultPidsLimit,
		Memory:     DefaultMemoryBytes,
		MemorySwap: DefaultMemoryBytes, // disable swap usage
		NanoCPUs:   DefaultNanoCPUs,
		AutoRemove: false, // RunOnce removes explicitly; long-lived containers persist
	}
}

// envFromMap renders a key/value map as the slice format docker expects.
// The order is the natural map iteration order, which is non-deterministic;
// callers that need reproducible output should sort before invocation.
func envFromMap(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	return out
}

// timeoutOrDefault picks the spec timeout, falling back to
// DefaultTimeout, and never returning zero or negative.
func timeoutOrDefault(spec recon.ContainerSpec) time.Duration {
	if spec.Timeout > 0 {
		return spec.Timeout
	}
	return DefaultTimeout
}
