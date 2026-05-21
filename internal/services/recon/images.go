// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package recon — container image pins.
//
// These constants are the single source of truth for which exact image
// the sandbox launcher pulls. They are bumped by CI:
//
//   - SpiderFootImageDigest    — by .github/workflows/build-recon-images.yml
//     on every push to main that touches deploy/recon/spiderfoot/.
//   - ToolkitImageDigest       — by .github/workflows/recon-toolkit-weekly.yml
//     on the weekly cron and on every push to main that touches
//     images/recon-toolkit/. The toolkit Dockerfile bases on
//     archlinux:latest + BlackArch overlay (amd64-only) and replaces
//     the prior Debian-slim image at deploy/recon/toolkit/.
//
// Each workflow opens a PR via peter-evans/create-pull-request that
// rewrites the matching digest in this file.
//
// Placeholder digests are checked in until the first CI run replaces
// them. Callers that need to pull the images locally can rely on the
// floating :latest tag or build the Dockerfile under images/recon-toolkit/
// directly.

package recon

// Image registry coordinates.  The repository part is fixed; tags and
// digests evolve.
const (
	// ImageRegistry is the canonical registry path for the recon
	// images.  Mirrored copies (Docker Hub, internal registries) are
	// supported via the operator-configured `recon.spiderfoot.image`
	// and `recon.toolkit.image` config keys, which override these
	// defaults when set.
	ImageRegistry = "ghcr.io/fr4nsys"

	// SpiderFootImageRepo holds the SpiderFoot OSINT engine.
	SpiderFootImageRepo = ImageRegistry + "/usulnet-recon-spiderfoot"

	// ToolkitImageRepo holds the metadata + atomic OSINT toolkit.
	ToolkitImageRepo = ImageRegistry + "/usulnet-recon-toolkit"
)

// SpiderFootImageDigest pins the SpiderFoot image to a content-addressable
// sha256.  CI rewrites this on each successful publish to main.
const SpiderFootImageDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// ToolkitImageDigest pins the toolkit image to a content-addressable
// sha256.  CI rewrites this on each successful publish to main.
const ToolkitImageDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// SpiderFootImage is the fully-qualified pull reference used by the
// sandbox launcher when the operator has not overridden it via config.
func SpiderFootImage() string {
	return SpiderFootImageRepo + "@" + SpiderFootImageDigest
}

// ToolkitImage is the fully-qualified pull reference used by the
// sandbox launcher when the operator has not overridden it via config.
func ToolkitImage() string {
	return ToolkitImageRepo + "@" + ToolkitImageDigest
}
