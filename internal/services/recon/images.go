// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package recon — container image pins.
//
// These constants are the single source of truth for which exact image
// the sandbox launcher pulls.  They are bumped by CI when
// .github/workflows/build-recon-images.yml publishes a new build to
// GHCR; the workflow opens a PR via peter-evans/create-pull-request
// that updates this file in lockstep with the registry tag.
//
// Placeholder digests are checked in for the initial PR; the first CI
// run on main will replace them with real ones.  Until then, callers
// that need to pull the images locally should rely on the floating
// :dev tag produced by `make docker-build-recon`.

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
