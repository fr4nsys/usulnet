// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

//go:build e2e

package smoke

import (
	"crypto/rand"
	"io"
)

// randSource returns crypto/rand.Reader. Wrapped in a function so the
// smoke test can swap it in unit tests if ever needed; today there
// is no such test, but keeping the seam is cheap.
func randSource() io.Reader {
	return rand.Reader
}
