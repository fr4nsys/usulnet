// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package recon

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// HashValue returns the SHA-256 digest of the canonical form of value
// (lowercased and trimmed of surrounding whitespace). The digest is stored
// alongside identifiers in recon_targets / recon_findings so PII does not
// leak through pg_stat or index dumps.
func HashValue(value string) []byte {
	sum := sha256.Sum256([]byte(NormalizeValue(value)))
	return sum[:]
}

// NormalizeValue returns the canonical form used by HashValue: the value
// trimmed of surrounding whitespace and lowercased. It is exported so
// callers persisting the raw value can store the same canonical form.
func NormalizeValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// HexPrefix returns the first n hex characters of hash. It is intended for
// logging: full hashes are noisy and a short prefix is enough to correlate
// log lines without exposing the full digest. Returns an empty string when
// hash is empty; clamps n to the available length.
func HexPrefix(hash []byte, n int) string {
	if len(hash) == 0 || n <= 0 {
		return ""
	}
	encoded := hex.EncodeToString(hash)
	if n > len(encoded) {
		n = len(encoded)
	}
	return encoded[:n]
}
