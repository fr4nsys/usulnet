// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package recon

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestNormalizeValue(t *testing.T) {
	cases := map[string]string{
		"  Alice@Example.COM  ":  "alice@example.com",
		"Domain.TEST":            "domain.test",
		"":                       "",
		"\tspaced\n":             "spaced",
		"already-canonical@x.io": "already-canonical@x.io",
	}
	for in, want := range cases {
		if got := NormalizeValue(in); got != want {
			t.Errorf("NormalizeValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHashValue_MatchesSHA256OfCanonical(t *testing.T) {
	input := "  Alice@Example.COM  "
	want := sha256.Sum256([]byte("alice@example.com"))
	got := HashValue(input)
	if !bytes.Equal(got, want[:]) {
		t.Errorf("HashValue digest mismatch")
	}
	if len(got) != 32 {
		t.Errorf("digest length = %d, want 32", len(got))
	}
}

func TestHashValue_DeterministicAndCaseInsensitive(t *testing.T) {
	a := HashValue("alice@example.com")
	b := HashValue("ALICE@example.com")
	c := HashValue(" alice@example.com\n")
	if !bytes.Equal(a, b) || !bytes.Equal(a, c) {
		t.Errorf("hashes should match across case and surrounding whitespace")
	}
}

func TestHexPrefix(t *testing.T) {
	h := HashValue("alice@example.com")
	cases := []struct {
		n    int
		want int
	}{
		{0, 0},
		{-3, 0},
		{8, 8},
		{200, 64}, // sha256 is 32 bytes = 64 hex chars
	}
	for _, c := range cases {
		got := HexPrefix(h, c.n)
		if len(got) != c.want {
			t.Errorf("HexPrefix(_, %d) len = %d, want %d", c.n, len(got), c.want)
		}
	}
	if HexPrefix(nil, 8) != "" {
		t.Errorf("HexPrefix(nil) should be empty")
	}
}
