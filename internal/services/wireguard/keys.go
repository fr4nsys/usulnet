// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// generateKeyPair generates a real WireGuard Curve25519 key pair (base64-encoded).
//
// v26.2.7 derived a "placeholder public key" by XOR-ing the private
// key, which would not interoperate with any real WireGuard client.
// v26.5.1 uses curve25519.X25519 to compute the correct public key
// from the clamped scalar — exactly what `wg pubkey` does.
func generateKeyPair() (privateKey, publicKey string, err error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return "", "", fmt.Errorf("random bytes: %w", err)
	}
	// Clamp per Curve25519 spec (RFC 7748 § 5).
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("derive public key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(priv),
		base64.StdEncoding.EncodeToString(pub), nil
}

// generatePresharedKey generates a random 256-bit preshared key (base64-encoded).
func generatePresharedKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("random bytes: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
