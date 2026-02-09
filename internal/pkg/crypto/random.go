// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"math/big"
)

// RandomBytes generates cryptographically secure random bytes
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// RandomHex generates a random hex-encoded string of n bytes
func RandomHex(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RandomBase64 generates a random URL-safe base64-encoded string of n bytes
func RandomBase64(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// RandomBase64Raw generates a random standard base64-encoded string of n bytes
func RandomBase64Raw(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// GenerateAPIKey generates a random API key (32 bytes hex = 64 chars)
func GenerateAPIKey() (string, error) {
	return RandomHex(32)
}

// GenerateToken generates a random token (32 bytes URL-safe base64)
func GenerateToken() (string, error) {
	return RandomBase64(32)
}

// GenerateRefreshToken generates a random refresh token (48 bytes URL-safe base64)
func GenerateRefreshToken() (string, error) {
	return RandomBase64(48)
}

// GenerateSecret generates a random secret (32 bytes for JWT secrets, etc.)
func GenerateSecret() (string, error) {
	return RandomBase64(32)
}

// GenerateAgentToken generates a random agent registration token
func GenerateAgentToken() (string, error) {
	return RandomHex(32)
}

// GenerateNonce generates a random nonce for cryptographic operations
func GenerateNonce(size int) ([]byte, error) {
	return RandomBytes(size)
}

// RandomInt generates a cryptographically secure random integer in [0, max)
func RandomInt(max int64) (int64, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0, err
	}
	return n.Int64(), nil
}

// RandomIntRange generates a random integer in [min, max]
func RandomIntRange(min, max int64) (int64, error) {
	if min > max {
		min, max = max, min
	}
	n, err := RandomInt(max - min + 1)
	if err != nil {
		return 0, err
	}
	return min + n, nil
}

// RandomString generates a random string of specified length using the given charset
func RandomString(length int, charset string) (string, error) {
	if len(charset) == 0 {
		charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	}

	result := make([]byte, length)
	for i := 0; i < length; i++ {
		idx, err := RandomInt(int64(len(charset)))
		if err != nil {
			return "", err
		}
		result[i] = charset[idx]
	}
	return string(result), nil
}

// RandomAlphanumeric generates a random alphanumeric string
func RandomAlphanumeric(length int) (string, error) {
	return RandomString(length, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
}

// RandomNumeric generates a random numeric string
func RandomNumeric(length int) (string, error) {
	return RandomString(length, "0123456789")
}

// MustRandomHex generates a random hex string or panics
// Use only in initialization code where failure is unrecoverable
func MustRandomHex(n int) string {
	s, err := RandomHex(n)
	if err != nil {
		panic(err)
	}
	return s
}

// MustRandomBytes generates random bytes or panics
// Use only in initialization code where failure is unrecoverable
func MustRandomBytes(n int) []byte {
	b, err := RandomBytes(n)
	if err != nil {
		panic(err)
	}
	return b
}
