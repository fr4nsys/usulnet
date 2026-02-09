// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

const (
	// bcryptCost is the cost factor for bcrypt hashing
	// 12 provides a good balance between security and performance
	bcryptCost = 12
)

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// CheckPassword compares a password with a bcrypt hash
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// HashPasswordWithCost hashes a password with a custom cost
func HashPasswordWithCost(password string, cost int) (string, error) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = bcryptCost
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// SHA256 computes SHA-256 hash of data and returns hex-encoded string
func SHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// SHA256String computes SHA-256 hash of a string
func SHA256String(s string) string {
	return SHA256([]byte(s))
}

// SHA256Bytes computes SHA-256 hash and returns raw bytes
func SHA256Bytes(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// SHA512 computes SHA-512 hash of data and returns hex-encoded string
func SHA512(data []byte) string {
	hash := sha512.Sum512(data)
	return hex.EncodeToString(hash[:])
}

// SHA512String computes SHA-512 hash of a string
func SHA512String(s string) string {
	return SHA512([]byte(s))
}

// HMACSHA256 computes HMAC-SHA256 and returns hex-encoded string
func HMACSHA256(message, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	return hex.EncodeToString(h.Sum(nil))
}

// HMACSHA256String computes HMAC-SHA256 of strings
func HMACSHA256String(message, key string) string {
	return HMACSHA256([]byte(message), []byte(key))
}

// HMACSHA256Verify verifies HMAC-SHA256
func HMACSHA256Verify(message, key []byte, expectedHex string) bool {
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		return false
	}

	h := hmac.New(sha256.New, key)
	h.Write(message)
	actual := h.Sum(nil)

	return hmac.Equal(actual, expected)
}

// HMACSHA512 computes HMAC-SHA512 and returns hex-encoded string
func HMACSHA512(message, key []byte) string {
	h := hmac.New(sha512.New, key)
	h.Write(message)
	return hex.EncodeToString(h.Sum(nil))
}

// HashAPIKey hashes an API key for storage (using SHA256, not bcrypt for performance)
func HashAPIKey(apiKey string) string {
	return SHA256String(apiKey)
}

// CheckAPIKey compares an API key with its hash
func CheckAPIKey(apiKey, hash string) bool {
	return SHA256String(apiKey) == hash
}

// HashToken hashes a refresh token or similar token
func HashToken(token string) string {
	return SHA256String(token)
}

// CheckToken compares a token with its hash
func CheckToken(token, hash string) bool {
	return SHA256String(token) == hash
}
