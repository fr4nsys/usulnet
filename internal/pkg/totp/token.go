// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package totp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// PendingTokenTTL is how long a TOTP pending token is valid.
	PendingTokenTTL = 5 * time.Minute
)

// GeneratePendingToken creates a signed short-lived token for the TOTP verification step.
// It contains the user ID and an expiration timestamp, signed with HMAC-SHA256.
func GeneratePendingToken(userID string, secret []byte) string {
	exp := time.Now().UTC().Add(PendingTokenTTL).Unix()
	payload := fmt.Sprintf("%s:%d", userID, exp)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payloadB64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return payloadB64 + "." + sig
}

// ValidatePendingToken verifies a TOTP pending token and returns the user ID if valid.
func ValidatePendingToken(token string, secret []byte) (string, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid token format")
	}

	payloadB64, sigB64 := parts[0], parts[1]

	// Verify signature
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payloadB64))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sigB64), []byte(expectedSig)) {
		return "", fmt.Errorf("invalid token signature")
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", fmt.Errorf("invalid token payload")
	}

	payload := string(payloadBytes)
	idx := strings.LastIndex(payload, ":")
	if idx < 0 {
		return "", fmt.Errorf("invalid token payload format")
	}

	userID := payload[:idx]
	expStr := payload[idx+1:]

	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid token expiration")
	}

	if time.Now().UTC().Unix() > exp {
		return "", fmt.Errorf("token expired")
	}

	return userID, nil
}
