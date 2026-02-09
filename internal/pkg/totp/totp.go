// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultDigits is the number of digits in a TOTP code
	DefaultDigits = 6
	// DefaultPeriod is the time step in seconds
	DefaultPeriod = 30
	// DefaultSecretSize is the size of the TOTP secret in bytes (160 bits)
	DefaultSecretSize = 20
	// DefaultIssuer is the default issuer name for otpauth URIs
	DefaultIssuer = "usulnet"
	// DefaultSkew allows codes from adjacent time periods (1 = ±30s)
	DefaultSkew = 1
)

// GenerateSecret creates a new random TOTP secret encoded as base32.
func GenerateSecret() (string, error) {
	secret := make([]byte, DefaultSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// GenerateCode generates a TOTP code for the given secret at the current time.
func GenerateCode(secret string, t time.Time) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}

	counter := uint64(t.Unix()) / DefaultPeriod
	return generateHOTP(key, counter, DefaultDigits), nil
}

// Validate checks if a TOTP code is valid for the given secret.
// It checks the current time period and ±DefaultSkew adjacent periods.
func Validate(code string, secret string) (bool, error) {
	if len(code) != DefaultDigits {
		return false, nil
	}

	key, err := decodeSecret(secret)
	if err != nil {
		return false, err
	}

	now := time.Now().UTC()
	counter := uint64(now.Unix()) / DefaultPeriod

	// Check current period and adjacent periods (±skew)
	for i := -DefaultSkew; i <= DefaultSkew; i++ {
		c := counter + uint64(i)
		expected := generateHOTP(key, c, DefaultDigits)
		if hmac.Equal([]byte(code), []byte(expected)) {
			return true, nil
		}
	}

	return false, nil
}

// OTPAuthURI generates an otpauth:// URI for QR code generation.
// Format: otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30
func OTPAuthURI(secret, account, issuer string) string {
	if issuer == "" {
		issuer = DefaultIssuer
	}

	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprintf("%d", DefaultDigits))
	v.Set("period", fmt.Sprintf("%d", DefaultPeriod))

	label := url.PathEscape(fmt.Sprintf("%s:%s", issuer, account))
	return fmt.Sprintf("otpauth://totp/%s?%s", label, v.Encode())
}

// generateHOTP implements HOTP (RFC 4226) which is the base for TOTP.
func generateHOTP(key []byte, counter uint64, digits int) string {
	// Counter to big-endian bytes
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	// HMAC-SHA1
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	hash := mac.Sum(nil)

	// Dynamic truncation (RFC 4226 §5.4)
	offset := hash[len(hash)-1] & 0x0f
	code := int64(binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff)

	// Modulo to get desired number of digits
	mod := int64(math.Pow10(digits))
	otp := code % mod

	return fmt.Sprintf("%0*d", digits, otp)
}

// decodeSecret decodes a base32-encoded TOTP secret.
func decodeSecret(secret string) ([]byte, error) {
	// Normalize: uppercase, strip spaces
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))

	// Add padding if needed
	if m := len(secret) % 8; m != 0 {
		secret += strings.Repeat("=", 8-m)
	}

	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("decode totp secret: %w", err)
	}
	return key, nil
}
