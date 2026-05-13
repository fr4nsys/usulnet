// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package license

import (
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

//go:embed keys/public.pem
var publicKeyPEM []byte

// Claims are the JWT payload fields inside a usulnet license key.
type Claims struct {
	LicenseID string    `json:"lid"`
	EmailHash string    `json:"eml"`
	Edition   Edition   `json:"edition"`
	MaxNodes  int       `json:"nod"`
	MaxUsers  int       `json:"usr"`
	Features  []Feature `json:"features"`
	jwt.RegisteredClaims
}

// Validator verifies license JWTs using the embedded RSA-4096 public key.
type Validator struct {
	publicKey *rsa.PublicKey
}

// NewValidator parses the embedded public key and returns a ready Validator.
func NewValidator() (*Validator, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("license: failed to decode embedded public key PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("license: failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("license: embedded key is not RSA")
	}

	if rsaPub.N.BitLen() < 4096 {
		return nil, fmt.Errorf("license: RSA key is %d bits, minimum 4096 required", rsaPub.N.BitLen())
	}

	return &Validator{publicKey: rsaPub}, nil
}

// Validate parses and cryptographically verifies a license JWT string.
// Returns the validated claims or an error explaining the failure.
func (v *Validator) Validate(licenseKey string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(licenseKey, &Claims{},
		func(token *jwt.Token) (interface{}, error) {
			// Reject any algorithm except RS512 (prevents alg=none and alg=HS* attacks)
			if token.Method.Alg() != "RS512" {
				return nil, fmt.Errorf("license: unexpected signing algorithm %q, expected RS512", token.Method.Alg())
			}
			return v.publicKey, nil
		},
		jwt.WithValidMethods([]string{"RS512"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return nil, fmt.Errorf("license: invalid token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("license: invalid claims")
	}

	// Validate edition
	switch claims.Edition {
	case Business, Enterprise:
		// ok
	default:
		return nil, fmt.Errorf("license: unknown edition %q", claims.Edition)
	}

	// Validate license ID prefix
	if len(claims.LicenseID) < 4 || claims.LicenseID[:4] != "USN-" {
		return nil, fmt.Errorf("license: invalid license ID format")
	}

	return claims, nil
}

// ClaimsToInfo converts validated JWT claims into a runtime Info struct.
// When the JWT does not contain an explicit features list, the full set
// of features for the edition is used (AllBusinessFeatures or
// AllEnterpriseFeatures). This ensures that a license JWT that relies on
// the edition field alone still grants access to all edition features.
func ClaimsToInfo(claims *Claims, instanceID string) *Info {
	info := &Info{
		Edition:    claims.Edition,
		Valid:      true,
		LicenseID:  claims.LicenseID,
		InstanceID: instanceID,
	}

	if claims.ExpiresAt != nil {
		t := claims.ExpiresAt.Time
		info.ExpiresAt = &t
		if time.Now().After(t) {
			info.Valid = false
		}
	}

	// Build limits and resolve features from claims + edition defaults
	switch claims.Edition {
	case Business:
		info.Limits = BusinessDefaultLimits()
		// Purchased nodes (from JWT "nod") are added on top of the CE base
		// so a customer who buys 3 nodes gets 3 + 1 (CE) = 4 total.
		if claims.MaxNodes > 0 {
			info.Limits.MaxNodes = claims.MaxNodes + CEBaseNodes
		}
		info.Limits.MaxUsers = claims.MaxUsers
		info.Features = resolveFeatures(claims.Features, AllBusinessFeatures())
	case Enterprise:
		info.Limits = EnterpriseLimits()
		info.Features = resolveFeatures(claims.Features, AllEnterpriseFeatures())
	}

	return info
}

// resolveFeatures returns the effective feature set for a license.
// If the JWT provides an explicit feature list, the result is the union
// of that list with the edition defaults — ensuring no edition feature
// is accidentally omitted. If the JWT list is empty, the full edition
// defaults are used.
func resolveFeatures(jwtFeatures []Feature, editionDefaults []Feature) []Feature {
	if len(jwtFeatures) == 0 {
		return editionDefaults
	}

	// Build a set from edition defaults, then merge any JWT-explicit features
	// that may not be in the defaults (forward-compatibility: a newer JWT
	// could grant features not yet known to this binary's defaults).
	seen := make(map[Feature]struct{}, len(editionDefaults)+len(jwtFeatures))
	merged := make([]Feature, 0, len(editionDefaults)+len(jwtFeatures))

	for _, f := range editionDefaults {
		if _, ok := seen[f]; !ok {
			seen[f] = struct{}{}
			merged = append(merged, f)
		}
	}
	for _, f := range jwtFeatures {
		if _, ok := seen[f]; !ok {
			seen[f] = struct{}{}
			merged = append(merged, f)
		}
	}

	return merged
}
