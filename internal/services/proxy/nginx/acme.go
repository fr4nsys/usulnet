// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package nginx

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	// letsEncryptProductionURL is the production ACME directory.
	letsEncryptProductionURL = "https://acme-v02.api.letsencrypt.org/directory"
	// letsEncryptStagingURL can be used for testing (not rate-limited).
	letsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// ACMEClient handles Let's Encrypt certificate requests via the ACME protocol.
// It uses HTTP-01 challenges, writing challenge tokens to a webroot that
// nginx serves at /.well-known/acme-challenge/.
type ACMEClient struct {
	accountKeyPath string
	webRoot        string
	staging        bool // use staging URL for testing
}

// NewACMEClient creates a new ACME client.
func NewACMEClient(accountDir, webRoot string, staging bool) *ACMEClient {
	return &ACMEClient{
		accountKeyPath: filepath.Join(accountDir, "account.key"),
		webRoot:        webRoot,
		staging:        staging,
	}
}

// RequestCertificate obtains a certificate from Let's Encrypt for the given domains.
// Returns PEM-encoded certificate chain and private key.
func (a *ACMEClient) RequestCertificate(ctx context.Context, domains []string, email string) (certPEM, keyPEM string, err error) {
	if len(domains) == 0 {
		return "", "", fmt.Errorf("acme: no domains specified")
	}

	slog.Info("acme: requesting certificate", "domains", domains, "email", email)

	// Load or create ACME account key
	accountKey, err := a.loadOrCreateAccountKey()
	if err != nil {
		return "", "", fmt.Errorf("acme: account key: %w", err)
	}

	// Create ACME client
	directoryURL := letsEncryptProductionURL
	if a.staging {
		directoryURL = letsEncryptStagingURL
	}

	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: directoryURL,
	}

	// Register account (idempotent — if already registered, returns existing)
	acct := &acme.Account{
		Contact: []string{"mailto:" + email},
	}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil {
		// ErrAccountAlreadyExists means we're already registered — that's fine
		if err != acme.ErrAccountAlreadyExists {
			return "", "", fmt.Errorf("acme: register account: %w", err)
		}
	}

	// Create certificate order
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domains...))
	if err != nil {
		return "", "", fmt.Errorf("acme: authorize order: %w", err)
	}

	// Solve challenges
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return "", "", fmt.Errorf("acme: get authorization: %w", err)
		}

		// Already valid (e.g. from a previous attempt)
		if authz.Status == acme.StatusValid {
			continue
		}

		// Find HTTP-01 challenge
		var challenge *acme.Challenge
		for _, ch := range authz.Challenges {
			if ch.Type == "http-01" {
				challenge = ch
				break
			}
		}
		if challenge == nil {
			return "", "", fmt.Errorf("acme: no HTTP-01 challenge available for %s", authz.Identifier.Value)
		}

		// Write challenge response to webroot
		response, err := client.HTTP01ChallengeResponse(challenge.Token)
		if err != nil {
			return "", "", fmt.Errorf("acme: challenge response: %w", err)
		}

		challengeDir := filepath.Join(a.webRoot, ".well-known", "acme-challenge")
		if err := os.MkdirAll(challengeDir, 0755); err != nil {
			return "", "", fmt.Errorf("acme: create challenge dir: %w", err)
		}

		challengePath := filepath.Join(challengeDir, challenge.Token)
		if err := os.WriteFile(challengePath, []byte(response), 0644); err != nil {
			return "", "", fmt.Errorf("acme: write challenge: %w", err)
		}
		defer os.Remove(challengePath) // Clean up after

		slog.Info("acme: challenge token written", "domain", authz.Identifier.Value, "token", challenge.Token)

		// Accept the challenge
		if _, err := client.Accept(ctx, challenge); err != nil {
			return "", "", fmt.Errorf("acme: accept challenge: %w", err)
		}

		// Wait for authorization to complete
		authzCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		if _, err := client.WaitAuthorization(authzCtx, authzURL); err != nil {
			cancel()
			return "", "", fmt.Errorf("acme: authorization failed for %s: %w", authz.Identifier.Value, err)
		}
		cancel()
	}

	// Wait for order to be ready
	orderCtx, orderCancel := context.WithTimeout(ctx, 2*time.Minute)
	defer orderCancel()
	order, err = client.WaitOrder(orderCtx, order.URI)
	if err != nil {
		return "", "", fmt.Errorf("acme: wait order: %w", err)
	}

	// Generate certificate key (separate from account key)
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("acme: generate cert key: %w", err)
	}

	// Create CSR
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}, certKey)
	if err != nil {
		return "", "", fmt.Errorf("acme: create CSR: %w", err)
	}

	// Finalize order — get the certificate chain
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return "", "", fmt.Errorf("acme: create order cert: %w", err)
	}

	// Encode cert chain to PEM
	var certPEMBuf []byte
	for _, der := range chain {
		certPEMBuf = append(certPEMBuf, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		})...)
	}

	// Encode private key to PEM
	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return "", "", fmt.Errorf("acme: marshal key: %w", err)
	}
	keyPEMBuf := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	slog.Info("acme: certificate obtained", "domains", domains)
	return string(certPEMBuf), string(keyPEMBuf), nil
}

// loadOrCreateAccountKey loads the ACME account private key from disk,
// or creates a new one if it doesn't exist.
func (a *ACMEClient) loadOrCreateAccountKey() (crypto.Signer, error) {
	// Try to load existing key
	keyPEM, err := os.ReadFile(a.accountKeyPath)
	if err == nil {
		block, _ := pem.Decode(keyPEM)
		if block != nil {
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err == nil {
				return key, nil
			}
			// Try PKCS8 format
			pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err == nil {
				if signer, ok := pkcs8Key.(crypto.Signer); ok {
					return signer, nil
				}
			}
		}
	}

	// Generate new key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate account key: %w", err)
	}

	// Save to disk
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal account key: %w", err)
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	if err := os.MkdirAll(filepath.Dir(a.accountKeyPath), 0700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(a.accountKeyPath, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("save account key: %w", err)
	}

	slog.Info("acme: new account key generated", "path", a.accountKeyPath)
	return key, nil
}
