// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package proxy

import (
	"context"

	"github.com/fr4nsys/usulnet/internal/models"
)

// SyncBackend abstracts the reverse proxy configuration backend (Caddy, nginx).
// The proxy service loads all configuration from the database, then delegates
// the config build + push/reload to the active backend.
type SyncBackend interface {
	// Sync builds the proxy configuration from the provided data and
	// pushes it to the running backend (Caddy admin API / nginx reload).
	Sync(ctx context.Context, data *SyncData) error

	// Healthy checks if the backend process is running and reachable.
	Healthy(ctx context.Context) (bool, error)

	// Mode returns the backend identifier: "caddy" or "nginx".
	Mode() string

	// RequestCertificate requests a Let's Encrypt certificate for the given domains.
	// Returns the PEM-encoded certificate chain and private key.
	RequestCertificate(ctx context.Context, domains []string, email string) (certPEM, keyPEM string, err error)

	// RenewCertificate renews an existing certificate using the stored key.
	RenewCertificate(ctx context.Context, domains []string, email string) (certPEM, keyPEM string, err error)
}

// SyncData holds all the data needed to build a proxy configuration.
// The proxy service populates this from the database; backends consume it
// to generate their native configuration format.
type SyncData struct {
	Hosts        []*models.ProxyHost
	DNSProviders map[string]*models.ProxyDNSProvider
	CustomCerts  map[string]*models.ProxyCertificate
	ACMEEmail    string
	ListenHTTP   string
	ListenHTTPS  string
}
