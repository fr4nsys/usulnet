// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package nginx

import (
	"context"
	"fmt"
	"log/slog"

	proxy "github.com/fr4nsys/usulnet/internal/services/proxy"
)

// Backend implements proxy.SyncBackend for nginx.
// It generates nginx configuration files, writes them to disk,
// validates the config, and reloads the nginx process.
type Backend struct {
	client *Client
	acme   *ACMEClient
}

// NewBackend creates an nginx SyncBackend.
func NewBackend(cfg Config) proxy.SyncBackend {
	client := NewClient(cfg)
	acmeClient := NewACMEClient(cfg.ACMEAccountDir, cfg.ACMEWebRoot, false)

	// Ensure all directories exist
	if err := client.EnsureDirectories(); err != nil {
		slog.Error("nginx: failed to create directories", "error", err)
	}

	// Write the WebSocket upgrade map
	if err := client.WriteWebSocketUpgradeMap(); err != nil {
		slog.Error("nginx: failed to write websocket map", "error", err)
	}

	return &Backend{
		client: client,
		acme:   acmeClient,
	}
}

func (b *Backend) Sync(ctx context.Context, data *proxy.SyncData) error {
	// Write custom certificates to disk (nginx reads them from files)
	for id, cert := range data.CustomCerts {
		if cert.CertPEM == "" {
			continue
		}
		var chain []byte
		if cert.ChainPEM != "" {
			chain = []byte(cert.ChainPEM)
		}
		if err := b.client.WriteCustomCertificate(id, []byte(cert.CertPEM), []byte(cert.KeyPEM), chain); err != nil {
			slog.Error("nginx: failed to write custom certificate", "cert_id", id, "error", err)
		}
	}

	// Build nginx configuration
	config := BuildConfig(
		data.Hosts,
		data.CustomCerts,
		data.ACMEEmail,
		data.ListenHTTP,
		data.ListenHTTPS,
		b.client.cfg.CertDir,
		b.client.cfg.ACMEWebRoot,
	)

	// Write config, validate, and reload nginx
	if err := b.client.WriteAndReload(ctx, config); err != nil {
		return fmt.Errorf("nginx sync: %w", err)
	}

	slog.Info("nginx: proxy configuration synced", "host_count", len(data.Hosts))
	return nil
}

func (b *Backend) Healthy(ctx context.Context) (bool, error) {
	return b.client.Healthy(ctx)
}

func (b *Backend) Mode() string {
	return "nginx"
}

// RequestCertificate obtains a Let's Encrypt certificate via ACME HTTP-01 challenge.
// The certificate is written to the cert directory for nginx to use.
func (b *Backend) RequestCertificate(ctx context.Context, domains []string, email string) (certPEM, keyPEM string, err error) {
	certPEM, keyPEM, err = b.acme.RequestCertificate(ctx, domains, email)
	if err != nil {
		return "", "", err
	}

	// Write certificate files for nginx
	primaryDomain := domains[0]
	if err := b.client.WriteCertificate("live", primaryDomain, []byte(certPEM), []byte(keyPEM)); err != nil {
		return "", "", fmt.Errorf("write certificate: %w", err)
	}

	return certPEM, keyPEM, nil
}

// RenewCertificate renews a certificate — same as requesting a new one.
func (b *Backend) RenewCertificate(ctx context.Context, domains []string, email string) (certPEM, keyPEM string, err error) {
	return b.RequestCertificate(ctx, domains, email)
}
