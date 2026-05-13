// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package proxy

import (
	"context"
	"fmt"

	"github.com/fr4nsys/usulnet/internal/services/proxy/caddy"
)

// CaddyBackend implements SyncBackend by generating a Caddy JSON config
// and pushing it to the Caddy admin API.
type CaddyBackend struct {
	client *caddy.Client
}

// NewCaddyBackend creates a SyncBackend for Caddy.
func NewCaddyBackend(client *caddy.Client) SyncBackend {
	return &CaddyBackend{client: client}
}

func (b *CaddyBackend) Sync(ctx context.Context, data *SyncData) error {
	config := caddy.BuildConfig(
		data.Hosts,
		data.DNSProviders,
		data.CustomCerts,
		data.ACMEEmail,
		data.ListenHTTP,
		data.ListenHTTPS,
	)
	if err := b.client.Load(ctx, config); err != nil {
		return fmt.Errorf("caddy load: %w", err)
	}
	return nil
}

func (b *CaddyBackend) Healthy(ctx context.Context) (bool, error) {
	return b.client.Healthy(ctx)
}

func (b *CaddyBackend) Mode() string {
	return "caddy"
}

// RequestCertificate is a no-op for Caddy — it handles ACME automatically.
func (b *CaddyBackend) RequestCertificate(_ context.Context, _ []string, _ string) (string, string, error) {
	return "", "", nil
}

// RenewCertificate is a no-op for Caddy — it auto-renews certificates.
func (b *CaddyBackend) RenewCertificate(_ context.Context, _ []string, _ string) (string, string, error) {
	return "", "", nil
}
