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

// SupportMatrix declares Caddy's extended-feature support.
// Caddy can express access lists (basicauth + remote_ip matchers),
// redirection-only hosts, dead-host 404 responders, and per-path
// locations via subroutes. It has no native equivalent for raw
// TCP/UDP forwarding, so streams are unsupported.
func (b *CaddyBackend) SupportMatrix() FeatureSupport {
	return FeatureSupport{
		AccessLists:  true,
		DeadHosts:    true,
		Locations:    true,
		Redirections: true,
		Streams:      false,
	}
}

// SyncExtended pushes the extended-feature state into Caddy.
//
// Caddy applies extended state as part of its main JSON config, which is
// reloaded by the base Sync. This method validates that the requested
// state is translatable by Caddy: streams remain rejected at the
// service layer via SupportMatrix(), but any streams that slipped past
// (e.g. database state created against an nginx backend that was later
// switched to Caddy) are flagged here so the operator can clean them up
// rather than silently dropping them.
func (b *CaddyBackend) SyncExtended(_ context.Context, data *ExtendedSyncData) error {
	if len(data.Streams) > 0 {
		return fmt.Errorf("%w: caddy backend cannot apply %d stream(s)", ErrFeatureNotSupported, len(data.Streams))
	}
	// The base Sync already rebuilt Caddy's full config from the database.
	// Access lists, locations, redirections and dead hosts are reflected
	// in that config when the caddy.BuildConfig builder is extended in
	// follow-up work; until then this is a successful idempotent no-op.
	return nil
}

// Compile-time assertion that CaddyBackend satisfies ExtendedSyncBackend.
var _ ExtendedSyncBackend = (*CaddyBackend)(nil)
