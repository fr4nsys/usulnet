// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import "strings"

// ApplyLocalServicesTLS rewrites the in-cluster Postgres / Redis / NATS
// connection settings to use TLS when server.tls.local_services is true.
// When false (the default) the function is a no-op and the binary
// continues to speak plain TCP on the private docker network.
//
// The rewrites match the docker-compose entrypoint behavior
// (deploy/tls/*.sh):
//
//   - Postgres: append `sslmode=require` to the URL when no sslmode is
//     already present, and force Database.SSLMode to "require". Self-
//     signed certs are accepted (`sslmode=require` does not verify the
//     chain).
//   - Redis: rewrite the scheme from `redis://` to `rediss://` so the
//     go-redis ParseURL sets up a TLS dialer. TLSSkipVerify is enabled
//     so the self-signed leaf is accepted; operators can mount their
//     own CA and set redis.tls_skip_verify=false to verify-full.
//   - NATS: enable NATS.TLS with SkipVerify=true. The URL itself stays
//     `nats://` — nats.go switches to TLS via the client TLSConfig, not
//     by URL scheme.
//
// Explicit operator overrides take precedence: if Database.SSLMode is
// already set, the URL already includes sslmode=, the Redis URL is
// already rediss://, or NATS.TLS.Enabled is already true, the relevant
// branch is skipped. This keeps the helper idempotent and lets
// operators tighten the posture (verify-full, mTLS) without the
// shortcut clobbering their config.
func ApplyLocalServicesTLS(cfg *Config) {
	if cfg == nil || !cfg.Server.TLS.LocalServices {
		return
	}

	if cfg.Database.URL != "" && !strings.Contains(cfg.Database.URL, "sslmode=") {
		if cfg.Database.SSLMode == "" || strings.EqualFold(cfg.Database.SSLMode, "disable") ||
			strings.EqualFold(cfg.Database.SSLMode, "allow") || strings.EqualFold(cfg.Database.SSLMode, "prefer") {
			cfg.Database.SSLMode = "require"
		}
	}

	if cfg.Redis.URL != "" && strings.HasPrefix(cfg.Redis.URL, "redis://") {
		cfg.Redis.URL = "rediss://" + strings.TrimPrefix(cfg.Redis.URL, "redis://")
	}
	// Self-signed leaf — skip cert chain verification by default. An
	// operator who mounts their own CA flips redis.tls_skip_verify=false
	// in config.yaml to opt back into verify-full.
	if !cfg.Redis.TLSSkipVerify && cfg.Redis.TLSCAFile == "" {
		cfg.Redis.TLSSkipVerify = true
	}

	if !cfg.NATS.TLS.Enabled {
		cfg.NATS.TLS.Enabled = true
		if cfg.NATS.TLS.CAFile == "" && cfg.NATS.TLS.CertFile == "" {
			cfg.NATS.TLS.SkipVerify = true
		}
	}
}
