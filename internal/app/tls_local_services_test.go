// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"strings"
	"testing"
)

func TestApplyLocalServicesTLS_NilConfig(t *testing.T) {
	// Must not panic.
	ApplyLocalServicesTLS(nil)
}

func TestApplyLocalServicesTLS_FlagOff_NoOp(t *testing.T) {
	cfg := &Config{
		Database: DatabaseConfig{URL: "postgres://u:p@postgres:5432/usulnet", SSLMode: "prefer"},
		Redis:    RedisConfig{URL: "redis://redis:6379"},
		NATS:     NATSConfig{URL: "nats://nats:4222"},
	}
	cfg.Server.TLS.LocalServices = false

	ApplyLocalServicesTLS(cfg)

	if cfg.Database.SSLMode != "prefer" {
		t.Errorf("expected SSLMode unchanged, got %q", cfg.Database.SSLMode)
	}
	if !strings.HasPrefix(cfg.Redis.URL, "redis://") {
		t.Errorf("expected redis:// URL unchanged, got %q", cfg.Redis.URL)
	}
	if cfg.NATS.TLS.Enabled {
		t.Errorf("expected NATS TLS off, got on")
	}
	if cfg.Redis.TLSSkipVerify {
		t.Errorf("expected redis TLSSkipVerify off, got on")
	}
}

func TestApplyLocalServicesTLS_FlagOn_RewritesPostgresSSLMode(t *testing.T) {
	cfg := &Config{
		Database: DatabaseConfig{URL: "postgres://u:p@postgres:5432/usulnet", SSLMode: "prefer"},
		Redis:    RedisConfig{URL: "redis://redis:6379"},
		NATS:     NATSConfig{URL: "nats://nats:4222"},
	}
	cfg.Server.TLS.LocalServices = true

	ApplyLocalServicesTLS(cfg)

	if cfg.Database.SSLMode != "require" {
		t.Errorf("expected SSLMode=require, got %q", cfg.Database.SSLMode)
	}
}

func TestApplyLocalServicesTLS_PreservesExplicitVerifyFull(t *testing.T) {
	cfg := &Config{
		Database: DatabaseConfig{URL: "postgres://u:p@postgres:5432/usulnet", SSLMode: "verify-full"},
	}
	cfg.Server.TLS.LocalServices = true

	ApplyLocalServicesTLS(cfg)

	if cfg.Database.SSLMode != "verify-full" {
		t.Errorf("expected explicit verify-full preserved, got %q", cfg.Database.SSLMode)
	}
}

func TestApplyLocalServicesTLS_DoesNotOverrideURLSSLMode(t *testing.T) {
	cfg := &Config{
		Database: DatabaseConfig{URL: "postgres://u:p@postgres:5432/usulnet?sslmode=disable", SSLMode: ""},
	}
	cfg.Server.TLS.LocalServices = true

	ApplyLocalServicesTLS(cfg)

	if cfg.Database.SSLMode != "" {
		t.Errorf("expected SSLMode untouched (URL already has sslmode=), got %q", cfg.Database.SSLMode)
	}
}

func TestApplyLocalServicesTLS_FlagOn_RewritesRedisScheme(t *testing.T) {
	cfg := &Config{
		Redis: RedisConfig{URL: "redis://redis:6379"},
	}
	cfg.Server.TLS.LocalServices = true

	ApplyLocalServicesTLS(cfg)

	if cfg.Redis.URL != "rediss://redis:6379" {
		t.Errorf("expected rediss:// URL, got %q", cfg.Redis.URL)
	}
	if !cfg.Redis.TLSSkipVerify {
		t.Errorf("expected TLSSkipVerify=true for self-signed in-cluster redis")
	}
}

func TestApplyLocalServicesTLS_FlagOn_RedisCAPresent_KeepsSkipVerifyOff(t *testing.T) {
	cfg := &Config{
		Redis: RedisConfig{URL: "redis://redis:6379", TLSCAFile: "/tls/ca.crt"},
	}
	cfg.Server.TLS.LocalServices = true

	ApplyLocalServicesTLS(cfg)

	if cfg.Redis.TLSSkipVerify {
		t.Errorf("expected TLSSkipVerify=false when CA is provided")
	}
	if cfg.Redis.URL != "rediss://redis:6379" {
		t.Errorf("expected rediss:// URL rewrite still applied, got %q", cfg.Redis.URL)
	}
}

func TestApplyLocalServicesTLS_FlagOn_AlreadyRediss_NoOp(t *testing.T) {
	cfg := &Config{
		Redis: RedisConfig{URL: "rediss://redis:6380"},
	}
	cfg.Server.TLS.LocalServices = true

	ApplyLocalServicesTLS(cfg)

	if cfg.Redis.URL != "rediss://redis:6380" {
		t.Errorf("expected rediss:// URL preserved, got %q", cfg.Redis.URL)
	}
}

func TestApplyLocalServicesTLS_FlagOn_EnablesNATSTLS(t *testing.T) {
	cfg := &Config{
		NATS: NATSConfig{URL: "nats://nats:4222"},
	}
	cfg.Server.TLS.LocalServices = true

	ApplyLocalServicesTLS(cfg)

	if !cfg.NATS.TLS.Enabled {
		t.Errorf("expected NATS TLS enabled")
	}
	if !cfg.NATS.TLS.SkipVerify {
		t.Errorf("expected NATS TLS SkipVerify true (self-signed)")
	}
}

func TestApplyLocalServicesTLS_FlagOn_PreservesOperatorMTLS(t *testing.T) {
	cfg := &Config{
		NATS: NATSConfig{URL: "nats://nats:4222"},
	}
	cfg.NATS.TLS.Enabled = true
	cfg.NATS.TLS.CertFile = "/tls/client.crt"
	cfg.NATS.TLS.KeyFile = "/tls/client.key"
	cfg.NATS.TLS.CAFile = "/tls/ca.crt"
	cfg.NATS.TLS.SkipVerify = false
	cfg.Server.TLS.LocalServices = true

	ApplyLocalServicesTLS(cfg)

	if cfg.NATS.TLS.SkipVerify {
		t.Errorf("expected operator-configured SkipVerify=false preserved")
	}
	if cfg.NATS.TLS.CAFile != "/tls/ca.crt" {
		t.Errorf("expected operator CA preserved, got %q", cfg.NATS.TLS.CAFile)
	}
}

func TestEffectiveDatabaseURL_NoSSLMode_ReturnsAsIs(t *testing.T) {
	cfg := &Config{Database: DatabaseConfig{URL: "postgres://u:p@h/db"}}
	got := cfg.EffectiveDatabaseURL()
	if got != "postgres://u:p@h/db" {
		t.Errorf("expected URL unchanged, got %q", got)
	}
}

func TestEffectiveDatabaseURL_AppendsSSLMode(t *testing.T) {
	cfg := &Config{Database: DatabaseConfig{URL: "postgres://u:p@h/db", SSLMode: "require"}}
	got := cfg.EffectiveDatabaseURL()
	if got != "postgres://u:p@h/db?sslmode=require" {
		t.Errorf("expected sslmode appended, got %q", got)
	}
}

func TestEffectiveDatabaseURL_AppendsSSLMode_WithExistingQuery(t *testing.T) {
	cfg := &Config{Database: DatabaseConfig{URL: "postgres://u:p@h/db?application_name=usulnet", SSLMode: "verify-full"}}
	got := cfg.EffectiveDatabaseURL()
	if got != "postgres://u:p@h/db?application_name=usulnet&sslmode=verify-full" {
		t.Errorf("expected sslmode appended with &, got %q", got)
	}
}

func TestEffectiveDatabaseURL_SkipsWhenURLHasSSLMode(t *testing.T) {
	cfg := &Config{Database: DatabaseConfig{URL: "postgres://u:p@h/db?sslmode=disable", SSLMode: "require"}}
	got := cfg.EffectiveDatabaseURL()
	if got != "postgres://u:p@h/db?sslmode=disable" {
		t.Errorf("expected URL untouched when sslmode= already present, got %q", got)
	}
}
