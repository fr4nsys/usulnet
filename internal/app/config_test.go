// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"strings"
	"testing"
	"time"
)

// validStandaloneConfig returns a Config that passes all validation.
func validStandaloneConfig() *Config {
	return &Config{
		Mode: "standalone",
		Server: ServerConfig{
			Port:      8080,
			HTTPSPort: 7443,
		},
		Database: DatabaseConfig{
			URL:             "postgres://user:pass@localhost/db",
			MaxOpenConns:    25,
			MaxIdleConns:    10,
			ConnMaxLifetime: 30 * time.Minute,
		},
		Redis: RedisConfig{
			URL:      "redis://localhost:6379",
			PoolSize: 10,
		},
		Security: SecurityConfig{
			JWTSecret:         strings.Repeat("a", 32),
			JWTExpiry:         24 * time.Hour,
			RefreshExpiry:     168 * time.Hour,
			PasswordMinLength: 8,
		},
		Storage: StorageConfig{
			Type: "local",
			Path: "/var/lib/usulnet",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
	}
}

func TestConfig_Validate_ValidStandalone(t *testing.T) {
	cfg := validStandaloneConfig()
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected valid config, got: %v", err)
	}
}

func TestConfig_Validate_InvalidMode(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.Mode = "invalid"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "invalid mode") {
		t.Errorf("expected invalid mode error, got: %v", err)
	}
}

func TestConfig_Validate_MissingDatabaseURL(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.Database.URL = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "database.url is required") {
		t.Errorf("expected database URL error, got: %v", err)
	}
}

func TestConfig_Validate_MissingRedisURL(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.Redis.URL = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "redis.url is required") {
		t.Errorf("expected redis URL error, got: %v", err)
	}
}

func TestConfig_Validate_MissingJWTSecret(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.Security.JWTSecret = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "jwt_secret is required") {
		t.Errorf("expected JWT secret error, got: %v", err)
	}
}

func TestConfig_Validate_ShortJWTSecret(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.Security.JWTSecret = "too-short"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "at least 32 characters") {
		t.Errorf("expected JWT secret length error, got: %v", err)
	}
}

func TestConfig_Validate_EncryptionKeyWrongLength(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.Security.ConfigEncryptionKey = "tooshort"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "64 hex characters") {
		t.Errorf("expected encryption key length error, got: %v", err)
	}
}

func TestConfig_Validate_EncryptionKeyValidLength(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.Security.ConfigEncryptionKey = strings.Repeat("ab", 32) // 64 hex chars
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected valid config with 64-char encryption key, got: %v", err)
	}
}

func TestConfig_Validate_TLS_NoCertWhenAutoTLSDisabled(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.AutoTLS = false
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "cert_file and server.tls.key_file are required") {
		t.Errorf("expected TLS cert/key error, got: %v", err)
	}
}

func TestConfig_Validate_TLS_AutoTLS_NoCertRequired(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.AutoTLS = true
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected valid config with auto_tls, got: %v", err)
	}
}

func TestConfig_Validate_NATS_TLS_NoCert(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.NATS.TLS.Enabled = true
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "nats.tls.cert_file") {
		t.Errorf("expected NATS TLS cert error, got: %v", err)
	}
}

func TestConfig_Validate_AgentMode_MissingMasterURL(t *testing.T) {
	cfg := &Config{
		Mode: "agent",
		Agent: AgentConfig{
			Token: "some-token",
		},
		NATS: NATSConfig{
			URL: "nats://localhost:4222",
		},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "agent.master_url is required") {
		t.Errorf("expected agent master_url error, got: %v", err)
	}
}

func TestConfig_Validate_AgentTLS_NoCert(t *testing.T) {
	cfg := &Config{
		Mode: "agent",
		Agent: AgentConfig{
			MasterURL:  "nats://master:4222",
			Token:      "some-token",
			TLSEnabled: true,
		},
		NATS: NATSConfig{
			URL: "nats://localhost:4222",
		},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "agent.tls_cert_file") {
		t.Errorf("expected agent TLS cert error, got: %v", err)
	}
}

func TestConfig_Validate_LoggingFile_NoPath(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.Logging.Output = "file"
	cfg.Logging.File.Path = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "logging.file.path is required") {
		t.Errorf("expected logging file path error, got: %v", err)
	}
}

func TestConfig_Validate_TracingEnabled_NoEndpoint(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.Observability.Tracing.Enabled = true
	cfg.Observability.Tracing.SamplingRate = 0.1
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "tracing.endpoint is required") {
		t.Errorf("expected tracing endpoint error, got: %v", err)
	}
}

func TestConfig_Validate_SamplingRate_OutOfBounds(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.Observability.Tracing.Enabled = true
	cfg.Observability.Tracing.Endpoint = "localhost:4318"
	cfg.Observability.Tracing.SamplingRate = 1.5
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "sampling_rate must be between") {
		t.Errorf("expected sampling rate error, got: %v", err)
	}
}

func TestConfig_Validate_PortConflict(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.Server.Port = 8080
	cfg.Server.HTTPSPort = 8080
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must not be the same") {
		t.Errorf("expected port conflict error, got: %v", err)
	}
}

func TestConfig_Validate_InvalidPort(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.Server.Port = 99999
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "not a valid port") {
		t.Errorf("expected invalid port error, got: %v", err)
	}
}

func TestConfig_Validate_NegativeDuration(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.Server.ReadTimeout = -1 * time.Second
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "non-negative") {
		t.Errorf("expected negative duration error, got: %v", err)
	}
}

func TestConfig_Validate_InvalidLogLevel(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.Logging.Level = "verbose"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "logging.level") {
		t.Errorf("expected log level error, got: %v", err)
	}
}

func TestConfig_Validate_RefreshLessThanJWT(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.Security.JWTExpiry = 24 * time.Hour
	cfg.Security.RefreshExpiry = 1 * time.Hour
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "refresh_expiry") {
		t.Errorf("expected refresh vs JWT expiry error, got: %v", err)
	}
}

func TestConfig_Validate_IdleExceedsMax(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.Database.MaxOpenConns = 10
	cfg.Database.MaxIdleConns = 20
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "max_idle_conns") {
		t.Errorf("expected idle conns error, got: %v", err)
	}
}

func TestConfig_Validate_S3_MissingBucket(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.Storage.Type = "s3"
	cfg.Storage.S3.AccessKey = "key"
	cfg.Storage.S3.SecretKey = "secret"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "s3.bucket is required") {
		t.Errorf("expected S3 bucket error, got: %v", err)
	}
}

func TestConfig_Validate_CollectsMultipleErrors(t *testing.T) {
	cfg := &Config{
		Mode: "standalone",
		// Missing database.url, redis.url, jwt_secret
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation errors")
	}
	msg := err.Error()
	// Should collect all three errors, not just the first
	if !strings.Contains(msg, "database.url") {
		t.Error("expected database.url error in output")
	}
	if !strings.Contains(msg, "redis.url") {
		t.Error("expected redis.url error in output")
	}
	if !strings.Contains(msg, "jwt_secret") {
		t.Error("expected jwt_secret error in output")
	}
}

func TestConfig_Validate_MasterMode_RequiresNATS(t *testing.T) {
	cfg := validStandaloneConfig()
	cfg.Mode = "master"
	cfg.NATS.URL = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "nats.url is required") {
		t.Errorf("expected NATS URL error for master mode, got: %v", err)
	}
}

// ============================================================================
// Helper function tests
// ============================================================================

func TestParseSize(t *testing.T) {
	tests := []struct {
		input    string
		defBytes int64
		want     int64
	}{
		{"100MB", 0, 100 * 1024 * 1024},
		{"1GB", 0, 1024 * 1024 * 1024},
		{"512KB", 0, 512 * 1024},
		{"1024B", 0, 1024},
		{"", 42, 42},
		{"invalid", 99, 99},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := parseSize(tc.input, tc.defBytes)
			if got != tc.want {
				t.Errorf("parseSize(%q, %d) = %d, want %d", tc.input, tc.defBytes, got, tc.want)
			}
		})
	}
}

func TestMaskURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "<not set>"},
		{"postgres://user:password@localhost/db", "postgres://user:***@localhost/db"},
		{"redis://localhost:6379", "redis://localhost:6379"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := maskURL(tc.input)
			if got != tc.want {
				t.Errorf("maskURL(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseSameSite(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"strict", "strict"},
		{"lax", "lax"},
		{"none", "none"},
		{"Strict", "strict"},
		{"unknown", "lax"}, // default
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := parseSameSite(tc.input)
			// Verify it returns a valid SameSite value (non-zero)
			if got == 0 {
				t.Errorf("parseSameSite(%q) returned zero value", tc.input)
			}
		})
	}
}
