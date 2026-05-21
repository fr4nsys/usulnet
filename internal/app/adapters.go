// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/fr4nsys/usulnet/internal/api"
	"github.com/fr4nsys/usulnet/internal/api/handlers"
	"github.com/fr4nsys/usulnet/internal/nats"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	reconconnectors "github.com/fr4nsys/usulnet/internal/services/recon/connectors"
	hibpconnector "github.com/fr4nsys/usulnet/internal/services/recon/connectors/hibp"
	shodanconnector "github.com/fr4nsys/usulnet/internal/services/recon/connectors/shodan"
)

// standaloneHostID is the well-known host ID used for the local Docker
// daemon in standalone (non-agent) mode.
var standaloneHostID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

// zapLicenseLogger adapts zap.SugaredLogger to satisfy license.Logger.
type zapLicenseLogger struct {
	sugar *zap.SugaredLogger
}

func (z *zapLicenseLogger) Info(msg string, keysAndValues ...any) {
	z.sugar.Infow(msg, keysAndValues...)
}
func (z *zapLicenseLogger) Warn(msg string, keysAndValues ...any) {
	z.sugar.Warnw(msg, keysAndValues...)
}
func (z *zapLicenseLogger) Error(msg string, keysAndValues ...any) {
	z.sugar.Errorw(msg, keysAndValues...)
}

// encryptorAdapter wraps *crypto.AESEncryptor to satisfy the web.Encryptor interface
// which expects Encrypt(string)(string,error) and Decrypt(string)(string,error).
type encryptorAdapter struct {
	enc *crypto.AESEncryptor
}

func (a *encryptorAdapter) Encrypt(plaintext string) (string, error) {
	return a.enc.EncryptString(plaintext)
}

func (a *encryptorAdapter) Decrypt(ciphertext string) (string, error) {
	return a.enc.DecryptString(ciphertext)
}

// connectorRegistryAdapter bridges *reconconnectors.Registry (which uses
// the package-local Info type to avoid a handlers→connectors import
// cycle) to handlers.ReconConnectorService. The adapter copies field
// values across; the types are structurally identical.
type connectorRegistryAdapter struct {
	reg *reconconnectors.Registry
}

func newConnectorRegistryAdapter(reg *reconconnectors.Registry) *connectorRegistryAdapter {
	return &connectorRegistryAdapter{reg: reg}
}

func (a *connectorRegistryAdapter) ListConnectors(ctx context.Context) ([]handlers.ReconConnectorInfo, error) {
	infos, err := a.reg.ListConnectors(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]handlers.ReconConnectorInfo, len(infos))
	for i, in := range infos {
		out[i] = handlers.ReconConnectorInfo{
			Kind:    in.Kind,
			Enabled: in.Enabled,
			Healthy: in.Healthy,
		}
	}
	return out, nil
}

func (a *connectorRegistryAdapter) SetConnector(ctx context.Context, kind string, creds map[string]string, enabled bool) error {
	return a.reg.SetConnector(ctx, kind, creds, enabled)
}

func (a *connectorRegistryAdapter) DeleteConnector(ctx context.Context, kind string) error {
	return a.reg.DeleteConnector(ctx, kind)
}

// resolveHIBPKey returns the HIBP API key + the enabled flag for the
// connector at boot. The lookup order is:
//
//  1. recon_connectors row (kind='hibp') decrypted via the
//     CredentialStore — operator-managed via the API.
//  2. USULNET_RECON_HIBP_API_KEY environment variable — kept as a
//     migration grace for installs that predate v26.5.1.
//
// When neither yields a key, the connector still registers (so the
// /connectors API can render "not configured"), but Enabled is false
// so HealthCheck returns ErrNoAPIKey without producing a 5xx.
func resolveHIBPKey(ctx context.Context, store reconconnectors.CredentialStore, log *logger.Logger) (string, bool) {
	if store != nil {
		// CredentialStore is the narrow interface (Save / Delete only);
		// the postgres impl also exposes Load(). Type-assert so we
		// don't widen the interface for every consumer that only
		// writes.
		if loader, ok := store.(interface {
			Load(ctx context.Context, kind string) (map[string]string, bool, error)
		}); ok {
			creds, enabled, err := loader.Load(ctx, hibpconnector.Kind)
			if err == nil {
				if key := creds["api_key"]; key != "" {
					return key, enabled
				}
				// Row exists but holds no key — treat as "not
				// configured" so the env-var fallback can fill in.
			} else if !errors.Is(err, postgres.ErrConnectorNotFound) {
				log.Warn("recon: load HIBP credentials failed", "error", err)
			}
		}
	}
	envKey := os.Getenv("USULNET_RECON_HIBP_API_KEY")
	return envKey, envKey != ""
}

// hibpKeySource returns a non-secret tag describing where the key
// came from. The value is only ever logged as `key_source=db` /
// `key_source=env` / `key_source=none` — never the key itself.
func hibpKeySource(store reconconnectors.CredentialStore, key string) string {
	if key == "" {
		return "none"
	}
	if store == nil {
		return "env"
	}
	// We don't re-query here — the resolveHIBPKey path is the
	// authority. If the DB held the key, store was non-nil and the
	// Load() returned the same string we got back; otherwise we fell
	// through to the env var.
	if os.Getenv("USULNET_RECON_HIBP_API_KEY") == key {
		return "env"
	}
	return "db"
}

// resolveShodanKey returns the Shodan API key + the enabled flag for
// the connector at boot. Lookup order mirrors resolveHIBPKey:
//
//  1. recon_connectors row (kind='shodan') decrypted via the
//     CredentialStore — operator-managed via the API.
//  2. USULNET_RECON_SHODAN_API_KEY environment variable — kept as a
//     migration grace for installs that pre-supply the key from the
//     environment rather than the UI.
//
// When neither yields a key the connector still registers (so the
// /connectors API can render "not configured"), but Enabled is false
// so HealthCheck returns ErrNoAPIKey without producing a 5xx.
func resolveShodanKey(ctx context.Context, store reconconnectors.CredentialStore, log *logger.Logger) (string, bool) {
	if store != nil {
		if loader, ok := store.(interface {
			Load(ctx context.Context, kind string) (map[string]string, bool, error)
		}); ok {
			creds, enabled, err := loader.Load(ctx, shodanconnector.Kind)
			if err == nil {
				if key := creds["api_key"]; key != "" {
					return key, enabled
				}
			} else if !errors.Is(err, postgres.ErrConnectorNotFound) {
				log.Warn("recon: load Shodan credentials failed", "error", err)
			}
		}
	}
	envKey := os.Getenv("USULNET_RECON_SHODAN_API_KEY")
	return envKey, envKey != ""
}

// shodanKeySource returns a non-secret tag describing where the
// Shodan key came from. Same contract as hibpKeySource — never logs
// the key itself, only the source tag.
func shodanKeySource(store reconconnectors.CredentialStore, key string) string {
	if key == "" {
		return "none"
	}
	if store == nil {
		return "env"
	}
	if os.Getenv("USULNET_RECON_SHODAN_API_KEY") == key {
		return "env"
	}
	return "db"
}

// natsProberAdapter wraps *nats.Client to satisfy the web.NATSProber interface.
// ServerInfo() returns a formatted string instead of the nats.ServerInfo struct.
type natsProberAdapter struct {
	client *nats.Client
}

func (a *natsProberAdapter) IsConnected() bool { return a.client.IsConnected() }
func (a *natsProberAdapter) IsTLS() bool       { return a.client.IsTLS() }
func (a *natsProberAdapter) ServerInfo() string {
	info := a.client.ServerInfo()
	if info.ServerName != "" {
		return fmt.Sprintf("NATS %s (%s)", info.ServerName, info.URL)
	}
	if info.URL != "" {
		return info.URL
	}
	return "NATS"
}

// countActiveHandlers counts non-nil handlers in the Handlers struct.
func countActiveHandlers(h *api.Handlers) int {
	count := 0
	if h.System != nil {
		count++
	}
	if h.WebSocket != nil {
		count++
	}
	if h.Auth != nil {
		count++
	}
	if h.Container != nil {
		count++
	}
	if h.Image != nil {
		count++
	}
	if h.Volume != nil {
		count++
	}
	if h.Network != nil {
		count++
	}
	if h.Stack != nil {
		count++
	}
	if h.Host != nil {
		count++
	}
	if h.User != nil {
		count++
	}
	if h.Backup != nil {
		count++
	}
	if h.Security != nil {
		count++
	}
	if h.Config != nil {
		count++
	}
	if h.Update != nil {
		count++
	}
	if h.Job != nil {
		count++
	}
	if h.Notification != nil {
		count++
	}
	return count
}

// buildNATSTLSConfig creates a *tls.Config from certificate file paths.
func buildNATSTLSConfig(certFile, keyFile, caFile string, skipVerify bool) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: skipVerify, //nolint:gosec // Configurable for dev environments
	}

	// Load CA certificate
	if caFile != "" {
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate %s: %w", caFile, err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", caFile)
		}
		tlsCfg.RootCAs = caCertPool
	}

	// Load client certificate and key for mutual TLS
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}
