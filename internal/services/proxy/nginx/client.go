// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package nginx

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Config holds nginx backend configuration.
type Config struct {
	// NginxBin is the path to the nginx binary (default: auto-detected).
	NginxBin string
	// ConfigDir is where usulnet writes virtual host configs (e.g. /etc/nginx/conf.d/usulnet/).
	ConfigDir string
	// CertDir is where SSL certificates are stored (e.g. /etc/usulnet/certs/).
	CertDir string
	// ACMEWebRoot is the directory nginx serves ACME HTTP-01 challenge files from.
	ACMEWebRoot string
	// ACMEAccountDir stores the ACME account key.
	ACMEAccountDir string
}

// DefaultConfig returns sensible defaults for the nginx backend.
func DefaultConfig() Config {
	return Config{
		ConfigDir:      "/etc/nginx/conf.d/usulnet",
		CertDir:        "/etc/usulnet/certs",
		ACMEWebRoot:    "/var/lib/usulnet/acme",
		ACMEAccountDir: "/var/lib/usulnet/acme/account",
	}
}

// Client manages the nginx process and configuration files.
type Client struct {
	cfg Config
	bin string // resolved nginx binary path
}

// NewClient creates a new nginx management client.
func NewClient(cfg Config) *Client {
	bin := cfg.NginxBin
	if bin == "" {
		bin = findNginxBinary()
	}

	return &Client{
		cfg: cfg,
		bin: bin,
	}
}

// WriteConfig writes the proxy configuration to the config directory.
func (c *Client) WriteConfig(configContent string) error {
	if err := os.MkdirAll(c.cfg.ConfigDir, 0755); err != nil {
		return fmt.Errorf("nginx: create config dir: %w", err)
	}

	configPath := filepath.Join(c.cfg.ConfigDir, "usulnet-proxy.conf")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("nginx: write config: %w", err)
	}

	return nil
}

// TestConfig validates the nginx configuration.
func (c *Client) TestConfig(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, c.bin, "-t")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx config test failed: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

// Reload signals nginx to reload its configuration.
func (c *Client) Reload(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, c.bin, "-s", "reload")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx reload failed: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

// WriteAndReload writes the config, tests it, and reloads nginx.
// If the test fails, the old config is preserved.
func (c *Client) WriteAndReload(ctx context.Context, configContent string) error {
	configPath := filepath.Join(c.cfg.ConfigDir, "usulnet-proxy.conf")

	// Read old config for rollback
	oldConfig, readErr := os.ReadFile(configPath)

	// Write new config
	if err := c.WriteConfig(configContent); err != nil {
		return err
	}

	// Test
	if err := c.TestConfig(ctx); err != nil {
		// Rollback to old config
		if readErr == nil {
			_ = os.WriteFile(configPath, oldConfig, 0644)
		}
		return fmt.Errorf("nginx: config validation failed (rolled back): %w", err)
	}

	// Reload
	if err := c.Reload(ctx); err != nil {
		return err
	}

	return nil
}

// Healthy checks if nginx is running.
func (c *Client) Healthy(ctx context.Context) (bool, error) {
	cmd := exec.CommandContext(ctx, c.bin, "-t")
	err := cmd.Run()
	if err != nil {
		// probe: any failure means "not healthy", caller takes false as the signal
		return false, nil //nolint:nilerr
	}
	return true, nil
}

// WriteCertificate writes a certificate and key to the cert directory.
func (c *Client) WriteCertificate(subDir, domain string, certPEM, keyPEM []byte) error {
	dir := filepath.Join(c.cfg.CertDir, subDir, domain)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("nginx: create cert dir: %w", err)
	}

	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("nginx: write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("nginx: write key: %w", err)
	}

	slog.Info("nginx: certificate written", "domain", domain, "dir", dir)
	return nil
}

// WriteCustomCertificate writes a custom (user-uploaded) certificate.
func (c *Client) WriteCustomCertificate(certID string, certPEM, keyPEM, chainPEM []byte) error {
	dir := filepath.Join(c.cfg.CertDir, "custom", certID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("nginx: create custom cert dir: %w", err)
	}

	// Build fullchain: cert + chain
	fullchain := certPEM
	if len(chainPEM) > 0 {
		fullchain = append(fullchain, '\n')
		fullchain = append(fullchain, chainPEM...)
	}

	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")

	if err := os.WriteFile(certPath, fullchain, 0644); err != nil {
		return fmt.Errorf("nginx: write custom cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("nginx: write custom key: %w", err)
	}

	return nil
}

// EnsureDirectories creates all required directories.
func (c *Client) EnsureDirectories() error {
	dirs := []string{
		c.cfg.ConfigDir,
		c.cfg.CertDir,
		c.cfg.ACMEWebRoot,
		filepath.Join(c.cfg.ACMEWebRoot, ".well-known", "acme-challenge"),
		c.cfg.ACMEAccountDir,
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("nginx: create directory %s: %w", d, err)
		}
	}
	return nil
}

// WriteWebSocketUpgradeMap writes the connection_upgrade map needed for WebSocket.
// This should be included in the http block of the main nginx.conf.
func (c *Client) WriteWebSocketUpgradeMap() error {
	mapContent := `# WebSocket upgrade map — managed by usulnet
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
`
	mapPath := filepath.Join(c.cfg.ConfigDir, "usulnet-websocket-map.conf")
	return os.WriteFile(mapPath, []byte(mapContent), 0644)
}

// findNginxBinary resolves the nginx binary path.
func findNginxBinary() string {
	candidates := []string{
		"/usr/sbin/nginx",
		"/usr/local/sbin/nginx",
		"/usr/bin/nginx",
		"/usr/local/bin/nginx",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("nginx"); err == nil {
		return p
	}
	return "nginx"
}

// GenerateSnakeoilCert generates a self-signed certificate for the default server.
// This is used as a fallback when no valid certificate exists yet.
func (c *Client) GenerateSnakeoilCert() error {
	dir := filepath.Join(c.cfg.CertDir, "internal", "_default")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")

	// Skip if already exists
	if _, err := os.Stat(certPath); err == nil {
		return nil
	}

	// Use openssl to generate a self-signed cert
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "openssl", "req", "-x509", "-nodes",
		"-days", "3650",
		"-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
		"-keyout", keyPath,
		"-out", certPath,
		"-subj", "/CN=usulnet-default/O=usulnet",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("generate snakeoil cert: %s: %w", string(output), err)
	}

	slog.Info("nginx: generated default self-signed certificate", "path", certPath)
	return nil
}
