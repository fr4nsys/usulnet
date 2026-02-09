// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// PKIManager manages the internal CA and certificate lifecycle.
// It handles auto-generation of CA and certificates on first startup,
// and loading existing ones from disk on subsequent starts.
type PKIManager struct {
	dataDir string
	ca      *CertificateAuthority
	mu      sync.RWMutex
}

// NewPKIManager creates a PKI manager that stores certificates in dataDir.
// It initializes the CA (generating if needed) and is ready to issue certs.
func NewPKIManager(dataDir string) (*PKIManager, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("pki: create data dir: %w", err)
	}

	mgr := &PKIManager{dataDir: dataDir}

	if err := mgr.initCA(); err != nil {
		return nil, err
	}

	return mgr, nil
}

// CA returns the certificate authority.
func (m *PKIManager) CA() *CertificateAuthority {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ca
}

// CACertPEM returns the CA certificate in PEM format.
func (m *PKIManager) CACertPEM() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ca.CACertPEM()
}

// CACertPath returns the path to the CA certificate file.
func (m *PKIManager) CACertPath() string {
	return filepath.Join(m.dataDir, "ca.crt")
}

// EnsureHTTPSCert returns cert/key paths for the HTTPS server.
// If custom cert/key are provided and exist, returns those paths.
// Otherwise auto-generates a self-signed cert from the internal CA.
func (m *PKIManager) EnsureHTTPSCert(customCert, customKey string, extraHosts ...string) (certPath, keyPath string, err error) {
	// Use custom certs if provided
	if customCert != "" && customKey != "" {
		if _, err := os.Stat(customCert); err == nil {
			if _, err := os.Stat(customKey); err == nil {
				return customCert, customKey, nil
			}
		}
		return "", "", fmt.Errorf("pki: custom cert/key not found: cert=%s key=%s", customCert, customKey)
	}

	// Auto-generate
	certPath = filepath.Join(m.dataDir, "https.crt")
	keyPath = filepath.Join(m.dataDir, "https.key")

	// Return existing if valid
	if valid, _ := m.isCertValid(certPath); valid {
		return certPath, keyPath, nil
	}

	m.mu.RLock()
	pair, err := m.ca.IssueHTTPSCert(extraHosts...)
	m.mu.RUnlock()
	if err != nil {
		return "", "", fmt.Errorf("pki: generate HTTPS cert: %w", err)
	}

	if err := pair.SaveToDir(m.dataDir, "https"); err != nil {
		return "", "", fmt.Errorf("pki: save HTTPS cert: %w", err)
	}

	return certPath, keyPath, nil
}

// EnsureNATSServerCert returns cert/key paths for the NATS server.
func (m *PKIManager) EnsureNATSServerCert(hosts ...string) (certPath, keyPath string, err error) {
	certPath = filepath.Join(m.dataDir, "nats-server.crt")
	keyPath = filepath.Join(m.dataDir, "nats-server.key")

	if valid, _ := m.isCertValid(certPath); valid {
		return certPath, keyPath, nil
	}

	m.mu.RLock()
	pair, err := m.ca.IssueNATSServerCert(hosts...)
	m.mu.RUnlock()
	if err != nil {
		return "", "", fmt.Errorf("pki: generate NATS server cert: %w", err)
	}

	if err := pair.SaveToDir(m.dataDir, "nats-server"); err != nil {
		return "", "", fmt.Errorf("pki: save NATS server cert: %w", err)
	}

	return certPath, keyPath, nil
}

// EnsureMasterNATSClientCert returns cert/key paths for the master's NATS client connection.
// This is a client-auth cert so the NATS server can verify the master's identity.
func (m *PKIManager) EnsureMasterNATSClientCert() (certPath, keyPath string, err error) {
	certPath = filepath.Join(m.dataDir, "nats-client.crt")
	keyPath = filepath.Join(m.dataDir, "nats-client.key")

	if valid, _ := m.isCertValid(certPath); valid {
		return certPath, keyPath, nil
	}

	m.mu.RLock()
	pair, err := m.ca.IssueCertificate(CertOptions{
		CommonName:   "usulnet-master",
		DNSNames:     []string{"localhost"},
		IsClient:     true,
		ValidityDays: ServerValidityYears * 365,
	})
	m.mu.RUnlock()
	if err != nil {
		return "", "", fmt.Errorf("pki: generate master NATS client cert: %w", err)
	}

	if err := pair.SaveToDir(m.dataDir, "nats-client"); err != nil {
		return "", "", fmt.Errorf("pki: save master NATS client cert: %w", err)
	}

	return certPath, keyPath, nil
}

// IssueAgentCert generates a new agent certificate and returns it as PEM.
// The certificate is NOT saved to disk (it's sent to the agent for deployment).
func (m *PKIManager) IssueAgentCert(agentID string, hosts ...string) (*CertPair, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ca.IssueAgentCert(agentID, hosts...)
}

// BuildTLSConfig creates a tls.Config for the HTTPS server from cert/key paths.
func (m *PKIManager) BuildTLSConfig(certPath, keyPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("pki: load TLS keypair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}, nil
}

// BuildNATSTLSConfig creates a tls.Config for NATS mTLS connections.
// This is used by the master's NATS client with the internal CA.
func (m *PKIManager) BuildNATSTLSConfig(certPath, keyPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("pki: load NATS keypair: %w", err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(m.CACertPEM())

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// VerifyAgentCert verifies that a certificate was signed by the internal CA.
func (m *PKIManager) VerifyAgentCert(certPEM []byte) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ca.VerifyCertificate(certPEM)
}

// DataDir returns the PKI data directory path.
func (m *PKIManager) DataDir() string {
	return m.dataDir
}

// initCA loads existing CA or generates a new one.
func (m *PKIManager) initCA() error {
	certPath := filepath.Join(m.dataDir, "ca.crt")
	keyPath := filepath.Join(m.dataDir, "ca.key")

	// Try to load existing CA
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			ca, err := LoadCAFromFiles(certPath, keyPath)
			if err == nil {
				m.ca = ca
				return nil
			}
			// CA files exist but are invalid — regenerate
		}
	}

	// Generate new CA
	bundle, err := GenerateCA()
	if err != nil {
		return fmt.Errorf("pki: generate CA: %w", err)
	}

	if err := bundle.SaveToDir(m.dataDir); err != nil {
		return fmt.Errorf("pki: save CA: %w", err)
	}

	ca, err := LoadCA(bundle.CertPEM, bundle.KeyPEM)
	if err != nil {
		return fmt.Errorf("pki: load new CA: %w", err)
	}

	m.ca = ca
	return nil
}

// isCertValid checks if a certificate file exists and is not expired.
func (m *PKIManager) isCertValid(certPath string) (bool, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return false, err
	}

	m.mu.RLock()
	err = m.ca.VerifyCertificate(data)
	m.mu.RUnlock()

	return err == nil, err
}
