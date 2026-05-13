// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// PKI errors
var (
	ErrCANotLoaded     = errors.New("pki: CA certificate and key not loaded")
	ErrCertExpired     = errors.New("pki: certificate has expired")
	ErrCertNotYetValid = errors.New("pki: certificate is not yet valid")
	ErrCAKeyMismatch   = errors.New("pki: CA certificate and key do not match")
	ErrInvalidPEMBlock = errors.New("pki: no valid PEM block found")
)

// Default validity periods
const (
	CAValidityYears     = 10
	ServerValidityYears = 5
	AgentValidityYears  = 2
)

// CertificateAuthority manages an internal CA for signing certificates.
type CertificateAuthority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// CertPair holds a PEM-encoded certificate and private key.
type CertPair struct {
	CertPEM []byte
	KeyPEM  []byte
}

// CABundle holds the CA certificate plus the key (optionally encrypted).
type CABundle struct {
	CertPEM []byte
	KeyPEM  []byte
}

// CertOptions configures certificate generation.
type CertOptions struct {
	// CommonName is the CN field (e.g., "usulnet-agent-<id>")
	CommonName string
	// Organization defaults to "usulnet"
	Organization string
	// DNSNames are Subject Alternative Names (DNS)
	DNSNames []string
	// IPAddresses are Subject Alternative Names (IP)
	IPAddresses []net.IP
	// ValidityDays overrides the default validity period
	ValidityDays int
	// IsServer marks the cert for server authentication (TLS server)
	IsServer bool
	// IsClient marks the cert for client authentication (mTLS client)
	IsClient bool
}

// GenerateCA creates a new self-signed CA certificate and private key.
// The CA uses ECDSA P-256 and is valid for CAValidityYears (10 years).
func GenerateCA() (*CABundle, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate CA key: %w", err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("pki: generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "usulnet Internal CA",
			Organization: []string{"usulnet"},
		},
		NotBefore:             now.Add(-5 * time.Minute), // Clock skew tolerance
		NotAfter:              now.AddDate(CAValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("pki: create CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pki: marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &CABundle{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// LoadCA loads a CA from PEM-encoded certificate and key data.
func LoadCA(certPEM, keyPEM []byte) (*CertificateAuthority, error) {
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("pki: load CA cert: %w", err)
	}

	key, err := parseECPrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("pki: load CA key: %w", err)
	}

	// Verify the key matches the certificate
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		return nil, ErrCAKeyMismatch
	}

	// Verify the CA cert is still valid
	now := time.Now()
	if now.After(cert.NotAfter) {
		return nil, ErrCertExpired
	}
	if now.Before(cert.NotBefore) {
		return nil, ErrCertNotYetValid
	}

	return &CertificateAuthority{cert: cert, key: key}, nil
}

// LoadCAFromFiles loads a CA from certificate and key files on disk.
func LoadCAFromFiles(certPath, keyPath string) (*CertificateAuthority, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("pki: read CA cert file: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("pki: read CA key file: %w", err)
	}

	return LoadCA(certPEM, keyPEM)
}

// CACertPEM returns the CA certificate in PEM format.
func (ca *CertificateAuthority) CACertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.cert.Raw,
	})
}

// CertInfo returns human-readable information about the CA certificate.
func (ca *CertificateAuthority) CertInfo() CertificateInfo {
	return certToInfo(ca.cert)
}

// IssueCertificate signs a new certificate with the given options.
func (ca *CertificateAuthority) IssueCertificate(opts CertOptions) (*CertPair, error) {
	if ca.cert == nil || ca.key == nil {
		return nil, ErrCANotLoaded
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate key: %w", err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("pki: generate serial: %w", err)
	}

	org := opts.Organization
	if org == "" {
		org = "usulnet"
	}

	validityDays := opts.ValidityDays
	if validityDays <= 0 {
		if opts.IsServer {
			validityDays = ServerValidityYears * 365
		} else {
			validityDays = AgentValidityYears * 365
		}
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: []string{org},
		},
		NotBefore: now.Add(-5 * time.Minute), // Clock skew tolerance
		NotAfter:  now.AddDate(0, 0, validityDays),
		DNSNames:  opts.DNSNames,
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	if opts.IPAddresses != nil {
		template.IPAddresses = opts.IPAddresses
	}

	// Set extended key usage based on purpose
	if opts.IsServer && opts.IsClient {
		template.ExtKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		}
	} else if opts.IsServer {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else if opts.IsClient {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		// Default: both server and client auth
		template.ExtKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		}
	}

	// Sign with CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("pki: sign certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pki: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &CertPair{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// IssueNATSServerCert generates a certificate for the NATS server (master).
// Includes both server auth for agents connecting and localhost SANs.
func (ca *CertificateAuthority) IssueNATSServerCert(hosts ...string) (*CertPair, error) {
	dnsNames := []string{"localhost"}
	var ips []net.IP
	ips = append(ips, net.IPv4(127, 0, 0, 1), net.IPv6loopback)

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, h)
		}
	}

	return ca.IssueCertificate(CertOptions{
		CommonName:   "usulnet-nats",
		DNSNames:     dnsNames,
		IPAddresses:  ips,
		IsServer:     true,
		ValidityDays: ServerValidityYears * 365,
	})
}

// IssueAgentCert generates a client certificate for an agent node.
// The agentID is embedded in the CommonName for identification.
func (ca *CertificateAuthority) IssueAgentCert(agentID string, hosts ...string) (*CertPair, error) {
	var dnsNames []string
	var ips []net.IP

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, h)
		}
	}

	return ca.IssueCertificate(CertOptions{
		CommonName:  fmt.Sprintf("usulnet-agent-%s", agentID),
		DNSNames:    dnsNames,
		IPAddresses: ips,
		IsClient:    true,
	})
}

// IssueHTTPSCert generates a server certificate for the HTTPS web interface.
func (ca *CertificateAuthority) IssueHTTPSCert(hosts ...string) (*CertPair, error) {
	dnsNames := []string{"localhost"}
	var ips []net.IP
	ips = append(ips, net.IPv4(127, 0, 0, 1), net.IPv6loopback)

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, h)
		}
	}

	return ca.IssueCertificate(CertOptions{
		CommonName:   "usulnet-https",
		DNSNames:     dnsNames,
		IPAddresses:  ips,
		IsServer:     true,
		ValidityDays: CAValidityYears * 365, // Same as CA for self-signed HTTPS
	})
}

// SaveToDir writes the CA certificate and key to a directory.
func (b *CABundle) SaveToDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("pki: create CA dir: %w", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), b.CertPEM, 0644); err != nil {
		return fmt.Errorf("pki: write CA cert: %w", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "ca.key"), b.KeyPEM, 0600); err != nil {
		return fmt.Errorf("pki: write CA key: %w", err)
	}

	return nil
}

// SaveToDir writes a certificate pair to a directory with the given prefix.
// Creates: <prefix>.crt and <prefix>.key
func (p *CertPair) SaveToDir(dir, prefix string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("pki: create cert dir: %w", err)
	}

	if err := os.WriteFile(filepath.Join(dir, prefix+".crt"), p.CertPEM, 0644); err != nil {
		return fmt.Errorf("pki: write cert: %w", err)
	}

	if err := os.WriteFile(filepath.Join(dir, prefix+".key"), p.KeyPEM, 0600); err != nil {
		return fmt.Errorf("pki: write key: %w", err)
	}

	return nil
}

// CertificateInfo contains human-readable certificate metadata.
type CertificateInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	IsCA         bool      `json:"is_ca"`
	DNSNames     []string  `json:"dns_names,omitempty"`
	IPAddresses  []string  `json:"ip_addresses,omitempty"`
	KeyUsages    []string  `json:"key_usages,omitempty"`
}

// ParseCertificateInfo extracts info from PEM-encoded certificate data.
func ParseCertificateInfo(certPEM []byte) (*CertificateInfo, error) {
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return nil, err
	}
	info := certToInfo(cert)
	return &info, nil
}

// VerifyCertificate checks if a certificate was signed by this CA and is still valid.
func (ca *CertificateAuthority) VerifyCertificate(certPEM []byte) error {
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return err
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)

	_, err = cert.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("pki: verify certificate: %w", err)
	}

	return nil
}

// --- Internal helpers ---

func generateSerialNumber() (*big.Int, error) {
	// 128-bit random serial number (RFC 5280 recommends >=20 bytes entropy)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

func parseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrInvalidPEMBlock
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: parse certificate: %w", err)
	}

	return cert, nil
}

func parseECPrivateKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, ErrInvalidPEMBlock
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: parse EC private key: %w", err)
	}

	return key, nil
}

func certToInfo(cert *x509.Certificate) CertificateInfo {
	info := CertificateInfo{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.Text(16),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		IsCA:         cert.IsCA,
		DNSNames:     cert.DNSNames,
	}

	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}

	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		info.KeyUsages = append(info.KeyUsages, "CertSign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		info.KeyUsages = append(info.KeyUsages, "CRLSign")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		info.KeyUsages = append(info.KeyUsages, "DigitalSignature")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		info.KeyUsages = append(info.KeyUsages, "KeyEncipherment")
	}

	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			info.KeyUsages = append(info.KeyUsages, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			info.KeyUsages = append(info.KeyUsages, "ClientAuth")
		}
	}

	return info
}
