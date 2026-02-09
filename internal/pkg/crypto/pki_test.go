// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateCA(t *testing.T) {
	bundle, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	if len(bundle.CertPEM) == 0 {
		t.Fatal("CertPEM is empty")
	}
	if len(bundle.KeyPEM) == 0 {
		t.Fatal("KeyPEM is empty")
	}

	// Parse and verify the CA certificate
	block, _ := pem.Decode(bundle.CertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("CertPEM is not a valid CERTIFICATE PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	if !cert.IsCA {
		t.Error("CA cert IsCA should be true")
	}
	if cert.Subject.CommonName != "usulnet Internal CA" {
		t.Errorf("CA CN = %q, want %q", cert.Subject.CommonName, "usulnet Internal CA")
	}
	if cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		t.Error("CA MaxPathLen should be 0 with MaxPathLenZero=true")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA should have KeyUsageCertSign")
	}

	// Validity: should be ~10 years
	validity := cert.NotAfter.Sub(cert.NotBefore)
	expectedMin := time.Duration(CAValidityYears*365-1) * 24 * time.Hour
	if validity < expectedMin {
		t.Errorf("CA validity %v is less than expected %v", validity, expectedMin)
	}

	// Verify key PEM
	keyBlock, _ := pem.Decode(bundle.KeyPEM)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		t.Fatal("KeyPEM is not a valid EC PRIVATE KEY PEM")
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse CA key: %v", err)
	}

	if key.Curve != elliptic.P256() {
		t.Error("CA key should use P-256 curve")
	}
}

func TestLoadCA(t *testing.T) {
	bundle, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	ca, err := LoadCA(bundle.CertPEM, bundle.KeyPEM)
	if err != nil {
		t.Fatalf("LoadCA() error: %v", err)
	}

	if ca.cert == nil {
		t.Fatal("CA cert is nil")
	}
	if ca.key == nil {
		t.Fatal("CA key is nil")
	}

	info := ca.CertInfo()
	if !info.IsCA {
		t.Error("CertInfo.IsCA should be true")
	}
}

func TestLoadCA_KeyMismatch(t *testing.T) {
	bundle1, _ := GenerateCA()
	bundle2, _ := GenerateCA()

	_, err := LoadCA(bundle1.CertPEM, bundle2.KeyPEM)
	if err != ErrCAKeyMismatch {
		t.Errorf("expected ErrCAKeyMismatch, got: %v", err)
	}
}

func TestLoadCA_InvalidPEM(t *testing.T) {
	bundle, _ := GenerateCA()

	_, err := LoadCA([]byte("not a cert"), bundle.KeyPEM)
	if err == nil {
		t.Error("expected error for invalid cert PEM")
	}

	_, err = LoadCA(bundle.CertPEM, []byte("not a key"))
	if err == nil {
		t.Error("expected error for invalid key PEM")
	}
}

func TestLoadCAFromFiles(t *testing.T) {
	bundle, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	dir := t.TempDir()
	if err := bundle.SaveToDir(dir); err != nil {
		t.Fatalf("SaveToDir() error: %v", err)
	}

	ca, err := LoadCAFromFiles(
		filepath.Join(dir, "ca.crt"),
		filepath.Join(dir, "ca.key"),
	)
	if err != nil {
		t.Fatalf("LoadCAFromFiles() error: %v", err)
	}

	if ca.cert.Subject.CommonName != "usulnet Internal CA" {
		t.Errorf("wrong CN: %s", ca.cert.Subject.CommonName)
	}
}

func TestIssueCertificate_ServerAndClient(t *testing.T) {
	bundle, _ := GenerateCA()
	ca, _ := LoadCA(bundle.CertPEM, bundle.KeyPEM)

	pair, err := ca.IssueCertificate(CertOptions{
		CommonName:  "test-server",
		DNSNames:    []string{"test.local", "localhost"},
		IPAddresses: []net.IP{net.IPv4(10, 0, 0, 1)},
		IsServer:    true,
		IsClient:    true,
	})
	if err != nil {
		t.Fatalf("IssueCertificate() error: %v", err)
	}

	// Parse the issued cert
	block, _ := pem.Decode(pair.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	if cert.Subject.CommonName != "test-server" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "test-server")
	}
	if cert.IsCA {
		t.Error("issued cert should not be a CA")
	}

	// Check SANs
	if len(cert.DNSNames) != 2 {
		t.Errorf("got %d DNS names, want 2", len(cert.DNSNames))
	}
	if len(cert.IPAddresses) != 1 {
		t.Errorf("got %d IP addresses, want 1", len(cert.IPAddresses))
	}

	// Check EKU
	hasServerAuth := false
	hasClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasServerAuth {
		t.Error("cert should have ServerAuth EKU")
	}
	if !hasClientAuth {
		t.Error("cert should have ClientAuth EKU")
	}

	// Verify cert is signed by CA
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Errorf("cert should verify against CA: %v", err)
	}
}

func TestIssueNATSServerCert(t *testing.T) {
	bundle, _ := GenerateCA()
	ca, _ := LoadCA(bundle.CertPEM, bundle.KeyPEM)

	pair, err := ca.IssueNATSServerCert("nats.example.com", "192.168.1.100")
	if err != nil {
		t.Fatalf("IssueNATSServerCert() error: %v", err)
	}

	block, _ := pem.Decode(pair.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	if cert.Subject.CommonName != "usulnet-nats" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "usulnet-nats")
	}

	// Should include localhost + provided hostname
	dnsFound := map[string]bool{}
	for _, dns := range cert.DNSNames {
		dnsFound[dns] = true
	}
	if !dnsFound["localhost"] {
		t.Error("NATS cert should include localhost SAN")
	}
	if !dnsFound["nats.example.com"] {
		t.Error("NATS cert should include provided hostname")
	}

	// Should include 127.0.0.1 + provided IP
	ipFound := map[string]bool{}
	for _, ip := range cert.IPAddresses {
		ipFound[ip.String()] = true
	}
	if !ipFound["127.0.0.1"] {
		t.Error("NATS cert should include 127.0.0.1")
	}
	if !ipFound["192.168.1.100"] {
		t.Error("NATS cert should include provided IP")
	}

	// Should have ServerAuth EKU
	hasServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
	}
	if !hasServerAuth {
		t.Error("NATS cert should have ServerAuth")
	}
}

func TestIssueAgentCert(t *testing.T) {
	bundle, _ := GenerateCA()
	ca, _ := LoadCA(bundle.CertPEM, bundle.KeyPEM)

	pair, err := ca.IssueAgentCert("abc123", "agent1.example.com")
	if err != nil {
		t.Fatalf("IssueAgentCert() error: %v", err)
	}

	block, _ := pem.Decode(pair.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	if cert.Subject.CommonName != "usulnet-agent-abc123" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "usulnet-agent-abc123")
	}

	// Should have ClientAuth EKU only
	hasClientAuth := false
	hasServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
	}
	if !hasClientAuth {
		t.Error("agent cert should have ClientAuth")
	}
	if hasServerAuth {
		t.Error("agent cert should NOT have ServerAuth")
	}

	// Validity: should be ~2 years
	validity := cert.NotAfter.Sub(cert.NotBefore)
	expectedMin := time.Duration(AgentValidityYears*365-1) * 24 * time.Hour
	if validity < expectedMin {
		t.Errorf("agent cert validity %v is less than expected %v", validity, expectedMin)
	}
}

func TestIssueHTTPSCert(t *testing.T) {
	bundle, _ := GenerateCA()
	ca, _ := LoadCA(bundle.CertPEM, bundle.KeyPEM)

	pair, err := ca.IssueHTTPSCert("usulnet.local", "10.0.0.5")
	if err != nil {
		t.Fatalf("IssueHTTPSCert() error: %v", err)
	}

	block, _ := pem.Decode(pair.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	if cert.Subject.CommonName != "usulnet-https" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "usulnet-https")
	}

	// Validity: should be ~10 years (same as CA)
	validity := cert.NotAfter.Sub(cert.NotBefore)
	expectedMin := time.Duration(CAValidityYears*365-1) * 24 * time.Hour
	if validity < expectedMin {
		t.Errorf("HTTPS cert validity %v is less than expected %v", validity, expectedMin)
	}
}

func TestVerifyCertificate(t *testing.T) {
	bundle, _ := GenerateCA()
	ca, _ := LoadCA(bundle.CertPEM, bundle.KeyPEM)

	pair, _ := ca.IssueAgentCert("verify-test")

	// Should verify against the CA
	if err := ca.VerifyCertificate(pair.CertPEM); err != nil {
		t.Errorf("VerifyCertificate() should pass: %v", err)
	}

	// Should fail against a different CA
	otherBundle, _ := GenerateCA()
	otherCA, _ := LoadCA(otherBundle.CertPEM, otherBundle.KeyPEM)

	if err := otherCA.VerifyCertificate(pair.CertPEM); err == nil {
		t.Error("VerifyCertificate() should fail with different CA")
	}
}

func TestCertPair_SaveToDir(t *testing.T) {
	bundle, _ := GenerateCA()
	ca, _ := LoadCA(bundle.CertPEM, bundle.KeyPEM)
	pair, _ := ca.IssueAgentCert("save-test")

	dir := t.TempDir()
	if err := pair.SaveToDir(dir, "agent"); err != nil {
		t.Fatalf("SaveToDir() error: %v", err)
	}

	// Verify files exist with correct permissions
	certInfo, err := os.Stat(filepath.Join(dir, "agent.crt"))
	if err != nil {
		t.Fatalf("agent.crt not found: %v", err)
	}
	if certInfo.Mode().Perm() != 0644 {
		t.Errorf("agent.crt perms = %o, want 0644", certInfo.Mode().Perm())
	}

	keyInfo, err := os.Stat(filepath.Join(dir, "agent.key"))
	if err != nil {
		t.Fatalf("agent.key not found: %v", err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Errorf("agent.key perms = %o, want 0600", keyInfo.Mode().Perm())
	}

	// Verify contents are valid PEM
	certData, _ := os.ReadFile(filepath.Join(dir, "agent.crt"))
	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Error("saved cert file is not valid PEM")
	}
}

func TestCABundle_SaveToDir(t *testing.T) {
	bundle, _ := GenerateCA()

	dir := t.TempDir()
	if err := bundle.SaveToDir(dir); err != nil {
		t.Fatalf("SaveToDir() error: %v", err)
	}

	// Verify ca.key has restricted permissions
	keyInfo, err := os.Stat(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("ca.key not found: %v", err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Errorf("ca.key perms = %o, want 0600", keyInfo.Mode().Perm())
	}
}

func TestParseCertificateInfo(t *testing.T) {
	bundle, _ := GenerateCA()
	ca, _ := LoadCA(bundle.CertPEM, bundle.KeyPEM)

	pair, _ := ca.IssueNATSServerCert("nats.test")

	info, err := ParseCertificateInfo(pair.CertPEM)
	if err != nil {
		t.Fatalf("ParseCertificateInfo() error: %v", err)
	}

	if info.Subject == "" {
		t.Error("Subject should not be empty")
	}
	if info.SerialNumber == "" {
		t.Error("SerialNumber should not be empty")
	}
	if info.IsCA {
		t.Error("IsCA should be false for server cert")
	}
	if len(info.DNSNames) == 0 {
		t.Error("DNSNames should not be empty")
	}
}

func TestTLSHandshake_MutualTLS(t *testing.T) {
	// Generate full PKI chain: CA → server cert + client cert
	bundle, _ := GenerateCA()
	ca, _ := LoadCA(bundle.CertPEM, bundle.KeyPEM)

	serverPair, _ := ca.IssueNATSServerCert("localhost")
	clientPair, _ := ca.IssueAgentCert("test-agent", "localhost")

	// Load certificates for TLS
	serverCert, err := tls.X509KeyPair(serverPair.CertPEM, serverPair.KeyPEM)
	if err != nil {
		t.Fatalf("load server cert: %v", err)
	}

	clientCert, err := tls.X509KeyPair(clientPair.CertPEM, clientPair.KeyPEM)
	if err != nil {
		t.Fatalf("load client cert: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(bundle.CertPEM)

	// Setup TLS server
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer listener.Close()

	// Server goroutine: accept one connection
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		// Force handshake
		if tlsConn, ok := conn.(*tls.Conn); ok {
			done <- tlsConn.Handshake()
		} else {
			done <- nil
		}
	}()

	// Client connects with mTLS
	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	}

	conn, err := tls.Dial("tcp", listener.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	conn.Close()

	// Check server handshake completed successfully
	if err := <-done; err != nil {
		t.Errorf("server handshake failed: %v", err)
	}
}

func TestTLSHandshake_RejectsUntrustedClient(t *testing.T) {
	// CA1 signs the server, CA2 signs the client — handshake should fail
	bundle1, _ := GenerateCA()
	ca1, _ := LoadCA(bundle1.CertPEM, bundle1.KeyPEM)
	bundle2, _ := GenerateCA()
	ca2, _ := LoadCA(bundle2.CertPEM, bundle2.KeyPEM)

	serverPair, _ := ca1.IssueNATSServerCert("localhost")
	clientPair, _ := ca2.IssueAgentCert("rogue-agent", "localhost")

	serverCert, _ := tls.X509KeyPair(serverPair.CertPEM, serverPair.KeyPEM)
	clientCert, _ := tls.X509KeyPair(clientPair.CertPEM, clientPair.KeyPEM)

	ca1Pool := x509.NewCertPool()
	ca1Pool.AppendCertsFromPEM(bundle1.CertPEM)

	// Server trusts only CA1
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    ca1Pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	// Client presents cert signed by CA2 — should be rejected
	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      ca1Pool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	}

	conn, err := tls.Dial("tcp", listener.Addr().String(), clientTLS)
	if err == nil {
		conn.Close()
		t.Error("handshake should have failed with untrusted client cert")
	}
}

func TestIssueCertificate_CustomValidity(t *testing.T) {
	bundle, _ := GenerateCA()
	ca, _ := LoadCA(bundle.CertPEM, bundle.KeyPEM)

	pair, err := ca.IssueCertificate(CertOptions{
		CommonName:   "custom-validity",
		ValidityDays: 30,
		IsServer:     true,
	})
	if err != nil {
		t.Fatalf("IssueCertificate() error: %v", err)
	}

	block, _ := pem.Decode(pair.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	validity := cert.NotAfter.Sub(cert.NotBefore)
	// Should be ~30 days + 5min clock skew
	if validity < 29*24*time.Hour || validity > 31*24*time.Hour {
		t.Errorf("custom validity %v not close to 30 days", validity)
	}
}

func TestIssueCertificate_DefaultEKU(t *testing.T) {
	bundle, _ := GenerateCA()
	ca, _ := LoadCA(bundle.CertPEM, bundle.KeyPEM)

	// No IsServer or IsClient set — should default to both
	pair, err := ca.IssueCertificate(CertOptions{
		CommonName: "default-eku",
	})
	if err != nil {
		t.Fatalf("IssueCertificate() error: %v", err)
	}

	block, _ := pem.Decode(pair.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	if len(cert.ExtKeyUsage) != 2 {
		t.Errorf("expected 2 EKUs (server+client), got %d", len(cert.ExtKeyUsage))
	}
}

func TestUniqueSerialNumbers(t *testing.T) {
	bundle, _ := GenerateCA()
	ca, _ := LoadCA(bundle.CertPEM, bundle.KeyPEM)

	serials := make(map[string]bool)
	for i := 0; i < 50; i++ {
		pair, err := ca.IssueAgentCert("agent-" + itoa(i))
		if err != nil {
			t.Fatalf("IssueCertificate() error: %v", err)
		}
		block, _ := pem.Decode(pair.CertPEM)
		cert, _ := x509.ParseCertificate(block.Bytes)
		serial := cert.SerialNumber.Text(16)
		if serials[serial] {
			t.Errorf("duplicate serial number: %s", serial)
		}
		serials[serial] = true
	}
}

func TestCACertPEM(t *testing.T) {
	bundle, _ := GenerateCA()
	ca, _ := LoadCA(bundle.CertPEM, bundle.KeyPEM)

	pem := ca.CACertPEM()
	if len(pem) == 0 {
		t.Fatal("CACertPEM() returned empty")
	}

	// Should be loadable
	info, err := ParseCertificateInfo(pem)
	if err != nil {
		t.Fatalf("ParseCertificateInfo() error: %v", err)
	}
	if !info.IsCA {
		t.Error("should be a CA cert")
	}
}

func TestECDSAKeyType(t *testing.T) {
	bundle, _ := GenerateCA()
	ca, _ := LoadCA(bundle.CertPEM, bundle.KeyPEM)

	pair, _ := ca.IssueAgentCert("ecdsa-test")

	block, _ := pem.Decode(pair.KeyPEM)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("key should be ECDSA: %v", err)
	}

	if key.Curve != elliptic.P256() {
		t.Errorf("key curve = %v, want P-256", key.Curve)
	}

	// Verify the cert public key matches
	certBlock, _ := pem.Decode(pair.CertPEM)
	cert, _ := x509.ParseCertificate(certBlock.Bytes)

	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("cert public key should be ECDSA")
	}
	if !pubKey.Equal(&key.PublicKey) {
		t.Error("cert public key should match private key")
	}
}

// ============================================================================
// PKI Manager Tests
// ============================================================================

func TestPKIManager_InitCA(t *testing.T) {
	dir := t.TempDir()
	mgr, err := NewPKIManager(dir)
	if err != nil {
		t.Fatalf("NewPKIManager() error: %v", err)
	}

	if mgr.CA() == nil {
		t.Fatal("CA should not be nil")
	}

	// CA files should exist
	if _, err := os.Stat(filepath.Join(dir, "ca.crt")); err != nil {
		t.Error("ca.crt should exist")
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.key")); err != nil {
		t.Error("ca.key should exist")
	}
}

func TestPKIManager_ReloadsExistingCA(t *testing.T) {
	dir := t.TempDir()

	// First init - generates CA
	mgr1, _ := NewPKIManager(dir)
	ca1PEM := mgr1.CACertPEM()

	// Second init - should reload same CA
	mgr2, err := NewPKIManager(dir)
	if err != nil {
		t.Fatalf("NewPKIManager() second init error: %v", err)
	}
	ca2PEM := mgr2.CACertPEM()

	if string(ca1PEM) != string(ca2PEM) {
		t.Error("second init should load same CA, not generate a new one")
	}
}

func TestPKIManager_EnsureHTTPSCert(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewPKIManager(dir)

	certPath, keyPath, err := mgr.EnsureHTTPSCert("", "")
	if err != nil {
		t.Fatalf("EnsureHTTPSCert() error: %v", err)
	}

	if certPath != filepath.Join(dir, "https.crt") {
		t.Errorf("certPath = %q, want %q", certPath, filepath.Join(dir, "https.crt"))
	}

	// Should be valid
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Errorf("generated HTTPS cert should be loadable: %v", err)
	}

	// Second call should return same paths without regenerating
	certPath2, _, _ := mgr.EnsureHTTPSCert("", "")
	if certPath2 != certPath {
		t.Error("second call should return same path")
	}
}

func TestPKIManager_EnsureNATSServerCert(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewPKIManager(dir)

	certPath, keyPath, err := mgr.EnsureNATSServerCert("nats", "localhost")
	if err != nil {
		t.Fatalf("EnsureNATSServerCert() error: %v", err)
	}

	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Errorf("NATS server cert should be loadable: %v", err)
	}
}

func TestPKIManager_EnsureMasterNATSClientCert(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewPKIManager(dir)

	certPath, keyPath, err := mgr.EnsureMasterNATSClientCert()
	if err != nil {
		t.Fatalf("EnsureMasterNATSClientCert() error: %v", err)
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("master NATS client cert should be loadable: %v", err)
	}

	// Verify it has ClientAuth EKU
	parsed, _ := x509.ParseCertificate(cert.Certificate[0])
	hasClientAuth := false
	for _, eku := range parsed.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasClientAuth {
		t.Error("master NATS client cert should have ClientAuth EKU")
	}
}

func TestPKIManager_FullMTLSWorkflow(t *testing.T) {
	// Test the complete workflow: PKI manager generates all certs,
	// then a mTLS handshake succeeds between NATS server cert and agent cert
	dir := t.TempDir()
	mgr, _ := NewPKIManager(dir)

	// Generate NATS server cert
	serverCertPath, serverKeyPath, _ := mgr.EnsureNATSServerCert("localhost")

	// Generate agent cert
	agentPair, err := mgr.IssueAgentCert("workflow-test")
	if err != nil {
		t.Fatalf("IssueAgentCert() error: %v", err)
	}

	// Load certs
	serverCert, _ := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	agentCert, _ := tls.X509KeyPair(agentPair.CertPEM, agentPair.KeyPEM)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(mgr.CACertPEM())

	// Setup mTLS server (simulating NATS server)
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer listener.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		if tlsConn, ok := conn.(*tls.Conn); ok {
			done <- tlsConn.Handshake()
		} else {
			done <- nil
		}
	}()

	// Agent connects with mTLS
	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{agentCert},
		RootCAs:      caPool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	}

	conn, err := tls.Dial("tcp", listener.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("agent mTLS dial failed: %v", err)
	}
	conn.Close()

	if err := <-done; err != nil {
		t.Errorf("server handshake failed: %v", err)
	}
}

func TestPKIManager_BuildNATSTLSConfig(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewPKIManager(dir)

	certPath, keyPath, _ := mgr.EnsureMasterNATSClientCert()

	tlsCfg, err := mgr.BuildNATSTLSConfig(certPath, keyPath)
	if err != nil {
		t.Fatalf("BuildNATSTLSConfig() error: %v", err)
	}

	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Error("MinVersion should be TLS 1.2")
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Error("should have 1 client certificate")
	}
	if tlsCfg.RootCAs == nil {
		t.Error("RootCAs should contain the CA")
	}
}

func TestPKIManager_VerifyAgentCert(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewPKIManager(dir)

	pair, _ := mgr.IssueAgentCert("verify-test")

	if err := mgr.VerifyAgentCert(pair.CertPEM); err != nil {
		t.Errorf("VerifyAgentCert() should pass: %v", err)
	}

	// Cert from different CA should fail
	otherDir := t.TempDir()
	otherMgr, _ := NewPKIManager(otherDir)
	otherPair, _ := otherMgr.IssueAgentCert("other-agent")

	if err := mgr.VerifyAgentCert(otherPair.CertPEM); err == nil {
		t.Error("VerifyAgentCert() should fail for cert from different CA")
	}
}
