// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package deploy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// Deploy Service + PKI Integration Tests
// ============================================================================

func TestDeployWithPKI_GenerateAgentCerts(t *testing.T) {
	// Setup real PKI manager
	dir := t.TempDir()
	pkiMgr, err := crypto.NewPKIManager(dir)
	if err != nil {
		t.Fatalf("NewPKIManager() error: %v", err)
	}

	svc := &Service{
		pkiManager: pkiMgr,
	}

	// Generate agent config with TLS
	req := DeployRequest{
		HostID:     uuid.New(),
		SSHHost:    "10.0.0.50",
		AgentToken: "test-token",
		GatewayURL: "nats://10.0.0.1:4222",
	}

	config, err := svc.generateAgentConfig(req, true)
	if err != nil {
		t.Fatalf("generateAgentConfig() error: %v", err)
	}

	// Verify TLS section is present
	if !strings.Contains(config, "enabled: true") {
		t.Error("config should have TLS enabled")
	}
	if !strings.Contains(config, "cert_file: \"/app/certs/agent.crt\"") {
		t.Error("config should have cert_file")
	}
	if !strings.Contains(config, "key_file: \"/app/certs/agent.key\"") {
		t.Error("config should have key_file")
	}
	if !strings.Contains(config, "ca_file: \"/app/certs/ca.crt\"") {
		t.Error("config should have ca_file")
	}
}

func TestDeployWithPKI_CertSignedByCA(t *testing.T) {
	dir := t.TempDir()
	pkiMgr, err := crypto.NewPKIManager(dir)
	if err != nil {
		t.Fatalf("NewPKIManager() error: %v", err)
	}

	hostID := uuid.New()
	sshHost := "10.0.0.50"

	// Issue agent cert (same as what deploy service does)
	agentCert, err := pkiMgr.IssueAgentCert(hostID.String(), sshHost)
	if err != nil {
		t.Fatalf("IssueAgentCert() error: %v", err)
	}

	// Verify cert is signed by the internal CA
	if err := pkiMgr.VerifyAgentCert(agentCert.CertPEM); err != nil {
		t.Errorf("agent cert should be verified by CA: %v", err)
	}

	// Parse the cert and verify its properties
	block, _ := pem.Decode(agentCert.CertPEM)
	if block == nil {
		t.Fatal("cert PEM decode failed")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	// Should be a client cert (for NATS mTLS)
	hasClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasClientAuth {
		t.Error("agent cert should have ClientAuth EKU for mTLS")
	}

	// Should have the SSH host as SAN
	ipFound := false
	for _, ip := range cert.IPAddresses {
		if ip.String() == sshHost {
			ipFound = true
		}
	}
	if !ipFound {
		t.Errorf("cert should contain IP SAN %s", sshHost)
	}

	// CN should contain host ID
	if !strings.Contains(cert.Subject.CommonName, hostID.String()) {
		t.Errorf("CN = %q, should contain host ID %s", cert.Subject.CommonName, hostID.String())
	}
}

func TestDeployWithPKI_CertMTLSHandshake(t *testing.T) {
	// Full integration: PKI generates all certs, deploy agent cert can
	// establish mTLS with NATS server cert
	dir := t.TempDir()
	pkiMgr, err := crypto.NewPKIManager(dir)
	if err != nil {
		t.Fatalf("NewPKIManager() error: %v", err)
	}

	// NATS server cert (what master uses)
	serverCertPath, serverKeyPath, err := pkiMgr.EnsureNATSServerCert("localhost")
	if err != nil {
		t.Fatalf("EnsureNATSServerCert() error: %v", err)
	}

	// Agent cert (what deploy service generates)
	agentPair, err := pkiMgr.IssueAgentCert("deploy-test-agent", "localhost")
	if err != nil {
		t.Fatalf("IssueAgentCert() error: %v", err)
	}

	// Load certs
	serverCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		t.Fatalf("load server cert: %v", err)
	}

	agentCert, err := tls.X509KeyPair(agentPair.CertPEM, agentPair.KeyPEM)
	if err != nil {
		t.Fatalf("load agent cert: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(pkiMgr.CACertPEM())

	// mTLS server (simulating NATS)
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

	// Agent connects
	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{agentCert},
		RootCAs:      caPool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	}

	conn, err := tls.Dial("tcp", listener.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("agent TLS dial failed: %v", err)
	}
	conn.Close()

	if err := <-done; err != nil {
		t.Errorf("server handshake failed: %v", err)
	}
}

func TestDeployWithPKI_RejectsWrongCA(t *testing.T) {
	// Agent cert from different CA should be rejected by NATS server
	masterDir := t.TempDir()
	masterPKI, _ := crypto.NewPKIManager(masterDir)

	rogueDir := t.TempDir()
	roguePKI, _ := crypto.NewPKIManager(rogueDir)

	// Server uses master CA
	serverCertPath, serverKeyPath, _ := masterPKI.EnsureNATSServerCert("localhost")

	// Rogue agent uses different CA
	roguePair, _ := roguePKI.IssueAgentCert("rogue-agent", "localhost")

	// Load certs
	serverCert, _ := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	rogueAgentCert, _ := tls.X509KeyPair(roguePair.CertPEM, roguePair.KeyPEM)

	masterPool := x509.NewCertPool()
	masterPool.AppendCertsFromPEM(masterPKI.CACertPEM())

	// Server requires certs from master CA
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    masterPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	listener, _ := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	// Rogue agent tries to connect
	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{rogueAgentCert},
		RootCAs:      masterPool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	}

	conn, err := tls.Dial("tcp", listener.Addr().String(), clientTLS)
	if err == nil {
		conn.Close()
		t.Error("rogue agent should be rejected")
	}
}

func TestDeployWithPKI_NoPKI_NoTLS(t *testing.T) {
	// Deploy service without PKI should generate config without TLS
	svc := &Service{}

	req := DeployRequest{
		SSHHost:    "10.0.0.50",
		AgentToken: "test-token",
		GatewayURL: "nats://10.0.0.1:4222",
	}

	config, err := svc.generateAgentConfig(req, false)
	if err != nil {
		t.Fatalf("generateAgentConfig() error: %v", err)
	}

	if strings.Contains(config, "tls:") {
		t.Error("config without TLS should not have tls section")
	}
	if strings.Contains(config, "enabled: true") {
		t.Error("config without TLS should not have enabled: true")
	}

	compose, err := svc.generateComposeFile(req, false)
	if err != nil {
		t.Fatalf("generateComposeFile() error: %v", err)
	}

	if strings.Contains(compose, "./certs") {
		t.Error("compose without TLS should not mount certs")
	}
}

func TestDeployWithPKI_ComposeWithTLS(t *testing.T) {
	svc := &Service{}

	req := DeployRequest{
		AgentImage: "usulnet-agent:v1.2.0",
		GatewayURL: "nats://master.internal:4222",
		AgentToken: "secure-token",
	}

	compose, err := svc.generateComposeFile(req, true)
	if err != nil {
		t.Fatalf("generateComposeFile() error: %v", err)
	}

	// Should mount certs volume
	if !strings.Contains(compose, "./certs:/app/certs:ro") {
		t.Error("TLS compose should mount certs volume")
	}

	// Should have correct image
	if !strings.Contains(compose, "usulnet-agent:v1.2.0") {
		t.Error("compose should use specified image")
	}

	// Should pass env vars
	if !strings.Contains(compose, "USULNET_GATEWAY_URL=nats://master.internal:4222") {
		t.Error("compose should pass gateway URL")
	}
}

// ============================================================================
// Deploy Request Defaults
// ============================================================================

func TestDeployRequest_Defaults(t *testing.T) {
	log, _ := logger.New("error", "console")
	svc := &Service{
		logger:      log.Named("deploy"),
		deployments: make(map[string]*DeployResult),
	}

	req := DeployRequest{
		SSHHost:    "10.0.0.50",
		SSHUser:    "root",
		AgentToken: "tok",
		GatewayURL: "nats://x",
		// SSHPort and AgentImage not set
	}

	// Deploy sets defaults (but will fail at SSH connect - we just test the ID returned)
	id, err := svc.Deploy(t.Context(), req)
	if err != nil {
		t.Fatalf("Deploy() error: %v", err)
	}
	if id == "" {
		t.Error("deploy ID should not be empty")
	}
	if len(id) != 8 {
		t.Errorf("deploy ID length = %d, want 8", len(id))
	}

	// Verify deployment is tracked (use GetDeployment which is mutex-safe)
	_, ok := svc.GetDeployment(id)
	if !ok {
		t.Fatal("deployment should be tracked")
	}

	// Also verify it appears in list
	all := svc.ListDeployments()
	if len(all) < 1 {
		t.Error("ListDeployments should include this deployment")
	}
}
