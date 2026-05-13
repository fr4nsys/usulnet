// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package deploy provides automated agent deployment via SSH + Docker.
// It handles connecting to remote hosts, generating TLS certificates,
// creating agent configuration, and deploying the agent container.
package deploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/google/uuid"
	gossh "golang.org/x/crypto/ssh"

	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// DeployStatus represents the current state of a deployment.
type DeployStatus string

const (
	StatusPending      DeployStatus = "pending"
	StatusConnecting   DeployStatus = "connecting"
	StatusChecking     DeployStatus = "checking"
	StatusDeploying    DeployStatus = "deploying"
	StatusWaiting      DeployStatus = "waiting"
	StatusComplete     DeployStatus = "complete"
	StatusFailed       DeployStatus = "failed"
)

// DeployRequest contains the information needed to deploy an agent.
type DeployRequest struct {
	// HostID is the host to deploy the agent on (from host service)
	HostID uuid.UUID
	// HostName is the display name
	HostName string
	// SSHHost is the IP or hostname to SSH into
	SSHHost string
	// SSHPort is the SSH port (default: 22)
	SSHPort int
	// SSHUser is the SSH username (needs sudo or root)
	SSHUser string
	// SSHAuthType is "password" or "key"
	SSHAuthType string
	// SSHPassword is the password for SSH auth
	SSHPassword string
	// SSHPrivateKey is the PEM-encoded private key for key auth
	SSHPrivateKey string
	// SSHPassphrase is the passphrase for the private key (optional)
	SSHPassphrase string
	// AgentToken is the pre-generated agent token
	AgentToken string
	// GatewayURL is the master's NATS URL the agent connects to
	GatewayURL string
	// AgentImage is the Docker image for the agent (default: usulnet-agent:latest)
	AgentImage string
	// SSHHostKeyFingerprint is the expected SSH host key fingerprint (SHA256:...).
	// If empty, the key is accepted on first connection (TOFU).
	SSHHostKeyFingerprint string
}

// DeployResult tracks the progress and outcome of a deployment.
type DeployResult struct {
	ID        string       `json:"id"`
	HostID    uuid.UUID    `json:"host_id"`
	HostName  string       `json:"host_name"`
	Status    DeployStatus `json:"status"`
	Step      string       `json:"step"`
	Logs      []string     `json:"logs"`
	Error     string       `json:"error,omitempty"`
	StartedAt time.Time    `json:"started_at"`
	EndedAt   *time.Time   `json:"ended_at,omitempty"`
	mu        sync.Mutex
}

func (r *DeployResult) addLog(msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Logs = append(r.Logs, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg))
}

func (r *DeployResult) setStatus(status DeployStatus, step string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Status = status
	r.Step = step
}

func (r *DeployResult) setError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Status = StatusFailed
	r.Error = err.Error()
	now := time.Now()
	r.EndedAt = &now
}

func (r *DeployResult) setComplete() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Status = StatusComplete
	r.Step = "done"
	now := time.Now()
	r.EndedAt = &now
}

// maxDeploymentHistory is the maximum number of completed deployments to keep
// in memory. Once exceeded, the oldest completed deployments are evicted.
const maxDeploymentHistory = 100

// Service handles agent deployments.
//
// NOTE: Deployment history is stored in-memory only and is lost on restart.
// A future improvement should persist deployments to PostgreSQL for audit
// and recovery purposes.
type Service struct {
	pkiManager  *crypto.PKIManager
	logger      *logger.Logger

	// Track active deployments (in-memory only — lost on restart)
	mu          sync.RWMutex
	deployments map[string]*DeployResult
}

// NewService creates a new deploy service.
func NewService(pkiMgr *crypto.PKIManager, log *logger.Logger) *Service {
	return &Service{
		pkiManager:  pkiMgr,
		logger:      log.Named("deploy"),
		deployments: make(map[string]*DeployResult),
	}
}

// Deploy starts an async agent deployment and returns the deployment ID.
func (s *Service) Deploy(ctx context.Context, req DeployRequest) (string, error) {
	if req.SSHHost == "" {
		return "", fmt.Errorf("SSH host is required")
	}
	if req.SSHUser == "" {
		return "", fmt.Errorf("SSH user is required")
	}
	if req.AgentToken == "" {
		return "", fmt.Errorf("agent token is required")
	}
	if req.GatewayURL == "" {
		return "", fmt.Errorf("gateway URL is required")
	}
	if req.SSHPort == 0 {
		req.SSHPort = 22
	}
	if req.AgentImage == "" {
		req.AgentImage = "usulnet-agent:latest"
	}

	deployID := uuid.New().String()[:8]
	result := &DeployResult{
		ID:        deployID,
		HostID:    req.HostID,
		HostName:  req.HostName,
		Status:    StatusPending,
		Step:      "initializing",
		Logs:      []string{},
		StartedAt: time.Now(),
	}

	s.mu.Lock()
	s.deployments[deployID] = result
	s.evictOldDeployments()
	s.mu.Unlock()

	// Run deployment in background
	go s.runDeploy(ctx, req, result)

	return deployID, nil
}

// GetDeployment returns the status of a deployment.
func (s *Service) GetDeployment(id string) (*DeployResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.deployments[id]
	return r, ok
}

// ListDeployments returns all tracked deployments.
func (s *Service) ListDeployments() []*DeployResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	results := make([]*DeployResult, 0, len(s.deployments))
	for _, r := range s.deployments {
		results = append(results, r)
	}
	return results
}

// runDeploy executes the deployment sequence.
func (s *Service) runDeploy(ctx context.Context, req DeployRequest, result *DeployResult) {
	s.logger.Info("Starting agent deployment",
		"deploy_id", result.ID,
		"host", req.SSHHost,
		"user", req.SSHUser,
	)

	// Step 1: Connect via SSH
	result.setStatus(StatusConnecting, "Connecting via SSH")
	result.addLog(fmt.Sprintf("Connecting to %s@%s:%d", req.SSHUser, req.SSHHost, req.SSHPort))

	client, err := s.sshConnect(req)
	if err != nil {
		result.setError(fmt.Errorf("SSH connection failed: %w", err))
		result.addLog("ERROR: " + err.Error())
		s.logger.Error("Deploy SSH connect failed", "error", err)
		return
	}
	defer client.Close()
	result.addLog("SSH connection established")

	// Step 2: Check Docker is installed
	result.setStatus(StatusChecking, "Checking Docker installation")
	result.addLog("Checking Docker installation on remote host")

	dockerVersion, err := s.sshExec(client, "docker --version")
	if err != nil {
		result.setError(fmt.Errorf("Docker not found on remote host: %w", err))
		result.addLog("ERROR: Docker is not installed. Please install Docker first.")
		return
	}
	result.addLog("Docker found: " + strings.TrimSpace(dockerVersion))

	// Check docker compose
	composeVersion, err := s.sshExec(client, "docker compose version 2>/dev/null || docker-compose --version 2>/dev/null")
	if err != nil {
		result.addLog("WARNING: Docker Compose not found, deploying with docker run")
	} else {
		result.addLog("Docker Compose found: " + strings.TrimSpace(composeVersion))
	}

	// Step 3: Generate TLS certificates (if PKI is available)
	result.setStatus(StatusDeploying, "Generating TLS certificates")
	var certPEM, keyPEM, caPEM string
	tlsEnabled := false

	if s.pkiManager != nil {
		result.addLog("Generating agent TLS certificate from internal CA")
		agentCert, certErr := s.pkiManager.IssueAgentCert(req.HostID.String(), req.SSHHost)
		if certErr != nil {
			result.addLog("WARNING: Failed to generate agent cert: " + certErr.Error())
			result.addLog("Deploying without TLS (agent will connect unencrypted)")
		} else {
			certPEM = string(agentCert.CertPEM)
			keyPEM = string(agentCert.KeyPEM)
			caPEM = string(s.pkiManager.CACertPEM())
			tlsEnabled = true
			result.addLog("TLS certificate generated successfully")
		}
	} else {
		result.addLog("PKI not available, deploying without TLS")
	}

	// Step 4: Create remote directories
	result.addLog("Creating agent directories on remote host")
	if _, err := s.sshExec(client, "sudo mkdir -p /opt/usulnet-agent/config /opt/usulnet-agent/data /opt/usulnet-agent/certs"); err != nil {
		result.setError(fmt.Errorf("failed to create directories: %w", err))
		result.addLog("ERROR: " + err.Error())
		return
	}

	// Step 5: Write TLS certificates to remote host
	if tlsEnabled {
		result.addLog("Deploying TLS certificates")
		if err := s.sshWriteFile(client, "/opt/usulnet-agent/certs/agent.crt", certPEM); err != nil {
			result.setError(fmt.Errorf("failed to write agent cert: %w", err))
			return
		}
		if err := s.sshWriteFile(client, "/opt/usulnet-agent/certs/agent.key", keyPEM); err != nil {
			result.setError(fmt.Errorf("failed to write agent key: %w", err))
			return
		}
		if err := s.sshWriteFile(client, "/opt/usulnet-agent/certs/ca.crt", caPEM); err != nil {
			result.setError(fmt.Errorf("failed to write CA cert: %w", err))
			return
		}
		// Secure permissions
		s.sshExec(client, "sudo chmod 600 /opt/usulnet-agent/certs/agent.key")
		s.sshExec(client, "sudo chmod 644 /opt/usulnet-agent/certs/agent.crt /opt/usulnet-agent/certs/ca.crt")
		result.addLog("TLS certificates deployed")
	}

	// Step 6: Generate agent config
	result.addLog("Generating agent configuration")
	agentConfig, err := s.generateAgentConfig(req, tlsEnabled)
	if err != nil {
		result.setError(fmt.Errorf("failed to generate agent config: %w", err))
		return
	}
	if err := s.sshWriteFile(client, "/opt/usulnet-agent/config/agent.yaml", agentConfig); err != nil {
		result.setError(fmt.Errorf("failed to write agent config: %w", err))
		return
	}
	result.addLog("Agent configuration written")

	// Step 7: Generate docker-compose.yml and deploy
	result.setStatus(StatusDeploying, "Deploying agent container")
	composeYAML, err := s.generateComposeFile(req, tlsEnabled)
	if err != nil {
		result.setError(fmt.Errorf("failed to generate compose file: %w", err))
		return
	}
	if err := s.sshWriteFile(client, "/opt/usulnet-agent/docker-compose.yml", composeYAML); err != nil {
		result.setError(fmt.Errorf("failed to write compose file: %w", err))
		return
	}
	result.addLog("docker-compose.yml written")

	// Step 8: Stop existing agent (if any) and start new one
	result.addLog("Stopping existing agent (if any)")
	s.sshExec(client, "cd /opt/usulnet-agent && sudo docker compose down 2>/dev/null || true")

	result.addLog("Starting agent container")
	output, err := s.sshExec(client, "cd /opt/usulnet-agent && sudo docker compose up -d")
	if err != nil {
		result.setError(fmt.Errorf("failed to start agent: %w", err))
		result.addLog("ERROR: " + err.Error())
		if output != "" {
			result.addLog("Output: " + output)
		}
		return
	}
	result.addLog("Agent container started")
	if output != "" {
		result.addLog(strings.TrimSpace(output))
	}

	// Step 9: Wait for agent to register
	result.setStatus(StatusWaiting, "Waiting for agent registration")
	result.addLog("Waiting for agent to connect to gateway (up to 30s)")

	// Check that the container is actually running
	time.Sleep(3 * time.Second)
	containerStatus, err := s.sshExec(client, "cd /opt/usulnet-agent && sudo docker compose ps --format '{{.State}}'")
	if err == nil {
		result.addLog("Container status: " + strings.TrimSpace(containerStatus))
	}

	// Check container logs for any issues
	containerLogs, err := s.sshExec(client, "cd /opt/usulnet-agent && sudo docker compose logs --tail=10 2>&1")
	if err == nil && containerLogs != "" {
		for _, line := range strings.Split(strings.TrimSpace(containerLogs), "\n") {
			if line != "" {
				result.addLog("  " + line)
			}
		}
	}

	result.setComplete()
	result.addLog("Agent deployment complete")
	s.logger.Info("Agent deployment completed",
		"deploy_id", result.ID,
		"host", req.SSHHost,
	)
}

// sshConnect establishes an SSH connection.
func (s *Service) sshConnect(req DeployRequest) (*gossh.Client, error) {
	var authMethods []gossh.AuthMethod

	switch req.SSHAuthType {
	case "password":
		if req.SSHPassword == "" {
			return nil, fmt.Errorf("password is required for password auth")
		}
		authMethods = append(authMethods, gossh.Password(req.SSHPassword))
	case "key":
		if req.SSHPrivateKey == "" {
			return nil, fmt.Errorf("private key is required for key auth")
		}
		var signer gossh.Signer
		var err error
		if req.SSHPassphrase != "" {
			signer, err = gossh.ParsePrivateKeyWithPassphrase([]byte(req.SSHPrivateKey), []byte(req.SSHPassphrase))
		} else {
			signer, err = gossh.ParsePrivateKey([]byte(req.SSHPrivateKey))
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		authMethods = append(authMethods, gossh.PublicKeys(signer))
	default:
		return nil, fmt.Errorf("unsupported auth type: %s", req.SSHAuthType)
	}

	config := &gossh.ClientConfig{
		User:            req.SSHUser,
		Auth:            authMethods,
		HostKeyCallback: buildDeployHostKeyCallback(req.SSHHostKeyFingerprint),
		Timeout:         30 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", req.SSHHost, req.SSHPort)
	client, err := gossh.Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// buildDeployHostKeyCallback returns a host key callback for deploy SSH connections.
// If expectedFingerprint is provided, it verifies against it. Otherwise accepts (TOFU).
func buildDeployHostKeyCallback(expectedFingerprint string) gossh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		hash := sha256.Sum256(key.Marshal())
		fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])

		if expectedFingerprint != "" && expectedFingerprint != fingerprint {
			return fmt.Errorf("host key mismatch for %s: expected %s, got %s",
				hostname, expectedFingerprint, fingerprint)
		}
		return nil
	}
}

// sshExec runs a command over SSH and returns the combined output.
func (s *Service) sshExec(client *gossh.Client, cmd string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	if err := session.Run(cmd); err != nil {
		errMsg := stderr.String()
		if errMsg == "" {
			errMsg = stdout.String()
		}
		return errMsg, fmt.Errorf("command failed: %s: %w", strings.TrimSpace(errMsg), err)
	}

	return stdout.String(), nil
}

// sshWriteFile writes content to a remote file via SSH.
func (s *Service) sshWriteFile(client *gossh.Client, path, content string) error {
	// Use heredoc to write file content via sudo tee
	// Escape any single quotes in content
	escaped := strings.ReplaceAll(content, "'", "'\\''")
	cmd := fmt.Sprintf("echo '%s' | sudo tee %s > /dev/null", escaped, path)

	if _, err := s.sshExec(client, cmd); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

// generateAgentConfig creates the agent YAML configuration.
func (s *Service) generateAgentConfig(req DeployRequest, tlsEnabled bool) (string, error) {
	tmpl, err := template.New("agent-config").Parse(agentConfigTemplate)
	if err != nil {
		return "", err
	}

	data := map[string]interface{}{
		"GatewayURL": req.GatewayURL,
		"Token":      req.AgentToken,
		"Hostname":   req.SSHHost,
		"TLSEnabled": tlsEnabled,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// generateComposeFile creates the docker-compose.yml for the agent.
func (s *Service) generateComposeFile(req DeployRequest, tlsEnabled bool) (string, error) {
	tmpl, err := template.New("compose").Parse(composeTemplate)
	if err != nil {
		return "", err
	}

	data := map[string]interface{}{
		"Image":      req.AgentImage,
		"GatewayURL": req.GatewayURL,
		"Token":      req.AgentToken,
		"TLSEnabled": tlsEnabled,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// evictOldDeployments removes the oldest completed deployments when the history
// exceeds maxDeploymentHistory. Must be called with s.mu held.
func (s *Service) evictOldDeployments() {
	if len(s.deployments) <= maxDeploymentHistory {
		return
	}

	// Find completed deployments and evict the oldest
	var oldest *DeployResult
	var oldestKey string
	for key, r := range s.deployments {
		if r.Status != StatusComplete && r.Status != StatusFailed {
			continue
		}
		if oldest == nil || r.StartedAt.Before(oldest.StartedAt) {
			oldest = r
			oldestKey = key
		}
	}
	if oldestKey != "" {
		delete(s.deployments, oldestKey)
	}
}

// agentConfigTemplate is the YAML template for agent configuration.
var agentConfigTemplate = `# usulnet Agent Configuration (auto-generated)
gateway_url: "{{.GatewayURL}}"
token: "{{.Token}}"
docker_host: "unix:///var/run/docker.sock"
hostname: "{{.Hostname}}"
data_dir: "/app/data"
log_level: "info"
log_format: "json"
{{if .TLSEnabled}}
tls:
  enabled: true
  cert_file: "/app/certs/agent.crt"
  key_file: "/app/certs/agent.key"
  ca_file: "/app/certs/ca.crt"
{{end}}`

// composeTemplate is the docker-compose.yml template for the agent.
var composeTemplate = `# usulnet Agent (auto-generated)
services:
  usulnet-agent:
    image: {{.Image}}
    container_name: usulnet-agent
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./config:/app/config:ro
      - ./data:/app/data{{if .TLSEnabled}}
      - ./certs:/app/certs:ro{{end}}
    environment:
      - USULNET_GATEWAY_URL={{.GatewayURL}}
      - USULNET_AGENT_TOKEN={{.Token}}
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
`
