// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package agent provides the usulnet agent that runs on remote Docker hosts.
// It connects to the central gateway via NATS, receives commands, and reports
// events and inventory.
package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Config holds the agent configuration.
type Config struct {
	// AgentID is the unique identifier for this agent (generated if empty)
	AgentID string
	// Token is the authentication token for the gateway
	Token string
	// GatewayURL is the NATS server URL
	GatewayURL string
	// DockerHost is the Docker daemon address (default: unix:// + configured socket path)
	DockerHost string
	// Hostname is the agent's hostname (auto-detected if empty)
	Hostname string
	// Labels are custom labels for this agent
	Labels map[string]string
	// LogLevel is the logging level
	LogLevel string
	// DataDir is the directory for local state storage
	DataDir string
	// BackupEnabled enables backup capabilities on this agent
	BackupEnabled bool
	// ScannerEnabled enables security scanning capabilities on this agent
	ScannerEnabled bool
	// TLS configuration for NATS
	TLSEnabled   bool
	TLSCertFile  string
	TLSKeyFile   string
	TLSCAFile    string
}

// DefaultConfig returns default agent configuration.
func DefaultConfig() Config {
	hostname, _ := os.Hostname()
	return Config{
		AgentID:    uuid.New().String(),
		GatewayURL: "nats://localhost:4222",
		DockerHost: "unix://" + docker.LocalSocketPath(),
		Hostname:   hostname,
		Labels:     make(map[string]string),
		LogLevel:   "info",
		DataDir:    "/var/lib/usulnet-agent",
	}
}

// Agent is the usulnet agent that runs on Docker hosts.
type Agent struct {
	config   Config
	id       string
	nats     *nats.Conn
	docker   *docker.Client
	executor *Executor
	log      *logger.Logger

	// Intervals from gateway registration
	heartbeatInterval time.Duration
	inventoryInterval time.Duration

	// Agent state
	startedAt time.Time
	lastError string
	lastErrorTime *time.Time
	activeJobs  int
	jobsMu      sync.Mutex

	// Shutdown handling
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a new agent.
func New(cfg Config, log *logger.Logger) (*Agent, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("token is required")
	}
	if cfg.GatewayURL == "" {
		cfg.GatewayURL = "nats://localhost:4222"
	}
	if cfg.AgentID == "" {
		cfg.AgentID = uuid.New().String()
	}
	if cfg.Hostname == "" {
		cfg.Hostname, _ = os.Hostname()
	}

	return &Agent{
		config:            cfg,
		id:                cfg.AgentID,
		log:               log.Named("agent"),
		heartbeatInterval: 30 * time.Second,
		inventoryInterval: 5 * time.Minute,
	}, nil
}

// Run starts the agent and blocks until context is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	a.ctx, a.cancel = context.WithCancel(ctx)
	a.startedAt = time.Now().UTC()

	a.log.Info("Starting agent",
		"agent_id", a.id,
		"gateway", a.config.GatewayURL,
		"docker_host", a.config.DockerHost,
	)

	// Connect to Docker
	if err := a.connectDocker(); err != nil {
		return fmt.Errorf("failed to connect to Docker: %w", err)
	}
	defer a.docker.Close()

	// Create executor
	a.executor = NewExecutor(a.docker, a.log)

	// Connect to NATS with reconnection
	if err := a.connectNATS(); err != nil {
		return fmt.Errorf("failed to connect to NATS: %w", err)
	}
	defer a.nats.Close()

	// Register with gateway
	if err := a.register(); err != nil {
		return fmt.Errorf("failed to register with gateway: %w", err)
	}

	// Subscribe to commands
	if err := a.subscribeToCommands(); err != nil {
		return fmt.Errorf("failed to subscribe to commands: %w", err)
	}

	// Start background loops
	a.wg.Add(2)
	go a.heartbeatLoop()
	go a.inventoryLoop()

	a.log.Info("Agent running",
		"heartbeat_interval", a.heartbeatInterval,
		"inventory_interval", a.inventoryInterval,
	)

	// Wait for shutdown
	<-a.ctx.Done()

	// Deregister from gateway
	a.deregister()

	// Wait for background tasks
	a.wg.Wait()

	a.log.Info("Agent stopped")
	return nil
}

// Stop stops the agent gracefully.
func (a *Agent) Stop() {
	a.log.Info("Stopping agent")
	a.cancel()
}

// connectDocker establishes connection to Docker daemon.
func (a *Agent) connectDocker() error {
	client, err := docker.NewClient(a.ctx, docker.ClientOptions{
		Host:    a.config.DockerHost,
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return err
	}

	a.docker = client
	a.log.Debug("Connected to Docker",
		"api_version", client.APIVersion(),
	)

	return nil
}

// connectNATS establishes connection to NATS server.
func (a *Agent) connectNATS() error {
	opts := []nats.Option{
		nats.Name("usulnet-agent-" + a.id),
		nats.Token(a.config.Token),
		nats.MaxReconnects(-1), // Infinite reconnects
		nats.ReconnectWait(5 * time.Second),
		nats.ReconnectBufSize(8 * 1024 * 1024), // 8MB buffer
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			if err != nil {
				a.log.Warn("Disconnected from gateway", "error", err)
				a.setLastError(err)
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			a.log.Info("Reconnected to gateway")
			// Re-register after reconnect
			go func() {
				if err := a.register(); err != nil {
					a.log.Error("Failed to re-register after reconnect", "error", err)
				}
			}()
		}),
		nats.ErrorHandler(func(nc *nats.Conn, sub *nats.Subscription, err error) {
			a.log.Error("NATS error", "subject", sub.Subject, "error", err)
			a.setLastError(err)
		}),
	}

	// Add TLS if configured
	if a.config.TLSEnabled {
		tlsCfg, tlsErr := a.buildTLSConfig()
		if tlsErr != nil {
			return fmt.Errorf("failed to build TLS config: %w", tlsErr)
		}
		opts = append(opts, nats.Secure(tlsCfg))
		a.log.Info("NATS TLS enabled")
	}

	conn, err := nats.Connect(a.config.GatewayURL, opts...)
	if err != nil {
		return err
	}

	a.nats = conn
	a.log.Debug("Connected to NATS", "url", a.config.GatewayURL)

	return nil
}

// buildTLSConfig creates a TLS configuration from the agent's TLS settings.
func (a *Agent) buildTLSConfig() (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Load CA certificate
	if a.config.TLSCAFile != "" {
		caCert, err := os.ReadFile(a.config.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsCfg.RootCAs = caCertPool
	}

	// Load client certificate and key
	if a.config.TLSCertFile != "" && a.config.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(a.config.TLSCertFile, a.config.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

// register sends registration request to gateway.
func (a *Agent) register() error {
	info := a.buildAgentInfo()

	req := protocol.RegistrationRequest{
		Token: a.config.Token,
		Info:  info,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal registration: %w", err)
	}

	// Send registration with timeout
	msg, err := a.nats.Request(protocol.SubjectAgentRegister, data, 30*time.Second)
	if err != nil {
		return fmt.Errorf("registration request failed: %w", err)
	}

	var resp protocol.RegistrationResponse
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("registration rejected: %s", resp.Error)
	}

	// Update configuration from gateway
	if resp.AgentID != "" {
		a.id = resp.AgentID
	}
	if resp.HeartbeatInterval > 0 {
		a.heartbeatInterval = resp.HeartbeatInterval
	}
	if resp.InventoryInterval > 0 {
		a.inventoryInterval = resp.InventoryInterval
	}

	a.log.Info("Registered with gateway",
		"agent_id", a.id,
		"heartbeat_interval", a.heartbeatInterval,
	)

	return nil
}

// deregister notifies gateway of graceful shutdown.
func (a *Agent) deregister() {
	req := protocol.DeregistrationRequest{
		AgentID: a.id,
		Reason:  "graceful shutdown",
	}

	data, _ := json.Marshal(req)
	subject := fmt.Sprintf("usulnet.agent.deregister.%s", a.id)
	
	// Best effort - don't wait for response
	a.nats.Publish(subject, data)
	a.nats.Flush()

	a.log.Debug("Sent deregistration")
}

// subscribeToCommands subscribes to command messages.
func (a *Agent) subscribeToCommands() error {
	subject := fmt.Sprintf("%s%s", protocol.SubjectCommandPrefix, a.id)

	_, err := a.nats.Subscribe(subject, a.handleCommand)
	if err != nil {
		return err
	}

	// Also subscribe to broadcast commands
	_, err = a.nats.Subscribe(protocol.SubjectBroadcast, a.handleCommand)
	if err != nil {
		return err
	}

	a.log.Debug("Subscribed to commands", "subject", subject)
	return nil
}

// handleCommand processes incoming commands.
func (a *Agent) handleCommand(msg *nats.Msg) {
	var cmd protocol.Command
	if err := json.Unmarshal(msg.Data, &cmd); err != nil {
		a.log.Warn("Invalid command", "error", err)
		return
	}

	a.log.Debug("Command received",
		"command_id", cmd.ID,
		"type", cmd.Type,
	)

	// Track active jobs
	a.jobsMu.Lock()
	a.activeJobs++
	a.jobsMu.Unlock()

	defer func() {
		a.jobsMu.Lock()
		a.activeJobs--
		a.jobsMu.Unlock()
	}()

	// Execute command
	result := a.executor.Execute(a.ctx, &cmd)

	// Send response if reply subject provided
	if cmd.ReplyTo != "" {
		data, err := json.Marshal(result)
		if err != nil {
			a.log.Error("Failed to marshal result", "error", err)
			return
		}

		if err := a.nats.Publish(cmd.ReplyTo, data); err != nil {
			a.log.Error("Failed to send result", "error", err)
		}
	}
}

// heartbeatLoop sends periodic heartbeats.
func (a *Agent) heartbeatLoop() {
	defer a.wg.Done()

	ticker := time.NewTicker(a.heartbeatInterval)
	defer ticker.Stop()

	// Send initial heartbeat
	a.sendHeartbeat()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.sendHeartbeat()
		}
	}
}

// sendHeartbeat sends a heartbeat message.
func (a *Agent) sendHeartbeat() {
	stats := a.collectQuickStats()

	a.jobsMu.Lock()
	activeJobs := a.activeJobs
	a.jobsMu.Unlock()

	hb := protocol.Heartbeat{
		AgentID:    a.id,
		Timestamp:  time.Now().UTC(),
		Uptime:     time.Since(a.startedAt),
		Stats:      stats,
		ActiveJobs: activeJobs,
		LastError:  a.lastError,
		Health:     a.determineHealth(),
	}

	if a.lastErrorTime != nil {
		hb.LastErrorTime = a.lastErrorTime
	}

	data, err := json.Marshal(hb)
	if err != nil {
		a.log.Warn("Failed to marshal heartbeat", "error", err)
		return
	}

	subject := fmt.Sprintf("usulnet.agent.heartbeat.%s", a.id)
	if err := a.nats.Publish(subject, data); err != nil {
		a.log.Warn("Failed to send heartbeat", "error", err)
		a.setLastError(err)
	}
}

// inventoryLoop sends periodic inventory updates.
func (a *Agent) inventoryLoop() {
	defer a.wg.Done()

	ticker := time.NewTicker(a.inventoryInterval)
	defer ticker.Stop()

	// Send initial inventory
	a.sendInventory()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.sendInventory()
		}
	}
}

// sendInventory sends inventory data to gateway.
func (a *Agent) sendInventory() {
	inv, err := a.collectInventory()
	if err != nil {
		a.log.Warn("Failed to collect inventory", "error", err)
		return
	}

	data, err := json.Marshal(inv)
	if err != nil {
		a.log.Warn("Failed to marshal inventory", "error", err)
		return
	}

	subject := fmt.Sprintf("usulnet.agent.inventory.%s", a.id)
	if err := a.nats.Publish(subject, data); err != nil {
		a.log.Warn("Failed to send inventory", "error", err)
	} else {
		a.log.Debug("Inventory sent",
			"containers", len(inv.Containers),
			"images", len(inv.Images),
		)
	}
}

// buildAgentInfo creates AgentInfo for registration.
func (a *Agent) buildAgentInfo() protocol.AgentInfo {
	return protocol.AgentInfo{
		AgentID:      a.id,
		Version:      Version,
		Hostname:     a.config.Hostname,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		DockerHost:   a.config.DockerHost,
		Labels:       a.config.Labels,
		Capabilities: a.getCapabilities(),
	}
}

// getCapabilities returns the agent's capabilities.
func (a *Agent) getCapabilities() []string {
	caps := []string{
		"container.lifecycle",
		"container.logs",
		"container.exec",
		"image.pull",
		"image.remove",
		"volume.manage",
		"network.manage",
		"stack.deploy",
	}

	// Add conditional capabilities based on agent configuration
	if a.config.BackupEnabled {
		caps = append(caps, "backup")
	}
	if a.config.ScannerEnabled {
		caps = append(caps, "security.scan")
	}

	return caps
}

// collectQuickStats collects lightweight stats for heartbeat.
func (a *Agent) collectQuickStats() *protocol.QuickStats {
	ctx, cancel := context.WithTimeout(a.ctx, 5*time.Second)
	defer cancel()

	info, err := a.docker.Info(ctx)
	if err != nil {
		a.log.Warn("Failed to get Docker info", "error", err)
		return nil
	}

	return &protocol.QuickStats{
		ContainersRunning: info.ContainersRunning,
		ContainersStopped: info.ContainersStopped,
		ContainersTotal:   info.Containers,
		ImagesCount:       info.Images,
		MemoryTotalBytes:  info.MemTotal,
	}
}

// collectInventory collects full inventory.
func (a *Agent) collectInventory() (*protocol.Inventory, error) {
	ctx, cancel := context.WithTimeout(a.ctx, 60*time.Second)
	defer cancel()

	inv := &protocol.Inventory{
		AgentID:     a.id,
		CollectedAt: time.Now().UTC(),
	}

	// Collect containers
	cli := a.docker.Raw()
	containers, err := cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		a.log.Warn("Failed to list containers for inventory", "error", err)
	} else {
		for _, c := range containers {
			ci := protocol.ContainerInfo{
				ID:      c.ID,
				Image:   c.Image,
				ImageID: c.ImageID,
				Command: c.Command,
				Created: c.Created,
				State:   string(c.State),
				Status:  c.Status,
				Labels:  c.Labels,
			}
			// Names
			for _, name := range c.Names {
				if len(name) > 0 && name[0] == '/' {
					ci.Names = append(ci.Names, name[1:])
				} else {
					ci.Names = append(ci.Names, name)
				}
			}
			// Ports
			for _, p := range c.Ports {
				ci.Ports = append(ci.Ports, protocol.PortBinding{
					IP:          p.IP,
					PrivatePort: p.PrivatePort,
					PublicPort:  p.PublicPort,
					Type:        p.Type,
				})
			}
			// Mounts
			for _, m := range c.Mounts {
				ci.Mounts = append(ci.Mounts, protocol.MountInfo{
					Type:        string(m.Type),
					Name:        m.Name,
					Source:      m.Source,
					Destination: m.Destination,
					Mode:        m.Mode,
					RW:          m.RW,
				})
			}
			// Network mode
			if c.HostConfig.NetworkMode != "" {
				ci.NetworkMode = c.HostConfig.NetworkMode
			}
			inv.Containers = append(inv.Containers, ci)
		}
	}

	// Collect images
	images, err := cli.ImageList(ctx, image.ListOptions{All: false})
	if err != nil {
		a.log.Warn("Failed to list images for inventory", "error", err)
	} else {
		for _, img := range images {
			ii := protocol.ImageInfo{
				ID:          img.ID,
				RepoTags:    img.RepoTags,
				RepoDigests: img.RepoDigests,
				Created:     img.Created,
				Size:        img.Size,
				VirtualSize: img.VirtualSize,
				Labels:      img.Labels,
			}
			inv.Images = append(inv.Images, ii)
		}
	}

	// Collect system info
	info, err := a.docker.Info(ctx)
	if err == nil {
		inv.SystemInfo = &protocol.SystemInfo{
			ID:                info.ID,
			Name:              info.Name,
			ServerVersion:     info.ServerVersion,
			APIVersion:        info.APIVersion,
			OS:                info.OS,
			Arch:              info.Architecture,
			KernelVersion:     info.KernelVersion,
			ContainersTotal:   info.Containers,
			ContainersRunning: info.ContainersRunning,
			ContainersPaused:  info.ContainersPaused,
			ContainersStopped: info.ContainersStopped,
			Images:            info.Images,
			MemoryTotal:       info.MemTotal,
			CPUs:              info.NCPU,
		}
	}

	return inv, nil
}

// determineHealth determines the current health status.
func (a *Agent) determineHealth() protocol.HealthStatus {
	// Check Docker connection
	ctx, cancel := context.WithTimeout(a.ctx, 5*time.Second)
	defer cancel()

	if err := a.docker.Ping(ctx); err != nil {
		return protocol.HealthStatusUnhealthy
	}

	// Check if there were recent errors
	if a.lastErrorTime != nil && time.Since(*a.lastErrorTime) < 5*time.Minute {
		return protocol.HealthStatusDegraded
	}

	return protocol.HealthStatusHealthy
}

// setLastError records the last error.
func (a *Agent) setLastError(err error) {
	now := time.Now().UTC()
	a.lastError = err.Error()
	a.lastErrorTime = &now
}

// ID returns the agent ID.
func (a *Agent) ID() string {
	return a.id
}

// Version is the agent version (set at build time).
var Version = "dev"
