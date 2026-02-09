// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Command usulnet-agent is the remote agent for the usulnet Docker management platform.
// It runs on each Docker host, connects to the central gateway via NATS, and executes
// commands received from the control plane.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/fr4nsys/usulnet/internal/agent"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

var (
	// Version is set at build time
	Version = "dev"
	// Commit is the git commit hash
	Commit = "unknown"
	// BuildDate is when the binary was built
	BuildDate = "unknown"
)

func main() {
	// Parse flags
	var (
		configFile  = flag.String("config", "", "Path to config file")
		gatewayURL  = flag.String("gateway", envOrDefault("USULNET_GATEWAY_URL", "nats://localhost:4222"), "Gateway NATS URL")
		token       = flag.String("token", envOrDefault("USULNET_AGENT_TOKEN", ""), "Agent authentication token")
		dockerHost  = flag.String("docker", envOrDefault("DOCKER_HOST", "unix:///var/run/docker.sock"), "Docker daemon address")
		hostname    = flag.String("hostname", "", "Override hostname (auto-detected if empty)")
		logLevel    = flag.String("log-level", envOrDefault("USULNET_LOG_LEVEL", "info"), "Log level (debug, info, warn, error)")
		logFormat   = flag.String("log-format", envOrDefault("USULNET_LOG_FORMAT", "json"), "Log format (json, console)")
		dataDir     = flag.String("data-dir", envOrDefault("USULNET_DATA_DIR", "/var/lib/usulnet-agent"), "Data directory for local state")
		showVersion = flag.Bool("version", false, "Show version and exit")
	)
	flag.Parse()

	// Show version
	if *showVersion {
		fmt.Printf("usulnet-agent %s (commit: %s, built: %s)\n", Version, Commit, BuildDate)
		os.Exit(0)
	}

	// Setup logger
	log, err := logger.New(*logLevel, *logFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync()

	// Set agent version
	agent.Version = Version

	log.Info("Starting usulnet agent",
		"version", Version,
		"commit", Commit,
		"built", BuildDate,
	)

	// Load config from file if specified
	cfg := agent.DefaultConfig()
	if *configFile != "" {
		if err := loadConfigFile(*configFile, &cfg); err != nil {
			log.Fatal("Failed to load config file", "error", err)
		}
	}

	// Override with flags/env
	if *gatewayURL != "" {
		cfg.GatewayURL = *gatewayURL
	}
	if *token != "" {
		cfg.Token = *token
	}
	if *dockerHost != "" {
		cfg.DockerHost = *dockerHost
	}
	if *hostname != "" {
		cfg.Hostname = *hostname
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	cfg.LogLevel = *logLevel

	// Validate required config
	if cfg.Token == "" {
		log.Fatal("Agent token is required. Set USULNET_AGENT_TOKEN or use --token flag")
	}

	// Create agent
	ag, err := agent.New(cfg, log)
	if err != nil {
		log.Fatal("Failed to create agent", "error", err)
	}

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Info("Received signal, shutting down", "signal", sig)
		cancel()

		// Force exit after timeout
		select {
		case <-time.After(30 * time.Second):
			log.Error("Shutdown timeout, forcing exit")
			os.Exit(1)
		case sig := <-sigCh:
			log.Error("Received second signal, forcing exit", "signal", sig)
			os.Exit(1)
		}
	}()

	// Run agent
	if err := ag.Run(ctx); err != nil && err != context.Canceled {
		log.Fatal("Agent failed", "error", err)
	}

	log.Info("Agent stopped")
}

// envOrDefault returns the environment variable value or a default.
func envOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

// agentFileConfig mirrors agent.Config for YAML parsing.
type agentFileConfig struct {
	GatewayURL string            `yaml:"gateway_url"`
	Token      string            `yaml:"token"`
	DockerHost string            `yaml:"docker_host"`
	Hostname   string            `yaml:"hostname"`
	AgentID    string            `yaml:"agent_id"`
	Labels     map[string]string `yaml:"labels"`
	DataDir    string            `yaml:"data_dir"`
	LogLevel   string            `yaml:"log_level"`
	LogFormat  string            `yaml:"log_format"`
	TLS        struct {
		Enabled  bool   `yaml:"enabled"`
		CertFile string `yaml:"cert_file"`
		KeyFile  string `yaml:"key_file"`
		CAFile   string `yaml:"ca_file"`
	} `yaml:"tls"`
}

// loadConfigFile loads configuration from a YAML file.
func loadConfigFile(path string, cfg *agent.Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	var fc agentFileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return fmt.Errorf("parse config file: %w", err)
	}

	if fc.GatewayURL != "" {
		cfg.GatewayURL = fc.GatewayURL
	}
	if fc.Token != "" {
		cfg.Token = fc.Token
	}
	if fc.DockerHost != "" {
		cfg.DockerHost = fc.DockerHost
	}
	if fc.Hostname != "" {
		cfg.Hostname = fc.Hostname
	}
	if fc.AgentID != "" {
		cfg.AgentID = fc.AgentID
	}
	if fc.Labels != nil {
		cfg.Labels = fc.Labels
	}
	if fc.DataDir != "" {
		cfg.DataDir = fc.DataDir
	}
	if fc.LogLevel != "" {
		cfg.LogLevel = fc.LogLevel
	}
	if fc.TLS.Enabled {
		cfg.TLSEnabled = true
		cfg.TLSCertFile = fc.TLS.CertFile
		cfg.TLSKeyFile = fc.TLS.KeyFile
		cfg.TLSCAFile = fc.TLS.CAFile
	}

	return nil
}
