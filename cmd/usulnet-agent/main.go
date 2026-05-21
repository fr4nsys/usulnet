// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Command usulnet-agent is the remote agent for the usulnet Docker management platform.
// It runs on each Docker host, connects to the central gateway via NATS, and executes
// commands received from the control plane.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
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

// Flag-bound vars. Cobra parses into these from rootCmd's persistent flags;
// every subcommand inherits them.
var (
	cfgFile    string
	gatewayURL string
	token      string
	dockerHost string
	hostname   string
	logLevel   string
	logFormat  string
	dataDir    string
)

var rootCmd = &cobra.Command{
	Use:   "usulnet-agent",
	Short: "usulnet remote agent — connect a Docker host to the gateway",
	Long: `usulnet-agent runs on each remote Docker host and connects to the
central usulnet gateway over NATS. It receives commands from the
control plane and executes them locally against the Docker daemon.

Running with no subcommand starts the agent (equivalent to
"usulnet-agent run"). Use "version" to print build info, or
"validate-config" to load+check the config without starting.`,
	// SilenceUsage stops cobra from dumping the full help text after a RunE
	// error; SilenceErrors stops cobra from prefixing the line itself so
	// main()'s error handler can format the output consistently.
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAgent(cmd)
	},
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start the agent and connect to the gateway",
	Long: `Run the agent connect-loop: load the config, dial the gateway over
NATS, then serve commands until SIGINT/SIGTERM (graceful) or a
second signal (force-exit after 30s).

Equivalent to invoking "usulnet-agent" with no subcommand.`,
	Example: `  usulnet-agent run
  usulnet-agent run --config /etc/usulnet-agent/config.yaml
  usulnet-agent run --gateway nats://master:4222 --token $TOKEN`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAgent(cmd)
	},
}

var versionCmd = &cobra.Command{
	Use:     "version",
	Short:   "Print version information",
	Long:    `Print the usulnet-agent version, commit, and build date.`,
	Example: `  usulnet-agent version`,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := fmt.Printf("usulnet-agent %s (commit: %s, built: %s)\n", Version, Commit, BuildDate)
		return err
	},
}

var validateConfigCmd = &cobra.Command{
	Use:   "validate-config",
	Short: "Load and validate the config without starting the agent",
	Long: `Load the agent config (from --config and environment) and run
the required-fields check. Exits 0 if a startable config can be
assembled; non-zero otherwise. Useful in CI / deploy pipelines to
catch typos before the agent restarts.`,
	Example: `  usulnet-agent validate-config --config /etc/usulnet-agent/config.yaml
  USULNET_AGENT_TOKEN=$TOKEN usulnet-agent validate-config`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := assembleConfig()
		if err != nil {
			return err
		}
		if err := validateConfig(cfg); err != nil {
			return err
		}
		fmt.Println("Agent configuration is valid")
		return nil
	},
}

// runAgent is shared between rootCmd and runCmd — both invoke it.
func runAgent(cmd *cobra.Command) error {
	log, err := logger.New(logLevel, logFormat)
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}
	defer func() { _ = log.Sync() }()

	cfg, err := assembleConfig()
	if err != nil {
		log.Error("Failed to assemble config", "error", err)
		return err
	}
	if err := validateConfig(cfg); err != nil {
		log.Error("Config validation failed", "error", err)
		return err
	}

	agent.Version = Version
	log.Info("Starting usulnet agent",
		"version", Version,
		"commit", Commit,
		"built", BuildDate,
	)

	ag, err := agent.New(cfg, log)
	if err != nil {
		return fmt.Errorf("create agent: %w", err)
	}

	ctx, cancel := context.WithCancel(cmd.Context())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Info("Received signal, shutting down", "signal", sig)
		cancel()

		// Force exit after timeout or on a second signal.
		select {
		case <-time.After(30 * time.Second):
			log.Error("Shutdown timeout, forcing exit")
			os.Exit(1)
		case sig := <-sigCh:
			log.Error("Received second signal, forcing exit", "signal", sig)
			os.Exit(1)
		}
	}()

	if err := ag.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("agent run: %w", err)
	}
	log.Info("Agent stopped")
	return nil
}

// assembleConfig builds an agent.Config from defaults + the optional
// config file + flag/env overrides. It does NOT validate; use
// validateConfig for the required-fields check.
func assembleConfig() (agent.Config, error) {
	cfg := agent.DefaultConfig()
	if cfgFile != "" {
		if err := loadConfigFile(cfgFile, &cfg); err != nil {
			return cfg, err
		}
	}
	// Flag-equivalent values (already env-resolved by the flag defaults)
	// override the file. Empty strings are skipped so the YAML wins when
	// a flag wasn't explicitly set.
	if gatewayURL != "" {
		cfg.GatewayURL = gatewayURL
	}
	if token != "" {
		cfg.Token = token
	}
	if dockerHost != "" {
		cfg.DockerHost = dockerHost
	}
	if hostname != "" {
		cfg.Hostname = hostname
	}
	if dataDir != "" {
		cfg.DataDir = dataDir
	}
	cfg.LogLevel = logLevel
	return cfg, nil
}

// validateConfig enforces the must-have fields. Currently only Token is
// required; everything else has a usable default.
func validateConfig(cfg agent.Config) error {
	if cfg.Token == "" {
		return errors.New("agent token is required (set USULNET_AGENT_TOKEN or --token)")
	}
	return nil
}

// loadConfigFile loads agent configuration from a YAML file.
//
// The file is unmarshaled directly into the supplied agent.Config —
// yaml tags on agent.Config drive the mapping, so adding new fields no
// longer requires a parallel mirror struct. Fields absent from the YAML
// keep their existing (DefaultConfig) values.
func loadConfigFile(path string, cfg *agent.Config) error {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("parse config file: %w", err)
	}
	return nil
}

// envOrDefault returns the environment variable value or a default.
func envOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

// dockerHostDefault resolves the default --docker value with the AG3
// env-var precedence: USULNET_AGENT_DOCKER_HOST wins, then DOCKER_HOST
// (for Docker tooling parity), then the unix-socket fallback.
func dockerHostDefault() string {
	if v := os.Getenv("USULNET_AGENT_DOCKER_HOST"); v != "" {
		return v
	}
	if v := os.Getenv("DOCKER_HOST"); v != "" {
		return v
	}
	return "unix:///var/run/docker.sock"
}

func init() {
	// Persistent flags — visible on every subcommand so
	// "usulnet-agent --config foo.yaml run" works.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "Path to YAML config file")
	rootCmd.PersistentFlags().StringVar(&gatewayURL, "gateway", envOrDefault("USULNET_GATEWAY_URL", "nats://localhost:4222"), "Gateway NATS URL (default $USULNET_GATEWAY_URL)")
	rootCmd.PersistentFlags().StringVar(&token, "token", envOrDefault("USULNET_AGENT_TOKEN", ""), "Agent authentication token (default $USULNET_AGENT_TOKEN)")
	rootCmd.PersistentFlags().StringVar(&dockerHost, "docker", dockerHostDefault(), "Docker daemon address (default $USULNET_AGENT_DOCKER_HOST, then $DOCKER_HOST)")
	rootCmd.PersistentFlags().StringVar(&hostname, "hostname", "", "Override hostname (auto-detected if empty)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", envOrDefault("USULNET_LOG_LEVEL", "info"), "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&logFormat, "log-format", envOrDefault("USULNET_LOG_FORMAT", "json"), "Log format (json, console)")
	rootCmd.PersistentFlags().StringVar(&dataDir, "data-dir", envOrDefault("USULNET_DATA_DIR", "/var/lib/usulnet-agent"), "Data directory for local state")

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(validateConfigCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "usulnet-agent:", err)
		os.Exit(1)
	}
}
