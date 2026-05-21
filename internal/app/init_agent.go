// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"fmt"
	"os"
	"time"

	agentpkg "github.com/fr4nsys/usulnet/internal/agent"
	dockerpkg "github.com/fr4nsys/usulnet/internal/docker"
)

// startAgent connects to the master via NATS and runs the local agent
// runtime. The agent mode does not bring up the web UI or any of the
// standalone services; it only forwards Docker commands and inventory.
func (app *Application) startAgent(ctx context.Context) error {
	app.Logger.Info("Starting in agent mode")

	if app.Config.Agent.Token == "" {
		return fmt.Errorf("agent token required - configure agent.token in config or set USULNET_AGENT_TOKEN")
	}

	gatewayURL := app.Config.NATS.URL
	if app.Config.Agent.MasterURL != "" {
		gatewayURL = app.Config.Agent.MasterURL
	}
	if gatewayURL == "" {
		return fmt.Errorf("NATS URL required for agent mode - configure nats.url or agent.master_url")
	}

	agentCfg := agentpkg.Config{
		AgentID:    app.Config.Agent.ID,
		Token:      app.Config.Agent.Token,
		GatewayURL: gatewayURL,
		DockerHost: "unix://" + dockerpkg.LocalSocketPath(),
		Hostname:   app.Config.Agent.Name,
		LogLevel:   app.Config.Logging.Level,
		DataDir:    "/var/lib/usulnet-agent",
		TLS: agentpkg.TLSConfig{
			Enabled:  app.Config.Agent.TLSEnabled,
			CertFile: app.Config.Agent.TLSCertFile,
			KeyFile:  app.Config.Agent.TLSKeyFile,
			CAFile:   app.Config.Agent.TLSCAFile,
		},
	}

	if agentCfg.Hostname == "" {
		agentCfg.Hostname, _ = os.Hostname()
	}

	ag, err := agentpkg.New(agentCfg, app.Logger)
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}
	app.agentInstance = ag

	agentErrCh := make(chan error, 1)
	go func() {
		if err := ag.Run(ctx); err != nil {
			app.Logger.Error("Agent error", "error", err)
			agentErrCh <- err
		}
	}()

	select {
	case err := <-agentErrCh:
		return fmt.Errorf("agent failed to start: %w", err)
	case <-time.After(3 * time.Second):
		// Agent started successfully.
	}

	app.Logger.Info("Agent mode: connected and running",
		"agent_id", agentCfg.AgentID,
		"gateway", gatewayURL,
		"hostname", agentCfg.Hostname,
	)

	return nil
}
