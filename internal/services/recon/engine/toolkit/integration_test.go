// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

//go:build integration

package toolkit_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/recon"
	"github.com/fr4nsys/usulnet/internal/services/recon/engine/toolkit"
	"github.com/fr4nsys/usulnet/internal/services/recon/sandbox"
)

// TestIntegration_Toolkit_HoleheNonExistent runs the holehe wrapper
// against a clearly non-existent test email. holehe's network
// surface depends on the targeted password-reset endpoints, so we
// only assert the engine drives the run to completion (or an
// engine-internal error) without panicking; the precise event count
// is not stable across runs.
func TestIntegration_Toolkit_HoleheNonExistent(t *testing.T) {
	if os.Getenv("USULNET_SKIP_DOCKER_TESTS") != "" {
		t.Skip("USULNET_SKIP_DOCKER_TESTS set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	client, err := docker.NewLocalClient(ctx)
	if err != nil {
		t.Skipf("no docker daemon: %v", err)
	}
	defer client.Close() //nolint:errcheck

	if err := client.Ping(ctx); err != nil {
		t.Skipf("docker ping failed: %v", err)
	}

	image := os.Getenv("USULNET_TEST_TOOLKIT_IMAGE")
	if image == "" {
		image = "ghcr.io/fr4nsys/usulnet-recon-toolkit:dev"
	}
	if err := client.ImagePullSync(ctx, image, docker.ImagePullOptions{}); err != nil {
		if !strings.Contains(err.Error(), "manifest unknown") && !strings.Contains(err.Error(), "not found") {
			t.Logf("ImagePullSync: %v (continuing in case image is local-only)", err)
		}
	}

	l, err := sandbox.NewLauncher(client, sandbox.Config{}, logger.Nop())
	if err != nil {
		t.Fatalf("NewLauncher: %v", err)
	}
	e, err := toolkit.New(l, toolkit.Options{Image: image, RunTimeout: 2 * time.Minute}, logger.Nop())
	if err != nil {
		t.Fatalf("toolkit.New: %v", err)
	}

	runID, err := e.Start(ctx, recon.EngineStartRequest{
		Target: recon.Target{
			ID:    uuid.New(),
			Type:  recon.TargetEmail,
			Value: "usulnet-no-such-account@example.com",
		},
		Profile: recon.Profile{
			Name:    "integration-holehe",
			Modules: []string{"toolkit:holehe"},
		},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	st, err := e.Status(ctx, runID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	switch st.Status {
	case recon.ScanCompleted, recon.ScanFailed:
		// Both are acceptable: holehe sometimes hits rate limits from
		// upstream sites depending on test environment IP reputation.
	default:
		t.Errorf("status = %q, want completed or failed", st.Status)
	}

	// Drain the channel so the engine cleans up.
	ch, err := e.Events(ctx, runID)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	count := 0
	for range ch {
		count++
	}
	t.Logf("holehe emitted %d events for the non-existent test email", count)
}
