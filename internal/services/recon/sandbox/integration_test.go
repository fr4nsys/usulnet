// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

//go:build integration

package sandbox_test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/recon"
	"github.com/fr4nsys/usulnet/internal/services/recon/sandbox"
)

// TestRunOnce_AlpineHello pulls alpine and runs `echo hello` through
// the launcher.  Skips if the docker daemon is not reachable.
func TestRunOnce_AlpineHello(t *testing.T) {
	if os.Getenv("USULNET_SKIP_DOCKER_TESTS") != "" {
		t.Skip("USULNET_SKIP_DOCKER_TESTS set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client, err := docker.NewLocalClient(ctx)
	if err != nil {
		t.Skipf("no docker daemon: %v", err)
	}
	defer client.Close() //nolint:errcheck

	if err := client.Ping(ctx); err != nil {
		t.Skipf("docker ping failed: %v", err)
	}

	// Make sure the image is available.
	if err := client.ImagePullSync(ctx, "alpine:3.21", docker.ImagePullOptions{}); err != nil {
		t.Fatalf("ImagePullSync alpine: %v", err)
	}

	l, err := sandbox.NewLauncher(client, sandbox.Config{}, logger.Nop())
	if err != nil {
		t.Fatalf("NewLauncher: %v", err)
	}

	spec := recon.ContainerSpec{
		Image:   "alpine:3.21",
		Command: []string{"echo", "hello"},
		Timeout: 30 * time.Second,
		Labels:  map[string]string{"usulnet.recon.test": "alpine-hello"},
	}

	out, code, err := l.RunOnce(ctx, spec)
	if err != nil {
		t.Fatalf("RunOnce: %v (output=%q)", err, out)
	}
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !bytes.Contains(out, []byte("hello")) {
		t.Errorf("output = %q, want to contain 'hello'", out)
	}
}
