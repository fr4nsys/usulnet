// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

//go:build integration

package spiderfoot_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/recon"
	"github.com/fr4nsys/usulnet/internal/services/recon/engine/spiderfoot"
	"github.com/fr4nsys/usulnet/internal/services/recon/sandbox"
)

// TestIntegration_SpiderFoot_DNSResolve spins up the real
// usulnet/recon-spiderfoot image via the Session 05 launcher, runs a
// minimal DNS-resolve scan against example.com, and asserts at least
// one event lands within 60 seconds. Skipped automatically when the
// docker daemon isn't reachable or USULNET_SKIP_DOCKER_TESTS is set.
func TestIntegration_SpiderFoot_DNSResolve(t *testing.T) {
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

	image := os.Getenv("USULNET_TEST_SPIDERFOOT_IMAGE")
	if image == "" {
		// Default to the floating dev tag produced by the local
		// `make docker-build-recon`; CI overrides via env.
		image = "ghcr.io/fr4nsys/usulnet-recon-spiderfoot:dev"
	}
	if err := client.ImagePullSync(ctx, image, docker.ImagePullOptions{}); err != nil {
		// Tolerate "manifest unknown" when running against a locally
		// built image not yet pushed; the launcher will use the
		// existing local image instead.
		if !strings.Contains(err.Error(), "manifest unknown") &&
			!strings.Contains(err.Error(), "not found") {
			t.Logf("ImagePullSync: %v (continuing in case the image is local-only)", err)
		}
	}

	l, err := sandbox.NewLauncher(client, sandbox.Config{}, logger.Nop())
	if err != nil {
		t.Fatalf("NewLauncher: %v", err)
	}

	spec := recon.ContainerSpec{
		Image:   image,
		Command: nil, // image entrypoint starts SpiderFoot's HTTP API on :5001
		Labels:  map[string]string{"usulnet.recon.test": "spiderfoot-dns"},
		Timeout: 4 * time.Minute,
	}
	containerID, err := l.EnsureRunning(ctx, spec)
	if err != nil {
		t.Fatalf("EnsureRunning: %v", err)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopCancel()
		_ = l.Stop(stopCtx, containerID)
	}()

	// Resolve the container's IP on the recon bridge by inspecting
	// it; the docker client exposes the network details via the
	// containers list.
	addr, err := waitForListener(ctx, containerID, client, 5001, 90*time.Second)
	if err != nil {
		t.Fatalf("waitForListener: %v", err)
	}

	c, err := spiderfoot.NewClient("http://"+addr, 10*time.Second)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	e, err := spiderfoot.New(c, spiderfoot.Options{
		PollInterval:  2 * time.Second,
		CancelTimeout: 30 * time.Second,
	}, logger.Nop())
	if err != nil {
		t.Fatalf("New engine: %v", err)
	}

	req := recon.EngineStartRequest{
		Target: recon.Target{
			ID:    uuid.New(),
			Type:  recon.TargetDomain,
			Value: "example.com",
		},
		Profile: recon.Profile{
			Name:    "integration-dns-only",
			Modules: []string{"sfp_dnsresolve"},
		},
	}
	runID, err := e.Start(ctx, req)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Logf("started SpiderFoot scan run_id=%s", runID)

	deadlineCtx, deadlineCancel := context.WithTimeout(ctx, 60*time.Second)
	defer deadlineCancel()

	ch, err := e.Events(deadlineCtx, runID)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}

	select {
	case evt, ok := <-ch:
		if !ok {
			t.Fatal("Events channel closed before any event arrived")
		}
		t.Logf("first event: module=%s type=%s value=%s", evt.Module, evt.Category, evt.Value)
	case <-deadlineCtx.Done():
		t.Fatal("no event from SpiderFoot within 60s")
	}

	// Drain the channel so the engine goroutine exits.
	cancelCtx, cancelCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelCancel()
	if err := e.Cancel(cancelCtx, runID); err != nil && !errors.Is(err, spiderfoot.ErrScanNotFound) {
		t.Logf("Cancel: %v", err)
	}
	for range ch {
	}
}

// waitForListener polls until the container's recon-network IP
// accepts TCP connections on port. Returns the host:port the
// SpiderFoot client should hit.
func waitForListener(ctx context.Context, containerID string, c *docker.Client, port int, max time.Duration) (string, error) {
	deadline := time.Now().Add(max)
	for {
		list, err := c.ContainerList(ctx, docker.ContainerListOptions{
			All: false,
			Filters: map[string][]string{
				"id": {containerID},
			},
		})
		if err == nil {
			for _, cnt := range list {
				ip := pickContainerIP(cnt)
				if ip == "" {
					continue
				}
				addr := fmt.Sprintf("%s:%d", ip, port)
				dialCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
				conn, derr := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
				cancel()
				if derr == nil {
					_ = conn.Close()
					return addr, nil
				}
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("listener on port %d not ready within %s", port, max)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// pickContainerIP returns the first non-empty network IP attached to
// the container. The docker.Container type is treated structurally
// because its exact shape lives in the docker client package.
func pickContainerIP(cnt docker.Container) string {
	for _, n := range cnt.Networks {
		if n.IPAddress != "" {
			return n.IPAddress
		}
	}
	return ""
}
