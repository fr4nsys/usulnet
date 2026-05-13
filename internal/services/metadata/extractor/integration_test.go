// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

//go:build integration

package extractor_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/metadata"
	"github.com/fr4nsys/usulnet/internal/services/metadata/extractor"
	"github.com/fr4nsys/usulnet/internal/services/recon/sandbox"
)

// TestIntegration_Extractor_JPEG exercises the dispatch+exiftool path
// against the real recon-toolkit image on a 1×1 JPEG fixture. Skips
// when docker is unreachable or USULNET_SKIP_DOCKER_TESTS is set.
func TestIntegration_Extractor_JPEG(t *testing.T) {
	if os.Getenv("USULNET_SKIP_DOCKER_TESTS") != "" {
		t.Skip("USULNET_SKIP_DOCKER_TESTS set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
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

	// Stage the fixture in a temp dir whose basename is "original" so
	// the dispatcher's mount layout matches production.
	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join("testdata", "sample.jpg"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	original := filepath.Join(dir, "original")
	if err := os.WriteFile(original, src, 0o600); err != nil {
		t.Fatalf("stage fixture: %v", err)
	}

	exif, err := extractor.NewExifTool(l, image, 30*time.Second, logger.Nop())
	if err != nil {
		t.Fatalf("NewExifTool: %v", err)
	}
	d, err := extractor.NewDispatch(exif, nil, nil, logger.Nop())
	if err != nil {
		t.Fatalf("NewDispatch: %v", err)
	}
	out, err := d.Extract(ctx, metadata.ExtractInput{
		Path:     original,
		Filename: "sample.jpg",
		MIME:     "image/jpeg",
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if _, ok := out["exiftool"]; !ok {
		t.Errorf("expected exiftool key, got %v", out)
	}
}
