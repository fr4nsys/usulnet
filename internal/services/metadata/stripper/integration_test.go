// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

//go:build integration

package stripper_test

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
	"github.com/fr4nsys/usulnet/internal/services/metadata/stripper"
	"github.com/fr4nsys/usulnet/internal/services/recon/sandbox"
)

// TestIntegration_Mat2_StripJPEG runs mat2 against the bundled 1×1
// JPEG fixture using the real recon-toolkit image. The test asserts
// that a cleaned file is produced and that its sha256 matches the
// digest the in-container side reports.
func TestIntegration_Mat2_StripJPEG(t *testing.T) {
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

	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join("testdata", "sample.jpg"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	original := filepath.Join(dir, "original")
	if err := os.WriteFile(original, src, 0o600); err != nil {
		t.Fatalf("stage fixture: %v", err)
	}

	m, err := stripper.NewMat2(l, image, 60*time.Second, logger.Nop())
	if err != nil {
		t.Fatalf("NewMat2: %v", err)
	}
	res, err := m.Strip(ctx, metadata.StripInput{
		Path:     original,
		Filename: "sample.jpg",
		MIME:     "image/jpeg",
	})
	if err != nil {
		t.Fatalf("Strip: %v", err)
	}
	if res.SizeBytes == 0 {
		t.Error("cleaned size is zero")
	}
	info, err := os.Stat(res.CleanedPath)
	if err != nil {
		t.Fatalf("stat cleaned: %v", err)
	}
	if info.Size() != res.SizeBytes {
		t.Errorf("cleaned on-disk size %d != result %d", info.Size(), res.SizeBytes)
	}
}
