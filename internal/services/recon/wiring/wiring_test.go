// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package wiring

import (
	"context"
	"sync/atomic"
	"testing"

	dockerpkg "github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/recon"
	reconsandbox "github.com/fr4nsys/usulnet/internal/services/recon/sandbox"
)

// countingFactory wraps a no-op launcher and counts construction
// invocations. It is the test double called out by the session-08
// acceptance criteria: "assert via a counting test double for the
// launcher" that Enabled=false never touches it.
type countingFactory struct {
	calls atomic.Int32
}

func (c *countingFactory) Build(_ *dockerpkg.Client, _ reconsandbox.Config, _ *logger.Logger) (recon.ContainerLauncher, error) {
	c.calls.Add(1)
	return nil, nil
}

func TestBuild_DisabledShortCircuits(t *testing.T) {
	factory := &countingFactory{}
	cfg := Config{Enabled: false}
	mod, err := Build(context.Background(), cfg, Deps{
		LauncherFact: factory.Build,
		Logger:       logger.Nop(),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if mod != nil {
		t.Fatalf("expected nil module when disabled, got %#v", mod)
	}
	if got := factory.calls.Load(); got != 0 {
		t.Fatalf("launcher factory called %d times when disabled; want 0", got)
	}
}

func TestBuild_EnabledNoDocker_ConstructsVerifiersOnly(t *testing.T) {
	factory := &countingFactory{}
	cfg := Config{
		Enabled:         true,
		RetentionDays:   90,
		InstallationOrg: "Acme Corp",
		BaseURL:         "https://u.example",
	}
	mod, err := Build(context.Background(), cfg, Deps{
		LauncherFact: factory.Build,
		Logger:       logger.Nop(),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if mod == nil {
		t.Fatalf("expected non-nil module")
	}
	if mod.Launcher != nil {
		t.Fatalf("no docker client should mean no launcher")
	}
	// Factory must not be called when DockerClient is nil.
	if got := factory.calls.Load(); got != 0 {
		t.Fatalf("launcher factory called %d times without docker client; want 0", got)
	}
	if mod.MetadataService != nil {
		t.Fatalf("metadata service should not exist without a DB")
	}
	if mod.ReconScanService != nil {
		t.Fatalf("recon scan service is stubbed pending S02; want nil")
	}

	// All five verifiers are present even without a DB / docker.
	wantMethods := []recon.OwnershipMethod{
		recon.OwnershipDNSTXT,
		recon.OwnershipEmailLink,
		recon.OwnershipRDAPMatch,
		recon.OwnershipAdminAttest,
		recon.OwnershipSelfAssert,
	}
	for _, m := range wantMethods {
		v, ok := mod.Verifiers[m]
		if !ok {
			t.Fatalf("missing verifier: %s", m)
		}
		if v.Method() != m {
			t.Fatalf("verifier method mismatch: got %s want %s", v.Method(), m)
		}
	}
	if mod.RDAPClient == nil {
		t.Fatalf("RDAP client missing")
	}
}
