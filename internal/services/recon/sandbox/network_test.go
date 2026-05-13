// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package sandbox

import (
	"context"
	"errors"
	"testing"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

func TestEnsureNetwork_ReturnsExisting(t *testing.T) {
	fd := &fakeDocker{
		netGetResp: &docker.Network{ID: "net-1", Name: DefaultNetworkName},
	}
	l := mustLauncher(t, fd)

	name, err := l.ensureNetwork(context.Background())
	if err != nil {
		t.Fatalf("ensureNetwork: %v", err)
	}
	if name != DefaultNetworkName {
		t.Errorf("name = %q, want %q", name, DefaultNetworkName)
	}
	if fd.netCalls != 0 {
		t.Errorf("expected no NetworkCreate, got %d", fd.netCalls)
	}
}

func TestEnsureNetwork_CreatesWhenAbsent(t *testing.T) {
	fd := &fakeDocker{
		netGetErr: errors.New("network not found"),
	}
	l := mustLauncher(t, fd)

	name, err := l.ensureNetwork(context.Background())
	if err != nil {
		t.Fatalf("ensureNetwork: %v", err)
	}
	if name != DefaultNetworkName {
		t.Errorf("name = %q, want %q", name, DefaultNetworkName)
	}
	if fd.netCalls != 1 {
		t.Errorf("NetworkCreate calls = %d, want 1", fd.netCalls)
	}
}

func TestEnsureNetwork_CreateFailure(t *testing.T) {
	fd := &fakeDocker{
		netGetErr: errors.New("network not found"),
		netCreErr: errors.New("driver init failed"),
	}
	l := mustLauncher(t, fd)

	_, err := l.ensureNetwork(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEnsureNetwork_LooseSubnetConfigurable(t *testing.T) {
	fd := &fakeDocker{
		netGetErr: errors.New("not found"),
	}
	l, err := newLauncher(fd, Config{NetworkSubnet: "10.99.0.0/24"}, logger.Nop())
	if err != nil {
		t.Fatalf("newLauncher: %v", err)
	}

	if _, err := l.ensureNetwork(context.Background()); err != nil {
		t.Fatalf("ensureNetwork: %v", err)
	}
	// We cannot read the create options back through fakeDocker
	// without exposing them; instead just assert the call happened.
	if fd.netCalls != 1 {
		t.Fatal("expected NetworkCreate to be called")
	}
}

func TestContains(t *testing.T) {
	cases := []struct {
		hay, needle string
		want        bool
	}{
		{"hello world", "world", true},
		{"hello", "world", false},
		{"abc", "", true},
		{"abc", "abcd", false},
		{"network not found", "not found", true},
	}
	for _, c := range cases {
		if got := contains(c.hay, c.needle); got != c.want {
			t.Errorf("contains(%q, %q) = %v, want %v", c.hay, c.needle, got, c.want)
		}
	}
}

func TestIsNotFound(t *testing.T) {
	if !isNotFound(errors.New("Error: No such network: x")) {
		t.Error("substring detection failed for docker not-found phrasing")
	}
	if !isNotFound(errNetworkNotFound) {
		t.Error("typed sentinel not detected")
	}
	if isNotFound(nil) {
		t.Error("nil should not be not-found")
	}
}
