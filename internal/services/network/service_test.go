// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package network

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

type mockHostProvider struct {
	client docker.ClientAPI
	err    error
}

func (m *mockHostProvider) GetClient(_ context.Context, _ uuid.UUID) (docker.ClientAPI, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.client, nil
}

// mockDockerClient implements docker.ClientAPI by embedding the interface and
// overriding only the methods used by the network service.
type mockDockerClient struct {
	docker.ClientAPI // embedded — panics if unimplemented method called

	networkListResult []docker.Network
	networkListErr    error
	networkGetResult  *docker.Network
	networkGetErr     error
	networkGetByName  *docker.Network
	networkGetByNameE error
	networkCreateRet  *docker.Network
	networkCreateErr  error
	networkRemoveErr  error
	networkConnectErr error
	networkDisconnErr error
	networkPruneRet   []string
	networkPruneErr   error
	networkExistsRet  bool
	networkExistsErr  error
	networkTopoRet    map[string][]string
	networkTopoErr    error
}

func (m *mockDockerClient) NetworkList(_ context.Context, _ docker.NetworkListOptions) ([]docker.Network, error) {
	return m.networkListResult, m.networkListErr
}

func (m *mockDockerClient) NetworkGet(_ context.Context, _ string) (*docker.Network, error) {
	return m.networkGetResult, m.networkGetErr
}

func (m *mockDockerClient) NetworkGetByName(_ context.Context, _ string) (*docker.Network, error) {
	return m.networkGetByName, m.networkGetByNameE
}

func (m *mockDockerClient) NetworkCreate(_ context.Context, _ docker.NetworkCreateOptions) (*docker.Network, error) {
	return m.networkCreateRet, m.networkCreateErr
}

func (m *mockDockerClient) NetworkRemove(_ context.Context, _ string) error {
	return m.networkRemoveErr
}

func (m *mockDockerClient) NetworkConnect(_ context.Context, _ string, _ docker.NetworkConnectOptions) error {
	return m.networkConnectErr
}

func (m *mockDockerClient) NetworkDisconnect(_ context.Context, _, _ string, _ bool) error {
	return m.networkDisconnErr
}

func (m *mockDockerClient) NetworkPrune(_ context.Context, _ map[string][]string) ([]string, error) {
	return m.networkPruneRet, m.networkPruneErr
}

func (m *mockDockerClient) NetworkExists(_ context.Context, _ string) (bool, error) {
	return m.networkExistsRet, m.networkExistsErr
}

func (m *mockDockerClient) NetworkTopology(_ context.Context) (map[string][]string, error) {
	return m.networkTopoRet, m.networkTopoErr
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestService(client *mockDockerClient) *Service {
	return NewService(&mockHostProvider{client: client}, logger.Nop())
}

func testHostID() uuid.UUID {
	return uuid.MustParse("00000000-0000-0000-0000-000000000001")
}

// ---------------------------------------------------------------------------
// Interface compliance
// ---------------------------------------------------------------------------

func TestMock_InterfaceCompliance(t *testing.T) {
	var _ HostClientProvider = (*mockHostProvider)(nil)
}

// ---------------------------------------------------------------------------
// Tests: NewService
// ---------------------------------------------------------------------------

func TestNewService(t *testing.T) {
	svc := NewService(&mockHostProvider{}, nil) // nil logger should default
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

// ---------------------------------------------------------------------------
// Tests: List
// ---------------------------------------------------------------------------

func TestList_HappyPath(t *testing.T) {
	client := &mockDockerClient{
		networkListResult: []docker.Network{
			{ID: "net1", Name: "bridge", Driver: "bridge"},
			{ID: "net2", Name: "mynet", Driver: "overlay"},
		},
		networkGetErr: fmt.Errorf("inspect not available"), // fallback to list data
	}
	svc := newTestService(client)

	nets, err := svc.List(context.Background(), testHostID())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 2 {
		t.Fatalf("expected 2 networks, got %d", len(nets))
	}
	if nets[0].Name != "bridge" {
		t.Errorf("first network = %q, want %q", nets[0].Name, "bridge")
	}
}

func TestList_HostClientError(t *testing.T) {
	svc := NewService(&mockHostProvider{err: fmt.Errorf("host offline")}, logger.Nop())

	_, err := svc.List(context.Background(), testHostID())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "host offline") {
		t.Errorf("error = %q, want 'host offline'", err.Error())
	}
}

func TestList_DockerError(t *testing.T) {
	client := &mockDockerClient{networkListErr: fmt.Errorf("docker daemon error")}
	svc := newTestService(client)

	_, err := svc.List(context.Background(), testHostID())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "list networks") {
		t.Errorf("error = %q, want wrapped with 'list networks'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Tests: Get
// ---------------------------------------------------------------------------

func TestGet_HappyPath(t *testing.T) {
	client := &mockDockerClient{
		networkGetResult: &docker.Network{
			ID:     "net1",
			Name:   "mynet",
			Driver: "bridge",
			IPAM: docker.IPAMConfig{
				Config: []docker.IPAMPoolConfig{{Subnet: "172.28.0.0/16", Gateway: "172.28.0.1"}},
			},
		},
	}
	svc := newTestService(client)

	net, err := svc.Get(context.Background(), testHostID(), "net1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if net.Name != "mynet" {
		t.Errorf("name = %q, want %q", net.Name, "mynet")
	}
	if len(net.IPAM.Config) != 1 {
		t.Fatalf("expected 1 IPAM config, got %d", len(net.IPAM.Config))
	}
	if net.IPAM.Config[0].Subnet != "172.28.0.0/16" {
		t.Errorf("subnet = %q, want %q", net.IPAM.Config[0].Subnet, "172.28.0.0/16")
	}
}

func TestGet_NotFound(t *testing.T) {
	client := &mockDockerClient{networkGetErr: fmt.Errorf("network not found")}
	svc := newTestService(client)

	_, err := svc.Get(context.Background(), testHostID(), "nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Tests: GetByName
// ---------------------------------------------------------------------------

func TestGetByName_HappyPath(t *testing.T) {
	client := &mockDockerClient{
		networkGetByName: &docker.Network{ID: "net1", Name: "mynet"},
	}
	svc := newTestService(client)

	net, err := svc.GetByName(context.Background(), testHostID(), "mynet")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if net.ID != "net1" {
		t.Errorf("ID = %q, want %q", net.ID, "net1")
	}
}

// ---------------------------------------------------------------------------
// Tests: Create
// ---------------------------------------------------------------------------

func TestCreate_HappyPath(t *testing.T) {
	client := &mockDockerClient{
		networkCreateRet: &docker.Network{
			ID:     "newnet1",
			Name:   "testnet",
			Driver: "bridge",
		},
	}
	svc := newTestService(client)

	input := &models.CreateNetworkInput{
		Name:   "testnet",
		Driver: "bridge",
		Labels: map[string]string{"env": "test"},
	}

	net, err := svc.Create(context.Background(), testHostID(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if net.Name != "testnet" {
		t.Errorf("name = %q, want %q", net.Name, "testnet")
	}
}

func TestCreate_WithIPAM(t *testing.T) {
	client := &mockDockerClient{
		networkCreateRet: &docker.Network{
			ID:     "ipamnet",
			Name:   "custom-net",
			Driver: "bridge",
		},
	}
	svc := newTestService(client)

	input := &models.CreateNetworkInput{
		Name:   "custom-net",
		Driver: "bridge",
		IPAM: &models.NetworkIPAMInput{
			Driver: "default",
			Config: []models.IPAMConfigInput{
				{Subnet: "10.0.0.0/24", Gateway: "10.0.0.1"},
			},
		},
	}

	net, err := svc.Create(context.Background(), testHostID(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if net.ID != "ipamnet" {
		t.Errorf("ID = %q, want %q", net.ID, "ipamnet")
	}
}

func TestCreate_Error(t *testing.T) {
	client := &mockDockerClient{networkCreateErr: fmt.Errorf("driver not found")}
	svc := newTestService(client)

	_, err := svc.Create(context.Background(), testHostID(), &models.CreateNetworkInput{Name: "fail"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "create network") {
		t.Errorf("error = %q, want wrapped", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Tests: Delete
// ---------------------------------------------------------------------------

func TestDelete_HappyPath(t *testing.T) {
	client := &mockDockerClient{}
	svc := newTestService(client)

	err := svc.Delete(context.Background(), testHostID(), "net1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDelete_Error(t *testing.T) {
	client := &mockDockerClient{networkRemoveErr: fmt.Errorf("network in use")}
	svc := newTestService(client)

	err := svc.Delete(context.Background(), testHostID(), "net1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "remove network") {
		t.Errorf("error = %q, want wrapped", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Tests: Connect / Disconnect
// ---------------------------------------------------------------------------

func TestConnect_HappyPath(t *testing.T) {
	client := &mockDockerClient{}
	svc := newTestService(client)

	err := svc.Connect(context.Background(), testHostID(), "net1", "container1", []string{"alias1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConnect_Error(t *testing.T) {
	client := &mockDockerClient{networkConnectErr: fmt.Errorf("already connected")}
	svc := newTestService(client)

	err := svc.Connect(context.Background(), testHostID(), "net1", "c1", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestDisconnect_HappyPath(t *testing.T) {
	client := &mockDockerClient{}
	svc := newTestService(client)

	err := svc.Disconnect(context.Background(), testHostID(), "net1", "c1", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDisconnect_Error(t *testing.T) {
	client := &mockDockerClient{networkDisconnErr: fmt.Errorf("not connected")}
	svc := newTestService(client)

	err := svc.Disconnect(context.Background(), testHostID(), "net1", "c1", true)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Tests: Prune
// ---------------------------------------------------------------------------

func TestPrune_HappyPath(t *testing.T) {
	client := &mockDockerClient{
		networkPruneRet: []string{"net1", "net2"},
	}
	svc := newTestService(client)

	result, err := svc.Prune(context.Background(), testHostID())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ItemsDeleted) != 2 {
		t.Errorf("expected 2 pruned networks, got %d", len(result.ItemsDeleted))
	}
}

func TestPrune_Error(t *testing.T) {
	client := &mockDockerClient{networkPruneErr: fmt.Errorf("prune failed")}
	svc := newTestService(client)

	_, err := svc.Prune(context.Background(), testHostID())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Tests: Exists
// ---------------------------------------------------------------------------

func TestExists_True(t *testing.T) {
	client := &mockDockerClient{networkExistsRet: true}
	svc := newTestService(client)

	exists, err := svc.Exists(context.Background(), testHostID(), "net1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected true, got false")
	}
}

func TestExists_False(t *testing.T) {
	client := &mockDockerClient{networkExistsRet: false}
	svc := newTestService(client)

	exists, err := svc.Exists(context.Background(), testHostID(), "net1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Error("expected false, got true")
	}
}

// ---------------------------------------------------------------------------
// Tests: GetTopology
// ---------------------------------------------------------------------------

func TestGetTopology_HappyPath(t *testing.T) {
	client := &mockDockerClient{
		networkTopoRet: map[string][]string{
			"bridge": {"container1", "container2"},
			"mynet":  {"container3"},
		},
	}
	svc := newTestService(client)

	topo, err := svc.GetTopology(context.Background(), testHostID())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(topo) != 2 {
		t.Errorf("expected 2 networks in topology, got %d", len(topo))
	}
}

// ---------------------------------------------------------------------------
// Tests: dockerToModel conversion
// ---------------------------------------------------------------------------

func TestDockerToModel_BasicFields(t *testing.T) {
	svc := newTestService(&mockDockerClient{})
	hostID := testHostID()
	now := time.Now()

	n := &docker.Network{
		ID:         "abc123",
		Name:       "test-net",
		Driver:     "bridge",
		Scope:      "local",
		EnableIPv6: true,
		Internal:   true,
		Attachable: true,
		Labels:     map[string]string{"env": "prod"},
		Options:    map[string]string{"opt1": "val1"},
		Created:    now,
	}

	model := svc.dockerToModel(n, hostID)
	if model.ID != "abc123" {
		t.Errorf("ID = %q, want %q", model.ID, "abc123")
	}
	if model.HostID != hostID {
		t.Errorf("HostID = %v, want %v", model.HostID, hostID)
	}
	if model.Name != "test-net" {
		t.Errorf("Name = %q, want %q", model.Name, "test-net")
	}
	if !model.EnableIPv6 {
		t.Error("expected EnableIPv6=true")
	}
	if !model.Internal {
		t.Error("expected Internal=true")
	}
}

func TestDockerToModel_WithContainers(t *testing.T) {
	svc := newTestService(&mockDockerClient{})

	n := &docker.Network{
		ID:   "net1",
		Name: "bridge",
		Containers: map[string]docker.NetworkContainer{
			"c1": {Name: "/mycontainer", EndpointID: "ep1", IPv4Address: "172.17.0.2/16"},
		},
	}

	model := svc.dockerToModel(n, testHostID())
	if len(model.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(model.Containers))
	}
	c := model.Containers["c1"]
	// Leading slash should be stripped.
	if c.Name != "mycontainer" {
		t.Errorf("container name = %q, want %q (should strip leading /)", c.Name, "mycontainer")
	}
	if c.IPv4Address != "172.17.0.2/16" {
		t.Errorf("IPv4 = %q", c.IPv4Address)
	}
}

func TestDockerToModel_WithIPAM(t *testing.T) {
	svc := newTestService(&mockDockerClient{})

	n := &docker.Network{
		ID:   "net1",
		Name: "custom",
		IPAM: docker.IPAMConfig{
			Driver: "default",
			Config: []docker.IPAMPoolConfig{
				{Subnet: "10.0.0.0/24", Gateway: "10.0.0.1", IPRange: "10.0.0.128/25"},
			},
		},
	}

	model := svc.dockerToModel(n, testHostID())
	if model.IPAM.Driver != "default" {
		t.Errorf("IPAM driver = %q, want %q", model.IPAM.Driver, "default")
	}
	if len(model.IPAM.Config) != 1 {
		t.Fatalf("expected 1 IPAM config, got %d", len(model.IPAM.Config))
	}
	if model.IPAM.Config[0].Subnet != "10.0.0.0/24" {
		t.Errorf("subnet = %q", model.IPAM.Config[0].Subnet)
	}
}

// ---------------------------------------------------------------------------
// Tests: Pure functions — ValidateSubnet
// ---------------------------------------------------------------------------

func TestValidateSubnet(t *testing.T) {
	tests := []struct {
		name    string
		subnet  string
		wantErr bool
	}{
		{"valid /24", "10.0.0.0/24", false},
		{"valid /16", "172.16.0.0/16", false},
		{"valid /32", "192.168.1.1/32", false},
		{"empty", "", false},
		{"invalid", "not-a-cidr", true},
		{"missing mask", "10.0.0.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSubnet(tt.subnet)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSubnet(%q) error = %v, wantErr %v", tt.subnet, err, tt.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: Pure functions — ValidateGateway
// ---------------------------------------------------------------------------

func TestValidateGateway(t *testing.T) {
	tests := []struct {
		name    string
		gateway string
		subnet  string
		wantErr bool
	}{
		{"valid gateway in subnet", "10.0.0.1", "10.0.0.0/24", false},
		{"empty gateway", "", "10.0.0.0/24", false},
		{"empty both", "", "", false},
		{"gateway no subnet", "10.0.0.1", "", false},
		{"invalid gateway IP", "not-an-ip", "10.0.0.0/24", true},
		{"gateway outside subnet", "192.168.1.1", "10.0.0.0/24", true},
		{"invalid subnet", "10.0.0.1", "bad-cidr", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateGateway(tt.gateway, tt.subnet)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateGateway(%q, %q) error = %v, wantErr %v", tt.gateway, tt.subnet, err, tt.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: ListByDriver
// ---------------------------------------------------------------------------

func TestListByDriver_HappyPath(t *testing.T) {
	client := &mockDockerClient{
		networkListResult: []docker.Network{
			{ID: "net1", Name: "overlay-net", Driver: "overlay"},
		},
	}
	svc := newTestService(client)

	nets, err := svc.ListByDriver(context.Background(), testHostID(), "overlay")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 1 {
		t.Fatalf("expected 1 network, got %d", len(nets))
	}
}

// ---------------------------------------------------------------------------
// Tests: ListUserDefined
// ---------------------------------------------------------------------------

func TestListUserDefined_FiltersSystem(t *testing.T) {
	client := &mockDockerClient{
		networkListResult: []docker.Network{
			{ID: "n1", Name: "bridge", Driver: "bridge"},
			{ID: "n2", Name: "host", Driver: "host"},
			{ID: "n3", Name: "none", Driver: "null"},
			{ID: "n4", Name: "my-custom-net", Driver: "bridge"},
		},
	}
	svc := newTestService(client)

	nets, err := svc.ListUserDefined(context.Background(), testHostID())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should exclude bridge, host, none
	if len(nets) != 1 {
		t.Fatalf("expected 1 user-defined network, got %d", len(nets))
	}
	if nets[0].Name != "my-custom-net" {
		t.Errorf("name = %q, want %q", nets[0].Name, "my-custom-net")
	}
}
