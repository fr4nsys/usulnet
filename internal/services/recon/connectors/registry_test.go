// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package connectors

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// fakeConnector is the minimum recon.Connector to drive Registry tests.
type fakeConnector struct {
	kind    string
	enabled bool
	hcErr   error
	hcCalls int
}

func (f *fakeConnector) Kind() string  { return f.kind }
func (f *fakeConnector) Enabled() bool { return f.enabled }
func (f *fakeConnector) HealthCheck(_ context.Context) error {
	f.hcCalls++
	return f.hcErr
}

// fakeStore captures Save and Delete calls so SetConnector /
// DeleteConnector paths can be asserted.
type fakeStore struct {
	mu        sync.Mutex
	saves     []saveCall
	deletes   []string
	saveErr   error
	deleteErr error
}

type saveCall struct {
	kind    string
	creds   map[string]string
	enabled bool
}

func (s *fakeStore) Save(_ context.Context, kind string, creds map[string]string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves = append(s.saves, saveCall{kind: kind, creds: creds, enabled: enabled})
	return s.saveErr
}

func (s *fakeStore) Delete(_ context.Context, kind string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes = append(s.deletes, kind)
	return s.deleteErr
}

func TestRegistry_Register_RejectsDuplicate(t *testing.T) {
	r := NewRegistry(nil, nil)
	a := &fakeConnector{kind: "a"}
	if err := r.Register(a); err != nil {
		t.Fatalf("Register a: %v", err)
	}
	if err := r.Register(a); err == nil {
		t.Fatal("duplicate Register should error")
	}
}

func TestRegistry_Register_RejectsNilOrEmpty(t *testing.T) {
	r := NewRegistry(nil, nil)
	if err := r.Register(nil); err == nil {
		t.Error("nil connector accepted")
	}
	if err := r.Register(&fakeConnector{kind: ""}); err == nil {
		t.Error("empty kind accepted")
	}
}

func TestRegistry_Get(t *testing.T) {
	r := NewRegistry(nil, nil)
	c := &fakeConnector{kind: "hibp"}
	_ = r.Register(c)
	got, ok := r.Get("hibp")
	if !ok || got != c {
		t.Errorf("Get hibp: got %v ok=%v", got, ok)
	}
	if _, ok := r.Get("missing"); ok {
		t.Error("Get missing should be false")
	}
}

func TestRegistry_ListConnectors_HealthCheckOnlyWhenEnabled(t *testing.T) {
	r := NewRegistry(nil, nil)
	on := &fakeConnector{kind: "on", enabled: true}
	off := &fakeConnector{kind: "off", enabled: false}
	_ = r.Register(on)
	_ = r.Register(off)

	infos, err := r.ListConnectors(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("got %d infos, want 2", len(infos))
	}

	// Sorted by kind.
	if infos[0].Kind != "off" || infos[1].Kind != "on" {
		t.Errorf("order = %q,%q", infos[0].Kind, infos[1].Kind)
	}
	if off.hcCalls != 0 {
		t.Errorf("disabled connector got %d health checks; want 0", off.hcCalls)
	}
	if on.hcCalls != 1 {
		t.Errorf("enabled connector got %d health checks; want 1", on.hcCalls)
	}
	if !infos[1].Healthy {
		t.Error("enabled+no-err should be Healthy=true")
	}
}

func TestRegistry_ListConnectors_UnhealthyOnError(t *testing.T) {
	r := NewRegistry(nil, nil)
	c := &fakeConnector{kind: "hibp", enabled: true, hcErr: errors.New("401")}
	_ = r.Register(c)
	infos, err := r.ListConnectors(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if infos[0].Healthy {
		t.Error("HealthCheck returned an error; Healthy should be false")
	}
}

func TestRegistry_SetConnector_PersistsThroughStore(t *testing.T) {
	store := &fakeStore{}
	r := NewRegistry(store, nil)
	_ = r.Register(&fakeConnector{kind: "hibp"})

	creds := map[string]string{"api_key": "abc"}
	if err := r.SetConnector(context.Background(), "hibp", creds, true); err != nil {
		t.Fatalf("SetConnector: %v", err)
	}
	if len(store.saves) != 1 {
		t.Fatalf("saves = %d, want 1", len(store.saves))
	}
	if store.saves[0].kind != "hibp" || store.saves[0].creds["api_key"] != "abc" || !store.saves[0].enabled {
		t.Errorf("unexpected save: %+v", store.saves[0])
	}
}

func TestRegistry_SetConnector_UnknownKind(t *testing.T) {
	r := NewRegistry(&fakeStore{}, nil)
	err := r.SetConnector(context.Background(), "missing", nil, true)
	if !errors.Is(err, ErrUnknownKind) {
		t.Errorf("err = %v, want ErrUnknownKind", err)
	}
}

func TestRegistry_SetConnector_NoStore(t *testing.T) {
	r := NewRegistry(nil, nil)
	_ = r.Register(&fakeConnector{kind: "hibp"})
	err := r.SetConnector(context.Background(), "hibp", nil, true)
	if !errors.Is(err, ErrNoCredentialStore) {
		t.Errorf("err = %v, want ErrNoCredentialStore", err)
	}
}

func TestRegistry_DeleteConnector_PersistsThroughStore(t *testing.T) {
	store := &fakeStore{}
	r := NewRegistry(store, nil)
	_ = r.Register(&fakeConnector{kind: "hibp"})

	if err := r.DeleteConnector(context.Background(), "hibp"); err != nil {
		t.Fatalf("DeleteConnector: %v", err)
	}
	if len(store.deletes) != 1 || store.deletes[0] != "hibp" {
		t.Errorf("deletes = %v, want [hibp]", store.deletes)
	}
}

func TestRegistry_DeleteConnector_UnknownKind(t *testing.T) {
	r := NewRegistry(&fakeStore{}, nil)
	err := r.DeleteConnector(context.Background(), "missing")
	if !errors.Is(err, ErrUnknownKind) {
		t.Errorf("err = %v, want ErrUnknownKind", err)
	}
}

func TestRegistry_DeleteConnector_NoStore(t *testing.T) {
	r := NewRegistry(nil, nil)
	_ = r.Register(&fakeConnector{kind: "hibp"})
	err := r.DeleteConnector(context.Background(), "hibp")
	if !errors.Is(err, ErrNoCredentialStore) {
		t.Errorf("err = %v, want ErrNoCredentialStore", err)
	}
}

// Compile-time assertion: fakeConnector satisfies recon.Connector.
var _ recon.Connector = (*fakeConnector)(nil)
