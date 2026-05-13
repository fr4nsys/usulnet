// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/services/recon/connectors"
)

// Compile-time check: the postgres impl satisfies the registry's
// CredentialStore interface. The check guards against signature
// drift in either side.
var _ connectors.CredentialStore = (*postgres.ReconConnectorsRepository)(nil)

var reconConnectorTables = []string{"recon_connectors"}

func newConnectorsRepo(t *testing.T) *postgres.ReconConnectorsRepository {
	t.Helper()
	return postgres.NewReconConnectorsRepository(testDB, newTestEncryptor(t))
}

func TestReconConnectorsRepo_RoundTrip(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, reconConnectorTables...) })

	repo := newConnectorsRepo(t)
	ctx := context.Background()

	if err := repo.Save(ctx, "hibp", map[string]string{"api_key": "alpha"}, true); err != nil {
		t.Fatalf("Save: %v", err)
	}
	creds, enabled, err := repo.Load(ctx, "hibp")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !enabled {
		t.Error("enabled should be true after Save")
	}
	if got := creds["api_key"]; got != "alpha" {
		t.Errorf("api_key = %q, want alpha", got)
	}
}

func TestReconConnectorsRepo_UpsertOverwrites(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, reconConnectorTables...) })

	repo := newConnectorsRepo(t)
	ctx := context.Background()

	if err := repo.Save(ctx, "hibp", map[string]string{"api_key": "first"}, true); err != nil {
		t.Fatalf("Save (first): %v", err)
	}
	if err := repo.Save(ctx, "hibp", map[string]string{"api_key": "second"}, false); err != nil {
		t.Fatalf("Save (second): %v", err)
	}

	creds, enabled, err := repo.Load(ctx, "hibp")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if enabled {
		t.Error("enabled should be false after second Save")
	}
	if got := creds["api_key"]; got != "second" {
		t.Errorf("api_key = %q, want second", got)
	}
}

func TestReconConnectorsRepo_LoadEncryptsAtRest(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, reconConnectorTables...) })

	repo := newConnectorsRepo(t)
	ctx := context.Background()
	plain := "super-secret-key-9f3c"
	if err := repo.Save(ctx, "hibp", map[string]string{"api_key": plain}, true); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Read raw bytes back from the table to verify the plaintext never
	// touches the column. If anyone refactors seal() out of the write
	// path, this test breaks loudly.
	var cipher, nonce []byte
	if err := testDB.QueryRow(ctx,
		`SELECT credentials_encrypted, nonce FROM recon_connectors WHERE kind = $1`,
		"hibp",
	).Scan(&cipher, &nonce); err != nil {
		t.Fatalf("select raw: %v", err)
	}
	if bytes.Contains(cipher, []byte(plain)) {
		t.Error("plaintext appears in credentials_encrypted column")
	}
	if len(nonce) == 0 {
		t.Error("nonce column should be populated")
	}
}

func TestReconConnectorsRepo_LoadNotFound(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, reconConnectorTables...) })

	repo := newConnectorsRepo(t)
	_, _, err := repo.Load(context.Background(), "missing")
	if !errors.Is(err, postgres.ErrConnectorNotFound) {
		t.Errorf("err = %v, want ErrConnectorNotFound", err)
	}
}

func TestReconConnectorsRepo_Delete(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, reconConnectorTables...) })

	repo := newConnectorsRepo(t)
	ctx := context.Background()
	if err := repo.Save(ctx, "hibp", map[string]string{"api_key": "alpha"}, true); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := repo.Delete(ctx, "hibp"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, err := repo.Load(ctx, "hibp"); !errors.Is(err, postgres.ErrConnectorNotFound) {
		t.Errorf("Load after Delete = %v, want ErrConnectorNotFound", err)
	}
}

func TestReconConnectorsRepo_DeleteNotFound(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, reconConnectorTables...) })

	repo := newConnectorsRepo(t)
	if err := repo.Delete(context.Background(), "missing"); !errors.Is(err, postgres.ErrConnectorNotFound) {
		t.Errorf("err = %v, want ErrConnectorNotFound", err)
	}
}

func TestReconConnectorsRepo_List(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, reconConnectorTables...) })

	repo := newConnectorsRepo(t)
	ctx := context.Background()
	if err := repo.Save(ctx, "shodan", nil, false); err != nil {
		t.Fatalf("Save shodan: %v", err)
	}
	if err := repo.Save(ctx, "hibp", map[string]string{"api_key": "k"}, true); err != nil {
		t.Fatalf("Save hibp: %v", err)
	}

	rows, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	// Sorted ascending by kind.
	if rows[0].Kind != "hibp" || rows[1].Kind != "shodan" {
		t.Errorf("List order = %q,%q", rows[0].Kind, rows[1].Kind)
	}
	if !rows[0].Enabled {
		t.Error("hibp row should be enabled")
	}
	if rows[1].Enabled {
		t.Error("shodan row should be disabled")
	}
}

func TestReconConnectorsRepo_SaveEmptyCredsAllowed(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, reconConnectorTables...) })

	repo := newConnectorsRepo(t)
	ctx := context.Background()

	// Save with nil creds: operator wants to flip enabled without
	// resupplying the key.
	if err := repo.Save(ctx, "hibp", nil, false); err != nil {
		t.Fatalf("Save nil creds: %v", err)
	}
	creds, enabled, err := repo.Load(ctx, "hibp")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if enabled {
		t.Error("enabled should be false")
	}
	if len(creds) != 0 {
		t.Errorf("creds = %v, want empty map", creds)
	}
}
