// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// reconTables lists every table the recon repository writes to. Used to
// reset state between tests.
var reconTables = []string{
	"recon_audit_log",
	"recon_findings_raw",
	"recon_findings",
	"recon_scan_summary",
	"recon_scans",
	"recon_ownership_proofs",
	"recon_targets",
}

// Compile-time interface check.
var _ recon.Repository = (*postgres.ReconRepository)(nil)

const testDEKHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newTestEncryptor(t *testing.T) *crypto.AESEncryptor {
	t.Helper()
	enc, err := crypto.NewAESEncryptor(testDEKHex)
	if err != nil {
		t.Fatalf("encryptor: %v", err)
	}
	return enc
}

func newReconRepo(t *testing.T) *postgres.ReconRepository {
	t.Helper()
	return postgres.NewReconRepository(testDB, newTestEncryptor(t))
}

// emailTarget builds an unsaved email target with hashed canonical value.
func emailTarget(value string) *recon.Target {
	return &recon.Target{
		Type:      recon.TargetEmail,
		Value:     recon.NormalizeValue(value),
		ValueHash: recon.HashValue(value),
		Label:     "test",
	}
}

// ============================================================================
// Targets
// ============================================================================

func TestReconRepo_TargetRoundTrip(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, reconTables...) })

	repo := newReconRepo(t)
	ctx := context.Background()

	tg := emailTarget("Alice@Example.com")
	if err := repo.InsertTarget(ctx, tg); err != nil {
		t.Fatalf("InsertTarget: %v", err)
	}
	if tg.ID == uuid.Nil {
		t.Fatal("expected ID to be set")
	}
	if tg.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be set")
	}

	got, err := repo.GetTargetByID(ctx, tg.ID)
	if err != nil {
		t.Fatalf("GetTargetByID: %v", err)
	}
	if got.Value != "alice@example.com" {
		t.Errorf("value = %q, want lowercased canonical form", got.Value)
	}
	if !bytes.Equal(got.ValueHash, tg.ValueHash) {
		t.Errorf("value_hash mismatch")
	}

	byHash, err := repo.GetTargetByHash(ctx, recon.TargetEmail, recon.HashValue("alice@example.com"))
	if err != nil {
		t.Fatalf("GetTargetByHash: %v", err)
	}
	if byHash.ID != tg.ID {
		t.Errorf("hash lookup ID mismatch")
	}
}

func TestReconRepo_TargetList_FilterByType(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, reconTables...) })

	repo := newReconRepo(t)
	ctx := context.Background()

	for _, v := range []string{"a@x.test", "b@x.test"} {
		if err := repo.InsertTarget(ctx, emailTarget(v)); err != nil {
			t.Fatalf("insert email target: %v", err)
		}
	}
	domain := &recon.Target{
		Type:      recon.TargetDomain,
		Value:     "example.test",
		ValueHash: recon.HashValue("example.test"),
	}
	if err := repo.InsertTarget(ctx, domain); err != nil {
		t.Fatalf("insert domain target: %v", err)
	}

	typ := recon.TargetEmail
	got, err := repo.ListTargets(ctx, recon.ListTargetsFilter{Type: &typ, Limit: 10})
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("len = %d, want 2", len(got))
	}
	for _, g := range got {
		if g.Type != recon.TargetEmail {
			t.Errorf("unexpected type %q in filtered result", g.Type)
		}
	}
}

// TestReconRepo_TargetCascadeDelete verifies that deleting a target removes
// its scans and findings (FK ON DELETE CASCADE in migration 044) while the
// audit log row is preserved with target_id set to NULL.
func TestReconRepo_TargetCascadeDelete(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, reconTables...) })

	repo := newReconRepo(t)
	ctx := context.Background()

	tg := emailTarget("cascade@example.test")
	if err := repo.InsertTarget(ctx, tg); err != nil {
		t.Fatalf("InsertTarget: %v", err)
	}
	profile := loadBuiltinProfile(t, repo, "email-exposure-lite")

	scan := &recon.Scan{TargetID: tg.ID, ProfileID: profile.ID}
	if err := repo.InsertScan(ctx, scan); err != nil {
		t.Fatalf("InsertScan: %v", err)
	}

	finding := &recon.Finding{
		ScanID:    scan.ID,
		TargetID:  tg.ID,
		Module:    "sfp_haveibeen",
		Category:  "BREACH",
		Severity:  recon.SeverityHigh,
		Value:     "leak.example.test",
		ValueHash: recon.HashValue("leak.example.test"),
	}
	if err := repo.UpsertFinding(ctx, finding, "spiderfoot", []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("UpsertFinding: %v", err)
	}

	if err := repo.AppendAudit(ctx, recon.AuditEntry{
		Action:   "scan.start",
		TargetID: &tg.ID,
		ScanID:   &scan.ID,
	}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}

	if err := repo.DeleteTarget(ctx, tg.ID); err != nil {
		t.Fatalf("DeleteTarget: %v", err)
	}

	// Scan should be gone.
	if _, err := repo.GetScanByID(ctx, scan.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("expected pgx.ErrNoRows for scan, got %v", err)
	}

	// Findings should be gone.
	findings, err := repo.ListFindings(ctx, recon.ListFindingsFilter{ScanID: &scan.ID})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings after cascade, got %d", len(findings))
	}

	// Audit log row remains with NULL target_id.
	var auditCount, nulledTargets int
	if err := testDB.QueryRow(ctx,
		`SELECT COUNT(*), COUNT(*) FILTER (WHERE target_id IS NULL) FROM recon_audit_log`,
	).Scan(&auditCount, &nulledTargets); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	if auditCount != 1 {
		t.Errorf("audit rows = %d, want 1 (append-only)", auditCount)
	}
	if nulledTargets != 1 {
		t.Errorf("nulled target_id rows = %d, want 1 (cascade sets NULL)", nulledTargets)
	}
}

// ============================================================================
// Ownership proofs
// ============================================================================

func TestReconRepo_OwnershipProofRoundTrip(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, reconTables...) })

	repo := newReconRepo(t)
	ctx := context.Background()

	tg := emailTarget("owner@example.test")
	if err := repo.InsertTarget(ctx, tg); err != nil {
		t.Fatalf("InsertTarget: %v", err)
	}

	proof := &recon.OwnershipProof{
		TargetID:  tg.ID,
		Method:    recon.OwnershipEmailLink,
		Status:    recon.OwnershipPending,
		Challenge: "tok-123",
		Evidence:  map[string]any{"sent_to": "owner@example.test"},
	}
	if err := repo.InsertOwnershipProof(ctx, proof); err != nil {
		t.Fatalf("InsertOwnershipProof: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	proof.Status = recon.OwnershipVerified
	proof.VerifiedAt = &now
	proof.Evidence["confirmed"] = true
	if err := repo.UpdateOwnershipProof(ctx, proof); err != nil {
		t.Fatalf("UpdateOwnershipProof: %v", err)
	}

	latest, err := repo.LatestVerifiedOwnership(ctx, tg.ID)
	if err != nil {
		t.Fatalf("LatestVerifiedOwnership: %v", err)
	}
	if latest.ID != proof.ID {
		t.Errorf("ID mismatch")
	}
	if latest.Status != recon.OwnershipVerified {
		t.Errorf("status = %q, want verified", latest.Status)
	}
	if latest.VerifiedAt == nil {
		t.Error("VerifiedAt should be set")
	}
	if v, _ := latest.Evidence["confirmed"].(bool); !v {
		t.Errorf("evidence not persisted: %#v", latest.Evidence)
	}
}

// ============================================================================
// Profiles
// ============================================================================

func TestReconRepo_BuiltinProfilesSeeded(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := newReconRepo(t)
	ctx := context.Background()

	profiles, err := repo.ListProfiles(ctx)
	if err != nil {
		t.Fatalf("ListProfiles: %v", err)
	}
	if len(profiles) < 4 {
		t.Fatalf("expected at least 4 builtin profiles, got %d", len(profiles))
	}

	byName, err := repo.GetProfileByName(ctx, "email-exposure-lite")
	if err != nil {
		t.Fatalf("GetProfileByName: %v", err)
	}
	if byName.Kind != "builtin" {
		t.Errorf("kind = %q, want builtin", byName.Kind)
	}
	if len(byName.Modules) == 0 {
		t.Error("expected modules to be populated")
	}
	if len(byName.TargetTypes) != 1 || byName.TargetTypes[0] != recon.TargetEmail {
		t.Errorf("target_types = %v, want [email]", byName.TargetTypes)
	}

	byID, err := repo.GetProfileByID(ctx, byName.ID)
	if err != nil {
		t.Fatalf("GetProfileByID: %v", err)
	}
	if byID.Name != byName.Name {
		t.Errorf("name mismatch by ID lookup")
	}
}

// ============================================================================
// User-defined profile CRUD (v26.5.1)
// ============================================================================

func TestReconRepo_InsertProfile_HappyPath(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, append([]string{}, reconTables...)...) })

	repo := newReconRepo(t)
	ctx := context.Background()

	p := &recon.Profile{
		Name:        "custom-profile-1",
		Description: "test custom profile",
		TargetTypes: []recon.TargetType{recon.TargetEmail},
		Modules:     []string{"sfp_haveibeen"},
	}
	if err := repo.InsertProfile(ctx, p); err != nil {
		t.Fatalf("InsertProfile: %v", err)
	}
	if p.ID == uuid.Nil {
		t.Fatal("expected ID to be set")
	}
	if p.Kind != "custom" {
		t.Errorf("Kind = %q, want custom", p.Kind)
	}

	got, err := repo.GetProfileByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("GetProfileByID: %v", err)
	}
	if got.Name != "custom-profile-1" {
		t.Errorf("Name = %q", got.Name)
	}
	if got.Kind != "custom" {
		t.Errorf("Kind = %q", got.Kind)
	}
	if len(got.Modules) != 1 || got.Modules[0] != "sfp_haveibeen" {
		t.Errorf("Modules = %v", got.Modules)
	}

	// Cleanup the custom row to avoid leaking into other tests.
	t.Cleanup(func() {
		_, _ = testDB.Exec(ctx, "DELETE FROM recon_profiles WHERE kind = 'custom'")
	})
}

func TestReconRepo_InsertProfile_DuplicateNameSurfacesErrProfileExists(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := newReconRepo(t)
	ctx := context.Background()

	p1 := &recon.Profile{
		Name:        "custom-profile-dup",
		TargetTypes: []recon.TargetType{recon.TargetEmail},
		Modules:     []string{"sfp_haveibeen"},
	}
	if err := repo.InsertProfile(ctx, p1); err != nil {
		t.Fatalf("InsertProfile: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testDB.Exec(ctx, "DELETE FROM recon_profiles WHERE name = $1", p1.Name)
	})

	p2 := &recon.Profile{
		Name:        "custom-profile-dup",
		TargetTypes: []recon.TargetType{recon.TargetEmail},
		Modules:     []string{"sfp_haveibeen"},
	}
	err := repo.InsertProfile(ctx, p2)
	if !errors.Is(err, recon.ErrProfileExists) {
		t.Errorf("err = %v, want ErrProfileExists", err)
	}
}

func TestReconRepo_UpdateProfile_RefusesBuiltin(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := newReconRepo(t)
	ctx := context.Background()

	builtin, err := repo.GetProfileByName(ctx, "email-exposure-lite")
	if err != nil {
		t.Fatalf("load builtin: %v", err)
	}
	builtin.Name = "renamed-illegally"
	err = repo.UpdateProfile(ctx, builtin)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("err = %v, want pgx.ErrNoRows for builtin row", err)
	}
}

func TestReconRepo_DeleteProfile_RefusesBuiltin(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := newReconRepo(t)
	ctx := context.Background()

	builtin, err := repo.GetProfileByName(ctx, "email-exposure-lite")
	if err != nil {
		t.Fatalf("load builtin: %v", err)
	}
	err = repo.DeleteProfile(ctx, builtin.ID)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("err = %v, want pgx.ErrNoRows for builtin row", err)
	}
}

func TestReconRepo_DeleteProfile_InUseSurfacesErrProfileInUse(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, append([]string{}, reconTables...)...) })

	repo := newReconRepo(t)
	ctx := context.Background()

	p := &recon.Profile{
		Name:        "custom-profile-inuse",
		TargetTypes: []recon.TargetType{recon.TargetEmail},
		Modules:     []string{"sfp_haveibeen"},
	}
	if err := repo.InsertProfile(ctx, p); err != nil {
		t.Fatalf("InsertProfile: %v", err)
	}
	t.Cleanup(func() {
		// Best-effort cleanup. The scan FK is RESTRICT so we must wipe
		// recon_scans first (reconTables truncation above does that).
		_, _ = testDB.Exec(ctx, "DELETE FROM recon_profiles WHERE name = $1", p.Name)
	})

	tg := emailTarget("inuse@example.test")
	if err := repo.InsertTarget(ctx, tg); err != nil {
		t.Fatalf("InsertTarget: %v", err)
	}
	scan := &recon.Scan{TargetID: tg.ID, ProfileID: p.ID}
	if err := repo.InsertScan(ctx, scan); err != nil {
		t.Fatalf("InsertScan: %v", err)
	}

	err := repo.DeleteProfile(ctx, p.ID)
	if !errors.Is(err, recon.ErrProfileInUse) {
		t.Errorf("err = %v, want ErrProfileInUse", err)
	}
}

func TestReconRepo_DeleteProfile_HappyPath(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := newReconRepo(t)
	ctx := context.Background()

	p := &recon.Profile{
		Name:        "custom-profile-deleteme",
		TargetTypes: []recon.TargetType{recon.TargetEmail},
		Modules:     []string{"sfp_haveibeen"},
	}
	if err := repo.InsertProfile(ctx, p); err != nil {
		t.Fatalf("InsertProfile: %v", err)
	}
	if err := repo.DeleteProfile(ctx, p.ID); err != nil {
		t.Fatalf("DeleteProfile: %v", err)
	}
	if _, err := repo.GetProfileByID(ctx, p.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("expected pgx.ErrNoRows after delete, got %v", err)
	}
}

// ============================================================================
// Scans
// ============================================================================

func TestReconRepo_ScanRoundTrip(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, reconTables...) })

	repo := newReconRepo(t)
	ctx := context.Background()

	tg := emailTarget("scan-rt@example.test")
	if err := repo.InsertTarget(ctx, tg); err != nil {
		t.Fatalf("InsertTarget: %v", err)
	}
	profile := loadBuiltinProfile(t, repo, "email-exposure-lite")

	scan := &recon.Scan{TargetID: tg.ID, ProfileID: profile.ID}
	if err := repo.InsertScan(ctx, scan); err != nil {
		t.Fatalf("InsertScan: %v", err)
	}
	if scan.Status != recon.ScanQueued {
		t.Errorf("status = %q, want queued (default)", scan.Status)
	}
	if scan.Engine != "spiderfoot" {
		t.Errorf("engine = %q, want spiderfoot (default)", scan.Engine)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	scan.Status = recon.ScanCompleted
	scan.EngineRunID = "sf-42"
	scan.StartedAt = &now
	scan.FinishedAt = &now
	if err := repo.UpdateScan(ctx, scan); err != nil {
		t.Fatalf("UpdateScan: %v", err)
	}

	got, err := repo.GetScanByID(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetScanByID: %v", err)
	}
	if got.Status != recon.ScanCompleted {
		t.Errorf("status = %q, want completed", got.Status)
	}
	if got.EngineRunID != "sf-42" {
		t.Errorf("engine_run_id = %q, want sf-42", got.EngineRunID)
	}

	running := recon.ScanCompleted
	list, err := repo.ListScans(ctx, recon.ListScansFilter{Status: &running, TargetID: &tg.ID})
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if len(list) != 1 || list[0].ID != scan.ID {
		t.Errorf("ListScans returned %d rows, want exactly the one scan", len(list))
	}
}

// ============================================================================
// Findings (dedup + encryption)
// ============================================================================

func TestReconRepo_UpsertFinding_Deduplicates(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, reconTables...) })

	repo := newReconRepo(t)
	ctx := context.Background()

	tg := emailTarget("dedup@example.test")
	if err := repo.InsertTarget(ctx, tg); err != nil {
		t.Fatalf("InsertTarget: %v", err)
	}
	profile := loadBuiltinProfile(t, repo, "email-exposure-lite")
	scan := &recon.Scan{TargetID: tg.ID, ProfileID: profile.ID}
	if err := repo.InsertScan(ctx, scan); err != nil {
		t.Fatalf("InsertScan: %v", err)
	}

	mk := func() *recon.Finding {
		return &recon.Finding{
			ScanID:    scan.ID,
			TargetID:  tg.ID,
			Module:    "sfp_haveibeen",
			Category:  "BREACH",
			Severity:  recon.SeverityMedium,
			Value:     "leak.example.test",
			ValueHash: recon.HashValue("leak.example.test"),
		}
	}

	first := mk()
	if err := repo.UpsertFinding(ctx, first, "spiderfoot", []byte(`{"v":1}`)); err != nil {
		t.Fatalf("first UpsertFinding: %v", err)
	}
	originalLastSeen := first.LastSeen

	// Sleep just enough to detect a NOW() refresh on the upsert.
	time.Sleep(10 * time.Millisecond)

	second := mk()
	second.Severity = recon.SeverityHigh
	if err := repo.UpsertFinding(ctx, second, "spiderfoot", []byte(`{"v":2}`)); err != nil {
		t.Fatalf("second UpsertFinding: %v", err)
	}

	if second.ID != first.ID {
		t.Errorf("expected dedup to reuse ID %s, got %s", first.ID, second.ID)
	}
	if !second.LastSeen.After(originalLastSeen) {
		t.Errorf("last_seen not refreshed: original=%v new=%v", originalLastSeen, second.LastSeen)
	}

	all, err := repo.ListFindings(ctx, recon.ListFindingsFilter{ScanID: &scan.ID})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("expected 1 finding after dedup, got %d", len(all))
	}
	if all[0].Severity != recon.SeverityHigh {
		t.Errorf("severity = %q, want high (latest upsert wins)", all[0].Severity)
	}
}

func TestReconRepo_FindingRawPayload_EncryptionRoundTrip(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, reconTables...) })

	repo := newReconRepo(t)
	ctx := context.Background()

	tg := emailTarget("enc@example.test")
	if err := repo.InsertTarget(ctx, tg); err != nil {
		t.Fatalf("InsertTarget: %v", err)
	}
	profile := loadBuiltinProfile(t, repo, "email-exposure-lite")
	scan := &recon.Scan{TargetID: tg.ID, ProfileID: profile.ID}
	if err := repo.InsertScan(ctx, scan); err != nil {
		t.Fatalf("InsertScan: %v", err)
	}

	plaintext := []byte(`{"raw":"sensitive","email":"enc@example.test","leaked":true}`)
	finding := &recon.Finding{
		ScanID:    scan.ID,
		TargetID:  tg.ID,
		Module:    "sfp_hunter",
		Category:  "EMAIL_ADDRESS",
		Severity:  recon.SeverityMedium,
		Value:     "enc@example.test",
		ValueHash: recon.HashValue("enc@example.test"),
	}
	if err := repo.UpsertFinding(ctx, finding, "spiderfoot", plaintext); err != nil {
		t.Fatalf("UpsertFinding: %v", err)
	}

	// 1) Plaintext must NOT appear in the on-disk ciphertext column.
	var ciphertext, nonce []byte
	if err := testDB.QueryRow(ctx,
		`SELECT payload_encrypted, nonce FROM recon_findings_raw WHERE finding_id = $1`,
		finding.ID,
	).Scan(&ciphertext, &nonce); err != nil {
		t.Fatalf("read raw row: %v", err)
	}
	if bytes.Contains(ciphertext, []byte("sensitive")) {
		t.Errorf("ciphertext contains plaintext substring — encryption did not run")
	}
	if len(nonce) != 12 {
		t.Errorf("nonce length = %d, want 12 (AES-GCM)", len(nonce))
	}

	// 2) Round-trip through GetFindingRawPayload returns the exact bytes.
	engine, got, err := repo.GetFindingRawPayload(ctx, finding.ID)
	if err != nil {
		t.Fatalf("GetFindingRawPayload: %v", err)
	}
	if engine != "spiderfoot" {
		t.Errorf("engine = %q, want spiderfoot", engine)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("payload mismatch:\n got %s\nwant %s", got, plaintext)
	}
}

// ============================================================================
// Scan summary
// ============================================================================

func TestReconRepo_ScanSummaryRoundTrip(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, reconTables...) })

	repo := newReconRepo(t)
	ctx := context.Background()

	tg := emailTarget("summary@example.test")
	if err := repo.InsertTarget(ctx, tg); err != nil {
		t.Fatalf("InsertTarget: %v", err)
	}
	profile := loadBuiltinProfile(t, repo, "email-exposure-lite")
	scan := &recon.Scan{TargetID: tg.ID, ProfileID: profile.ID}
	if err := repo.InsertScan(ctx, scan); err != nil {
		t.Fatalf("InsertScan: %v", err)
	}

	summary := &recon.ScanSummary{
		ScanID:       scan.ID,
		Counts:       map[string]int{"high": 2, "info": 5},
		Grade:        "B",
		Correlations: []map[string]any{{"type": "shared_email", "weight": 0.8}},
	}
	if err := repo.UpsertScanSummary(ctx, summary); err != nil {
		t.Fatalf("UpsertScanSummary: %v", err)
	}

	got, err := repo.GetScanSummary(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetScanSummary: %v", err)
	}
	if got.Grade != "B" {
		t.Errorf("grade = %q, want B", got.Grade)
	}
	if got.Counts["high"] != 2 {
		t.Errorf("counts[high] = %d, want 2", got.Counts["high"])
	}
	if len(got.Correlations) != 1 {
		t.Errorf("correlations len = %d, want 1", len(got.Correlations))
	}

	// Upsert again to confirm replacement semantics.
	summary.Grade = "A"
	summary.Counts = map[string]int{"info": 10}
	if err := repo.UpsertScanSummary(ctx, summary); err != nil {
		t.Fatalf("UpsertScanSummary replace: %v", err)
	}
	got, err = repo.GetScanSummary(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetScanSummary after replace: %v", err)
	}
	if got.Grade != "A" || got.Counts["high"] != 0 {
		t.Errorf("upsert did not replace fields: %+v", got)
	}
}

// ============================================================================
// Audit log (append-only)
// ============================================================================

func TestReconRepo_AppendAuditOnly(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, reconTables...) })

	repo := newReconRepo(t)
	ctx := context.Background()

	entries := []recon.AuditEntry{
		{Action: "module.enabled"},
		{Action: "target.created", Details: map[string]any{"type": "email"}},
		{Action: "scan.start", IP: "203.0.113.7"},
	}
	for i, e := range entries {
		if err := repo.AppendAudit(ctx, e); err != nil {
			t.Fatalf("AppendAudit[%d]: %v", i, err)
		}
	}

	var count int
	if err := testDB.QueryRow(ctx, `SELECT COUNT(*) FROM recon_audit_log`).Scan(&count); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if count != len(entries) {
		t.Errorf("audit rows = %d, want %d", count, len(entries))
	}

	// IP is persisted as INET; verify it round-trips and details JSON is stored.
	rows, err := testDB.Query(ctx,
		`SELECT action, COALESCE(host(ip), ''), details::text FROM recon_audit_log ORDER BY created_at ASC`,
	)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows.Close()

	var saw []recon.AuditEntry
	for rows.Next() {
		var (
			action, ipStr, detailsRaw string
		)
		if err := rows.Scan(&action, &ipStr, &detailsRaw); err != nil {
			t.Fatalf("scan: %v", err)
		}
		var details map[string]any
		if detailsRaw != "" {
			_ = json.Unmarshal([]byte(detailsRaw), &details)
		}
		saw = append(saw, recon.AuditEntry{Action: action, IP: ipStr, Details: details})
	}

	if saw[2].IP != "203.0.113.7" {
		t.Errorf("ip = %q, want 203.0.113.7", saw[2].IP)
	}
	if saw[1].Details["type"] != "email" {
		t.Errorf("details not persisted: %#v", saw[1].Details)
	}
}

// ============================================================================
// Helpers
// ============================================================================

func loadBuiltinProfile(t *testing.T, repo *postgres.ReconRepository, name string) recon.Profile {
	t.Helper()
	p, err := repo.GetProfileByName(context.Background(), name)
	if err != nil {
		t.Fatalf("load builtin profile %q: %v", name, err)
	}
	return *p
}
