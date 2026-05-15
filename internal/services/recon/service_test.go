// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package recon

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ---------------------------------------------------------------------------
// stubRepo — in-memory repository for unit tests. Thread-safe so test
// goroutines and the RunScan event loop can hit it concurrently under
// -race.
// ---------------------------------------------------------------------------

type stubRepo struct {
	mu       sync.Mutex
	targets  map[uuid.UUID]*Target
	proofs   map[uuid.UUID]*OwnershipProof
	profiles map[uuid.UUID]*Profile
	scans    map[uuid.UUID]*Scan
	findings []*Finding
	summary  map[uuid.UUID]*ScanSummary
	audit    []AuditEntry

	insertTargetErr error
	listScansErr    error
}

func newStubRepo() *stubRepo {
	return &stubRepo{
		targets:  map[uuid.UUID]*Target{},
		proofs:   map[uuid.UUID]*OwnershipProof{},
		profiles: map[uuid.UUID]*Profile{},
		scans:    map[uuid.UUID]*Scan{},
		summary:  map[uuid.UUID]*ScanSummary{},
	}
}

func (r *stubRepo) InsertTarget(_ context.Context, t *Target) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.insertTargetErr != nil {
		return r.insertTargetErr
	}
	r.targets[t.ID] = cloneTarget(t)
	return nil
}

func (r *stubRepo) GetTargetByID(_ context.Context, id uuid.UUID) (*Target, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.targets[id]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	return cloneTarget(t), nil
}

func (r *stubRepo) GetTargetByHash(_ context.Context, typ TargetType, hash []byte) (*Target, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.targets {
		if t.Type == typ && bytesEqual(t.ValueHash, hash) {
			return cloneTarget(t), nil
		}
	}
	return nil, pgx.ErrNoRows
}

func (r *stubRepo) ListTargets(_ context.Context, filter ListTargetsFilter) ([]Target, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Target, 0, len(r.targets))
	for _, t := range r.targets {
		if filter.Type != nil && t.Type != *filter.Type {
			continue
		}
		out = append(out, *cloneTarget(t))
	}
	return out, nil
}

func (r *stubRepo) DeleteTarget(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.targets, id)
	return nil
}

func (r *stubRepo) InsertOwnershipProof(_ context.Context, p *OwnershipProof) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.proofs[p.ID] = cloneProof(p)
	return nil
}

func (r *stubRepo) UpdateOwnershipProof(_ context.Context, p *OwnershipProof) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.proofs[p.ID] = cloneProof(p)
	return nil
}

func (r *stubRepo) GetOwnershipProofByID(_ context.Context, id uuid.UUID) (*OwnershipProof, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.proofs[id]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	return cloneProof(p), nil
}

func (r *stubRepo) LatestVerifiedOwnership(_ context.Context, targetID uuid.UUID) (*OwnershipProof, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var latest *OwnershipProof
	for _, p := range r.proofs {
		if p.TargetID != targetID || p.Status != OwnershipVerified {
			continue
		}
		if latest == nil || p.UpdatedAt.After(latest.UpdatedAt) {
			latest = p
		}
	}
	if latest == nil {
		return nil, pgx.ErrNoRows
	}
	return cloneProof(latest), nil
}

func (r *stubRepo) GetProfileByID(_ context.Context, id uuid.UUID) (*Profile, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.profiles[id]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	return cloneProfile(p), nil
}

func (r *stubRepo) GetProfileByName(_ context.Context, name string) (*Profile, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.profiles {
		if p.Name == name {
			return cloneProfile(p), nil
		}
	}
	return nil, pgx.ErrNoRows
}

func (r *stubRepo) ListProfiles(_ context.Context) ([]Profile, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Profile, 0, len(r.profiles))
	for _, p := range r.profiles {
		out = append(out, *cloneProfile(p))
	}
	return out, nil
}

func (r *stubRepo) InsertProfile(_ context.Context, p *Profile) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.profiles {
		if existing.Name == p.Name {
			return ErrProfileExists
		}
	}
	r.profiles[p.ID] = cloneProfile(p)
	return nil
}

func (r *stubRepo) UpdateProfile(_ context.Context, p *Profile) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.profiles[p.ID]
	if !ok || existing.Kind != "custom" {
		return pgx.ErrNoRows
	}
	for id, other := range r.profiles {
		if id != p.ID && other.Name == p.Name {
			return ErrProfileExists
		}
	}
	r.profiles[p.ID] = cloneProfile(p)
	return nil
}

func (r *stubRepo) DeleteProfile(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.profiles[id]
	if !ok || existing.Kind != "custom" {
		return pgx.ErrNoRows
	}
	// Surface FK ON DELETE RESTRICT semantics: any scan referencing
	// the profile blocks the delete.
	for _, s := range r.scans {
		if s.ProfileID == id {
			return ErrProfileInUse
		}
	}
	delete(r.profiles, id)
	return nil
}

func (r *stubRepo) InsertScan(_ context.Context, s *Scan) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scans[s.ID] = cloneScan(s)
	return nil
}

func (r *stubRepo) UpdateScan(_ context.Context, s *Scan) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scans[s.ID] = cloneScan(s)
	return nil
}

func (r *stubRepo) GetScanByID(_ context.Context, id uuid.UUID) (*Scan, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.scans[id]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	return cloneScan(s), nil
}

func (r *stubRepo) ListScans(_ context.Context, _ ListScansFilter) ([]Scan, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.listScansErr != nil {
		return nil, r.listScansErr
	}
	out := make([]Scan, 0, len(r.scans))
	for _, s := range r.scans {
		out = append(out, *cloneScan(s))
	}
	return out, nil
}

func (r *stubRepo) UpsertFinding(_ context.Context, f *Finding, _ string, _ []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.findings = append(r.findings, cloneFinding(f))
	return nil
}

func (r *stubRepo) ListFindings(_ context.Context, filter ListFindingsFilter) ([]Finding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Finding, 0, len(r.findings))
	for _, f := range r.findings {
		if filter.ScanID != nil && f.ScanID != *filter.ScanID {
			continue
		}
		if filter.Severity != nil && f.Severity != *filter.Severity {
			continue
		}
		out = append(out, *cloneFinding(f))
	}
	return out, nil
}

func (r *stubRepo) UpsertScanSummary(_ context.Context, s *ScanSummary) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.summary[s.ScanID] = cloneSummary(s)
	return nil
}

func (r *stubRepo) GetScanSummary(_ context.Context, scanID uuid.UUID) (*ScanSummary, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.summary[scanID]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	return cloneSummary(s), nil
}

func (r *stubRepo) AppendAudit(_ context.Context, entry AuditEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.audit = append(r.audit, entry)
	return nil
}

func (r *stubRepo) auditSnapshot() []AuditEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]AuditEntry, len(r.audit))
	copy(out, r.audit)
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Clone helpers — every accessor returns a defensive copy so test
// assertions don't accidentally mutate stored state.
// ---------------------------------------------------------------------------

func cloneTarget(t *Target) *Target {
	if t == nil {
		return nil
	}
	out := *t
	out.ValueHash = append([]byte(nil), t.ValueHash...)
	return &out
}

func cloneProof(p *OwnershipProof) *OwnershipProof {
	if p == nil {
		return nil
	}
	out := *p
	out.Evidence = map[string]any{}
	for k, v := range p.Evidence {
		out.Evidence[k] = v
	}
	return &out
}

func cloneProfile(p *Profile) *Profile {
	if p == nil {
		return nil
	}
	out := *p
	out.TargetTypes = append([]TargetType(nil), p.TargetTypes...)
	out.Modules = append([]string(nil), p.Modules...)
	return &out
}

func cloneScan(s *Scan) *Scan {
	if s == nil {
		return nil
	}
	out := *s
	return &out
}

func cloneFinding(f *Finding) *Finding {
	if f == nil {
		return nil
	}
	out := *f
	out.ValueHash = append([]byte(nil), f.ValueHash...)
	return &out
}

func cloneSummary(s *ScanSummary) *ScanSummary {
	if s == nil {
		return nil
	}
	out := *s
	out.Counts = map[string]int{}
	for k, v := range s.Counts {
		out.Counts[k] = v
	}
	return &out
}

// ---------------------------------------------------------------------------
// fixedClock — pins time.Now for tests that assert StartedAt /
// FinishedAt / CreatedAt timestamps.
// ---------------------------------------------------------------------------

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

// ---------------------------------------------------------------------------
// stubVerifier — minimal OwnershipVerifier double. ok=true marks the
// proof verified on Start; failOn={Start,Verify} drives error paths.
// ---------------------------------------------------------------------------

type stubVerifier struct {
	method   OwnershipMethod
	startOK  bool
	verifyOK bool
	startErr error
}

func (v *stubVerifier) Method() OwnershipMethod { return v.method }

func (v *stubVerifier) Start(_ context.Context, _ *Target, p *OwnershipProof) error {
	if v.startErr != nil {
		return v.startErr
	}
	p.Challenge = "stub-challenge"
	if p.Evidence == nil {
		p.Evidence = map[string]any{}
	}
	p.Evidence["stub"] = true
	if v.startOK {
		now := time.Now().UTC()
		p.Status = OwnershipVerified
		p.VerifiedAt = &now
	}
	return nil
}

func (v *stubVerifier) Verify(_ context.Context, _ *Target, p *OwnershipProof, _ map[string]any) error {
	if v.verifyOK {
		now := time.Now().UTC()
		p.Status = OwnershipVerified
		p.VerifiedAt = &now
		return nil
	}
	p.Status = OwnershipFailed
	return ErrOwnershipMismatch
}

// ---------------------------------------------------------------------------
// stubEngine — local copy of the package-level engine stub so this
// test file doesn't import its own subpackage (which would create an
// import cycle in the recon package).
// ---------------------------------------------------------------------------

type stubEngine struct {
	name     string
	events   []EngineEvent
	startErr error
	canceled bool
}

func (e *stubEngine) Name() string { return e.name }

func (e *stubEngine) Start(_ context.Context, _ EngineStartRequest) (string, error) {
	if e.startErr != nil {
		return "", e.startErr
	}
	return "run-" + e.name, nil
}

func (e *stubEngine) Events(ctx context.Context, _ string) (<-chan EngineEvent, error) {
	out := make(chan EngineEvent, len(e.events)+1)
	go func() {
		defer close(out)
		for _, ev := range e.events {
			select {
			case <-ctx.Done():
				return
			case out <- ev:
			}
		}
	}()
	return out, nil
}

func (e *stubEngine) Cancel(_ context.Context, _ string) error {
	e.canceled = true
	return nil
}

func (e *stubEngine) Status(_ context.Context, _ string) (EngineStatus, error) {
	return EngineStatus{Status: ScanCompleted, Progress: 100}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestService(t *testing.T, repo *stubRepo, engines map[string]Engine, verifiers map[OwnershipMethod]OwnershipVerifier) *Implementation {
	t.Helper()
	svc, err := NewService(repo, engines, verifiers, fixedClock{now: time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)}, Config{DefaultEngine: "stub"}, logger.Nop())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func seedProfile(t *testing.T, repo *stubRepo, kind string, supported ...TargetType) Profile {
	t.Helper()
	p := Profile{
		ID:          uuid.New(),
		Name:        "profile-" + kind,
		Kind:        kind,
		TargetTypes: append([]TargetType(nil), supported...),
		Modules:     []string{"stub-module"},
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	repo.profiles[p.ID] = &p
	return p
}

func seedTarget(t *testing.T, svc *Implementation, typ TargetType, value string) *Target {
	t.Helper()
	got, err := svc.CreateTarget(context.Background(), CreateTargetInput{Type: typ, Value: value})
	if err != nil {
		t.Fatalf("seedTarget: %v", err)
	}
	return got
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestNewService_RequiresRepo(t *testing.T) {
	if _, err := NewService(nil, nil, nil, nil, Config{}, nil); err == nil {
		t.Fatal("NewService(nil repo) should fail")
	}
}

func TestNewService_AppliesDefaults(t *testing.T) {
	svc, err := NewService(newStubRepo(), nil, nil, nil, Config{}, nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if svc.cfg.DefaultEngine != ProfileKindSpiderFoot {
		t.Errorf("DefaultEngine = %q, want %q", svc.cfg.DefaultEngine, ProfileKindSpiderFoot)
	}
	if svc.cfg.FindingsBufferSize <= 0 {
		t.Error("FindingsBufferSize should be defaulted to a positive integer")
	}
}

// ---------------------------------------------------------------------------
// CreateTarget
// ---------------------------------------------------------------------------

func TestCreateTarget_HappyPath_NormalizesValue(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, nil, nil)

	got, err := svc.CreateTarget(context.Background(), CreateTargetInput{
		Type:  TargetEmail,
		Value: "  ALICE@Example.com  ",
		Label: "  alice  ",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	if got.Value != "alice@example.com" {
		t.Errorf("Value = %q, want %q", got.Value, "alice@example.com")
	}
	if got.Label != "alice" {
		t.Errorf("Label = %q, want %q", got.Label, "alice")
	}
	if len(got.ValueHash) == 0 {
		t.Error("ValueHash should be populated")
	}
	if entries := repo.auditSnapshot(); len(entries) != 1 || entries[0].Action != AuditActionTargetCreated {
		t.Errorf("audit entries = %v, want one target.created entry", entries)
	}
}

func TestCreateTarget_RejectsUnknownType(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, nil, nil)

	_, err := svc.CreateTarget(context.Background(), CreateTargetInput{
		Type:  TargetType("hostname"),
		Value: "example.com",
	})
	if !errors.Is(err, ErrTargetTypeUnsupported) {
		t.Errorf("err = %v, want ErrTargetTypeUnsupported", err)
	}
}

func TestCreateTarget_RejectsBlankValue(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, nil, nil)

	_, err := svc.CreateTarget(context.Background(), CreateTargetInput{Type: TargetDomain, Value: "   "})
	if !errors.Is(err, ErrTargetValueInvalid) {
		t.Errorf("err = %v, want ErrTargetValueInvalid", err)
	}
}

func TestCreateTarget_RejectsDuplicate(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, nil, nil)

	if _, err := svc.CreateTarget(context.Background(), CreateTargetInput{Type: TargetDomain, Value: "example.com"}); err != nil {
		t.Fatalf("first CreateTarget: %v", err)
	}
	_, err := svc.CreateTarget(context.Background(), CreateTargetInput{Type: TargetDomain, Value: "EXAMPLE.com"})
	if !errors.Is(err, ErrTargetExists) {
		t.Errorf("err = %v, want ErrTargetExists", err)
	}
}

// ---------------------------------------------------------------------------
// GetTarget / DeleteTarget
// ---------------------------------------------------------------------------

func TestGetTarget_NotFound(t *testing.T) {
	svc := newTestService(t, newStubRepo(), nil, nil)
	_, err := svc.GetTarget(context.Background(), uuid.New())
	if !errors.Is(err, ErrTargetNotFound) {
		t.Errorf("err = %v, want ErrTargetNotFound", err)
	}
}

func TestDeleteTarget_HappyPath(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, nil, nil)
	got := seedTarget(t, svc, TargetDomain, "example.com")

	if err := svc.DeleteTarget(context.Background(), got.ID); err != nil {
		t.Fatalf("DeleteTarget: %v", err)
	}
	if _, err := repo.GetTargetByID(context.Background(), got.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("target should be removed; got err = %v", err)
	}
	saw := false
	for _, e := range repo.auditSnapshot() {
		if e.Action == AuditActionTargetDeleted {
			saw = true
		}
	}
	if !saw {
		t.Error("audit should record target.deleted")
	}
}

func TestDeleteTarget_NotFound(t *testing.T) {
	svc := newTestService(t, newStubRepo(), nil, nil)
	err := svc.DeleteTarget(context.Background(), uuid.New())
	if !errors.Is(err, ErrTargetNotFound) {
		t.Errorf("err = %v, want ErrTargetNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// ListTargets
// ---------------------------------------------------------------------------

func TestListTargets_PaginationDefaultsAndFilter(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, nil, nil)
	seedTarget(t, svc, TargetDomain, "a.example.com")
	seedTarget(t, svc, TargetDomain, "b.example.com")
	seedTarget(t, svc, TargetEmail, "c@example.com")

	all, err := svc.ListTargets(context.Background(), ListTargetsFilter{})
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("len(all) = %d, want 3", len(all))
	}

	typ := TargetEmail
	emails, err := svc.ListTargets(context.Background(), ListTargetsFilter{Type: &typ})
	if err != nil {
		t.Fatalf("ListTargets(email): %v", err)
	}
	if len(emails) != 1 || emails[0].Type != TargetEmail {
		t.Errorf("emails = %v, want one email target", emails)
	}
}

// ---------------------------------------------------------------------------
// Ownership
// ---------------------------------------------------------------------------

func TestStartOwnershipProof_HappyPath_SelfAssert(t *testing.T) {
	repo := newStubRepo()
	verifiers := map[OwnershipMethod]OwnershipVerifier{
		OwnershipSelfAssert: &stubVerifier{method: OwnershipSelfAssert, startOK: true},
	}
	svc := newTestService(t, repo, nil, verifiers)
	target := seedTarget(t, svc, TargetUsername, "alice")

	proof, err := svc.StartOwnershipProof(context.Background(), target.ID, OwnershipSelfAssert)
	if err != nil {
		t.Fatalf("StartOwnershipProof: %v", err)
	}
	if proof.Status != OwnershipVerified {
		t.Errorf("Status = %q, want verified", proof.Status)
	}
	if proof.Method != OwnershipSelfAssert {
		t.Errorf("Method = %q, want self_assert", proof.Method)
	}
}

func TestStartOwnershipProof_TargetNotFound(t *testing.T) {
	verifiers := map[OwnershipMethod]OwnershipVerifier{OwnershipSelfAssert: &stubVerifier{method: OwnershipSelfAssert}}
	svc := newTestService(t, newStubRepo(), nil, verifiers)
	_, err := svc.StartOwnershipProof(context.Background(), uuid.New(), OwnershipSelfAssert)
	if !errors.Is(err, ErrTargetNotFound) {
		t.Errorf("err = %v, want ErrTargetNotFound", err)
	}
}

func TestStartOwnershipProof_MethodUnknown(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, nil, nil)
	target := seedTarget(t, svc, TargetDomain, "example.com")
	_, err := svc.StartOwnershipProof(context.Background(), target.ID, OwnershipDNSTXT)
	if !errors.Is(err, ErrOwnershipMethodUnknown) {
		t.Errorf("err = %v, want ErrOwnershipMethodUnknown", err)
	}
}

func TestVerifyOwnershipProof_HappyPath(t *testing.T) {
	repo := newStubRepo()
	verifiers := map[OwnershipMethod]OwnershipVerifier{
		OwnershipDNSTXT: &stubVerifier{method: OwnershipDNSTXT, verifyOK: true},
	}
	svc := newTestService(t, repo, nil, verifiers)
	target := seedTarget(t, svc, TargetDomain, "example.com")
	proof, err := svc.StartOwnershipProof(context.Background(), target.ID, OwnershipDNSTXT)
	if err != nil {
		t.Fatalf("StartOwnershipProof: %v", err)
	}

	verified, err := svc.VerifyOwnershipProof(context.Background(), proof.ID)
	if err != nil {
		t.Fatalf("VerifyOwnershipProof: %v", err)
	}
	if verified.Status != OwnershipVerified {
		t.Errorf("Status = %q, want verified", verified.Status)
	}

	saw := false
	for _, e := range repo.auditSnapshot() {
		if e.Action == AuditActionOwnershipVerified {
			saw = true
		}
	}
	if !saw {
		t.Error("audit should record ownership.verified")
	}
}

func TestVerifyOwnershipProof_ProofNotFound(t *testing.T) {
	svc := newTestService(t, newStubRepo(), nil, nil)
	_, err := svc.VerifyOwnershipProof(context.Background(), uuid.New())
	if !errors.Is(err, ErrOwnershipProofNotFound) {
		t.Errorf("err = %v, want ErrOwnershipProofNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

func TestGetProfile_NotFound(t *testing.T) {
	svc := newTestService(t, newStubRepo(), nil, nil)
	_, err := svc.GetProfile(context.Background(), uuid.New())
	if !errors.Is(err, ErrProfileNotFound) {
		t.Errorf("err = %v, want ErrProfileNotFound", err)
	}
}

func TestListProfiles_ReturnsAllSeeded(t *testing.T) {
	repo := newStubRepo()
	seedProfile(t, repo, "stub", TargetDomain)
	seedProfile(t, repo, "stub", TargetEmail)
	svc := newTestService(t, repo, nil, nil)

	got, err := svc.ListProfiles(context.Background())
	if err != nil {
		t.Fatalf("ListProfiles: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d profiles, want 2", len(got))
	}
}

// ---------------------------------------------------------------------------
// User-defined profile CRUD (v26.5.1)
// ---------------------------------------------------------------------------

func validCreateProfileInput() CreateProfileInput {
	return CreateProfileInput{
		Name:        "custom-email-deep",
		Description: "Deep email checks",
		TargetTypes: []TargetType{TargetEmail},
		Modules:     []string{"sfp_haveibeen", "toolkit:holehe"},
	}
}

func TestCreateProfile_HappyPath(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, nil, nil)

	in := validCreateProfileInput()
	got, err := svc.CreateProfile(context.Background(), in)
	if err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}
	if got.Kind != "custom" {
		t.Errorf("Kind = %q, want custom", got.Kind)
	}
	if got.Name != in.Name {
		t.Errorf("Name = %q, want %q", got.Name, in.Name)
	}

	saw := false
	for _, e := range repo.auditSnapshot() {
		if e.Action == AuditActionProfileCreated {
			saw = true
		}
	}
	if !saw {
		t.Error("audit should record profile.created")
	}
}

func TestCreateProfile_RejectsBlankName(t *testing.T) {
	svc := newTestService(t, newStubRepo(), nil, nil)
	in := validCreateProfileInput()
	in.Name = "   "
	_, err := svc.CreateProfile(context.Background(), in)
	if !errors.Is(err, ErrProfileInvalid) {
		t.Errorf("err = %v, want ErrProfileInvalid", err)
	}
}

func TestCreateProfile_RejectsDuplicateName(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, nil, nil)
	if _, err := svc.CreateProfile(context.Background(), validCreateProfileInput()); err != nil {
		t.Fatalf("first CreateProfile: %v", err)
	}
	_, err := svc.CreateProfile(context.Background(), validCreateProfileInput())
	if !errors.Is(err, ErrProfileExists) {
		t.Errorf("err = %v, want ErrProfileExists", err)
	}
}

func TestCreateProfile_RejectsUnknownTargetType(t *testing.T) {
	svc := newTestService(t, newStubRepo(), nil, nil)
	in := validCreateProfileInput()
	in.TargetTypes = []TargetType{TargetType("hostname")}
	_, err := svc.CreateProfile(context.Background(), in)
	if !errors.Is(err, ErrProfileInvalid) {
		t.Errorf("err = %v, want ErrProfileInvalid", err)
	}
}

func TestCreateProfile_RejectsUnknownModule(t *testing.T) {
	svc := newTestService(t, newStubRepo(), nil, nil)
	in := validCreateProfileInput()
	in.Modules = []string{"sfp_haveibeen", "sfp_made_up_module"}
	_, err := svc.CreateProfile(context.Background(), in)
	if !errors.Is(err, ErrProfileInvalid) {
		t.Errorf("err = %v, want ErrProfileInvalid", err)
	}
}

func TestCreateProfile_RejectsEmptyModules(t *testing.T) {
	svc := newTestService(t, newStubRepo(), nil, nil)
	in := validCreateProfileInput()
	in.Modules = nil
	_, err := svc.CreateProfile(context.Background(), in)
	if !errors.Is(err, ErrProfileInvalid) {
		t.Errorf("err = %v, want ErrProfileInvalid", err)
	}
}

func TestUpdateProfile_HappyPath(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, nil, nil)
	created, err := svc.CreateProfile(context.Background(), validCreateProfileInput())
	if err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}

	got, err := svc.UpdateProfile(context.Background(), created.ID, UpdateProfileInput{
		Name:        "custom-email-deep-v2",
		Description: "renamed",
		TargetTypes: []TargetType{TargetEmail, TargetUsername},
		Modules:     []string{"sfp_haveibeen"},
	})
	if err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if got.Name != "custom-email-deep-v2" {
		t.Errorf("Name = %q, want renamed", got.Name)
	}
	if len(got.TargetTypes) != 2 {
		t.Errorf("TargetTypes = %v, want 2 entries", got.TargetTypes)
	}
	saw := false
	for _, e := range repo.auditSnapshot() {
		if e.Action == AuditActionProfileUpdated {
			saw = true
		}
	}
	if !saw {
		t.Error("audit should record profile.updated")
	}
}

func TestUpdateProfile_RejectsBuiltin(t *testing.T) {
	repo := newStubRepo()
	builtin := Profile{
		ID:          uuid.New(),
		Name:        "email-exposure-lite",
		Kind:        "builtin",
		TargetTypes: []TargetType{TargetEmail},
		Modules:     []string{"sfp_haveibeen"},
	}
	repo.profiles[builtin.ID] = &builtin
	svc := newTestService(t, repo, nil, nil)

	_, err := svc.UpdateProfile(context.Background(), builtin.ID, UpdateProfileInput{
		Name:        "renamed",
		TargetTypes: []TargetType{TargetEmail},
		Modules:     []string{"sfp_haveibeen"},
	})
	if !errors.Is(err, ErrProfileBuiltin) {
		t.Errorf("err = %v, want ErrProfileBuiltin", err)
	}
}

func TestUpdateProfile_NotFound(t *testing.T) {
	svc := newTestService(t, newStubRepo(), nil, nil)
	_, err := svc.UpdateProfile(context.Background(), uuid.New(), UpdateProfileInput{
		Name:        "x",
		TargetTypes: []TargetType{TargetEmail},
		Modules:     []string{"sfp_haveibeen"},
	})
	if !errors.Is(err, ErrProfileNotFound) {
		t.Errorf("err = %v, want ErrProfileNotFound", err)
	}
}

func TestDeleteProfile_HappyPath(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, nil, nil)
	created, err := svc.CreateProfile(context.Background(), validCreateProfileInput())
	if err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}

	if err := svc.DeleteProfile(context.Background(), created.ID); err != nil {
		t.Fatalf("DeleteProfile: %v", err)
	}
	if _, err := svc.GetProfile(context.Background(), created.ID); !errors.Is(err, ErrProfileNotFound) {
		t.Errorf("profile should be gone; err = %v", err)
	}
	saw := false
	for _, e := range repo.auditSnapshot() {
		if e.Action == AuditActionProfileDeleted {
			saw = true
		}
	}
	if !saw {
		t.Error("audit should record profile.deleted")
	}
}

func TestDeleteProfile_RejectsBuiltin(t *testing.T) {
	repo := newStubRepo()
	builtin := Profile{
		ID:          uuid.New(),
		Name:        "email-exposure-lite",
		Kind:        "builtin",
		TargetTypes: []TargetType{TargetEmail},
		Modules:     []string{"sfp_haveibeen"},
	}
	repo.profiles[builtin.ID] = &builtin
	svc := newTestService(t, repo, nil, nil)

	err := svc.DeleteProfile(context.Background(), builtin.ID)
	if !errors.Is(err, ErrProfileBuiltin) {
		t.Errorf("err = %v, want ErrProfileBuiltin", err)
	}
}

func TestDeleteProfile_InUse(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, map[string]Engine{"stub": &stubEngine{name: "stub"}}, nil)
	created, err := svc.CreateProfile(context.Background(), CreateProfileInput{
		Name:        "in-use-profile",
		TargetTypes: []TargetType{TargetUsername},
		Modules:     []string{"stub-module"},
	})
	if err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}
	target := seedTarget(t, svc, TargetUsername, "alice")
	if _, err := svc.StartScan(context.Background(), StartScanInput{TargetID: target.ID, ProfileID: created.ID}); err != nil {
		t.Fatalf("StartScan: %v", err)
	}

	err = svc.DeleteProfile(context.Background(), created.ID)
	if !errors.Is(err, ErrProfileInUse) {
		t.Errorf("err = %v, want ErrProfileInUse", err)
	}
}

func TestDeleteProfile_NotFound(t *testing.T) {
	svc := newTestService(t, newStubRepo(), nil, nil)
	err := svc.DeleteProfile(context.Background(), uuid.New())
	if !errors.Is(err, ErrProfileNotFound) {
		t.Errorf("err = %v, want ErrProfileNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// StartScan
// ---------------------------------------------------------------------------

func TestStartScan_HappyPath_UsernameNoOwnershipRequired(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, map[string]Engine{"stub": &stubEngine{name: "stub"}}, nil)
	target := seedTarget(t, svc, TargetUsername, "alice")
	profile := seedProfile(t, repo, "stub", TargetUsername)

	scan, err := svc.StartScan(context.Background(), StartScanInput{TargetID: target.ID, ProfileID: profile.ID})
	if err != nil {
		t.Fatalf("StartScan: %v", err)
	}
	if scan.Status != ScanQueued {
		t.Errorf("Status = %q, want queued", scan.Status)
	}
	if scan.Engine != "stub" {
		t.Errorf("Engine = %q, want stub", scan.Engine)
	}
}

func TestStartScan_DomainWithoutOwnership(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, map[string]Engine{"stub": &stubEngine{name: "stub"}}, nil)
	target := seedTarget(t, svc, TargetDomain, "example.com")
	profile := seedProfile(t, repo, "stub", TargetDomain)

	_, err := svc.StartScan(context.Background(), StartScanInput{TargetID: target.ID, ProfileID: profile.ID})
	if !errors.Is(err, ErrOwnershipRequired) {
		t.Errorf("err = %v, want ErrOwnershipRequired", err)
	}
}

func TestStartScan_DomainWithOwnership(t *testing.T) {
	repo := newStubRepo()
	verifiers := map[OwnershipMethod]OwnershipVerifier{
		OwnershipDNSTXT: &stubVerifier{method: OwnershipDNSTXT, startOK: true},
	}
	svc := newTestService(t, repo, map[string]Engine{"stub": &stubEngine{name: "stub"}}, verifiers)
	target := seedTarget(t, svc, TargetDomain, "example.com")
	if _, err := svc.StartOwnershipProof(context.Background(), target.ID, OwnershipDNSTXT); err != nil {
		t.Fatalf("StartOwnershipProof: %v", err)
	}
	profile := seedProfile(t, repo, "stub", TargetDomain)

	scan, err := svc.StartScan(context.Background(), StartScanInput{TargetID: target.ID, ProfileID: profile.ID})
	if err != nil {
		t.Fatalf("StartScan: %v", err)
	}
	if scan.Status != ScanQueued {
		t.Errorf("Status = %q, want queued", scan.Status)
	}
}

func TestStartScan_ProfileNotFound(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, nil, nil)
	target := seedTarget(t, svc, TargetUsername, "alice")
	_, err := svc.StartScan(context.Background(), StartScanInput{TargetID: target.ID, ProfileID: uuid.New()})
	if !errors.Is(err, ErrProfileNotFound) {
		t.Errorf("err = %v, want ErrProfileNotFound", err)
	}
}

func TestStartScan_TargetTypeMismatch(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, map[string]Engine{"stub": &stubEngine{name: "stub"}}, nil)
	target := seedTarget(t, svc, TargetUsername, "alice")
	profile := seedProfile(t, repo, "stub", TargetEmail) // does not cover username

	_, err := svc.StartScan(context.Background(), StartScanInput{TargetID: target.ID, ProfileID: profile.ID})
	if !errors.Is(err, ErrTargetTypeUnsupported) {
		t.Errorf("err = %v, want ErrTargetTypeUnsupported", err)
	}
}

// ---------------------------------------------------------------------------
// CancelScan
// ---------------------------------------------------------------------------

func TestCancelScan_HappyPath(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, map[string]Engine{"stub": &stubEngine{name: "stub"}}, nil)
	target := seedTarget(t, svc, TargetUsername, "alice")
	profile := seedProfile(t, repo, "stub", TargetUsername)
	scan, err := svc.StartScan(context.Background(), StartScanInput{TargetID: target.ID, ProfileID: profile.ID})
	if err != nil {
		t.Fatalf("StartScan: %v", err)
	}

	if err := svc.CancelScan(context.Background(), scan.ID); err != nil {
		t.Fatalf("CancelScan: %v", err)
	}
	got, _ := svc.GetScan(context.Background(), scan.ID)
	if got.Status != ScanCancelled {
		t.Errorf("Status = %q, want canceled", got.Status)
	}
}

func TestCancelScan_AlreadyTerminal(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, nil, nil)
	scanID := uuid.New()
	repo.scans[scanID] = &Scan{ID: scanID, Status: ScanCompleted}

	err := svc.CancelScan(context.Background(), scanID)
	if !errors.Is(err, ErrScanInvalidState) {
		t.Errorf("err = %v, want ErrScanInvalidState", err)
	}
}

func TestCancelScan_NotFound(t *testing.T) {
	svc := newTestService(t, newStubRepo(), nil, nil)
	err := svc.CancelScan(context.Background(), uuid.New())
	if !errors.Is(err, ErrScanNotFound) {
		t.Errorf("err = %v, want ErrScanNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// RunScan
// ---------------------------------------------------------------------------

func TestRunScan_PersistsFindingsAndCompletes(t *testing.T) {
	repo := newStubRepo()
	engine := &stubEngine{
		name: "stub",
		events: []EngineEvent{
			{Module: "stub-module", Category: "exposure", Severity: SeverityInfo, Value: "info-1"},
			{Module: "stub-module", Category: "exposure", Severity: SeverityHigh, Value: "high-1"},
		},
	}
	svc := newTestService(t, repo, map[string]Engine{"stub": engine}, nil)
	target := seedTarget(t, svc, TargetUsername, "alice")
	profile := seedProfile(t, repo, "stub", TargetUsername)
	scan, err := svc.StartScan(context.Background(), StartScanInput{TargetID: target.ID, ProfileID: profile.ID})
	if err != nil {
		t.Fatalf("StartScan: %v", err)
	}

	if err := svc.RunScan(context.Background(), scan.ID); err != nil {
		t.Fatalf("RunScan: %v", err)
	}

	got, _ := svc.GetScan(context.Background(), scan.ID)
	if got.Status != ScanCompleted {
		t.Errorf("Status = %q, want completed", got.Status)
	}
	if got.StartedAt == nil || got.FinishedAt == nil {
		t.Error("StartedAt and FinishedAt should be populated")
	}
	if got.EngineRunID == "" {
		t.Error("EngineRunID should be persisted")
	}

	findings, _ := svc.ListFindings(context.Background(), ListFindingsFilter{ScanID: &scan.ID})
	if len(findings) != 2 {
		t.Errorf("findings = %d, want 2", len(findings))
	}

	summary, err := svc.GetScanSummary(context.Background(), scan.ID)
	if err != nil {
		t.Fatalf("GetScanSummary: %v", err)
	}
	if summary.Grade != "C" {
		t.Errorf("Grade = %q, want C (one high-severity finding)", summary.Grade)
	}
	if summary.Counts[string(SeverityHigh)] != 1 {
		t.Errorf("Counts[high] = %d, want 1", summary.Counts[string(SeverityHigh)])
	}
}

func TestRunScan_ScanNotFound(t *testing.T) {
	svc := newTestService(t, newStubRepo(), nil, nil)
	err := svc.RunScan(context.Background(), uuid.New())
	if !errors.Is(err, ErrScanNotFound) {
		t.Errorf("err = %v, want ErrScanNotFound", err)
	}
}

func TestRunScan_WrongState(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, nil, nil)
	scanID := uuid.New()
	repo.scans[scanID] = &Scan{ID: scanID, Status: ScanRunning, Engine: "stub"}
	err := svc.RunScan(context.Background(), scanID)
	if !errors.Is(err, ErrScanInvalidState) {
		t.Errorf("err = %v, want ErrScanInvalidState", err)
	}
}

func TestRunScan_EngineUnavailable(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, nil, nil) // no engines registered
	target := seedTarget(t, svc, TargetUsername, "alice")
	profile := seedProfile(t, repo, "spiderfoot", TargetUsername)
	scan, err := svc.StartScan(context.Background(), StartScanInput{TargetID: target.ID, ProfileID: profile.ID})
	if err != nil {
		t.Fatalf("StartScan: %v", err)
	}

	err = svc.RunScan(context.Background(), scan.ID)
	if !errors.Is(err, ErrEngineUnavailable) {
		t.Errorf("err = %v, want ErrEngineUnavailable", err)
	}
	got, _ := svc.GetScan(context.Background(), scan.ID)
	if got.Status != ScanFailed {
		t.Errorf("scan should be marked failed; got %q", got.Status)
	}
}

func TestRunScan_ContextCancelled(t *testing.T) {
	repo := newStubRepo()
	// Engine that emits a single event but waits on context cancellation.
	engine := &slowEngine{}
	svc := newTestService(t, repo, map[string]Engine{"stub": engine}, nil)
	target := seedTarget(t, svc, TargetUsername, "alice")
	profile := seedProfile(t, repo, "stub", TargetUsername)
	scan, err := svc.StartScan(context.Background(), StartScanInput{TargetID: target.ID, ProfileID: profile.ID})
	if err != nil {
		t.Fatalf("StartScan: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- svc.RunScan(ctx, scan.ID) }()
	// Give the engine event loop a moment to enter the select.
	time.Sleep(20 * time.Millisecond)
	cancel()
	err = <-done
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	got, _ := svc.GetScan(context.Background(), scan.ID)
	if got.Status != ScanCancelled {
		t.Errorf("Status = %q, want canceled", got.Status)
	}
}

// slowEngine never emits an event; Events stays open until ctx is
// canceled, which lets the cancellation branch of RunScan run.
type slowEngine struct{ canceled bool }

func (e *slowEngine) Name() string { return "stub" }
func (e *slowEngine) Start(_ context.Context, _ EngineStartRequest) (string, error) {
	return "slow-run", nil
}
func (e *slowEngine) Events(ctx context.Context, _ string) (<-chan EngineEvent, error) {
	out := make(chan EngineEvent)
	go func() {
		<-ctx.Done()
		close(out)
	}()
	return out, nil
}
func (e *slowEngine) Cancel(_ context.Context, _ string) error {
	e.canceled = true
	return nil
}
func (e *slowEngine) Status(_ context.Context, _ string) (EngineStatus, error) {
	return EngineStatus{Status: ScanRunning, Progress: 50}, nil
}

// ---------------------------------------------------------------------------
// ListFindings + ListScans + GetScanSummary failure paths
// ---------------------------------------------------------------------------

func TestListFindings_ClampsLimit(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(t, repo, nil, nil)

	out, err := svc.ListFindings(context.Background(), ListFindingsFilter{Limit: 5000})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	// Empty repo → empty slice; the point of the test is that the
	// clamp does not blow up at the boundary value.
	if len(out) != 0 {
		t.Errorf("len(out) = %d, want 0", len(out))
	}
}

func TestListScans_PropagatesRepoError(t *testing.T) {
	repo := newStubRepo()
	repo.listScansErr = errors.New("db down")
	svc := newTestService(t, repo, nil, nil)
	_, err := svc.ListScans(context.Background(), ListScansFilter{})
	if err == nil {
		t.Fatal("ListScans should propagate repo error")
	}
}

func TestGetScanSummary_NotFound(t *testing.T) {
	svc := newTestService(t, newStubRepo(), nil, nil)
	_, err := svc.GetScanSummary(context.Background(), uuid.New())
	if !errors.Is(err, ErrScanNotFound) {
		t.Errorf("err = %v, want ErrScanNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// grade helper
// ---------------------------------------------------------------------------

func TestGrade(t *testing.T) {
	cases := []struct {
		name  string
		input map[string]int
		want  string
	}{
		{"clean", map[string]int{"info": 5}, "A"},
		{"high only", map[string]int{"high": 1}, "C"},
		{"critical wins", map[string]int{"critical": 1, "high": 9}, "F"},
		{"empty", map[string]int{}, "A"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := grade(tc.input); got != tc.want {
				t.Errorf("grade(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
