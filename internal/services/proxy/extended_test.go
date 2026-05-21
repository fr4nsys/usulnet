// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package proxy

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ---------------------------------------------------------------------------
// In-memory mocks for the extended repositories.
// ---------------------------------------------------------------------------

type mockAccessListRepo struct {
	lists []*models.ProxyAccessList
}

func (r *mockAccessListRepo) Create(_ context.Context, al *models.ProxyAccessList) error {
	if al.ID == uuid.Nil {
		al.ID = uuid.New()
	}
	r.lists = append(r.lists, al)
	return nil
}
func (r *mockAccessListRepo) GetByID(_ context.Context, id uuid.UUID) (*models.ProxyAccessList, error) {
	for _, al := range r.lists {
		if al.ID == id {
			return al, nil
		}
	}
	return nil, errors.New("access list not found")
}
func (r *mockAccessListRepo) List(_ context.Context, _ uuid.UUID) ([]*models.ProxyAccessList, error) {
	return r.lists, nil
}
func (r *mockAccessListRepo) Update(_ context.Context, al *models.ProxyAccessList) error {
	for i, existing := range r.lists {
		if existing.ID == al.ID {
			r.lists[i] = al
			return nil
		}
	}
	return errors.New("access list not found")
}
func (r *mockAccessListRepo) Delete(_ context.Context, id uuid.UUID) error {
	for i, al := range r.lists {
		if al.ID == id {
			r.lists = append(r.lists[:i], r.lists[i+1:]...)
			return nil
		}
	}
	return errors.New("access list not found")
}

type mockDeadHostRepo struct {
	dead []*models.ProxyDeadHost
}

func (r *mockDeadHostRepo) Create(_ context.Context, d *models.ProxyDeadHost) error {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	r.dead = append(r.dead, d)
	return nil
}
func (r *mockDeadHostRepo) GetByID(_ context.Context, id uuid.UUID) (*models.ProxyDeadHost, error) {
	for _, d := range r.dead {
		if d.ID == id {
			return d, nil
		}
	}
	return nil, errors.New("dead host not found")
}
func (r *mockDeadHostRepo) List(_ context.Context, _ uuid.UUID) ([]*models.ProxyDeadHost, error) {
	return r.dead, nil
}
func (r *mockDeadHostRepo) Update(_ context.Context, d *models.ProxyDeadHost) error {
	for i, existing := range r.dead {
		if existing.ID == d.ID {
			r.dead[i] = d
			return nil
		}
	}
	return errors.New("dead host not found")
}
func (r *mockDeadHostRepo) Delete(_ context.Context, id uuid.UUID) error {
	for i, d := range r.dead {
		if d.ID == id {
			r.dead = append(r.dead[:i], r.dead[i+1:]...)
			return nil
		}
	}
	return errors.New("dead host not found")
}

type mockLocationRepo struct {
	byHost map[uuid.UUID][]models.ProxyLocation
}

func newMockLocationRepo() *mockLocationRepo {
	return &mockLocationRepo{byHost: make(map[uuid.UUID][]models.ProxyLocation)}
}
func (r *mockLocationRepo) ListByHost(_ context.Context, id uuid.UUID) ([]models.ProxyLocation, error) {
	return r.byHost[id], nil
}
func (r *mockLocationRepo) ListAllGrouped(_ context.Context) (map[uuid.UUID][]models.ProxyLocation, error) {
	out := make(map[uuid.UUID][]models.ProxyLocation, len(r.byHost))
	for id, locs := range r.byHost {
		if len(locs) == 0 {
			continue
		}
		cp := make([]models.ProxyLocation, len(locs))
		copy(cp, locs)
		out[id] = cp
	}
	return out, nil
}
func (r *mockLocationRepo) ReplaceForHost(_ context.Context, id uuid.UUID, locs []models.ProxyLocation) error {
	r.byHost[id] = locs
	return nil
}

type mockRedirectionRepo struct {
	rds []*models.ProxyRedirection
}

func (r *mockRedirectionRepo) Create(_ context.Context, rd *models.ProxyRedirection) error {
	if rd.ID == uuid.Nil {
		rd.ID = uuid.New()
	}
	r.rds = append(r.rds, rd)
	return nil
}
func (r *mockRedirectionRepo) GetByID(_ context.Context, id uuid.UUID) (*models.ProxyRedirection, error) {
	for _, rd := range r.rds {
		if rd.ID == id {
			return rd, nil
		}
	}
	return nil, errors.New("redirection not found")
}
func (r *mockRedirectionRepo) List(_ context.Context, _ uuid.UUID) ([]*models.ProxyRedirection, error) {
	return r.rds, nil
}
func (r *mockRedirectionRepo) Update(_ context.Context, rd *models.ProxyRedirection) error {
	for i, existing := range r.rds {
		if existing.ID == rd.ID {
			r.rds[i] = rd
			return nil
		}
	}
	return errors.New("redirection not found")
}
func (r *mockRedirectionRepo) Delete(_ context.Context, id uuid.UUID) error {
	for i, rd := range r.rds {
		if rd.ID == id {
			r.rds = append(r.rds[:i], r.rds[i+1:]...)
			return nil
		}
	}
	return errors.New("redirection not found")
}

type mockStreamRepo struct {
	streams []*models.ProxyStream
}

func (r *mockStreamRepo) Create(_ context.Context, s *models.ProxyStream) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	r.streams = append(r.streams, s)
	return nil
}
func (r *mockStreamRepo) GetByID(_ context.Context, id uuid.UUID) (*models.ProxyStream, error) {
	for _, s := range r.streams {
		if s.ID == id {
			return s, nil
		}
	}
	return nil, errors.New("stream not found")
}
func (r *mockStreamRepo) List(_ context.Context, _ uuid.UUID) ([]*models.ProxyStream, error) {
	return r.streams, nil
}
func (r *mockStreamRepo) Update(_ context.Context, s *models.ProxyStream) error {
	for i, existing := range r.streams {
		if existing.ID == s.ID {
			r.streams[i] = s
			return nil
		}
	}
	return errors.New("stream not found")
}
func (r *mockStreamRepo) Delete(_ context.Context, id uuid.UUID) error {
	for i, s := range r.streams {
		if s.ID == id {
			r.streams = append(r.streams[:i], r.streams[i+1:]...)
			return nil
		}
	}
	return errors.New("stream not found")
}

// mockExtendedBackend records SyncExtended calls and reports its own
// support matrix. It is used to verify (a) idempotency of apply and
// (b) that the service surfaces ErrFeatureNotSupported when the
// backend rejects state.
type mockExtendedBackend struct {
	mockBackend
	supportMatrix     FeatureSupport
	extSyncCalls      int
	lastExtData       *ExtendedSyncData
	rejectStreams     bool
	extSyncErrToThrow error
}

func (b *mockExtendedBackend) SupportMatrix() FeatureSupport { return b.supportMatrix }

func (b *mockExtendedBackend) SyncExtended(_ context.Context, data *ExtendedSyncData) error {
	b.extSyncCalls++
	b.lastExtData = data
	if b.extSyncErrToThrow != nil {
		return b.extSyncErrToThrow
	}
	if b.rejectStreams && len(data.Streams) > 0 {
		return ErrFeatureNotSupported
	}
	return nil
}

// ---------------------------------------------------------------------------
// Test helper that builds a service wired with the extended repos and a
// fully-supportive extended backend.
// ---------------------------------------------------------------------------

func newTestServiceExtended(t *testing.T, allBackendSupport bool) (
	*Service, *mockExtendedBackend,
	*mockAccessListRepo, *mockDeadHostRepo, *mockLocationRepo,
	*mockRedirectionRepo, *mockStreamRepo,
) {
	t.Helper()

	support := FeatureSupport{
		AccessLists:  allBackendSupport,
		DeadHosts:    allBackendSupport,
		Locations:    allBackendSupport,
		Redirections: allBackendSupport,
		Streams:      allBackendSupport,
	}
	backend := &mockExtendedBackend{
		mockBackend:   mockBackend{healthy: true, mode: "nginx-mock"},
		supportMatrix: support,
	}

	svc, _, _, _ := newTestService(t)
	// Replace the backend with the extended mock.
	svc.backend = backend

	al := &mockAccessListRepo{}
	dh := &mockDeadHostRepo{}
	loc := newMockLocationRepo()
	rd := &mockRedirectionRepo{}
	st := &mockStreamRepo{}
	svc.WithExtendedRepositories(al, dh, loc, rd, st)

	return svc, backend, al, dh, loc, rd, st
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestApplyExtendedIdempotent asserts the contract that calling Apply
// twice with the same database state produces the same data on the
// second call and does not generate spurious differences.
func TestApplyExtendedIdempotent(t *testing.T) {
	ctx := context.Background()
	svc, backend, alRepo, _, _, _, _ := newTestServiceExtended(t, true)

	al := &models.ProxyAccessList{
		Name:    "internal",
		Enabled: true,
		Clients: []models.ProxyAccessListClient{
			{Address: "10.0.0.0/8", Directive: models.AccessDirectiveAllow},
		},
	}
	if err := svc.CreateAccessList(ctx, al, nil); err != nil {
		t.Fatalf("CreateAccessList: %v", err)
	}

	// One create implies (a) base Sync, (b) extended Sync. Both should
	// have been called exactly once.
	if backend.syncCalls != 1 {
		t.Fatalf("base Sync after create: got %d calls, want 1", backend.syncCalls)
	}
	if backend.extSyncCalls != 1 {
		t.Fatalf("extended Sync after create: got %d calls, want 1", backend.extSyncCalls)
	}
	if got := backend.lastExtData; got == nil || len(got.AccessLists) != 1 {
		t.Fatalf("expected 1 access list in extended data; got %+v", got)
	}

	// Replay apply — no DB changes. The backend should be called again
	// with the same data; the assertion is that idempotent replay
	// produces no diff at the application level.
	first := backend.lastExtData
	if err := svc.ApplyExtended(ctx); err != nil {
		t.Fatalf("ApplyExtended replay: %v", err)
	}
	second := backend.lastExtData
	if len(first.AccessLists) != len(second.AccessLists) {
		t.Fatalf("idempotency violated: first=%d access lists, second=%d",
			len(first.AccessLists), len(second.AccessLists))
	}
	if first.AccessLists[0].ID != second.AccessLists[0].ID {
		t.Fatalf("idempotency violated: access list ID changed across applies")
	}
	if backend.extSyncCalls != 2 {
		t.Fatalf("expected exactly two extended sync calls (create + replay); got %d", backend.extSyncCalls)
	}

	// Sanity: repository still holds exactly one row.
	if len(alRepo.lists) != 1 {
		t.Fatalf("repository drift: got %d access lists, want 1", len(alRepo.lists))
	}
}

// TestApplyExtendedStreamsAgainstCaddy asserts that the service surfaces
// ErrFeatureNotSupported when the active backend rejects streams.
// This is the contract that lets the API layer map to HTTP 422.
func TestApplyExtendedStreamsAgainstCaddy(t *testing.T) {
	ctx := context.Background()
	svc, backend, _, _, _, _, _ := newTestServiceExtended(t, true)

	// Simulate Caddy's stream support: false (the support matrix says
	// streams are unsupported, even though all other features work).
	backend.supportMatrix.Streams = false
	backend.rejectStreams = true

	st := &models.ProxyStream{
		IncomingPort:   5000,
		ForwardingHost: "upstream.local",
		ForwardingPort: 9000,
		TCPForwarding:  true,
		Enabled:        true,
	}
	err := svc.CreateStream(ctx, st, nil)
	if err == nil {
		t.Fatal("expected ErrFeatureNotSupported, got nil")
	}
	if !errors.Is(err, ErrFeatureNotSupported) {
		t.Fatalf("got %v, want ErrFeatureNotSupported", err)
	}
}

// TestApplyExtendedNoExtendedBackend asserts that a backend not
// implementing ExtendedSyncBackend does not crash on apply — the
// extended state is held authoritatively but not pushed.
func TestApplyExtendedNoExtendedBackend(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := newTestService(t)

	// Wire the extended repos but keep the plain mockBackend (does not
	// implement ExtendedSyncBackend). The service should reject feature
	// mutations because SupportMatrix() returns zero values.
	al := &mockAccessListRepo{}
	svc.WithExtendedRepositories(al, &mockDeadHostRepo{}, newMockLocationRepo(),
		&mockRedirectionRepo{}, &mockStreamRepo{})

	err := svc.CreateAccessList(ctx, &models.ProxyAccessList{Name: "x"}, nil)
	if err == nil || !errors.Is(err, ErrFeatureNotSupported) {
		t.Fatalf("expected ErrFeatureNotSupported when backend lacks extended support; got %v", err)
	}
}

// TestSupportMatrix sanity-checks the SupportMatrix passthrough.
func TestSupportMatrix(t *testing.T) {
	svc, backend, _, _, _, _, _ := newTestServiceExtended(t, true)
	m := svc.SupportMatrix()
	if m != backend.supportMatrix {
		t.Fatalf("SupportMatrix mismatch: got %+v, want %+v", m, backend.supportMatrix)
	}
}

// TestApplyExtendedRedirectionsRoundTrip checks that creating a
// redirection persists it and that listing returns the same value.
func TestApplyExtendedRedirectionsRoundTrip(t *testing.T) {
	ctx := context.Background()
	svc, backend, _, _, _, rdRepo, _ := newTestServiceExtended(t, true)

	rd := &models.ProxyRedirection{
		Domains:         []string{"old.example.com"},
		ForwardScheme:   "https",
		ForwardDomain:   "new.example.com",
		ForwardHTTPCode: 301,
		Enabled:         true,
	}
	if err := svc.CreateRedirection(ctx, rd, nil); err != nil {
		t.Fatalf("CreateRedirection: %v", err)
	}

	got, err := svc.ListRedirections(ctx)
	if err != nil {
		t.Fatalf("ListRedirections: %v", err)
	}
	if len(got) != 1 || got[0].ForwardDomain != "new.example.com" {
		t.Fatalf("redirection round trip failed: %+v", got)
	}
	if len(rdRepo.rds) != 1 {
		t.Fatalf("repository drift: %d rows", len(rdRepo.rds))
	}
	if backend.extSyncCalls != 1 {
		t.Fatalf("extended sync call count: got %d, want 1", backend.extSyncCalls)
	}
}

// TestSmokeFullHostConfig builds a host plus locations plus an access
// list and asserts the backend sees the consolidated state on apply.
func TestSmokeFullHostConfig(t *testing.T) {
	ctx := context.Background()
	svc, backend, _, _, locRepo, _, _ := newTestServiceExtended(t, true)

	// Pre-create a proxy host directly in the mock repository so its ID
	// is stable for location association.
	host := &models.ProxyHost{
		ID:             uuid.New(),
		Name:           "primary",
		Domains:        []string{"app.example.com"},
		UpstreamScheme: models.ProxyUpstreamHTTP,
		UpstreamHost:   "127.0.0.1",
		UpstreamPort:   8080,
		Enabled:        true,
	}
	// Reach into the mock host repo to seed.
	mh, ok := svc.hosts.(*mockHostRepo)
	if !ok {
		t.Fatalf("expected mockHostRepo, got %T", svc.hosts)
	}
	mh.hosts = append(mh.hosts, host)

	// Locations
	if err := svc.SetLocations(ctx, host.ID, []models.ProxyLocation{
		{
			Path:           "/api",
			UpstreamScheme: "http",
			UpstreamHost:   "127.0.0.1",
			UpstreamPort:   9090,
			Enabled:        true,
		},
	}, nil); err != nil {
		t.Fatalf("SetLocations: %v", err)
	}

	// Access list with one deny + one allow
	al := &models.ProxyAccessList{
		Name:       "office",
		SatisfyAny: false,
		PassAuth:   false,
		Enabled:    true,
		Clients: []models.ProxyAccessListClient{
			{Address: "10.0.0.0/8", Directive: models.AccessDirectiveAllow},
			{Address: "10.99.0.0/16", Directive: models.AccessDirectiveDeny},
		},
	}
	if err := svc.CreateAccessList(ctx, al, nil); err != nil {
		t.Fatalf("CreateAccessList: %v", err)
	}

	// Redirection
	if err := svc.CreateRedirection(ctx, &models.ProxyRedirection{
		Domains:         []string{"old.example.com"},
		ForwardScheme:   "https",
		ForwardDomain:   "app.example.com",
		ForwardHTTPCode: 301,
		Enabled:         true,
	}, nil); err != nil {
		t.Fatalf("CreateRedirection: %v", err)
	}

	// Last apply should reflect everything in the data passed to the backend.
	got := backend.lastExtData
	if got == nil {
		t.Fatal("backend never received extended data")
	}
	if len(got.AccessLists) != 1 {
		t.Fatalf("expected 1 access list in apply, got %d", len(got.AccessLists))
	}
	if len(got.Redirections) != 1 {
		t.Fatalf("expected 1 redirection in apply, got %d", len(got.Redirections))
	}
	if locs := got.Locations[host.ID]; len(locs) != 1 || locs[0].Path != "/api" {
		t.Fatalf("expected /api location for host %s, got %+v", host.ID, got.Locations)
	}

	// Access-list precedence sanity check (covered exhaustively in
	// access_control_test.go but pinned again here for end-to-end).
	if got := EvaluateClientAccess(al, "10.99.1.1"); got != AccessDenied {
		t.Fatalf("expected deny for 10.99.1.1, got %d", got)
	}
	if got := EvaluateClientAccess(al, "10.1.0.1"); got != AccessAllowed {
		t.Fatalf("expected allow for 10.1.0.1, got %d", got)
	}

	// Verify the location repo has the row too.
	if locs, _ := locRepo.ListByHost(ctx, host.ID); len(locs) != 1 {
		t.Fatalf("expected 1 location row in repo, got %d", len(locs))
	}
}
