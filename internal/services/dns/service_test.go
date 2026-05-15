// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package dns_test

import (
	"context"
	stderrors "errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/dns"
)

// ============================================================================
// Helpers — in-memory fakes for every persistence interface so the tests run
// hermetically without hitting Postgres.
// ============================================================================

type fakeEncryptor struct{}

func (fakeEncryptor) EncryptString(p string) (string, error) { return "enc:" + p, nil }
func (fakeEncryptor) DecryptString(c string) (string, error) {
	if len(c) < 4 || c[:4] != "enc:" {
		return "", stderrors.New("not encrypted")
	}
	return c[4:], nil
}

type fakeProviderRepo struct {
	mu    sync.Mutex
	store map[uuid.UUID]*models.DNSProvider
}

func newFakeProviderRepo() *fakeProviderRepo {
	return &fakeProviderRepo{store: make(map[uuid.UUID]*models.DNSProvider)}
}
func (r *fakeProviderRepo) Create(_ context.Context, p *models.DNSProvider) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	p.UpdatedAt = time.Now()
	cp := *p
	r.store[p.ID] = &cp
	return nil
}
func (r *fakeProviderRepo) GetByID(_ context.Context, id uuid.UUID) (*models.DNSProvider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.store[id]
	if !ok {
		return nil, stderrors.New("not found")
	}
	cp := *p
	return &cp, nil
}
func (r *fakeProviderRepo) List(_ context.Context, hostID uuid.UUID) ([]*models.DNSProvider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []*models.DNSProvider{}
	for _, p := range r.store {
		if p.HostID == hostID {
			cp := *p
			out = append(out, &cp)
		}
	}
	return out, nil
}
func (r *fakeProviderRepo) ListAll(_ context.Context) ([]*models.DNSProvider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*models.DNSProvider, 0, len(r.store))
	for _, p := range r.store {
		cp := *p
		out = append(out, &cp)
	}
	return out, nil
}
func (r *fakeProviderRepo) Update(_ context.Context, p *models.DNSProvider) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.store[p.ID]
	if !ok {
		return stderrors.New("not found")
	}
	if p.Credentials == "" {
		p.Credentials = existing.Credentials
	}
	cp := *p
	cp.UpdatedAt = time.Now()
	r.store[p.ID] = &cp
	return nil
}
func (r *fakeProviderRepo) Delete(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.store, id)
	return nil
}

type fakeRecordRepo struct {
	mu    sync.Mutex
	store map[uuid.UUID]*models.DNSRecord
}

func newFakeRecordRepo() *fakeRecordRepo {
	return &fakeRecordRepo{store: make(map[uuid.UUID]*models.DNSRecord)}
}
func (r *fakeRecordRepo) Create(_ context.Context, rec *models.DNSRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec.ID == uuid.Nil {
		rec.ID = uuid.New()
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now()
	}
	rec.UpdatedAt = time.Now()
	cp := *rec
	r.store[rec.ID] = &cp
	return nil
}
func (r *fakeRecordRepo) GetByID(_ context.Context, id uuid.UUID) (*models.DNSRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.store[id]
	if !ok {
		return nil, stderrors.New("not found")
	}
	cp := *rec
	return &cp, nil
}
func (r *fakeRecordRepo) ListByProvider(_ context.Context, id uuid.UUID) ([]*models.DNSRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []*models.DNSRecord{}
	for _, rec := range r.store {
		if rec.ProviderID == id {
			cp := *rec
			out = append(out, &cp)
		}
	}
	return out, nil
}
func (r *fakeRecordRepo) ListByHost(_ context.Context, id uuid.UUID) ([]*models.DNSRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []*models.DNSRecord{}
	for _, rec := range r.store {
		if rec.HostID == id {
			cp := *rec
			out = append(out, &cp)
		}
	}
	return out, nil
}
func (r *fakeRecordRepo) Update(_ context.Context, rec *models.DNSRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.store[rec.ID]; !ok {
		return stderrors.New("not found")
	}
	cp := *rec
	cp.UpdatedAt = time.Now()
	r.store[rec.ID] = &cp
	return nil
}
func (r *fakeRecordRepo) Delete(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.store, id)
	return nil
}

type fakeOrderRepo struct {
	mu    sync.Mutex
	store map[uuid.UUID]*models.DNSACMEOrder
}

func newFakeOrderRepo() *fakeOrderRepo {
	return &fakeOrderRepo{store: make(map[uuid.UUID]*models.DNSACMEOrder)}
}
func (r *fakeOrderRepo) Create(_ context.Context, o *models.DNSACMEOrder) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if o.ID == uuid.Nil {
		o.ID = uuid.New()
	}
	if o.CreatedAt.IsZero() {
		o.CreatedAt = time.Now()
	}
	o.UpdatedAt = time.Now()
	cp := *o
	r.store[o.ID] = &cp
	return nil
}
func (r *fakeOrderRepo) GetByID(_ context.Context, id uuid.UUID) (*models.DNSACMEOrder, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	o, ok := r.store[id]
	if !ok {
		return nil, stderrors.New("not found")
	}
	cp := *o
	return &cp, nil
}
func (r *fakeOrderRepo) ListByHost(_ context.Context, hostID uuid.UUID) ([]*models.DNSACMEOrder, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []*models.DNSACMEOrder{}
	for _, o := range r.store {
		if o.HostID == hostID {
			cp := *o
			out = append(out, &cp)
		}
	}
	return out, nil
}
func (r *fakeOrderRepo) ListInFlight(_ context.Context) ([]*models.DNSACMEOrder, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []*models.DNSACMEOrder{}
	for _, o := range r.store {
		if !o.State.IsTerminal() {
			cp := *o
			out = append(out, &cp)
		}
	}
	return out, nil
}
func (r *fakeOrderRepo) Update(_ context.Context, o *models.DNSACMEOrder) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.store[o.ID]; !ok {
		return stderrors.New("not found")
	}
	cp := *o
	cp.UpdatedAt = time.Now()
	r.store[o.ID] = &cp
	return nil
}
func (r *fakeOrderRepo) Delete(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.store, id)
	return nil
}

type fakeAuditRepo struct {
	mu    sync.Mutex
	store []*models.DNSAuditLog
}

func newFakeAuditRepo() *fakeAuditRepo { return &fakeAuditRepo{} }
func (r *fakeAuditRepo) Create(_ context.Context, e *models.DNSAuditLog) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	cp := *e
	r.store = append(r.store, &cp)
	return nil
}
func (r *fakeAuditRepo) List(_ context.Context, hostID uuid.UUID, limit, offset int) ([]*models.DNSAuditLog, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []*models.DNSAuditLog{}
	for _, e := range r.store {
		if e.HostID == hostID {
			out = append(out, e)
		}
	}
	total := len(out)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return out[offset:end], total, nil
}
func (r *fakeAuditRepo) ListByOrder(_ context.Context, orderID uuid.UUID) ([]*models.DNSAuditLog, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []*models.DNSAuditLog{}
	for _, e := range r.store {
		if e.ResourceType == "acme_order" && e.ResourceID == orderID {
			out = append(out, e)
		}
	}
	return out, nil
}

// ============================================================================
// Fake DNS plugin — records every call so we can assert ordering.
// ============================================================================

type fakeProvider struct {
	mu       sync.Mutex
	created  []dns.ProviderRecord
	deleted  []string
	verifyOK bool
}

func newFakeProvider(verifyOK bool) *fakeProvider { return &fakeProvider{verifyOK: verifyOK} }

func (f *fakeProvider) Kind() models.DNSProviderKind { return "fake" }
func (f *fakeProvider) Close() error                 { return nil }
func (f *fakeProvider) VerifyCredentials(context.Context) error {
	if !f.verifyOK {
		return dns.ErrInvalidCredentials
	}
	return nil
}
func (f *fakeProvider) CreateRecord(_ context.Context, rec dns.ProviderRecord) (dns.ProviderRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec.ID = uuid.New().String()
	f.created = append(f.created, rec)
	return rec, nil
}
func (f *fakeProvider) DeleteRecord(_ context.Context, id string, _ dns.ProviderRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, id)
	return nil
}
func (f *fakeProvider) ListRecords(context.Context, string) ([]dns.ProviderRecord, error) {
	return nil, nil
}

// ============================================================================
// Resolver fakes
// ============================================================================

type fakeResolver struct {
	values []string
	err    error
	hits   int
}

func (r *fakeResolver) LookupTXT(_ context.Context, _ string) ([]string, error) {
	r.hits++
	return r.values, r.err
}

// ============================================================================
// Test setup
// ============================================================================

func newTestServiceWithProvider(t *testing.T, verifyOK bool) (*dns.Service, *fakeProvider) {
	t.Helper()
	provider := newFakeProvider(verifyOK)
	registry := dns.NewRegistry()
	registry.MustRegister("fake", func(_ context.Context, _ []byte, _ map[string]any) (dns.Provider, error) {
		return provider, nil
	}, dns.Capabilities{DisplayName: "Fake"})

	svc := dns.NewService(
		newFakeProviderRepo(), newFakeRecordRepo(), newFakeOrderRepo(), newFakeAuditRepo(),
		registry, fakeEncryptor{}, dns.DefaultConfig(), nil,
	)
	return svc, provider
}

// ============================================================================
// Tests
// ============================================================================

func TestService_CreateProvider_RejectsBadCredentialsJSON(t *testing.T) {
	svc, _ := newTestServiceWithProvider(t, true)
	_, err := svc.CreateProvider(context.Background(), dns.CreateProviderInput{
		HostID:       uuid.New(),
		Name:         "p",
		ProviderKind: "fake",
		Credentials:  []byte("not-json"),
	}, nil)
	if err == nil {
		t.Fatalf("expected error for malformed credentials JSON")
	}
}

func TestService_CreateProvider_EncryptsCredentials(t *testing.T) {
	svc, _ := newTestServiceWithProvider(t, true)
	host := uuid.New()
	p, err := svc.CreateProvider(context.Background(), dns.CreateProviderInput{
		HostID:       host,
		Name:         "p",
		ProviderKind: "fake",
		Credentials:  []byte(`{"token":"secret"}`),
		Enabled:      true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Credentials != "" {
		t.Fatalf("CreateProvider returned credentials in response: %s", p.Credentials)
	}
}

func TestService_CreateRecord_PersistsAfterUpstreamSuccess(t *testing.T) {
	svc, provider := newTestServiceWithProvider(t, true)
	host := uuid.New()
	p, err := svc.CreateProvider(context.Background(), dns.CreateProviderInput{
		HostID:       host,
		Name:         "p",
		ProviderKind: "fake",
		Credentials:  []byte(`{"token":"x"}`),
		Enabled:      true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := svc.CreateRecord(context.Background(), p.ID, dns.RecordInput{
		Name: "foo.example.com", Type: models.DNSRecordTypeA, Content: "1.2.3.4", TTL: 60,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec.ProviderRecordID == "" {
		t.Fatalf("expected provider record id, got empty")
	}
	if len(provider.created) != 1 {
		t.Fatalf("expected 1 upstream create, got %d", len(provider.created))
	}
}

func TestService_DeleteRecord_RemovesUpstreamAndLocal(t *testing.T) {
	svc, provider := newTestServiceWithProvider(t, true)
	host := uuid.New()
	p, _ := svc.CreateProvider(context.Background(), dns.CreateProviderInput{
		HostID: host, Name: "p", ProviderKind: "fake",
		Credentials: []byte(`{"token":"x"}`), Enabled: true,
	}, nil)
	rec, _ := svc.CreateRecord(context.Background(), p.ID, dns.RecordInput{
		Name: "a.example.com", Type: models.DNSRecordTypeA, Content: "1.2.3.4", TTL: 60,
	}, nil)

	if err := svc.DeleteRecord(context.Background(), rec.ID, nil); err != nil {
		t.Fatal(err)
	}
	if len(provider.deleted) != 1 {
		t.Fatalf("expected upstream delete called once, got %d", len(provider.deleted))
	}
	if got, err := svc.ListRecords(context.Background(), p.ID); err != nil || len(got) != 0 {
		t.Fatalf("expected 0 records after delete, got %d err=%v", len(got), err)
	}
}

// ============================================================================
// ACME state machine tests
// ============================================================================

func TestService_ACME_HappyPath(t *testing.T) {
	svc, provider := newTestServiceWithProvider(t, true)
	resolver := &fakeResolver{}
	svc.SetResolver(resolver)

	host := uuid.New()
	p, _ := svc.CreateProvider(context.Background(), dns.CreateProviderInput{
		HostID: host, Name: "p", ProviderKind: "fake",
		Credentials: []byte(`{"token":"x"}`), Enabled: true,
	}, nil)

	order, err := svc.StartOrder(context.Background(), dns.ACMEOrderRequest{
		HostID:         host,
		ProviderID:     p.ID,
		Domain:         "app.example.com",
		ChallengeValue: "challenge-value-001",
	})
	if err != nil {
		t.Fatal(err)
	}
	if order.State != models.ACMEOrderStatePending {
		t.Fatalf("expected pending, got %s", order.State)
	}

	// Resolver returns no values: the state machine should remain in
	// "propagating" until it sees the value.
	processed, err := svc.ProcessOrder(context.Background(), order.ID)
	if err != nil {
		t.Fatal(err)
	}
	if processed.State != models.ACMEOrderStatePropagating {
		t.Fatalf("expected propagating after first ProcessOrder, got %s", processed.State)
	}
	if len(provider.created) != 1 {
		t.Fatalf("expected TXT record created upstream once, got %d", len(provider.created))
	}

	// Resolver now returns the expected challenge value.
	resolver.values = []string{"challenge-value-001"}
	processed, err = svc.ProcessOrder(context.Background(), order.ID)
	if err != nil {
		t.Fatal(err)
	}
	if processed.State != models.ACMEOrderStateReady {
		t.Fatalf("expected ready after propagation observed, got %s", processed.State)
	}

	// Proxy module reports CA success → service cleans up.
	processed, err = svc.MarkOrderCompleted(context.Background(), order.ID)
	if err != nil {
		t.Fatal(err)
	}
	if processed.State != models.ACMEOrderStateCompleted {
		t.Fatalf("expected completed, got %s", processed.State)
	}
	if len(provider.deleted) != 1 {
		t.Fatalf("expected upstream TXT deletion, got %d deletions", len(provider.deleted))
	}
}

func TestService_ACME_PropagationTimeout(t *testing.T) {
	svc, _ := newTestServiceWithProvider(t, true)
	resolver := &fakeResolver{}
	svc.SetResolver(resolver)

	host := uuid.New()
	p, _ := svc.CreateProvider(context.Background(), dns.CreateProviderInput{
		HostID: host, Name: "p", ProviderKind: "fake",
		Credentials: []byte(`{"token":"x"}`), Enabled: true,
	}, nil)

	order, err := svc.StartOrder(context.Background(), dns.ACMEOrderRequest{
		HostID: host, ProviderID: p.ID,
		Domain: "fail.example.com", ChallengeValue: "v",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Default config makes 30 attempts; loop until terminal or 200
	// iterations as a safety net.
	for i := 0; i < 200; i++ {
		o, _ := svc.ProcessOrder(context.Background(), order.ID)
		if o == nil {
			t.Fatalf("nil order at iteration %d", i)
		}
		if o.State.IsTerminal() {
			if o.State != models.ACMEOrderStateFailed {
				t.Fatalf("expected failed, got %s", o.State)
			}
			return
		}
	}
	t.Fatalf("state machine never reached terminal state")
}

func TestService_ACME_FailOrder_TriggersCleanup(t *testing.T) {
	svc, provider := newTestServiceWithProvider(t, true)
	resolver := &fakeResolver{}
	svc.SetResolver(resolver)

	host := uuid.New()
	p, _ := svc.CreateProvider(context.Background(), dns.CreateProviderInput{
		HostID: host, Name: "p", ProviderKind: "fake",
		Credentials: []byte(`{"token":"x"}`), Enabled: true,
	}, nil)
	order, _ := svc.StartOrder(context.Background(), dns.ACMEOrderRequest{
		HostID: host, ProviderID: p.ID,
		Domain: "x.example.com", ChallengeValue: "v",
	})
	// Drop the TXT (transitions to propagating, creates record).
	if _, err := svc.ProcessOrder(context.Background(), order.ID); err != nil {
		t.Fatal(err)
	}
	if len(provider.created) != 1 {
		t.Fatalf("expected one TXT create")
	}

	if _, err := svc.FailOrder(context.Background(), order.ID, "CA said no"); err != nil {
		t.Fatal(err)
	}
	if len(provider.deleted) != 1 {
		t.Fatalf("expected TXT cleanup on FailOrder, got %d deletions", len(provider.deleted))
	}
}

func TestService_SupportedProviders_SortedByKind(t *testing.T) {
	svc, _ := newTestServiceWithProvider(t, true)
	caps := svc.SupportedProviders()
	if len(caps) != 1 {
		t.Fatalf("expected 1 capability, got %d", len(caps))
	}
}
