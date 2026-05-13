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
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/proxy/caddy"
)

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

type mockHostRepo struct {
	hosts       []*models.ProxyHost
	createErr   error
	updateErr   error
	deleteErr   error
	getByIDErr  error
	statusCalls []statusCall
}

type statusCall struct {
	ID     uuid.UUID
	Status models.ProxyHostStatus
}

func (r *mockHostRepo) Create(_ context.Context, h *models.ProxyHost) error {
	if r.createErr != nil {
		return r.createErr
	}
	r.hosts = append(r.hosts, h)
	return nil
}

func (r *mockHostRepo) GetByID(_ context.Context, id uuid.UUID) (*models.ProxyHost, error) {
	if r.getByIDErr != nil {
		return nil, r.getByIDErr
	}
	for _, h := range r.hosts {
		if h.ID == id {
			return h, nil
		}
	}
	return nil, errors.New("host not found")
}

func (r *mockHostRepo) List(_ context.Context, _ uuid.UUID, _ bool) ([]*models.ProxyHost, error) {
	return r.hosts, nil
}

func (r *mockHostRepo) ListAll(_ context.Context, enabledOnly bool) ([]*models.ProxyHost, error) {
	if !enabledOnly {
		return r.hosts, nil
	}
	var result []*models.ProxyHost
	for _, h := range r.hosts {
		if h.Enabled {
			result = append(result, h)
		}
	}
	return result, nil
}

func (r *mockHostRepo) Update(_ context.Context, h *models.ProxyHost) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	for i, existing := range r.hosts {
		if existing.ID == h.ID {
			r.hosts[i] = h
			return nil
		}
	}
	return errors.New("host not found")
}

func (r *mockHostRepo) Delete(_ context.Context, id uuid.UUID) error {
	if r.deleteErr != nil {
		return r.deleteErr
	}
	for i, h := range r.hosts {
		if h.ID == id {
			r.hosts = append(r.hosts[:i], r.hosts[i+1:]...)
			return nil
		}
	}
	return errors.New("host not found")
}

func (r *mockHostRepo) UpdateStatus(_ context.Context, id uuid.UUID, status models.ProxyHostStatus, _ string) error {
	r.statusCalls = append(r.statusCalls, statusCall{ID: id, Status: status})
	return nil
}

func (r *mockHostRepo) GetByContainerID(_ context.Context, containerID string) (*models.ProxyHost, error) {
	for _, h := range r.hosts {
		if h.ContainerID == containerID {
			return h, nil
		}
	}
	return nil, nil
}

type mockHeaderRepo struct {
	headers map[uuid.UUID][]models.ProxyHeader
}

func newMockHeaderRepo() *mockHeaderRepo {
	return &mockHeaderRepo{headers: make(map[uuid.UUID][]models.ProxyHeader)}
}

func (r *mockHeaderRepo) ListByHost(_ context.Context, id uuid.UUID) ([]models.ProxyHeader, error) {
	return r.headers[id], nil
}

func (r *mockHeaderRepo) ReplaceForHost(_ context.Context, id uuid.UUID, headers []models.ProxyHeader) error {
	r.headers[id] = headers
	return nil
}

type mockCertRepo struct {
	certs []*models.ProxyCertificate
}

func (r *mockCertRepo) Create(_ context.Context, c *models.ProxyCertificate) error {
	r.certs = append(r.certs, c)
	return nil
}

func (r *mockCertRepo) GetByID(_ context.Context, id uuid.UUID) (*models.ProxyCertificate, error) {
	for _, c := range r.certs {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, errors.New("cert not found")
}

func (r *mockCertRepo) List(_ context.Context, _ uuid.UUID) ([]*models.ProxyCertificate, error) {
	return r.certs, nil
}

func (r *mockCertRepo) Update(_ context.Context, c *models.ProxyCertificate) error {
	for i, existing := range r.certs {
		if existing.ID == c.ID {
			r.certs[i] = c
			return nil
		}
	}
	return errors.New("cert not found")
}

func (r *mockCertRepo) Delete(_ context.Context, id uuid.UUID) error {
	for i, c := range r.certs {
		if c.ID == id {
			r.certs = append(r.certs[:i], r.certs[i+1:]...)
			return nil
		}
	}
	return errors.New("cert not found")
}

type mockDNSRepo struct {
	providers []*models.ProxyDNSProvider
}

func (r *mockDNSRepo) Create(_ context.Context, p *models.ProxyDNSProvider) error {
	r.providers = append(r.providers, p)
	return nil
}

func (r *mockDNSRepo) GetByID(_ context.Context, id uuid.UUID) (*models.ProxyDNSProvider, error) {
	for _, p := range r.providers {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, errors.New("dns provider not found")
}

func (r *mockDNSRepo) List(_ context.Context, _ uuid.UUID) ([]*models.ProxyDNSProvider, error) {
	return r.providers, nil
}

func (r *mockDNSRepo) GetDefault(_ context.Context, _ uuid.UUID) (*models.ProxyDNSProvider, error) {
	for _, p := range r.providers {
		if p.IsDefault {
			return p, nil
		}
	}
	return nil, errors.New("no default provider")
}

func (r *mockDNSRepo) Update(_ context.Context, _ *models.ProxyDNSProvider) error { return nil }
func (r *mockDNSRepo) Delete(_ context.Context, id uuid.UUID) error {
	for i, p := range r.providers {
		if p.ID == id {
			r.providers = append(r.providers[:i], r.providers[i+1:]...)
			return nil
		}
	}
	return errors.New("not found")
}

type mockAuditRepo struct {
	entries []*models.ProxyAuditLog
}

func (r *mockAuditRepo) Create(_ context.Context, e *models.ProxyAuditLog) error {
	r.entries = append(r.entries, e)
	return nil
}

func (r *mockAuditRepo) List(_ context.Context, _ uuid.UUID, limit, offset int) ([]*models.ProxyAuditLog, int, error) {
	total := len(r.entries)
	if offset >= total {
		return nil, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return r.entries[offset:end], total, nil
}

type mockEncryptor struct{}

func (e *mockEncryptor) EncryptString(plaintext string) (string, error) {
	return "enc:" + plaintext, nil
}
func (e *mockEncryptor) DecryptString(ciphertext string) (string, error) {
	if len(ciphertext) > 4 && ciphertext[:4] == "enc:" {
		return ciphertext[4:], nil
	}
	return ciphertext, nil
}

type mockBackend struct {
	syncCalls  int
	syncErr    error
	healthy    bool
	healthyErr error
	mode       string
}

func (b *mockBackend) Sync(_ context.Context, _ *SyncData) error {
	b.syncCalls++
	return b.syncErr
}
func (b *mockBackend) Healthy(_ context.Context) (bool, error) {
	return b.healthy, b.healthyErr
}
func (b *mockBackend) Mode() string {
	if b.mode == "" {
		return "mock"
	}
	return b.mode
}
func (b *mockBackend) RequestCertificate(_ context.Context, _ []string, _ string) (string, string, error) {
	return "cert-pem", "key-pem", nil
}
func (b *mockBackend) RenewCertificate(_ context.Context, _ []string, _ string) (string, string, error) {
	return "renewed-cert", "renewed-key", nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newTestService(t *testing.T) (*Service, *mockHostRepo, *mockBackend, *mockAuditRepo) {
	t.Helper()
	hostRepo := &mockHostRepo{}
	headerRepo := newMockHeaderRepo()
	certRepo := &mockCertRepo{}
	dnsRepo := &mockDNSRepo{}
	auditRepo := &mockAuditRepo{}
	enc := &mockEncryptor{}
	backend := &mockBackend{healthy: true}
	log := logger.Nop()

	cfg := Config{
		DefaultHostID: uuid.New(),
		ACMEEmail:     "test@example.com",
		ListenHTTP:    ":80",
		ListenHTTPS:   ":443",
	}

	svc := NewService(hostRepo, headerRepo, certRepo, dnsRepo, auditRepo, enc, backend, cfg, log)
	return svc, hostRepo, backend, auditRepo
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestNewService(t *testing.T) {
	svc, _, backend, _ := newTestService(t)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	if svc.Backend() != backend {
		t.Error("expected backend to match")
	}
}

func TestCreateHost(t *testing.T) {
	svc, hostRepo, backend, auditRepo := newTestService(t)
	ctx := context.Background()

	input := &models.CreateProxyHostInput{
		Name:            "web-app",
		Domains:         []string{"app.test.com"},
		UpstreamScheme:  "http",
		UpstreamHost:    "10.0.0.1",
		UpstreamPort:    8080,
		SSLMode:         models.ProxySSLModeNone,
		EnableWebSocket: true,
	}

	h, err := svc.CreateHost(ctx, input, nil)
	if err != nil {
		t.Fatalf("CreateHost failed: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil host")
	}
	if h.Name != "web-app" {
		t.Errorf("expected name web-app, got %s", h.Name)
	}
	if h.Status != models.ProxyHostStatusActive {
		t.Errorf("expected active status, got %s", h.Status)
	}
	if len(hostRepo.hosts) != 1 {
		t.Errorf("expected 1 host in repo, got %d", len(hostRepo.hosts))
	}
	if backend.syncCalls != 1 {
		t.Errorf("expected 1 sync call, got %d", backend.syncCalls)
	}
	if len(auditRepo.entries) != 1 {
		t.Errorf("expected 1 audit entry, got %d", len(auditRepo.entries))
	}
	if auditRepo.entries[0].Action != "create" {
		t.Errorf("expected create action, got %s", auditRepo.entries[0].Action)
	}
}

func TestCreateHost_RepoError(t *testing.T) {
	svc, hostRepo, _, _ := newTestService(t)
	hostRepo.createErr = errors.New("db error")
	ctx := context.Background()

	_, err := svc.CreateHost(ctx, &models.CreateProxyHostInput{
		Name:    "test",
		Domains: []string{"test.com"},
	}, nil)
	if err == nil {
		t.Error("expected error from failed repo create")
	}
}

func TestCreateHost_SyncError_StillReturnsHost(t *testing.T) {
	svc, _, backend, _ := newTestService(t)
	backend.syncErr = errors.New("sync failed")
	ctx := context.Background()

	h, err := svc.CreateHost(ctx, &models.CreateProxyHostInput{
		Name:    "test",
		Domains: []string{"test.com"},
	}, nil)
	if err != nil {
		t.Error("should not return error when sync fails")
	}
	if h == nil {
		t.Error("should return host even when sync fails")
	}
}

func TestGetHost(t *testing.T) {
	svc, hostRepo, _, _ := newTestService(t)
	ctx := context.Background()

	id := uuid.New()
	hostRepo.hosts = []*models.ProxyHost{
		{ID: id, Name: "test", Domains: []string{"test.com"}},
	}

	h, err := svc.GetHost(ctx, id)
	if err != nil {
		t.Fatalf("GetHost failed: %v", err)
	}
	if h.Name != "test" {
		t.Errorf("expected name test, got %s", h.Name)
	}
}

func TestGetHost_NotFound(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()

	_, err := svc.GetHost(ctx, uuid.New())
	if err == nil {
		t.Error("expected error for non-existent host")
	}
}

func TestListHosts(t *testing.T) {
	svc, hostRepo, _, _ := newTestService(t)
	ctx := context.Background()

	hostRepo.hosts = []*models.ProxyHost{
		{ID: uuid.New(), Name: "h1"},
		{ID: uuid.New(), Name: "h2"},
	}

	hosts, err := svc.ListHosts(ctx)
	if err != nil {
		t.Fatalf("ListHosts failed: %v", err)
	}
	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(hosts))
	}
}

func TestUpdateHost(t *testing.T) {
	svc, hostRepo, backend, _ := newTestService(t)
	ctx := context.Background()

	id := uuid.New()
	hostRepo.hosts = []*models.ProxyHost{
		{ID: id, Name: "old", Domains: []string{"old.com"}, Enabled: true},
	}

	newName := "new"
	h, err := svc.UpdateHost(ctx, id, &models.UpdateProxyHostInput{
		Name: &newName,
	}, nil)
	if err != nil {
		t.Fatalf("UpdateHost failed: %v", err)
	}
	if h.Name != "new" {
		t.Errorf("expected updated name, got %s", h.Name)
	}
	if backend.syncCalls != 1 {
		t.Errorf("expected sync after update")
	}
}

func TestUpdateHost_PartialUpdate(t *testing.T) {
	svc, hostRepo, _, _ := newTestService(t)
	ctx := context.Background()

	id := uuid.New()
	hostRepo.hosts = []*models.ProxyHost{
		{
			ID: id, Name: "app", Domains: []string{"app.com"},
			UpstreamHost: "10.0.0.1", UpstreamPort: 8080,
			SSLMode: models.ProxySSLModeNone, Enabled: true,
		},
	}

	newPort := 9090
	h, err := svc.UpdateHost(ctx, id, &models.UpdateProxyHostInput{
		UpstreamPort: &newPort,
	}, nil)
	if err != nil {
		t.Fatalf("UpdateHost failed: %v", err)
	}
	// Only port should change
	if h.UpstreamPort != 9090 {
		t.Errorf("expected port 9090, got %d", h.UpstreamPort)
	}
	if h.Name != "app" {
		t.Errorf("name should remain unchanged, got %s", h.Name)
	}
	if h.UpstreamHost != "10.0.0.1" {
		t.Errorf("upstream host should remain unchanged, got %s", h.UpstreamHost)
	}
}

func TestDeleteHost(t *testing.T) {
	svc, hostRepo, backend, auditRepo := newTestService(t)
	ctx := context.Background()

	id := uuid.New()
	hostRepo.hosts = []*models.ProxyHost{
		{ID: id, Name: "doomed"},
	}

	err := svc.DeleteHost(ctx, id, nil)
	if err != nil {
		t.Fatalf("DeleteHost failed: %v", err)
	}
	if len(hostRepo.hosts) != 0 {
		t.Error("expected host to be deleted")
	}
	if backend.syncCalls != 1 {
		t.Error("expected sync after delete")
	}
	if len(auditRepo.entries) == 0 || auditRepo.entries[0].Action != "delete" {
		t.Error("expected delete audit log")
	}
}

func TestEnableHost(t *testing.T) {
	svc, hostRepo, _, _ := newTestService(t)
	ctx := context.Background()

	id := uuid.New()
	hostRepo.hosts = []*models.ProxyHost{
		{ID: id, Name: "test", Enabled: false},
	}

	err := svc.EnableHost(ctx, id, nil)
	if err != nil {
		t.Fatalf("EnableHost failed: %v", err)
	}
	if !hostRepo.hosts[0].Enabled {
		t.Error("expected host to be enabled")
	}
}

func TestDisableHost(t *testing.T) {
	svc, hostRepo, _, _ := newTestService(t)
	ctx := context.Background()

	id := uuid.New()
	hostRepo.hosts = []*models.ProxyHost{
		{ID: id, Name: "test", Enabled: true},
	}

	err := svc.DisableHost(ctx, id, nil)
	if err != nil {
		t.Fatalf("DisableHost failed: %v", err)
	}
	if hostRepo.hosts[0].Enabled {
		t.Error("expected host to be disabled")
	}
}

func TestSync(t *testing.T) {
	svc, hostRepo, backend, _ := newTestService(t)
	ctx := context.Background()

	hostRepo.hosts = []*models.ProxyHost{
		{ID: uuid.New(), Name: "h1", Enabled: true},
	}

	err := svc.Sync(ctx)
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	if backend.syncCalls != 1 {
		t.Errorf("expected 1 sync, got %d", backend.syncCalls)
	}
}

func TestSync_BackendError(t *testing.T) {
	svc, _, backend, _ := newTestService(t)
	backend.syncErr = errors.New("backend down")
	ctx := context.Background()

	err := svc.Sync(ctx)
	if err == nil {
		t.Error("expected error from backend sync failure")
	}
}

func TestSyncToCaddy_BackwardsCompatible(t *testing.T) {
	svc, _, backend, _ := newTestService(t)
	ctx := context.Background()

	err := svc.SyncToCaddy(ctx)
	if err != nil {
		t.Fatalf("SyncToCaddy failed: %v", err)
	}
	if backend.syncCalls != 1 {
		t.Error("SyncToCaddy should delegate to Sync")
	}
}

func TestBackendHealthy(t *testing.T) {
	svc, _, backend, _ := newTestService(t)
	ctx := context.Background()

	backend.healthy = true
	healthy, err := svc.BackendHealthy(ctx)
	if err != nil {
		t.Fatalf("BackendHealthy failed: %v", err)
	}
	if !healthy {
		t.Error("expected healthy")
	}

	backend.healthy = false
	healthy, _ = svc.BackendHealthy(ctx)
	if healthy {
		t.Error("expected unhealthy")
	}
}

func TestCaddyHealthy_BackwardsCompatible(t *testing.T) {
	svc, _, backend, _ := newTestService(t)
	ctx := context.Background()
	backend.healthy = true

	healthy, err := svc.CaddyHealthy(ctx)
	if err != nil || !healthy {
		t.Error("CaddyHealthy should delegate to BackendHealthy")
	}
}

func TestUpstreamStatus_NonCaddyBackendReturnsEmpty(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()

	status, err := svc.UpstreamStatus(ctx)
	if err != nil {
		t.Fatalf("UpstreamStatus failed: %v", err)
	}

	upstreams, ok := status.([]caddy.UpstreamStatus)
	if !ok {
		t.Fatalf("expected []caddy.UpstreamStatus, got %T", status)
	}
	if len(upstreams) != 0 {
		t.Fatalf("expected no upstream status entries, got %d", len(upstreams))
	}
}

func TestBackendMode(t *testing.T) {
	svc, _, backend, _ := newTestService(t)
	backend.mode = "nginx"
	if svc.BackendMode() != "nginx" {
		t.Errorf("expected nginx, got %s", svc.BackendMode())
	}
}

func TestRequestLECertificate(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()

	cert, key, err := svc.RequestLECertificate(ctx, []string{"example.com"}, "admin@example.com")
	if err != nil {
		t.Fatalf("RequestLECertificate failed: %v", err)
	}
	if cert != "cert-pem" || key != "key-pem" {
		t.Error("unexpected certificate content from mock backend")
	}
}

func TestRenewLECertificate(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()

	cert, key, err := svc.RenewLECertificate(ctx, []string{"example.com"}, "admin@example.com")
	if err != nil {
		t.Fatalf("RenewLECertificate failed: %v", err)
	}
	if cert != "renewed-cert" || key != "renewed-key" {
		t.Error("unexpected renewed certificate content")
	}
}

func TestUploadCertificate(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()

	c, err := svc.UploadCertificate(ctx, "my-cert", []string{"example.com"}, "cert-pem", "key-pem", "", nil)
	if err != nil {
		t.Fatalf("UploadCertificate failed: %v", err)
	}
	if c.Name != "my-cert" {
		t.Errorf("expected name my-cert, got %s", c.Name)
	}
	// Key should be encrypted
	if c.KeyPEM != "enc:key-pem" {
		t.Errorf("expected encrypted key, got %s", c.KeyPEM)
	}
}

func TestDeleteCertificate(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()

	// First upload
	c, _ := svc.UploadCertificate(ctx, "cert", []string{"example.com"}, "c", "k", "", nil)

	err := svc.DeleteCertificate(ctx, c.ID, nil)
	if err != nil {
		t.Fatalf("DeleteCertificate failed: %v", err)
	}
}

func TestListAuditLogs(t *testing.T) {
	svc, _, _, auditRepo := newTestService(t)
	ctx := context.Background()

	auditRepo.entries = []*models.ProxyAuditLog{
		{Action: "create"},
		{Action: "delete"},
		{Action: "update"},
	}

	entries, total, err := svc.ListAuditLogs(ctx, 2, 0)
	if err != nil {
		t.Fatalf("ListAuditLogs failed: %v", err)
	}
	if total != 3 {
		t.Errorf("expected total 3, got %d", total)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries (limit), got %d", len(entries))
	}
}

func TestAutoProxyFromLabels_NoLabel(t *testing.T) {
	svc, _, backend, _ := newTestService(t)
	ctx := context.Background()

	err := svc.AutoProxyFromLabels(ctx, "container-1", "web", map[string]string{})
	if err != nil {
		t.Fatalf("AutoProxyFromLabels failed: %v", err)
	}
	if backend.syncCalls != 0 {
		t.Error("should not sync when no proxy label present")
	}
}

func TestAutoProxyFromLabels_CreateNew(t *testing.T) {
	svc, hostRepo, backend, _ := newTestService(t)
	ctx := context.Background()

	labels := map[string]string{
		models.LabelCaddyDomain:    "app.example.com",
		models.LabelCaddyPort:      "3000",
		models.LabelCaddyWebsocket: "true",
	}

	err := svc.AutoProxyFromLabels(ctx, "container-1", "web-app", labels)
	if err != nil {
		t.Fatalf("AutoProxyFromLabels failed: %v", err)
	}
	if len(hostRepo.hosts) != 1 {
		t.Fatalf("expected 1 host created, got %d", len(hostRepo.hosts))
	}

	h := hostRepo.hosts[0]
	if h.Domains[0] != "app.example.com" {
		t.Errorf("expected domain app.example.com, got %s", h.Domains[0])
	}
	if h.UpstreamPort != 3000 {
		t.Errorf("expected port 3000, got %d", h.UpstreamPort)
	}
	if !h.EnableWebSocket {
		t.Error("expected WebSocket enabled")
	}
	if backend.syncCalls == 0 {
		t.Error("expected sync after auto-proxy create")
	}
}

func TestAutoProxyFromLabels_UpdateExisting(t *testing.T) {
	svc, hostRepo, _, _ := newTestService(t)
	ctx := context.Background()

	id := uuid.New()
	hostRepo.hosts = []*models.ProxyHost{
		{
			ID:           id,
			ContainerID:  "container-1",
			Domains:      []string{"old.com"},
			UpstreamPort: 80,
			Enabled:      true,
		},
	}

	labels := map[string]string{
		models.LabelCaddyDomain: "new.example.com",
		models.LabelCaddyPort:   "9090",
	}

	err := svc.AutoProxyFromLabels(ctx, "container-1", "web-app", labels)
	if err != nil {
		t.Fatalf("AutoProxyFromLabels update failed: %v", err)
	}
	// Should update, not create new
	if len(hostRepo.hosts) != 1 {
		t.Errorf("should update existing, not create new; got %d hosts", len(hostRepo.hosts))
	}
	if hostRepo.hosts[0].Domains[0] != "new.example.com" {
		t.Errorf("expected updated domain, got %s", hostRepo.hosts[0].Domains[0])
	}
}

func TestAutoProxyFromLabels_SSLDisabled(t *testing.T) {
	svc, hostRepo, _, _ := newTestService(t)
	ctx := context.Background()

	labels := map[string]string{
		models.LabelCaddyDomain: "app.example.com",
		models.LabelCaddySSL:    "false",
	}

	err := svc.AutoProxyFromLabels(ctx, "c1", "app", labels)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hostRepo.hosts[0].SSLMode != models.ProxySSLModeNone {
		t.Errorf("expected SSLModeNone when ssl=false, got %s", hostRepo.hosts[0].SSLMode)
	}
}

func TestMaskToken(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "****"},
		{"ab", "****"},
		{"abcd", "****"},
		{"abcde", "****bcde"},
		{"secrettoken123", "****n123"},
	}
	for _, tt := range tests {
		got := maskToken(tt.input)
		if got != tt.expected {
			t.Errorf("maskToken(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestCreateDNSProvider(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()

	p, err := svc.CreateDNSProvider(ctx, "CF", "cloudflare", "secret-token", "example.com", 60, true, nil)
	if err != nil {
		t.Fatalf("CreateDNSProvider failed: %v", err)
	}
	if p.Name != "CF" {
		t.Errorf("expected name CF, got %s", p.Name)
	}
	// Token should be masked in returned object
	if p.APIToken != "" {
		t.Error("API token should be cleared in returned provider")
	}
	if p.APITokenHint == "" {
		t.Error("expected token hint to be set")
	}
}

func TestCreateDNSProvider_UnsupportedProvider(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()

	_, err := svc.CreateDNSProvider(ctx, "test", "unsupported_provider", "token", "", 0, false, nil)
	if err == nil {
		t.Error("expected error for unsupported DNS provider")
	}
}
