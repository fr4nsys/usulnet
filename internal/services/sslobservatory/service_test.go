// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package sslobservatory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ============================================================================
// In-memory fakes
// ============================================================================

type fakeTargetRepo struct {
	mu      sync.Mutex
	targets map[uuid.UUID]*models.SSLTarget
}

func newFakeTargetRepo() *fakeTargetRepo {
	return &fakeTargetRepo{targets: make(map[uuid.UUID]*models.SSLTarget)}
}
func (f *fakeTargetRepo) Create(_ context.Context, t *models.SSLTarget) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	cp := *t
	f.targets[t.ID] = &cp
	return nil
}
func (f *fakeTargetRepo) GetByID(_ context.Context, id uuid.UUID) (*models.SSLTarget, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.targets[id]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *t
	return &cp, nil
}
func (f *fakeTargetRepo) List(_ context.Context, hostID uuid.UUID) ([]models.SSLTarget, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]models.SSLTarget, 0)
	for _, t := range f.targets {
		if t.HostID == hostID {
			out = append(out, *t)
		}
	}
	return out, nil
}
func (f *fakeTargetRepo) Update(_ context.Context, t *models.SSLTarget) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.targets[t.ID]; !ok {
		return errors.New("not found")
	}
	cp := *t
	f.targets[t.ID] = &cp
	return nil
}
func (f *fakeTargetRepo) Delete(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.targets[id]; !ok {
		return errors.New("not found")
	}
	delete(f.targets, id)
	return nil
}
func (f *fakeTargetRepo) ListEnabled(_ context.Context, hostID uuid.UUID) ([]models.SSLTarget, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]models.SSLTarget, 0)
	for _, t := range f.targets {
		if !t.Enabled {
			continue
		}
		if hostID == uuid.Nil || t.HostID == hostID {
			out = append(out, *t)
		}
	}
	return out, nil
}

type fakeScanRepo struct {
	mu     sync.Mutex
	scans  []*models.SSLScanResult
	stats  *models.SSLDashboardStats
	expire []models.SSLScanResult
}

func newFakeScanRepo() *fakeScanRepo {
	return &fakeScanRepo{stats: &models.SSLDashboardStats{GradeDistribution: map[string]int{}}}
}
func (f *fakeScanRepo) Create(_ context.Context, s *models.SSLScanResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	cp := *s
	f.scans = append(f.scans, &cp)
	return nil
}
func (f *fakeScanRepo) GetLatestByTarget(_ context.Context, targetID uuid.UUID) (*models.SSLScanResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.scans) - 1; i >= 0; i-- {
		if f.scans[i].TargetID == targetID {
			cp := *f.scans[i]
			return &cp, nil
		}
	}
	return nil, errors.New("not found")
}
func (f *fakeScanRepo) GetLatestByTargetHostname(_ context.Context, targetID uuid.UUID, hostname string) (*models.SSLScanResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.scans) - 1; i >= 0; i-- {
		if f.scans[i].TargetID == targetID && f.scans[i].ScanHostname == hostname {
			cp := *f.scans[i]
			return &cp, nil
		}
	}
	return nil, errors.New("not found")
}
func (f *fakeScanRepo) ListByTarget(_ context.Context, targetID uuid.UUID, limit, offset int) ([]models.SSLScanResult, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]models.SSLScanResult, 0)
	for _, s := range f.scans {
		if s.TargetID == targetID {
			out = append(out, *s)
		}
	}
	total := len(out)
	if offset >= total {
		return nil, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return out[offset:end], total, nil
}
func (f *fakeScanRepo) GetExpiringCerts(_ context.Context, _ uuid.UUID, _ int) ([]models.SSLScanResult, error) {
	return f.expire, nil
}
func (f *fakeScanRepo) GetDashboardStats(_ context.Context, _ uuid.UUID) (*models.SSLDashboardStats, error) {
	return f.stats, nil
}

type recordedAlert struct {
	target    uuid.UUID
	hostname  string
	daysLeft  int
	threshold int
}

type fakeNotifier struct {
	mu     sync.Mutex
	alerts []recordedAlert
	fail   bool
}

func (n *fakeNotifier) NotifyCertExpiring(_ context.Context, t *models.SSLTarget, s *models.SSLScanResult, daysLeft, threshold int) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.fail {
		return errors.New("notify failed")
	}
	n.alerts = append(n.alerts, recordedAlert{
		target:    t.ID,
		hostname:  s.ScanHostname,
		daysLeft:  daysLeft,
		threshold: threshold,
	})
	return nil
}

// ============================================================================
// Helpers
// ============================================================================

// newTLSServer starts a TLS server on a random localhost port using a
// self-signed leaf cert valid for `dnsNames` and expiring at `notAfter`.
// Returns the host:port and a shutdown func.
func newTLSServer(t *testing.T, dnsNames []string, notAfter time.Time) (string, func()) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	stop := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-stop:
					return
				default:
				}
				return
			}
			// Force handshake then drop. The scanner only needs the
			// handshake to inspect the cert.
			if tc, ok := conn.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
			_ = conn.Close()
		}
	}()
	return ln.Addr().String(), func() {
		close(stop)
		_ = ln.Close()
	}
}

// splitHostPort returns the port from a host:port string.
func parsePort(t *testing.T, hp string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(hp)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	var port int
	for _, c := range p {
		port = port*10 + int(c-'0')
	}
	return port
}

// ============================================================================
// Validation tests
// ============================================================================

func TestNormalizeHostname(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"example.com", "example.com", true},
		{"  Example.COM ", "example.com", true},
		{"", "", false},
		{"   ", "", false},
		{"bad\x00host", "", false},
	}
	for _, c := range cases {
		got, err := normalizeHostname(c.in)
		if c.wantOK && err != nil {
			t.Errorf("normalizeHostname(%q): unexpected error %v", c.in, err)
		}
		if !c.wantOK && err == nil {
			t.Errorf("normalizeHostname(%q): expected error, got %q", c.in, got)
		}
		if c.wantOK && got != c.want {
			t.Errorf("normalizeHostname(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeExtraHostnames(t *testing.T) {
	got, err := sanitizeExtraHostnames("example.com", []string{
		"www.example.com",
		"example.com",     // duplicate of primary, must drop
		"WWW.example.com", // case-fold dup of www
		"",                // empty drop
		"api.example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"www.example.com", "api.example.com"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	if _, err := sanitizeExtraHostnames("example.com", []string{"bad\x01host"}); err == nil {
		t.Fatal("expected error on control-char hostname")
	}
}

func TestSanitizeThresholds(t *testing.T) {
	got := sanitizeThresholds([]int{14, 30, -1, 0, 14, 7, 3, 1})
	want := []int{30, 14, 7, 3, 1}
	if len(got) != len(want) {
		t.Fatalf("len=%d, want %d, %v", len(got), len(want), got)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] < got[i] {
			t.Errorf("not descending: %v", got)
			break
		}
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%d want %d", i, got[i], want[i])
		}
	}
}

// ============================================================================
// CRUD tests
// ============================================================================

func TestCreateTarget_DefaultsAndValidation(t *testing.T) {
	tRepo := newFakeTargetRepo()
	svc := NewService(tRepo, newFakeScanRepo(), nil)
	hostID := uuid.New()

	if _, err := svc.CreateTarget(context.Background(), uuid.Nil, models.CreateSSLTargetInput{
		Name: "x", Hostname: "y",
	}); err == nil {
		t.Fatal("expected error for nil host id")
	}

	if _, err := svc.CreateTarget(context.Background(), hostID, models.CreateSSLTargetInput{
		Name: "", Hostname: "example.com",
	}); err == nil {
		t.Fatal("expected error for empty name")
	}

	if _, err := svc.CreateTarget(context.Background(), hostID, models.CreateSSLTargetInput{
		Name: "x", Hostname: "",
	}); err == nil {
		t.Fatal("expected error for empty hostname")
	}

	if _, err := svc.CreateTarget(context.Background(), hostID, models.CreateSSLTargetInput{
		Name: "x", Hostname: "example.com", Port: 70000,
	}); err == nil {
		t.Fatal("expected error for invalid port")
	}

	target, err := svc.CreateTarget(context.Background(), hostID, models.CreateSSLTargetInput{
		Name:            "Example",
		Hostname:        "  Example.com ",
		Port:            0, // → 443 default
		ExtraHostnames:  []string{"www.example.com", "api.example.com", "  "},
		AlertThresholds: []int{30, 30, 7, -1, 14},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if target.Port != 443 {
		t.Errorf("port default: got %d", target.Port)
	}
	if target.Hostname != "example.com" {
		t.Errorf("hostname normalize: got %q", target.Hostname)
	}
	if len(target.ExtraHostnames) != 2 {
		t.Errorf("extra hostnames dedup: got %v", target.ExtraHostnames)
	}
	got := target.EffectiveThresholds()
	wantThresholds := []int{30, 14, 7}
	if len(got) != len(wantThresholds) {
		t.Fatalf("thresholds=%v want %v", got, wantThresholds)
	}
}

func TestUpdateTarget(t *testing.T) {
	tRepo := newFakeTargetRepo()
	svc := NewService(tRepo, newFakeScanRepo(), nil)
	hostID := uuid.New()
	tgt, _ := svc.CreateTarget(context.Background(), hostID, models.CreateSSLTargetInput{
		Name:     "Example",
		Hostname: "example.com",
		Port:     443,
	})

	name := "Updated"
	port := 8443
	enabled := false
	updated, err := svc.UpdateTarget(context.Background(), tgt.ID, models.UpdateSSLTargetInput{
		Name:            &name,
		Port:            &port,
		Enabled:         &enabled,
		ExtraHostnames:  []string{"www.example.com"},
		AlertThresholds: []int{14, 7},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "Updated" || updated.Port != 8443 || updated.Enabled {
		t.Errorf("partial update wrong: %+v", updated)
	}
	if len(updated.ExtraHostnames) != 1 || updated.ExtraHostnames[0] != "www.example.com" {
		t.Errorf("extras=%v", updated.ExtraHostnames)
	}
	got := updated.EffectiveThresholds()
	if len(got) != 2 || got[0] != 14 || got[1] != 7 {
		t.Errorf("thresholds=%v", got)
	}

	emptyName := ""
	if _, err := svc.UpdateTarget(context.Background(), tgt.ID, models.UpdateSSLTargetInput{
		Name: &emptyName,
	}); err == nil {
		t.Fatal("expected error for empty name update")
	}
}

// ============================================================================
// Scoring tests
// ============================================================================

func TestScoreToGrade(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{100, "A+"},
		{95, "A+"},
		{94, "A"},
		{85, "A"},
		{84, "B"},
		{70, "B"},
		{55, "C"},
		{40, "D"},
		{0, "F"},
	}
	for _, c := range cases {
		got := scoreToGrade(c.score)
		if got != c.want {
			t.Errorf("scoreToGrade(%d) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestCalculateScore_Components(t *testing.T) {
	future := time.Now().Add(60 * 24 * time.Hour)
	ciphers := []CipherInfo{{Name: "TLS_AES_256_GCM_SHA384", ID: 0x1302, Strength: "strong"}}
	cj, _ := json.Marshal(ciphers)
	r := &models.SSLScanResult{
		CertChainValid:  true,
		CertNotAfter:    &future,
		CertKeyBits:     2048,
		HasOCSPStapling: true,
		HasSCT:          true,
		CertChainLength: 3,
		CipherSuites:    cj,
	}
	got := calculateScore(r, tls.VersionTLS13)
	// 30 (TLS1.3) + 15 (chain valid) + 10 (not expired) + 5 (key>=2048)
	// + 5 (ocsp) + 5 (sct) + 5 (chain 1<len<5) + 20 (GCM cipher) = 95
	if got < 95 {
		t.Errorf("expected A+ score, got %d", got)
	}
}

func TestCipherStrength(t *testing.T) {
	cases := map[string]string{
		"TLS_AES_256_GCM_SHA384":         "strong",
		"TLS_CHACHA20_POLY1305_SHA256":   "strong",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC": "acceptable",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA":  "weak",
		"":                               "unknown",
	}
	for in, want := range cases {
		if got := cipherStrength(in); got != want {
			t.Errorf("cipherStrength(%q) = %q, want %q", in, got, want)
		}
	}
}

// ============================================================================
// SNI scan tests (real TLS handshake)
// ============================================================================

func TestScanTarget_SNI_OnePerHostname(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TLS server test in short mode")
	}
	notAfter := time.Now().Add(20 * 24 * time.Hour)
	addr, stop := newTLSServer(t, []string{"example.com", "www.example.com"}, notAfter)
	defer stop()

	tRepo := newFakeTargetRepo()
	sRepo := newFakeScanRepo()
	svc := NewService(tRepo, sRepo, nil)
	svc.SetConfig(Config{DialTimeout: 3 * time.Second, PerTargetConcurrency: 2})

	hostID := uuid.New()
	tgt, err := svc.CreateTarget(context.Background(), hostID, models.CreateSSLTargetInput{
		Name:           "example",
		Hostname:       "127.0.0.1",
		Port:           parsePort(t, addr),
		ExtraHostnames: []string{"www.example.com"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	results, err := svc.ScanTarget(context.Background(), tgt.ID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results (one per SNI), got %d", len(results))
	}
	gotHosts := []string{results[0].ScanHostname, results[1].ScanHostname}
	sort.Strings(gotHosts)
	want := []string{"127.0.0.1", "www.example.com"}
	if gotHosts[0] != want[0] || gotHosts[1] != want[1] {
		t.Errorf("scan hostnames=%v, want %v", gotHosts, want)
	}
	for _, r := range results {
		if r.ErrorMessage != "" {
			t.Errorf("scan %s: error: %s", r.ScanHostname, r.ErrorMessage)
		}
		if r.CertificateCN == "" {
			t.Errorf("scan %s: missing CN", r.ScanHostname)
		}
		if r.Grade == "U" {
			t.Errorf("scan %s: grade stayed U", r.ScanHostname)
		}
	}
}

func TestScanTarget_DialTimeoutOnUnreachable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	tRepo := newFakeTargetRepo()
	svc := NewService(tRepo, newFakeScanRepo(), nil)
	svc.SetConfig(Config{DialTimeout: 200 * time.Millisecond})

	hostID := uuid.New()
	// 192.0.2.0/24 is TEST-NET-1, never routable.
	tgt, _ := svc.CreateTarget(context.Background(), hostID, models.CreateSSLTargetInput{
		Name:     "blackhole",
		Hostname: "192.0.2.1",
		Port:     443,
	})

	start := time.Now()
	results, err := svc.ScanTarget(context.Background(), tgt.ID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].ErrorMessage == "" {
		t.Fatal("expected an error message for unreachable host")
	}
	// Must respect the timeout, not the package default 10s.
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("dial did not honor short timeout: %v", d)
	}
}

func TestScanAll_PerTargetConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TLS server test in short mode")
	}
	notAfter := time.Now().Add(60 * 24 * time.Hour)
	addr, stop := newTLSServer(t, []string{"server"}, notAfter)
	defer stop()

	tRepo := newFakeTargetRepo()
	sRepo := newFakeScanRepo()
	svc := NewService(tRepo, sRepo, nil)
	svc.SetConfig(Config{DialTimeout: 3 * time.Second, PerTargetConcurrency: 2})

	hostID := uuid.New()
	for i := 0; i < 4; i++ {
		_, err := svc.CreateTarget(context.Background(), hostID, models.CreateSSLTargetInput{
			Name:     "t" + string(rune('a'+i)),
			Hostname: "127.0.0.1",
			Port:     parsePort(t, addr),
		})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	scanned, err := svc.ScanAll(context.Background(), hostID)
	if err != nil {
		t.Fatalf("scan all: %v", err)
	}
	if scanned != 4 {
		t.Errorf("scanned=%d want 4", scanned)
	}
	// Each scan created one result row.
	if len(sRepo.scans) != 4 {
		t.Errorf("scan rows=%d want 4", len(sRepo.scans))
	}
}

// ============================================================================
// Alert hook tests
// ============================================================================

func TestMaybeAlert_FiresLargestMatched(t *testing.T) {
	tRepo := newFakeTargetRepo()
	sRepo := newFakeScanRepo()
	svc := NewService(tRepo, sRepo, nil)
	notifier := &fakeNotifier{}
	svc.SetNotifier(notifier)

	hostID := uuid.New()
	tgt, _ := svc.CreateTarget(context.Background(), hostID, models.CreateSSLTargetInput{
		Name:            "expiring",
		Hostname:        "example.com",
		Port:            443,
		AlertThresholds: []int{30, 14, 7, 3, 1},
	})

	// Build a fake scan with cert_not_after 6 days out.
	in6days := time.Now().Add(6 * 24 * time.Hour)
	scan := &models.SSLScanResult{
		TargetID:     tgt.ID,
		ScanHostname: tgt.Hostname,
		CertNotAfter: &in6days,
	}
	svc.maybeAlert(context.Background(), tgt, scan)

	if len(notifier.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(notifier.alerts))
	}
	a := notifier.alerts[0]
	if a.threshold != 7 {
		t.Errorf("expected threshold=7 (largest matched), got %d", a.threshold)
	}
}

func TestMaybeAlert_NoNotifier(t *testing.T) {
	svc := NewService(newFakeTargetRepo(), newFakeScanRepo(), nil)
	tgt := &models.SSLTarget{ID: uuid.New(), Hostname: "x"}
	soon := time.Now().Add(1 * 24 * time.Hour)
	// Must not panic.
	svc.maybeAlert(context.Background(), tgt, &models.SSLScanResult{
		TargetID: tgt.ID, ScanHostname: "x", CertNotAfter: &soon,
	})
}

func TestMaybeAlert_NotifierFailureNonFatal(t *testing.T) {
	svc := NewService(newFakeTargetRepo(), newFakeScanRepo(), nil)
	notifier := &fakeNotifier{fail: true}
	svc.SetNotifier(notifier)
	tgt := &models.SSLTarget{
		ID:              uuid.New(),
		Hostname:        "x",
		AlertThresholds: []int64{14},
	}
	soon := time.Now().Add(2 * 24 * time.Hour)
	svc.maybeAlert(context.Background(), tgt, &models.SSLScanResult{
		TargetID: tgt.ID, ScanHostname: "x", CertNotAfter: &soon,
	})
	// Should not panic, errors swallowed.
}

// ============================================================================
// Smoke E2E: target → scan → result row
// ============================================================================

func TestSmokeE2E_TargetScanProducesResultRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TLS smoke test in short mode")
	}
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	addr, stop := newTLSServer(t, []string{"example.com"}, notAfter)
	defer stop()

	tRepo := newFakeTargetRepo()
	sRepo := newFakeScanRepo()
	svc := NewService(tRepo, sRepo, nil)
	svc.SetConfig(Config{DialTimeout: 3 * time.Second})

	hostID := uuid.New()
	tgt, err := svc.CreateTarget(context.Background(), hostID, models.CreateSSLTargetInput{
		Name:     "example.com",
		Hostname: "127.0.0.1",
		Port:     parsePort(t, addr),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	results, err := svc.ScanTarget(context.Background(), tgt.ID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected exactly 1 result, got %d", len(results))
	}
	if got := results[0]; got.ErrorMessage != "" {
		t.Fatalf("scan returned error message: %s", got.ErrorMessage)
	}

	// Verify a row exists in the scan repo.
	latest, err := sRepo.GetLatestByTarget(context.Background(), tgt.ID)
	if err != nil {
		t.Fatalf("get latest: %v", err)
	}
	if latest.TargetID != tgt.ID {
		t.Errorf("latest.TargetID mismatch")
	}
	if !strings.EqualFold(latest.CertificateCN, "example.com") {
		t.Errorf("CN=%q want example.com", latest.CertificateCN)
	}
	if latest.CertNotAfter == nil {
		t.Fatal("CertNotAfter is nil")
	}
}
