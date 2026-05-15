// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package sslobservatory provides SSL/TLS scanning and certificate analysis.
//
// The observatory is a fully self-hosted module: every TLS handshake
// is performed in-process by crypto/tls — there is no call-out to any
// external observatory / scanner service, and no telemetry leaves the
// usulnet binary.
//
// Improvements over v26.2.7:
//   - Repository extracted into internal/repository/postgres; the service
//     no longer inlines SQL.
//   - Per-target alert thresholds (defaults 30/14/7/3/1 days).
//   - SNI virtual-host support: one scan_result row per (target, hostname).
//   - Per-target concurrency cap (default 4 in flight) keeps ScanAll
//     from amplifying load across many hosts.
//   - Every TLS dial has a hard 10s timeout.
//   - No biz gating, no edition checks, no call-home.
package sslobservatory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Sentinel errors returned by the service. API handlers map these to
// stable HTTP status codes.
var (
	// ErrInvalidInput is returned when the caller supplies a malformed
	// target field (empty name/hostname, port out of range, etc.).
	ErrInvalidInput = stderrors.New("ssl observatory: invalid input")
)

// DialTimeout is the hard timeout enforced on every TLS dial. The
// connection is aborted if the remote server has not completed the
// handshake by then. Exposed as a package var only so tests can
// shrink it.
var DialTimeout = 10 * time.Second

// DefaultPerTargetConcurrency caps the number of concurrent TLS
// dials a ScanAll run will issue. Avoids amplifying the scan when
// the operator has many SNI hostnames or many targets across hosts.
const DefaultPerTargetConcurrency = 4

// CipherInfo is the shape persisted in ssl_scan_results.cipher_suites.
// Kept exported so the web/api layers can decode it consistently.
type CipherInfo struct {
	Name     string `json:"name"`
	ID       uint16 `json:"id"`
	Strength string `json:"strength"`
}

// TargetRepository defines persistence for SSL targets.
type TargetRepository interface {
	Create(ctx context.Context, target *models.SSLTarget) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.SSLTarget, error)
	List(ctx context.Context, hostID uuid.UUID) ([]models.SSLTarget, error)
	Update(ctx context.Context, target *models.SSLTarget) error
	Delete(ctx context.Context, id uuid.UUID) error
	ListEnabled(ctx context.Context, hostID uuid.UUID) ([]models.SSLTarget, error)
}

// ScanResultRepository defines persistence for scan results.
type ScanResultRepository interface {
	Create(ctx context.Context, result *models.SSLScanResult) error
	GetLatestByTarget(ctx context.Context, targetID uuid.UUID) (*models.SSLScanResult, error)
	GetLatestByTargetHostname(ctx context.Context, targetID uuid.UUID, hostname string) (*models.SSLScanResult, error)
	ListByTarget(ctx context.Context, targetID uuid.UUID, limit, offset int) ([]models.SSLScanResult, int, error)
	GetExpiringCerts(ctx context.Context, hostID uuid.UUID, withinDays int) ([]models.SSLScanResult, error)
	GetDashboardStats(ctx context.Context, hostID uuid.UUID) (*models.SSLDashboardStats, error)
}

// Notifier is the narrow interface this service needs to dispatch
// certificate-expiry alerts. Satisfied by an adapter over
// internal/services/notification.Service; the service stays nil-safe
// when no notifier is wired (silent observability).
type Notifier interface {
	NotifyCertExpiring(ctx context.Context, target *models.SSLTarget, scan *models.SSLScanResult, daysLeft, threshold int) error
}

// Config tunes the service. Zero values pick sane defaults.
type Config struct {
	// PerTargetConcurrency caps the number of in-flight TLS dials
	// during ScanAll. 0 means the package default (4).
	PerTargetConcurrency int

	// DialTimeout overrides the package-level DialTimeout for this
	// instance. 0 means use DialTimeout (10s).
	DialTimeout time.Duration
}

// Service implements SSL Observatory business logic.
type Service struct {
	targets  TargetRepository
	scans    ScanResultRepository
	notifier Notifier
	logger   *logger.Logger
	cfg      Config
}

// NewService creates a new SSL Observatory service. notifier may be
// nil — alerts simply become a no-op in that case.
func NewService(targets TargetRepository, scans ScanResultRepository, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		targets: targets,
		scans:   scans,
		logger:  log.Named("ssl_observatory"),
		cfg: Config{
			PerTargetConcurrency: DefaultPerTargetConcurrency,
			DialTimeout:          DialTimeout,
		},
	}
}

// SetNotifier installs a notifier. Safe to call once after construction.
func (s *Service) SetNotifier(n Notifier) {
	s.notifier = n
}

// SetConfig overrides the service config. Zero fields keep the
// existing value.
func (s *Service) SetConfig(cfg Config) {
	if cfg.PerTargetConcurrency > 0 {
		s.cfg.PerTargetConcurrency = cfg.PerTargetConcurrency
	}
	if cfg.DialTimeout > 0 {
		s.cfg.DialTimeout = cfg.DialTimeout
	}
}

// dialTimeout returns the effective per-dial timeout, never zero.
func (s *Service) dialTimeout() time.Duration {
	if s.cfg.DialTimeout > 0 {
		return s.cfg.DialTimeout
	}
	return DialTimeout
}

// perTargetConcurrency returns the effective concurrency cap.
func (s *Service) perTargetConcurrency() int {
	if s.cfg.PerTargetConcurrency > 0 {
		return s.cfg.PerTargetConcurrency
	}
	return DefaultPerTargetConcurrency
}

// ============================================================================
// Input validation
// ============================================================================

// validatePort rejects ports outside the well-formed 1..65535 range.
func validatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%w: port %d out of range", ErrInvalidInput, port)
	}
	return nil
}

// normalizeHostname trims whitespace and rejects empty / control-char
// strings. Lowercased so duplicate-target checks behave consistently.
func normalizeHostname(h string) (string, error) {
	h = strings.TrimSpace(strings.ToLower(h))
	if h == "" {
		return "", fmt.Errorf("%w: hostname is required", ErrInvalidInput)
	}
	for _, r := range h {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%w: hostname contains control characters", ErrInvalidInput)
		}
	}
	return h, nil
}

// sanitizeExtraHostnames normalizes and deduplicates the SNI list
// (excluding the primary hostname). Empty entries are dropped.
func sanitizeExtraHostnames(primary string, extras []string) ([]string, error) {
	out := make([]string, 0, len(extras))
	seen := map[string]struct{}{primary: {}}
	for _, h := range extras {
		h = strings.TrimSpace(strings.ToLower(h))
		if h == "" {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		for _, r := range h {
			if r < 0x20 || r == 0x7f {
				return nil, fmt.Errorf("%w: extra hostname contains control characters", ErrInvalidInput)
			}
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out, nil
}

// sanitizeThresholds keeps only positive, distinct values, sorted
// descending so the alert hook always notifies the largest unmet
// threshold first.
func sanitizeThresholds(in []int) []int {
	seen := map[int]struct{}{}
	out := make([]int, 0, len(in))
	for _, v := range in {
		if v <= 0 {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	// Descending insertion sort — small list.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] < out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// ============================================================================
// Target CRUD
// ============================================================================

// ListTargets returns all SSL targets for a host.
func (s *Service) ListTargets(ctx context.Context, hostID uuid.UUID) ([]models.SSLTarget, error) {
	return s.targets.List(ctx, hostID)
}

// GetTarget returns an SSL target by ID.
func (s *Service) GetTarget(ctx context.Context, id uuid.UUID) (*models.SSLTarget, error) {
	return s.targets.GetByID(ctx, id)
}

// CreateTarget creates a new SSL target.
func (s *Service) CreateTarget(ctx context.Context, hostID uuid.UUID, input models.CreateSSLTargetInput) (*models.SSLTarget, error) {
	if hostID == uuid.Nil {
		return nil, fmt.Errorf("%w: host_id is required", ErrInvalidInput)
	}

	name := strings.TrimSpace(input.Name)
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalidInput)
	}

	hostname, err := normalizeHostname(input.Hostname)
	if err != nil {
		return nil, err
	}

	port := input.Port
	if port == 0 {
		port = 443
	}
	if err := validatePort(port); err != nil {
		return nil, err
	}

	extras, err := sanitizeExtraHostnames(hostname, input.ExtraHostnames)
	if err != nil {
		return nil, err
	}

	thresholds := sanitizeThresholds(input.AlertThresholds)

	target := &models.SSLTarget{
		ID:              uuid.New(),
		HostID:          hostID,
		Name:            name,
		Hostname:        hostname,
		Port:            port,
		ExtraHostnames:  extras,
		AlertThresholds: int64Slice(thresholds),
		Enabled:         true,
	}

	if err := s.targets.Create(ctx, target); err != nil {
		return nil, err
	}
	return target, nil
}

// UpdateTarget patches an existing SSL target with the supplied
// fields. Nil fields are left untouched. ExtraHostnames /
// AlertThresholds always replace when non-nil (empty slice clears).
func (s *Service) UpdateTarget(ctx context.Context, id uuid.UUID, input models.UpdateSSLTargetInput) (*models.SSLTarget, error) {
	target, err := s.targets.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		n := strings.TrimSpace(*input.Name)
		if n == "" {
			return nil, fmt.Errorf("%w: name cannot be empty", ErrInvalidInput)
		}
		target.Name = n
	}
	if input.Hostname != nil {
		h, err := normalizeHostname(*input.Hostname)
		if err != nil {
			return nil, err
		}
		target.Hostname = h
	}
	if input.Port != nil {
		if err := validatePort(*input.Port); err != nil {
			return nil, err
		}
		target.Port = *input.Port
	}
	if input.ExtraHostnames != nil {
		extras, err := sanitizeExtraHostnames(target.Hostname, input.ExtraHostnames)
		if err != nil {
			return nil, err
		}
		target.ExtraHostnames = extras
	}
	if input.AlertThresholds != nil {
		target.AlertThresholds = int64Slice(sanitizeThresholds(input.AlertThresholds))
	}
	if input.Enabled != nil {
		target.Enabled = *input.Enabled
	}

	if err := s.targets.Update(ctx, target); err != nil {
		return nil, err
	}
	return target, nil
}

// DeleteTarget deletes an SSL target.
func (s *Service) DeleteTarget(ctx context.Context, id uuid.UUID) error {
	return s.targets.Delete(ctx, id)
}

// ============================================================================
// Scanning
// ============================================================================

// ScanTarget performs TLS scans on a single target — one handshake per
// hostname (primary + extra SNI). One scan_result row is persisted per
// (target, hostname). The returned slice mirrors that ordering.
func (s *Service) ScanTarget(ctx context.Context, targetID uuid.UUID) ([]models.SSLScanResult, error) {
	target, err := s.targets.GetByID(ctx, targetID)
	if err != nil {
		return nil, fmt.Errorf("get target: %w", err)
	}

	results := s.performScanWithSNI(ctx, target)
	for i := range results {
		if err := s.scans.Create(ctx, &results[i]); err != nil {
			return nil, fmt.Errorf("save scan result: %w", err)
		}
		s.maybeAlert(ctx, target, &results[i])
	}

	return results, nil
}

// ScanAll scans every enabled target for a host (or every host when
// hostID == uuid.Nil), respecting the per-target concurrency cap.
// Returns the number of distinct (target, hostname) scans completed.
func (s *Service) ScanAll(ctx context.Context, hostID uuid.UUID) (int, error) {
	targets, err := s.targets.ListEnabled(ctx, hostID)
	if err != nil {
		return 0, fmt.Errorf("list enabled targets: %w", err)
	}
	if len(targets) == 0 {
		return 0, nil
	}

	cap := s.perTargetConcurrency()
	if cap > len(targets) {
		cap = len(targets)
	}
	if cap < 1 {
		cap = 1
	}

	sem := make(chan struct{}, cap)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		scanned  int
		firstErr error
	)

	for i := range targets {
		t := targets[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				mu.Lock()
				if firstErr == nil {
					firstErr = ctx.Err()
				}
				mu.Unlock()
				return
			}
			defer func() { <-sem }()

			results := s.performScanWithSNI(ctx, &t)
			for i := range results {
				if err := s.scans.Create(ctx, &results[i]); err != nil {
					s.logger.Error("failed to save scan result",
						"target_id", t.ID,
						"hostname", results[i].ScanHostname,
						"error", err)
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					continue
				}
				s.maybeAlert(ctx, &t, &results[i])
				mu.Lock()
				scanned++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return scanned, firstErr
}

// performScanWithSNI dials each hostname in the target's ScanHostnames
// list with the hostname as the SNI server_name. Returns one
// SSLScanResult per hostname (primary first), even when the dial fails.
func (s *Service) performScanWithSNI(ctx context.Context, target *models.SSLTarget) []models.SSLScanResult {
	hostnames := target.ScanHostnames()
	if len(hostnames) == 0 {
		hostnames = []string{target.Hostname}
	}
	out := make([]models.SSLScanResult, 0, len(hostnames))
	for _, h := range hostnames {
		out = append(out, s.performScan(ctx, target, h))
	}
	return out
}

// performScan opens one TLS handshake to (target.IP-or-hostname:port)
// with sni as the server_name. InsecureSkipVerify is intentionally on
// because we *analyze* the cert (including invalid ones); chain
// validity is computed afterwards from PeerCertificates.
func (s *Service) performScan(ctx context.Context, target *models.SSLTarget, sni string) models.SSLScanResult {
	start := time.Now()
	addr := fmt.Sprintf("%s:%d", target.Hostname, target.Port)

	result := models.SSLScanResult{
		ID:           uuid.New(),
		TargetID:     target.ID,
		ScanHostname: sni,
		Grade:        "U",
		Score:        0,
	}

	dialer := &net.Dialer{Timeout: s.dialTimeout()}
	dialCtx, cancel := context.WithTimeout(ctx, s.dialTimeout())
	defer cancel()

	tlsConfig := &tls.Config{
		ServerName: sni,
		// We analyze even invalid certs. Verification is performed
		// in-band against the returned chain so we still know whether
		// the cert would be trusted.
		InsecureSkipVerify: true, //nolint:gosec // intentional — see comment
		MinVersion:         tls.VersionTLS10,
	}

	conn, err := (&tls.Dialer{
		NetDialer: dialer,
		Config:    tlsConfig,
	}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("TLS connection failed: %v", err)
		result.ScanDurationMs = int(time.Since(start).Milliseconds())
		result.ScannedAt = time.Now()
		return result
	}
	defer func() { _ = conn.Close() }()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		result.ErrorMessage = "internal: tls.Dialer did not return *tls.Conn"
		result.ScanDurationMs = int(time.Since(start).Milliseconds())
		result.ScannedAt = time.Now()
		return result
	}

	state := tlsConn.ConnectionState()

	// Protocol version
	result.ProtocolVersions = []string{tlsVersionName(state.Version)}

	// Cipher suite
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	ciphers := []CipherInfo{{
		Name:     cipherName,
		ID:       state.CipherSuite,
		Strength: cipherStrength(cipherName),
	}}
	if cipherJSON, jerr := json.Marshal(ciphers); jerr == nil {
		result.CipherSuites = cipherJSON
	}

	// Certificate analysis
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.CertificateCN = cert.Subject.CommonName
		result.CertificateIssuer = cert.Issuer.CommonName
		nb := cert.NotBefore
		na := cert.NotAfter
		result.CertNotBefore = &nb
		result.CertNotAfter = &na
		result.CertKeyBits = certKeyBits(cert)
		result.CertKeyType = certKeyType(cert)
		result.CertChainLength = len(state.PeerCertificates)

		var sans []string
		sans = append(sans, cert.DNSNames...)
		for _, ip := range cert.IPAddresses {
			sans = append(sans, ip.String())
		}
		result.CertificateSANs = sans

		opts := x509.VerifyOptions{
			DNSName:       sni,
			CurrentTime:   time.Now(),
			Intermediates: x509.NewCertPool(),
		}
		for _, ic := range state.PeerCertificates[1:] {
			opts.Intermediates.AddCert(ic)
		}
		_, verifyErr := cert.Verify(opts)
		result.CertChainValid = verifyErr == nil
	}

	// HSTS check requires an HTTP exchange, which this module deliberately
	// does not perform. Left as false — the proxy module (session 09)
	// surfaces HSTS state from the configured response headers.
	result.HasHSTS = false

	result.HasOCSPStapling = len(state.OCSPResponse) > 0
	result.HasSCT = len(state.SignedCertificateTimestamps) > 0

	result.Score = calculateScore(&result, state.Version)
	result.Grade = scoreToGrade(result.Score)

	result.ScanDurationMs = int(time.Since(start).Milliseconds())
	result.ScannedAt = time.Now()

	return result
}

// maybeAlert dispatches a cert-expiry notification when the scan's
// remaining-days value has dropped at or below one of the target's
// configured thresholds. The fired threshold is the *smallest* one
// the cert currently satisfies — i.e. the most urgent bucket the
// cert just crossed into. A best-effort log.Warn covers notifier
// failures — we never unwind the scan over notification trouble.
func (s *Service) maybeAlert(ctx context.Context, target *models.SSLTarget, scan *models.SSLScanResult) {
	if s.notifier == nil || scan.CertNotAfter == nil {
		return
	}
	thresholds := target.EffectiveThresholds()
	if len(thresholds) == 0 {
		return
	}
	daysLeft := int(time.Until(*scan.CertNotAfter).Hours() / 24)
	if daysLeft <= 0 {
		return
	}

	// thresholds are stored descending [30,14,7,3,1]. Iterate from the
	// end so we find the smallest threshold that daysLeft satisfies.
	picked := -1
	for i := len(thresholds) - 1; i >= 0; i-- {
		if daysLeft <= thresholds[i] {
			picked = thresholds[i]
			break
		}
	}
	if picked < 0 {
		return
	}

	if err := s.notifier.NotifyCertExpiring(ctx, target, scan, daysLeft, picked); err != nil {
		s.logger.Warn("ssl cert-expiry notification failed",
			"target_id", target.ID,
			"hostname", scan.ScanHostname,
			"days_left", daysLeft,
			"threshold", picked,
			"error", err,
		)
	}
}

// ============================================================================
// Scoring
// ============================================================================

// calculateScore is a deterministic scoring rubric matching v26.2.7 but
// extracted as a free function so it is trivially unit-testable.
func calculateScore(result *models.SSLScanResult, tlsVersion uint16) int {
	score := 0

	// Protocol score (max 30)
	switch tlsVersion {
	case tls.VersionTLS13:
		score += 30
	case tls.VersionTLS12:
		score += 25
	case tls.VersionTLS11:
		score += 10
	case tls.VersionTLS10:
		score += 5
	}

	// Certificate score (max 30)
	if result.CertChainValid {
		score += 15
	}
	if result.CertNotAfter != nil && result.CertNotAfter.After(time.Now()) {
		score += 10
	}
	if result.CertKeyBits >= 2048 {
		score += 5
	}

	// Features score (max 20)
	if result.HasOCSPStapling {
		score += 5
	}
	if result.HasSCT {
		score += 5
	}
	if result.HasHSTS {
		score += 5
	}
	if result.CertChainLength > 1 && result.CertChainLength < 5 {
		score += 5
	}

	// Cipher score (max 20)
	cipherName := ""
	if result.CipherSuites != nil {
		var ciphers []CipherInfo
		if json.Unmarshal(result.CipherSuites, &ciphers) == nil && len(ciphers) > 0 {
			cipherName = ciphers[0].Name
		}
	}
	switch {
	case strings.Contains(cipherName, "GCM"), strings.Contains(cipherName, "CHACHA20"):
		score += 20
	case strings.Contains(cipherName, "CBC"):
		score += 10
	case cipherName != "":
		score += 5
	}

	return score
}

func scoreToGrade(score int) string {
	switch {
	case score >= 95:
		return "A+"
	case score >= 85:
		return "A"
	case score >= 70:
		return "B"
	case score >= 55:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func cipherStrength(name string) string {
	switch {
	case strings.Contains(name, "256"), strings.Contains(name, "CHACHA20"):
		return "strong"
	case strings.Contains(name, "128"):
		return "acceptable"
	case strings.Contains(name, "3DES"), strings.Contains(name, "RC4"):
		return "weak"
	default:
		return "unknown"
	}
}

func certKeyType(cert *x509.Certificate) string {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	default:
		return "unknown"
	}
}

func certKeyBits(cert *x509.Certificate) int {
	if key, ok := cert.PublicKey.(interface{ Size() int }); ok {
		return key.Size() * 8
	}
	return 0
}

// int64Slice converts an int slice to []int64 for pq.Int64Array
// (the array type postgres requires for INTEGER[]).
func int64Slice(in []int) []int64 {
	out := make([]int64, len(in))
	for i, v := range in {
		out[i] = int64(v)
	}
	return out
}

// ============================================================================
// Dashboard / Queries
// ============================================================================

// GetLatestScan returns the latest scan result for a target (any hostname).
func (s *Service) GetLatestScan(ctx context.Context, targetID uuid.UUID) (*models.SSLScanResult, error) {
	return s.scans.GetLatestByTarget(ctx, targetID)
}

// GetLatestScanByHostname returns the latest scan result for one
// (target, hostname) pair.
func (s *Service) GetLatestScanByHostname(ctx context.Context, targetID uuid.UUID, hostname string) (*models.SSLScanResult, error) {
	return s.scans.GetLatestByTargetHostname(ctx, targetID, hostname)
}

// ListScans returns paginated scan results for a target.
func (s *Service) ListScans(ctx context.Context, targetID uuid.UUID, limit, offset int) ([]models.SSLScanResult, int, error) {
	return s.scans.ListByTarget(ctx, targetID, limit, offset)
}

// GetExpiringCerts returns certs expiring within N days.
func (s *Service) GetExpiringCerts(ctx context.Context, hostID uuid.UUID, days int) ([]models.SSLScanResult, error) {
	return s.scans.GetExpiringCerts(ctx, hostID, days)
}

// GetDashboardStats returns aggregated dashboard statistics.
func (s *Service) GetDashboardStats(ctx context.Context, hostID uuid.UUID) (*models.SSLDashboardStats, error) {
	return s.scans.GetDashboardStats(ctx, hostID)
}
