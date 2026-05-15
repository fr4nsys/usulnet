// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package dns provides DNS provider plugin orchestration for the
// usulnet platform. It owns the persistence boundary for providers,
// records, and ACME DNS-01 orders, and brokers calls to provider
// plugins (Cloudflare, Route53, DigitalOcean, RFC 2136) registered at
// boot time.
//
// Improvements vs v26.2.7:
//
//   - The v26.2.7 module ran an embedded miekg/dns authoritative
//     server. session-10 puts that out of scope; this rewrite is
//     entirely focused on dropping records into third-party DNS
//     providers for ACME DNS-01 challenges and proxy A/CNAME mgmt.
//   - Provider plugins live under internal/services/dns/providers/<kind>/
//     and register themselves via the Registry — explicit registration
//     means one place to look when a plugin "doesn't show up".
//   - Provider credentials are encrypted at rest with the installation
//     AES-256-GCM key (same posture as recon connectors). The repo
//     stores ciphertext, the service decrypts only when invoking a
//     plugin, and credentials are never serialized to API responses.
//   - The ACME DNS-01 flow is a persistent state machine
//     (see acme.go) — orders survive restarts mid-flight.
//   - All provider tests run against in-process httptest servers; no
//     real-API calls.
package dns

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Encryptor is the contract the service needs from
// internal/pkg/crypto.AESEncryptor. Declaring it here keeps the
// service unit-testable without spinning up a real key.
type Encryptor interface {
	EncryptString(plaintext string) (string, error)
	DecryptString(ciphertext string) (string, error)
}

// ProviderRepository persists DNS providers.
type ProviderRepository interface {
	Create(ctx context.Context, p *models.DNSProvider) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.DNSProvider, error)
	List(ctx context.Context, hostID uuid.UUID) ([]*models.DNSProvider, error)
	ListAll(ctx context.Context) ([]*models.DNSProvider, error)
	Update(ctx context.Context, p *models.DNSProvider) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// RecordRepository persists DNS records.
type RecordRepository interface {
	Create(ctx context.Context, rec *models.DNSRecord) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.DNSRecord, error)
	ListByProvider(ctx context.Context, providerID uuid.UUID) ([]*models.DNSRecord, error)
	ListByHost(ctx context.Context, hostID uuid.UUID) ([]*models.DNSRecord, error)
	Update(ctx context.Context, rec *models.DNSRecord) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// OrderRepository persists ACME DNS-01 orders.
type OrderRepository interface {
	Create(ctx context.Context, o *models.DNSACMEOrder) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.DNSACMEOrder, error)
	ListByHost(ctx context.Context, hostID uuid.UUID) ([]*models.DNSACMEOrder, error)
	ListInFlight(ctx context.Context) ([]*models.DNSACMEOrder, error)
	Update(ctx context.Context, o *models.DNSACMEOrder) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// AuditRepository persists DNS audit log entries.
type AuditRepository interface {
	Create(ctx context.Context, e *models.DNSAuditLog) error
	List(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.DNSAuditLog, int, error)
	ListByOrder(ctx context.Context, orderID uuid.UUID) ([]*models.DNSAuditLog, error)
}

// Config holds DNS service configuration.
type Config struct {
	// PropagationTimeout caps how long the ACME state machine waits
	// for a TXT record to be observable before declaring failure.
	PropagationTimeout time.Duration
	// PropagationCheckInterval is the polling cadence between TXT
	// observability checks.
	PropagationCheckInterval time.Duration
	// PropagationCheckMaxAttempts caps the number of attempts the
	// state machine will make. If 0, defaults to PropagationTimeout
	// divided by PropagationCheckInterval.
	PropagationCheckMaxAttempts int
	// ResolverAddress is the DNS resolver used to verify TXT record
	// propagation. Default "1.1.1.1:53".
	ResolverAddress string
}

// DefaultConfig returns sensible defaults: poll every 10s, give up
// after 5 minutes total.
func DefaultConfig() Config {
	return Config{
		PropagationTimeout:       5 * time.Minute,
		PropagationCheckInterval: 10 * time.Second,
		ResolverAddress:          "1.1.1.1:53",
	}
}

// Resolver is the interface the ACME flow uses to verify TXT record
// propagation. The default implementation queries a public resolver
// over UDP; tests inject a fake.
type Resolver interface {
	LookupTXT(ctx context.Context, fqdn string) ([]string, error)
}

// Service orchestrates DNS providers, records, and ACME DNS-01 orders.
type Service struct {
	providers ProviderRepository
	records   RecordRepository
	orders    OrderRepository
	audit     AuditRepository
	registry  *Registry
	enc       Encryptor
	resolver  Resolver
	cfg       Config
	logger    *logger.Logger

	// providerMu guards the in-memory plugin cache (kept short-lived
	// because credentials may rotate at any time).
	providerMu sync.Mutex
}

// NewService wires the service. registry must contain the plugins
// the binary should expose; the wiring layer is responsible for
// registering them.
func NewService(
	providers ProviderRepository,
	records RecordRepository,
	orders OrderRepository,
	audit AuditRepository,
	registry *Registry,
	enc Encryptor,
	cfg Config,
	log *logger.Logger,
) *Service {
	if registry == nil {
		registry = NewRegistry()
	}
	if log == nil {
		log = logger.Nop()
	}
	if cfg.PropagationTimeout == 0 {
		cfg.PropagationTimeout = 5 * time.Minute
	}
	if cfg.PropagationCheckInterval == 0 {
		cfg.PropagationCheckInterval = 10 * time.Second
	}
	if cfg.ResolverAddress == "" {
		cfg.ResolverAddress = "1.1.1.1:53"
	}
	if cfg.PropagationCheckMaxAttempts == 0 && cfg.PropagationCheckInterval > 0 {
		cfg.PropagationCheckMaxAttempts = int(cfg.PropagationTimeout / cfg.PropagationCheckInterval)
	}

	s := &Service{
		providers: providers,
		records:   records,
		orders:    orders,
		audit:     audit,
		registry:  registry,
		enc:       enc,
		cfg:       cfg,
		logger:    log.Named("dns"),
	}
	s.resolver = newDNSResolver(cfg.ResolverAddress)
	return s
}

// SetResolver replaces the propagation resolver. Tests use this to
// inject deterministic behavior.
func (s *Service) SetResolver(r Resolver) {
	if r != nil {
		s.resolver = r
	}
}

// Registry exposes the registered plugin set so callers (handlers,
// CLI) can render the capability matrix.
func (s *Service) Registry() *Registry { return s.registry }

// SupportedProviders is a convenience that maps the registry into the
// REST API shape.
func (s *Service) SupportedProviders() []Capabilities {
	return s.registry.Capabilities()
}

// ============================================================================
// Provider CRUD
// ============================================================================

// CreateProviderInput carries the user-supplied fields for a new
// provider. Credentials is the plaintext JSON blob (the service
// encrypts it before persisting); the caller is expected to validate
// shape against the registry's CredentialFields advertisement at the
// HTTP boundary.
type CreateProviderInput struct {
	HostID       uuid.UUID
	Name         string
	ProviderKind models.DNSProviderKind
	Description  string
	Enabled      bool
	Credentials  []byte
	Config       map[string]any
}

// ListProviders returns the providers for a host. Credentials are
// always blank in the returned slice to avoid accidental leakage; use
// loadDecryptedCredentials internally when invoking a plugin.
func (s *Service) ListProviders(ctx context.Context, hostID uuid.UUID) ([]*models.DNSProvider, error) {
	all, err := s.providers.List(ctx, hostID)
	if err != nil {
		return nil, err
	}
	for _, p := range all {
		p.Credentials = ""
	}
	return all, nil
}

// GetProvider returns a single provider with the credentials field
// blanked.
func (s *Service) GetProvider(ctx context.Context, id uuid.UUID) (*models.DNSProvider, error) {
	p, err := s.providers.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	p.Credentials = ""
	return p, nil
}

// CreateProvider persists a new provider. Credentials are encrypted
// at rest. After the row is committed, the service spins up a plugin
// once via VerifyCredentials so a wrong token is reported immediately.
func (s *Service) CreateProvider(ctx context.Context, in CreateProviderInput, userID *uuid.UUID) (*models.DNSProvider, error) {
	if in.Name == "" {
		return nil, fmt.Errorf("dns: provider name is required")
	}
	if !s.registry.Has(in.ProviderKind) {
		return nil, fmt.Errorf("%w: %s", ErrProviderNotFound, in.ProviderKind)
	}
	if len(in.Credentials) == 0 {
		return nil, fmt.Errorf("dns: credentials are required")
	}
	if !json.Valid(in.Credentials) {
		return nil, fmt.Errorf("dns: credentials are not valid JSON")
	}

	encrypted, err := s.enc.EncryptString(string(in.Credentials))
	if err != nil {
		return nil, fmt.Errorf("dns: encrypt credentials: %w", err)
	}

	p := &models.DNSProvider{
		ID:           uuid.New(),
		HostID:       in.HostID,
		Name:         in.Name,
		ProviderKind: in.ProviderKind,
		Enabled:      in.Enabled,
		Description:  in.Description,
		Credentials:  encrypted,
		Config:       in.Config,
		CreatedBy:    userID,
		UpdatedBy:    userID,
	}
	if p.Config == nil {
		p.Config = map[string]any{}
	}

	if err := s.providers.Create(ctx, p); err != nil {
		return nil, err
	}

	s.logAudit(ctx, p.HostID, userID, "create", "provider", p.ID, p.Name, string(p.ProviderKind))

	plugin, err := s.openPlugin(ctx, p, in.Credentials)
	if err != nil {
		s.logger.Warn("plugin verify failed at create", "provider", p.ID, "error", err)
	} else {
		if vErr := plugin.VerifyCredentials(ctx); vErr != nil {
			s.logger.Warn("provider credentials rejected by upstream", "provider", p.ID, "error", vErr)
		}
		_ = plugin.Close()
	}

	p.Credentials = ""
	return p, nil
}

// UpdateProviderInput carries the user-mutable fields. If Credentials
// is nil, the existing ciphertext is preserved.
type UpdateProviderInput struct {
	Name        string
	Description string
	Enabled     bool
	Credentials []byte
	Config      map[string]any
}

// UpdateProvider patches the row in place.
func (s *Service) UpdateProvider(ctx context.Context, id uuid.UUID, in UpdateProviderInput, userID *uuid.UUID) (*models.DNSProvider, error) {
	cur, err := s.providers.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	cur.Name = in.Name
	cur.Description = in.Description
	cur.Enabled = in.Enabled
	cur.Config = in.Config
	if cur.Config == nil {
		cur.Config = map[string]any{}
	}
	cur.UpdatedBy = userID

	if len(in.Credentials) > 0 {
		if !json.Valid(in.Credentials) {
			return nil, fmt.Errorf("dns: credentials are not valid JSON")
		}
		encrypted, encErr := s.enc.EncryptString(string(in.Credentials))
		if encErr != nil {
			return nil, fmt.Errorf("dns: encrypt credentials: %w", encErr)
		}
		cur.Credentials = encrypted
	} else {
		// Preserve existing ciphertext: set to empty so the repo's
		// Update preserves the column.
		cur.Credentials = ""
	}

	if err := s.providers.Update(ctx, cur); err != nil {
		return nil, err
	}

	s.logAudit(ctx, cur.HostID, userID, "update", "provider", cur.ID, cur.Name, "")

	cur.Credentials = ""
	return cur, nil
}

// DeleteProvider removes a provider. The cascade in the migration
// removes records and orders too; this method also writes an audit
// entry so the timeline is preserved.
func (s *Service) DeleteProvider(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	cur, err := s.providers.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.providers.Delete(ctx, id); err != nil {
		return err
	}
	s.logAudit(ctx, cur.HostID, userID, "delete", "provider", id, cur.Name, "")
	return nil
}

// ============================================================================
// Records
// ============================================================================

// RecordInput is the input shape for the record CRUD endpoints.
type RecordInput struct {
	Name    string
	Type    models.DNSRecordType
	Content string
	TTL     int
}

// ListRecords returns persisted records for a provider.
func (s *Service) ListRecords(ctx context.Context, providerID uuid.UUID) ([]*models.DNSRecord, error) {
	return s.records.ListByProvider(ctx, providerID)
}

// ListHostRecords returns persisted records across all providers for
// a host.
func (s *Service) ListHostRecords(ctx context.Context, hostID uuid.UUID) ([]*models.DNSRecord, error) {
	return s.records.ListByHost(ctx, hostID)
}

// CreateRecord asks the upstream provider to add the record and
// persists the resulting row. If the upstream call fails, no row is
// written.
func (s *Service) CreateRecord(ctx context.Context, providerID uuid.UUID, in RecordInput, userID *uuid.UUID) (*models.DNSRecord, error) {
	p, plaintext, err := s.loadDecryptedCredentials(ctx, providerID)
	if err != nil {
		return nil, err
	}
	plugin, err := s.openPlugin(ctx, p, plaintext)
	if err != nil {
		return nil, err
	}
	defer plugin.Close()

	if in.TTL <= 0 {
		in.TTL = 300
	}

	created, err := plugin.CreateRecord(ctx, ProviderRecord{
		Name: in.Name, Type: in.Type, Content: in.Content, TTL: in.TTL,
	})
	if err != nil {
		return nil, err
	}

	rec := &models.DNSRecord{
		ID:               uuid.New(),
		ProviderID:       providerID,
		HostID:           p.HostID,
		Name:             in.Name,
		Type:             in.Type,
		Content:          in.Content,
		TTL:              in.TTL,
		ProviderRecordID: created.ID,
		ManagedBy:        "manual",
	}
	if err := s.records.Create(ctx, rec); err != nil {
		// Best-effort cleanup so we don't leave an orphan upstream.
		if delErr := plugin.DeleteRecord(ctx, created.ID, created); delErr != nil &&
			!stderrors.Is(delErr, ErrRecordNotFound) {
			s.logger.Warn("dns: cleanup of orphan upstream record failed", "error", delErr)
		}
		return nil, err
	}

	s.logAudit(ctx, p.HostID, userID, "create", "record", rec.ID, rec.Name, fmt.Sprintf("type=%s ttl=%d", rec.Type, rec.TTL))
	return rec, nil
}

// DeleteRecord removes a record both upstream and locally.
func (s *Service) DeleteRecord(ctx context.Context, recordID uuid.UUID, userID *uuid.UUID) error {
	rec, err := s.records.GetByID(ctx, recordID)
	if err != nil {
		return err
	}

	p, plaintext, err := s.loadDecryptedCredentials(ctx, rec.ProviderID)
	if err != nil {
		return err
	}
	plugin, err := s.openPlugin(ctx, p, plaintext)
	if err != nil {
		return err
	}
	defer plugin.Close()

	pr := ProviderRecord{
		ID: rec.ProviderRecordID, Name: rec.Name, Type: rec.Type, Content: rec.Content, TTL: rec.TTL,
	}
	if err := plugin.DeleteRecord(ctx, rec.ProviderRecordID, pr); err != nil &&
		!stderrors.Is(err, ErrRecordNotFound) {
		return err
	}
	if err := s.records.Delete(ctx, rec.ID); err != nil {
		return err
	}
	s.logAudit(ctx, p.HostID, userID, "delete", "record", rec.ID, rec.Name, fmt.Sprintf("type=%s", rec.Type))
	return nil
}

// ============================================================================
// Audit
// ============================================================================

// ListAudit returns recent audit entries for a host.
func (s *Service) ListAudit(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.DNSAuditLog, int, error) {
	return s.audit.List(ctx, hostID, limit, offset)
}

// ListOrderAudit returns audit entries for a single ACME order.
func (s *Service) ListOrderAudit(ctx context.Context, orderID uuid.UUID) ([]*models.DNSAuditLog, error) {
	return s.audit.ListByOrder(ctx, orderID)
}

// ============================================================================
// Internal helpers
// ============================================================================

// loadDecryptedCredentials returns the provider row plus the
// plaintext credential blob.
func (s *Service) loadDecryptedCredentials(ctx context.Context, providerID uuid.UUID) (*models.DNSProvider, []byte, error) {
	p, err := s.providers.GetByID(ctx, providerID)
	if err != nil {
		return nil, nil, err
	}
	if !p.Enabled {
		return nil, nil, fmt.Errorf("dns: provider %s is disabled", p.Name)
	}
	if s.enc == nil {
		return nil, nil, fmt.Errorf("dns: encryptor not configured")
	}
	plaintext, err := s.enc.DecryptString(p.Credentials)
	if err != nil {
		return nil, nil, fmt.Errorf("dns: decrypt credentials: %w", err)
	}
	return p, []byte(plaintext), nil
}

// openPlugin builds a Provider for the given row. Currently no
// caching — credentials may rotate, and the cost of a fresh struct is
// trivial compared to the network round-trip the plugin will make.
func (s *Service) openPlugin(ctx context.Context, p *models.DNSProvider, credentials []byte) (Provider, error) {
	s.providerMu.Lock()
	defer s.providerMu.Unlock()

	factory, err := s.registry.Factory(p.ProviderKind)
	if err != nil {
		return nil, err
	}
	cfg := p.Config
	if cfg == nil {
		cfg = map[string]any{}
	}
	plugin, err := factory(ctx, credentials, cfg)
	if err != nil {
		return nil, fmt.Errorf("dns: open provider plugin: %w", err)
	}
	return plugin, nil
}

// logAudit writes a best-effort audit entry. Failures are logged but
// don't propagate so a working DNS write isn't masked by an audit
// outage.
func (s *Service) logAudit(ctx context.Context, hostID uuid.UUID, userID *uuid.UUID, action, resType string, resID uuid.UUID, resName, details string) {
	entry := &models.DNSAuditLog{
		HostID:       hostID,
		UserID:       userID,
		Action:       action,
		ResourceType: resType,
		ResourceID:   resID,
		ResourceName: resName,
		Details:      details,
	}
	if err := s.audit.Create(ctx, entry); err != nil {
		s.logger.Warn("dns: write audit entry failed", "action", action, "error", err)
	}
}

// challengeFQDN returns the standard ACME DNS-01 challenge name for a
// domain. Exported helper for tests.
func challengeFQDN(domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	// Wildcard certificate: ACME hashes the apex of the wildcard.
	domain = strings.TrimPrefix(domain, "*.")
	return "_acme-challenge." + domain
}
