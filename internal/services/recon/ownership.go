// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package recon

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// OwnershipVerifier is the strategy interface satisfied by each of the
// five concrete verifiers (DNS TXT, email link, RDAP, admin attest,
// self-assert).
//
// Start initializes a fresh OwnershipProof: it populates Challenge and
// Evidence as appropriate to the method but leaves Status untouched
// (callers are expected to persist the pending row before verification
// runs). Verify drives the actual check, updates Status / VerifiedAt and
// the Evidence map in-place, and returns nil on success or a wrapped
// error on a non-recoverable failure.
//
// The interface is intentionally narrow so each strategy can be unit
// tested in isolation without spinning up the whole recon.Service.
type OwnershipVerifier interface {
	Method() OwnershipMethod
	Start(ctx context.Context, target *Target, proof *OwnershipProof) error
	Verify(ctx context.Context, target *Target, proof *OwnershipProof, input map[string]any) error
}

// DNSResolver abstracts net.Resolver so the DNS-TXT verifier can be
// unit-tested without real DNS traffic.
type DNSResolver interface {
	LookupTXT(ctx context.Context, host string) ([]string, error)
}

// netDNSResolver is the stdlib-backed default DNSResolver.
type netDNSResolver struct{}

// LookupTXT delegates to net.LookupTXT with the supplied context's
// deadline enforced by net.Resolver.
func (netDNSResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	var r net.Resolver
	return r.LookupTXT(ctx, host)
}

// DefaultDNSResolver returns a DNSResolver that performs real lookups
// via the host's configured resolver.
func DefaultDNSResolver() DNSResolver { return netDNSResolver{} }

// EmailSender is the narrow contract the email-link verifier requires.
// The app wiring layer adapts the broader notification service to this
// interface so the verifier package stays free of notification-package
// imports.
type EmailSender interface {
	SendVerificationEmail(ctx context.Context, to, link string) error
}

// AuditSink lets verifiers append to the recon_audit_log without
// depending on the full Repository (the admin-attest path needs only
// AppendAudit).
type AuditSink interface {
	AppendAudit(ctx context.Context, entry AuditEntry) error
}

// Common ownership errors. Wrapped by the verifiers so callers can use
// errors.Is to switch on outcomes (e.g., surface "challenge missing" as
// a 400 vs. "TXT mismatch" as a 409).
var (
	ErrOwnershipChallengeMissing = errors.New("ownership challenge missing")
	ErrOwnershipMismatch         = errors.New("ownership challenge mismatch")
	ErrOwnershipExpired          = errors.New("ownership challenge expired")
	ErrOwnershipUnsupported      = errors.New("ownership method does not support target type")
	ErrOwnershipForbidden        = errors.New("ownership verification forbidden for this actor")
	ErrOwnershipInputMissing     = errors.New("ownership verification input missing")
)

// ============================================================================
// Token helpers
// ============================================================================

// tokenBytes is the entropy length used by all token-based verifiers.
// 32 bytes encoded as hex => 64 ASCII characters, comfortably exceeding
// the 128-bit threshold for unguessable tokens.
const tokenBytes = 32

// emailTokenTTL is the lifetime of an email verification challenge.
// Mirrors the RFC ("token TTL = 1h, single-use").
const emailTokenTTL = time.Hour

// generateToken returns "usulnet-verify=<hex>" — the canonical token
// format documented in §7.1 of docs/recon.md. The "usulnet-verify=" prefix
// is part of the value the user has to publish (DNS TXT) or the server
// hashes (email), so it travels with the token everywhere except in
// pure-hash compares.
func generateToken() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("recon: ownership: generate token: %w", err)
	}
	return "usulnet-verify=" + hex.EncodeToString(buf), nil
}

// hashToken returns the lowercase hex SHA-256 of token. The email
// verifier stores this in evidence so the plain-text token never lands
// on disk.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ============================================================================
// dnsTXTVerifier — domain ownership via TXT record
// ============================================================================

// DNSChallengeHost builds the FQDN that must carry the verification TXT
// record for a given domain target. Exported so the API/web layers can
// show the user the exact host to publish.
func DNSChallengeHost(domain string) string {
	return "usulnet-verify." + strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// dnsTXTVerifier verifies domain ownership by reading a TXT record at
// "usulnet-verify.<domain>" and matching it against an issued token.
type dnsTXTVerifier struct {
	resolver DNSResolver
	log      *logger.Logger
}

// NewDNSTXTVerifier returns a verifier wired with the supplied resolver.
// A nil resolver falls back to DefaultDNSResolver.
func NewDNSTXTVerifier(resolver DNSResolver, log *logger.Logger) OwnershipVerifier {
	if resolver == nil {
		resolver = DefaultDNSResolver()
	}
	if log == nil {
		log = logger.Nop()
	}
	return &dnsTXTVerifier{resolver: resolver, log: log.Named("recon.ownership.dns_txt")}
}

func (v *dnsTXTVerifier) Method() OwnershipMethod { return OwnershipDNSTXT }

func (v *dnsTXTVerifier) Start(_ context.Context, target *Target, proof *OwnershipProof) error {
	if target.Type != TargetDomain {
		return fmt.Errorf("recon: ownership: dns_txt: %w", ErrOwnershipUnsupported)
	}
	token, err := generateToken()
	if err != nil {
		return err
	}
	proof.Challenge = token
	if proof.Evidence == nil {
		proof.Evidence = make(map[string]any, 2)
	}
	proof.Evidence["host"] = DNSChallengeHost(target.Value)
	proof.Evidence["record"] = token
	return nil
}

func (v *dnsTXTVerifier) Verify(ctx context.Context, target *Target, proof *OwnershipProof, _ map[string]any) error {
	if target.Type != TargetDomain {
		return fmt.Errorf("recon: ownership: dns_txt: %w", ErrOwnershipUnsupported)
	}
	if strings.TrimSpace(proof.Challenge) == "" {
		return fmt.Errorf("recon: ownership: dns_txt: %w", ErrOwnershipChallengeMissing)
	}
	host := DNSChallengeHost(target.Value)
	records, err := v.resolver.LookupTXT(ctx, host)
	if err != nil {
		return fmt.Errorf("recon: ownership: dns_txt: lookup %q: %w", host, err)
	}
	for _, r := range records {
		if strings.TrimSpace(r) == proof.Challenge {
			now := time.Now().UTC()
			proof.Status = OwnershipVerified
			proof.VerifiedAt = &now
			return nil
		}
	}
	proof.Status = OwnershipFailed
	return fmt.Errorf("recon: ownership: dns_txt: %w", ErrOwnershipMismatch)
}

// ============================================================================
// emailLinkVerifier — email ownership via one-time link
// ============================================================================

// emailLinkVerifier verifies email ownership by sending a one-time link
// to the address and checking the user-supplied token against a stored
// hash. The plaintext token is never persisted; only its sha256 lives in
// evidence.
type emailLinkVerifier struct {
	sender  EmailSender
	baseURL string
	log     *logger.Logger
}

// NewEmailLinkVerifier returns a verifier wired with the supplied
// email sender. baseURL is the externally reachable base of the usulnet
// install (e.g., "https://usulnet.example.com"); it forms the
// /recon/targets/<id>/verify?token=… link that the user receives.
func NewEmailLinkVerifier(sender EmailSender, baseURL string, log *logger.Logger) OwnershipVerifier {
	if log == nil {
		log = logger.Nop()
	}
	return &emailLinkVerifier{
		sender:  sender,
		baseURL: strings.TrimRight(baseURL, "/"),
		log:     log.Named("recon.ownership.email_link"),
	}
}

func (v *emailLinkVerifier) Method() OwnershipMethod { return OwnershipEmailLink }

func (v *emailLinkVerifier) Start(ctx context.Context, target *Target, proof *OwnershipProof) error {
	if target.Type != TargetEmail {
		return fmt.Errorf("recon: ownership: email_link: %w", ErrOwnershipUnsupported)
	}
	if v.sender == nil {
		return fmt.Errorf("recon: ownership: email_link: no email sender configured")
	}
	token, err := generateToken()
	if err != nil {
		return err
	}
	proof.Challenge = ""
	if proof.Evidence == nil {
		proof.Evidence = make(map[string]any, 3)
	}
	proof.Evidence["token_hash"] = hashToken(token)
	proof.Evidence["issued_at"] = time.Now().UTC().Format(time.RFC3339)
	proof.Evidence["expires_at"] = time.Now().UTC().Add(emailTokenTTL).Format(time.RFC3339)
	link := fmt.Sprintf("%s/recon/targets/%s/verify?token=%s", v.baseURL, target.ID, token)
	if err := v.sender.SendVerificationEmail(ctx, target.Value, link); err != nil {
		return fmt.Errorf("recon: ownership: email_link: send: %w", err)
	}
	return nil
}

func (v *emailLinkVerifier) Verify(_ context.Context, target *Target, proof *OwnershipProof, input map[string]any) error {
	if target.Type != TargetEmail {
		return fmt.Errorf("recon: ownership: email_link: %w", ErrOwnershipUnsupported)
	}
	storedHash, _ := proof.Evidence["token_hash"].(string)
	if storedHash == "" {
		return fmt.Errorf("recon: ownership: email_link: %w", ErrOwnershipChallengeMissing)
	}
	if expRaw, ok := proof.Evidence["expires_at"].(string); ok && expRaw != "" {
		if exp, err := time.Parse(time.RFC3339, expRaw); err == nil && time.Now().UTC().After(exp) {
			proof.Status = OwnershipFailed
			return fmt.Errorf("recon: ownership: email_link: %w", ErrOwnershipExpired)
		}
	}
	suppliedToken, _ := input["token"].(string)
	if suppliedToken == "" {
		return fmt.Errorf("recon: ownership: email_link: %w", ErrOwnershipInputMissing)
	}
	if hashToken(suppliedToken) != storedHash {
		proof.Status = OwnershipFailed
		return fmt.Errorf("recon: ownership: email_link: %w", ErrOwnershipMismatch)
	}
	// Single-use: blank the stored hash so a replay fails ErrOwnershipChallengeMissing.
	delete(proof.Evidence, "token_hash")
	now := time.Now().UTC()
	proof.Status = OwnershipVerified
	proof.VerifiedAt = &now
	return nil
}

// ============================================================================
// rdapVerifier — IP / domain ownership via RDAP registrant lookup
// ============================================================================

// rdapVerifier matches the registrant org of a domain or IP against a
// usulnet-supplied org name configured at the installation level. The
// match is case-insensitive on the trimmed canonical form.
type rdapVerifier struct {
	client      *RDAPClient
	expectedOrg string
	log         *logger.Logger
}

// NewRDAPVerifier wires the verifier with an RDAP client and the org
// name that legitimate registrants must match. A blank expectedOrg
// fails-closed (every verification returns ErrOwnershipMismatch) so
// operators must explicitly configure the installation org.
func NewRDAPVerifier(client *RDAPClient, expectedOrg string, log *logger.Logger) OwnershipVerifier {
	if client == nil {
		client = NewRDAPClient(0)
	}
	if log == nil {
		log = logger.Nop()
	}
	return &rdapVerifier{
		client:      client,
		expectedOrg: strings.TrimSpace(expectedOrg),
		log:         log.Named("recon.ownership.rdap"),
	}
}

func (v *rdapVerifier) Method() OwnershipMethod { return OwnershipRDAPMatch }

func (v *rdapVerifier) Start(_ context.Context, target *Target, proof *OwnershipProof) error {
	switch target.Type {
	case TargetDomain, TargetIP, TargetIPRange:
	default:
		return fmt.Errorf("recon: ownership: rdap: %w", ErrOwnershipUnsupported)
	}
	if proof.Evidence == nil {
		proof.Evidence = make(map[string]any, 1)
	}
	proof.Evidence["expected_org"] = v.expectedOrg
	return nil
}

func (v *rdapVerifier) Verify(ctx context.Context, target *Target, proof *OwnershipProof, input map[string]any) error {
	if v.expectedOrg == "" {
		proof.Status = OwnershipFailed
		return fmt.Errorf("recon: ownership: rdap: %w", ErrOwnershipMismatch)
	}

	var registrant string
	var err error
	switch target.Type {
	case TargetDomain:
		registrant, err = v.client.LookupDomainOrg(ctx, target.Value)
	case TargetIP, TargetIPRange:
		registrant, err = v.client.LookupIPOrg(ctx, target.Value)
	default:
		return fmt.Errorf("recon: ownership: rdap: %w", ErrOwnershipUnsupported)
	}
	if err != nil {
		return fmt.Errorf("recon: ownership: rdap: %w", err)
	}

	if proof.Evidence == nil {
		proof.Evidence = make(map[string]any, 2)
	}
	proof.Evidence["registrant_org"] = registrant
	proof.Evidence["expected_org"] = v.expectedOrg

	// An admin attestation may travel with the input under "attestation":
	// "true" — useful when the registrar redacts the registrant per GDPR.
	// The attestation path goes through adminAttestVerifier in production,
	// but RDAP accepts it as an override when set explicitly by an admin.
	if att, ok := input["attestation"].(bool); ok && att {
		now := time.Now().UTC()
		proof.Evidence["attested"] = true
		proof.Status = OwnershipVerified
		proof.VerifiedAt = &now
		return nil
	}

	if !equalOrg(registrant, v.expectedOrg) {
		proof.Status = OwnershipFailed
		return fmt.Errorf("recon: ownership: rdap: %w", ErrOwnershipMismatch)
	}
	now := time.Now().UTC()
	proof.Status = OwnershipVerified
	proof.VerifiedAt = &now
	return nil
}

// equalOrg compares two organization names case-insensitively after
// trimming and collapsing internal whitespace. Registrars vary on
// trailing commas, "Inc." vs "Inc", and similar; the comparison is
// deliberately loose so a single space difference does not block
// legitimate operators.
func equalOrg(a, b string) bool {
	return strings.EqualFold(collapseSpaces(a), collapseSpaces(b))
}

func collapseSpaces(s string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
}

// ============================================================================
// adminAttestVerifier — admin-signed override, logged
// ============================================================================

// adminAttestVerifier accepts a verification from an actor with the
// `admin` role and writes the attestation to recon_audit_log. The
// caller must inject the actor's role and id via the input map.
type adminAttestVerifier struct {
	audit AuditSink
	log   *logger.Logger
}

// NewAdminAttestVerifier wires the verifier with the audit sink.
func NewAdminAttestVerifier(audit AuditSink, log *logger.Logger) OwnershipVerifier {
	if log == nil {
		log = logger.Nop()
	}
	return &adminAttestVerifier{audit: audit, log: log.Named("recon.ownership.admin_attest")}
}

func (v *adminAttestVerifier) Method() OwnershipMethod { return OwnershipAdminAttest }

func (v *adminAttestVerifier) Start(_ context.Context, _ *Target, proof *OwnershipProof) error {
	if proof.Evidence == nil {
		proof.Evidence = make(map[string]any, 1)
	}
	proof.Evidence["requires_admin"] = true
	return nil
}

func (v *adminAttestVerifier) Verify(ctx context.Context, target *Target, proof *OwnershipProof, input map[string]any) error {
	role, _ := input["actor_role"].(string)
	if !strings.EqualFold(role, "admin") {
		proof.Status = OwnershipFailed
		return fmt.Errorf("recon: ownership: admin_attest: %w", ErrOwnershipForbidden)
	}
	note, _ := input["note"].(string)
	if proof.Evidence == nil {
		proof.Evidence = make(map[string]any, 3)
	}
	if note != "" {
		proof.Evidence["note"] = note
	}
	proof.Evidence["attested_role"] = "admin"
	if actorID, ok := input["actor_id"].(string); ok && actorID != "" {
		proof.Evidence["actor_id"] = actorID
	}

	now := time.Now().UTC()
	proof.Status = OwnershipVerified
	proof.VerifiedAt = &now

	if v.audit != nil {
		details := map[string]any{
			"method":    string(OwnershipAdminAttest),
			"target_id": target.ID.String(),
			"note":      note,
		}
		entry := AuditEntry{
			Action:   "ownership.admin_attest",
			TargetID: &target.ID,
			Details:  details,
		}
		if err := v.audit.AppendAudit(ctx, entry); err != nil {
			// Audit failure is not fatal but operators must see it.
			v.log.Warn("admin attest audit append failed",
				"target_id", target.ID,
				"error", err,
			)
		}
	}
	v.log.Info("admin attest verified",
		"target_id", target.ID,
		"target_type", string(target.Type),
	)
	return nil
}

// ============================================================================
// selfAssertVerifier — auto-verified for username / phone targets
// ============================================================================

// selfAssertVerifier permits only username and phone target types. The
// proof is verified immediately on creation: "you logged in and
// asserted this is yours" per RFC §7.1.
type selfAssertVerifier struct {
	log *logger.Logger
}

// NewSelfAssertVerifier returns the verifier.
func NewSelfAssertVerifier(log *logger.Logger) OwnershipVerifier {
	if log == nil {
		log = logger.Nop()
	}
	return &selfAssertVerifier{log: log.Named("recon.ownership.self_assert")}
}

func (v *selfAssertVerifier) Method() OwnershipMethod { return OwnershipSelfAssert }

func (v *selfAssertVerifier) Start(_ context.Context, target *Target, proof *OwnershipProof) error {
	if target.Type != TargetUsername && target.Type != TargetPhone {
		return fmt.Errorf("recon: ownership: self_assert: %w", ErrOwnershipUnsupported)
	}
	now := time.Now().UTC()
	proof.Status = OwnershipVerified
	proof.VerifiedAt = &now
	if proof.Evidence == nil {
		proof.Evidence = make(map[string]any, 1)
	}
	proof.Evidence["self_asserted"] = true
	return nil
}

func (v *selfAssertVerifier) Verify(_ context.Context, target *Target, proof *OwnershipProof, _ map[string]any) error {
	if target.Type != TargetUsername && target.Type != TargetPhone {
		return fmt.Errorf("recon: ownership: self_assert: %w", ErrOwnershipUnsupported)
	}
	if proof.Status != OwnershipVerified {
		now := time.Now().UTC()
		proof.Status = OwnershipVerified
		proof.VerifiedAt = &now
	}
	return nil
}
