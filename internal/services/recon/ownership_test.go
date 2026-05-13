// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package recon

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ----- DNS resolver stub --------------------------------------------------

type stubResolver struct {
	records map[string][]string
	err     error
}

func (s *stubResolver) LookupTXT(_ context.Context, host string) ([]string, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.records[host], nil
}

// ----- Email sender stub --------------------------------------------------

type stubEmailSender struct {
	mu   sync.Mutex
	sent int
	last string
	addr string
	fail error
}

func (s *stubEmailSender) SendVerificationEmail(_ context.Context, to, link string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	s.sent++
	s.last = link
	s.addr = to
	return nil
}

// ----- Audit sink stub ----------------------------------------------------

type stubAudit struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (s *stubAudit) AppendAudit(_ context.Context, e AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, e)
	return nil
}

// ----- Helpers ------------------------------------------------------------

func newTestTarget(t *testing.T, typ TargetType, value string) *Target {
	t.Helper()
	return &Target{
		ID:    uuid.New(),
		Type:  typ,
		Value: value,
	}
}

func newPendingProof(method OwnershipMethod, targetID uuid.UUID) *OwnershipProof {
	return &OwnershipProof{
		ID:       uuid.New(),
		TargetID: targetID,
		Method:   method,
		Status:   OwnershipPending,
	}
}

// =========================================================================
// dnsTXTVerifier
// =========================================================================

func TestDNSTXTVerifier_StartAndVerify_Match(t *testing.T) {
	target := newTestTarget(t, TargetDomain, "Example.COM")
	proof := newPendingProof(OwnershipDNSTXT, target.ID)

	resolver := &stubResolver{records: map[string][]string{}}
	v := NewDNSTXTVerifier(resolver, nil)

	if err := v.Start(context.Background(), target, proof); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !strings.HasPrefix(proof.Challenge, "usulnet-verify=") {
		t.Fatalf("challenge format: %q", proof.Challenge)
	}
	host, _ := proof.Evidence["host"].(string)
	if host != "usulnet-verify.example.com" {
		t.Fatalf("evidence host: got %q", host)
	}

	// User publishes the TXT record.
	resolver.records[host] = []string{"some-other-thing", proof.Challenge}

	if err := v.Verify(context.Background(), target, proof, nil); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if proof.Status != OwnershipVerified {
		t.Fatalf("status: %v", proof.Status)
	}
	if proof.VerifiedAt == nil {
		t.Fatalf("VerifiedAt not set")
	}
}

func TestDNSTXTVerifier_Mismatch(t *testing.T) {
	target := newTestTarget(t, TargetDomain, "example.com")
	proof := newPendingProof(OwnershipDNSTXT, target.ID)

	resolver := &stubResolver{records: map[string][]string{
		"usulnet-verify.example.com": {"usulnet-verify=wrong"},
	}}
	v := NewDNSTXTVerifier(resolver, nil)
	if err := v.Start(context.Background(), target, proof); err != nil {
		t.Fatalf("Start: %v", err)
	}
	err := v.Verify(context.Background(), target, proof, nil)
	if !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("expected mismatch, got: %v", err)
	}
	if proof.Status != OwnershipFailed {
		t.Fatalf("status: %v", proof.Status)
	}
}

func TestDNSTXTVerifier_UnsupportedType(t *testing.T) {
	target := newTestTarget(t, TargetEmail, "foo@example.com")
	proof := newPendingProof(OwnershipDNSTXT, target.ID)
	v := NewDNSTXTVerifier(&stubResolver{}, nil)
	if err := v.Start(context.Background(), target, proof); !errors.Is(err, ErrOwnershipUnsupported) {
		t.Fatalf("Start: %v", err)
	}
	if err := v.Verify(context.Background(), target, proof, nil); !errors.Is(err, ErrOwnershipUnsupported) {
		t.Fatalf("Verify: %v", err)
	}
}

func TestDNSTXTVerifier_ChallengeMissing(t *testing.T) {
	target := newTestTarget(t, TargetDomain, "example.com")
	proof := newPendingProof(OwnershipDNSTXT, target.ID)
	v := NewDNSTXTVerifier(&stubResolver{}, nil)
	err := v.Verify(context.Background(), target, proof, nil)
	if !errors.Is(err, ErrOwnershipChallengeMissing) {
		t.Fatalf("expected challenge missing, got: %v", err)
	}
}

// =========================================================================
// emailLinkVerifier
// =========================================================================

func TestEmailLinkVerifier_HappyPath(t *testing.T) {
	target := newTestTarget(t, TargetEmail, "alice@example.com")
	proof := newPendingProof(OwnershipEmailLink, target.ID)
	sender := &stubEmailSender{}

	v := NewEmailLinkVerifier(sender, "https://u.example/", nil)
	if err := v.Start(context.Background(), target, proof); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if sender.sent != 1 {
		t.Fatalf("email send count: %d", sender.sent)
	}
	if sender.addr != target.Value {
		t.Fatalf("recipient: %q", sender.addr)
	}
	if !strings.Contains(sender.last, "token=") {
		t.Fatalf("link: %q", sender.last)
	}
	hashStored, _ := proof.Evidence["token_hash"].(string)
	if hashStored == "" {
		t.Fatalf("token_hash not stored")
	}

	// Pull the raw token from the URL we captured (this is the user
	// clicking the email link).
	token := sender.last[strings.Index(sender.last, "token=")+len("token="):]
	if err := v.Verify(context.Background(), target, proof, map[string]any{"token": token}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if proof.Status != OwnershipVerified {
		t.Fatalf("status: %v", proof.Status)
	}
	// Single-use: replaying must now fail with challenge-missing.
	err := v.Verify(context.Background(), target, proof, map[string]any{"token": token})
	if !errors.Is(err, ErrOwnershipChallengeMissing) {
		t.Fatalf("replay should fail with challenge missing, got: %v", err)
	}
}

func TestEmailLinkVerifier_WrongToken(t *testing.T) {
	target := newTestTarget(t, TargetEmail, "alice@example.com")
	proof := newPendingProof(OwnershipEmailLink, target.ID)
	sender := &stubEmailSender{}
	v := NewEmailLinkVerifier(sender, "https://u.example", nil)
	if err := v.Start(context.Background(), target, proof); err != nil {
		t.Fatalf("Start: %v", err)
	}
	err := v.Verify(context.Background(), target, proof, map[string]any{"token": "bogus"})
	if !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("expected mismatch, got: %v", err)
	}
	if proof.Status != OwnershipFailed {
		t.Fatalf("status: %v", proof.Status)
	}
}

func TestEmailLinkVerifier_Expired(t *testing.T) {
	target := newTestTarget(t, TargetEmail, "alice@example.com")
	proof := newPendingProof(OwnershipEmailLink, target.ID)
	sender := &stubEmailSender{}
	v := NewEmailLinkVerifier(sender, "https://u.example", nil)
	if err := v.Start(context.Background(), target, proof); err != nil {
		t.Fatalf("Start: %v", err)
	}
	proof.Evidence["expires_at"] = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)

	token := sender.last[strings.Index(sender.last, "token=")+len("token="):]
	err := v.Verify(context.Background(), target, proof, map[string]any{"token": token})
	if !errors.Is(err, ErrOwnershipExpired) {
		t.Fatalf("expected expired, got: %v", err)
	}
}

func TestEmailLinkVerifier_UnsupportedType(t *testing.T) {
	target := newTestTarget(t, TargetDomain, "example.com")
	proof := newPendingProof(OwnershipEmailLink, target.ID)
	v := NewEmailLinkVerifier(&stubEmailSender{}, "https://u", nil)
	if err := v.Start(context.Background(), target, proof); !errors.Is(err, ErrOwnershipUnsupported) {
		t.Fatalf("Start: %v", err)
	}
}

// =========================================================================
// rdapVerifier — exercises with a stub *RDAPClient via httptest in rdap_test
// =========================================================================

func TestRDAPVerifier_Match(t *testing.T) {
	target := newTestTarget(t, TargetDomain, "example.com")
	proof := newPendingProof(OwnershipRDAPMatch, target.ID)
	srv := newRDAPTestServer(t, map[string]string{
		"/domain/example.com": rdapDomainBody("Acme Corp"),
	})
	defer srv.Close()
	client := NewRDAPClientWithBase(srv.URL, 0)

	v := NewRDAPVerifier(client, "Acme Corp", nil)
	if err := v.Start(context.Background(), target, proof); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := v.Verify(context.Background(), target, proof, nil); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if proof.Status != OwnershipVerified {
		t.Fatalf("status: %v", proof.Status)
	}
	if got, _ := proof.Evidence["registrant_org"].(string); got != "Acme Corp" {
		t.Fatalf("registrant_org: %q", got)
	}
}

func TestRDAPVerifier_Mismatch(t *testing.T) {
	target := newTestTarget(t, TargetDomain, "example.com")
	proof := newPendingProof(OwnershipRDAPMatch, target.ID)
	srv := newRDAPTestServer(t, map[string]string{
		"/domain/example.com": rdapDomainBody("Someone Else LLC"),
	})
	defer srv.Close()
	client := NewRDAPClientWithBase(srv.URL, 0)

	v := NewRDAPVerifier(client, "Acme Corp", nil)
	err := v.Verify(context.Background(), target, proof, nil)
	if !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("expected mismatch, got: %v", err)
	}
	if proof.Status != OwnershipFailed {
		t.Fatalf("status: %v", proof.Status)
	}
}

func TestRDAPVerifier_AttestationOverride(t *testing.T) {
	target := newTestTarget(t, TargetDomain, "example.com")
	proof := newPendingProof(OwnershipRDAPMatch, target.ID)
	srv := newRDAPTestServer(t, map[string]string{
		"/domain/example.com": rdapDomainBody("REDACTED FOR PRIVACY"),
	})
	defer srv.Close()
	client := NewRDAPClientWithBase(srv.URL, 0)

	v := NewRDAPVerifier(client, "Acme Corp", nil)
	if err := v.Verify(context.Background(), target, proof, map[string]any{"attestation": true}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if proof.Status != OwnershipVerified {
		t.Fatalf("status: %v", proof.Status)
	}
	if v, _ := proof.Evidence["attested"].(bool); !v {
		t.Fatalf("attested flag not set")
	}
}

func TestRDAPVerifier_BlankExpectedOrg(t *testing.T) {
	target := newTestTarget(t, TargetDomain, "example.com")
	proof := newPendingProof(OwnershipRDAPMatch, target.ID)
	v := NewRDAPVerifier(nil, "", nil)
	err := v.Verify(context.Background(), target, proof, nil)
	if !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("expected mismatch with blank org, got: %v", err)
	}
}

func TestRDAPVerifier_UnsupportedType(t *testing.T) {
	target := newTestTarget(t, TargetEmail, "foo@example.com")
	proof := newPendingProof(OwnershipRDAPMatch, target.ID)
	v := NewRDAPVerifier(nil, "Acme Corp", nil)
	if err := v.Start(context.Background(), target, proof); !errors.Is(err, ErrOwnershipUnsupported) {
		t.Fatalf("Start: %v", err)
	}
}

// =========================================================================
// adminAttestVerifier
// =========================================================================

func TestAdminAttestVerifier_AdminRoleVerifies(t *testing.T) {
	target := newTestTarget(t, TargetIPRange, "192.0.2.0/24")
	proof := newPendingProof(OwnershipAdminAttest, target.ID)
	audit := &stubAudit{}

	v := NewAdminAttestVerifier(audit, nil)
	if err := v.Start(context.Background(), target, proof); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := v.Verify(context.Background(), target, proof, map[string]any{
		"actor_role": "admin",
		"actor_id":   "user-1",
		"note":       "owned by operations team per ticket OPS-42",
	}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if proof.Status != OwnershipVerified {
		t.Fatalf("status: %v", proof.Status)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("audit entries: %d", len(audit.entries))
	}
	if audit.entries[0].Action != "ownership.admin_attest" {
		t.Fatalf("audit action: %q", audit.entries[0].Action)
	}
	if got, _ := proof.Evidence["actor_id"].(string); got != "user-1" {
		t.Fatalf("evidence actor_id: %q", got)
	}
}

func TestAdminAttestVerifier_NonAdminForbidden(t *testing.T) {
	target := newTestTarget(t, TargetIPRange, "192.0.2.0/24")
	proof := newPendingProof(OwnershipAdminAttest, target.ID)
	audit := &stubAudit{}
	v := NewAdminAttestVerifier(audit, nil)
	err := v.Verify(context.Background(), target, proof, map[string]any{
		"actor_role": "operator",
	})
	if !errors.Is(err, ErrOwnershipForbidden) {
		t.Fatalf("expected forbidden, got: %v", err)
	}
	if proof.Status != OwnershipFailed {
		t.Fatalf("status: %v", proof.Status)
	}
	if len(audit.entries) != 0 {
		t.Fatalf("audit should not log forbidden attempt: %d", len(audit.entries))
	}
}

// =========================================================================
// selfAssertVerifier
// =========================================================================

func TestSelfAssertVerifier_UsernameAutoVerifies(t *testing.T) {
	target := newTestTarget(t, TargetUsername, "alice")
	proof := newPendingProof(OwnershipSelfAssert, target.ID)
	v := NewSelfAssertVerifier(nil)
	if err := v.Start(context.Background(), target, proof); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if proof.Status != OwnershipVerified {
		t.Fatalf("expected verified on Start, got %v", proof.Status)
	}
	if proof.VerifiedAt == nil {
		t.Fatalf("VerifiedAt not set")
	}
	if v, _ := proof.Evidence["self_asserted"].(bool); !v {
		t.Fatalf("evidence flag not set")
	}
}

func TestSelfAssertVerifier_RejectsDomain(t *testing.T) {
	target := newTestTarget(t, TargetDomain, "example.com")
	proof := newPendingProof(OwnershipSelfAssert, target.ID)
	v := NewSelfAssertVerifier(nil)
	err := v.Start(context.Background(), target, proof)
	if !errors.Is(err, ErrOwnershipUnsupported) {
		t.Fatalf("expected unsupported, got: %v", err)
	}
	err = v.Verify(context.Background(), target, proof, nil)
	if !errors.Is(err, ErrOwnershipUnsupported) {
		t.Fatalf("Verify: %v", err)
	}
}
