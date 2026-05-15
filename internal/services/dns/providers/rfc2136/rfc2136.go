// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package rfc2136 implements the generic RFC 2136 dynamic DNS update
// provider. It speaks to any nameserver that accepts authenticated
// dynamic updates (BIND, NSD with dnsupdate, PowerDNS with the
// matching plugin, Knot DNS, ...). TSIG (HMAC) keys authenticate the
// update messages.
package rfc2136

import (
	"context"
	"encoding/base64"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"net"
	"strings"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/dns"
)

// Capabilities returns the plugin's static metadata.
func Capabilities() dns.Capabilities {
	return dns.Capabilities{
		DisplayName: "Generic RFC 2136 (dynamic DNS update)",
		Description: "Sends RFC 2136 UPDATE messages to a self-managed nameserver authenticated with a TSIG key.",
		Records: []dns.SupportedRecord{
			{Type: models.DNSRecordTypeA, Read: false, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeAAAA, Read: false, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeCNAME, Read: false, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeMX, Read: false, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeTXT, Read: false, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeNS, Read: false, Write: true, UpdateTTL: true},
		},
		CredentialFields: []dns.CredentialField{
			{Key: "tsig_key_name", Label: "TSIG key name", Required: true, Secret: false,
				Description: "Name of the TSIG key as configured on the nameserver."},
			{Key: "tsig_secret", Label: "TSIG secret (base64)", Required: true, Secret: true,
				Description: "Base64-encoded TSIG key material."},
			{Key: "tsig_algorithm", Label: "TSIG algorithm", Required: false, Secret: false,
				Description: "One of hmac-sha256, hmac-sha512, hmac-sha1, hmac-md5. Default hmac-sha256."},
		},
		ConfigFields: []dns.ConfigField{
			{Key: "nameserver", Label: "Nameserver address (host:port)", Type: "string", Default: "127.0.0.1:53",
				Description: "Address of the authoritative nameserver that accepts UPDATE messages."},
			{Key: "zone", Label: "Zone (FQDN, trailing dot)", Type: "string",
				Description: "Default zone for record updates. May be overridden per record by the matching suffix."},
			{Key: "timeout_seconds", Label: "Network timeout (s)", Type: "int", Default: 10},
		},
	}
}

// Credentials is the JSON shape stored encrypted at rest.
type Credentials struct {
	TSIGKeyName   string `json:"tsig_key_name"`
	TSIGSecret    string `json:"tsig_secret"`
	TSIGAlgorithm string `json:"tsig_algorithm,omitempty"`
}

// Provider implements dns.Provider via miekg/dns UPDATE messages.
type Provider struct {
	keyName    string
	secret     string
	algorithm  string
	nameserver string
	zone       string
	timeout    time.Duration
}

// Factory builds a Provider.
func Factory(_ context.Context, credentialsBlob []byte, config map[string]any) (dns.Provider, error) {
	var creds Credentials
	if err := json.Unmarshal(credentialsBlob, &creds); err != nil {
		return nil, fmt.Errorf("rfc2136: invalid credentials JSON: %w", err)
	}
	if strings.TrimSpace(creds.TSIGKeyName) == "" || strings.TrimSpace(creds.TSIGSecret) == "" {
		return nil, fmt.Errorf("rfc2136: %w: tsig_key_name and tsig_secret required", dns.ErrInvalidCredentials)
	}
	if _, err := base64.StdEncoding.DecodeString(creds.TSIGSecret); err != nil {
		return nil, fmt.Errorf("rfc2136: %w: tsig_secret must be base64", dns.ErrInvalidCredentials)
	}
	algo := strings.ToLower(strings.TrimSpace(creds.TSIGAlgorithm))
	if algo == "" {
		algo = "hmac-sha256"
	}
	if _, ok := tsigAlgorithm(algo); !ok {
		return nil, fmt.Errorf("rfc2136: unsupported tsig algorithm %q", algo)
	}

	ns, _ := config["nameserver"].(string)
	if ns == "" {
		ns = "127.0.0.1:53"
	}
	if !strings.Contains(ns, ":") {
		ns += ":53"
	}
	zone, _ := config["zone"].(string)
	if zone != "" && !strings.HasSuffix(zone, ".") {
		zone += "."
	}
	to := 10 * time.Second
	if v, ok := config["timeout_seconds"].(float64); ok && v > 0 {
		to = time.Duration(v) * time.Second
	} else if vi, ok := config["timeout_seconds"].(int); ok && vi > 0 {
		to = time.Duration(vi) * time.Second
	}

	return &Provider{
		keyName:    mdns.Fqdn(creds.TSIGKeyName),
		secret:     creds.TSIGSecret,
		algorithm:  algo,
		nameserver: ns,
		zone:       zone,
		timeout:    to,
	}, nil
}

// Register adds the plugin to the registry.
func Register(reg *dns.Registry) error {
	return reg.Register(models.DNSProviderKindRFC2136, Factory, Capabilities())
}

// Kind returns the provider identifier.
func (p *Provider) Kind() models.DNSProviderKind { return models.DNSProviderKindRFC2136 }

// Close is a no-op.
func (p *Provider) Close() error { return nil }

// VerifyCredentials sends an empty UPDATE message and inspects the
// rcode. Servers with a properly configured TSIG key reply NOERROR
// (or NOTAUTH for a wrong key); we treat NOTAUTH and BADKEY as
// invalid credentials.
func (p *Provider) VerifyCredentials(ctx context.Context) error {
	zone := p.zone
	if zone == "" {
		// Use root as a probe zone if no default is set; servers
		// usually reject NOTZONE which still proves authentication.
		zone = "."
	}
	msg := new(mdns.Msg)
	msg.SetUpdate(zone)
	if err := p.sendWithDeadline(ctx, msg); err != nil {
		return err
	}
	return nil
}

// CreateRecord adds a record. RFC 2136's add primitive is "add this
// RR to the existing rrset" — we use that so multiple TXT entries can
// coexist (matters for ACME chained challenges).
func (p *Provider) CreateRecord(ctx context.Context, rec dns.ProviderRecord) (dns.ProviderRecord, error) {
	zone := p.zoneFor(rec.Name)
	if zone == "" {
		return dns.ProviderRecord{}, dns.ErrZoneNotFound
	}
	rr, err := buildRR(rec)
	if err != nil {
		return dns.ProviderRecord{}, err
	}
	msg := new(mdns.Msg)
	msg.SetUpdate(zone)
	msg.Insert([]mdns.RR{rr})
	if err := p.sendWithDeadline(ctx, msg); err != nil {
		return dns.ProviderRecord{}, err
	}
	// RFC 2136 has no record id concept; synthesize one from the
	// content so DeleteRecord can rebuild the precise rrset.
	return dns.ProviderRecord{
		ID:      naturalRecordID(rec),
		Name:    rec.Name,
		Type:    rec.Type,
		Content: rec.Content,
		TTL:     rec.TTL,
	}, nil
}

// DeleteRecord removes the precise rrset entry that matches the
// supplied record. RFC 2136's "delete one RR from rrset" primitive
// matches by name+type+class+rdata, not by an opaque id.
func (p *Provider) DeleteRecord(ctx context.Context, _ string, rec dns.ProviderRecord) error {
	zone := p.zoneFor(rec.Name)
	if zone == "" {
		return dns.ErrZoneNotFound
	}
	rr, err := buildRR(rec)
	if err != nil {
		return err
	}
	msg := new(mdns.Msg)
	msg.SetUpdate(zone)
	msg.Remove([]mdns.RR{rr})
	if err := p.sendWithDeadline(ctx, msg); err != nil {
		// NXRRSET on delete means the record was already gone; fine.
		var rcodeErr *rcodeError
		if stderrors.As(err, &rcodeErr) && rcodeErr.code == mdns.RcodeNXRrset {
			return dns.ErrRecordNotFound
		}
		return err
	}
	return nil
}

// ListRecords is not supported via UPDATE; the spec only covers
// mutations. Operators can read via DNS query if they need a list.
func (p *Provider) ListRecords(_ context.Context, _ string) ([]dns.ProviderRecord, error) {
	return nil, fmt.Errorf("rfc2136: ListRecords is not supported via dynamic update")
}

// ============================================================================
// Internal helpers
// ============================================================================

// rcodeError wraps a non-NOERROR DNS response so callers can switch
// on the wire-level rcode.
type rcodeError struct {
	code int
}

func (e *rcodeError) Error() string {
	return fmt.Sprintf("rfc2136: server returned rcode %s", mdns.RcodeToString[e.code])
}

func (p *Provider) sendWithDeadline(ctx context.Context, msg *mdns.Msg) error {
	if alg, ok := tsigAlgorithm(p.algorithm); ok {
		msg.SetTsig(p.keyName, alg, 300, time.Now().Unix())
	}
	c := &mdns.Client{
		Net:     "tcp",
		Timeout: p.timeout,
		TsigSecret: map[string]string{
			p.keyName: p.secret,
		},
	}
	deadline, ok := ctx.Deadline()
	if ok {
		c.Timeout = time.Until(deadline)
	}
	resp, _, err := c.Exchange(msg, p.nameserver)
	if err != nil {
		if stderrors.Is(err, mdns.ErrAuth) {
			return fmt.Errorf("%w: tsig verification failed", dns.ErrInvalidCredentials)
		}
		// Translate connection refused / TLS issues to credential
		// errors when authentication failed at the wire level.
		var netErr *net.OpError
		if stderrors.As(err, &netErr) {
			return fmt.Errorf("rfc2136: %s: %w", p.nameserver, err)
		}
		return fmt.Errorf("rfc2136: exchange: %w", err)
	}
	switch resp.Rcode {
	case mdns.RcodeSuccess:
		return nil
	case mdns.RcodeNotAuth, mdns.RcodeBadKey, mdns.RcodeBadTime:
		return fmt.Errorf("%w: %s", dns.ErrInvalidCredentials, mdns.RcodeToString[resp.Rcode])
	case mdns.RcodeNotZone:
		return fmt.Errorf("%w: %s", dns.ErrZoneNotFound, mdns.RcodeToString[resp.Rcode])
	default:
		return &rcodeError{code: resp.Rcode}
	}
}

func (p *Provider) zoneFor(name string) string {
	if p.zone != "" {
		return p.zone
	}
	// Without a configured zone, fall back to the second-level domain
	// of the record. This is a heuristic — operators with deeply
	// nested authoritative zones should set the zone in config.
	parts := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts[len(parts)-2:], ".") + "."
}

func tsigAlgorithm(algo string) (string, bool) {
	switch strings.ToLower(algo) {
	case "hmac-md5":
		return mdns.HmacMD5, true
	case "hmac-sha1":
		return mdns.HmacSHA1, true
	case "hmac-sha256":
		return mdns.HmacSHA256, true
	case "hmac-sha512":
		return mdns.HmacSHA512, true
	}
	return "", false
}

func buildRR(rec dns.ProviderRecord) (mdns.RR, error) {
	rrType, ok := mdns.StringToType[strings.ToUpper(string(rec.Type))]
	if !ok {
		return nil, fmt.Errorf("rfc2136: unsupported record type %q", rec.Type)
	}
	zoneStr := mdns.Fqdn(rec.Name)
	ttl := rec.TTL
	if ttl <= 0 {
		ttl = 300
	}
	// Build a textual RR and parse it; this lets miekg/dns handle the
	// wire-level encoding for every RR type without duplicating its
	// rdata builders here.
	content := rec.Content
	if rrType == mdns.TypeTXT && !strings.HasPrefix(content, `"`) {
		content = fmt.Sprintf("%q", content)
	}
	line := fmt.Sprintf("%s %d IN %s %s", zoneStr, ttl, rec.Type, content)
	rr, err := mdns.NewRR(line)
	if err != nil {
		return nil, fmt.Errorf("rfc2136: build rr: %w", err)
	}
	return rr, nil
}

func naturalRecordID(rec dns.ProviderRecord) string {
	return strings.ToLower(strings.TrimSuffix(rec.Name, ".")) + "|" + string(rec.Type) + "|" + rec.Content
}

// Compile-time interface check.
var _ dns.Provider = (*Provider)(nil)
