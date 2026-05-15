// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package digitalocean implements the DigitalOcean DNS provider plugin
// against the v2 REST API. Per session-10's risk note, we use direct
// HTTP rather than the godo SDK to keep the dependency tree small.
package digitalocean

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/dns"
)

// DefaultBaseURL is the v2 DigitalOcean API.
const DefaultBaseURL = "https://api.digitalocean.com/v2"

// Capabilities returns the plugin's static metadata.
func Capabilities() dns.Capabilities {
	return dns.Capabilities{
		DisplayName: "DigitalOcean",
		Description: "DigitalOcean DNS via the v2 REST API. Requires a Personal Access Token with read+write scope.",
		Records: []dns.SupportedRecord{
			{Type: models.DNSRecordTypeA, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeAAAA, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeCNAME, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeMX, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeTXT, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeNS, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeSRV, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeCAA, Read: true, Write: true, UpdateTTL: true},
		},
		CredentialFields: []dns.CredentialField{
			{Key: "api_token", Label: "API Token", Required: true, Secret: true,
				Description: "DigitalOcean Personal Access Token with read+write."},
		},
		ConfigFields: []dns.ConfigField{
			{Key: "base_url", Label: "API base URL", Type: "string", Default: DefaultBaseURL,
				Description: "Override for tests or self-hosted DigitalOcean-compatible endpoints."},
		},
	}
}

// Credentials is the JSON shape the encrypted blob holds.
type Credentials struct {
	APIToken string `json:"api_token"`
}

// Provider implements dns.Provider against the DigitalOcean REST API.
type Provider struct {
	baseURL string
	token   string
	client  *http.Client
}

// Factory builds a Provider.
func Factory(_ context.Context, credentials []byte, config map[string]any) (dns.Provider, error) {
	var creds Credentials
	if err := json.Unmarshal(credentials, &creds); err != nil {
		return nil, fmt.Errorf("digitalocean: invalid credentials JSON: %w", err)
	}
	if strings.TrimSpace(creds.APIToken) == "" {
		return nil, fmt.Errorf("digitalocean: %w: api_token is required", dns.ErrInvalidCredentials)
	}
	base := DefaultBaseURL
	if v, ok := config["base_url"].(string); ok && v != "" {
		base = strings.TrimRight(v, "/")
	}
	return &Provider{
		baseURL: base,
		token:   creds.APIToken,
		client:  &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Register adds the plugin to the registry.
func Register(reg *dns.Registry) error {
	return reg.Register(models.DNSProviderKindDigitalOcean, Factory, Capabilities())
}

// Kind returns the provider identifier.
func (p *Provider) Kind() models.DNSProviderKind { return models.DNSProviderKindDigitalOcean }

// Close is a no-op.
func (p *Provider) Close() error { return nil }

// VerifyCredentials hits /v2/account, the cheapest authenticated
// endpoint that exists.
func (p *Provider) VerifyCredentials(ctx context.Context) error {
	resp, err := p.do(ctx, http.MethodGet, "/account", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return dns.ErrInvalidCredentials
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("digitalocean: verify failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// CreateRecord adds a record under the matching domain.
func (p *Provider) CreateRecord(ctx context.Context, rec dns.ProviderRecord) (dns.ProviderRecord, error) {
	domain, sub, err := p.findDomain(ctx, rec.Name)
	if err != nil {
		return dns.ProviderRecord{}, err
	}
	body := map[string]any{
		"type": string(rec.Type),
		"name": sub,
		"data": rec.Content,
		"ttl":  rec.TTL,
	}
	resp, err := p.do(ctx, http.MethodPost, "/domains/"+domain+"/records", body)
	if err != nil {
		return dns.ProviderRecord{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return dns.ProviderRecord{}, decodeError(resp, "create record")
	}
	var out struct {
		DomainRecord recordPayload `json:"domain_record"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return dns.ProviderRecord{}, fmt.Errorf("digitalocean: decode create record: %w", err)
	}
	return dns.ProviderRecord{
		ID:      strconv.Itoa(out.DomainRecord.ID),
		Name:    joinSubAndDomain(out.DomainRecord.Name, domain),
		Type:    models.DNSRecordType(out.DomainRecord.Type),
		Content: out.DomainRecord.Data,
		TTL:     out.DomainRecord.TTL,
	}, nil
}

// DeleteRecord removes a record by id.
func (p *Provider) DeleteRecord(ctx context.Context, id string, rec dns.ProviderRecord) error {
	domain, _, err := p.findDomain(ctx, rec.Name)
	if err != nil {
		return err
	}
	resp, err := p.do(ctx, http.MethodDelete, "/domains/"+domain+"/records/"+id, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return dns.ErrRecordNotFound
	}
	if resp.StatusCode != http.StatusNoContent {
		return decodeError(resp, "delete record")
	}
	return nil
}

// ListRecords returns the records for a domain.
func (p *Provider) ListRecords(ctx context.Context, zone string) ([]dns.ProviderRecord, error) {
	domain, _, err := p.findDomain(ctx, zone)
	if err != nil {
		return nil, err
	}
	resp, err := p.do(ctx, http.MethodGet, "/domains/"+domain+"/records?per_page=200", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, decodeError(resp, "list records")
	}
	var out struct {
		DomainRecords []recordPayload `json:"domain_records"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("digitalocean: decode list records: %w", err)
	}
	results := make([]dns.ProviderRecord, 0, len(out.DomainRecords))
	for _, r := range out.DomainRecords {
		results = append(results, dns.ProviderRecord{
			ID:      strconv.Itoa(r.ID),
			Name:    joinSubAndDomain(r.Name, domain),
			Type:    models.DNSRecordType(r.Type),
			Content: r.Data,
			TTL:     r.TTL,
		})
	}
	return results, nil
}

// ============================================================================
// Internal helpers
// ============================================================================

type recordPayload struct {
	ID   int    `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
	Data string `json:"data"`
	TTL  int    `json:"ttl"`
}

// findDomain finds the registered domain for a record name and returns
// the domain plus the subdomain prefix DigitalOcean wants ("@" for the
// apex).
func (p *Provider) findDomain(ctx context.Context, recordName string) (string, string, error) {
	name := strings.TrimSuffix(recordName, ".")
	if name == "" {
		return "", "", dns.ErrZoneNotFound
	}

	candidates := splitCandidates(name)
	for _, candidate := range candidates {
		resp, err := p.do(ctx, http.MethodGet, "/domains/"+candidate, nil)
		if err != nil {
			return "", "", err
		}
		switch resp.StatusCode {
		case http.StatusOK:
			resp.Body.Close()
			sub := strings.TrimSuffix(strings.TrimSuffix(name, candidate), ".")
			if sub == "" {
				sub = "@"
			}
			return candidate, sub, nil
		case http.StatusNotFound:
			resp.Body.Close()
			continue
		default:
			err := decodeError(resp, "lookup domain")
			resp.Body.Close()
			return "", "", err
		}
	}
	return "", "", dns.ErrZoneNotFound
}

// splitCandidates returns the suffix candidates for a record name,
// most-specific first. ("a.b.example.com" → ["a.b.example.com",
// "b.example.com", "example.com", "com"]).
func splitCandidates(name string) []string {
	out := []string{}
	cur := name
	for cur != "" {
		out = append(out, cur)
		idx := strings.Index(cur, ".")
		if idx < 0 {
			break
		}
		cur = cur[idx+1:]
	}
	return out
}

func joinSubAndDomain(sub, domain string) string {
	if sub == "" || sub == "@" {
		return domain
	}
	return sub + "." + domain
}

func (p *Provider) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("digitalocean: %s %s: %w", method, path, err)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("%w: %s", dns.ErrInvalidCredentials, strings.TrimSpace(string(body)))
	}
	return resp, nil
}

func decodeError(resp *http.Response, op string) error {
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("digitalocean: %s failed (status %d): %s", op, resp.StatusCode, strings.TrimSpace(string(body)))
}

// Compile-time interface check.
var _ dns.Provider = (*Provider)(nil)
