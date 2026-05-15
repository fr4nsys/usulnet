// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package cloudflare implements the Cloudflare DNS provider plugin
// against the v4 REST API. We deliberately avoid the cloudflare-go
// SDK to keep the dependency tree small — the wire surface we need
// (zones, dns_records, user/tokens/verify) fits in a few hundred
// lines of plain HTTP.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/dns"
)

// DefaultBaseURL is the v4 Cloudflare API.
const DefaultBaseURL = "https://api.cloudflare.com/client/v4"

// Capabilities returns the static metadata the registry advertises.
func Capabilities() dns.Capabilities {
	return dns.Capabilities{
		DisplayName: "Cloudflare",
		Description: "Cloudflare DNS via the v4 REST API. Requires an API token with Zone.DNS edit permission.",
		Records: []dns.SupportedRecord{
			{Type: models.DNSRecordTypeA, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeAAAA, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeCNAME, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeMX, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeTXT, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeNS, Read: true, Write: false},
			{Type: models.DNSRecordTypeSRV, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeCAA, Read: true, Write: true, UpdateTTL: true},
		},
		CredentialFields: []dns.CredentialField{
			{Key: "api_token", Label: "API Token", Required: true, Secret: true,
				Description: "Cloudflare API token scoped to Zone.DNS edit on the relevant zones."},
		},
		ConfigFields: []dns.ConfigField{
			{Key: "base_url", Label: "API base URL", Type: "string", Default: DefaultBaseURL,
				Description: "Override for tests or self-hosted Cloudflare-compatible endpoints."},
		},
	}
}

// Credentials is the JSON shape stored encrypted at rest.
type Credentials struct {
	APIToken string `json:"api_token"`
}

// Provider implements dns.Provider against the Cloudflare REST API.
type Provider struct {
	baseURL string
	token   string
	client  *http.Client
}

// Factory builds a Provider from the encrypted credential blob.
// Registered with dns.Registry via Register.
func Factory(_ context.Context, credentials []byte, config map[string]any) (dns.Provider, error) {
	var creds Credentials
	if err := json.Unmarshal(credentials, &creds); err != nil {
		return nil, fmt.Errorf("cloudflare: invalid credentials JSON: %w", err)
	}
	if strings.TrimSpace(creds.APIToken) == "" {
		return nil, fmt.Errorf("cloudflare: %w: api_token is required", dns.ErrInvalidCredentials)
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

// Register adds the Cloudflare plugin to the registry. Called from
// the wiring layer once at boot.
func Register(reg *dns.Registry) error {
	return reg.Register(models.DNSProviderKindCloudflare, Factory, Capabilities())
}

// Kind returns the provider identifier.
func (p *Provider) Kind() models.DNSProviderKind { return models.DNSProviderKindCloudflare }

// Close is a no-op — the http.Client owns no resources we need to
// release explicitly.
func (p *Provider) Close() error { return nil }

// VerifyCredentials calls /user/tokens/verify which returns 200 only
// when the token is valid. Cheap, doesn't require any zone.
func (p *Provider) VerifyCredentials(ctx context.Context) error {
	resp, err := p.do(ctx, http.MethodGet, "/user/tokens/verify", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var out struct {
		Success bool `json:"success"`
	}
	if err := decodeJSON(resp, &out); err != nil {
		return err
	}
	if !out.Success {
		return dns.ErrInvalidCredentials
	}
	return nil
}

// CreateRecord adds a DNS record under the matching zone.
func (p *Provider) CreateRecord(ctx context.Context, rec dns.ProviderRecord) (dns.ProviderRecord, error) {
	zoneID, err := p.zoneIDFor(ctx, rec.Name)
	if err != nil {
		return dns.ProviderRecord{}, err
	}
	body := map[string]any{
		"type":    string(rec.Type),
		"name":    rec.Name,
		"content": rec.Content,
		"ttl":     rec.TTL,
	}
	resp, err := p.do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", body)
	if err != nil {
		return dns.ProviderRecord{}, err
	}
	defer resp.Body.Close()
	var out struct {
		Success bool          `json:"success"`
		Errors  []apiError    `json:"errors"`
		Result  recordPayload `json:"result"`
	}
	if err := decodeJSON(resp, &out); err != nil {
		return dns.ProviderRecord{}, err
	}
	if !out.Success {
		return dns.ProviderRecord{}, fmt.Errorf("cloudflare: create record failed: %s", joinErrors(out.Errors))
	}
	return dns.ProviderRecord{
		ID: out.Result.ID, Name: out.Result.Name, Type: models.DNSRecordType(out.Result.Type),
		Content: out.Result.Content, TTL: out.Result.TTL,
	}, nil
}

// DeleteRecord removes a record by id. The zone must still be
// inferable from rec.Name.
func (p *Provider) DeleteRecord(ctx context.Context, id string, rec dns.ProviderRecord) error {
	zoneID, err := p.zoneIDFor(ctx, rec.Name)
	if err != nil {
		return err
	}
	resp, err := p.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+id, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return dns.ErrRecordNotFound
	}
	var out struct {
		Success bool       `json:"success"`
		Errors  []apiError `json:"errors"`
	}
	if err := decodeJSON(resp, &out); err != nil {
		return err
	}
	if !out.Success {
		// Cloudflare returns 81044 for record-not-found.
		for _, e := range out.Errors {
			if e.Code == 81044 || e.Code == 7000 {
				return dns.ErrRecordNotFound
			}
		}
		return fmt.Errorf("cloudflare: delete record failed: %s", joinErrors(out.Errors))
	}
	return nil
}

// ListRecords returns the records for a zone (looked up by name).
func (p *Provider) ListRecords(ctx context.Context, zone string) ([]dns.ProviderRecord, error) {
	zoneID, err := p.zoneIDFor(ctx, zone)
	if err != nil {
		return nil, err
	}
	resp, err := p.do(ctx, http.MethodGet, "/zones/"+zoneID+"/dns_records?per_page=1000", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Success bool            `json:"success"`
		Errors  []apiError      `json:"errors"`
		Result  []recordPayload `json:"result"`
	}
	if err := decodeJSON(resp, &out); err != nil {
		return nil, err
	}
	if !out.Success {
		return nil, fmt.Errorf("cloudflare: list records failed: %s", joinErrors(out.Errors))
	}
	results := make([]dns.ProviderRecord, 0, len(out.Result))
	for _, r := range out.Result {
		results = append(results, dns.ProviderRecord{
			ID: r.ID, Name: r.Name, Type: models.DNSRecordType(r.Type),
			Content: r.Content, TTL: r.TTL,
		})
	}
	return results, nil
}

// ============================================================================
// Internal helpers
// ============================================================================

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type recordPayload struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

type zonePayload struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// zoneIDFor walks up the labels of a record name to find the most
// specific zone the credentialed account owns. Cloudflare's
// /zones?name= endpoint matches an exact zone name only, so we strip
// labels left-to-right until we find a match.
func (p *Provider) zoneIDFor(ctx context.Context, recordName string) (string, error) {
	name := strings.TrimSuffix(recordName, ".")
	if name == "" {
		return "", dns.ErrZoneNotFound
	}
	for name != "" {
		resp, err := p.do(ctx, http.MethodGet, "/zones?name="+name, nil)
		if err != nil {
			return "", err
		}
		var out struct {
			Success bool          `json:"success"`
			Errors  []apiError    `json:"errors"`
			Result  []zonePayload `json:"result"`
		}
		if err := decodeJSON(resp, &out); err != nil {
			resp.Body.Close()
			return "", err
		}
		resp.Body.Close()
		if !out.Success {
			return "", fmt.Errorf("cloudflare: zone lookup failed: %s", joinErrors(out.Errors))
		}
		if len(out.Result) > 0 {
			return out.Result[0].ID, nil
		}
		idx := strings.Index(name, ".")
		if idx < 0 {
			break
		}
		name = name[idx+1:]
	}
	return "", dns.ErrZoneNotFound
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
		return nil, fmt.Errorf("cloudflare: %s %s: %w", method, path, err)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("%w: %s", dns.ErrInvalidCredentials, strings.TrimSpace(string(body)))
	}
	return resp, nil
}

func decodeJSON(resp *http.Response, out any) error {
	if out == nil {
		return nil
	}
	if resp.StatusCode >= http.StatusInternalServerError {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("cloudflare: upstream error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("cloudflare: decode response: %w", err)
	}
	return nil
}

func joinErrors(errs []apiError) string {
	if len(errs) == 0 {
		return "<no error detail>"
	}
	parts := make([]string, len(errs))
	for i, e := range errs {
		parts[i] = fmt.Sprintf("[%d] %s", e.Code, e.Message)
	}
	return strings.Join(parts, "; ")
}

// Compile-time interface check.
var _ dns.Provider = (*Provider)(nil)
