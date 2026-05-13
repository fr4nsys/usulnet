// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package recon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RDAP returns structured registration data for domains and IP space.
// We use the IANA-maintained bootstrap servers (rdap.org as a thin
// indirection) and parse the minimum subset of RFC 7483 we need to
// extract a registrant organisation name.

// rdapDefaultBaseURL is the public bootstrap front-end. It accepts
// "/domain/<name>" and "/ip/<addr>" and 302-redirects to the
// registrar/RIR-specific RDAP endpoint, which the stdlib client
// follows transparently.
const rdapDefaultBaseURL = "https://rdap.org"

// rdapDefaultTimeout is the default per-call HTTP timeout. Operators
// run RDAP in tight loops during onboarding; one second per RTT is the
// rough budget.
const rdapDefaultTimeout = 10 * time.Second

// ErrRDAPNotFound is returned when the RDAP server responds 404 — the
// domain or IP block is not registered or the registry refuses to
// answer.
var ErrRDAPNotFound = errors.New("rdap: object not found")

// RDAPClient is a thin RFC 7483 client. It is safe for concurrent use
// because *http.Client is.
type RDAPClient struct {
	baseURL string
	http    *http.Client
}

// NewRDAPClient returns a client targeting the default IANA bootstrap
// front-end. A non-positive timeout falls back to rdapDefaultTimeout.
func NewRDAPClient(timeout time.Duration) *RDAPClient {
	return NewRDAPClientWithBase(rdapDefaultBaseURL, timeout)
}

// NewRDAPClientWithBase lets tests inject an httptest.Server URL.
func NewRDAPClientWithBase(baseURL string, timeout time.Duration) *RDAPClient {
	if timeout <= 0 {
		timeout = rdapDefaultTimeout
	}
	return &RDAPClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: timeout},
	}
}

// rdapResponse is the subset of RFC 7483 we parse. Real responses are
// significantly larger; unknown fields are ignored.
type rdapResponse struct {
	ObjectClassName string       `json:"objectClassName"`
	Handle          string       `json:"handle"`
	LDHName         string       `json:"ldhName"`
	Name            string       `json:"name"`
	Entities        []rdapEntity `json:"entities"`
}

// rdapEntity is one of the entities (registrant, admin, tech) embedded
// in a domain or IP response.
type rdapEntity struct {
	Handle string   `json:"handle"`
	Roles  []string `json:"roles"`
	// VCardArray is the jCard payload — an opaque array because the
	// inner structure is a positional list-of-lists. parseOrgFromVCard
	// pulls "fn" or "org" out by walking it generically.
	VCardArray []any        `json:"vcardArray"`
	Entities   []rdapEntity `json:"entities"`
}

// LookupDomainOrg fetches RDAP data for a domain and returns the
// registrant organisation name, or ErrRDAPNotFound when the registry
// refuses the lookup.
func (c *RDAPClient) LookupDomainOrg(ctx context.Context, domain string) (string, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return "", fmt.Errorf("rdap: empty domain")
	}
	endpoint := c.baseURL + "/domain/" + url.PathEscape(domain)
	resp, err := c.get(ctx, endpoint)
	if err != nil {
		return "", err
	}
	return extractRegistrantOrg(resp), nil
}

// LookupIPOrg fetches RDAP data for an IP or CIDR. For a CIDR we look
// up the first address: RDAP returns the enclosing network either way.
func (c *RDAPClient) LookupIPOrg(ctx context.Context, ipOrCIDR string) (string, error) {
	addr, err := normaliseIPForRDAP(ipOrCIDR)
	if err != nil {
		return "", err
	}
	endpoint := c.baseURL + "/ip/" + url.PathEscape(addr)
	resp, err := c.get(ctx, endpoint)
	if err != nil {
		return "", err
	}
	return extractRegistrantOrg(resp), nil
}

// get performs a single GET, decodes the body, and normalises the
// limited set of HTTP outcomes we care about.
func (c *RDAPClient) get(ctx context.Context, endpoint string) (*rdapResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("rdap: build request: %w", err)
	}
	req.Header.Set("Accept", "application/rdap+json, application/json;q=0.5")
	req.Header.Set("User-Agent", "usulnet-recon-rdap/1.0")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rdap: http: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrRDAPNotFound
	case resp.StatusCode >= 400:
		return nil, fmt.Errorf("rdap: unexpected status %d", resp.StatusCode)
	}

	// Cap body size so a runaway RDAP server cannot exhaust memory; 1 MiB
	// comfortably exceeds the largest legitimate registrar response.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("rdap: read body: %w", err)
	}
	var out rdapResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("rdap: decode: %w", err)
	}
	return &out, nil
}

// extractRegistrantOrg walks the entity tree looking for an entity with
// the "registrant" role (preferred) or, failing that, the first entity
// with a usable organisation name. Returns "" when nothing matches —
// callers handle that case by reporting an ownership mismatch.
func extractRegistrantOrg(r *rdapResponse) string {
	if r == nil {
		return ""
	}
	// Pass 1: a registrant entity wins.
	if v := walkEntities(r.Entities, "registrant"); v != "" {
		return v
	}
	// Pass 2: any entity with org/fn fields. Registrars that redact the
	// role still publish "fn"/"org" for the network handle itself.
	return walkEntities(r.Entities, "")
}

// walkEntities depth-first searches entities for a matching role and
// returns the first org name it finds.
func walkEntities(entities []rdapEntity, role string) string {
	for _, e := range entities {
		if role == "" || hasRole(e.Roles, role) {
			if v := parseOrgFromVCard(e.VCardArray); v != "" {
				return v
			}
		}
		if v := walkEntities(e.Entities, role); v != "" {
			return v
		}
	}
	return ""
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if strings.EqualFold(r, want) {
			return true
		}
	}
	return false
}

// parseOrgFromVCard extracts the "org" or "fn" property from a jCard
// (RFC 7095) array. The shape is:
//
//	["vcard", [ ["version", {}, "text", "4.0"],
//	            ["fn",      {}, "text", "Example Inc."],
//	            ["org",     {}, "text", ["Example", "Inc."]],
//	            ... ] ]
//
// We tolerate strings or string slices in the value slot; some
// registrars use nested arrays.
func parseOrgFromVCard(arr []any) string {
	if len(arr) < 2 {
		return ""
	}
	props, ok := arr[1].([]any)
	if !ok {
		return ""
	}
	var fnFallback string
	for _, p := range props {
		entry, ok := p.([]any)
		if !ok || len(entry) < 4 {
			continue
		}
		name, _ := entry[0].(string)
		switch strings.ToLower(name) {
		case "org":
			if v := vcardValueToString(entry[3]); v != "" {
				return v
			}
		case "fn":
			if fnFallback == "" {
				fnFallback = vcardValueToString(entry[3])
			}
		}
	}
	return fnFallback
}

// vcardValueToString collapses the polymorphic value slot of a jCard
// entry into a single human-readable string. A list of components like
// ["Example", "Inc."] becomes "Example Inc.".
func vcardValueToString(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case []any:
		parts := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					parts = append(parts, s)
				}
			}
		}
		return strings.Join(parts, " ")
	default:
		return ""
	}
}

// normaliseIPForRDAP accepts an IP or CIDR and returns a single address
// suitable for the /ip/<addr> RDAP endpoint. RDAP servers resolve a
// single IP to the enclosing network so we do not need to walk a range.
func normaliseIPForRDAP(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("rdap: empty ip")
	}
	if strings.Contains(s, "/") {
		ip, _, err := net.ParseCIDR(s)
		if err != nil {
			return "", fmt.Errorf("rdap: parse cidr: %w", err)
		}
		return ip.String(), nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String(), nil
	}
	return "", fmt.Errorf("rdap: invalid ip %q", s)
}
