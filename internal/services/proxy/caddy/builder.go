// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package caddy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fr4nsys/usulnet/internal/models"
)

// BuildConfig generates a complete Caddy JSON configuration from proxy hosts.
// This is the heart of the Caddy integration: our DB is the source of truth,
// and we generate the full Caddy config from it on every sync.
func BuildConfig(hosts []*models.ProxyHost, dnsProviders map[string]*models.ProxyDNSProvider, customCerts map[string]*models.ProxyCertificate, acmeEmail string, listenHTTP, listenHTTPS string) *CaddyConfig {
	if listenHTTP == "" {
		listenHTTP = ":80"
	}
	if listenHTTPS == "" {
		listenHTTPS = ":443"
	}

	routes := make([]Route, 0, len(hosts))
	tlsPolicies := make([]TLSAutomationPolicy, 0)
	pemCerts := make([]LoadPEMCert, 0)
	skipHTTPS := make([]string, 0)

	for _, h := range hosts {
		if !h.Enabled {
			continue
		}

		route := buildRoute(h)
		routes = append(routes, route)

		// TLS policy per host
		switch h.SSLMode {
		case models.ProxySSLModeNone:
			skipHTTPS = append(skipHTTPS, h.Domains...)

		case models.ProxySSLModeAuto:
			// Default ACME (HTTP-01). Caddy handles this automatically,
			// but we add a policy for explicit email config.
			if acmeEmail != "" {
				tlsPolicies = append(tlsPolicies, TLSAutomationPolicy{
					Subjects: h.Domains,
					Issuers: []TLSIssuer{
						{Module: "acme", Email: acmeEmail},
					},
				})
			}

		case models.ProxySSLModeDNS:
			// DNS-01 challenge (supports wildcards)
			if h.DNSProviderID != nil {
				if prov, ok := dnsProviders[h.DNSProviderID.String()]; ok {
					policy := buildDNSPolicy(h.Domains, prov, acmeEmail)
					tlsPolicies = append(tlsPolicies, policy)
				}
			}

		case models.ProxySSLModeCustom:
			// User-provided certificate
			if h.CertificateID != nil {
				if cert, ok := customCerts[h.CertificateID.String()]; ok {
					pemCerts = append(pemCerts, LoadPEMCert{
						Certificate: cert.CertPEM + "\n" + cert.ChainPEM,
						Key:         cert.KeyPEM,
						Tags:        []string{"custom-" + h.ID.String()},
					})
				}
			}
			// Need explicit policy to skip ACME
			tlsPolicies = append(tlsPolicies, TLSAutomationPolicy{
				Subjects: h.Domains,
			})

		case models.ProxySSLModeInternal:
			tlsPolicies = append(tlsPolicies, TLSAutomationPolicy{
				Subjects: h.Domains,
				Issuers:  []TLSIssuer{{Module: "internal"}},
			})
		}
	}

	// Build server
	srv := &Server{
		Listen: []string{listenHTTPS, listenHTTP},
		Routes: routes,
	}

	if len(skipHTTPS) > 0 {
		srv.AutomaticHTTPS = &AutoHTTPS{
			Skip:      skipHTTPS,
			SkipCerts: skipHTTPS,
		}
	}

	// Build TLS app
	var tlsApp *TLSApp
	if len(tlsPolicies) > 0 || len(pemCerts) > 0 {
		tlsApp = &TLSApp{}
		if len(tlsPolicies) > 0 {
			tlsApp.Automation = &TLSAutomation{Policies: tlsPolicies}
		}
		if len(pemCerts) > 0 {
			tlsApp.Certificates = &TLSCertificates{LoadPEM: pemCerts}
		}
	}

	return &CaddyConfig{
		Admin: &AdminConfig{
			Listen: "0.0.0.0:2019",
		},
		Apps: &Apps{
			HTTP: &HTTPApp{
				Servers: map[string]*Server{
					"usulnet": srv,
				},
			},
			TLS: tlsApp,
		},
	}
}

// buildRoute generates a Caddy route for a single proxy host.
func buildRoute(h *models.ProxyHost) Route {
	handlers := make([]json.RawMessage, 0, 4)

	// 1. Compression (before reverse_proxy so response is compressed)
	if h.EnableCompression {
		enc := EncodeHandler{
			Handler: "encode",
			Encodings: map[string]interface{}{
				"zstd": map[string]interface{}{},
				"gzip": map[string]interface{}{},
			},
			Prefer: []string{"zstd", "gzip"},
		}
		handlers = append(handlers, mustMarshal(enc))
	}

	// 2. HSTS header
	if h.EnableHSTS && h.SSLMode != models.ProxySSLModeNone {
		hsts := HeadersHandler{
			Handler: "headers",
			Response: &HeaderFieldOps{
				Set: map[string][]string{
					"Strict-Transport-Security": {"max-age=31536000; includeSubDomains; preload"},
				},
			},
		}
		handlers = append(handlers, mustMarshal(hsts))
	}

	// 3. Custom headers
	if len(h.CustomHeaders) > 0 {
		reqSet := make(map[string][]string)
		reqAdd := make(map[string][]string)
		reqDel := make([]string, 0)
		respSet := make(map[string][]string)
		respAdd := make(map[string][]string)
		respDel := make([]string, 0)

		for _, ch := range h.CustomHeaders {
			switch ch.Direction {
			case "request":
				switch ch.Operation {
				case "set":
					reqSet[ch.Name] = []string{ch.Value}
				case "add":
					reqAdd[ch.Name] = append(reqAdd[ch.Name], ch.Value)
				case "delete":
					reqDel = append(reqDel, ch.Name)
				}
			case "response":
				switch ch.Operation {
				case "set":
					respSet[ch.Name] = []string{ch.Value}
				case "add":
					respAdd[ch.Name] = append(respAdd[ch.Name], ch.Value)
				case "delete":
					respDel = append(respDel, ch.Name)
				}
			}
		}

		hh := HeadersHandler{Handler: "headers"}
		if len(reqSet) > 0 || len(reqAdd) > 0 || len(reqDel) > 0 {
			hh.Request = &HeaderFieldOps{}
			if len(reqSet) > 0 {
				hh.Request.Set = reqSet
			}
			if len(reqAdd) > 0 {
				hh.Request.Add = reqAdd
			}
			if len(reqDel) > 0 {
				hh.Request.Delete = reqDel
			}
		}
		if len(respSet) > 0 || len(respAdd) > 0 || len(respDel) > 0 {
			hh.Response = &HeaderFieldOps{}
			if len(respSet) > 0 {
				hh.Response.Set = respSet
			}
			if len(respAdd) > 0 {
				hh.Response.Add = respAdd
			}
			if len(respDel) > 0 {
				hh.Response.Delete = respDel
			}
		}
		handlers = append(handlers, mustMarshal(hh))
	}

	// 4. Reverse proxy handler (always last)
	rp := buildReverseProxy(h)
	handlers = append(handlers, mustMarshal(rp))

	return Route{
		ID: "usulnet-" + h.ID.String(),
		Match: []MatchConfig{
			{Host: h.Domains},
		},
		Handle:   handlers,
		Terminal: true,
	}
}

// buildReverseProxy generates the reverse_proxy handler for a host.
func buildReverseProxy(h *models.ProxyHost) ReverseProxyHandler {
	dial := fmt.Sprintf("%s:%d", h.UpstreamHost, h.UpstreamPort)

	rp := ReverseProxyHandler{
		Handler:   "reverse_proxy",
		Upstreams: []Upstream{{Dial: dial}},
	}

	// Transport configuration
	switch h.UpstreamScheme {
	case models.ProxyUpstreamHTTPS:
		rp.Transport = &HTTPTransport{
			Module: "http",
			TLS:    &UpstreamTLS{InsecureSkipVerify: false},
		}
	case models.ProxyUpstreamH2C:
		rp.Transport = &HTTPTransport{
			Module:   "http",
			Versions: []string{"h2c", "2"},
		}
	}

	// WebSocket: set flush_interval to -1 for streaming
	if h.EnableWebSocket {
		rp.FlushInterval = json.Number("-1")
	}

	// Proxy headers (standard set for reverse proxy)
	rp.Headers = &HeaderOps{
		Request: &HeaderFieldOps{
			Set: map[string][]string{
				"X-Forwarded-For":   {"{http.request.remote.host}"},
				"X-Forwarded-Proto": {"{http.request.scheme}"},
				"X-Forwarded-Host":  {"{http.request.host}"},
				"X-Real-IP":         {"{http.request.remote.host}"},
			},
		},
	}

	// Health checks
	if h.HealthCheckEnabled && h.HealthCheckPath != "" {
		interval := h.HealthCheckInterval
		if interval <= 0 {
			interval = 30
		}
		rp.HealthChecks = &HealthChecks{
			Active: &ActiveHealthCheck{
				Path:     h.HealthCheckPath,
				Interval: fmt.Sprintf("%ds", interval),
				Timeout:  "5s",
			},
		}
	}

	return rp
}

// buildDNSPolicy creates a TLS automation policy with DNS-01 challenge.
func buildDNSPolicy(domains []string, prov *models.ProxyDNSProvider, email string) TLSAutomationPolicy {
	// The DNS provider module config depends on the provider type.
	// Caddy expects: {"name": "cloudflare", "api_token": "xxx"}
	provConfig := map[string]interface{}{
		"name":      prov.Provider,
		"api_token": prov.APIToken,
	}
	if prov.Zone != "" {
		provConfig["zone"] = prov.Zone
	}

	provJSON, _ := json.Marshal(provConfig)

	propagation := prov.Propagation
	if propagation <= 0 {
		propagation = 60
	}

	return TLSAutomationPolicy{
		Subjects: domains,
		Issuers: []TLSIssuer{
			{
				Module: "acme",
				Email:  email,
				Challenges: &Challenges{
					DNS: &DNSChallenge{
						Provider:           json.RawMessage(provJSON),
						PropagationTimeout: fmt.Sprintf("%ds", propagation),
					},
					HTTP: &HTTPChallenge{Disabled: true},
				},
			},
		},
	}
}

// UpstreamURL returns the full upstream URL for a proxy host.
func UpstreamURL(h *models.ProxyHost) string {
	path := strings.TrimRight(h.UpstreamPath, "/")
	return fmt.Sprintf("%s://%s:%d%s", h.UpstreamScheme, h.UpstreamHost, h.UpstreamPort, path)
}

func mustMarshal(v interface{}) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic("caddy: marshal handler: " + err.Error())
	}
	return data
}
