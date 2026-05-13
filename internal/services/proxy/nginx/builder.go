// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package nginx generates nginx configuration from proxy host definitions
// and manages the nginx process lifecycle for the usulnet reverse proxy.
package nginx

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/models"
)

// BuildConfig generates a complete nginx configuration for all proxy hosts.
// The generated config is written as a single file included by the main nginx.conf.
func BuildConfig(hosts []*models.ProxyHost, customCerts map[string]*models.ProxyCertificate, acmeEmail, listenHTTP, listenHTTPS, certDir, acmeWebRoot string) string {
	if listenHTTP == "" {
		listenHTTP = "80"
	}
	if listenHTTPS == "" {
		listenHTTPS = "443"
	}
	// Strip leading colon if present (e.g. ":80" → "80")
	listenHTTP = strings.TrimPrefix(listenHTTP, ":")
	listenHTTPS = strings.TrimPrefix(listenHTTPS, ":")

	var b strings.Builder

	b.WriteString("# Managed by usulnet — do not edit manually\n")
	b.WriteString(fmt.Sprintf("# Generated at: %s\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("# Hosts: %d\n\n", len(hosts)))

	// Map: build unique upstreams
	for _, h := range hosts {
		if !h.Enabled {
			continue
		}
		b.WriteString(buildUpstream(h))
		b.WriteByte('\n')
	}

	// Server blocks
	for _, h := range hosts {
		if !h.Enabled {
			continue
		}
		b.WriteString(buildServerBlock(h, customCerts, listenHTTP, listenHTTPS, certDir, acmeWebRoot))
		b.WriteByte('\n')
	}

	// Default server block — catch-all that returns 444 for unmatched requests
	b.WriteString(buildDefaultServer(listenHTTP, listenHTTPS, certDir))

	return b.String()
}

func upstreamName(h *models.ProxyHost) string {
	return "usulnet_" + h.ID.String()[:8]
}

func buildUpstream(h *models.ProxyHost) string {
	var b strings.Builder
	name := upstreamName(h)
	b.WriteString(fmt.Sprintf("upstream %s {\n", name))
	b.WriteString(fmt.Sprintf("    server %s:%d;\n", h.UpstreamHost, h.UpstreamPort))

	if h.HealthCheckEnabled && h.HealthCheckPath != "" {
		// nginx plus has health checks; for open-source nginx, use passive checks
		b.WriteString("    # Health check path: " + h.HealthCheckPath + "\n")
	}

	b.WriteString("}\n")
	return b.String()
}

func buildServerBlock(h *models.ProxyHost, customCerts map[string]*models.ProxyCertificate, listenHTTP, listenHTTPS, certDir, acmeWebRoot string) string {
	hasSSL := h.SSLMode != models.ProxySSLModeNone
	domains := strings.Join(h.Domains, " ")

	var b strings.Builder

	// HTTP server block
	if hasSSL && h.SSLForceHTTPS {
		// HTTP → HTTPS redirect
		b.WriteString(fmt.Sprintf("server {\n"))
		b.WriteString(fmt.Sprintf("    listen %s;\n", listenHTTP))
		b.WriteString(fmt.Sprintf("    listen [::]:%s;\n", listenHTTP))
		b.WriteString(fmt.Sprintf("    server_name %s;\n\n", domains))
		// ACME challenge location (always serve, even during redirect)
		b.WriteString(fmt.Sprintf("    location /.well-known/acme-challenge/ {\n"))
		b.WriteString(fmt.Sprintf("        root %s;\n", acmeWebRoot))
		b.WriteString(fmt.Sprintf("    }\n\n"))
		b.WriteString(fmt.Sprintf("    location / {\n"))
		b.WriteString(fmt.Sprintf("        return 301 https://$host$request_uri;\n"))
		b.WriteString(fmt.Sprintf("    }\n"))
		b.WriteString(fmt.Sprintf("}\n\n"))
	}

	// Main server block (HTTPS or plain HTTP)
	b.WriteString("server {\n")

	if hasSSL {
		b.WriteString(fmt.Sprintf("    listen %s ssl", listenHTTPS))
		if h.EnableHTTP2 {
			b.WriteString(" http2")
		}
		b.WriteString(";\n")
		b.WriteString(fmt.Sprintf("    listen [::]:%s ssl", listenHTTPS))
		if h.EnableHTTP2 {
			b.WriteString(" http2")
		}
		b.WriteString(";\n")

		// Also listen on HTTP if not forcing redirect (to serve both)
		if !h.SSLForceHTTPS {
			b.WriteString(fmt.Sprintf("    listen %s;\n", listenHTTP))
			b.WriteString(fmt.Sprintf("    listen [::]:%s;\n", listenHTTP))
		}
	} else {
		b.WriteString(fmt.Sprintf("    listen %s;\n", listenHTTP))
		b.WriteString(fmt.Sprintf("    listen [::]:%s;\n", listenHTTP))
	}

	b.WriteString(fmt.Sprintf("    server_name %s;\n\n", domains))

	// SSL configuration
	if hasSSL {
		certPath, keyPath := certPaths(h, customCerts, certDir)
		b.WriteString(fmt.Sprintf("    ssl_certificate %s;\n", certPath))
		b.WriteString(fmt.Sprintf("    ssl_certificate_key %s;\n", keyPath))
		b.WriteString("    ssl_protocols TLSv1.2 TLSv1.3;\n")
		b.WriteString("    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\n")
		b.WriteString("    ssl_prefer_server_ciphers on;\n")
		b.WriteString("    ssl_session_cache shared:SSL:10m;\n")
		b.WriteString("    ssl_session_timeout 10m;\n\n")
	}

	// HSTS
	if h.EnableHSTS && hasSSL {
		b.WriteString("    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n\n")
	}

	// Compression
	if h.EnableCompression {
		b.WriteString("    gzip on;\n")
		b.WriteString("    gzip_vary on;\n")
		b.WriteString("    gzip_proxied any;\n")
		b.WriteString("    gzip_comp_level 6;\n")
		b.WriteString("    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript image/svg+xml;\n\n")
	}

	// ACME challenge (in case SSL block serves HTTP too)
	if hasSSL && !h.SSLForceHTTPS {
		b.WriteString(fmt.Sprintf("    location /.well-known/acme-challenge/ {\n"))
		b.WriteString(fmt.Sprintf("        root %s;\n", acmeWebRoot))
		b.WriteString(fmt.Sprintf("    }\n\n"))
	}

	// Proxy location
	upName := upstreamName(h)
	proxyScheme := h.UpstreamScheme
	if proxyScheme == "" || proxyScheme == "h2c" {
		proxyScheme = "http"
	}

	b.WriteString("    location / {\n")
	b.WriteString(fmt.Sprintf("        proxy_pass %s://%s", proxyScheme, upName))
	if h.UpstreamPath != "" {
		b.WriteString(strings.TrimRight(h.UpstreamPath, "/"))
	}
	b.WriteString(";\n")

	// Standard proxy headers
	b.WriteString("        proxy_set_header Host $host;\n")
	b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
	b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
	b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
	b.WriteString("        proxy_set_header X-Forwarded-Host $host;\n")

	// WebSocket support
	if h.EnableWebSocket {
		b.WriteString("\n        # WebSocket support\n")
		b.WriteString("        proxy_http_version 1.1;\n")
		b.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
		b.WriteString("        proxy_set_header Connection $connection_upgrade;\n")
		b.WriteString("        proxy_read_timeout 86400s;\n")
		b.WriteString("        proxy_send_timeout 86400s;\n")
	}

	// Custom headers
	for _, ch := range h.CustomHeaders {
		switch ch.Direction {
		case "request":
			switch ch.Operation {
			case "set":
				b.WriteString(fmt.Sprintf("        proxy_set_header %s %q;\n", ch.Name, ch.Value))
			case "add":
				b.WriteString(fmt.Sprintf("        proxy_set_header %s %q;\n", ch.Name, ch.Value))
			case "delete":
				b.WriteString(fmt.Sprintf("        proxy_set_header %s \"\";\n", ch.Name))
			}
		case "response":
			switch ch.Operation {
			case "set":
				b.WriteString(fmt.Sprintf("        add_header %s %q always;\n", ch.Name, ch.Value))
			case "add":
				b.WriteString(fmt.Sprintf("        add_header %s %q;\n", ch.Name, ch.Value))
			case "delete":
				b.WriteString(fmt.Sprintf("        proxy_hide_header %s;\n", ch.Name))
			}
		}
	}

	b.WriteString("    }\n")
	b.WriteString("}\n")

	return b.String()
}

// certPaths resolves the SSL certificate and key file paths for a host.
func certPaths(h *models.ProxyHost, customCerts map[string]*models.ProxyCertificate, certDir string) (certPath, keyPath string) {
	primaryDomain := h.Domains[0]

	switch h.SSLMode {
	case models.ProxySSLModeCustom:
		if h.CertificateID != nil {
			certPath = filepath.Join(certDir, "custom", h.CertificateID.String(), "fullchain.pem")
			keyPath = filepath.Join(certDir, "custom", h.CertificateID.String(), "privkey.pem")
			return
		}
	case models.ProxySSLModeInternal:
		certPath = filepath.Join(certDir, "internal", primaryDomain, "fullchain.pem")
		keyPath = filepath.Join(certDir, "internal", primaryDomain, "privkey.pem")
		return
	}

	// Default: ACME (Let's Encrypt) — auto or dns mode
	certPath = filepath.Join(certDir, "live", primaryDomain, "fullchain.pem")
	keyPath = filepath.Join(certDir, "live", primaryDomain, "privkey.pem")
	return
}

func buildDefaultServer(listenHTTP, listenHTTPS, certDir string) string {
	var b strings.Builder
	b.WriteString("# Default server — reject unmatched requests\n")
	b.WriteString("server {\n")
	b.WriteString(fmt.Sprintf("    listen %s default_server;\n", listenHTTP))
	b.WriteString(fmt.Sprintf("    listen [::]:%s default_server;\n", listenHTTP))
	b.WriteString("    server_name _;\n")
	b.WriteString("    return 444;\n")
	b.WriteString("}\n")
	return b.String()
}
