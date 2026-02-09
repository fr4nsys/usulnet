// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	proxysvc "github.com/fr4nsys/usulnet/internal/services/proxy"
)

// caddyProxyAdapter implements ProxyService using the Caddy-based proxy service.
// This replaces the NPM proxyAdapter for Caddy-managed reverse proxying.
type caddyProxyAdapter struct {
	svc *proxysvc.Service
}

// newCaddyProxyAdapter creates a new Caddy proxy adapter.
func newCaddyProxyAdapter(svc *proxysvc.Service) *caddyProxyAdapter {
	return &caddyProxyAdapter{svc: svc}
}

// ---- Proxy Hosts ----

func (a *caddyProxyAdapter) ListHosts(ctx context.Context) ([]ProxyHostView, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("proxy service not configured")
	}

	hosts, err := a.svc.ListHosts(ctx)
	if err != nil {
		return nil, err
	}

	views := make([]ProxyHostView, 0, len(hosts))
	for _, h := range hosts {
		views = append(views, proxyHostToView(h))
	}
	return views, nil
}

func (a *caddyProxyAdapter) GetHost(ctx context.Context, id int) (*ProxyHostView, error) {
	// The web layer uses int IDs (legacy from NPM). We use the id as a lookup key.
	// For Caddy integration, we parse the UUID from query param or use a mapping.
	// For now, we list all and find by index (transitional).
	uid, err := a.resolveHostID(ctx, id)
	if err != nil {
		return nil, err
	}

	h, err := a.svc.GetHost(ctx, uid)
	if err != nil {
		return nil, err
	}

	v := proxyHostToView(h)
	return &v, nil
}

func (a *caddyProxyAdapter) CreateHost(ctx context.Context, v *ProxyHostView) error {
	input := &models.CreateProxyHostInput{
		Name:              v.Domain,
		Domains:           []string{v.Domain},
		UpstreamScheme:    models.ProxyUpstreamHTTP,
		UpstreamHost:      v.ForwardHost,
		UpstreamPort:      v.ForwardPort,
		SSLMode:           models.ProxySSLModeAuto,
		SSLForceHTTPS:     v.SSLEnabled,
		EnableWebSocket:   true,
		EnableCompression: true,
		EnableHSTS:        v.SSLEnabled,
		EnableHTTP2:       true,
		ContainerID:       v.ContainerID,
		ContainerName:     v.Container,
	}

	if !v.SSLEnabled {
		input.SSLMode = models.ProxySSLModeNone
		input.SSLForceHTTPS = false
		input.EnableHSTS = false
	}

	_, err := a.svc.CreateHost(ctx, input, nil)
	return err
}

func (a *caddyProxyAdapter) UpdateHost(ctx context.Context, v *ProxyHostView) error {
	uid, err := a.resolveHostID(ctx, v.ID)
	if err != nil {
		return err
	}

	scheme := models.ProxyUpstreamHTTP
	sslMode := models.ProxySSLModeAuto
	if !v.SSLEnabled {
		sslMode = models.ProxySSLModeNone
	}

	input := &models.UpdateProxyHostInput{
		Name:            &v.Domain,
		Domains:         []string{v.Domain},
		UpstreamScheme:  &scheme,
		UpstreamHost:    &v.ForwardHost,
		UpstreamPort:    &v.ForwardPort,
		SSLMode:         &sslMode,
		SSLForceHTTPS:   &v.SSLEnabled,
		Enabled:         &v.Enabled,
	}

	_, err = a.svc.UpdateHost(ctx, uid, input, nil)
	return err
}

func (a *caddyProxyAdapter) RemoveHost(ctx context.Context, id int) error {
	uid, err := a.resolveHostID(ctx, id)
	if err != nil {
		return err
	}
	return a.svc.DeleteHost(ctx, uid, nil)
}

func (a *caddyProxyAdapter) EnableHost(ctx context.Context, id int) error {
	uid, err := a.resolveHostID(ctx, id)
	if err != nil {
		return err
	}
	return a.svc.EnableHost(ctx, uid, nil)
}

func (a *caddyProxyAdapter) DisableHost(ctx context.Context, id int) error {
	uid, err := a.resolveHostID(ctx, id)
	if err != nil {
		return err
	}
	return a.svc.DisableHost(ctx, uid, nil)
}

func (a *caddyProxyAdapter) Sync(ctx context.Context) error {
	return a.svc.SyncToCaddy(ctx)
}

// ---- Redirections (not implemented in Caddy Phase 1) ----

func (a *caddyProxyAdapter) ListRedirections(ctx context.Context) ([]RedirectionHostView, error) {
	return []RedirectionHostView{}, nil
}
func (a *caddyProxyAdapter) CreateRedirection(ctx context.Context, r *RedirectionHostView) error {
	return fmt.Errorf("redirections not yet supported in Caddy mode")
}
func (a *caddyProxyAdapter) UpdateRedirection(ctx context.Context, r *RedirectionHostView) error {
	return fmt.Errorf("redirections not yet supported in Caddy mode")
}
func (a *caddyProxyAdapter) DeleteRedirection(ctx context.Context, id int) error {
	return fmt.Errorf("redirections not yet supported in Caddy mode")
}
func (a *caddyProxyAdapter) GetRedirection(ctx context.Context, id int) (*RedirectionHostView, error) {
	return nil, fmt.Errorf("redirections not yet supported in Caddy mode")
}

// ---- Streams (not implemented in Caddy Phase 1) ----

func (a *caddyProxyAdapter) ListStreams(ctx context.Context) ([]StreamView, error) {
	return []StreamView{}, nil
}
func (a *caddyProxyAdapter) CreateStream(ctx context.Context, s *StreamView) error {
	return fmt.Errorf("streams not yet supported in Caddy mode")
}
func (a *caddyProxyAdapter) UpdateStream(ctx context.Context, s *StreamView) error {
	return fmt.Errorf("streams not yet supported in Caddy mode")
}
func (a *caddyProxyAdapter) DeleteStream(ctx context.Context, id int) error {
	return fmt.Errorf("streams not yet supported in Caddy mode")
}
func (a *caddyProxyAdapter) GetStream(ctx context.Context, id int) (*StreamView, error) {
	return nil, fmt.Errorf("streams not yet supported in Caddy mode")
}

// ---- Dead Hosts (not applicable in Caddy) ----

func (a *caddyProxyAdapter) ListDeadHosts(ctx context.Context) ([]DeadHostView, error) {
	return []DeadHostView{}, nil
}
func (a *caddyProxyAdapter) CreateDeadHost(ctx context.Context, d *DeadHostView) error {
	return fmt.Errorf("dead hosts not applicable in Caddy mode")
}
func (a *caddyProxyAdapter) DeleteDeadHost(ctx context.Context, id int) error {
	return fmt.Errorf("dead hosts not applicable in Caddy mode")
}

// ---- Certificates ----

func (a *caddyProxyAdapter) ListCertificates(ctx context.Context) ([]CertificateView, error) {
	certs, err := a.svc.ListCertificates(ctx)
	if err != nil {
		return nil, err
	}

	views := make([]CertificateView, 0, len(certs))
	for i, c := range certs {
		expires := ""
		if c.ExpiresAt != nil {
			expires = c.ExpiresAt.Format("2006-01-02")
		}
		views = append(views, CertificateView{
			ID:          i + 1,
			NiceName:    c.Name,
			Provider:    c.Provider,
			DomainNames: c.Domains,
			ExpiresOn:   expires,
		})
	}
	return views, nil
}

func (a *caddyProxyAdapter) GetCertificate(ctx context.Context, id int) (*CertificateView, error) {
	certs, err := a.svc.ListCertificates(ctx)
	if err != nil {
		return nil, err
	}
	idx := id - 1
	if idx < 0 || idx >= len(certs) {
		return nil, fmt.Errorf("certificate not found")
	}
	c := certs[idx]
	expires := ""
	if c.ExpiresAt != nil {
		expires = c.ExpiresAt.Format("2006-01-02")
	}
	return &CertificateView{
		ID:          id,
		NiceName:    c.Name,
		Provider:    c.Provider,
		DomainNames: c.Domains,
		ExpiresOn:   expires,
	}, nil
}

func (a *caddyProxyAdapter) RequestLECertificate(ctx context.Context, domains []string, email string, agree bool, dnsChallenge bool, dnsProvider, dnsCredentials string, propagation int) error {
	// In Caddy mode, SSL is automatic. This is a no-op—just sync.
	return a.svc.SyncToCaddy(ctx)
}

func (a *caddyProxyAdapter) UploadCustomCertificate(ctx context.Context, niceName string, cert, key, intermediate []byte) error {
	_, err := a.svc.UploadCertificate(ctx, niceName, nil, string(cert), string(key), string(intermediate), nil)
	return err
}

func (a *caddyProxyAdapter) RenewCertificate(ctx context.Context, id int) error {
	// Caddy handles renewal automatically
	return nil
}

func (a *caddyProxyAdapter) DeleteCertificate(ctx context.Context, id int) error {
	certs, err := a.svc.ListCertificates(ctx)
	if err != nil {
		return err
	}
	idx := id - 1
	if idx < 0 || idx >= len(certs) {
		return fmt.Errorf("certificate not found")
	}
	return a.svc.DeleteCertificate(ctx, certs[idx].ID, nil)
}

// ---- Access Lists (not implemented in Caddy Phase 1) ----

func (a *caddyProxyAdapter) ListAccessLists(ctx context.Context) ([]AccessListView, error) {
	return []AccessListView{}, nil
}
func (a *caddyProxyAdapter) GetAccessList(ctx context.Context, id int) (*AccessListDetailView, error) {
	return nil, fmt.Errorf("access lists not yet supported in Caddy mode")
}
func (a *caddyProxyAdapter) CreateAccessList(ctx context.Context, al *AccessListDetailView) error {
	return fmt.Errorf("access lists not yet supported in Caddy mode")
}
func (a *caddyProxyAdapter) UpdateAccessList(ctx context.Context, al *AccessListDetailView) error {
	return fmt.Errorf("access lists not yet supported in Caddy mode")
}
func (a *caddyProxyAdapter) DeleteAccessList(ctx context.Context, id int) error {
	return fmt.Errorf("access lists not yet supported in Caddy mode")
}

// ---- Audit ----

func (a *caddyProxyAdapter) ListAuditLogs(ctx context.Context, limit, offset int) ([]AuditLogView, int, error) {
	entries, total, err := a.svc.ListAuditLogs(ctx, limit, offset)
	if err != nil {
		return nil, 0, err
	}

	views := make([]AuditLogView, 0, len(entries))
	for _, e := range entries {
		userID := ""
		if e.UserID != nil {
			userID = e.UserID.String()
		}
		views = append(views, AuditLogView{
			ID:           e.ID.String(),
			Operation:    e.Action,
			ResourceType: e.ResourceType,
			ResourceID:   hashUUIDToInt(e.ResourceID),
			ResourceName: e.ResourceName,
			UserName:     userID,
			CreatedAt:    e.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	return views, total, nil
}

// ---- Connection management (Caddy mode: simplified) ----

func (a *caddyProxyAdapter) GetConnection(ctx context.Context) (*models.NPMConnection, error) {
	healthy, _ := a.svc.CaddyHealthy(ctx)
	status := "unhealthy"
	if healthy {
		status = "healthy"
	}

	// Return a synthetic connection object for UI compatibility
	return &models.NPMConnection{
		ID:           "caddy",
		BaseURL:      "caddy:2019",
		IsEnabled:    true,
		HealthStatus: status,
	}, nil
}

func (a *caddyProxyAdapter) SetupConnection(ctx context.Context, baseURL, email, password, userID string) error {
	// In Caddy mode, no external connection setup needed
	return nil
}

func (a *caddyProxyAdapter) UpdateConnectionConfig(ctx context.Context, connID string, baseURL, email, password *string, enabled *bool, userID string) error {
	return nil
}

func (a *caddyProxyAdapter) DeleteConnection(ctx context.Context, connID string) error {
	return nil
}

func (a *caddyProxyAdapter) IsConnected(ctx context.Context) bool {
	healthy, _ := a.svc.CaddyHealthy(ctx)
	return healthy
}

// ---- UUID resolution ----

// resolveHostID maps a legacy int ID to a UUID.
// The int ID is the 1-based index in the ordered host list.
// This is a transitional approach until the web layer fully uses UUIDs.
func (a *caddyProxyAdapter) resolveHostID(ctx context.Context, id int) (uuid.UUID, error) {
	hosts, err := a.svc.ListHosts(ctx)
	if err != nil {
		return uuid.Nil, err
	}

	// Try parsing as UUID string first (if templates pass uuid as param)
	// The id parameter comes from chi URL params which are strings.
	// But since the interface uses int, we fall back to index-based.
	idx := id - 1
	if idx < 0 || idx >= len(hosts) {
		return uuid.Nil, fmt.Errorf("proxy host not found: index %d", id)
	}
	return hosts[idx].ID, nil
}

// proxyHostToView converts a ProxyHost model to the legacy ProxyHostView.
func proxyHostToView(h *models.ProxyHost) ProxyHostView {
	domain := ""
	if len(h.Domains) > 0 {
		domain = h.Domains[0]
	}

	return ProxyHostView{
		ID:          hashUUIDToInt(h.ID), // Stable int ID from UUID
		Domain:      domain,
		ForwardHost: h.UpstreamHost,
		ForwardPort: h.UpstreamPort,
		SSLEnabled:  h.SSLMode != models.ProxySSLModeNone,
		Enabled:     h.Enabled,
		ContainerID: h.ContainerID,
		Container:   h.ContainerName,
	}
}

// hashUUIDToInt generates a deterministic positive int from a UUID.
// Used for backwards compatibility with templates that expect int IDs.
func hashUUIDToInt(id uuid.UUID) int {
	// Use first 4 bytes as uint32, ensure positive
	b := id[:]
	n := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if n < 0 {
		n = -n
	}
	if n == 0 {
		n = 1
	}
	return n
}
