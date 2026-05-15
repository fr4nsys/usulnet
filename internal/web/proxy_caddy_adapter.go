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
		Name:           &v.Domain,
		Domains:        []string{v.Domain},
		UpstreamScheme: &scheme,
		UpstreamHost:   &v.ForwardHost,
		UpstreamPort:   &v.ForwardPort,
		SSLMode:        &sslMode,
		SSLForceHTTPS:  &v.SSLEnabled,
		Enabled:        &v.Enabled,
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
	return a.svc.Sync(ctx)
}

// ---- Redirections (v26.5.1 — local state, backend-applied on sync) ----

func (a *caddyProxyAdapter) ListRedirections(ctx context.Context) ([]RedirectionHostView, error) {
	rds, err := a.svc.ListRedirections(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]RedirectionHostView, 0, len(rds))
	for _, rd := range rds {
		views = append(views, redirectionToView(rd))
	}
	return views, nil
}

func (a *caddyProxyAdapter) GetRedirection(ctx context.Context, id int) (*RedirectionHostView, error) {
	uid, err := a.resolveRedirectionID(ctx, id)
	if err != nil {
		return nil, err
	}
	rd, err := a.svc.GetRedirection(ctx, uid)
	if err != nil {
		return nil, err
	}
	v := redirectionToView(rd)
	return &v, nil
}

func (a *caddyProxyAdapter) CreateRedirection(ctx context.Context, r *RedirectionHostView) error {
	rd := viewToRedirection(r)
	if err := a.svc.CreateRedirection(ctx, rd, nil); err != nil {
		return err
	}
	r.ID = hashUUIDToInt(rd.ID)
	return nil
}

func (a *caddyProxyAdapter) UpdateRedirection(ctx context.Context, r *RedirectionHostView) error {
	uid, err := a.resolveRedirectionID(ctx, r.ID)
	if err != nil {
		return err
	}
	rd := viewToRedirection(r)
	rd.ID = uid
	return a.svc.UpdateRedirection(ctx, rd, nil)
}

func (a *caddyProxyAdapter) DeleteRedirection(ctx context.Context, id int) error {
	uid, err := a.resolveRedirectionID(ctx, id)
	if err != nil {
		return err
	}
	return a.svc.DeleteRedirection(ctx, uid, nil)
}

// ---- Streams (Caddy: ErrFeatureNotSupported on apply) ----

func (a *caddyProxyAdapter) ListStreams(ctx context.Context) ([]StreamView, error) {
	streams, err := a.svc.ListStreams(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]StreamView, 0, len(streams))
	for _, s := range streams {
		views = append(views, streamToView(s))
	}
	return views, nil
}

func (a *caddyProxyAdapter) GetStream(ctx context.Context, id int) (*StreamView, error) {
	uid, err := a.resolveStreamID(ctx, id)
	if err != nil {
		return nil, err
	}
	s, err := a.svc.GetStream(ctx, uid)
	if err != nil {
		return nil, err
	}
	v := streamToView(s)
	return &v, nil
}

func (a *caddyProxyAdapter) CreateStream(ctx context.Context, s *StreamView) error {
	st := viewToStream(s)
	if err := a.svc.CreateStream(ctx, st, nil); err != nil {
		return err
	}
	s.ID = hashUUIDToInt(st.ID)
	return nil
}

func (a *caddyProxyAdapter) UpdateStream(ctx context.Context, s *StreamView) error {
	uid, err := a.resolveStreamID(ctx, s.ID)
	if err != nil {
		return err
	}
	st := viewToStream(s)
	st.ID = uid
	return a.svc.UpdateStream(ctx, st, nil)
}

func (a *caddyProxyAdapter) DeleteStream(ctx context.Context, id int) error {
	uid, err := a.resolveStreamID(ctx, id)
	if err != nil {
		return err
	}
	return a.svc.DeleteStream(ctx, uid, nil)
}

// ---- Dead Hosts (v26.5.1 — local state) ----

func (a *caddyProxyAdapter) ListDeadHosts(ctx context.Context) ([]DeadHostView, error) {
	dead, err := a.svc.ListDeadHosts(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]DeadHostView, 0, len(dead))
	for _, d := range dead {
		views = append(views, deadHostToView(d))
	}
	return views, nil
}

func (a *caddyProxyAdapter) CreateDeadHost(ctx context.Context, d *DeadHostView) error {
	dh := viewToDeadHost(d)
	if err := a.svc.CreateDeadHost(ctx, dh, nil); err != nil {
		return err
	}
	d.ID = hashUUIDToInt(dh.ID)
	return nil
}

func (a *caddyProxyAdapter) DeleteDeadHost(ctx context.Context, id int) error {
	uid, err := a.resolveDeadHostID(ctx, id)
	if err != nil {
		return err
	}
	return a.svc.DeleteDeadHost(ctx, uid, nil)
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
	// Request certificate via the active backend.
	// For Caddy, this triggers a sync (Caddy handles ACME automatically).
	// For nginx, this runs the ACME flow and writes cert files.
	certPEM, keyPEM, err := a.svc.RequestLECertificate(ctx, domains, email)
	if err != nil {
		return err
	}
	// If the backend returned a certificate, store it in the database
	if certPEM != "" && keyPEM != "" {
		_, err = a.svc.UploadCertificate(ctx, domains[0], domains, certPEM, keyPEM, "", nil)
		if err != nil {
			return fmt.Errorf("store LE certificate: %w", err)
		}
	}
	// Sync to apply the new certificate
	return a.svc.Sync(ctx)
}

func (a *caddyProxyAdapter) UploadCustomCertificate(ctx context.Context, niceName string, cert, key, intermediate []byte) error {
	_, err := a.svc.UploadCertificate(ctx, niceName, nil, string(cert), string(key), string(intermediate), nil)
	return err
}

func (a *caddyProxyAdapter) RenewCertificate(ctx context.Context, id int) error {
	// For Caddy, auto-renewal is handled automatically.
	// For nginx, we re-request the certificate.
	certs, err := a.svc.ListCertificates(ctx)
	if err != nil {
		return err
	}
	idx := id - 1
	if idx < 0 || idx >= len(certs) {
		return fmt.Errorf("certificate not found")
	}
	cert := certs[idx]
	if cert.Provider == "custom" {
		return fmt.Errorf("cannot auto-renew custom certificates")
	}
	_, _, err = a.svc.RenewLECertificate(ctx, cert.Domains, "")
	return err
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

// ---- Access Lists (v26.5.1 — local state, backend-applied on sync) ----

func (a *caddyProxyAdapter) ListAccessLists(ctx context.Context) ([]AccessListView, error) {
	lists, err := a.svc.ListAccessLists(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]AccessListView, 0, len(lists))
	for _, al := range lists {
		views = append(views, AccessListView{
			ID:          hashUUIDToInt(al.ID),
			Name:        al.Name,
			SatisfyAny:  al.SatisfyAny,
			PassAuth:    al.PassAuth,
			ItemCount:   len(al.Items),
			ClientCount: len(al.Clients),
		})
	}
	return views, nil
}

func (a *caddyProxyAdapter) GetAccessList(ctx context.Context, id int) (*AccessListDetailView, error) {
	uid, err := a.resolveAccessListID(ctx, id)
	if err != nil {
		return nil, err
	}
	al, err := a.svc.GetAccessList(ctx, uid)
	if err != nil {
		return nil, err
	}
	return accessListToDetailView(al), nil
}

func (a *caddyProxyAdapter) CreateAccessList(ctx context.Context, av *AccessListDetailView) error {
	al := viewToAccessList(av)
	if err := a.svc.CreateAccessList(ctx, al, nil); err != nil {
		return err
	}
	av.ID = hashUUIDToInt(al.ID)
	return nil
}

func (a *caddyProxyAdapter) UpdateAccessList(ctx context.Context, av *AccessListDetailView) error {
	uid, err := a.resolveAccessListID(ctx, av.ID)
	if err != nil {
		return err
	}
	al := viewToAccessList(av)
	al.ID = uid
	return a.svc.UpdateAccessList(ctx, al, nil)
}

func (a *caddyProxyAdapter) DeleteAccessList(ctx context.Context, id int) error {
	uid, err := a.resolveAccessListID(ctx, id)
	if err != nil {
		return err
	}
	return a.svc.DeleteAccessList(ctx, uid, nil)
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
	healthy, _ := a.svc.BackendHealthy(ctx)
	status := "unhealthy"
	if healthy {
		status = "healthy"
	}

	mode := a.svc.BackendMode()
	// Return a synthetic connection object for UI compatibility
	return &models.NPMConnection{
		ID:           mode,
		BaseURL:      mode,
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
	healthy, _ := a.svc.BackendHealthy(ctx)
	return healthy
}

func (a *caddyProxyAdapter) Mode() string {
	return a.svc.BackendMode()
}

func (a *caddyProxyAdapter) BackendSupport() ProxyBackendSupport {
	m := a.svc.SupportMatrix()
	return ProxyBackendSupport{
		Mode:         a.svc.BackendMode(),
		AccessLists:  m.AccessLists,
		DeadHosts:    m.DeadHosts,
		Locations:    m.Locations,
		Redirections: m.Redirections,
		Streams:      m.Streams,
	}
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

// ============================================================================
// v26.5.1 extended-feature ID resolvers + view <-> model converters.
//
// Until the web layer carries UUIDs end-to-end, we identify rows via
// hashUUIDToInt(uuid) and resolve back by scanning the current list.
// ============================================================================

func (a *caddyProxyAdapter) resolveRedirectionID(ctx context.Context, hashID int) (uuid.UUID, error) {
	rds, err := a.svc.ListRedirections(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	for _, rd := range rds {
		if hashUUIDToInt(rd.ID) == hashID {
			return rd.ID, nil
		}
	}
	return uuid.Nil, fmt.Errorf("redirection not found: id %d", hashID)
}

func (a *caddyProxyAdapter) resolveStreamID(ctx context.Context, hashID int) (uuid.UUID, error) {
	streams, err := a.svc.ListStreams(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	for _, s := range streams {
		if hashUUIDToInt(s.ID) == hashID {
			return s.ID, nil
		}
	}
	return uuid.Nil, fmt.Errorf("stream not found: id %d", hashID)
}

func (a *caddyProxyAdapter) resolveDeadHostID(ctx context.Context, hashID int) (uuid.UUID, error) {
	dead, err := a.svc.ListDeadHosts(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	for _, d := range dead {
		if hashUUIDToInt(d.ID) == hashID {
			return d.ID, nil
		}
	}
	return uuid.Nil, fmt.Errorf("dead host not found: id %d", hashID)
}

func (a *caddyProxyAdapter) resolveAccessListID(ctx context.Context, hashID int) (uuid.UUID, error) {
	lists, err := a.svc.ListAccessLists(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	for _, al := range lists {
		if hashUUIDToInt(al.ID) == hashID {
			return al.ID, nil
		}
	}
	return uuid.Nil, fmt.Errorf("access list not found: id %d", hashID)
}

func redirectionToView(rd *models.ProxyRedirection) RedirectionHostView {
	domain := ""
	if len(rd.Domains) > 0 {
		domain = rd.Domains[0]
	}
	certID := 0
	if rd.CertificateID != nil {
		certID = hashUUIDToInt(*rd.CertificateID)
	}
	return RedirectionHostView{
		ID:              hashUUIDToInt(rd.ID),
		DomainNames:     rd.Domains,
		Domain:          domain,
		ForwardScheme:   rd.ForwardScheme,
		ForwardDomain:   rd.ForwardDomain,
		ForwardHTTPCode: rd.ForwardHTTPCode,
		PreservePath:    rd.PreservePath,
		SSLForced:       rd.SSLForceHTTPS,
		CertificateID:   certID,
		Enabled:         rd.Enabled,
	}
}

func viewToRedirection(v *RedirectionHostView) *models.ProxyRedirection {
	domains := v.DomainNames
	if len(domains) == 0 && v.Domain != "" {
		domains = []string{v.Domain}
	}
	scheme := v.ForwardScheme
	if scheme == "" {
		scheme = "https"
	}
	code := v.ForwardHTTPCode
	if code == 0 {
		code = 301
	}
	return &models.ProxyRedirection{
		Domains:         domains,
		ForwardScheme:   scheme,
		ForwardDomain:   v.ForwardDomain,
		ForwardHTTPCode: code,
		PreservePath:    v.PreservePath,
		SSLMode:         models.ProxySSLModeNone,
		SSLForceHTTPS:   v.SSLForced,
		Enabled:         v.Enabled,
	}
}

func streamToView(s *models.ProxyStream) StreamView {
	return StreamView{
		ID:             hashUUIDToInt(s.ID),
		IncomingPort:   s.IncomingPort,
		ForwardingHost: s.ForwardingHost,
		ForwardingPort: s.ForwardingPort,
		TCPForwarding:  s.TCPForwarding,
		UDPForwarding:  s.UDPForwarding,
		Enabled:        s.Enabled,
	}
}

func viewToStream(v *StreamView) *models.ProxyStream {
	return &models.ProxyStream{
		IncomingPort:   v.IncomingPort,
		ForwardingHost: v.ForwardingHost,
		ForwardingPort: v.ForwardingPort,
		TCPForwarding:  v.TCPForwarding,
		UDPForwarding:  v.UDPForwarding,
		Enabled:        v.Enabled,
	}
}

func deadHostToView(d *models.ProxyDeadHost) DeadHostView {
	domain := ""
	if len(d.Domains) > 0 {
		domain = d.Domains[0]
	}
	certID := 0
	if d.CertificateID != nil {
		certID = hashUUIDToInt(*d.CertificateID)
	}
	return DeadHostView{
		ID:          hashUUIDToInt(d.ID),
		DomainNames: d.Domains,
		Domain:      domain,
		SSLForced:   d.SSLForceHTTPS,
		CertID:      certID,
		Enabled:     d.Enabled,
	}
}

func viewToDeadHost(v *DeadHostView) *models.ProxyDeadHost {
	domains := v.DomainNames
	if len(domains) == 0 && v.Domain != "" {
		domains = []string{v.Domain}
	}
	return &models.ProxyDeadHost{
		Domains:       domains,
		SSLMode:       models.ProxySSLModeNone,
		SSLForceHTTPS: v.SSLForced,
		Enabled:       v.Enabled,
	}
}

func accessListToDetailView(al *models.ProxyAccessList) *AccessListDetailView {
	items := make([]AccessListItemView, 0, len(al.Items))
	for _, item := range al.Items {
		items = append(items, AccessListItemView{Username: item.Username})
	}
	clients := make([]AccessListClientView, 0, len(al.Clients))
	for _, c := range al.Clients {
		clients = append(clients, AccessListClientView{Address: c.Address, Directive: c.Directive})
	}
	return &AccessListDetailView{
		ID:         hashUUIDToInt(al.ID),
		Name:       al.Name,
		SatisfyAny: al.SatisfyAny,
		PassAuth:   al.PassAuth,
		Items:      items,
		Clients:    clients,
	}
}

func viewToAccessList(v *AccessListDetailView) *models.ProxyAccessList {
	items := make([]models.ProxyAccessListAuth, 0, len(v.Items))
	for _, it := range v.Items {
		items = append(items, models.ProxyAccessListAuth{
			Username:     it.Username,
			PasswordHash: it.Password, // hashed by the backend at sync time
		})
	}
	clients := make([]models.ProxyAccessListClient, 0, len(v.Clients))
	for _, c := range v.Clients {
		directive := c.Directive
		if directive == "" {
			directive = models.AccessDirectiveAllow
		}
		clients = append(clients, models.ProxyAccessListClient{
			Address:   c.Address,
			Directive: directive,
		})
	}
	return &models.ProxyAccessList{
		Name:       v.Name,
		SatisfyAny: v.SatisfyAny,
		PassAuth:   v.PassAuth,
		Enabled:    true,
		Items:      items,
		Clients:    clients,
	}
}
