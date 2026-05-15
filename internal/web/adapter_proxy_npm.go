// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/integrations/npm"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
)

type proxyAdapter struct {
	npmSvc *npm.Service
	hostID uuid.UUID
}

// hasSSLCertificate checks if a CertificateID interface{} value represents a valid certificate.
// NPM returns CertificateID as int, string "new", or null from JSON.
func hasSSLCertificate(v interface{}) bool {
	if v == nil {
		return false
	}
	switch val := v.(type) {
	case float64:
		return val > 0
	case int:
		return val > 0
	case string:
		return val != "" && val != "0"
	default:
		return false
	}
}

func (a *proxyAdapter) ListHosts(ctx context.Context) ([]ProxyHostView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}

	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}

	hosts, err := client.ListProxyHosts(ctx)
	if err != nil {
		return nil, err
	}

	views := make([]ProxyHostView, 0, len(hosts))
	for _, h := range hosts {
		views = append(views, npmHostToView(h))
	}
	return views, nil
}

// npmHostToView converts an NPM ProxyHost to a ProxyHostView with all fields.
func npmHostToView(h *npm.ProxyHost) ProxyHostView {
	domain := ""
	if len(h.DomainNames) > 0 {
		domain = h.DomainNames[0]
	}
	certID := 0
	if v, ok := h.CertificateID.(float64); ok {
		certID = int(v)
	}
	return ProxyHostView{
		ID:                    h.ID,
		DomainNames:           h.DomainNames,
		Domain:                domain,
		ForwardScheme:         h.ForwardScheme,
		ForwardHost:           h.ForwardHost,
		ForwardPort:           h.ForwardPort,
		CertificateID:         certID,
		SSLEnabled:            hasSSLCertificate(h.CertificateID),
		SSLForced:             h.SSLForced,
		HSTSEnabled:           h.HSTSEnabled,
		HSTSSubdomains:        h.HSTSSubdomains,
		HTTP2Support:          h.HTTP2Support,
		BlockExploits:         h.BlockExploits,
		CachingEnabled:        h.CachingEnabled,
		AllowWebsocketUpgrade: h.AllowWebsocketUpgrade,
		AccessListID:          h.AccessListID,
		AdvancedConfig:        h.AdvancedConfig,
		Enabled:               h.Enabled,
		CreatedOn:             h.CreatedOn,
		ModifiedOn:            h.ModifiedOn,
	}
}

func (a *proxyAdapter) GetHost(ctx context.Context, id int) (*ProxyHostView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}

	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}

	h, err := client.GetProxyHost(ctx, id)
	if err != nil {
		return nil, err
	}

	view := npmHostToView(h)
	return &view, nil
}

func (a *proxyAdapter) CreateHost(ctx context.Context, h *ProxyHostView) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}

	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}

	domainNames := h.DomainNames
	if len(domainNames) == 0 && h.Domain != "" {
		domainNames = []string{h.Domain}
	}

	forwardScheme := h.ForwardScheme
	if forwardScheme == "" {
		forwardScheme = "http"
	}

	host := &npm.ProxyHost{
		DomainNames:           domainNames,
		ForwardScheme:         forwardScheme,
		ForwardHost:           h.ForwardHost,
		ForwardPort:           h.ForwardPort,
		SSLForced:             h.SSLForced,
		HSTSEnabled:           h.HSTSEnabled,
		HSTSSubdomains:        h.HSTSSubdomains,
		HTTP2Support:          h.HTTP2Support,
		BlockExploits:         h.BlockExploits,
		CachingEnabled:        h.CachingEnabled,
		AllowWebsocketUpgrade: h.AllowWebsocketUpgrade,
		AccessListID:          h.AccessListID,
		AdvancedConfig:        h.AdvancedConfig,
		Enabled:               true,
	}

	if h.CertificateID > 0 {
		host.CertificateID = h.CertificateID
	}

	created, err := client.CreateProxyHost(ctx, host)
	if err != nil {
		return err
	}
	h.ID = created.ID
	return nil
}

func (a *proxyAdapter) UpdateHost(ctx context.Context, h *ProxyHostView) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}

	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}

	domainNames := h.DomainNames
	if len(domainNames) == 0 && h.Domain != "" {
		domainNames = []string{h.Domain}
	}

	forwardScheme := h.ForwardScheme
	if forwardScheme == "" {
		forwardScheme = "http"
	}

	host := &npm.ProxyHost{
		DomainNames:           domainNames,
		ForwardScheme:         forwardScheme,
		ForwardHost:           h.ForwardHost,
		ForwardPort:           h.ForwardPort,
		SSLForced:             h.SSLForced,
		HSTSEnabled:           h.HSTSEnabled,
		HSTSSubdomains:        h.HSTSSubdomains,
		HTTP2Support:          h.HTTP2Support,
		BlockExploits:         h.BlockExploits,
		CachingEnabled:        h.CachingEnabled,
		AllowWebsocketUpgrade: h.AllowWebsocketUpgrade,
		AccessListID:          h.AccessListID,
		AdvancedConfig:        h.AdvancedConfig,
		Enabled:               h.Enabled,
	}

	if h.CertificateID > 0 {
		host.CertificateID = h.CertificateID
	}

	_, err = client.UpdateProxyHost(ctx, h.ID, host)
	return err
}

func (a *proxyAdapter) RemoveHost(ctx context.Context, id int) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}

	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}

	return client.DeleteProxyHost(ctx, id)
}

func (a *proxyAdapter) EnableHost(ctx context.Context, id int) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}

	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}

	return client.EnableProxyHost(ctx, id)
}

func (a *proxyAdapter) DisableHost(ctx context.Context, id int) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}

	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}

	return client.DisableProxyHost(ctx, id)
}

func (a *proxyAdapter) Sync(ctx context.Context) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	return a.npmSvc.TestConnection(ctx, resolveHostID(ctx, a.hostID).String())
}

// --- NPM Connection Management ---

func (a *proxyAdapter) GetConnection(ctx context.Context) (*models.NPMConnection, error) {
	if a.npmSvc == nil {
		return nil, nil // Not configured, return nil
	}
	conn, err := a.npmSvc.GetConnection(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		// "NPM not configured for this host" is the expected miss path;
		// every other error is propagated so the caller can react to
		// real database or network problems instead of seeing nil.
		if appErr, ok := errors.GetAppError(err); ok && appErr.Code == errors.CodeNPMNotConfigured {
			return nil, nil
		}
		return nil, err
	}
	return conn, nil
}

func (a *proxyAdapter) SetupConnection(ctx context.Context, baseURL, email, password, userID string) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not enabled")
	}
	_, err := a.npmSvc.ConfigureConnection(ctx, resolveHostID(ctx, a.hostID).String(), &npm.ConnectionCreate{
		HostID:        resolveHostID(ctx, a.hostID).String(),
		BaseURL:       baseURL,
		AdminEmail:    email,
		AdminPassword: password,
	}, userID)
	return err
}

func (a *proxyAdapter) UpdateConnectionConfig(ctx context.Context, connID string, baseURL, email, password *string, enabled *bool, userID string) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not enabled")
	}
	_, err := a.npmSvc.UpdateConnection(ctx, connID, &npm.ConnectionUpdate{
		BaseURL:       baseURL,
		AdminEmail:    email,
		AdminPassword: password,
		IsEnabled:     enabled,
	}, userID)
	return err
}

func (a *proxyAdapter) DeleteConnection(ctx context.Context, connID string) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not enabled")
	}
	return a.npmSvc.DeleteConnection(ctx, connID)
}

func (a *proxyAdapter) IsConnected(ctx context.Context) bool {
	if a.npmSvc == nil {
		return false
	}
	conn, err := a.npmSvc.GetConnection(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil || conn == nil {
		return false
	}
	return conn.IsEnabled && conn.HealthStatus == "healthy"
}

func (a *proxyAdapter) Mode() string {
	return "npm"
}

// BackendSupport reports NPM's extended-feature support. NPM applies
// all of v26.2.7's extended features natively, so the matrix is full.
func (a *proxyAdapter) BackendSupport() ProxyBackendSupport {
	return ProxyBackendSupport{
		Mode:         "npm",
		AccessLists:  true,
		DeadHosts:    true,
		Locations:    true,
		Redirections: true,
		Streams:      true,
	}
}

// --- Redirections ---

func (a *proxyAdapter) ListRedirections(ctx context.Context) ([]RedirectionHostView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}
	redirs, err := client.ListRedirectionHosts(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]RedirectionHostView, 0, len(redirs))
	for _, r := range redirs {
		domain := ""
		if len(r.DomainNames) > 0 {
			domain = r.DomainNames[0]
		}
		certID := 0
		if v, ok := r.CertificateID.(float64); ok {
			certID = int(v)
		}
		views = append(views, RedirectionHostView{
			ID:              r.ID,
			DomainNames:     r.DomainNames,
			Domain:          domain,
			ForwardScheme:   r.ForwardScheme,
			ForwardDomain:   r.ForwardDomainName,
			ForwardHTTPCode: r.ForwardHTTPCode,
			Enabled:         r.Enabled,
			PreservePath:    r.PreservePath,
			SSLForced:       r.SSLForced,
			CertificateID:   certID,
		})
	}
	return views, nil
}

func (a *proxyAdapter) GetRedirection(ctx context.Context, id int) (*RedirectionHostView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}
	r, err := client.GetRedirectionHost(ctx, id)
	if err != nil {
		return nil, err
	}
	domain := ""
	if len(r.DomainNames) > 0 {
		domain = r.DomainNames[0]
	}
	certID := 0
	if v, ok := r.CertificateID.(float64); ok {
		certID = int(v)
	}
	return &RedirectionHostView{
		ID:              r.ID,
		DomainNames:     r.DomainNames,
		Domain:          domain,
		ForwardScheme:   r.ForwardScheme,
		ForwardDomain:   r.ForwardDomainName,
		ForwardHTTPCode: r.ForwardHTTPCode,
		Enabled:         r.Enabled,
		PreservePath:    r.PreservePath,
		SSLForced:       r.SSLForced,
		CertificateID:   certID,
	}, nil
}

func (a *proxyAdapter) CreateRedirection(ctx context.Context, rv *RedirectionHostView) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	domainNames := rv.DomainNames
	if len(domainNames) == 0 && rv.Domain != "" {
		domainNames = []string{rv.Domain}
	}
	r := &npm.RedirectionHost{
		DomainNames:       domainNames,
		ForwardScheme:     rv.ForwardScheme,
		ForwardDomainName: rv.ForwardDomain,
		ForwardHTTPCode:   rv.ForwardHTTPCode,
		PreservePath:      rv.PreservePath,
		SSLForced:         rv.SSLForced,
		CertificateID:     rv.CertificateID,
		Enabled:           true,
	}
	created, err := client.CreateRedirectionHost(ctx, r)
	if err != nil {
		return err
	}
	rv.ID = created.ID
	return nil
}

func (a *proxyAdapter) UpdateRedirection(ctx context.Context, rv *RedirectionHostView) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	domainNames := rv.DomainNames
	if len(domainNames) == 0 && rv.Domain != "" {
		domainNames = []string{rv.Domain}
	}
	r := &npm.RedirectionHost{
		DomainNames:       domainNames,
		ForwardScheme:     rv.ForwardScheme,
		ForwardDomainName: rv.ForwardDomain,
		ForwardHTTPCode:   rv.ForwardHTTPCode,
		PreservePath:      rv.PreservePath,
		SSLForced:         rv.SSLForced,
		CertificateID:     rv.CertificateID,
		Enabled:           rv.Enabled,
	}
	_, err = client.UpdateRedirectionHost(ctx, rv.ID, r)
	return err
}

func (a *proxyAdapter) DeleteRedirection(ctx context.Context, id int) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	return client.DeleteRedirectionHost(ctx, id)
}

// --- Streams ---

func (a *proxyAdapter) ListStreams(ctx context.Context) ([]StreamView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}
	streams, err := client.ListStreams(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]StreamView, 0, len(streams))
	for _, s := range streams {
		views = append(views, StreamView{
			ID:             s.ID,
			IncomingPort:   s.IncomingPort,
			ForwardingHost: s.ForwardingHost,
			ForwardingPort: s.ForwardingPort,
			TCPForwarding:  s.TCPForwarding,
			UDPForwarding:  s.UDPForwarding,
			Enabled:        s.Enabled,
		})
	}
	return views, nil
}

func (a *proxyAdapter) GetStream(ctx context.Context, id int) (*StreamView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}
	s, err := client.GetStream(ctx, id)
	if err != nil {
		return nil, err
	}
	return &StreamView{
		ID:             s.ID,
		IncomingPort:   s.IncomingPort,
		ForwardingHost: s.ForwardingHost,
		ForwardingPort: s.ForwardingPort,
		TCPForwarding:  s.TCPForwarding,
		UDPForwarding:  s.UDPForwarding,
		Enabled:        s.Enabled,
	}, nil
}

func (a *proxyAdapter) CreateStream(ctx context.Context, sv *StreamView) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	s := &npm.Stream{
		IncomingPort:   sv.IncomingPort,
		ForwardingHost: sv.ForwardingHost,
		ForwardingPort: sv.ForwardingPort,
		TCPForwarding:  sv.TCPForwarding,
		UDPForwarding:  sv.UDPForwarding,
		Enabled:        true,
	}
	created, err := client.CreateStream(ctx, s)
	if err != nil {
		return err
	}
	sv.ID = created.ID
	return nil
}

func (a *proxyAdapter) UpdateStream(ctx context.Context, sv *StreamView) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	s := &npm.Stream{
		IncomingPort:   sv.IncomingPort,
		ForwardingHost: sv.ForwardingHost,
		ForwardingPort: sv.ForwardingPort,
		TCPForwarding:  sv.TCPForwarding,
		UDPForwarding:  sv.UDPForwarding,
		Enabled:        sv.Enabled,
	}
	_, err = client.UpdateStream(ctx, sv.ID, s)
	return err
}

func (a *proxyAdapter) DeleteStream(ctx context.Context, id int) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	return client.DeleteStream(ctx, id)
}

// --- Dead Hosts ---

func (a *proxyAdapter) ListDeadHosts(ctx context.Context) ([]DeadHostView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}
	dead, err := client.ListDeadHosts(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]DeadHostView, 0, len(dead))
	for _, d := range dead {
		domain := ""
		if len(d.DomainNames) > 0 {
			domain = d.DomainNames[0]
		}
		certID := 0
		if v, ok := d.CertificateID.(float64); ok {
			certID = int(v)
		}
		views = append(views, DeadHostView{
			ID:          d.ID,
			DomainNames: d.DomainNames,
			Domain:      domain,
			SSLForced:   d.SSLForced,
			CertID:      certID,
			Enabled:     d.Enabled,
		})
	}
	return views, nil
}

func (a *proxyAdapter) CreateDeadHost(ctx context.Context, dv *DeadHostView) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	domainNames := dv.DomainNames
	if len(domainNames) == 0 && dv.Domain != "" {
		domainNames = []string{dv.Domain}
	}
	d := &npm.DeadHost{
		DomainNames: domainNames,
		SSLForced:   dv.SSLForced,
		Enabled:     true,
	}
	if dv.CertID > 0 {
		d.CertificateID = dv.CertID
	}
	created, err := client.CreateDeadHost(ctx, d)
	if err != nil {
		return err
	}
	dv.ID = created.ID
	return nil
}

func (a *proxyAdapter) DeleteDeadHost(ctx context.Context, id int) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	return client.DeleteDeadHost(ctx, id)
}

// --- Certificates ---

func (a *proxyAdapter) ListCertificates(ctx context.Context) ([]CertificateView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}
	certs, err := client.ListCertificates(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]CertificateView, 0, len(certs))
	for _, c := range certs {
		views = append(views, CertificateView{
			ID:        c.ID,
			NiceName:  c.NiceName,
			Provider:  c.Provider,
			ExpiresOn: c.ExpiresOn,
		})
	}
	return views, nil
}

func (a *proxyAdapter) GetCertificate(ctx context.Context, id int) (*CertificateView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}
	c, err := client.GetCertificate(ctx, id)
	if err != nil {
		return nil, err
	}
	return &CertificateView{
		ID:          c.ID,
		NiceName:    c.NiceName,
		Provider:    c.Provider,
		ExpiresOn:   c.ExpiresOn,
		DomainNames: c.DomainNames,
	}, nil
}

func (a *proxyAdapter) RequestLECertificate(ctx context.Context, domains []string, email string, agree bool, dnsChallenge bool, dnsProvider, dnsCredentials string, propagation int) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}

	req := &npm.CertificateRequest{
		DomainNames:        domains,
		LetsencryptEmail:   email,
		LetsencryptAgree:   agree,
		DNSChallenge:       dnsChallenge,
		DNSProvider:        dnsProvider,
		PropagationSeconds: propagation,
	}
	if dnsCredentials != "" {
		req.DNSProviderCredentials = dnsCredentials
	}

	_, err = client.RequestLetsEncryptCertificate(ctx, req)
	return err
}

func (a *proxyAdapter) UploadCustomCertificate(ctx context.Context, niceName string, cert, key, intermediate []byte) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	_, err = client.UploadCustomCertificate(ctx, niceName, cert, key, intermediate)
	return err
}

func (a *proxyAdapter) RenewCertificate(ctx context.Context, id int) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	_, err = client.RenewCertificate(ctx, id)
	return err
}

func (a *proxyAdapter) DeleteCertificate(ctx context.Context, id int) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	return client.DeleteCertificate(ctx, id)
}

// --- Access Lists ---

func (a *proxyAdapter) ListAccessLists(ctx context.Context) ([]AccessListView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}
	lists, err := client.ListAccessLists(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]AccessListView, 0, len(lists))
	for _, l := range lists {
		views = append(views, AccessListView{
			ID:          l.ID,
			Name:        l.Name,
			PassAuth:    l.PassAuth,
			SatisfyAny:  l.SatisfyAny,
			ClientCount: toInt(l.Meta["clients"]),
			ItemCount:   toInt(l.Meta["items"]),
		})
	}
	return views, nil
}

func (a *proxyAdapter) GetAccessList(ctx context.Context, id int) (*AccessListDetailView, error) {
	if a.npmSvc == nil {
		return nil, fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return nil, err
	}
	l, err := client.GetAccessList(ctx, id)
	if err != nil {
		return nil, err
	}
	items := make([]AccessListItemView, 0, len(l.Items))
	for _, i := range l.Items {
		items = append(items, AccessListItemView{
			Username: i.Username,
			Password: i.Password,
		})
	}
	clients := make([]AccessListClientView, 0, len(l.Clients))
	for _, c := range l.Clients {
		clients = append(clients, AccessListClientView{
			Address:   c.Address,
			Directive: c.Directive,
		})
	}
	return &AccessListDetailView{
		ID:         l.ID,
		Name:       l.Name,
		PassAuth:   l.PassAuth,
		SatisfyAny: l.SatisfyAny,
		Items:      items,
		Clients:    clients,
	}, nil
}

func (a *proxyAdapter) CreateAccessList(ctx context.Context, av *AccessListDetailView) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	items := make([]npm.AccessListItem, 0, len(av.Items))
	for _, i := range av.Items {
		items = append(items, npm.AccessListItem{Username: i.Username, Password: i.Password})
	}
	clients := make([]npm.AccessListClient, 0, len(av.Clients))
	for _, c := range av.Clients {
		clients = append(clients, npm.AccessListClient{Address: c.Address, Directive: c.Directive})
	}
	l := &npm.AccessList{
		Name:       av.Name,
		PassAuth:   av.PassAuth,
		SatisfyAny: av.SatisfyAny,
		Items:      items,
		Clients:    clients,
	}
	created, err := client.CreateAccessList(ctx, l)
	if err != nil {
		return err
	}
	av.ID = created.ID
	return nil
}

func (a *proxyAdapter) UpdateAccessList(ctx context.Context, av *AccessListDetailView) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	items := make([]npm.AccessListItem, 0, len(av.Items))
	for _, i := range av.Items {
		items = append(items, npm.AccessListItem{Username: i.Username, Password: i.Password})
	}
	clients := make([]npm.AccessListClient, 0, len(av.Clients))
	for _, c := range av.Clients {
		clients = append(clients, npm.AccessListClient{Address: c.Address, Directive: c.Directive})
	}
	l := &npm.AccessList{
		Name:       av.Name,
		PassAuth:   av.PassAuth,
		SatisfyAny: av.SatisfyAny,
		Items:      items,
		Clients:    clients,
	}
	_, err = client.UpdateAccessList(ctx, av.ID, l)
	return err
}

func (a *proxyAdapter) DeleteAccessList(ctx context.Context, id int) error {
	if a.npmSvc == nil {
		return fmt.Errorf("NPM integration not configured")
	}
	client, err := a.npmSvc.GetClient(ctx, resolveHostID(ctx, a.hostID).String())
	if err != nil {
		return err
	}
	return client.DeleteAccessList(ctx, id)
}

// --- Audit Logs ---

func (a *proxyAdapter) ListAuditLogs(ctx context.Context, limit, offset int) ([]AuditLogView, int, error) {
	if a.npmSvc == nil {
		return nil, 0, fmt.Errorf("NPM integration not configured")
	}
	logs, total, err := a.npmSvc.GetAuditLogs(ctx, resolveHostID(ctx, a.hostID).String(), limit, offset)
	if err != nil {
		return nil, 0, err
	}
	views := make([]AuditLogView, 0, len(logs))
	for _, l := range logs {
		userName := ""
		if l.UserID != nil {
			userName = *l.UserID
		}
		views = append(views, AuditLogView{
			ID:           l.ID,
			Operation:    l.Operation,
			ResourceType: l.ResourceType,
			ResourceID:   l.ResourceID,
			ResourceName: l.ResourceName,
			UserName:     userName,
			CreatedAt:    l.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	return views, total, nil
}

// toInt safely converts interface{} to int for access list meta counts
func toInt(v interface{}) int {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case int64:
		return int(val)
	default:
		return 0
	}
}
