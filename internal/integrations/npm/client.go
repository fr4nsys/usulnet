// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package npm provides a client for Nginx Proxy Manager API integration.
package npm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/fr4nsys/usulnet/internal/pkg/errors"
)

// Client is a client for the Nginx Proxy Manager API.
type Client struct {
	baseURL    string
	httpClient *http.Client
	logger     *zap.Logger

	// Authentication
	token    string
	tokenExp time.Time
	email    string
	password string
	mu       sync.RWMutex
}

// Config holds the NPM client configuration.
type Config struct {
	BaseURL  string // e.g., "http://npm:81"
	Email    string // NPM admin email
	Password string // NPM admin password
	Timeout  time.Duration
}

// NewClient creates a new NPM API client.
func NewClient(config *Config, logger *zap.Logger) *Client {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &Client{
		baseURL:  config.BaseURL,
		email:    config.Email,
		password: config.Password,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		logger: logger,
	}
}

// =============================================================================
// Authentication
// =============================================================================

// TokenResponse represents the NPM token response.
type TokenResponse struct {
	Token   string `json:"token"`
	Expires string `json:"expires"`
}

// authenticate obtains or refreshes the API token.
func (c *Client) authenticate(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if token is still valid (with 5 minute buffer)
	if c.token != "" && time.Now().Add(5*time.Minute).Before(c.tokenExp) {
		return nil
	}

	payload := map[string]string{
		"identity": c.email,
		"secret":   c.password,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to marshal auth request")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/tokens", bytes.NewReader(body))
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to create auth request")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, errors.CodeNPMConnectionFailed, "failed to authenticate with NPM")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New(errors.CodeUnauthorized, "NPM authentication failed")
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to decode token response")
	}

	c.token = tokenResp.Token
	// NPM tokens typically expire in 1 day
	c.tokenExp = time.Now().Add(23 * time.Hour)

	c.logger.Debug("NPM authentication successful")
	return nil
}

// doRequest performs an authenticated request to NPM API.
// On 401 Unauthorized, it invalidates the cached token and retries once.
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	resp, err := c.doRequestOnce(ctx, method, path, body)
	if err != nil {
		return nil, err
	}

	// If 401, invalidate token and retry once
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		c.mu.Lock()
		c.token = ""
		c.tokenExp = time.Time{}
		c.mu.Unlock()

		c.logger.Debug("NPM returned 401, re-authenticating and retrying",
			zap.String("method", method),
			zap.String("path", path))

		return c.doRequestOnce(ctx, method, path, body)
	}

	return resp, nil
}

// doRequestOnce performs a single authenticated request to NPM API.
func (c *Client) doRequestOnce(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	if err := c.authenticate(ctx); err != nil {
		return nil, err
	}

	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to marshal request body")
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to create request")
	}

	c.mu.RLock()
	req.Header.Set("Authorization", "Bearer "+c.token)
	c.mu.RUnlock()
	req.Header.Set("Content-Type", "application/json")

	return c.httpClient.Do(req)
}

// =============================================================================
// Proxy Hosts
// =============================================================================

// ProxyHost represents an NPM proxy host.
type ProxyHost struct {
	ID                    int                    `json:"id,omitempty"`
	CreatedOn             string                 `json:"created_on,omitempty"`
	ModifiedOn            string                 `json:"modified_on,omitempty"`
	DomainNames           []string               `json:"domain_names"`
	ForwardScheme         string                 `json:"forward_scheme"`
	ForwardHost           string                 `json:"forward_host"`
	ForwardPort           int                    `json:"forward_port"`
	CertificateID         interface{}            `json:"certificate_id"` // int, "new", or null
	SSLForced             bool                   `json:"ssl_forced"`
	HSTSEnabled           bool                   `json:"hsts_enabled"`
	HSTSSubdomains        bool                   `json:"hsts_subdomains"`
	HTTP2Support          bool                   `json:"http2_support"`
	BlockExploits         bool                   `json:"block_exploits"`
	CachingEnabled        bool                   `json:"caching_enabled"`
	AllowWebsocketUpgrade bool                   `json:"allow_websocket_upgrade"`
	AccessListID          int                    `json:"access_list_id"`
	AdvancedConfig        string                 `json:"advanced_config"`
	Enabled               bool                   `json:"enabled"`
	Locations             []ProxyHostLocation    `json:"locations,omitempty"`
	Meta                  map[string]interface{} `json:"meta,omitempty"`
	// Expanded fields (when using ?expand=...)
	Certificate *Certificate `json:"certificate,omitempty"`
	AccessList  *AccessList  `json:"access_list,omitempty"`
}

// ProxyHostLocation represents a custom location in a proxy host.
type ProxyHostLocation struct {
	Path           string `json:"path"`
	ForwardScheme  string `json:"forward_scheme,omitempty"`
	ForwardHost    string `json:"forward_host,omitempty"`
	ForwardPort    int    `json:"forward_port,omitempty"`
	AdvancedConfig string `json:"advanced_config,omitempty"`
}

// ProxyHostCreate is the input for creating a proxy host.
type ProxyHostCreate struct {
	DomainNames    []string    `json:"domain_names"`
	ForwardScheme  string      `json:"forward_scheme"`
	ForwardHost    string      `json:"forward_host"`
	ForwardPort    int         `json:"forward_port"`
	CertificateID  interface{} `json:"certificate_id,omitempty"`
	SSLForced      bool        `json:"ssl_forced,omitempty"`
	HSTSEnabled    bool        `json:"hsts_enabled,omitempty"`
	HSTSSubdomains bool        `json:"hsts_subdomains,omitempty"`
	HTTP2Support   bool        `json:"http2_support,omitempty"`
	BlockExploits  bool        `json:"block_exploits,omitempty"`
	CachingEnabled bool        `json:"caching_enabled,omitempty"`
	AllowWebsocket bool        `json:"allow_websocket_upgrade,omitempty"`
	AccessListID   int         `json:"access_list_id,omitempty"`
	AdvancedConfig string      `json:"advanced_config,omitempty"`
}

// ProxyHostUpdate is the input for updating a proxy host.
type ProxyHostUpdate struct {
	DomainNames    []string    `json:"domain_names,omitempty"`
	ForwardScheme  *string     `json:"forward_scheme,omitempty"`
	ForwardHost    *string     `json:"forward_host,omitempty"`
	ForwardPort    *int        `json:"forward_port,omitempty"`
	CertificateID  interface{} `json:"certificate_id,omitempty"`
	SSLForced      *bool       `json:"ssl_forced,omitempty"`
	HSTSEnabled    *bool       `json:"hsts_enabled,omitempty"`
	HSTSSubdomains *bool       `json:"hsts_subdomains,omitempty"`
	HTTP2Support   *bool       `json:"http2_support,omitempty"`
	BlockExploits  *bool       `json:"block_exploits,omitempty"`
	CachingEnabled *bool       `json:"caching_enabled,omitempty"`
	AllowWebsocket *bool       `json:"allow_websocket_upgrade,omitempty"`
	AccessListID   *int        `json:"access_list_id,omitempty"`
	AdvancedConfig *string     `json:"advanced_config,omitempty"`
	Enabled        *bool       `json:"enabled,omitempty"`
}

// ListProxyHosts returns all proxy hosts.
func (c *Client) ListProxyHosts(ctx context.Context) ([]*ProxyHost, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/nginx/proxy-hosts?expand=certificate,access_list", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var hosts []*ProxyHost
	if err := json.NewDecoder(resp.Body).Decode(&hosts); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode proxy hosts")
	}

	return hosts, nil
}

// GetProxyHost returns a proxy host by ID.
func (c *Client) GetProxyHost(ctx context.Context, id int) (*ProxyHost, error) {
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/nginx/proxy-hosts/%d?expand=certificate,access_list", id), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New(errors.CodeNotFound, "proxy host not found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var host ProxyHost
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode proxy host")
	}

	return &host, nil
}

// CreateProxyHost creates a new proxy host.
func (c *Client) CreateProxyHost(ctx context.Context, host *ProxyHost) (*ProxyHost, error) {
	resp, err := c.doRequest(ctx, "POST", "/api/nginx/proxy-hosts", host)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, c.handleError(resp)
	}

	var created ProxyHost
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode created proxy host")
	}

	return &created, nil
}

// UpdateProxyHost updates an existing proxy host.
func (c *Client) UpdateProxyHost(ctx context.Context, id int, host *ProxyHost) (*ProxyHost, error) {
	resp, err := c.doRequest(ctx, "PUT", fmt.Sprintf("/api/nginx/proxy-hosts/%d", id), host)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var updated ProxyHost
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode updated proxy host")
	}

	return &updated, nil
}

// DeleteProxyHost deletes a proxy host.
func (c *Client) DeleteProxyHost(ctx context.Context, id int) error {
	resp, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/api/nginx/proxy-hosts/%d", id), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.handleError(resp)
	}

	return nil
}

// EnableProxyHost enables a proxy host.
func (c *Client) EnableProxyHost(ctx context.Context, id int) error {
	resp, err := c.doRequest(ctx, "POST", fmt.Sprintf("/api/nginx/proxy-hosts/%d/enable", id), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.handleError(resp)
	}

	return nil
}

// DisableProxyHost disables a proxy host.
func (c *Client) DisableProxyHost(ctx context.Context, id int) error {
	resp, err := c.doRequest(ctx, "POST", fmt.Sprintf("/api/nginx/proxy-hosts/%d/disable", id), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.handleError(resp)
	}

	return nil
}

// =============================================================================
// Redirection Hosts
// =============================================================================

// RedirectionHost represents an NPM redirection host.
type RedirectionHost struct {
	ID                int                    `json:"id,omitempty"`
	CreatedOn         string                 `json:"created_on,omitempty"`
	ModifiedOn        string                 `json:"modified_on,omitempty"`
	DomainNames       []string               `json:"domain_names"`
	ForwardScheme     string                 `json:"forward_scheme"`
	ForwardDomainName string                 `json:"forward_domain_name"`
	ForwardHTTPCode   int                    `json:"forward_http_code"`
	PreservePath      bool                   `json:"preserve_path"`
	CertificateID     interface{}            `json:"certificate_id"`
	SSLForced         bool                   `json:"ssl_forced"`
	HSTSEnabled       bool                   `json:"hsts_enabled"`
	HSTSSubdomains    bool                   `json:"hsts_subdomains"`
	HTTP2Support      bool                   `json:"http2_support"`
	BlockExploits     bool                   `json:"block_exploits"`
	AdvancedConfig    string                 `json:"advanced_config"`
	Enabled           bool                   `json:"enabled"`
	Meta              map[string]interface{} `json:"meta,omitempty"`
	Certificate       *Certificate           `json:"certificate,omitempty"`
}

// RedirectionCreate is the input for creating a redirection host.
type RedirectionCreate struct {
	DomainNames     []string    `json:"domain_names"`
	ForwardScheme   string      `json:"forward_scheme"`
	ForwardDomain   string      `json:"forward_domain_name"`
	ForwardHTTPCode int         `json:"forward_http_code"`
	PreservePath    bool        `json:"preserve_path"`
	CertificateID   interface{} `json:"certificate_id,omitempty"`
	SSLForced       bool        `json:"ssl_forced,omitempty"`
	HSTSEnabled     bool        `json:"hsts_enabled,omitempty"`
	HSTSSubdomains  bool        `json:"hsts_subdomains,omitempty"`
	HTTP2Support    bool        `json:"http2_support,omitempty"`
	BlockExploits   bool        `json:"block_exploits,omitempty"`
	AdvancedConfig  string      `json:"advanced_config,omitempty"`
}

// ListRedirectionHosts returns all redirection hosts.
func (c *Client) ListRedirectionHosts(ctx context.Context) ([]*RedirectionHost, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/nginx/redirection-hosts?expand=certificate", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var hosts []*RedirectionHost
	if err := json.NewDecoder(resp.Body).Decode(&hosts); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode redirection hosts")
	}

	return hosts, nil
}

// GetRedirectionHost returns a redirection host by ID.
func (c *Client) GetRedirectionHost(ctx context.Context, id int) (*RedirectionHost, error) {
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/nginx/redirection-hosts/%d?expand=certificate", id), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New(errors.CodeNotFound, "redirection host not found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var host RedirectionHost
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode redirection host")
	}

	return &host, nil
}

// CreateRedirectionHost creates a new redirection host.
func (c *Client) CreateRedirectionHost(ctx context.Context, host *RedirectionHost) (*RedirectionHost, error) {
	resp, err := c.doRequest(ctx, "POST", "/api/nginx/redirection-hosts", host)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, c.handleError(resp)
	}

	var created RedirectionHost
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode created redirection host")
	}

	return &created, nil
}

// UpdateRedirectionHost updates an existing redirection host.
func (c *Client) UpdateRedirectionHost(ctx context.Context, id int, host *RedirectionHost) (*RedirectionHost, error) {
	resp, err := c.doRequest(ctx, "PUT", fmt.Sprintf("/api/nginx/redirection-hosts/%d", id), host)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var updated RedirectionHost
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode updated redirection host")
	}

	return &updated, nil
}

// DeleteRedirectionHost deletes a redirection host.
func (c *Client) DeleteRedirectionHost(ctx context.Context, id int) error {
	resp, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/api/nginx/redirection-hosts/%d", id), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.handleError(resp)
	}

	return nil
}

// =============================================================================
// Streams (TCP/UDP)
// =============================================================================

// Stream represents an NPM stream.
type Stream struct {
	ID             int                    `json:"id,omitempty"`
	CreatedOn      string                 `json:"created_on,omitempty"`
	ModifiedOn     string                 `json:"modified_on,omitempty"`
	IncomingPort   int                    `json:"incoming_port"`
	ForwardingHost string                 `json:"forwarding_host"`
	ForwardingPort int                    `json:"forwarding_port"`
	TCPForwarding  bool                   `json:"tcp_forwarding"`
	UDPForwarding  bool                   `json:"udp_forwarding"`
	CertificateID  interface{}            `json:"certificate_id"`
	Enabled        bool                   `json:"enabled"`
	Meta           map[string]interface{} `json:"meta,omitempty"`
	Certificate    *Certificate           `json:"certificate,omitempty"`
}

// ListStreams returns all streams.
func (c *Client) ListStreams(ctx context.Context) ([]*Stream, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/nginx/streams?expand=certificate", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var streams []*Stream
	if err := json.NewDecoder(resp.Body).Decode(&streams); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode streams")
	}

	return streams, nil
}

// GetStream returns a stream by ID.
func (c *Client) GetStream(ctx context.Context, id int) (*Stream, error) {
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/nginx/streams/%d?expand=certificate", id), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New(errors.CodeNotFound, "stream not found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var stream Stream
	if err := json.NewDecoder(resp.Body).Decode(&stream); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode stream")
	}

	return &stream, nil
}

// CreateStream creates a new stream.
func (c *Client) CreateStream(ctx context.Context, stream *Stream) (*Stream, error) {
	resp, err := c.doRequest(ctx, "POST", "/api/nginx/streams", stream)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, c.handleError(resp)
	}

	var created Stream
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode created stream")
	}

	return &created, nil
}

// UpdateStream updates an existing stream.
func (c *Client) UpdateStream(ctx context.Context, id int, stream *Stream) (*Stream, error) {
	resp, err := c.doRequest(ctx, "PUT", fmt.Sprintf("/api/nginx/streams/%d", id), stream)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var updated Stream
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode updated stream")
	}

	return &updated, nil
}

// DeleteStream deletes a stream.
func (c *Client) DeleteStream(ctx context.Context, id int) error {
	resp, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/api/nginx/streams/%d", id), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.handleError(resp)
	}

	return nil
}

// =============================================================================
// Dead Hosts (404)
// =============================================================================

// DeadHost represents an NPM dead host (404 page).
type DeadHost struct {
	ID             int                    `json:"id,omitempty"`
	CreatedOn      string                 `json:"created_on,omitempty"`
	ModifiedOn     string                 `json:"modified_on,omitempty"`
	DomainNames    []string               `json:"domain_names"`
	CertificateID  interface{}            `json:"certificate_id"`
	SSLForced      bool                   `json:"ssl_forced"`
	HSTSEnabled    bool                   `json:"hsts_enabled"`
	HSTSSubdomains bool                   `json:"hsts_subdomains"`
	HTTP2Support   bool                   `json:"http2_support"`
	AdvancedConfig string                 `json:"advanced_config"`
	Enabled        bool                   `json:"enabled"`
	Meta           map[string]interface{} `json:"meta,omitempty"`
	Certificate    *Certificate           `json:"certificate,omitempty"`
}

// ListDeadHosts returns all dead hosts.
func (c *Client) ListDeadHosts(ctx context.Context) ([]*DeadHost, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/nginx/dead-hosts?expand=certificate", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var hosts []*DeadHost
	if err := json.NewDecoder(resp.Body).Decode(&hosts); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode dead hosts")
	}

	return hosts, nil
}

// CreateDeadHost creates a new dead host.
func (c *Client) CreateDeadHost(ctx context.Context, host *DeadHost) (*DeadHost, error) {
	resp, err := c.doRequest(ctx, "POST", "/api/nginx/dead-hosts", host)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, c.handleError(resp)
	}

	var created DeadHost
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode created dead host")
	}

	return &created, nil
}

// DeleteDeadHost deletes a dead host.
func (c *Client) DeleteDeadHost(ctx context.Context, id int) error {
	resp, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/api/nginx/dead-hosts/%d", id), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.handleError(resp)
	}

	return nil
}

// =============================================================================
// Certificates
// =============================================================================

// Certificate represents an NPM certificate.
type Certificate struct {
	ID          int                    `json:"id,omitempty"`
	CreatedOn   string                 `json:"created_on,omitempty"`
	ModifiedOn  string                 `json:"modified_on,omitempty"`
	Provider    string                 `json:"provider"` // letsencrypt, other
	NiceName    string                 `json:"nice_name"`
	DomainNames []string               `json:"domain_names"`
	ExpiresOn   string                 `json:"expires_on,omitempty"`
	Meta        map[string]interface{} `json:"meta,omitempty"`
}

// CertificateRequest represents a request to create a Let's Encrypt certificate.
type CertificateRequest struct {
	DomainNames            []string               `json:"domain_names"`
	Meta                   map[string]interface{} `json:"meta,omitempty"`
	LetsencryptEmail       string                 `json:"letsencrypt_email,omitempty"`
	LetsencryptAgree       bool                   `json:"letsencrypt_agree,omitempty"`
	DNSChallenge           bool                   `json:"dns_challenge,omitempty"`
	DNSProvider            string                 `json:"dns_provider,omitempty"`
	DNSProviderCredentials string                 `json:"dns_provider_credentials,omitempty"`
	PropagationSeconds     int                    `json:"propagation_seconds,omitempty"`
}

// ListCertificates returns all certificates.
func (c *Client) ListCertificates(ctx context.Context) ([]*Certificate, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/nginx/certificates", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var certs []*Certificate
	if err := json.NewDecoder(resp.Body).Decode(&certs); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode certificates")
	}

	return certs, nil
}

// GetCertificate returns a certificate by ID.
func (c *Client) GetCertificate(ctx context.Context, id int) (*Certificate, error) {
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/nginx/certificates/%d", id), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New(errors.CodeNotFound, "certificate not found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var cert Certificate
	if err := json.NewDecoder(resp.Body).Decode(&cert); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode certificate")
	}

	return &cert, nil
}

// RequestLetsEncryptCertificate requests a new Let's Encrypt certificate.
func (c *Client) RequestLetsEncryptCertificate(ctx context.Context, req *CertificateRequest) (*Certificate, error) {
	resp, err := c.doRequest(ctx, "POST", "/api/nginx/certificates", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, c.handleError(resp)
	}

	var cert Certificate
	if err := json.NewDecoder(resp.Body).Decode(&cert); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode certificate")
	}

	return &cert, nil
}

// UploadCustomCertificate uploads a custom SSL certificate to NPM.
func (c *Client) UploadCustomCertificate(ctx context.Context, niceName string, cert, key, intermediate []byte) (*Certificate, error) {
	payload := map[string]interface{}{
		"nice_name": niceName,
		"provider":  "other",
		"meta": map[string]interface{}{
			"certificate":              string(cert),
			"certificate_key":          string(key),
			"intermediate_certificate": string(intermediate),
		},
	}

	resp, err := c.doRequest(ctx, "POST", "/api/nginx/certificates", payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, c.handleError(resp)
	}

	var result Certificate
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode certificate response")
	}

	return &result, nil
}

// RenewCertificate renews a certificate.
func (c *Client) RenewCertificate(ctx context.Context, id int) (*Certificate, error) {
	resp, err := c.doRequest(ctx, "POST", fmt.Sprintf("/api/nginx/certificates/%d/renew", id), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var cert Certificate
	if err := json.NewDecoder(resp.Body).Decode(&cert); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode certificate")
	}

	return &cert, nil
}

// DeleteCertificate deletes a certificate.
func (c *Client) DeleteCertificate(ctx context.Context, id int) error {
	resp, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/api/nginx/certificates/%d", id), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.handleError(resp)
	}

	return nil
}

// =============================================================================
// Access Lists
// =============================================================================

// AccessList represents an NPM access list.
type AccessList struct {
	ID         int                    `json:"id,omitempty"`
	CreatedOn  string                 `json:"created_on,omitempty"`
	ModifiedOn string                 `json:"modified_on,omitempty"`
	Name       string                 `json:"name"`
	SatisfyAny bool                   `json:"satisfy_any"`
	PassAuth   bool                   `json:"pass_auth"`
	Items      []AccessListItem       `json:"items,omitempty"`
	Clients    []AccessListClient     `json:"clients,omitempty"`
	Meta       map[string]interface{} `json:"meta,omitempty"`
}

// AccessListItem represents an authorization item (username/password).
type AccessListItem struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AccessListClient represents a client IP rule.
type AccessListClient struct {
	Address   string `json:"address"`
	Directive string `json:"directive"` // allow or deny
}

// AccessListCreate is the input for creating an access list.
type AccessListCreate struct {
	Name       string             `json:"name"`
	SatisfyAny bool               `json:"satisfy_any,omitempty"`
	PassAuth   bool               `json:"pass_auth,omitempty"`
	Items      []AccessListItem   `json:"items,omitempty"`
	Clients    []AccessListClient `json:"clients,omitempty"`
}

// ListAccessLists returns all access lists.
func (c *Client) ListAccessLists(ctx context.Context) ([]*AccessList, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/nginx/access-lists?expand=items,clients", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var lists []*AccessList
	if err := json.NewDecoder(resp.Body).Decode(&lists); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode access lists")
	}

	return lists, nil
}

// GetAccessList returns an access list by ID.
func (c *Client) GetAccessList(ctx context.Context, id int) (*AccessList, error) {
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/nginx/access-lists/%d?expand=items,clients", id), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New(errors.CodeNotFound, "access list not found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var list AccessList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode access list")
	}

	return &list, nil
}

// CreateAccessList creates a new access list.
func (c *Client) CreateAccessList(ctx context.Context, list *AccessList) (*AccessList, error) {
	resp, err := c.doRequest(ctx, "POST", "/api/nginx/access-lists", list)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, c.handleError(resp)
	}

	var created AccessList
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode created access list")
	}

	return &created, nil
}

// UpdateAccessList updates an existing access list.
func (c *Client) UpdateAccessList(ctx context.Context, id int, list *AccessList) (*AccessList, error) {
	resp, err := c.doRequest(ctx, "PUT", fmt.Sprintf("/api/nginx/access-lists/%d", id), list)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var updated AccessList
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode updated access list")
	}

	return &updated, nil
}

// DeleteAccessList deletes an access list.
func (c *Client) DeleteAccessList(ctx context.Context, id int) error {
	resp, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/api/nginx/access-lists/%d", id), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.handleError(resp)
	}

	return nil
}

// =============================================================================
// Reports / Stats
// =============================================================================

// HostsCount represents the count of hosts by type.
type HostsCount struct {
	Proxy       int `json:"proxy"`
	Redirection int `json:"redirection"`
	Stream      int `json:"stream"`
	Dead        int `json:"dead"`
}

// GetHostsCount returns the count of hosts by type.
func (c *Client) GetHostsCount(ctx context.Context) (*HostsCount, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/reports/hosts", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var count HostsCount
	if err := json.NewDecoder(resp.Body).Decode(&count); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode hosts count")
	}

	return &count, nil
}

// =============================================================================
// Settings
// =============================================================================

// Setting represents an NPM setting.
type Setting struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Value       interface{}            `json:"value"`
	Meta        map[string]interface{} `json:"meta"`
}

// GetSettings returns all settings.
func (c *Client) GetSettings(ctx context.Context) ([]*Setting, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/settings", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var settings []*Setting
	if err := json.NewDecoder(resp.Body).Decode(&settings); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode settings")
	}

	return settings, nil
}

// UpdateSetting updates a setting.
func (c *Client) UpdateSetting(ctx context.Context, id string, value interface{}) (*Setting, error) {
	payload := map[string]interface{}{"value": value}
	resp, err := c.doRequest(ctx, "PUT", fmt.Sprintf("/api/settings/%s", id), payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var setting Setting
	if err := json.NewDecoder(resp.Body).Decode(&setting); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode setting")
	}

	return &setting, nil
}

// =============================================================================
// Nginx Control
// =============================================================================

// ReloadNginx reloads the nginx configuration.
func (c *Client) ReloadNginx(ctx context.Context) error {
	resp, err := c.doRequest(ctx, "POST", "/api/nginx/reload", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.handleError(resp)
	}

	return nil
}

// =============================================================================
// Health / Status
// =============================================================================

// Health checks if NPM is healthy.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/api/", nil)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to create health request")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, errors.CodeNPMConnectionFailed, "NPM is not reachable")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New(errors.CodeNPMConnectionFailed, "NPM health check failed")
	}

	return nil
}

// =============================================================================
// Error Handling
// =============================================================================

// APIError represents an NPM API error.
type APIError struct {
	Error   interface{} `json:"error"`
	Message string      `json:"message"`
}

func (c *Client) handleError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)

	// Use specific error code for auth failures
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return errors.New(errors.CodeUnauthorized, "NPM authentication failed")
	}

	var apiErr APIError
	if err := json.Unmarshal(body, &apiErr); err == nil && apiErr.Message != "" {
		return errors.New(errors.CodeNPMConnectionFailed, "NPM API error: "+apiErr.Message)
	}

	return errors.New(errors.CodeNPMConnectionFailed, fmt.Sprintf("NPM API error: %d - %s", resp.StatusCode, string(body)))
}
