// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package caddy

import "encoding/json"

// CaddyConfig is the top-level Caddy v2 JSON configuration.
// Ref: https://caddyserver.com/docs/json/
type CaddyConfig struct {
	Admin   *AdminConfig   `json:"admin,omitempty"`
	Apps    *Apps          `json:"apps,omitempty"`
	Logging *LoggingConfig `json:"logging,omitempty"`
}

// AdminConfig controls the admin API endpoint.
type AdminConfig struct {
	Listen  string `json:"listen,omitempty"`
	Enforce bool   `json:"enforce_origin,omitempty"`
	Origins []string `json:"origins,omitempty"`
}

// Apps contains Caddy app modules.
type Apps struct {
	HTTP   *HTTPApp   `json:"http,omitempty"`
	TLS    *TLSApp    `json:"tls,omitempty"`
	Layer4 *Layer4App `json:"layer4,omitempty"`
}

// HTTPApp is the http app configuration.
type HTTPApp struct {
	Servers map[string]*Server `json:"servers,omitempty"`
}

// Server is an HTTP server within Caddy.
type Server struct {
	Listen            []string           `json:"listen,omitempty"`
	Routes            []Route            `json:"routes,omitempty"`
	AutomaticHTTPS    *AutoHTTPS         `json:"automatic_https,omitempty"`
	TLSConnectionPolicies []TLSConnPolicy `json:"tls_connection_policies,omitempty"`
	Logs              *ServerLogs        `json:"logs,omitempty"`
}

// AutoHTTPS controls automatic HTTPS behaviour.
type AutoHTTPS struct {
	Disable          bool     `json:"disable,omitempty"`
	DisableRedirects bool     `json:"disable_redirects,omitempty"`
	Skip             []string `json:"skip,omitempty"`
	SkipCerts        []string `json:"skip_certificates,omitempty"`
}

// Route is a Caddy HTTP route.
type Route struct {
	ID       string           `json:"@id,omitempty"` // For scoped API access
	Match    []MatchConfig    `json:"match,omitempty"`
	Handle   []json.RawMessage `json:"handle,omitempty"`
	Terminal bool             `json:"terminal,omitempty"`
}

// MatchConfig defines route matching rules.
type MatchConfig struct {
	Host []string `json:"host,omitempty"`
	Path []string `json:"path,omitempty"`
}

// ---- Handler types (serialized as json.RawMessage in Route.Handle) ----

// SubrouteHandler wraps routes in a subroute.
type SubrouteHandler struct {
	Handler string  `json:"handler"` // "subroute"
	Routes  []Route `json:"routes,omitempty"`
}

// ReverseProxyHandler is the reverse_proxy handler.
type ReverseProxyHandler struct {
	Handler      string              `json:"handler"` // "reverse_proxy"
	Upstreams    []Upstream          `json:"upstreams,omitempty"`
	Transport    *HTTPTransport      `json:"transport,omitempty"`
	Headers      *HeaderOps          `json:"headers,omitempty"`
	HealthChecks *HealthChecks       `json:"health_checks,omitempty"`
	FlushInterval json.Number        `json:"flush_interval,omitempty"` // -1 for WebSocket
}

// Upstream defines a backend upstream.
type Upstream struct {
	Dial string `json:"dial"`
}

// HTTPTransport configures the transport to upstreams.
type HTTPTransport struct {
	Module    string    `json:"protocol"` // "http"
	TLS       *UpstreamTLS `json:"tls,omitempty"`
	Versions  []string  `json:"versions,omitempty"` // ["h2c", "2"]
}

// UpstreamTLS configures TLS to the upstream.
type UpstreamTLS struct {
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
}

// HeaderOps configures header manipulation.
type HeaderOps struct {
	Request  *HeaderFieldOps `json:"request,omitempty"`
	Response *HeaderFieldOps `json:"response,omitempty"`
}

// HeaderFieldOps sets/adds/deletes headers.
type HeaderFieldOps struct {
	Set    map[string][]string `json:"set,omitempty"`
	Add    map[string][]string `json:"add,omitempty"`
	Delete []string            `json:"delete,omitempty"`
}

// HealthChecks configures upstream health checking.
type HealthChecks struct {
	Active *ActiveHealthCheck `json:"active,omitempty"`
}

// ActiveHealthCheck defines active health check parameters.
type ActiveHealthCheck struct {
	Path     string `json:"path,omitempty"`
	Interval string `json:"interval,omitempty"` // duration string like "30s"
	Timeout  string `json:"timeout,omitempty"`
}

// EncodeHandler adds compression.
type EncodeHandler struct {
	Handler   string                 `json:"handler"` // "encode"
	Encodings map[string]interface{} `json:"encodings,omitempty"`
	Prefer    []string               `json:"prefer,omitempty"`
}

// HeadersHandler manipulates response/request headers.
type HeadersHandler struct {
	Handler  string       `json:"handler"` // "headers"
	Response *HeaderFieldOps `json:"response,omitempty"`
	Request  *HeaderFieldOps `json:"request,omitempty"`
}

// ---- TLS configuration ----

// TLSApp is the tls app configuration.
type TLSApp struct {
	Automation *TLSAutomation `json:"automation,omitempty"`
	Certificates *TLSCertificates `json:"certificates,omitempty"`
}

// TLSAutomation defines ACME automation policies.
type TLSAutomation struct {
	Policies []TLSAutomationPolicy `json:"policies,omitempty"`
}

// TLSAutomationPolicy defines how certificates are obtained for given subjects.
type TLSAutomationPolicy struct {
	Subjects []string     `json:"subjects,omitempty"`
	Issuers  []TLSIssuer  `json:"issuers,omitempty"`
	OnDemand bool         `json:"on_demand,omitempty"`
}

// TLSIssuer is a certificate issuer (ACME, internal, etc.).
type TLSIssuer struct {
	Module      string       `json:"module"`                    // "acme", "internal", "zerossl"
	CA          string       `json:"ca,omitempty"`              // e.g. "https://acme-v02.api.letsencrypt.org/directory"
	Email       string       `json:"email,omitempty"`
	Challenges  *Challenges  `json:"challenges,omitempty"`
}

// Challenges configures ACME challenge types.
type Challenges struct {
	DNS *DNSChallenge `json:"dns,omitempty"`
	HTTP *HTTPChallenge `json:"http,omitempty"`
}

// DNSChallenge configures the DNS-01 ACME challenge.
type DNSChallenge struct {
	Provider   json.RawMessage `json:"provider,omitempty"`
	Resolvers  []string        `json:"resolvers,omitempty"`
	PropagationTimeout string  `json:"propagation_timeout,omitempty"` // e.g. "120s"
}

// HTTPChallenge configures the HTTP-01 ACME challenge.
type HTTPChallenge struct {
	Disabled bool `json:"disabled,omitempty"`
}

// TLSCertificates holds manually loaded certificates.
type TLSCertificates struct {
	LoadPEM []LoadPEMCert `json:"load_pem,omitempty"`
}

// LoadPEMCert loads a certificate from PEM data.
type LoadPEMCert struct {
	Certificate string   `json:"certificate"`
	Key         string   `json:"key"`
	Tags        []string `json:"tags,omitempty"`
}

// TLSConnPolicy controls per-connection TLS behaviour.
type TLSConnPolicy struct {
	Match          *TLSConnMatch `json:"match,omitempty"`
	CertSelection  interface{}   `json:"certificate_selection,omitempty"`
	ALPN           []string      `json:"alpn,omitempty"`
	ProtocolMin    string        `json:"protocol_min,omitempty"`
	ProtocolMax    string        `json:"protocol_max,omitempty"`
}

// TLSConnMatch matches TLS connections by SNI.
type TLSConnMatch struct {
	SNI []string `json:"sni,omitempty"`
}

// ServerLogs configures per-server logging.
type ServerLogs struct {
	DefaultLoggerName string `json:"default_logger_name,omitempty"`
}

// LoggingConfig configures Caddy's logging.
type LoggingConfig struct {
	Logs map[string]*LogConfig `json:"logs,omitempty"`
}

// LogConfig defines a single logger.
type LogConfig struct {
	Writer  *LogWriter `json:"writer,omitempty"`
	Level   string     `json:"level,omitempty"`
	Encoder *LogEncoder `json:"encoder,omitempty"`
}

// LogWriter defines where logs go.
type LogWriter struct {
	Output   string `json:"output"` // "stdout", "stderr", "file"
	Filename string `json:"filename,omitempty"`
}

// LogEncoder defines log format.
type LogEncoder struct {
	Format string `json:"format"` // "console", "json"
}

// ---- Static Response (for redirections and dead hosts) ----

// StaticResponseHandler returns a static HTTP response (used for redirections and error pages).
type StaticResponseHandler struct {
	Handler    string              `json:"handler"`               // "static_response"
	StatusCode string              `json:"status_code,omitempty"` // e.g. "301", "302", "404", "410"
	Headers    map[string][]string `json:"headers,omitempty"`     // e.g. {"Location": ["https://..."]}
	Body       string              `json:"body,omitempty"`
	Close      bool                `json:"close,omitempty"`
}

// ---- Authentication (for access lists) ----

// AuthenticationHandler provides HTTP authentication.
type AuthenticationHandler struct {
	Handler   string             `json:"handler"` // "authentication"
	Providers *AuthProviders     `json:"providers,omitempty"`
}

// AuthProviders holds authentication provider configs.
type AuthProviders struct {
	HTTPBasic *HTTPBasicAuth `json:"http_basic,omitempty"`
}

// HTTPBasicAuth configures HTTP basic authentication with bcrypt passwords.
type HTTPBasicAuth struct {
	Accounts []BasicAuthAccount `json:"accounts,omitempty"`
	Hash     *PasswordHash      `json:"hash,omitempty"`
}

// BasicAuthAccount represents a single basic auth credential.
type BasicAuthAccount struct {
	Username string `json:"username"`
	Password string `json:"password"` // bcrypt hash
}

// PasswordHash specifies the password hashing algorithm.
type PasswordHash struct {
	Algorithm string `json:"algorithm"` // "bcrypt"
}

// ---- Layer4 (for TCP/UDP stream forwarding) ----

// Layer4App is the layer4 app configuration for TCP/UDP forwarding.
// Requires the caddy-l4 module to be compiled into Caddy.
type Layer4App struct {
	Servers map[string]*Layer4Server `json:"servers,omitempty"`
}

// Layer4Server listens on addresses and routes layer4 connections.
type Layer4Server struct {
	Listen []string      `json:"listen,omitempty"`
	Routes []Layer4Route `json:"routes,omitempty"`
}

// Layer4Route defines a layer4 routing rule.
type Layer4Route struct {
	Handle []json.RawMessage `json:"handle,omitempty"`
}

// Layer4ProxyHandler forwards layer4 connections to upstreams.
type Layer4ProxyHandler struct {
	Handler   string           `json:"handler"` // "proxy"
	Upstreams []Layer4Upstream `json:"upstreams,omitempty"`
}

// Layer4Upstream defines a layer4 upstream destination.
type Layer4Upstream struct {
	Dial []string `json:"dial"`
}
