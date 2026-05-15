// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all application configuration
type Config struct {
	Mode          string              `mapstructure:"mode"`
	Server        ServerConfig        `mapstructure:"server"`
	Database      DatabaseConfig      `mapstructure:"database"`
	Redis         RedisConfig         `mapstructure:"redis"`
	NATS          NATSConfig          `mapstructure:"nats"`
	Security      SecurityConfig      `mapstructure:"security"`
	Storage       StorageConfig       `mapstructure:"storage"`
	Agent         AgentConfig         `mapstructure:"agent"`
	Docker        DockerConfig        `mapstructure:"docker"`
	Trivy         TrivyConfig         `mapstructure:"trivy"`
	NPM           NPMConfig           `mapstructure:"npm"`
	Caddy         CaddyConfig         `mapstructure:"caddy"`
	Nginx         NginxConfig         `mapstructure:"nginx"`
	Minio         MinIOConfig         `mapstructure:"minio"`
	Logging       LoggingConfig       `mapstructure:"logging"`
	Metrics       MetricsConfig       `mapstructure:"metrics"`
	Observability ObservabilityConfig `mapstructure:"observability"`
	Terminal      TerminalConfig      `mapstructure:"terminal"`
	Guacd         GuacdConfig         `mapstructure:"guacd"`
	Recon         ReconConfig         `mapstructure:"recon"`
	ImageBuilder  ImageBuilderConfig  `mapstructure:"image_builder"`
	ImageSign     ImageSignConfig     `mapstructure:"image_sign"`
}

// ImageBuilderConfig holds runtime knobs for the image builder module.
// All fields default to sensible values via DefaultConfig() — operators
// only override when they need a larger context cap or a different log
// channel prefix.
type ImageBuilderConfig struct {
	// MaxContextBytes caps a single build-context upload. Defaults to
	// 256 MiB when zero or unset. Sized at the application layer so
	// the cap is enforced before the payload reaches Docker.
	MaxContextBytes int64 `mapstructure:"max_context_bytes"`

	// LogTailBytes is the trailing window of build log bytes that is
	// persisted to the row after a build completes. Defaults to 64 KiB.
	LogTailBytes int `mapstructure:"log_tail_bytes"`

	// LogChannelPrefix is the Redis pub/sub channel prefix used by
	// the build streamer. Defaults to "imagebuilder:logs".
	LogChannelPrefix string `mapstructure:"log_channel_prefix"`
}

// ImageSignConfig toggles the optional cosign hook on successful
// builds. When Enabled is false the image builder skips the signing
// step. The actual cosign binary path / Sigstore endpoints live on the
// imagesign service config — this flag only controls the hook wiring.
type ImageSignConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// ReconConfig holds runtime knobs for the recon / privacy module.
// See docs/recon.md §13 and docs/v26.5/technical-notes.md "Feature flag".
//
// Enabled gates the entire module: when false, none of the recon
// services, workers, network, or containers are constructed at runtime.
type ReconConfig struct {
	// Enabled toggles the whole module. Default: false.
	Enabled bool `mapstructure:"enabled"`

	// RetentionDays controls how long findings and metadata artifacts
	// survive before the retention worker sweeps them. Default: 90.
	RetentionDays int `mapstructure:"retention_days"`

	// MaxConcurrentScans caps how many recon scans the scheduler may
	// run in parallel. Default: 2.
	MaxConcurrentScans int `mapstructure:"max_concurrent_scans"`

	// InstallationOrg is the organization name the RDAP-match ownership
	// strategy compares against. Blank means "RDAP-based verification
	// fails closed"; operators must set this explicitly to use the
	// rdap_match method.
	InstallationOrg string `mapstructure:"installation_org"`

	// BaseURL overrides the public origin used to build email
	// verification links. Falls back to Server.BaseURL when empty.
	BaseURL string `mapstructure:"base_url"`

	SpiderFoot ReconEngineConfig     `mapstructure:"spiderfoot"`
	Toolkit    ReconEngineConfig     `mapstructure:"toolkit"`
	Egress     ReconEgressConfig     `mapstructure:"egress"`
	Connectors ReconConnectorsConfig `mapstructure:"connectors"`
}

// ReconEngineConfig is the per-engine image override (pin a digest in
// air-gapped installs or when CI publishes a new image).
type ReconEngineConfig struct {
	Image  string `mapstructure:"image"`
	Listen string `mapstructure:"listen"`
}

// ReconEgressConfig holds the egress allow-list applied at network
// creation. An empty list keeps the default policy (DNS + 80 + 443).
type ReconEgressConfig struct {
	Allowlist []string `mapstructure:"allowlist"`
}

// ReconConnectorsConfig toggles optional external-API connectors. The
// credentials themselves live in recon_connectors (encrypted) and are
// configured via the UI; these flags only control whether the
// connector is registered at startup.
type ReconConnectorsConfig struct {
	HIBP   ReconConnectorToggle `mapstructure:"hibp"`
	Shodan ReconConnectorToggle `mapstructure:"shodan"`
}

// ReconConnectorToggle is the minimal enable/disable for a connector.
type ReconConnectorToggle struct {
	Enabled bool `mapstructure:"enabled"`
}

// DockerConfig holds Docker daemon connection configuration.
type DockerConfig struct {
	// Socket is the path to the Docker daemon Unix socket.
	// For rootless Docker, this is typically /run/user/<UID>/docker.sock
	// or $XDG_RUNTIME_DIR/docker.sock.
	Socket string `mapstructure:"socket"`
}

// TerminalConfig holds host terminal configuration.
// Previously read from HOST_TERMINAL_* env vars; now centralized in Config.
type TerminalConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	User    string `mapstructure:"user"`
	Shell   string `mapstructure:"shell"`
}

// GuacdConfig holds Apache Guacamole daemon configuration for web-based RDP.
// The guacd service is included by default. Set GUACD_ENABLED=false to disable.
type GuacdConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Host    string `mapstructure:"host"`
	Port    int    `mapstructure:"port"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	HTTPSPort       int           `mapstructure:"https_port"`
	BaseURL         string        `mapstructure:"base_url"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	IdleTimeout     time.Duration `mapstructure:"idle_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	MaxRequestSize  string        `mapstructure:"max_request_size"`
	RateLimitRPS    int           `mapstructure:"rate_limit_rps"`
	RateLimitBurst  int           `mapstructure:"rate_limit_burst"`
	RedirectHTTPS   bool          `mapstructure:"redirect_https"` // Redirect HTTP→HTTPS when TLS is enabled

	// TLS configuration
	TLS ServerTLSConfig `mapstructure:"tls"`
}

// ServerTLSConfig holds TLS configuration for the HTTP server
type ServerTLSConfig struct {
	// Enabled activates HTTPS. If true and no cert/key provided, auto-generates self-signed.
	Enabled bool `mapstructure:"enabled"`
	// CertFile is the path to a custom TLS certificate (overrides auto-generated)
	CertFile string `mapstructure:"cert_file"`
	// KeyFile is the path to a custom TLS private key
	KeyFile string `mapstructure:"key_file"`
	// AutoTLS generates a self-signed certificate if no custom cert is provided (default: true)
	AutoTLS bool `mapstructure:"auto_tls"`
	// DataDir is where auto-generated CA and certs are stored (default: <storage.path>/pki)
	DataDir string `mapstructure:"data_dir"`
	// LocalServices opts in to TLS for the in-cluster Postgres / Redis / NATS
	// links. Defaults to false (plain TCP on the private docker network).
	// When true, the compose entrypoints generate self-signed ECDSA P-256
	// certs and the application rewrites the connection URLs to
	// postgres ssl=require (skip-verify), rediss://, and nats with TLS.
	// Operators can mount their own CA to flip skip-verify off.
	LocalServices bool `mapstructure:"local_services"`
}

// DatabaseConfig holds PostgreSQL configuration
type DatabaseConfig struct {
	URL             string        `mapstructure:"url"`
	SSLMode         string        `mapstructure:"ssl_mode"` // disable, allow, prefer, require, verify-ca, verify-full
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `mapstructure:"conn_max_idle_time"`
	QueryTimeout    time.Duration `mapstructure:"query_timeout"`
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	URL           string        `mapstructure:"url"`
	TLSEnabled    bool          `mapstructure:"tls_enabled"`     // Force TLS even with redis:// URL
	TLSCertFile   string        `mapstructure:"tls_cert_file"`   // Client certificate for mTLS
	TLSKeyFile    string        `mapstructure:"tls_key_file"`    // Client key for mTLS
	TLSCAFile     string        `mapstructure:"tls_ca_file"`     // Custom CA for server verification
	TLSSkipVerify bool          `mapstructure:"tls_skip_verify"` // Skip server cert verification
	PoolSize      int           `mapstructure:"pool_size"`
	MinIdleConns  int           `mapstructure:"min_idle_conns"`
	DialTimeout   time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout   time.Duration `mapstructure:"read_timeout"`
	WriteTimeout  time.Duration `mapstructure:"write_timeout"`
}

// NATSConfig holds NATS configuration
type NATSConfig struct {
	URL           string        `mapstructure:"url"`
	Name          string        `mapstructure:"name"`
	MaxReconnects int           `mapstructure:"max_reconnects"`
	ReconnectWait time.Duration `mapstructure:"reconnect_wait"`
	JetStream     struct {
		Enabled bool   `mapstructure:"enabled"`
		Domain  string `mapstructure:"domain"`
	} `mapstructure:"jetstream"`

	// Authentication
	Token    string `mapstructure:"token"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`

	// TLS Configuration
	TLS struct {
		Enabled    bool   `mapstructure:"enabled"`
		CertFile   string `mapstructure:"cert_file"`
		KeyFile    string `mapstructure:"key_file"`
		CAFile     string `mapstructure:"ca_file"`
		SkipVerify bool   `mapstructure:"skip_verify"`
	} `mapstructure:"tls"`
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	JWTSecret             string        `mapstructure:"jwt_secret"`
	JWTExpiry             time.Duration `mapstructure:"jwt_expiry"`
	RefreshExpiry         time.Duration `mapstructure:"refresh_expiry"`
	ConfigEncryptionKey   string        `mapstructure:"config_encryption_key"`
	CookieSecure          bool          `mapstructure:"cookie_secure"`
	CookieSameSite        string        `mapstructure:"cookie_samesite"`
	CookieDomain          string        `mapstructure:"cookie_domain"`
	PasswordMinLength     int           `mapstructure:"password_min_length"`
	PasswordRequireUpper  bool          `mapstructure:"password_require_uppercase"`
	PasswordRequireNumber bool          `mapstructure:"password_require_number"`
	PasswordRequireSymbol bool          `mapstructure:"password_require_special"`
	MaxFailedLogins       int           `mapstructure:"max_failed_logins"`
	LockoutDuration       time.Duration `mapstructure:"lockout_duration"`
	APIKeyLength          int           `mapstructure:"api_key_length"`
}

// StorageConfig holds storage configuration
type StorageConfig struct {
	Type   string   `mapstructure:"type"` // local | s3
	Path   string   `mapstructure:"path"`
	S3     S3Config `mapstructure:"s3"`
	Backup struct {
		Compression      string `mapstructure:"compression"`
		CompressionLevel int    `mapstructure:"compression_level"`
		RetentionDays    int    `mapstructure:"default_retention_days"`
	} `mapstructure:"backup"`
}

// S3Config holds S3-compatible storage configuration
type S3Config struct {
	Endpoint     string `mapstructure:"endpoint"`
	Bucket       string `mapstructure:"bucket"`
	Region       string `mapstructure:"region"`
	AccessKey    string `mapstructure:"access_key"`
	SecretKey    string `mapstructure:"secret_key"`
	UsePathStyle bool   `mapstructure:"use_path_style"`
	UseSSL       bool   `mapstructure:"use_ssl"` // Use HTTPS for S3 connections (default: true)
}

// AgentConfig holds agent-specific configuration
type AgentConfig struct {
	MasterURL         string        `mapstructure:"master_url"`
	ID                string        `mapstructure:"id"`
	Name              string        `mapstructure:"name"`
	Token             string        `mapstructure:"token"`
	HeartbeatInterval time.Duration `mapstructure:"heartbeat_interval"`
	InventoryInterval time.Duration `mapstructure:"inventory_interval"`
	MetricsInterval   time.Duration `mapstructure:"metrics_interval"`
	ReconnectDelay    time.Duration `mapstructure:"reconnect_delay"`
	MaxReconnectDelay time.Duration `mapstructure:"max_reconnect_delay"`

	// TLS for NATS connection to master
	TLSEnabled  bool   `mapstructure:"tls_enabled"`
	TLSCertFile string `mapstructure:"tls_cert_file"`
	TLSKeyFile  string `mapstructure:"tls_key_file"`
	TLSCAFile   string `mapstructure:"tls_ca_file"`
}

// TrivyConfig holds Trivy scanner configuration
type TrivyConfig struct {
	Enabled         bool          `mapstructure:"enabled"`
	CacheDir        string        `mapstructure:"cache_dir"`
	Timeout         time.Duration `mapstructure:"timeout"`
	Severity        string        `mapstructure:"severity"`
	IgnoreUnfixed   bool          `mapstructure:"ignore_unfixed"`
	UpdateDBOnStart bool          `mapstructure:"update_db_on_start"`
}

// NPMConfig holds Nginx Proxy Manager integration configuration.
// NPM connections are managed manually via the Settings UI.
type NPMConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// CaddyConfig holds Caddy reverse proxy configuration.
// Users connect their existing Caddy instance via the Settings UI.
type CaddyConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	AdminURL    string `mapstructure:"admin_url"`
	ACMEEmail   string `mapstructure:"acme_email"`
	ListenHTTP  string `mapstructure:"listen_http"`
	ListenHTTPS string `mapstructure:"listen_https"`
}

// NginxConfig holds nginx reverse proxy configuration.
// When enabled, usulnet manages nginx configuration files and Let's Encrypt
// certificates directly. This is the default/recommended proxy backend.
type NginxConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	ConfigDir      string `mapstructure:"config_dir"`
	CertDir        string `mapstructure:"cert_dir"`
	ACMEEmail      string `mapstructure:"acme_email"`
	ACMEWebRoot    string `mapstructure:"acme_web_root"`
	ACMEAccountDir string `mapstructure:"acme_account_dir"`
	ListenHTTP     string `mapstructure:"listen_http"`
	ListenHTTPS    string `mapstructure:"listen_https"`
}

// MinIOConfig holds MinIO/S3 configuration.
// S3 connections are managed manually via the Settings UI.
type MinIOConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
	File   struct {
		Path       string `mapstructure:"path"`
		MaxSize    string `mapstructure:"max_size"`
		MaxBackups int    `mapstructure:"max_backups"`
		MaxAge     int    `mapstructure:"max_age"`
		Compress   bool   `mapstructure:"compress"`
	} `mapstructure:"file"`
}

// MetricsConfig holds Prometheus metrics configuration
type MetricsConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	Path           string `mapstructure:"path"`
	GoMetrics      bool   `mapstructure:"go_metrics"`
	ProcessMetrics bool   `mapstructure:"process_metrics"`
}

// ObservabilityConfig holds OpenTelemetry tracing and distributed observability settings.
type ObservabilityConfig struct {
	Tracing TracingConfig `mapstructure:"tracing"`
}

// TracingConfig holds distributed tracing configuration.
type TracingConfig struct {
	// Enabled activates OpenTelemetry tracing. Default: false.
	Enabled bool `mapstructure:"enabled"`
	// Exporter selects the trace exporter: "otlp" (default).
	Exporter string `mapstructure:"exporter"`
	// Endpoint is the collector endpoint (e.g. "localhost:4318" for OTLP/HTTP).
	Endpoint string `mapstructure:"endpoint"`
	// Insecure disables TLS for the exporter connection. Default: true.
	Insecure bool `mapstructure:"insecure"`
	// SamplingRate controls the fraction of traces sampled (0.0–1.0). Default: 0.1.
	SamplingRate float64 `mapstructure:"sampling_rate"`
}

// LoadConfig loads configuration from file and environment
func LoadConfig(cfgFile string) (*Config, error) {
	v := viper.New()

	// Config file settings
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath("/etc/usulnet")
		v.AddConfigPath("$HOME/.usulnet")
		v.AddConfigPath(".")
	}

	// Environment variables
	v.SetEnvPrefix("USULNET")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Dual-binding: USULNET_ prefixed (canonical) + unprefixed (Docker Compose compat).
	// BindEnv picks the first set: USULNET_DATABASE_URL takes priority over DATABASE_URL.
	_ = v.BindEnv("database.url", "USULNET_DATABASE_URL", "DATABASE_URL")
	_ = v.BindEnv("redis.url", "USULNET_REDIS_URL", "REDIS_URL")
	_ = v.BindEnv("nats.url", "USULNET_NATS_URL", "NATS_URL")
	_ = v.BindEnv("security.jwt_secret", "USULNET_JWT_SECRET", "JWT_SECRET")
	_ = v.BindEnv("security.config_encryption_key", "USULNET_ENCRYPTION_KEY", "CONFIG_ENCRYPTION_KEY")
	_ = v.BindEnv("storage.s3.access_key", "USULNET_S3_ACCESS_KEY", "S3_ACCESS_KEY")
	_ = v.BindEnv("storage.s3.secret_key", "USULNET_S3_SECRET_KEY", "S3_SECRET_KEY")
	_ = v.BindEnv("caddy.admin_url", "USULNET_CADDY_ADMIN_URL")
	_ = v.BindEnv("caddy.acme_email", "USULNET_CADDY_ACME_EMAIL")
	// Backwards-compatible bindings for legacy HOST_TERMINAL_* env vars
	_ = v.BindEnv("terminal.enabled", "USULNET_TERMINAL_ENABLED", "HOST_TERMINAL_ENABLED")
	_ = v.BindEnv("terminal.user", "USULNET_TERMINAL_USER", "HOST_TERMINAL_USER")
	_ = v.BindEnv("terminal.shell", "USULNET_TERMINAL_SHELL", "HOST_TERMINAL_SHELL")
	// Guacd (Apache Guacamole daemon) for web-based RDP
	_ = v.BindEnv("guacd.enabled", "USULNET_GUACD_ENABLED", "GUACD_ENABLED")
	_ = v.BindEnv("guacd.host", "USULNET_GUACD_HOST", "GUACD_HOST")
	_ = v.BindEnv("guacd.port", "USULNET_GUACD_PORT", "GUACD_PORT")
	// Docker socket path (for rootless Docker or custom socket locations)
	_ = v.BindEnv("docker.socket", "USULNET_DOCKER_SOCKET", "DOCKER_SOCKET")
	// Opt-in TLS for the in-cluster Postgres / Redis / NATS links.
	// Off by default; flipping to true makes the compose entrypoints
	// generate self-signed certs and rewires the application URL scheme.
	_ = v.BindEnv("server.tls.local_services", "USULNET_TLS_LOCAL_SERVICES")

	// Set defaults
	setDefaults(v)

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundError) {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		// Config file not found, proceed with env vars and defaults
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	return &cfg, nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// Mode
	v.SetDefault("mode", "standalone")

	// Server
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.base_url", "http://localhost:8080")
	v.SetDefault("server.read_timeout", "30s")
	v.SetDefault("server.write_timeout", "30s")
	v.SetDefault("server.idle_timeout", "120s")
	v.SetDefault("server.shutdown_timeout", "10s")
	v.SetDefault("server.max_request_size", "50MB")
	v.SetDefault("server.rate_limit_rps", 100)
	v.SetDefault("server.rate_limit_burst", 200)
	v.SetDefault("server.https_port", 7443)
	v.SetDefault("server.tls.enabled", false)
	v.SetDefault("server.tls.auto_tls", true)
	v.SetDefault("server.tls.local_services", false)
	v.SetDefault("server.redirect_https", true)

	// Database (tuned to reduce connection churn under moderate load)
	v.SetDefault("database.ssl_mode", "prefer")
	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 10)
	v.SetDefault("database.conn_max_lifetime", "30m")
	v.SetDefault("database.conn_max_idle_time", "5m")
	v.SetDefault("database.query_timeout", "30s")

	// Redis
	v.SetDefault("redis.pool_size", 10)
	v.SetDefault("redis.min_idle_conns", 5)
	v.SetDefault("redis.dial_timeout", "5s")
	v.SetDefault("redis.read_timeout", "3s")
	v.SetDefault("redis.write_timeout", "3s")

	// NATS
	v.SetDefault("nats.name", "usulnet")
	v.SetDefault("nats.max_reconnects", -1)
	v.SetDefault("nats.reconnect_wait", "2s")
	v.SetDefault("nats.jetstream.enabled", true)

	// Security
	v.SetDefault("security.jwt_expiry", "24h")
	v.SetDefault("security.refresh_expiry", "168h") // 7 days
	v.SetDefault("security.cookie_secure", true)
	v.SetDefault("security.cookie_samesite", "strict")
	v.SetDefault("security.password_min_length", 8)
	v.SetDefault("security.password_require_uppercase", true)
	v.SetDefault("security.password_require_number", true)
	v.SetDefault("security.password_require_special", false)
	v.SetDefault("security.max_failed_logins", 5)
	v.SetDefault("security.lockout_duration", "15m")
	v.SetDefault("security.api_key_length", 32)

	// Storage
	v.SetDefault("storage.type", "local")
	v.SetDefault("storage.path", "/var/lib/usulnet")
	v.SetDefault("storage.backup.compression", "zstd")
	v.SetDefault("storage.backup.compression_level", 3)
	v.SetDefault("storage.backup.default_retention_days", 30)
	v.SetDefault("storage.s3.use_ssl", true)

	// Agent
	v.SetDefault("agent.heartbeat_interval", "30s")
	v.SetDefault("agent.inventory_interval", "5m")
	v.SetDefault("agent.metrics_interval", "1m")
	v.SetDefault("agent.reconnect_delay", "5s")
	v.SetDefault("agent.max_reconnect_delay", "5m")

	// Trivy
	v.SetDefault("trivy.enabled", true)
	v.SetDefault("trivy.cache_dir", "/var/lib/usulnet/trivy")
	v.SetDefault("trivy.timeout", "5m")
	v.SetDefault("trivy.severity", "CRITICAL,HIGH,MEDIUM")
	v.SetDefault("trivy.ignore_unfixed", false)
	v.SetDefault("trivy.update_db_on_start", true)

	// Caddy reverse proxy (connect your existing Caddy instance via Settings)
	v.SetDefault("caddy.admin_url", "")
	v.SetDefault("caddy.acme_email", "")
	v.SetDefault("caddy.listen_http", ":80")
	v.SetDefault("caddy.listen_https", ":443")

	// Logging
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output", "stdout")
	v.SetDefault("logging.file.max_size", "100MB")
	v.SetDefault("logging.file.max_backups", 5)
	v.SetDefault("logging.file.max_age", 30)
	v.SetDefault("logging.file.compress", true)

	// Metrics
	v.SetDefault("metrics.enabled", true)
	v.SetDefault("metrics.path", "/metrics")
	v.SetDefault("metrics.go_metrics", true)
	v.SetDefault("metrics.process_metrics", true)

	// Observability / Tracing
	v.SetDefault("observability.tracing.enabled", false)
	v.SetDefault("observability.tracing.exporter", "otlp")
	v.SetDefault("observability.tracing.endpoint", "localhost:4318")
	v.SetDefault("observability.tracing.insecure", true)
	v.SetDefault("observability.tracing.sampling_rate", 0.1)

	// Host Terminal (migrated from HOST_TERMINAL_* env vars)
	v.SetDefault("terminal.enabled", true)
	v.SetDefault("terminal.user", "nobody_usulnet")
	v.SetDefault("terminal.shell", "/bin/bash")

	// Docker socket path (empty = auto-detect at startup)
	v.SetDefault("docker.socket", "")

	// Guacd (Apache Guacamole daemon) for web-based RDP
	v.SetDefault("guacd.enabled", true)
	v.SetDefault("guacd.host", "guacd")
	v.SetDefault("guacd.port", 4822)

	// Recon / privacy module (disabled by default — see docs/recon.md §7)
	v.SetDefault("recon.enabled", false)
	v.SetDefault("recon.retention_days", 90)
	v.SetDefault("recon.max_concurrent_scans", 2)
	v.SetDefault("recon.installation_org", "")
	v.SetDefault("recon.base_url", "")
	v.SetDefault("recon.spiderfoot.listen", "127.0.0.1:5001")
	v.SetDefault("recon.egress.allowlist", []string{})
	v.SetDefault("recon.connectors.hibp.enabled", false)
	v.SetDefault("recon.connectors.shodan.enabled", false)

	// Image Builder (v26.5.1 — port from v26.2.7). Defaults match
	// imagebuilder.DefaultConfig: 256 MiB context cap, 64 KiB log tail
	// persisted to the row. Live logs stream through Redis pub/sub on
	// the imagebuilder:logs channel prefix.
	v.SetDefault("image_builder.max_context_bytes", int64(256*1024*1024))
	v.SetDefault("image_builder.log_tail_bytes", 64*1024)
	v.SetDefault("image_builder.log_channel_prefix", "imagebuilder:logs")

	// Optional image signing hook on successful builds. Off by default;
	// turn on with `image_sign.enabled=true` (and have cosign on PATH).
	v.SetDefault("image_sign.enabled", false)
}

// Validate validates the configuration.
// Collects all errors so the operator can fix them in one pass.
func (c *Config) Validate() error {
	var errs []error

	// Mode validation
	validModes := map[string]bool{"standalone": true, "master": true, "agent": true}
	if !validModes[c.Mode] {
		errs = append(errs, fmt.Errorf("invalid mode: %s (must be standalone, master, or agent)", c.Mode))
	}

	// Database URL required for master/standalone
	if c.Mode != "agent" && c.Database.URL == "" {
		errs = append(errs, fmt.Errorf("database.url is required for %s mode", c.Mode))
	}

	// Redis URL required for master/standalone
	if c.Mode != "agent" && c.Redis.URL == "" {
		errs = append(errs, fmt.Errorf("redis.url is required for %s mode", c.Mode))
	}

	// NATS URL required for master/agent
	if c.Mode != "standalone" && c.NATS.URL == "" {
		errs = append(errs, fmt.Errorf("nats.url is required for %s mode", c.Mode))
	}

	// Agent-specific validation
	if c.Mode == "agent" {
		if c.Agent.MasterURL == "" {
			errs = append(errs, fmt.Errorf("agent.master_url is required for agent mode"))
		}
		if c.Agent.Token == "" {
			errs = append(errs, fmt.Errorf("agent.token is required for agent mode"))
		}
	}

	// Security validation for master/standalone
	if c.Mode != "agent" {
		if c.Security.JWTSecret == "" {
			errs = append(errs, fmt.Errorf("security.jwt_secret is required"))
		} else if len(c.Security.JWTSecret) < 32 {
			errs = append(errs, fmt.Errorf("security.jwt_secret must be at least 32 characters"))
		}
	}

	// Encryption key validation (64 hex chars = 32 bytes for AES-256)
	if c.Mode != "agent" && c.Security.ConfigEncryptionKey != "" {
		if len(c.Security.ConfigEncryptionKey) != 64 {
			errs = append(errs, fmt.Errorf("security.config_encryption_key must be exactly 64 hex characters (got %d)", len(c.Security.ConfigEncryptionKey)))
		}
	}

	// Storage validation
	if c.Storage.Type == "s3" {
		if c.Storage.S3.Bucket == "" {
			errs = append(errs, fmt.Errorf("storage.s3.bucket is required when using S3 storage"))
		}
		if c.Storage.S3.AccessKey == "" || c.Storage.S3.SecretKey == "" {
			errs = append(errs, fmt.Errorf("storage.s3 credentials are required when using S3 storage"))
		}
	}

	// TLS validation: custom cert/key required when auto_tls is disabled
	if c.Server.TLS.Enabled && !c.Server.TLS.AutoTLS {
		if c.Server.TLS.CertFile == "" || c.Server.TLS.KeyFile == "" {
			errs = append(errs, fmt.Errorf("server.tls.cert_file and server.tls.key_file are required when tls.enabled=true and tls.auto_tls=false"))
		}
	}

	// NATS TLS validation
	if c.NATS.TLS.Enabled {
		if c.NATS.TLS.CertFile == "" || c.NATS.TLS.KeyFile == "" {
			errs = append(errs, fmt.Errorf("nats.tls.cert_file and nats.tls.key_file are required when nats.tls.enabled=true"))
		}
	}

	// Agent TLS validation
	if c.Mode == "agent" && c.Agent.TLSEnabled {
		if c.Agent.TLSCertFile == "" || c.Agent.TLSKeyFile == "" {
			errs = append(errs, fmt.Errorf("agent.tls_cert_file and agent.tls_key_file are required when agent.tls_enabled=true"))
		}
	}

	// Logging file path required when output is "file"
	if strings.EqualFold(c.Logging.Output, "file") && c.Logging.File.Path == "" {
		errs = append(errs, fmt.Errorf("logging.file.path is required when logging.output=file"))
	}

	// Tracing endpoint required when enabled
	if c.Observability.Tracing.Enabled && c.Observability.Tracing.Endpoint == "" {
		errs = append(errs, fmt.Errorf("observability.tracing.endpoint is required when tracing is enabled"))
	}

	// Sampling rate bounds
	if c.Observability.Tracing.Enabled && (c.Observability.Tracing.SamplingRate < 0 || c.Observability.Tracing.SamplingRate > 1) {
		errs = append(errs, fmt.Errorf("observability.tracing.sampling_rate must be between 0.0 and 1.0 (got %f)", c.Observability.Tracing.SamplingRate))
	}

	// Port validation
	errs = append(errs, c.validatePorts()...)

	// Duration validation
	errs = append(errs, c.validateDurations()...)

	// Enum validation
	errs = append(errs, c.validateEnums()...)

	// Relationship validation
	errs = append(errs, c.validateRelationships()...)

	if len(errs) == 0 {
		return nil
	}
	// Join all errors with newlines for readable operator output
	var msgs []string
	for _, e := range errs {
		msgs = append(msgs, e.Error())
	}
	return fmt.Errorf("config validation failed:\n  - %s", strings.Join(msgs, "\n  - "))
}

// validatePorts checks that port values are in the valid range.
func (c *Config) validatePorts() []error {
	var errs []error
	checkPort := func(name string, port int) {
		if port != 0 && (port < 1 || port > 65535) {
			errs = append(errs, fmt.Errorf("%s: %d is not a valid port (1-65535)", name, port))
		}
	}
	checkPort("server.port", c.Server.Port)
	checkPort("server.https_port", c.Server.HTTPSPort)
	return errs
}

// validateDurations checks that duration values are positive where required.
func (c *Config) validateDurations() []error {
	var errs []error
	checkPositive := func(name string, d time.Duration) {
		if d < 0 {
			errs = append(errs, fmt.Errorf("%s must be non-negative, got %s", name, d))
		}
	}
	// Server timeouts
	checkPositive("server.read_timeout", c.Server.ReadTimeout)
	checkPositive("server.write_timeout", c.Server.WriteTimeout)
	checkPositive("server.idle_timeout", c.Server.IdleTimeout)
	checkPositive("server.shutdown_timeout", c.Server.ShutdownTimeout)
	// Database
	checkPositive("database.conn_max_lifetime", c.Database.ConnMaxLifetime)
	checkPositive("database.conn_max_idle_time", c.Database.ConnMaxIdleTime)
	checkPositive("database.query_timeout", c.Database.QueryTimeout)
	// Redis
	checkPositive("redis.dial_timeout", c.Redis.DialTimeout)
	checkPositive("redis.read_timeout", c.Redis.ReadTimeout)
	checkPositive("redis.write_timeout", c.Redis.WriteTimeout)
	// Security
	checkPositive("security.jwt_expiry", c.Security.JWTExpiry)
	checkPositive("security.refresh_expiry", c.Security.RefreshExpiry)
	checkPositive("security.lockout_duration", c.Security.LockoutDuration)
	return errs
}

// validateEnums checks that enum-like string fields have valid values.
func (c *Config) validateEnums() []error {
	var errs []error
	// Logging level
	if c.Logging.Level != "" {
		validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
		if !validLevels[strings.ToLower(c.Logging.Level)] {
			errs = append(errs, fmt.Errorf("logging.level: %q is not valid (debug, info, warn, error)", c.Logging.Level))
		}
	}
	// Logging format
	if c.Logging.Format != "" {
		validFormats := map[string]bool{"json": true, "text": true, "console": true}
		if !validFormats[strings.ToLower(c.Logging.Format)] {
			errs = append(errs, fmt.Errorf("logging.format: %q is not valid (json, text, console)", c.Logging.Format))
		}
	}
	// Storage type
	if c.Storage.Type != "" {
		validTypes := map[string]bool{"local": true, "s3": true}
		if !validTypes[strings.ToLower(c.Storage.Type)] {
			errs = append(errs, fmt.Errorf("storage.type: %q is not valid (local, s3)", c.Storage.Type))
		}
	}
	// Cookie SameSite
	if c.Security.CookieSameSite != "" {
		validSS := map[string]bool{"strict": true, "lax": true, "none": true}
		if !validSS[strings.ToLower(c.Security.CookieSameSite)] {
			errs = append(errs, fmt.Errorf("security.cookie_samesite: %q is not valid (strict, lax, none)", c.Security.CookieSameSite))
		}
	}
	return errs
}

// validateRelationships checks cross-field constraints.
func (c *Config) validateRelationships() []error {
	var errs []error
	// MaxIdleConns should not exceed MaxOpenConns
	if c.Database.MaxIdleConns > 0 && c.Database.MaxOpenConns > 0 && c.Database.MaxIdleConns > c.Database.MaxOpenConns {
		errs = append(errs, fmt.Errorf("database.max_idle_conns (%d) must not exceed database.max_open_conns (%d)",
			c.Database.MaxIdleConns, c.Database.MaxOpenConns))
	}
	// Redis MinIdleConns vs PoolSize
	if c.Redis.MinIdleConns > 0 && c.Redis.PoolSize > 0 && c.Redis.MinIdleConns > c.Redis.PoolSize {
		errs = append(errs, fmt.Errorf("redis.min_idle_conns (%d) must not exceed redis.pool_size (%d)",
			c.Redis.MinIdleConns, c.Redis.PoolSize))
	}
	// Port conflict
	if c.Server.Port > 0 && c.Server.HTTPSPort > 0 && c.Server.Port == c.Server.HTTPSPort {
		errs = append(errs, fmt.Errorf("server.port and server.https_port must not be the same (%d)", c.Server.Port))
	}
	// RefreshExpiry should be >= JWTExpiry
	if c.Security.JWTExpiry > 0 && c.Security.RefreshExpiry > 0 && c.Security.RefreshExpiry < c.Security.JWTExpiry {
		errs = append(errs, fmt.Errorf("security.refresh_expiry (%s) should be >= security.jwt_expiry (%s)",
			c.Security.RefreshExpiry, c.Security.JWTExpiry))
	}
	// PasswordMinLength
	if c.Security.PasswordMinLength > 0 && c.Security.PasswordMinLength < 8 {
		errs = append(errs, fmt.Errorf("security.password_min_length (%d) should be at least 8", c.Security.PasswordMinLength))
	}
	// RateLimitRPS and Burst
	if c.Server.RateLimitRPS < 0 {
		errs = append(errs, fmt.Errorf("server.rate_limit_rps must be non-negative"))
	}
	if c.Server.RateLimitBurst < 0 {
		errs = append(errs, fmt.Errorf("server.rate_limit_burst must be non-negative"))
	}
	return errs
}

// PrintMasked prints configuration with sensitive values masked
func (c *Config) PrintMasked() {
	fmt.Printf("Mode: %s\n", c.Mode)
	fmt.Printf("Server: %s:%d\n", c.Server.Host, c.Server.Port)
	if c.Server.TLS.Enabled {
		fmt.Printf("HTTPS: %s:%d (auto_tls: %v)\n", c.Server.Host, c.Server.HTTPSPort, c.Server.TLS.AutoTLS)
	}
	fmt.Printf("Database URL: %s\n", maskURL(c.Database.URL))
	fmt.Printf("Redis URL: %s\n", maskURL(c.Redis.URL))
	fmt.Printf("NATS URL: %s\n", maskURL(c.NATS.URL))
	if c.Docker.Socket != "" {
		fmt.Printf("Docker Socket: %s\n", c.Docker.Socket)
	} else {
		fmt.Printf("Docker Socket: <auto-detect>\n")
	}
	fmt.Printf("Storage Type: %s\n", c.Storage.Type)
	fmt.Printf("Storage Path: %s\n", c.Storage.Path)
	fmt.Printf("Log Level: %s\n", c.Logging.Level)
	fmt.Printf("Log Format: %s\n", c.Logging.Format)
	fmt.Printf("Metrics Enabled: %v\n", c.Metrics.Enabled)
	fmt.Printf("Trivy Enabled: %v\n", c.Trivy.Enabled)
	fmt.Printf("Caddy Enabled: %v\n", c.Caddy.Enabled)
	if c.Caddy.Enabled {
		fmt.Printf("Caddy Admin URL: %s\n", c.Caddy.AdminURL)
	}
}

// EffectiveDatabaseURL returns Database.URL with sslmode appended from
// Database.SSLMode when the URL does not already carry an sslmode= query
// parameter. The original URL is returned untouched when SSLMode is
// empty or the URL already specifies one. Used by the application Run
// path and the standalone migrate / admin commands so both observe the
// same effective DSN.
func (c *Config) EffectiveDatabaseURL() string {
	u := c.Database.URL
	if c.Database.SSLMode == "" || strings.Contains(u, "sslmode=") {
		return u
	}
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	return u + sep + "sslmode=" + c.Database.SSLMode
}

// parseSameSite converts a config string ("strict", "lax", "none") to http.SameSite.
// Returns http.SameSiteLaxMode for unrecognized values.
func parseSameSite(s string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

// parseSize parses a human-readable size string (e.g., "100MB", "1GB") to bytes.
// Returns defaultBytes if the string is empty or unparseable.
func parseSize(s string, defaultBytes int64) int64 {
	if s == "" {
		return defaultBytes
	}
	s = strings.TrimSpace(strings.ToUpper(s))
	multiplier := int64(1)
	switch {
	case strings.HasSuffix(s, "GB"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "GB")
	case strings.HasSuffix(s, "MB"):
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "KB"):
		multiplier = 1024
		s = strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "B"):
		s = strings.TrimSuffix(s, "B")
	}
	var n int64
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n); err != nil {
		return defaultBytes
	}
	return n * multiplier
}

// maskURL masks password in URL
func maskURL(url string) string {
	if url == "" {
		return "<not set>"
	}
	// Simple masking - replace password in URL
	// postgres://user:password@host -> postgres://user:***@host
	parts := strings.SplitN(url, "@", 2)
	if len(parts) == 2 {
		authParts := strings.SplitN(parts[0], ":", 3)
		if len(authParts) == 3 {
			return authParts[0] + ":" + authParts[1] + ":***@" + parts[1]
		}
	}
	return url
}
