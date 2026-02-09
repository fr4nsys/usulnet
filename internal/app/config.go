// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all application configuration
type Config struct {
	Mode     string         `mapstructure:"mode"`
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Redis    RedisConfig    `mapstructure:"redis"`
	NATS     NATSConfig     `mapstructure:"nats"`
	Security SecurityConfig `mapstructure:"security"`
	Storage  StorageConfig  `mapstructure:"storage"`
	Agent    AgentConfig    `mapstructure:"agent"`
	Trivy    TrivyConfig    `mapstructure:"trivy"`
	NPM      NPMConfig      `mapstructure:"npm"`
	Caddy    CaddyConfig    `mapstructure:"caddy"`
	Minio    MinIOConfig    `mapstructure:"minio"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Metrics  MetricsConfig  `mapstructure:"metrics"`
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
}

// DatabaseConfig holds PostgreSQL configuration
type DatabaseConfig struct {
	URL             string        `mapstructure:"url"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `mapstructure:"conn_max_idle_time"`
	QueryTimeout    time.Duration `mapstructure:"query_timeout"`
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	URL          string        `mapstructure:"url"`
	PoolSize     int           `mapstructure:"pool_size"`
	MinIdleConns int           `mapstructure:"min_idle_conns"`
	DialTimeout  time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
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

	// Allow direct env vars for common settings
	_ = v.BindEnv("database.url", "DATABASE_URL")
	_ = v.BindEnv("redis.url", "REDIS_URL")
	_ = v.BindEnv("nats.url", "NATS_URL")
	_ = v.BindEnv("security.jwt_secret", "JWT_SECRET")
	_ = v.BindEnv("security.config_encryption_key", "CONFIG_ENCRYPTION_KEY")
	_ = v.BindEnv("storage.s3.access_key", "S3_ACCESS_KEY")
	_ = v.BindEnv("storage.s3.secret_key", "S3_SECRET_KEY")
	_ = v.BindEnv("caddy.admin_url", "USULNET_CADDY_ADMIN_URL")
	_ = v.BindEnv("caddy.acme_email", "USULNET_CADDY_ACME_EMAIL")

	// Set defaults
	setDefaults(v)

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
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

	// Database (tuned to reduce connection churn under moderate load)
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
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Mode validation
	validModes := map[string]bool{"standalone": true, "master": true, "agent": true}
	if !validModes[c.Mode] {
		return fmt.Errorf("invalid mode: %s (must be standalone, master, or agent)", c.Mode)
	}

	// Database URL required for master/standalone
	if c.Mode != "agent" && c.Database.URL == "" {
		return fmt.Errorf("database.url is required for %s mode", c.Mode)
	}

	// Redis URL required for master/standalone
	if c.Mode != "agent" && c.Redis.URL == "" {
		return fmt.Errorf("redis.url is required for %s mode", c.Mode)
	}

	// NATS URL required for master/agent
	if c.Mode != "standalone" && c.NATS.URL == "" {
		return fmt.Errorf("nats.url is required for %s mode", c.Mode)
	}

	// Agent-specific validation
	if c.Mode == "agent" {
		if c.Agent.MasterURL == "" {
			return fmt.Errorf("agent.master_url is required for agent mode")
		}
		if c.Agent.Token == "" {
			return fmt.Errorf("agent.token is required for agent mode")
		}
	}

	// Security validation for master/standalone
	if c.Mode != "agent" {
		if c.Security.JWTSecret == "" {
			return fmt.Errorf("security.jwt_secret is required")
		}
		if len(c.Security.JWTSecret) < 32 {
			return fmt.Errorf("security.jwt_secret must be at least 32 characters")
		}
	}

	// Storage validation
	if c.Storage.Type == "s3" {
		if c.Storage.S3.Bucket == "" {
			return fmt.Errorf("storage.s3.bucket is required when using S3 storage")
		}
		if c.Storage.S3.AccessKey == "" || c.Storage.S3.SecretKey == "" {
			return fmt.Errorf("storage.s3 credentials are required when using S3 storage")
		}
	}

	return nil
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
