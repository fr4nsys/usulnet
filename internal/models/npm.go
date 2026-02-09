// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import "time"

// NPMConnection represents the connection configuration to an NPM instance.
type NPMConnection struct {
	ID                    string    `json:"id" db:"id"`
	HostID                string    `json:"host_id" db:"host_id"`
	BaseURL               string    `json:"base_url" db:"base_url"`
	AdminEmail            string    `json:"admin_email" db:"admin_email"`
	AdminPasswordEncrypted string   `json:"-" db:"admin_password_encrypted"` // Never expose
	IsEnabled             bool      `json:"is_enabled" db:"is_enabled"`
	LastHealthCheck       *time.Time `json:"last_health_check,omitempty" db:"last_health_check"`
	HealthStatus          string    `json:"health_status" db:"health_status"`
	HealthMessage         string    `json:"health_message,omitempty" db:"health_message"`
	CreatedAt             time.Time `json:"created_at" db:"created_at"`
	UpdatedAt             time.Time `json:"updated_at" db:"updated_at"`
	CreatedBy             *string   `json:"created_by,omitempty" db:"created_by"`
	UpdatedBy             *string   `json:"updated_by,omitempty" db:"updated_by"`
}

// NPMConnectionCreate represents data to create a new NPM connection.
type NPMConnectionCreate struct {
	HostID        string `json:"host_id" validate:"required,uuid"`
	BaseURL       string `json:"base_url" validate:"required,url"`
	AdminEmail    string `json:"admin_email" validate:"required,email"`
	AdminPassword string `json:"admin_password" validate:"required,min=6"`
}

// NPMConnectionUpdate represents data to update an NPM connection.
type NPMConnectionUpdate struct {
	BaseURL       *string `json:"base_url,omitempty"`
	AdminEmail    *string `json:"admin_email,omitempty"`
	AdminPassword *string `json:"admin_password,omitempty"`
	IsEnabled     *bool   `json:"is_enabled,omitempty"`
}

// ContainerProxyMapping maps a Docker container to an NPM proxy host.
type ContainerProxyMapping struct {
	ID             string    `json:"id" db:"id"`
	HostID         string    `json:"host_id" db:"host_id"`
	ContainerID    string    `json:"container_id" db:"container_id"`
	ContainerName  string    `json:"container_name" db:"container_name"`
	NPMProxyHostID int       `json:"npm_proxy_host_id" db:"npm_proxy_host_id"`
	AutoCreated    bool      `json:"auto_created" db:"auto_created"`
	DomainSource   string    `json:"domain_source" db:"domain_source"` // 'label', 'manual', 'container_name'
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

// NPMAuditLog represents an audit log entry for NPM operations.
type NPMAuditLog struct {
	ID           string                 `json:"id" db:"id"`
	HostID       string                 `json:"host_id" db:"host_id"`
	UserID       *string                `json:"user_id,omitempty" db:"user_id"`
	Operation    string                 `json:"operation" db:"operation"`
	ResourceType string                 `json:"resource_type" db:"resource_type"`
	ResourceID   int                    `json:"resource_id" db:"resource_id"`
	ResourceName string                 `json:"resource_name,omitempty" db:"resource_name"`
	Details      map[string]interface{} `json:"details,omitempty" db:"details"`
	CreatedAt    time.Time              `json:"created_at" db:"created_at"`
}

// NPM Operation types
const (
	NPMOperationCreate  = "create"
	NPMOperationUpdate  = "update"
	NPMOperationDelete  = "delete"
	NPMOperationEnable  = "enable"
	NPMOperationDisable = "disable"
)

// NPM Resource types
const (
	NPMResourceProxyHost   = "proxy_host"
	NPMResourceRedirection = "redirection"
	NPMResourceStream      = "stream"
	NPMResourceDeadHost    = "dead_host"
	NPMResourceCertificate = "certificate"
	NPMResourceAccessList  = "access_list"
)

// NPM Health status
const (
	NPMHealthStatusHealthy   = "healthy"
	NPMHealthStatusUnhealthy = "unhealthy"
	NPMHealthStatusUnknown   = "unknown"
)

// AutoProxyLabels defines the Docker labels for auto-proxy feature.
// Example: com.usulnet.proxy.domain=example.com
const (
	LabelProxyDomain      = "com.usulnet.proxy.domain"       // Domain name
	LabelProxyPort        = "com.usulnet.proxy.port"         // Backend port (default: first exposed)
	LabelProxyScheme      = "com.usulnet.proxy.scheme"       // http/https (default: http)
	LabelProxySSL         = "com.usulnet.proxy.ssl"          // Enable SSL (default: true if domain set)
	LabelProxySSLForced   = "com.usulnet.proxy.ssl_forced"   // Force HTTPS (default: true)
	LabelProxyWebsocket   = "com.usulnet.proxy.websocket"    // Enable WebSocket (default: false)
	LabelProxyBlockExploit = "com.usulnet.proxy.block_exploits" // Block exploits (default: true)
)

// AutoProxyConfig represents the configuration extracted from container labels.
type AutoProxyConfig struct {
	ContainerID   string
	ContainerName string
	Domain        string
	Port          int
	Scheme        string
	SSL           bool
	SSLForced     bool
	Websocket     bool
	BlockExploits bool
}
