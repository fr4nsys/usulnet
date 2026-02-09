// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// SSHKeyType represents the type of SSH key.
type SSHKeyType string

const (
	SSHKeyTypeRSA     SSHKeyType = "rsa"
	SSHKeyTypeED25519 SSHKeyType = "ed25519"
	SSHKeyTypeECDSA   SSHKeyType = "ecdsa"
)

// SSHKey represents a stored SSH key pair.
type SSHKey struct {
	ID          uuid.UUID  `db:"id" json:"id"`
	Name        string     `db:"name" json:"name"`
	KeyType     SSHKeyType `db:"key_type" json:"key_type"`
	PublicKey   string     `db:"public_key" json:"public_key"`
	PrivateKey  string     `db:"private_key" json:"-"`           // Encrypted, never exposed in JSON
	Passphrase  string     `db:"passphrase" json:"-"`            // Encrypted passphrase for the key
	Fingerprint string     `db:"fingerprint" json:"fingerprint"` // SSH fingerprint (SHA256)
	Comment     string     `db:"comment" json:"comment,omitempty"`
	CreatedBy   uuid.UUID  `db:"created_by" json:"created_by"`
	CreatedAt   time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time  `db:"updated_at" json:"updated_at"`
	LastUsed    *time.Time `db:"last_used" json:"last_used,omitempty"`
}

// SSHAuthType represents the authentication method for SSH.
type SSHAuthType string

const (
	SSHAuthPassword  SSHAuthType = "password"
	SSHAuthKey       SSHAuthType = "key"
	SSHAuthAgent     SSHAuthType = "agent"
	SSHAuthKeyboard  SSHAuthType = "keyboard" // keyboard-interactive
)

// SSHConnectionStatus represents the status of an SSH connection.
type SSHConnectionStatus string

const (
	SSHConnectionActive   SSHConnectionStatus = "active"
	SSHConnectionInactive SSHConnectionStatus = "inactive"
	SSHConnectionError    SSHConnectionStatus = "error"
	SSHConnectionUnknown  SSHConnectionStatus = "unknown"
)

// SSHConnection represents a saved SSH connection profile.
type SSHConnection struct {
	ID          uuid.UUID             `db:"id" json:"id"`
	Name        string                `db:"name" json:"name"`
	Description string                `db:"description" json:"description,omitempty"`
	Host        string                `db:"host" json:"host"`
	Port        int                   `db:"port" json:"port"`
	Username    string                `db:"username" json:"username"`
	AuthType    SSHAuthType           `db:"auth_type" json:"auth_type"`
	KeyID       *uuid.UUID            `db:"key_id" json:"key_id,omitempty"`       // FK to SSHKey
	Password    string                `db:"password" json:"-"`                    // Encrypted, for password auth
	JumpHost    *uuid.UUID            `db:"jump_host" json:"jump_host,omitempty"` // FK to another SSHConnection (ProxyJump)
	Tags        []string              `db:"tags" json:"tags,omitempty"`           // JSON array in DB
	Category    string                `db:"category" json:"category,omitempty"`
	Status      SSHConnectionStatus   `db:"status" json:"status"`
	StatusMsg   string                `db:"status_message" json:"status_message,omitempty"`
	LastChecked *time.Time            `db:"last_checked" json:"last_checked,omitempty"`
	CreatedBy   uuid.UUID             `db:"created_by" json:"created_by"`
	CreatedAt   time.Time             `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time             `db:"updated_at" json:"updated_at"`

	// SSH options (stored as JSON in DB)
	Options SSHConnectionOptions `db:"options" json:"options,omitempty"`

	// Relations (not stored, populated on read)
	Key *SSHKey `db:"-" json:"key,omitempty"`
}

// SSHConnectionOptions contains advanced SSH options.
type SSHConnectionOptions struct {
	StrictHostKeyChecking bool              `json:"strict_host_key_checking"`
	HostKeyFingerprint    string            `json:"host_key_fingerprint,omitempty"` // SHA256 fingerprint, stored on first connect (TOFU)
	Compression           bool              `json:"compression"`
	KeepAliveInterval     int               `json:"keep_alive_interval,omitempty"` // seconds
	ConnectionTimeout     int               `json:"connection_timeout,omitempty"`  // seconds
	ForwardAgent          bool              `json:"forward_agent"`
	LocalForwards         []SSHPortForward  `json:"local_forwards,omitempty"`
	RemoteForwards        []SSHPortForward  `json:"remote_forwards,omitempty"`
	Environment           map[string]string `json:"environment,omitempty"`
}

// SSHPortForward represents a port forwarding rule.
type SSHPortForward struct {
	LocalHost  string `json:"local_host"`
	LocalPort  int    `json:"local_port"`
	RemoteHost string `json:"remote_host"`
	RemotePort int    `json:"remote_port"`
}

// SSHSession represents an active SSH session.
type SSHSession struct {
	ID           uuid.UUID  `db:"id" json:"id"`
	ConnectionID uuid.UUID  `db:"connection_id" json:"connection_id"`
	UserID       uuid.UUID  `db:"user_id" json:"user_id"`
	StartedAt    time.Time  `db:"started_at" json:"started_at"`
	EndedAt      *time.Time `db:"ended_at" json:"ended_at,omitempty"`
	ClientIP     string     `db:"client_ip" json:"client_ip"`
	TermType     string     `db:"term_type" json:"term_type"`
	TermCols     int        `db:"term_cols" json:"term_cols"`
	TermRows     int        `db:"term_rows" json:"term_rows"`
}

// CreateSSHKeyInput is the input for creating an SSH key.
type CreateSSHKeyInput struct {
	Name       string     `json:"name" validate:"required,max=100"`
	KeyType    SSHKeyType `json:"key_type" validate:"required,oneof=rsa ed25519 ecdsa"`
	PublicKey  string     `json:"public_key,omitempty"`  // If importing
	PrivateKey string     `json:"private_key,omitempty"` // If importing
	Passphrase string     `json:"passphrase,omitempty"`
	Comment    string     `json:"comment,omitempty"`
	Generate   bool       `json:"generate"` // If true, generate new key pair
	KeyBits    int        `json:"key_bits,omitempty"` // For RSA: 2048, 4096; for ECDSA: 256, 384, 521
}

// CreateSSHConnectionInput is the input for creating an SSH connection.
type CreateSSHConnectionInput struct {
	Name        string                `json:"name" validate:"required,max=100"`
	Description string                `json:"description,omitempty" validate:"max=500"`
	Host        string                `json:"host" validate:"required"`
	Port        int                   `json:"port" validate:"required,min=1,max=65535"`
	Username    string                `json:"username" validate:"max=100"`
	AuthType    SSHAuthType           `json:"auth_type" validate:"required,oneof=password key agent keyboard"`
	KeyID       *uuid.UUID            `json:"key_id,omitempty"`
	Password    string                `json:"password,omitempty"`
	JumpHost    *uuid.UUID            `json:"jump_host,omitempty"`
	Tags        []string              `json:"tags,omitempty"`
	Category    string                `json:"category,omitempty" validate:"max=50"`
	Options     *SSHConnectionOptions `json:"options,omitempty"`
}

// UpdateSSHConnectionInput is the input for updating an SSH connection.
type UpdateSSHConnectionInput struct {
	Name        *string               `json:"name,omitempty" validate:"omitempty,max=100"`
	Description *string               `json:"description,omitempty" validate:"omitempty,max=500"`
	Host        *string               `json:"host,omitempty"`
	Port        *int                  `json:"port,omitempty" validate:"omitempty,min=1,max=65535"`
	Username    *string               `json:"username,omitempty" validate:"omitempty,max=100"`
	AuthType    *SSHAuthType          `json:"auth_type,omitempty" validate:"omitempty,oneof=password key agent keyboard"`
	KeyID       *uuid.UUID            `json:"key_id,omitempty"`
	Password    *string               `json:"password,omitempty"`
	JumpHost    *uuid.UUID            `json:"jump_host,omitempty"`
	Tags        []string              `json:"tags,omitempty"`
	Category    *string               `json:"category,omitempty" validate:"omitempty,max=50"`
	Options     *SSHConnectionOptions `json:"options,omitempty"`
}

// SSHTestResult represents the result of testing an SSH connection.
type SSHTestResult struct {
	Success      bool      `json:"success"`
	Message      string    `json:"message"`
	Latency      int64     `json:"latency_ms"`      // Connection latency in milliseconds
	ServerInfo   string    `json:"server_info"`     // SSH server banner
	HostKey      string    `json:"host_key"`        // Server host key fingerprint
	TestedAt     time.Time `json:"tested_at"`
}

// SSHFileInfo represents file information from SFTP.
type SSHFileInfo struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	Size       int64     `json:"size"`
	Mode       string    `json:"mode"`       // Unix permissions string
	ModeOctal  string    `json:"mode_octal"` // e.g., "0755"
	IsDir      bool      `json:"is_dir"`
	IsLink     bool      `json:"is_link"`
	LinkTarget string    `json:"link_target,omitempty"`
	Owner      string    `json:"owner"`
	Group      string    `json:"group"`
	ModTime    time.Time `json:"mod_time"`
	AccessTime time.Time `json:"access_time,omitempty"`
}

// SFTPTransfer represents a file transfer operation.
type SFTPTransfer struct {
	ID            uuid.UUID `json:"id"`
	ConnectionID  uuid.UUID `json:"connection_id"`
	UserID        uuid.UUID `json:"user_id"`
	Operation     string    `json:"operation"` // "upload" or "download"
	LocalPath     string    `json:"local_path"`
	RemotePath    string    `json:"remote_path"`
	Size          int64     `json:"size"`
	BytesTransferred int64  `json:"bytes_transferred"`
	Status        string    `json:"status"` // "pending", "in_progress", "completed", "failed"
	Error         string    `json:"error,omitempty"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
}

// SSHTunnelType represents the type of SSH tunnel.
type SSHTunnelType string

const (
	SSHTunnelTypeLocal   SSHTunnelType = "local"   // -L: Local port forward
	SSHTunnelTypeRemote  SSHTunnelType = "remote"  // -R: Remote port forward
	SSHTunnelTypeDynamic SSHTunnelType = "dynamic" // -D: SOCKS proxy
)

// SSHTunnelStatus represents the status of an SSH tunnel.
type SSHTunnelStatus string

const (
	SSHTunnelStatusActive  SSHTunnelStatus = "active"
	SSHTunnelStatusStopped SSHTunnelStatus = "stopped"
	SSHTunnelStatusError   SSHTunnelStatus = "error"
)

// SSHTunnel represents a persistent SSH port forwarding tunnel configuration.
type SSHTunnel struct {
	ID           uuid.UUID       `db:"id" json:"id"`
	ConnectionID uuid.UUID       `db:"connection_id" json:"connection_id"`
	UserID       uuid.UUID       `db:"user_id" json:"user_id"`
	Type         SSHTunnelType   `db:"type" json:"type"`
	LocalHost    string          `db:"local_host" json:"local_host"`
	LocalPort    int             `db:"local_port" json:"local_port"`
	RemoteHost   string          `db:"remote_host" json:"remote_host"`
	RemotePort   int             `db:"remote_port" json:"remote_port"`
	Status       SSHTunnelStatus `db:"status" json:"status"`
	StatusMsg    string          `db:"status_message" json:"status_message,omitempty"`
	AutoStart    bool            `db:"auto_start" json:"auto_start"` // Start when connection opens
	CreatedAt    time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt    time.Time       `db:"updated_at" json:"updated_at"`
}

// CreateSSHTunnelInput is the input for creating an SSH tunnel.
type CreateSSHTunnelInput struct {
	ConnectionID uuid.UUID     `json:"connection_id" validate:"required"`
	Type         SSHTunnelType `json:"type" validate:"required,oneof=local remote dynamic"`
	LocalHost    string        `json:"local_host" validate:"required"`
	LocalPort    int           `json:"local_port" validate:"required,min=1,max=65535"`
	RemoteHost   string        `json:"remote_host,omitempty"` // Not required for dynamic
	RemotePort   int           `json:"remote_port,omitempty" validate:"omitempty,min=1,max=65535"`
	AutoStart    bool          `json:"auto_start"`
}
