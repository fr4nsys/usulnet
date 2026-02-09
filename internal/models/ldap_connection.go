// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// LDAPConnectionStatus represents the connection status.
type LDAPConnectionStatus string

const (
	LDAPStatusConnected    LDAPConnectionStatus = "connected"
	LDAPStatusDisconnected LDAPConnectionStatus = "disconnected"
	LDAPStatusError        LDAPConnectionStatus = "error"
)

// LDAPConnection represents a stored LDAP connection for browser functionality.
type LDAPConnection struct {
	ID              uuid.UUID            `db:"id" json:"id"`
	UserID          uuid.UUID            `db:"user_id" json:"user_id"`
	Name            string               `db:"name" json:"name"`
	Host            string               `db:"host" json:"host"`
	Port            int                  `db:"port" json:"port"`
	UseTLS          bool                 `db:"use_tls" json:"use_tls"`
	StartTLS        bool                 `db:"start_tls" json:"start_tls"`
	SkipTLSVerify   bool                 `db:"skip_tls_verify" json:"skip_tls_verify"`
	BindDN          string               `db:"bind_dn" json:"bind_dn"`
	BindPassword    string               `db:"bind_password" json:"-"` // encrypted
	BaseDN          string               `db:"base_dn" json:"base_dn"`
	Status          LDAPConnectionStatus `db:"status" json:"status"`
	StatusMessage   string               `db:"status_message" json:"status_message,omitempty"`
	LastChecked     *time.Time           `db:"last_checked" json:"last_checked,omitempty"`
	LastConnectedAt *time.Time           `db:"last_connected_at" json:"last_connected_at,omitempty"`
	CreatedAt       time.Time            `db:"created_at" json:"created_at"`
	UpdatedAt       time.Time            `db:"updated_at" json:"updated_at"`
}

// CreateLDAPConnectionInput is the input for creating an LDAP connection.
type CreateLDAPConnectionInput struct {
	Name          string `json:"name" validate:"required,min=1,max=100"`
	Host          string `json:"host" validate:"required"`
	Port          int    `json:"port" validate:"required,min=1,max=65535"`
	UseTLS        bool   `json:"use_tls"`
	StartTLS      bool   `json:"start_tls"`
	SkipTLSVerify bool   `json:"skip_tls_verify"`
	BindDN        string `json:"bind_dn" validate:"required"`
	BindPassword  string `json:"bind_password" validate:"required"`
	BaseDN        string `json:"base_dn" validate:"required"`
}

// UpdateLDAPConnectionInput is the input for updating an LDAP connection.
type UpdateLDAPConnectionInput struct {
	Name          *string `json:"name,omitempty"`
	Host          *string `json:"host,omitempty"`
	Port          *int    `json:"port,omitempty"`
	UseTLS        *bool   `json:"use_tls,omitempty"`
	StartTLS      *bool   `json:"start_tls,omitempty"`
	SkipTLSVerify *bool   `json:"skip_tls_verify,omitempty"`
	BindDN        *string `json:"bind_dn,omitempty"`
	BindPassword  *string `json:"bind_password,omitempty"`
	BaseDN        *string `json:"base_dn,omitempty"`
}

// LDAPEntry represents an LDAP directory entry.
type LDAPEntry struct {
	DN          string            `json:"dn"`
	RDN         string            `json:"rdn"`
	ObjectClass []string          `json:"object_class"`
	Attributes  map[string][]string `json:"attributes"`
	HasChildren bool              `json:"has_children"`
}

// LDAPSearchResult represents the result of an LDAP search.
type LDAPSearchResult struct {
	Entries     []LDAPEntry `json:"entries"`
	TotalCount  int         `json:"total_count"`
	SearchTime  time.Duration `json:"search_time"`
	BaseDN      string      `json:"base_dn"`
	Filter      string      `json:"filter"`
	Scope       string      `json:"scope"`
}

// LDAPTestResulter interface for LDAP connection test results.
type LDAPTestResulter interface {
	IsSuccess() bool
	GetMessage() string
	GetLatency() time.Duration
}
