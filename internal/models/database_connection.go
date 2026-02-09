// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// DatabaseTestResulter interface for database connection test results.
type DatabaseTestResulter interface {
	IsSuccess() bool
	GetMessage() string
	GetLatency() time.Duration
}

// DatabaseType represents the type of database.
type DatabaseType string

const (
	DatabaseTypePostgres DatabaseType = "postgres"
	DatabaseTypeMySQL    DatabaseType = "mysql"
	DatabaseTypeMariaDB  DatabaseType = "mariadb"
	DatabaseTypeMongoDB  DatabaseType = "mongodb"
	DatabaseTypeRedis    DatabaseType = "redis"
	DatabaseTypeSQLite   DatabaseType = "sqlite"
)

// DatabaseConnectionStatus represents the connection status.
type DatabaseConnectionStatus string

const (
	DatabaseStatusConnected    DatabaseConnectionStatus = "connected"
	DatabaseStatusDisconnected DatabaseConnectionStatus = "disconnected"
	DatabaseStatusError        DatabaseConnectionStatus = "error"
)

// DatabaseConnection represents a stored database connection configuration.
type DatabaseConnection struct {
	ID              uuid.UUID                `db:"id" json:"id"`
	UserID          uuid.UUID                `db:"user_id" json:"user_id"`
	Name            string                   `db:"name" json:"name"`
	Type            DatabaseType             `db:"type" json:"type"`
	Host            string                   `db:"host" json:"host"`
	Port            int                      `db:"port" json:"port"`
	Database        string                   `db:"database" json:"database"`
	Username        string                   `db:"username" json:"username"`
	Password        string                   `db:"password" json:"-"` // encrypted, never exposed
	SSL             bool                     `db:"ssl" json:"ssl"`
	SSLMode         string                   `db:"ssl_mode" json:"ssl_mode,omitempty"`
	CACert          string                   `db:"ca_cert" json:"-"`
	ClientCert      string                   `db:"client_cert" json:"-"`
	ClientKey       string                   `db:"client_key" json:"-"`
	Options         map[string]string        `db:"options" json:"options,omitempty"`
	Status          DatabaseConnectionStatus `db:"status" json:"status"`
	StatusMessage   string                   `db:"status_message" json:"status_message,omitempty"`
	LastChecked     *time.Time               `db:"last_checked" json:"last_checked,omitempty"`
	LastConnectedAt *time.Time               `db:"last_connected_at" json:"last_connected_at,omitempty"`
	CreatedAt       time.Time                `db:"created_at" json:"created_at"`
	UpdatedAt       time.Time                `db:"updated_at" json:"updated_at"`
}

// CreateDatabaseConnectionInput is the input for creating a database connection.
type CreateDatabaseConnectionInput struct {
	Name       string            `json:"name" validate:"required,min=1,max=100"`
	Type       DatabaseType      `json:"type" validate:"required,oneof=postgres mysql mariadb mongodb redis sqlite"`
	Host       string            `json:"host" validate:"required"`
	Port       int               `json:"port" validate:"required,min=1,max=65535"`
	Database   string            `json:"database" validate:"required"`
	Username   string            `json:"username"`
	Password   string            `json:"password"`
	SSL        bool              `json:"ssl"`
	SSLMode    string            `json:"ssl_mode,omitempty"`
	CACert     string            `json:"ca_cert,omitempty"`
	ClientCert string            `json:"client_cert,omitempty"`
	ClientKey  string            `json:"client_key,omitempty"`
	Options    map[string]string `json:"options,omitempty"`
}

// UpdateDatabaseConnectionInput is the input for updating a database connection.
type UpdateDatabaseConnectionInput struct {
	Name       *string           `json:"name,omitempty"`
	Host       *string           `json:"host,omitempty"`
	Port       *int              `json:"port,omitempty"`
	Database   *string           `json:"database,omitempty"`
	Username   *string           `json:"username,omitempty"`
	Password   *string           `json:"password,omitempty"`
	SSL        *bool             `json:"ssl,omitempty"`
	SSLMode    *string           `json:"ssl_mode,omitempty"`
	CACert     *string           `json:"ca_cert,omitempty"`
	ClientCert *string           `json:"client_cert,omitempty"`
	ClientKey  *string           `json:"client_key,omitempty"`
	Options    map[string]string `json:"options,omitempty"`
}

// DatabaseTable represents a table/collection in a database.
type DatabaseTable struct {
	Name      string `json:"name"`
	Type      string `json:"type"` // table, view, materialized_view, collection
	Schema    string `json:"schema,omitempty"`
	RowCount  int64  `json:"row_count"`
	Size      int64  `json:"size"`       // bytes
	SizeHuman string `json:"size_human"` // human readable
}

// DatabaseColumn represents a column in a table.
type DatabaseColumn struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Nullable     bool   `json:"nullable"`
	Default      string `json:"default,omitempty"`
	IsPrimaryKey bool   `json:"is_primary_key"`
	IsForeignKey bool   `json:"is_foreign_key"`
	ForeignKey   string `json:"foreign_key,omitempty"` // table.column reference
	Comment      string `json:"comment,omitempty"`
}

// DatabaseQueryResult represents the result of a database query.
type DatabaseQueryResult struct {
	Columns      []string                 `json:"columns"`
	Rows         []map[string]interface{} `json:"rows"`
	RowCount     int64                    `json:"row_count"`
	AffectedRows int64                    `json:"affected_rows"`
	Duration     time.Duration            `json:"duration"`
	Error        string                   `json:"error,omitempty"`
}

// GetDefaultPort returns the default port for a database type.
func GetDefaultPort(dbType DatabaseType) int {
	switch dbType {
	case DatabaseTypePostgres:
		return 5432
	case DatabaseTypeMySQL, DatabaseTypeMariaDB:
		return 3306
	case DatabaseTypeMongoDB:
		return 27017
	case DatabaseTypeRedis:
		return 6379
	case DatabaseTypeSQLite:
		return 0 // SQLite is file-based
	default:
		return 0
	}
}
