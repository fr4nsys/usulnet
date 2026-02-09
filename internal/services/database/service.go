// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"

	// Database drivers
	_ "github.com/go-sql-driver/mysql" // MySQL / MariaDB
	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL
)

// ConnectionRepository defines the interface for database connection storage.
type ConnectionRepository interface {
	Create(ctx context.Context, conn *models.DatabaseConnection) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.DatabaseConnection, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.DatabaseConnection, error)
	Update(ctx context.Context, id uuid.UUID, input models.UpdateDatabaseConnectionInput) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.DatabaseConnectionStatus, message string) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// Service manages database connections and operations.
type Service struct {
	connRepo ConnectionRepository
	crypto   *crypto.Encryptor
	logger   *logger.Logger
}

// NewService creates a new database connection service.
func NewService(
	connRepo *postgres.DatabaseConnectionRepository,
	cryptoSvc *crypto.Encryptor,
	log *logger.Logger,
) *Service {
	return &Service{
		connRepo: connRepo,
		crypto:   cryptoSvc,
		logger:   log.Named("database"),
	}
}

// ============================================================================
// Connection CRUD
// ============================================================================

// CreateConnection creates a new database connection.
func (s *Service) CreateConnection(ctx context.Context, input models.CreateDatabaseConnectionInput, userID uuid.UUID) (*models.DatabaseConnection, error) {
	// Encrypt password if provided
	var encryptedPassword string
	if input.Password != "" && s.crypto != nil {
		encrypted, err := s.crypto.EncryptString(input.Password)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to encrypt password")
		}
		encryptedPassword = encrypted
	}

	conn := &models.DatabaseConnection{
		UserID:     userID,
		Name:       input.Name,
		Type:       input.Type,
		Host:       input.Host,
		Port:       input.Port,
		Database:   input.Database,
		Username:   input.Username,
		Password:   encryptedPassword,
		SSL:        input.SSL,
		SSLMode:    input.SSLMode,
		CACert:     input.CACert,
		ClientCert: input.ClientCert,
		ClientKey:  input.ClientKey,
		Options:    input.Options,
		Status:     models.DatabaseStatusDisconnected,
	}

	if err := s.connRepo.Create(ctx, conn); err != nil {
		return nil, err
	}

	s.logger.Info("created database connection",
		"id", conn.ID,
		"name", conn.Name,
		"type", conn.Type,
		"user_id", userID,
	)

	return conn, nil
}

// GetConnection retrieves a database connection by ID.
func (s *Service) GetConnection(ctx context.Context, id uuid.UUID) (*models.DatabaseConnection, error) {
	return s.connRepo.GetByID(ctx, id)
}

// ListConnections retrieves all database connections for a user.
func (s *Service) ListConnections(ctx context.Context, userID uuid.UUID) ([]*models.DatabaseConnection, error) {
	return s.connRepo.ListByUser(ctx, userID)
}

// UpdateConnection updates a database connection.
func (s *Service) UpdateConnection(ctx context.Context, id uuid.UUID, input models.UpdateDatabaseConnectionInput) error {
	// Encrypt new password if provided
	if input.Password != nil && *input.Password != "" && s.crypto != nil {
		encrypted, err := s.crypto.EncryptString(*input.Password)
		if err != nil {
			return errors.Wrap(err, errors.CodeInternal, "failed to encrypt password")
		}
		input.Password = &encrypted
	}

	return s.connRepo.Update(ctx, id, input)
}

// DeleteConnection removes a database connection.
func (s *Service) DeleteConnection(ctx context.Context, id uuid.UUID) error {
	return s.connRepo.Delete(ctx, id)
}

// ============================================================================
// Connection Testing
// ============================================================================

// TestConnection tests a database connection and returns the result.
func (s *Service) TestConnection(ctx context.Context, id uuid.UUID) (models.DatabaseTestResulter, error) {
	conn, err := s.connRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Decrypt password
	password := ""
	if conn.Password != "" && s.crypto != nil {
		decrypted, err := s.crypto.DecryptString(conn.Password)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to decrypt password")
		}
		password = decrypted
	}

	start := time.Now()
	result := &TestResult{ConnectionID: id}

	db, err := s.connect(conn, password)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		s.connRepo.UpdateStatus(ctx, id, models.DatabaseStatusError, err.Error())
		return result, nil
	}
	defer db.Close()

	// Ping the database
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		result.Success = false
		result.Message = "Ping failed: " + err.Error()
		s.connRepo.UpdateStatus(ctx, id, models.DatabaseStatusError, err.Error())
		return result, nil
	}

	result.Success = true
	result.Message = "Connection successful"
	result.Latency = time.Since(start)

	s.connRepo.UpdateStatus(ctx, id, models.DatabaseStatusConnected, "Connected successfully")
	return result, nil
}

// TestResult contains the result of a connection test.
type TestResult struct {
	ConnectionID uuid.UUID     `json:"connection_id"`
	Success      bool          `json:"success"`
	Message      string        `json:"message"`
	Latency      time.Duration `json:"latency"`
}

// IsSuccess returns whether the test was successful.
func (r *TestResult) IsSuccess() bool { return r.Success }

// GetMessage returns the test message.
func (r *TestResult) GetMessage() string { return r.Message }

// GetLatency returns the connection latency.
func (r *TestResult) GetLatency() time.Duration { return r.Latency }

// ============================================================================
// Database Operations
// ============================================================================

// Connect opens a database connection.
func (s *Service) Connect(ctx context.Context, id uuid.UUID) (*sql.DB, error) {
	conn, err := s.connRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Decrypt password
	password := ""
	if conn.Password != "" && s.crypto != nil {
		decrypted, err := s.crypto.DecryptString(conn.Password)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to decrypt password")
		}
		password = decrypted
	}

	return s.connect(conn, password)
}

// connect establishes a database connection.
func (s *Service) connect(conn *models.DatabaseConnection, password string) (*sql.DB, error) {
	dsn, driver := s.buildDSN(conn, password)
	if dsn == "" {
		return nil, errors.New(errors.CodeValidation, "unsupported database type: "+string(conn.Type))
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to open database connection")
	}

	// Configure connection pool
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)

	return db, nil
}

// buildDSN constructs the connection string for different database types.
func (s *Service) buildDSN(conn *models.DatabaseConnection, password string) (string, string) {
	switch conn.Type {
	case models.DatabaseTypePostgres:
		sslmode := "disable"
		if conn.SSL {
			sslmode = conn.SSLMode
			if sslmode == "" {
				sslmode = "require"
			}
		}
		dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			conn.Host, conn.Port, conn.Username, password, conn.Database, sslmode)
		return dsn, "pgx"

	case models.DatabaseTypeMySQL, models.DatabaseTypeMariaDB:
		tls := "false"
		if conn.SSL {
			tls = "true"
		}
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=%s&parseTime=true",
			conn.Username, password, conn.Host, conn.Port, conn.Database, tls)
		return dsn, "mysql"

	case models.DatabaseTypeRedis:
		// Redis uses a different connection approach (not sql.DB)
		return "", ""

	case models.DatabaseTypeMongoDB:
		// MongoDB uses a different connection approach (not sql.DB)
		return "", ""

	case models.DatabaseTypeSQLite:
		return conn.Database, "sqlite3"

	default:
		return "", ""
	}
}

// ListTables returns the list of tables in the database.
func (s *Service) ListTables(ctx context.Context, id uuid.UUID) ([]models.DatabaseTable, error) {
	conn, err := s.connRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	db, err := s.Connect(ctx, id)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	switch conn.Type {
	case models.DatabaseTypePostgres:
		return s.listTablesPostgres(ctx, db, conn.Database)
	case models.DatabaseTypeMySQL, models.DatabaseTypeMariaDB:
		return s.listTablesMySQL(ctx, db, conn.Database)
	default:
		return nil, errors.New(errors.CodeValidation, "table listing not supported for this database type")
	}
}

func (s *Service) listTablesPostgres(ctx context.Context, db *sql.DB, database string) ([]models.DatabaseTable, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT
			t.table_name,
			t.table_type,
			t.table_schema,
			COALESCE(c.reltuples::bigint, 0) as row_count,
			COALESCE(pg_total_relation_size(quote_ident(t.table_schema) || '.' || quote_ident(t.table_name)), 0) as size
		FROM information_schema.tables t
		LEFT JOIN pg_class c ON c.relname = t.table_name
		WHERE t.table_schema NOT IN ('pg_catalog', 'information_schema')
		ORDER BY t.table_schema, t.table_name
	`)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list tables")
	}
	defer rows.Close()

	var tables []models.DatabaseTable
	for rows.Next() {
		var t models.DatabaseTable
		var tableType string
		var size int64
		if err := rows.Scan(&t.Name, &tableType, &t.Schema, &t.RowCount, &size); err != nil {
			continue
		}
		t.Size = size
		t.SizeHuman = formatBytes(size)
		if strings.Contains(strings.ToLower(tableType), "view") {
			t.Type = "view"
		} else {
			t.Type = "table"
		}
		tables = append(tables, t)
	}

	return tables, nil
}

func (s *Service) listTablesMySQL(ctx context.Context, db *sql.DB, database string) ([]models.DatabaseTable, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT
			TABLE_NAME,
			TABLE_TYPE,
			TABLE_ROWS,
			DATA_LENGTH + INDEX_LENGTH as size
		FROM information_schema.TABLES
		WHERE TABLE_SCHEMA = ?
		ORDER BY TABLE_NAME
	`, database)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list tables")
	}
	defer rows.Close()

	var tables []models.DatabaseTable
	for rows.Next() {
		var t models.DatabaseTable
		var tableType string
		var rowCount, size sql.NullInt64
		if err := rows.Scan(&t.Name, &tableType, &rowCount, &size); err != nil {
			continue
		}
		t.RowCount = rowCount.Int64
		t.Size = size.Int64
		t.SizeHuman = formatBytes(size.Int64)
		if strings.Contains(strings.ToLower(tableType), "view") {
			t.Type = "view"
		} else {
			t.Type = "table"
		}
		tables = append(tables, t)
	}

	return tables, nil
}

// GetTableColumns returns the columns of a table.
func (s *Service) GetTableColumns(ctx context.Context, id uuid.UUID, tableName string) ([]models.DatabaseColumn, error) {
	conn, err := s.connRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	db, err := s.Connect(ctx, id)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	switch conn.Type {
	case models.DatabaseTypePostgres:
		return s.getTableColumnsPostgres(ctx, db, tableName)
	case models.DatabaseTypeMySQL, models.DatabaseTypeMariaDB:
		return s.getTableColumnsMySQL(ctx, db, conn.Database, tableName)
	default:
		return nil, errors.New(errors.CodeValidation, "column listing not supported for this database type")
	}
}

func (s *Service) getTableColumnsPostgres(ctx context.Context, db *sql.DB, tableName string) ([]models.DatabaseColumn, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT
			c.column_name,
			c.data_type,
			c.is_nullable = 'YES',
			COALESCE(c.column_default, ''),
			COALESCE(pk.constraint_type = 'PRIMARY KEY', false) as is_pk,
			COALESCE(fk.constraint_type = 'FOREIGN KEY', false) as is_fk,
			COALESCE(fk_ref.foreign_table_name || '.' || fk_ref.foreign_column_name, '') as fk_ref
		FROM information_schema.columns c
		LEFT JOIN (
			SELECT kcu.column_name, tc.constraint_type
			FROM information_schema.table_constraints tc
			JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
			WHERE tc.table_name = $1 AND tc.constraint_type = 'PRIMARY KEY'
		) pk ON pk.column_name = c.column_name
		LEFT JOIN (
			SELECT kcu.column_name, tc.constraint_type
			FROM information_schema.table_constraints tc
			JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
			WHERE tc.table_name = $1 AND tc.constraint_type = 'FOREIGN KEY'
		) fk ON fk.column_name = c.column_name
		LEFT JOIN (
			SELECT kcu.column_name, ccu.table_name as foreign_table_name, ccu.column_name as foreign_column_name
			FROM information_schema.table_constraints tc
			JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
			JOIN information_schema.constraint_column_usage ccu ON ccu.constraint_name = tc.constraint_name
			WHERE tc.table_name = $1 AND tc.constraint_type = 'FOREIGN KEY'
		) fk_ref ON fk_ref.column_name = c.column_name
		WHERE c.table_name = $1
		ORDER BY c.ordinal_position
	`, tableName)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get columns")
	}
	defer rows.Close()

	var columns []models.DatabaseColumn
	for rows.Next() {
		var col models.DatabaseColumn
		if err := rows.Scan(&col.Name, &col.Type, &col.Nullable, &col.Default, &col.IsPrimaryKey, &col.IsForeignKey, &col.ForeignKey); err != nil {
			continue
		}
		columns = append(columns, col)
	}

	return columns, nil
}

func (s *Service) getTableColumnsMySQL(ctx context.Context, db *sql.DB, database, tableName string) ([]models.DatabaseColumn, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT
			COLUMN_NAME,
			DATA_TYPE,
			IS_NULLABLE = 'YES',
			COALESCE(COLUMN_DEFAULT, ''),
			COLUMN_KEY = 'PRI',
			COLUMN_KEY = 'MUL'
		FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
		ORDER BY ORDINAL_POSITION
	`, database, tableName)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get columns")
	}
	defer rows.Close()

	var columns []models.DatabaseColumn
	for rows.Next() {
		var col models.DatabaseColumn
		if err := rows.Scan(&col.Name, &col.Type, &col.Nullable, &col.Default, &col.IsPrimaryKey, &col.IsForeignKey); err != nil {
			continue
		}
		columns = append(columns, col)
	}

	return columns, nil
}

// GetTableData returns rows from a table with pagination.
func (s *Service) GetTableData(ctx context.Context, id uuid.UUID, tableName string, page, pageSize int) ([]map[string]interface{}, int64, error) {
	conn, err := s.connRepo.GetByID(ctx, id)
	if err != nil {
		return nil, 0, err
	}

	db, err := s.Connect(ctx, id)
	if err != nil {
		return nil, 0, err
	}
	defer db.Close()

	// Get total count
	var totalCount int64
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)
	if err := db.QueryRowContext(ctx, countQuery).Scan(&totalCount); err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count rows")
	}

	// Get data with pagination
	offset := (page - 1) * pageSize
	var dataQuery string
	switch conn.Type {
	case models.DatabaseTypePostgres:
		dataQuery = fmt.Sprintf("SELECT * FROM %s LIMIT %d OFFSET %d", tableName, pageSize, offset)
	case models.DatabaseTypeMySQL, models.DatabaseTypeMariaDB:
		dataQuery = fmt.Sprintf("SELECT * FROM %s LIMIT %d OFFSET %d", tableName, pageSize, offset)
	default:
		return nil, 0, errors.New(errors.CodeValidation, "data query not supported for this database type")
	}

	rows, err := db.QueryContext(ctx, dataQuery)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to query data")
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to get columns")
	}

	var results []map[string]interface{}
	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			continue
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}
		results = append(results, row)
	}

	return results, totalCount, nil
}

// ExecuteQuery executes a SQL query (read-only by default).
func (s *Service) ExecuteQuery(ctx context.Context, id uuid.UUID, query string, writeMode bool) (*models.DatabaseQueryResult, error) {
	start := time.Now()
	result := &models.DatabaseQueryResult{}

	// Basic SQL injection prevention for read-only mode
	if !writeMode {
		lowerQuery := strings.ToLower(strings.TrimSpace(query))
		dangerousKeywords := []string{"insert", "update", "delete", "drop", "truncate", "alter", "create", "grant", "revoke"}
		for _, keyword := range dangerousKeywords {
			if strings.HasPrefix(lowerQuery, keyword) || strings.Contains(lowerQuery, " "+keyword+" ") {
				result.Error = "Write operations not allowed in read-only mode"
				return result, nil
			}
		}
	}

	db, err := s.Connect(ctx, id)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	defer db.Close()

	// Execute the query
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	result.Columns = columns

	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			continue
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}
		result.Rows = append(result.Rows, row)
		result.RowCount++
	}

	result.Duration = time.Since(start)
	return result, nil
}

// Helper function to format bytes
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
