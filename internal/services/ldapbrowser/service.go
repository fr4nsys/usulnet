// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package ldapbrowser

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// ConnectionRepository defines the interface for LDAP connection storage.
type ConnectionRepository interface {
	Create(ctx context.Context, conn *models.LDAPConnection) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.LDAPConnection, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.LDAPConnection, error)
	Update(ctx context.Context, id uuid.UUID, input models.UpdateLDAPConnectionInput) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.LDAPConnectionStatus, message string) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// Service manages LDAP browser connections and operations.
type Service struct {
	connRepo ConnectionRepository
	crypto   *crypto.Encryptor
	logger   *logger.Logger
}

// NewService creates a new LDAP browser service.
func NewService(
	connRepo *postgres.LDAPBrowserRepository,
	cryptoSvc *crypto.Encryptor,
	log *logger.Logger,
) *Service {
	return &Service{
		connRepo: connRepo,
		crypto:   cryptoSvc,
		logger:   log.Named("ldapbrowser"),
	}
}

// ============================================================================
// Connection CRUD
// ============================================================================

// CreateConnection creates a new LDAP connection.
func (s *Service) CreateConnection(ctx context.Context, input models.CreateLDAPConnectionInput, userID uuid.UUID) (*models.LDAPConnection, error) {
	// Encrypt password if provided
	var encryptedPassword string
	if input.BindPassword != "" && s.crypto != nil {
		encrypted, err := s.crypto.EncryptString(input.BindPassword)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to encrypt password")
		}
		encryptedPassword = encrypted
	}

	conn := &models.LDAPConnection{
		UserID:        userID,
		Name:          input.Name,
		Host:          input.Host,
		Port:          input.Port,
		UseTLS:        input.UseTLS,
		StartTLS:      input.StartTLS,
		SkipTLSVerify: input.SkipTLSVerify,
		BindDN:        input.BindDN,
		BindPassword:  encryptedPassword,
		BaseDN:        input.BaseDN,
		Status:        models.LDAPStatusDisconnected,
	}

	if err := s.connRepo.Create(ctx, conn); err != nil {
		return nil, err
	}

	s.logger.Info("created LDAP connection",
		"id", conn.ID,
		"name", conn.Name,
		"host", conn.Host,
		"user_id", userID,
	)

	return conn, nil
}

// GetConnection retrieves an LDAP connection by ID.
func (s *Service) GetConnection(ctx context.Context, id uuid.UUID) (*models.LDAPConnection, error) {
	return s.connRepo.GetByID(ctx, id)
}

// ListConnections retrieves all LDAP connections for a user.
func (s *Service) ListConnections(ctx context.Context, userID uuid.UUID) ([]*models.LDAPConnection, error) {
	return s.connRepo.ListByUser(ctx, userID)
}

// UpdateConnection updates an LDAP connection.
func (s *Service) UpdateConnection(ctx context.Context, id uuid.UUID, input models.UpdateLDAPConnectionInput) error {
	// Encrypt new password if provided
	if input.BindPassword != nil && *input.BindPassword != "" && s.crypto != nil {
		encrypted, err := s.crypto.EncryptString(*input.BindPassword)
		if err != nil {
			return errors.Wrap(err, errors.CodeInternal, "failed to encrypt password")
		}
		input.BindPassword = &encrypted
	}

	return s.connRepo.Update(ctx, id, input)
}

// DeleteConnection removes an LDAP connection.
func (s *Service) DeleteConnection(ctx context.Context, id uuid.UUID) error {
	return s.connRepo.Delete(ctx, id)
}

// ============================================================================
// Connection Testing
// ============================================================================

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

// TestConnection tests an LDAP connection and returns the result.
func (s *Service) TestConnection(ctx context.Context, id uuid.UUID) (models.LDAPTestResulter, error) {
	conn, err := s.connRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Decrypt password
	password := ""
	if conn.BindPassword != "" && s.crypto != nil {
		decrypted, err := s.crypto.DecryptString(conn.BindPassword)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to decrypt password")
		}
		password = decrypted
	}

	start := time.Now()
	result := &TestResult{ConnectionID: id}

	ldapConn, err := s.connect(conn, password)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		s.connRepo.UpdateStatus(ctx, id, models.LDAPStatusError, err.Error())
		return result, nil
	}
	defer ldapConn.Close()

	result.Success = true
	result.Message = "Connection successful"
	result.Latency = time.Since(start)

	s.connRepo.UpdateStatus(ctx, id, models.LDAPStatusConnected, "Connected successfully")
	return result, nil
}

// ============================================================================
// LDAP Operations
// ============================================================================

// connect establishes an LDAP connection.
func (s *Service) connect(conn *models.LDAPConnection, password string) (*ldap.Conn, error) {
	var l *ldap.Conn
	var err error

	address := fmt.Sprintf("%s:%d", conn.Host, conn.Port)

	if conn.UseTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: conn.SkipTLSVerify,
		}
		l, err = ldap.DialTLS("tcp", address, tlsConfig)
	} else {
		l, err = ldap.Dial("tcp", address)
	}

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to connect to LDAP server")
	}

	// StartTLS if configured
	if !conn.UseTLS && conn.StartTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: conn.SkipTLSVerify,
		}
		if err := l.StartTLS(tlsConfig); err != nil {
			l.Close()
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to start TLS")
		}
	}

	// Bind
	if err := l.Bind(conn.BindDN, password); err != nil {
		l.Close()
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to bind to LDAP server")
	}

	return l, nil
}

// Connect opens an LDAP connection for operations.
func (s *Service) Connect(ctx context.Context, id uuid.UUID) (*ldap.Conn, error) {
	conn, err := s.connRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Decrypt password
	password := ""
	if conn.BindPassword != "" && s.crypto != nil {
		decrypted, err := s.crypto.DecryptString(conn.BindPassword)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to decrypt password")
		}
		password = decrypted
	}

	return s.connect(conn, password)
}

// ListEntries returns directory entries at the given base DN.
func (s *Service) ListEntries(ctx context.Context, id uuid.UUID, baseDN string, scope int) ([]models.LDAPEntry, error) {
	conn, err := s.connRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if baseDN == "" {
		baseDN = conn.BaseDN
	}

	l, err := s.Connect(ctx, id)
	if err != nil {
		return nil, err
	}
	defer l.Close()

	// Search for entries
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		scope,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"*", "+"}, // All attributes
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "LDAP search failed")
	}

	var entries []models.LDAPEntry
	for _, entry := range sr.Entries {
		ldapEntry := models.LDAPEntry{
			DN:          entry.DN,
			RDN:         getRDN(entry.DN),
			Attributes:  make(map[string][]string),
			ObjectClass: entry.GetAttributeValues("objectClass"),
		}

		for _, attr := range entry.Attributes {
			ldapEntry.Attributes[attr.Name] = attr.Values
		}

		// Check if has children
		ldapEntry.HasChildren = s.hasChildren(l, entry.DN)

		entries = append(entries, ldapEntry)
	}

	return entries, nil
}

// GetEntry returns a single directory entry.
func (s *Service) GetEntry(ctx context.Context, id uuid.UUID, dn string) (*models.LDAPEntry, error) {
	l, err := s.Connect(ctx, id)
	if err != nil {
		return nil, err
	}
	defer l.Close()

	searchRequest := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"*", "+"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "LDAP search failed")
	}

	if len(sr.Entries) == 0 {
		return nil, errors.NotFound("LDAP entry")
	}

	entry := sr.Entries[0]
	ldapEntry := &models.LDAPEntry{
		DN:          entry.DN,
		RDN:         getRDN(entry.DN),
		Attributes:  make(map[string][]string),
		ObjectClass: entry.GetAttributeValues("objectClass"),
		HasChildren: s.hasChildren(l, entry.DN),
	}

	for _, attr := range entry.Attributes {
		ldapEntry.Attributes[attr.Name] = attr.Values
	}

	return ldapEntry, nil
}

// Search executes an LDAP search.
func (s *Service) Search(ctx context.Context, id uuid.UUID, baseDN, filter string, scope int, attributes []string) (*models.LDAPSearchResult, error) {
	conn, err := s.connRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if baseDN == "" {
		baseDN = conn.BaseDN
	}

	if filter == "" {
		filter = "(objectClass=*)"
	}

	if len(attributes) == 0 {
		attributes = []string{"*", "+"}
	}

	start := time.Now()

	l, err := s.Connect(ctx, id)
	if err != nil {
		return nil, err
	}
	defer l.Close()

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		scope,
		ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attributes,
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "LDAP search failed")
	}

	result := &models.LDAPSearchResult{
		BaseDN:     baseDN,
		Filter:     filter,
		Scope:      scopeToString(scope),
		SearchTime: time.Since(start),
		TotalCount: len(sr.Entries),
	}

	for _, entry := range sr.Entries {
		ldapEntry := models.LDAPEntry{
			DN:          entry.DN,
			RDN:         getRDN(entry.DN),
			Attributes:  make(map[string][]string),
			ObjectClass: entry.GetAttributeValues("objectClass"),
		}

		for _, attr := range entry.Attributes {
			ldapEntry.Attributes[attr.Name] = attr.Values
		}

		result.Entries = append(result.Entries, ldapEntry)
	}

	return result, nil
}

// hasChildren checks if an entry has child entries.
func (s *Service) hasChildren(l *ldap.Conn, dn string) bool {
	searchRequest := ldap.NewSearchRequest(
		dn,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return false
	}

	return len(sr.Entries) > 0
}

// Helper functions

func getRDN(dn string) string {
	parts := strings.SplitN(dn, ",", 2)
	if len(parts) > 0 {
		return parts[0]
	}
	return dn
}

func scopeToString(scope int) string {
	switch scope {
	case ldap.ScopeBaseObject:
		return "base"
	case ldap.ScopeSingleLevel:
		return "one"
	case ldap.ScopeWholeSubtree:
		return "sub"
	default:
		return "unknown"
	}
}
