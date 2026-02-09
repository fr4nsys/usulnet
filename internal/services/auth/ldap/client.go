// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package ldap provides LDAP authentication services.
package ldap

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
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Config represents LDAP server configuration.
type Config struct {
	ID            uuid.UUID
	Name          string
	Host          string
	Port          int
	UseTLS        bool
	StartTLS      bool
	SkipTLSVerify bool
	BindDN        string
	BindPassword  string // Encrypted
	BaseDN        string
	UserFilter    string
	UsernameAttr  string
	EmailAttr     string
	GroupFilter   string
	GroupAttr     string
	AdminGroup    string
	OperatorGroup string
	DefaultRole   models.UserRole
	Enabled       bool
	Timeout       time.Duration
}

// DefaultConfig returns a default LDAP configuration.
func DefaultConfig() Config {
	return Config{
		Port:         389,
		UsernameAttr: "sAMAccountName", // Active Directory default
		EmailAttr:    "mail",
		UserFilter:   "(objectClass=user)",
		GroupFilter:  "(objectClass=group)",
		GroupAttr:    "member",
		DefaultRole:  models.RoleViewer,
		Timeout:      10 * time.Second,
	}
}

// User represents a user retrieved from LDAP.
type User struct {
	Username string
	Email    string
	DN       string
	Groups   []string
	Role     models.UserRole
}

// Client provides LDAP authentication and user lookup.
type Client struct {
	config    Config
	encryptor *crypto.AESEncryptor
	logger    *logger.Logger
}

// NewClient creates a new LDAP client.
func NewClient(config Config, encryptor *crypto.AESEncryptor, log *logger.Logger) *Client {
	if log == nil {
		log = logger.Nop()
	}

	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}

	return &Client{
		config:    config,
		encryptor: encryptor,
		logger:    log.Named("ldap"),
	}
}

// ============================================================================
// LDAPProvider Interface Implementation
// ============================================================================

// GetName returns the provider name.
func (c *Client) GetName() string {
	return c.config.Name
}

// IsEnabled returns whether the provider is enabled.
func (c *Client) IsEnabled() bool {
	return c.config.Enabled
}

// GetID returns the provider ID.
func (c *Client) GetID() uuid.UUID {
	return c.config.ID
}

// ============================================================================
// Connection Management
// ============================================================================

// connect establishes a connection to the LDAP server.
func (c *Client) connect() (*ldap.Conn, error) {
	address := fmt.Sprintf("%s:%d", c.config.Host, c.config.Port)

	var conn *ldap.Conn
	var err error

	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.config.SkipTLSVerify,
		ServerName:         c.config.Host,
	}

	if c.config.UseTLS {
		// Connect with TLS (LDAPS)
		conn, err = ldap.DialTLS("tcp", address, tlsConfig)
	} else {
		// Connect without TLS
		conn, err = ldap.Dial("tcp", address)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	// Upgrade to TLS if StartTLS is enabled
	if c.config.StartTLS && !c.config.UseTLS {
		if err := conn.StartTLS(tlsConfig); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to start TLS: %w", err)
		}
	}

	// Set timeout
	conn.SetTimeout(c.config.Timeout)

	return conn, nil
}

// bindAsReader binds as the reader account for searches.
func (c *Client) bindAsReader(conn *ldap.Conn) error {
	if c.config.BindDN == "" {
		// Anonymous bind
		return conn.UnauthenticatedBind("")
	}

	// Decrypt bind password if encrypted
	password := c.config.BindPassword
	if c.encryptor != nil && password != "" {
		decrypted, err := c.encryptor.DecryptString(password)
		if err != nil {
			// Assume password is not encrypted (legacy)
			c.logger.Warn("failed to decrypt bind password, using as-is")
		} else {
			password = decrypted
		}
	}

	return conn.Bind(c.config.BindDN, password)
}

// ============================================================================
// Authentication
// ============================================================================

// Authenticate authenticates a user against LDAP.
func (c *Client) Authenticate(ctx context.Context, username, password string) (*User, error) {
	if !c.config.Enabled {
		return nil, fmt.Errorf("LDAP provider %s is disabled", c.config.Name)
	}

	conn, err := c.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Bind as reader to search for user
	if err := c.bindAsReader(conn); err != nil {
		return nil, fmt.Errorf("failed to bind as reader: %w", err)
	}

	// Search for user
	userDN, userEntry, err := c.searchUser(conn, username)
	if err != nil {
		// Prevent user enumeration timing attack
		c.performDummyBind(conn)
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Attempt to bind as the user
	if err := conn.Bind(userDN, password); err != nil {
		c.logger.Debug("LDAP authentication failed",
			"username", username,
			"error", err,
		)
		return nil, fmt.Errorf("authentication failed")
	}

	// Get user groups
	groups := c.getUserGroups(conn, userDN)

	// Determine role from groups
	role := c.determineRole(groups)

	// Build user object
	user := &User{
		Username: username,
		DN:       userDN,
		Groups:   groups,
		Role:     role,
	}

	// Get email if available
	if c.config.EmailAttr != "" && userEntry != nil {
		user.Email = userEntry.GetAttributeValue(c.config.EmailAttr)
	}

	c.logger.Info("LDAP authentication successful",
		"username", username,
		"groups", len(groups),
		"role", role,
	)

	return user, nil
}

// performDummyBind performs a dummy bind to prevent timing attacks.
func (c *Client) performDummyBind(conn *ldap.Conn) {
	// Use a fake DN and password to normalize response time
	_ = conn.Bind("cn=dummy,dc=dummy,dc=local", "dummy-password")
}

// searchUser searches for a user by username.
func (c *Client) searchUser(conn *ldap.Conn, username string) (string, *ldap.Entry, error) {
	// Escape username to prevent LDAP injection
	escapedUsername := ldap.EscapeFilter(username)

	// Build search filter
	filter := fmt.Sprintf("(&%s(%s=%s))",
		c.config.UserFilter,
		c.config.UsernameAttr,
		escapedUsername,
	)

	searchRequest := ldap.NewSearchRequest(
		c.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, // No size limit
		int(c.config.Timeout.Seconds()),
		false,
		filter,
		[]string{"dn", c.config.UsernameAttr, c.config.EmailAttr},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return "", nil, fmt.Errorf("search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return "", nil, fmt.Errorf("user not found")
	}

	if len(result.Entries) > 1 {
		return "", nil, fmt.Errorf("multiple users found")
	}

	entry := result.Entries[0]
	return entry.DN, entry, nil
}

// getUserGroups retrieves the groups a user belongs to.
func (c *Client) getUserGroups(conn *ldap.Conn, userDN string) []string {
	if c.config.GroupFilter == "" || c.config.GroupAttr == "" {
		return nil
	}

	// Re-bind as reader for group search
	if err := c.bindAsReader(conn); err != nil {
		c.logger.Warn("failed to re-bind for group search", "error", err)
		return nil
	}

	escapedUserDN := ldap.EscapeFilter(userDN)

	// Build group search filter
	filter := fmt.Sprintf("(&%s(%s=%s))",
		c.config.GroupFilter,
		c.config.GroupAttr,
		escapedUserDN,
	)

	searchRequest := ldap.NewSearchRequest(
		c.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		int(c.config.Timeout.Seconds()),
		false,
		filter,
		[]string{"cn"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		c.logger.Warn("group search failed", "error", err)
		return nil
	}

	groups := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		cn := entry.GetAttributeValue("cn")
		if cn != "" {
			groups = append(groups, cn)
		}
	}

	return groups
}

// determineRole determines the user role based on group membership.
func (c *Client) determineRole(groups []string) models.UserRole {
	for _, group := range groups {
		groupLower := strings.ToLower(group)

		// Check admin group
		if c.config.AdminGroup != "" && strings.ToLower(c.config.AdminGroup) == groupLower {
			return models.RoleAdmin
		}

		// Check operator group
		if c.config.OperatorGroup != "" && strings.ToLower(c.config.OperatorGroup) == groupLower {
			return models.RoleOperator
		}
	}

	return c.config.DefaultRole
}

// ============================================================================
// User Search
// ============================================================================

// SearchUsers searches for users matching criteria.
func (c *Client) SearchUsers(ctx context.Context) ([]User, error) {
	if !c.config.Enabled {
		return nil, fmt.Errorf("LDAP provider %s is disabled", c.config.Name)
	}

	conn, err := c.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := c.bindAsReader(conn); err != nil {
		return nil, fmt.Errorf("failed to bind: %w", err)
	}

	searchRequest := ldap.NewSearchRequest(
		c.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		int(c.config.Timeout.Seconds()),
		false,
		c.config.UserFilter,
		[]string{"dn", c.config.UsernameAttr, c.config.EmailAttr},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	users := make([]User, 0, len(result.Entries))
	for _, entry := range result.Entries {
		username := entry.GetAttributeValue(c.config.UsernameAttr)
		if username == "" {
			continue
		}

		user := User{
			Username: username,
			Email:    entry.GetAttributeValue(c.config.EmailAttr),
			DN:       entry.DN,
			Role:     c.config.DefaultRole,
		}
		users = append(users, user)
	}

	return users, nil
}

// ============================================================================
// Connection Testing
// ============================================================================

// TestConnection tests the LDAP connection.
func (c *Client) TestConnection(ctx context.Context) error {
	conn, err := c.connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := c.bindAsReader(conn); err != nil {
		return fmt.Errorf("bind failed: %w", err)
	}

	c.logger.Info("LDAP connection test successful", "host", c.config.Host)
	return nil
}

// TestAuthentication tests authentication with specific credentials.
func (c *Client) TestAuthentication(ctx context.Context, username, password string) error {
	user, err := c.Authenticate(ctx, username, password)
	if err != nil {
		return err
	}

	c.logger.Info("LDAP authentication test successful",
		"username", username,
		"dn", user.DN,
	)

	return nil
}

// ============================================================================
// Group Search
// ============================================================================

// SearchGroups searches for groups in LDAP.
func (c *Client) SearchGroups(ctx context.Context) ([]string, error) {
	if !c.config.Enabled {
		return nil, fmt.Errorf("LDAP provider %s is disabled", c.config.Name)
	}

	conn, err := c.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := c.bindAsReader(conn); err != nil {
		return nil, fmt.Errorf("failed to bind: %w", err)
	}

	searchRequest := ldap.NewSearchRequest(
		c.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		int(c.config.Timeout.Seconds()),
		false,
		c.config.GroupFilter,
		[]string{"cn"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	groups := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		cn := entry.GetAttributeValue("cn")
		if cn != "" {
			groups = append(groups, cn)
		}
	}

	return groups, nil
}

// ============================================================================
// Configuration Update
// ============================================================================

// UpdateConfig updates the client configuration.
func (c *Client) UpdateConfig(config Config) {
	c.config = config
}

// GetConfig returns the current configuration (with password masked).
func (c *Client) GetConfig() Config {
	cfg := c.config
	cfg.BindPassword = "********" // Mask password
	return cfg
}

// ============================================================================
// Provider Factory
// ============================================================================

// ProviderFromModel creates a Client from a models.LDAPConfig.
func ProviderFromModel(cfg *models.LDAPConfig, encryptor *crypto.AESEncryptor, log *logger.Logger) *Client {
	return NewClient(Config{
		ID:            cfg.ID,
		Name:          cfg.Name,
		Host:          cfg.Host,
		Port:          cfg.Port,
		UseTLS:        cfg.UseTLS,
		StartTLS:      cfg.StartTLS,
		SkipTLSVerify: cfg.SkipTLSVerify,
		BindDN:        cfg.BindDN,
		BindPassword:  cfg.BindPassword,
		BaseDN:        cfg.BaseDN,
		UserFilter:    cfg.UserFilter,
		UsernameAttr:  cfg.UsernameAttr,
		EmailAttr:     cfg.EmailAttr,
		GroupFilter:   cfg.GroupFilter,
		GroupAttr:     cfg.GroupAttr,
		AdminGroup:    cfg.AdminGroup,
		OperatorGroup: cfg.OperatorGroup,
		DefaultRole:   cfg.DefaultRole,
		Enabled:       cfg.IsEnabled,
		Timeout:       10 * time.Second,
	}, encryptor, log)
}
