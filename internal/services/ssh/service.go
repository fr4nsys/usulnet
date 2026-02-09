// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package ssh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// KeyRepository defines the interface for SSH key persistence.
type KeyRepository interface {
	Create(ctx context.Context, key *models.SSHKey) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.SSHKey, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.SSHKey, error)
	Update(ctx context.Context, key *models.SSHKey) error
	Delete(ctx context.Context, id uuid.UUID) error
	UpdateLastUsed(ctx context.Context, id uuid.UUID) error
	GetByFingerprint(ctx context.Context, fingerprint string) (*models.SSHKey, error)
}

// ConnectionRepository defines the interface for SSH connection persistence.
type ConnectionRepository interface {
	Create(ctx context.Context, conn *models.SSHConnection) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.SSHConnection, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.SSHConnection, error)
	ListByCategory(ctx context.Context, userID uuid.UUID, category string) ([]*models.SSHConnection, error)
	Update(ctx context.Context, conn *models.SSHConnection) error
	Delete(ctx context.Context, id uuid.UUID) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.SSHConnectionStatus, msg string) error
	GetCategories(ctx context.Context, userID uuid.UUID) ([]string, error)
}

// SessionRepository defines the interface for SSH session persistence.
type SessionRepository interface {
	Create(ctx context.Context, session *models.SSHSession) error
	End(ctx context.Context, id uuid.UUID) error
	ListByConnection(ctx context.Context, connID uuid.UUID, limit int) ([]*models.SSHSession, error)
	ListActive(ctx context.Context) ([]*models.SSHSession, error)
}

// TunnelRepository defines the interface for SSH tunnel persistence.
type TunnelRepository interface {
	Create(ctx context.Context, tunnel *models.SSHTunnel) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.SSHTunnel, error)
	ListByConnection(ctx context.Context, connID uuid.UUID) ([]*models.SSHTunnel, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.SSHTunnel, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.SSHTunnelStatus, msg string) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// Encryptor handles encryption/decryption of sensitive data.
type Encryptor interface {
	EncryptString(plaintext string) (string, error)
	DecryptString(ciphertext string) (string, error)
}

// Service manages SSH keys, connections, and terminal sessions.
type Service struct {
	keyRepo     KeyRepository
	connRepo    ConnectionRepository
	sessionRepo SessionRepository
	tunnelRepo  TunnelRepository
	encryptor   Encryptor
	logger      *logger.Logger

	// Active client connections (for reuse)
	mu      sync.RWMutex
	clients map[uuid.UUID]*ssh.Client

	// Active tunnels (in-memory for managing running tunnels)
	tunnelMu       sync.RWMutex
	activeTunnels  map[uuid.UUID]chan struct{} // tunnel ID -> stop channel
}

// NewService creates a new SSH service.
func NewService(
	keyRepo KeyRepository,
	connRepo ConnectionRepository,
	sessionRepo SessionRepository,
	encryptor Encryptor,
	log *logger.Logger,
) *Service {
	return &Service{
		keyRepo:       keyRepo,
		connRepo:      connRepo,
		sessionRepo:   sessionRepo,
		encryptor:     encryptor,
		logger:        log.Named("ssh"),
		clients:       make(map[uuid.UUID]*ssh.Client),
		activeTunnels: make(map[uuid.UUID]chan struct{}),
	}
}

// SetTunnelRepo sets the tunnel repository (for optional injection).
func (s *Service) SetTunnelRepo(repo TunnelRepository) {
	s.tunnelRepo = repo
}

// ============================================================================
// SSH Key Management
// ============================================================================

// GenerateKey generates a new SSH key pair.
func (s *Service) GenerateKey(ctx context.Context, input models.CreateSSHKeyInput, userID uuid.UUID) (*models.SSHKey, error) {
	var publicKey, privateKey string
	var err error

	switch input.KeyType {
	case models.SSHKeyTypeED25519:
		publicKey, privateKey, err = s.generateED25519Key()
	case models.SSHKeyTypeRSA:
		bits := input.KeyBits
		if bits == 0 {
			bits = 4096
		}
		publicKey, privateKey, err = s.generateRSAKey(bits)
	default:
		return nil, errors.New(errors.CodeValidationFailed, "unsupported key type: "+string(input.KeyType))
	}

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to generate key pair")
	}

	// Encrypt private key for storage
	encPrivateKey, err := s.encryptor.EncryptString(privateKey)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeEncryptionFailed, "failed to encrypt private key")
	}

	// Encrypt passphrase if provided
	encPassphrase := ""
	if input.Passphrase != "" {
		encPassphrase, err = s.encryptor.EncryptString(input.Passphrase)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeEncryptionFailed, "failed to encrypt passphrase")
		}
	}

	// Calculate fingerprint
	fingerprint, err := s.calculateFingerprint(publicKey)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to calculate fingerprint")
	}

	key := &models.SSHKey{
		Name:        input.Name,
		KeyType:     input.KeyType,
		PublicKey:   publicKey,
		PrivateKey:  encPrivateKey,
		Passphrase:  encPassphrase,
		Fingerprint: fingerprint,
		Comment:     input.Comment,
		CreatedBy:   userID,
	}

	if err := s.keyRepo.Create(ctx, key); err != nil {
		return nil, err
	}

	s.logger.Info("SSH key generated", "key_id", key.ID, "type", input.KeyType, "user_id", userID)
	return key, nil
}

// ImportKey imports an existing SSH key pair.
func (s *Service) ImportKey(ctx context.Context, input models.CreateSSHKeyInput, userID uuid.UUID) (*models.SSHKey, error) {
	if input.PublicKey == "" || input.PrivateKey == "" {
		return nil, errors.New(errors.CodeValidationFailed, "public and private keys are required for import")
	}

	// Validate the key pair
	if err := s.validateKeyPair(input.PublicKey, input.PrivateKey, input.Passphrase); err != nil {
		return nil, errors.Wrap(err, errors.CodeValidationFailed, "invalid key pair")
	}

	// Encrypt private key
	encPrivateKey, err := s.encryptor.EncryptString(input.PrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeEncryptionFailed, "failed to encrypt private key")
	}

	// Encrypt passphrase if provided
	encPassphrase := ""
	if input.Passphrase != "" {
		encPassphrase, err = s.encryptor.EncryptString(input.Passphrase)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeEncryptionFailed, "failed to encrypt passphrase")
		}
	}

	// Calculate fingerprint
	fingerprint, err := s.calculateFingerprint(input.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to calculate fingerprint")
	}

	// Detect key type
	keyType := s.detectKeyType(input.PublicKey)

	key := &models.SSHKey{
		Name:        input.Name,
		KeyType:     keyType,
		PublicKey:   input.PublicKey,
		PrivateKey:  encPrivateKey,
		Passphrase:  encPassphrase,
		Fingerprint: fingerprint,
		Comment:     input.Comment,
		CreatedBy:   userID,
	}

	if err := s.keyRepo.Create(ctx, key); err != nil {
		return nil, err
	}

	s.logger.Info("SSH key imported", "key_id", key.ID, "type", keyType, "user_id", userID)
	return key, nil
}

// GetKey retrieves an SSH key by ID.
func (s *Service) GetKey(ctx context.Context, id uuid.UUID) (*models.SSHKey, error) {
	return s.keyRepo.GetByID(ctx, id)
}

// ListKeys retrieves all SSH keys for a user.
func (s *Service) ListKeys(ctx context.Context, userID uuid.UUID) ([]*models.SSHKey, error) {
	return s.keyRepo.ListByUser(ctx, userID)
}

// DeleteKey removes an SSH key.
func (s *Service) DeleteKey(ctx context.Context, id uuid.UUID) error {
	if err := s.keyRepo.Delete(ctx, id); err != nil {
		return err
	}
	s.logger.Info("SSH key deleted", "key_id", id)
	return nil
}

// ============================================================================
// SSH Connection Management
// ============================================================================

// CreateConnection creates a new SSH connection profile.
func (s *Service) CreateConnection(ctx context.Context, input models.CreateSSHConnectionInput, userID uuid.UUID) (*models.SSHConnection, error) {
	// Encrypt password if using password auth
	encPassword := ""
	if input.AuthType == models.SSHAuthPassword && input.Password != "" {
		var err error
		encPassword, err = s.encryptor.EncryptString(input.Password)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeEncryptionFailed, "failed to encrypt password")
		}
	}

	// Validate key exists if using key auth
	if input.AuthType == models.SSHAuthKey && input.KeyID != nil {
		_, err := s.keyRepo.GetByID(ctx, *input.KeyID)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeNotFound, "SSH key not found")
		}
	}

	conn := &models.SSHConnection{
		Name:        input.Name,
		Description: input.Description,
		Host:        input.Host,
		Port:        input.Port,
		Username:    input.Username,
		AuthType:    input.AuthType,
		KeyID:       input.KeyID,
		Password:    encPassword,
		JumpHost:    input.JumpHost,
		Tags:        input.Tags,
		Category:    input.Category,
		Status:      models.SSHConnectionUnknown,
		CreatedBy:   userID,
	}

	if input.Options != nil {
		conn.Options = *input.Options
	}

	if err := s.connRepo.Create(ctx, conn); err != nil {
		return nil, err
	}

	s.logger.Info("SSH connection created", "conn_id", conn.ID, "host", conn.Host, "user_id", userID)
	return conn, nil
}

// GetConnection retrieves an SSH connection by ID.
func (s *Service) GetConnection(ctx context.Context, id uuid.UUID) (*models.SSHConnection, error) {
	conn, err := s.connRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Load associated key if present
	if conn.KeyID != nil {
		key, err := s.keyRepo.GetByID(ctx, *conn.KeyID)
		if err == nil {
			conn.Key = key
		}
	}

	return conn, nil
}

// ListConnections retrieves all SSH connections for a user.
func (s *Service) ListConnections(ctx context.Context, userID uuid.UUID) ([]*models.SSHConnection, error) {
	return s.connRepo.ListByUser(ctx, userID)
}

// ListConnectionsByCategory retrieves SSH connections by category.
func (s *Service) ListConnectionsByCategory(ctx context.Context, userID uuid.UUID, category string) ([]*models.SSHConnection, error) {
	return s.connRepo.ListByCategory(ctx, userID, category)
}

// UpdateConnection updates an SSH connection.
func (s *Service) UpdateConnection(ctx context.Context, id uuid.UUID, input models.UpdateSSHConnectionInput) (*models.SSHConnection, error) {
	conn, err := s.connRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		conn.Name = *input.Name
	}
	if input.Description != nil {
		conn.Description = *input.Description
	}
	if input.Host != nil {
		conn.Host = *input.Host
	}
	if input.Port != nil {
		conn.Port = *input.Port
	}
	if input.Username != nil {
		conn.Username = *input.Username
	}
	if input.AuthType != nil {
		conn.AuthType = *input.AuthType
	}
	if input.KeyID != nil {
		conn.KeyID = input.KeyID
	}
	if input.Password != nil && *input.Password != "" {
		encPassword, err := s.encryptor.EncryptString(*input.Password)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeEncryptionFailed, "failed to encrypt password")
		}
		conn.Password = encPassword
	}
	if input.JumpHost != nil {
		conn.JumpHost = input.JumpHost
	}
	if input.Tags != nil {
		conn.Tags = input.Tags
	}
	if input.Category != nil {
		conn.Category = *input.Category
	}
	if input.Options != nil {
		conn.Options = *input.Options
	}

	if err := s.connRepo.Update(ctx, conn); err != nil {
		return nil, err
	}

	// Invalidate cached client
	s.closeClient(id)

	s.logger.Info("SSH connection updated", "conn_id", id)
	return conn, nil
}

// DeleteConnection removes an SSH connection.
func (s *Service) DeleteConnection(ctx context.Context, id uuid.UUID) error {
	// Close any active client
	s.closeClient(id)

	if err := s.connRepo.Delete(ctx, id); err != nil {
		return err
	}

	s.logger.Info("SSH connection deleted", "conn_id", id)
	return nil
}

// SaveConnectionOptions persists the connection's options (e.g., after TOFU host key storage).
func (s *Service) SaveConnectionOptions(ctx context.Context, conn *models.SSHConnection) error {
	return s.connRepo.Update(ctx, conn)
}

// GetCategories returns all unique categories for a user.
func (s *Service) GetCategories(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return s.connRepo.GetCategories(ctx, userID)
}

// TestConnection tests connectivity to an SSH host.
func (s *Service) TestConnection(ctx context.Context, id uuid.UUID) (*models.SSHTestResult, error) {
	conn, err := s.GetConnection(ctx, id)
	if err != nil {
		return nil, err
	}

	result := &models.SSHTestResult{
		TestedAt: time.Now(),
	}

	start := time.Now()

	client, err := s.dial(ctx, conn)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		_ = s.connRepo.UpdateStatus(ctx, id, models.SSHConnectionError, err.Error())
		return result, nil
	}
	defer client.Close()

	result.Latency = time.Since(start).Milliseconds()
	result.Success = true
	result.Message = "Connection successful"
	result.ServerInfo = string(client.ServerVersion())
	result.HostKey = conn.Options.HostKeyFingerprint

	_ = s.connRepo.UpdateStatus(ctx, id, models.SSHConnectionActive, "")

	return result, nil
}

// ============================================================================
// SSH Terminal Sessions
// ============================================================================

// Connect establishes an SSH connection and returns a client for terminal use.
func (s *Service) Connect(ctx context.Context, connID uuid.UUID, userID uuid.UUID, clientIP string) (*ssh.Client, *models.SSHSession, error) {
	conn, err := s.GetConnection(ctx, connID)
	if err != nil {
		return nil, nil, err
	}

	client, err := s.dial(ctx, conn)
	if err != nil {
		_ = s.connRepo.UpdateStatus(ctx, connID, models.SSHConnectionError, err.Error())
		return nil, nil, err
	}

	// Create session record
	session := &models.SSHSession{
		ConnectionID: connID,
		UserID:       userID,
		ClientIP:     clientIP,
		TermType:     "xterm-256color",
		TermCols:     80,
		TermRows:     24,
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		client.Close()
		return nil, nil, err
	}

	// Update key last used if applicable
	if conn.KeyID != nil {
		_ = s.keyRepo.UpdateLastUsed(ctx, *conn.KeyID)
	}

	_ = s.connRepo.UpdateStatus(ctx, connID, models.SSHConnectionActive, "")

	s.logger.Info("SSH session started", "conn_id", connID, "session_id", session.ID, "user_id", userID)
	return client, session, nil
}

// CreateSession saves an SSH session record (used for runtime-credential connections).
func (s *Service) CreateSession(ctx context.Context, session *models.SSHSession) error {
	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return err
	}
	s.logger.Info("SSH session created", "session_id", session.ID, "conn_id", session.ConnectionID)
	return nil
}

// EndSession marks an SSH session as ended.
func (s *Service) EndSession(ctx context.Context, sessionID uuid.UUID) error {
	if err := s.sessionRepo.End(ctx, sessionID); err != nil {
		return err
	}
	s.logger.Info("SSH session ended", "session_id", sessionID)
	return nil
}

// GetActiveSessions returns all active SSH sessions.
func (s *Service) GetActiveSessions(ctx context.Context) ([]*models.SSHSession, error) {
	return s.sessionRepo.ListActive(ctx)
}

// GetSessionHistory returns session history for a connection.
func (s *Service) GetSessionHistory(ctx context.Context, connID uuid.UUID, limit int) ([]*models.SSHSession, error) {
	return s.sessionRepo.ListByConnection(ctx, connID, limit)
}

// ============================================================================
// Internal Helpers
// ============================================================================

func (s *Service) dial(ctx context.Context, conn *models.SSHConnection) (*ssh.Client, error) {
	config, err := s.buildSSHConfig(ctx, conn)
	if err != nil {
		return nil, err
	}

	addr := fmt.Sprintf("%s:%d", conn.Host, conn.Port)

	// Handle jump host if configured
	if conn.JumpHost != nil {
		jumpConn, err := s.connRepo.GetByID(ctx, *conn.JumpHost)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to get jump host")
		}

		jumpClient, err := s.dial(ctx, jumpConn)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to connect to jump host")
		}

		netConn, err := jumpClient.Dial("tcp", addr)
		if err != nil {
			jumpClient.Close()
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to dial through jump host")
		}

		ncc, chans, reqs, err := ssh.NewClientConn(netConn, addr, config)
		if err != nil {
			netConn.Close()
			jumpClient.Close()
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to establish SSH connection")
		}

		return ssh.NewClient(ncc, chans, reqs), nil
	}

	// Direct connection
	timeout := 30 * time.Second
	if conn.Options.ConnectionTimeout > 0 {
		timeout = time.Duration(conn.Options.ConnectionTimeout) * time.Second
	}

	netConn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to dial SSH host")
	}

	ncc, chans, reqs, err := ssh.NewClientConn(netConn, addr, config)
	if err != nil {
		netConn.Close()
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to establish SSH connection")
	}

	return ssh.NewClient(ncc, chans, reqs), nil
}

func (s *Service) buildSSHConfig(ctx context.Context, conn *models.SSHConnection) (*ssh.ClientConfig, error) {
	var authMethods []ssh.AuthMethod

	switch conn.AuthType {
	case models.SSHAuthPassword:
		password, err := s.encryptor.DecryptString(conn.Password)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDecryptionFailed, "failed to decrypt password")
		}
		authMethods = append(authMethods, ssh.Password(password))

	case models.SSHAuthKey:
		if conn.KeyID == nil {
			return nil, errors.New(errors.CodeValidationFailed, "key ID required for key auth")
		}

		key, err := s.keyRepo.GetByID(ctx, *conn.KeyID)
		if err != nil {
			return nil, err
		}

		privateKey, err := s.encryptor.DecryptString(key.PrivateKey)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDecryptionFailed, "failed to decrypt private key")
		}

		var signer ssh.Signer
		if key.Passphrase != "" {
			passphrase, err := s.encryptor.DecryptString(key.Passphrase)
			if err != nil {
				return nil, errors.Wrap(err, errors.CodeDecryptionFailed, "failed to decrypt passphrase")
			}
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(privateKey), []byte(passphrase))
			if err != nil {
				return nil, errors.Wrap(err, errors.CodeInternal, "failed to parse private key")
			}
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(privateKey))
			if err != nil {
				return nil, errors.Wrap(err, errors.CodeInternal, "failed to parse private key")
			}
		}

		authMethods = append(authMethods, ssh.PublicKeys(signer))

	case models.SSHAuthAgent:
		// Agent auth would require socket connection - for now return error
		return nil, errors.New(errors.CodeNotSupported, "SSH agent auth not yet implemented")

	case models.SSHAuthKeyboard:
		return nil, errors.New(errors.CodeNotSupported, "keyboard-interactive auth not yet implemented")
	}

	config := &ssh.ClientConfig{
		User:            conn.Username,
		Auth:            authMethods,
		HostKeyCallback: s.buildHostKeyCallback(conn),
		Timeout:         30 * time.Second,
	}

	if conn.Options.ConnectionTimeout > 0 {
		config.Timeout = time.Duration(conn.Options.ConnectionTimeout) * time.Second
	}

	return config, nil
}

// buildHostKeyCallback returns a host key callback that implements TOFU
// (Trust On First Use). On first connection, the host key fingerprint is
// stored in the connection options. On subsequent connections, the key is
// verified against the stored fingerprint.
func (s *Service) buildHostKeyCallback(conn *models.SSHConnection) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fingerprint := sshFingerprint(key)

		stored := conn.Options.HostKeyFingerprint
		if stored == "" {
			// TOFU: first connection, store the fingerprint
			conn.Options.HostKeyFingerprint = fingerprint
			if err := s.connRepo.Update(context.Background(), conn); err != nil {
				s.logger.Warn("failed to persist host key fingerprint",
					"connection_id", conn.ID, "error", err)
			}
			s.logger.Info("SSH host key stored (TOFU)",
				"connection_id", conn.ID, "host", hostname, "fingerprint", fingerprint)
			return nil
		}

		if stored != fingerprint {
			return fmt.Errorf("host key mismatch for %s: expected %s, got %s (possible MITM attack)",
				hostname, stored, fingerprint)
		}

		return nil
	}
}

// sshFingerprint returns the SHA256 fingerprint of an SSH public key.
func sshFingerprint(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])
}

func (s *Service) closeClient(id uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if client, ok := s.clients[id]; ok {
		client.Close()
		delete(s.clients, id)
	}
}

func (s *Service) generateED25519Key() (publicKey, privateKey string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	publicKey = string(ssh.MarshalAuthorizedKey(sshPub))

	privBlock := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: marshalED25519PrivateKey(priv),
	}
	privateKey = string(pem.EncodeToMemory(privBlock))

	return publicKey, privateKey, nil
}

func (s *Service) generateRSAKey(bits int) (publicKey, privateKey string, err error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", err
	}

	sshPub, err := ssh.NewPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", "", err
	}
	publicKey = string(ssh.MarshalAuthorizedKey(sshPub))

	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}
	privateKey = string(pem.EncodeToMemory(privBlock))

	return publicKey, privateKey, nil
}

func (s *Service) calculateFingerprint(publicKey string) (string, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(pubKey), nil
}

func (s *Service) detectKeyType(publicKey string) models.SSHKeyType {
	if len(publicKey) > 10 {
		if publicKey[:11] == "ssh-ed25519" {
			return models.SSHKeyTypeED25519
		}
		if publicKey[:7] == "ssh-rsa" {
			return models.SSHKeyTypeRSA
		}
		if publicKey[:11] == "ecdsa-sha2-" {
			return models.SSHKeyTypeECDSA
		}
	}
	return models.SSHKeyTypeRSA
}

func (s *Service) validateKeyPair(publicKey, privateKey, passphrase string) error {
	var signer ssh.Signer
	var err error

	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(privateKey), []byte(passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey([]byte(privateKey))
	}
	if err != nil {
		return err
	}

	// Verify public key matches
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return err
	}

	if string(pubKey.Marshal()) != string(signer.PublicKey().Marshal()) {
		return errors.New(errors.CodeValidationFailed, "public key does not match private key")
	}

	return nil
}

// marshalED25519PrivateKey marshals an ED25519 private key in OpenSSH format.
func marshalED25519PrivateKey(key ed25519.PrivateKey) []byte {
	// Simplified OpenSSH private key format
	// For production, use proper OpenSSH key serialization
	return key
}

// ============================================================================
// SSH Tunnel Management
// ============================================================================

// CreateTunnel creates a new SSH tunnel configuration.
func (s *Service) CreateTunnel(ctx context.Context, input models.CreateSSHTunnelInput, userID uuid.UUID) (*models.SSHTunnel, error) {
	if s.tunnelRepo == nil {
		return nil, errors.New(errors.CodeInternal, "tunnel repository not configured")
	}

	// Validate connection exists and belongs to user (or user has access)
	conn, err := s.connRepo.GetByID(ctx, input.ConnectionID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "connection not found")
	}
	if conn.CreatedBy != userID {
		return nil, errors.New(errors.CodeForbidden, "access denied to this connection")
	}

	// Default values
	if input.LocalHost == "" {
		input.LocalHost = "127.0.0.1"
	}
	if input.RemoteHost == "" && input.Type != models.SSHTunnelTypeDynamic {
		input.RemoteHost = "localhost"
	}

	tunnel := &models.SSHTunnel{
		ConnectionID: input.ConnectionID,
		UserID:       userID,
		Type:         input.Type,
		LocalHost:    input.LocalHost,
		LocalPort:    input.LocalPort,
		RemoteHost:   input.RemoteHost,
		RemotePort:   input.RemotePort,
		Status:       models.SSHTunnelStatusStopped,
		AutoStart:    input.AutoStart,
	}

	if err := s.tunnelRepo.Create(ctx, tunnel); err != nil {
		return nil, err
	}

	s.logger.Info("tunnel created", "tunnel_id", tunnel.ID, "type", tunnel.Type, "local_port", tunnel.LocalPort)
	return tunnel, nil
}

// GetTunnel retrieves a tunnel by ID.
func (s *Service) GetTunnel(ctx context.Context, id uuid.UUID) (*models.SSHTunnel, error) {
	if s.tunnelRepo == nil {
		return nil, errors.New(errors.CodeInternal, "tunnel repository not configured")
	}
	return s.tunnelRepo.GetByID(ctx, id)
}

// ListTunnelsByConnection retrieves all tunnels for a connection.
func (s *Service) ListTunnelsByConnection(ctx context.Context, connID uuid.UUID) ([]*models.SSHTunnel, error) {
	if s.tunnelRepo == nil {
		return nil, errors.New(errors.CodeInternal, "tunnel repository not configured")
	}
	return s.tunnelRepo.ListByConnection(ctx, connID)
}

// DeleteTunnel removes a tunnel configuration.
func (s *Service) DeleteTunnel(ctx context.Context, id uuid.UUID) error {
	if s.tunnelRepo == nil {
		return errors.New(errors.CodeInternal, "tunnel repository not configured")
	}

	// Stop if running
	s.StopTunnel(ctx, id)

	return s.tunnelRepo.Delete(ctx, id)
}

// StartTunnel starts a port forwarding tunnel.
func (s *Service) StartTunnel(ctx context.Context, tunnelID uuid.UUID) error {
	if s.tunnelRepo == nil {
		return errors.New(errors.CodeInternal, "tunnel repository not configured")
	}

	tunnel, err := s.tunnelRepo.GetByID(ctx, tunnelID)
	if err != nil {
		return err
	}

	// Check if already running
	s.tunnelMu.RLock()
	if _, exists := s.activeTunnels[tunnelID]; exists {
		s.tunnelMu.RUnlock()
		return nil // Already running
	}
	s.tunnelMu.RUnlock()

	// Get connection
	conn, err := s.connRepo.GetByID(ctx, tunnel.ConnectionID)
	if err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "connection not found")
	}

	// Dial SSH
	client, err := s.dial(ctx, conn)
	if err != nil {
		s.tunnelRepo.UpdateStatus(ctx, tunnelID, models.SSHTunnelStatusError, err.Error())
		return err
	}

	// Create stop channel
	stopCh := make(chan struct{})

	s.tunnelMu.Lock()
	s.activeTunnels[tunnelID] = stopCh
	s.tunnelMu.Unlock()

	// Start tunnel in goroutine
	go s.runTunnel(ctx, tunnel, client, stopCh)

	// Update status
	s.tunnelRepo.UpdateStatus(ctx, tunnelID, models.SSHTunnelStatusActive, "")
	s.logger.Info("tunnel started", "tunnel_id", tunnelID, "type", tunnel.Type)

	return nil
}

// StopTunnel stops a running tunnel.
func (s *Service) StopTunnel(ctx context.Context, tunnelID uuid.UUID) error {
	s.tunnelMu.Lock()
	stopCh, exists := s.activeTunnels[tunnelID]
	if exists {
		close(stopCh)
		delete(s.activeTunnels, tunnelID)
	}
	s.tunnelMu.Unlock()

	if s.tunnelRepo != nil {
		s.tunnelRepo.UpdateStatus(ctx, tunnelID, models.SSHTunnelStatusStopped, "")
	}

	s.logger.Info("tunnel stopped", "tunnel_id", tunnelID)
	return nil
}

// ToggleTunnel starts or stops a tunnel based on current status.
func (s *Service) ToggleTunnel(ctx context.Context, tunnelID uuid.UUID) error {
	s.tunnelMu.RLock()
	_, running := s.activeTunnels[tunnelID]
	s.tunnelMu.RUnlock()

	if running {
		return s.StopTunnel(ctx, tunnelID)
	}
	return s.StartTunnel(ctx, tunnelID)
}

// runTunnel handles the actual port forwarding.
func (s *Service) runTunnel(ctx context.Context, tunnel *models.SSHTunnel, client *ssh.Client, stopCh chan struct{}) {
	defer func() {
		s.tunnelMu.Lock()
		delete(s.activeTunnels, tunnel.ID)
		s.tunnelMu.Unlock()
		if s.tunnelRepo != nil {
			s.tunnelRepo.UpdateStatus(ctx, tunnel.ID, models.SSHTunnelStatusStopped, "")
		}
	}()

	switch tunnel.Type {
	case models.SSHTunnelTypeLocal:
		s.runLocalForward(tunnel, client, stopCh)
	case models.SSHTunnelTypeRemote:
		s.runRemoteForward(tunnel, client, stopCh)
	case models.SSHTunnelTypeDynamic:
		s.runDynamicForward(tunnel, client, stopCh)
	}
}

// runLocalForward handles local port forwarding (-L).
func (s *Service) runLocalForward(tunnel *models.SSHTunnel, client *ssh.Client, stopCh chan struct{}) {
	localAddr := fmt.Sprintf("%s:%d", tunnel.LocalHost, tunnel.LocalPort)
	remoteAddr := fmt.Sprintf("%s:%d", tunnel.RemoteHost, tunnel.RemotePort)

	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		s.logger.Error("failed to start local forward listener", "error", err, "addr", localAddr)
		return
	}
	defer listener.Close()

	s.logger.Info("local forward listening", "local", localAddr, "remote", remoteAddr)

	go func() {
		<-stopCh
		listener.Close()
	}()

	for {
		localConn, err := listener.Accept()
		if err != nil {
			select {
			case <-stopCh:
				return // Normal shutdown
			default:
				s.logger.Error("accept error", "error", err)
				continue
			}
		}

		go func(local net.Conn) {
			defer local.Close()

			remote, err := client.Dial("tcp", remoteAddr)
			if err != nil {
				s.logger.Error("failed to dial remote", "error", err, "addr", remoteAddr)
				return
			}
			defer remote.Close()

			s.proxyConnections(local, remote)
		}(localConn)
	}
}

// runRemoteForward handles remote port forwarding (-R).
func (s *Service) runRemoteForward(tunnel *models.SSHTunnel, client *ssh.Client, stopCh chan struct{}) {
	remoteAddr := fmt.Sprintf("%s:%d", tunnel.RemoteHost, tunnel.RemotePort)
	localAddr := fmt.Sprintf("%s:%d", tunnel.LocalHost, tunnel.LocalPort)

	listener, err := client.Listen("tcp", remoteAddr)
	if err != nil {
		s.logger.Error("failed to start remote forward listener", "error", err, "addr", remoteAddr)
		return
	}
	defer listener.Close()

	s.logger.Info("remote forward listening", "remote", remoteAddr, "local", localAddr)

	go func() {
		<-stopCh
		listener.Close()
	}()

	for {
		remoteConn, err := listener.Accept()
		if err != nil {
			select {
			case <-stopCh:
				return
			default:
				s.logger.Error("accept error", "error", err)
				continue
			}
		}

		go func(remote net.Conn) {
			defer remote.Close()

			local, err := net.Dial("tcp", localAddr)
			if err != nil {
				s.logger.Error("failed to dial local", "error", err, "addr", localAddr)
				return
			}
			defer local.Close()

			s.proxyConnections(remote, local)
		}(remoteConn)
	}
}

// runDynamicForward handles SOCKS proxy (-D).
func (s *Service) runDynamicForward(tunnel *models.SSHTunnel, client *ssh.Client, stopCh chan struct{}) {
	localAddr := fmt.Sprintf("%s:%d", tunnel.LocalHost, tunnel.LocalPort)

	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		s.logger.Error("failed to start SOCKS listener", "error", err, "addr", localAddr)
		return
	}
	defer listener.Close()

	s.logger.Info("SOCKS proxy listening", "addr", localAddr)

	go func() {
		<-stopCh
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-stopCh:
				return
			default:
				s.logger.Error("accept error", "error", err)
				continue
			}
		}

		go s.handleSOCKS5(conn, client, stopCh)
	}
}

// handleSOCKS5 handles a SOCKS5 connection (simplified implementation).
func (s *Service) handleSOCKS5(conn net.Conn, client *ssh.Client, stopCh chan struct{}) {
	defer conn.Close()

	// SOCKS5 handshake
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}

	// No auth
	conn.Write([]byte{0x05, 0x00})

	// Read request
	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return
	}

	// Parse destination
	var addr string
	switch buf[3] {
	case 0x01: // IPv4
		addr = fmt.Sprintf("%d.%d.%d.%d:%d", buf[4], buf[5], buf[6], buf[7],
			int(buf[8])<<8|int(buf[9]))
	case 0x03: // Domain
		domainLen := int(buf[4])
		addr = fmt.Sprintf("%s:%d", string(buf[5:5+domainLen]),
			int(buf[5+domainLen])<<8|int(buf[6+domainLen]))
	case 0x04: // IPv6
		addr = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
			int(buf[4])<<8|int(buf[5]), int(buf[6])<<8|int(buf[7]),
			int(buf[8])<<8|int(buf[9]), int(buf[10])<<8|int(buf[11]),
			int(buf[12])<<8|int(buf[13]), int(buf[14])<<8|int(buf[15]),
			int(buf[16])<<8|int(buf[17]), int(buf[18])<<8|int(buf[19]),
			int(buf[20])<<8|int(buf[21]))
	default:
		return
	}

	// Connect through SSH
	remote, err := client.Dial("tcp", addr)
	if err != nil {
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Host unreachable
		return
	}
	defer remote.Close()

	// Success
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	s.proxyConnections(conn, remote)
}

// proxyConnections copies data bidirectionally between two connections.
func (s *Service) proxyConnections(c1, c2 net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		copyBuffer(c1, c2)
		done <- struct{}{}
	}()

	go func() {
		copyBuffer(c2, c1)
		done <- struct{}{}
	}()

	<-done
}

// copyBuffer copies from src to dst.
func copyBuffer(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
}

// Cleanup closes all cached SSH clients and stops all tunnels.
func (s *Service) Cleanup() {
	// Stop all tunnels
	s.tunnelMu.Lock()
	for id, stopCh := range s.activeTunnels {
		close(stopCh)
		delete(s.activeTunnels, id)
	}
	s.tunnelMu.Unlock()

	// Close all clients
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, client := range s.clients {
		client.Close()
		delete(s.clients, id)
	}
}
