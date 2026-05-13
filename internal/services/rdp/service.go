// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package rdp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ConnectionRepository defines the interface for RDP connection storage.
type ConnectionRepository interface {
	Create(ctx context.Context, conn *models.RDPConnection) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.RDPConnection, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.RDPConnection, error)
	Update(ctx context.Context, id uuid.UUID, input models.UpdateRDPConnectionInput) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.RDPConnectionStatus, message string) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// Service manages RDP connections.
type Service struct {
	connRepo ConnectionRepository
	crypto   *crypto.Encryptor
	logger   *logger.Logger
}

// NewService creates a new RDP connection service.
func NewService(
	connRepo ConnectionRepository,
	cryptoSvc *crypto.Encryptor,
	log *logger.Logger,
) *Service {
	return &Service{
		connRepo: connRepo,
		crypto:   cryptoSvc,
		logger:   log.Named("rdp"),
	}
}

// CreateConnection creates a new RDP connection with encrypted password.
func (s *Service) CreateConnection(ctx context.Context, input models.CreateRDPConnectionInput, userID uuid.UUID) (*models.RDPConnection, error) {
	// Encrypt password if provided
	var encryptedPassword string
	if input.Password != "" && s.crypto != nil {
		encrypted, err := s.crypto.EncryptString(input.Password)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to encrypt password")
		}
		encryptedPassword = encrypted
	}

	if input.Port == 0 {
		input.Port = 3389
	}
	if input.Resolution == "" {
		input.Resolution = "1920x1080"
	}
	if input.ColorDepth == "" {
		input.ColorDepth = "32"
	}
	if input.Security == "" {
		input.Security = models.RDPSecurityAny
	}

	conn := &models.RDPConnection{
		UserID:     userID,
		Name:       input.Name,
		Host:       input.Host,
		Port:       input.Port,
		Username:   input.Username,
		Domain:     input.Domain,
		Password:   encryptedPassword,
		Resolution: input.Resolution,
		ColorDepth: input.ColorDepth,
		Security:   input.Security,
		Tags:       input.Tags,
	}

	if err := s.connRepo.Create(ctx, conn); err != nil {
		return nil, err
	}

	s.logger.Info("RDP connection created", "id", conn.ID, "name", conn.Name, "host", conn.Host)
	return conn, nil
}

// GetConnection retrieves an RDP connection by ID.
func (s *Service) GetConnection(ctx context.Context, id uuid.UUID) (*models.RDPConnection, error) {
	return s.connRepo.GetByID(ctx, id)
}

// ListConnections retrieves all RDP connections for a user.
func (s *Service) ListConnections(ctx context.Context, userID uuid.UUID) ([]*models.RDPConnection, error) {
	return s.connRepo.ListByUser(ctx, userID)
}

// UpdateConnection updates an RDP connection.
func (s *Service) UpdateConnection(ctx context.Context, id uuid.UUID, input models.UpdateRDPConnectionInput) error {
	// Encrypt password if being updated
	if input.Password != nil && *input.Password != "" && s.crypto != nil {
		encrypted, err := s.crypto.EncryptString(*input.Password)
		if err != nil {
			return errors.Wrap(err, errors.CodeInternal, "failed to encrypt password")
		}
		input.Password = &encrypted
	}

	return s.connRepo.Update(ctx, id, input)
}

// DeleteConnection deletes an RDP connection.
func (s *Service) DeleteConnection(ctx context.Context, id uuid.UUID) error {
	return s.connRepo.Delete(ctx, id)
}

// TestConnection tests TCP connectivity to the RDP host.
func (s *Service) TestConnection(ctx context.Context, id uuid.UUID) (bool, string, time.Duration, error) {
	conn, err := s.connRepo.GetByID(ctx, id)
	if err != nil {
		return false, "Connection not found", 0, err
	}

	addr := net.JoinHostPort(conn.Host, strconv.Itoa(conn.Port))
	start := time.Now()
	tcpConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	latency := time.Since(start)

	if err != nil {
		_ = s.connRepo.UpdateStatus(ctx, id, models.RDPConnectionError, err.Error())
		return false, fmt.Sprintf("Connection to %s failed: %s", addr, err.Error()), latency, nil
	}
	tcpConn.Close()

	_ = s.connRepo.UpdateStatus(ctx, id, models.RDPConnectionActive, "Connected")
	return true, fmt.Sprintf("Successfully connected to %s (RDP port open)", addr), latency, nil
}
