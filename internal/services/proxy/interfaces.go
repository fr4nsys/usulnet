// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package proxy

import (
	"context"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// HostRepository defines persistence operations for proxy hosts.
type HostRepository interface {
	Create(ctx context.Context, h *models.ProxyHost) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.ProxyHost, error)
	List(ctx context.Context, hostID uuid.UUID, enabledOnly bool) ([]*models.ProxyHost, error)
	ListAll(ctx context.Context, enabledOnly bool) ([]*models.ProxyHost, error)
	Update(ctx context.Context, h *models.ProxyHost) error
	Delete(ctx context.Context, id uuid.UUID) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.ProxyHostStatus, msg string) error
	GetByContainerID(ctx context.Context, containerID string) (*models.ProxyHost, error)
}

// HeaderRepository defines persistence operations for proxy custom headers.
type HeaderRepository interface {
	ListByHost(ctx context.Context, proxyHostID uuid.UUID) ([]models.ProxyHeader, error)
	ReplaceForHost(ctx context.Context, proxyHostID uuid.UUID, headers []models.ProxyHeader) error
}

// CertificateRepository defines persistence operations for proxy certificates.
type CertificateRepository interface {
	Create(ctx context.Context, c *models.ProxyCertificate) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.ProxyCertificate, error)
	List(ctx context.Context, hostID uuid.UUID) ([]*models.ProxyCertificate, error)
	Update(ctx context.Context, c *models.ProxyCertificate) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// DNSProviderRepository defines persistence operations for DNS providers.
type DNSProviderRepository interface {
	Create(ctx context.Context, p *models.ProxyDNSProvider) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.ProxyDNSProvider, error)
	List(ctx context.Context, hostID uuid.UUID) ([]*models.ProxyDNSProvider, error)
	GetDefault(ctx context.Context, hostID uuid.UUID) (*models.ProxyDNSProvider, error)
	Update(ctx context.Context, p *models.ProxyDNSProvider) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// AuditLogRepository defines persistence for proxy audit logs.
type AuditLogRepository interface {
	Create(ctx context.Context, entry *models.ProxyAuditLog) error
	List(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.ProxyAuditLog, int, error)
}

// Encryptor handles encryption/decryption of sensitive data (DNS API tokens, cert keys).
type Encryptor interface {
	EncryptString(plaintext string) (string, error)
	DecryptString(ciphertext string) (string, error)
}

// AccessListRepository defines persistence for proxy access lists (auth + IP rules).
type AccessListRepository interface {
	Create(ctx context.Context, al *models.ProxyAccessList) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.ProxyAccessList, error)
	List(ctx context.Context, hostID uuid.UUID) ([]*models.ProxyAccessList, error)
	Update(ctx context.Context, al *models.ProxyAccessList) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// DeadHostRepository defines persistence for proxy dead hosts (404 catch-alls).
type DeadHostRepository interface {
	Create(ctx context.Context, d *models.ProxyDeadHost) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.ProxyDeadHost, error)
	List(ctx context.Context, hostID uuid.UUID) ([]*models.ProxyDeadHost, error)
	Update(ctx context.Context, d *models.ProxyDeadHost) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// LocationRepository defines persistence for per-host path routes.
type LocationRepository interface {
	ListByHost(ctx context.Context, proxyHostID uuid.UUID) ([]models.ProxyLocation, error)
	ReplaceForHost(ctx context.Context, proxyHostID uuid.UUID, locations []models.ProxyLocation) error
}

// RedirectionRepository defines persistence for proxy redirections.
type RedirectionRepository interface {
	Create(ctx context.Context, rd *models.ProxyRedirection) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.ProxyRedirection, error)
	List(ctx context.Context, hostID uuid.UUID) ([]*models.ProxyRedirection, error)
	Update(ctx context.Context, rd *models.ProxyRedirection) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// StreamRepository defines persistence for raw TCP/UDP streams.
type StreamRepository interface {
	Create(ctx context.Context, s *models.ProxyStream) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.ProxyStream, error)
	List(ctx context.Context, hostID uuid.UUID) ([]*models.ProxyStream, error)
	Update(ctx context.Context, s *models.ProxyStream) error
	Delete(ctx context.Context, id uuid.UUID) error
}
