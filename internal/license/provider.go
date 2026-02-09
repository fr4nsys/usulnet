// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package license

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Logger is a minimal logging interface for the license package.
type Logger interface {
	Info(msg string, keysAndValues ...any)
	Warn(msg string, keysAndValues ...any)
	Error(msg string, keysAndValues ...any)
}

// Provider is the central runtime authority for license state.
// It is safe for concurrent use.
type Provider struct {
	mu         sync.RWMutex
	info       *Info
	rawJWT     string
	validator  *Validator
	store      *Store
	instanceID string
	logger     Logger
	stopCh     chan struct{}
}

// NewProvider creates a Provider that:
//  1. Parses the embedded RSA-4096 public key
//  2. Generates (or loads) the instance fingerprint
//  3. Attempts to load a stored license JWT from disk
//  4. Falls back to CE if none found or invalid
//  5. Starts a background goroutine that re-validates every 6 hours
func NewProvider(dataDir string, logger Logger) (*Provider, error) {
	validator, err := NewValidator()
	if err != nil {
		return nil, fmt.Errorf("license provider: %w", err)
	}

	instanceID, err := GenerateInstanceID(dataDir)
	if err != nil {
		logger.Warn("license: could not generate instance ID, continuing without", "error", err)
		instanceID = "unknown"
	}

	store := NewStore(dataDir)

	p := &Provider{
		info:       NewCEInfo(),
		validator:  validator,
		store:      store,
		instanceID: instanceID,
		logger:     logger,
		stopCh:     make(chan struct{}),
	}

	// Try to load stored license
	if rawJWT, err := store.Load(); err != nil {
		logger.Warn("license: failed to load stored license", "error", err)
	} else if rawJWT != "" {
		if err := p.activate(rawJWT); err != nil {
			logger.Warn("license: stored license is invalid, falling back to CE", "error", err)
		} else {
			logger.Info("license: loaded stored license",
				"edition", p.info.Edition,
				"license_id", p.info.LicenseID,
				"expires_at", p.info.ExpiresAt,
			)
		}
	}

	// Start background re-validation
	go p.backgroundValidator()

	return p, nil
}

// Activate validates and applies a new license JWT.
// On success, it persists the JWT to disk.
func (p *Provider) Activate(licenseKey string) error {
	if err := p.activate(licenseKey); err != nil {
		return err
	}

	// Persist to disk
	if err := p.store.Save(licenseKey); err != nil {
		p.logger.Error("license: failed to persist license to disk", "error", err)
		// Don't fail activation — it's active in memory
	}

	p.logger.Info("license: activated",
		"edition", p.info.Edition,
		"license_id", p.info.LicenseID,
		"nodes", p.info.Limits.MaxNodes,
		"users", p.info.Limits.MaxUsers,
	)

	return nil
}

func (p *Provider) activate(licenseKey string) error {
	claims, err := p.validator.Validate(licenseKey)
	if err != nil {
		return err
	}

	info := ClaimsToInfo(claims, p.instanceID)
	if !info.Valid {
		return fmt.Errorf("license: token is expired")
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.info = info
	p.rawJWT = licenseKey
	return nil
}

// Deactivate removes the license and reverts to CE.
func (p *Provider) Deactivate() error {
	p.mu.Lock()
	p.info = NewCEInfo()
	p.rawJWT = ""
	p.mu.Unlock()

	if err := p.store.Remove(); err != nil {
		return fmt.Errorf("license: failed to remove stored license: %w", err)
	}

	p.logger.Info("license: deactivated, reverted to CE")
	return nil
}

// GetInfo returns a snapshot of the current license state.
func (p *Provider) GetInfo() *Info {
	p.mu.RLock()
	defer p.mu.RUnlock()
	// Return a copy to prevent mutation
	cp := *p.info
	return &cp
}

// GetLicense returns the current license info (satisfies LicenseProvider).
func (p *Provider) GetLicense(ctx context.Context) (*Info, error) {
	return p.GetInfo(), nil
}

// HasFeature checks if a feature is enabled (satisfies LicenseProvider).
func (p *Provider) HasFeature(ctx context.Context, feature Feature) bool {
	info := p.GetInfo()
	return info.HasFeature(feature)
}

// IsValid returns true if the license is valid and not expired (satisfies LicenseProvider).
func (p *Provider) IsValid(ctx context.Context) bool {
	info := p.GetInfo()
	return info.Valid && !info.IsExpired()
}

// GetLimits returns the current resource limits.
func (p *Provider) GetLimits() Limits {
	info := p.GetInfo()
	return info.Limits
}

// Edition returns the current edition.
func (p *Provider) Edition() Edition {
	info := p.GetInfo()
	return info.Edition
}

// InstanceID returns the computed instance fingerprint.
func (p *Provider) InstanceID() string {
	return p.instanceID
}

// RawJWT returns the stored JWT string (empty for CE).
func (p *Provider) RawJWT() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.rawJWT
}

// Stop terminates the background re-validation goroutine.
func (p *Provider) Stop() {
	close(p.stopCh)
}

// backgroundValidator re-checks the license every 6 hours.
// If the license has expired, it downgrades features but keeps
// the edition marker so the UI can show "expired" rather than "CE".
func (p *Provider) backgroundValidator() {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.mu.RLock()
			rawJWT := p.rawJWT
			p.mu.RUnlock()

			if rawJWT == "" {
				continue // CE, nothing to re-validate
			}

			claims, err := p.validator.Validate(rawJWT)
			if err != nil {
				p.logger.Warn("license: background re-validation failed", "error", err)
				p.mu.Lock()
				p.info.Valid = false
				p.mu.Unlock()
				continue
			}

			info := ClaimsToInfo(claims, p.instanceID)
			p.mu.Lock()
			p.info = info
			p.mu.Unlock()

			if !info.Valid {
				p.logger.Warn("license: license has expired",
					"license_id", info.LicenseID,
					"expired_at", info.ExpiresAt,
				)
			}
		}
	}
}
