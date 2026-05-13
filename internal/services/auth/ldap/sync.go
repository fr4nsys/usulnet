// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package ldap

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// SyncConfig contains configuration for LDAP sync.
type SyncConfig struct {
	// Interval between sync runs
	Interval time.Duration

	// BatchSize for processing users
	BatchSize int

	// DisableUsers that no longer exist in LDAP
	DisableUsers bool

	// UpdateRoles from LDAP groups on sync
	UpdateRoles bool

	// DryRun logs changes without applying them
	DryRun bool
}

// DefaultSyncConfig returns default sync configuration.
func DefaultSyncConfig() SyncConfig {
	return SyncConfig{
		Interval:     6 * time.Hour,
		BatchSize:    100,
		DisableUsers: false,
		UpdateRoles:  true,
		DryRun:       false,
	}
}

// SyncResult contains the result of a sync operation.
type SyncResult struct {
	StartedAt   time.Time
	CompletedAt time.Time
	Duration    time.Duration
	Provider    string

	UsersFound    int
	UsersCreated  int
	UsersUpdated  int
	UsersDisabled int
	UsersSkipped  int
	Errors        []string
}

// SyncService handles LDAP user synchronization.
type SyncService struct {
	clients    []*Client
	userRepo   *postgres.UserRepository
	config     SyncConfig
	logger     *logger.Logger

	mu         sync.Mutex
	running    bool
	lastResult *SyncResult
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

// NewSyncService creates a new LDAP sync service.
func NewSyncService(
	clients []*Client,
	userRepo *postgres.UserRepository,
	config SyncConfig,
	log *logger.Logger,
) *SyncService {
	if log == nil {
		log = logger.Nop()
	}

	return &SyncService{
		clients:  clients,
		userRepo: userRepo,
		config:   config,
		logger:   log.Named("ldap.sync"),
		stopCh:   make(chan struct{}),
	}
}

// Start starts the periodic sync worker.
func (s *SyncService) Start(ctx context.Context) {
	if s.config.Interval <= 0 {
		s.logger.Info("LDAP sync disabled (interval <= 0)")
		return
	}

	s.logger.Info("starting LDAP sync worker",
		"interval", s.config.Interval,
		"providers", len(s.clients),
	)

	// Run initial sync after startup delay (cancelable)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		select {
		case <-time.After(30 * time.Second):
			s.SyncAll(ctx)
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		}
	}()

	// Periodic sync
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(s.config.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.SyncAll(ctx)
			}
		}
	}()
}

// Stop stops the sync worker and waits for goroutines to finish.
func (s *SyncService) Stop() {
	close(s.stopCh)

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		s.logger.Warn("timeout waiting for LDAP sync workers to stop")
	}
}

// SyncAll synchronizes users from all LDAP providers.
func (s *SyncService) SyncAll(ctx context.Context) []*SyncResult {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		s.logger.Warn("sync already in progress, skipping")
		return nil
	}
	s.running = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	results := make([]*SyncResult, 0, len(s.clients))

	for _, client := range s.clients {
		if !client.IsEnabled() {
			continue
		}

		result := s.syncProvider(ctx, client)
		results = append(results, result)

		s.mu.Lock()
		s.lastResult = result
		s.mu.Unlock()
	}

	return results
}

// SyncProvider synchronizes users from a specific LDAP provider.
func (s *SyncService) SyncProvider(ctx context.Context, providerName string) (*SyncResult, error) {
	for _, client := range s.clients {
		if client.GetName() == providerName {
			return s.syncProvider(ctx, client), nil
		}
	}
	return nil, fmt.Errorf("LDAP provider not found: %s", providerName)
}

// syncProvider performs the actual sync for a provider.
func (s *SyncService) syncProvider(ctx context.Context, client *Client) *SyncResult {
	result := &SyncResult{
		StartedAt: time.Now().UTC(),
		Provider:  client.GetName(),
		Errors:    make([]string, 0),
	}

	s.logger.Info("starting LDAP sync",
		"provider", client.GetName(),
		"dry_run", s.config.DryRun,
	)

	// Fetch users from LDAP
	ldapUsers, err := client.SearchUsers(ctx)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("search users: %v", err))
		result.CompletedAt = time.Now().UTC()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)
		s.logger.Error("LDAP sync failed", "provider", client.GetName(), "error", err)
		return result
	}

	result.UsersFound = len(ldapUsers)
	s.logger.Info("found LDAP users", "count", len(ldapUsers), "provider", client.GetName())

	// Track existing LDAP users for disable check
	existingLDAPUsers := make(map[string]bool)

	// Process users in batches
	for i := 0; i < len(ldapUsers); i += s.config.BatchSize {
		end := i + s.config.BatchSize
		if end > len(ldapUsers) {
			end = len(ldapUsers)
		}

		batch := ldapUsers[i:end]
		s.processBatch(ctx, client, batch, result, existingLDAPUsers)
	}

	// Disable users no longer in LDAP
	if s.config.DisableUsers {
		s.disableMissingUsers(ctx, client.GetName(), existingLDAPUsers, result)
	}

	result.CompletedAt = time.Now().UTC()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)

	s.logger.Info("LDAP sync completed",
		"provider", client.GetName(),
		"duration", result.Duration,
		"found", result.UsersFound,
		"created", result.UsersCreated,
		"updated", result.UsersUpdated,
		"disabled", result.UsersDisabled,
		"skipped", result.UsersSkipped,
		"errors", len(result.Errors),
	)

	return result
}

// processBatch processes a batch of LDAP users.
func (s *SyncService) processBatch(
	ctx context.Context,
	client *Client,
	users []User,
	result *SyncResult,
	existingUsers map[string]bool,
) {
	for _, ldapUser := range users {
		if ldapUser.Username == "" {
			result.UsersSkipped++
			continue
		}

		existingUsers[ldapUser.Username] = true

		// Check if user exists
		existingUser, err := s.userRepo.GetByUsername(ctx, ldapUser.Username)
		if err != nil {
			// User doesn't exist, create
			if s.config.DryRun {
				s.logger.Info("[DRY RUN] would create user",
					"username", ldapUser.Username,
					"email", ldapUser.Email,
					"role", ldapUser.Role,
				)
				result.UsersCreated++
				continue
			}

			newUser := &models.User{
				ID:       uuid.New(),
				Username: ldapUser.Username,
				Role:     ldapUser.Role,
				IsActive: true,
				IsLDAP:   true,
			}

			if ldapUser.Email != "" {
				newUser.Email = &ldapUser.Email
			}

			if err := s.userRepo.Create(ctx, newUser); err != nil {
				result.Errors = append(result.Errors,
					fmt.Sprintf("create user %s: %v", ldapUser.Username, err))
				continue
			}

			result.UsersCreated++
			s.logger.Debug("created LDAP user", "username", ldapUser.Username)
			continue
		}

		// User exists, check if update needed
		if !existingUser.IsLDAP {
			// Local user with same username, skip
			result.UsersSkipped++
			s.logger.Warn("skipping LDAP user, local user exists",
				"username", ldapUser.Username)
			continue
		}

		// Check for updates
		needsUpdate := false

		// Update email if changed
		if ldapUser.Email != "" {
			if existingUser.Email == nil || *existingUser.Email != ldapUser.Email {
				if s.config.DryRun {
					s.logger.Info("[DRY RUN] would update email",
						"username", ldapUser.Username,
						"old", existingUser.Email,
						"new", ldapUser.Email,
					)
				} else {
					existingUser.Email = &ldapUser.Email
					needsUpdate = true
				}
			}
		}

		// Update role if configured and changed
		if s.config.UpdateRoles && existingUser.Role != ldapUser.Role {
			if s.config.DryRun {
				s.logger.Info("[DRY RUN] would update role",
					"username", ldapUser.Username,
					"old", existingUser.Role,
					"new", ldapUser.Role,
				)
			} else {
				existingUser.Role = ldapUser.Role
				needsUpdate = true
			}
		}

		// Reactivate if was disabled
		if !existingUser.IsActive {
			if s.config.DryRun {
				s.logger.Info("[DRY RUN] would reactivate user",
					"username", ldapUser.Username,
				)
			} else {
				existingUser.IsActive = true
				needsUpdate = true
			}
		}

		if needsUpdate {
			if err := s.userRepo.Update(ctx, existingUser); err != nil {
				result.Errors = append(result.Errors,
					fmt.Sprintf("update user %s: %v", ldapUser.Username, err))
				continue
			}
			result.UsersUpdated++
			s.logger.Debug("updated LDAP user", "username", ldapUser.Username)
		}
	}
}

// disableMissingUsers disables users that no longer exist in LDAP.
func (s *SyncService) disableMissingUsers(
	ctx context.Context,
	providerName string,
	existingUsers map[string]bool,
	result *SyncResult,
) {
	// Get all active LDAP users from database
	isLDAP := true
	isActive := true
	dbUsers, _, err := s.userRepo.List(ctx, postgres.UserListOptions{
		IsLDAP:   &isLDAP,
		IsActive: &isActive,
		PerPage:  10000, // Get all
	})
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("list users: %v", err))
		return
	}

	for _, user := range dbUsers {
		// Skip if user still exists in LDAP
		if existingUsers[user.Username] {
			continue
		}

		if s.config.DryRun {
			s.logger.Info("[DRY RUN] would disable user",
				"username", user.Username,
				"reason", "not found in LDAP",
			)
			result.UsersDisabled++
			continue
		}

		user.IsActive = false
		if err := s.userRepo.Update(ctx, user); err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("disable user %s: %v", user.Username, err))
			continue
		}

		result.UsersDisabled++
		s.logger.Info("disabled LDAP user",
			"username", user.Username,
			"reason", "not found in LDAP",
		)
	}
}

// GetLastResult returns the last sync result.
func (s *SyncService) GetLastResult() *SyncResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastResult
}

// IsRunning returns whether a sync is currently running.
func (s *SyncService) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// AddClient adds an LDAP client to sync.
func (s *SyncService) AddClient(client *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients = append(s.clients, client)
}

// RemoveClient removes an LDAP client from sync.
func (s *SyncService) RemoveClient(providerName string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, client := range s.clients {
		if client.GetName() == providerName {
			s.clients = append(s.clients[:i], s.clients[i+1:]...)
			return
		}
	}
}

// UpdateConfig updates the sync configuration.
func (s *SyncService) UpdateConfig(config SyncConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = config
}
