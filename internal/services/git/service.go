// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package git

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	gitprovider "github.com/fr4nsys/usulnet/internal/integrations/git"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// Service provides unified Git integration for Gitea, GitHub, and GitLab.
type Service struct {
	connRepo      *postgres.GitConnectionRepository
	repoRepo      *postgres.GitRepositoryRepository
	encryptor     *crypto.AESEncryptor
	logger        *logger.Logger
	limitProvider license.LimitProvider
}

// SetLimitProvider sets the license limit provider for enforcing MaxGitConnections.
func (s *Service) SetLimitProvider(lp license.LimitProvider) {
	s.limitProvider = lp
}

// NewService creates a new unified Git service.
func NewService(
	connRepo *postgres.GitConnectionRepository,
	repoRepo *postgres.GitRepositoryRepository,
	encryptor *crypto.AESEncryptor,
	log *logger.Logger,
) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		connRepo:  connRepo,
		repoRepo:  repoRepo,
		encryptor: encryptor,
		logger:    log.Named("git"),
	}
}

// ============================================================================
// Connection Management
// ============================================================================

// CreateConnectionInput holds input for creating a Git connection.
type CreateConnectionInput struct {
	HostID        uuid.UUID
	ProviderType  models.GitProviderType
	Name          string
	URL           string
	APIToken      string
	WebhookSecret string
	CreatedBy     uuid.UUID
}

// CreateConnection creates a new Git connection (any provider).
func (s *Service) CreateConnection(ctx context.Context, input *CreateConnectionInput) (*models.GitConnection, error) {
	// Enforce MaxGitConnections license limit
	if s.limitProvider != nil {
		limit := s.limitProvider.GetLimits().MaxGitConnections
		if limit > 0 {
			count, err := s.connRepo.CountAll(ctx)
			if err == nil && count >= limit {
				return nil, errors.NewWithStatus(errors.CodeLimitExceeded,
					fmt.Sprintf("git connection limit reached (%d/%d), upgrade your license for more", count, limit), 402)
			}
		}
	}

	if input.Name == "" {
		return nil, errors.New(errors.CodeBadRequest, "name is required")
	}
	if input.APIToken == "" {
		return nil, errors.New(errors.CodeBadRequest, "API token is required")
	}

	// Set default URLs based on provider
	switch input.ProviderType {
	case models.GitProviderGitHub:
		if input.URL == "" {
			input.URL = "https://api.github.com"
		}
	case models.GitProviderGitLab:
		if input.URL == "" {
			input.URL = "https://gitlab.com"
		}
	case models.GitProviderGitea:
		if input.URL == "" {
			return nil, errors.New(errors.CodeBadRequest, "URL is required for Gitea")
		}
	default:
		return nil, errors.New(errors.CodeBadRequest, "invalid provider type")
	}

	// Normalize URL
	input.URL = strings.TrimRight(input.URL, "/")

	// Encrypt token
	encToken, err := s.encryptor.EncryptString(input.APIToken)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to encrypt API token")
	}

	var encWebhookSecret *string
	if input.WebhookSecret != "" {
		enc, err := s.encryptor.EncryptString(input.WebhookSecret)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to encrypt webhook secret")
		}
		encWebhookSecret = &enc
	}

	conn := &models.GitConnection{
		ID:                     uuid.New(),
		HostID:                 input.HostID,
		ProviderType:           input.ProviderType,
		Name:                   input.Name,
		URL:                    input.URL,
		APITokenEncrypted:      encToken,
		WebhookSecretEncrypted: encWebhookSecret,
		Status:                 models.GitStatusPending,
		AutoSync:               true,
		SyncIntervalMinutes:    30,
		CreatedBy:              &input.CreatedBy,
	}

	if err := s.connRepo.Create(ctx, conn); err != nil {
		return nil, err
	}

	// Test connection in background
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := s.TestConnection(bgCtx, conn.ID); err != nil {
			s.logger.Error("initial connection test failed", "id", conn.ID, "error", err)
		}
	}()

	s.logger.Info("git connection created",
		"id", conn.ID,
		"name", conn.Name,
		"provider", conn.ProviderType,
		"url", conn.URL,
	)
	return conn, nil
}

// GetConnection retrieves a connection by ID.
func (s *Service) GetConnection(ctx context.Context, id uuid.UUID) (*models.GitConnection, error) {
	return s.connRepo.GetByID(ctx, id)
}

// ListConnections returns all connections for a host.
func (s *Service) ListConnections(ctx context.Context, hostID uuid.UUID) ([]*models.GitConnection, error) {
	return s.connRepo.ListByHost(ctx, hostID)
}

// ListAllConnections returns all connections.
func (s *Service) ListAllConnections(ctx context.Context) ([]*models.GitConnection, error) {
	return s.connRepo.ListAll(ctx)
}

// DeleteConnection removes a connection and all associated data.
func (s *Service) DeleteConnection(ctx context.Context, id uuid.UUID) error {
	// Delete associated repos first
	if err := s.repoRepo.DeleteByConnection(ctx, id); err != nil {
		s.logger.Warn("failed to delete repos for connection", "id", id, "error", err)
	}

	if err := s.connRepo.Delete(ctx, id); err != nil {
		return err
	}
	s.logger.Info("git connection deleted", "id", id)
	return nil
}

// ============================================================================
// Connection Testing
// ============================================================================

// TestResult holds the result of a connection test.
type TestResult struct {
	Success  bool
	Error    string
	Username string
	Version  string
}

// TestConnection tests connectivity and updates status.
func (s *Service) TestConnection(ctx context.Context, id uuid.UUID) (*TestResult, error) {
	conn, err := s.connRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	result := &TestResult{}

	// Get provider
	provider, err := s.getProvider(conn)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		s.connRepo.UpdateStatus(ctx, id, models.GitStatusError, strPtr(result.Error))
		return result, nil
	}

	// Test connection
	if err := provider.TestConnection(ctx); err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("connection failed: %v", err)
		s.connRepo.UpdateStatus(ctx, id, models.GitStatusError, strPtr(result.Error))
		return result, nil
	}

	// Get version
	version, err := provider.GetVersion(ctx)
	if err != nil {
		s.logger.Warn("failed to get provider version", "id", id, "error", err)
	} else {
		result.Version = version
	}

	result.Success = true
	s.connRepo.UpdateStatus(ctx, id, models.GitStatusConnected, nil)
	if version != "" {
		s.connRepo.UpdateVersion(ctx, id, &version)
	}

	return result, nil
}

// ============================================================================
// Repository Sync
// ============================================================================

// SyncRepositories syncs all repositories from a connection.
func (s *Service) SyncRepositories(ctx context.Context, connID uuid.UUID) (int, error) {
	conn, err := s.connRepo.GetByID(ctx, connID)
	if err != nil {
		return 0, err
	}

	provider, err := s.getProvider(conn)
	if err != nil {
		return 0, err
	}

	// List repos from provider
	repos, err := provider.ListRepositories(ctx)
	if err != nil {
		errMsg := fmt.Sprintf("failed to list repositories: %v", err)
		s.connRepo.UpdateStatus(ctx, connID, models.GitStatusError, &errMsg)
		return 0, errors.Wrap(err, errors.CodeExternal, "failed to list repositories")
	}

	// Track active repo IDs for cleanup
	var activeIDs []int64
	now := time.Now()

	for _, r := range repos {
		repo := &models.GitRepository{
			ConnectionID:  connID,
			ProviderType:  conn.ProviderType,
			ProviderID:    r.ProviderID,
			FullName:      r.FullName,
			Description:   r.Description,
			CloneURL:      r.CloneURL,
			HTMLURL:       r.HTMLURL,
			DefaultBranch: r.DefaultBranch,
			IsPrivate:     r.IsPrivate,
			IsFork:        r.IsFork,
			IsArchived:    r.IsArchived,
			StarsCount:    r.StarsCount,
			ForksCount:    r.ForksCount,
			OpenIssues:    r.OpenIssues,
			SizeKB:        r.SizeKB,
			LastSyncAt:    &now,
			CreatedAt:     now,
			UpdatedAt:     now,
		}

		if err := s.repoRepo.Upsert(ctx, repo); err != nil {
			s.logger.Warn("failed to upsert repo", "repo", r.FullName, "error", err)
			continue
		}

		activeIDs = append(activeIDs, r.ProviderID)
	}

	// Remove stale repos
	if err := s.repoRepo.DeleteStale(ctx, connID, activeIDs); err != nil {
		s.logger.Warn("failed to delete stale repos", "connID", connID, "error", err)
	}

	// Update connection status
	s.connRepo.UpdateSyncState(ctx, connID, len(repos))
	s.connRepo.UpdateStatus(ctx, connID, models.GitStatusConnected, nil)

	s.logger.Info("repositories synced", "connID", connID, "count", len(repos))
	return len(repos), nil
}

// ============================================================================
// Repository Operations
// ============================================================================

// GetRepository returns a repository by ID.
func (s *Service) GetRepository(ctx context.Context, id uuid.UUID) (*models.GitRepository, error) {
	return s.repoRepo.GetByID(ctx, id)
}

// ListRepositories returns all repositories for a connection.
func (s *Service) ListRepositories(ctx context.Context, connID uuid.UUID) ([]*models.GitRepository, error) {
	return s.repoRepo.ListByConnection(ctx, connID)
}

// ListAllRepositories returns all repositories.
func (s *Service) ListAllRepositories(ctx context.Context) ([]*models.GitRepository, error) {
	return s.repoRepo.ListAll(ctx)
}

// DeleteRepository deletes a repository from the database.
func (s *Service) DeleteRepository(ctx context.Context, id uuid.UUID) error {
	return s.repoRepo.Delete(ctx, id)
}

// ============================================================================
// Provider Operations (delegated)
// ============================================================================

// GetBranches lists branches for a repository.
func (s *Service) GetBranches(ctx context.Context, repoID uuid.UUID) ([]models.GitBranch, error) {
	repo, err := s.repoRepo.GetByID(ctx, repoID)
	if err != nil {
		return nil, err
	}

	conn, err := s.connRepo.GetByID(ctx, repo.ConnectionID)
	if err != nil {
		return nil, err
	}

	provider, err := s.getProvider(conn)
	if err != nil {
		return nil, err
	}

	return provider.ListBranches(ctx, repo.FullName)
}

// GetCommits lists commits for a repository.
func (s *Service) GetCommits(ctx context.Context, repoID uuid.UUID, branch string, limit int) ([]models.GitCommit, error) {
	repo, err := s.repoRepo.GetByID(ctx, repoID)
	if err != nil {
		return nil, err
	}

	conn, err := s.connRepo.GetByID(ctx, repo.ConnectionID)
	if err != nil {
		return nil, err
	}

	provider, err := s.getProvider(conn)
	if err != nil {
		return nil, err
	}

	opts := gitprovider.ListCommitsOptions{
		SHA:     branch,
		PerPage: limit,
	}
	return provider.ListCommits(ctx, repo.FullName, opts)
}

// GetTags lists tags for a repository.
func (s *Service) GetTags(ctx context.Context, repoID uuid.UUID) ([]models.GitTag, error) {
	repo, err := s.repoRepo.GetByID(ctx, repoID)
	if err != nil {
		return nil, err
	}

	conn, err := s.connRepo.GetByID(ctx, repo.ConnectionID)
	if err != nil {
		return nil, err
	}

	provider, err := s.getProvider(conn)
	if err != nil {
		return nil, err
	}

	return provider.ListTags(ctx, repo.FullName)
}

// GetFileContent gets file content from a repository.
func (s *Service) GetFileContent(ctx context.Context, repoID uuid.UUID, path, ref string) (*models.GitFileContent, error) {
	repo, err := s.repoRepo.GetByID(ctx, repoID)
	if err != nil {
		return nil, err
	}

	conn, err := s.connRepo.GetByID(ctx, repo.ConnectionID)
	if err != nil {
		return nil, err
	}

	provider, err := s.getProvider(conn)
	if err != nil {
		return nil, err
	}

	return provider.GetFileContent(ctx, repo.FullName, path, ref)
}

// ListTree lists directory contents.
func (s *Service) ListTree(ctx context.Context, repoID uuid.UUID, path, ref string) ([]models.GitTreeEntry, error) {
	repo, err := s.repoRepo.GetByID(ctx, repoID)
	if err != nil {
		return nil, err
	}

	conn, err := s.connRepo.GetByID(ctx, repo.ConnectionID)
	if err != nil {
		return nil, err
	}

	provider, err := s.getProvider(conn)
	if err != nil {
		return nil, err
	}

	return provider.ListTree(ctx, repo.FullName, path, ref)
}

// GetPullRequests lists pull requests for a repository.
func (s *Service) GetPullRequests(ctx context.Context, repoID uuid.UUID, state string) ([]models.GitPullRequest, error) {
	repo, err := s.repoRepo.GetByID(ctx, repoID)
	if err != nil {
		return nil, err
	}

	conn, err := s.connRepo.GetByID(ctx, repo.ConnectionID)
	if err != nil {
		return nil, err
	}

	provider, err := s.getProvider(conn)
	if err != nil {
		return nil, err
	}

	opts := gitprovider.ListPROptions{State: state}
	return provider.ListPullRequests(ctx, repo.FullName, opts)
}

// GetIssues lists issues for a repository.
func (s *Service) GetIssues(ctx context.Context, repoID uuid.UUID, state string) ([]models.GitIssue, error) {
	repo, err := s.repoRepo.GetByID(ctx, repoID)
	if err != nil {
		return nil, err
	}

	conn, err := s.connRepo.GetByID(ctx, repo.ConnectionID)
	if err != nil {
		return nil, err
	}

	provider, err := s.getProvider(conn)
	if err != nil {
		return nil, err
	}

	opts := gitprovider.ListIssueOptions{State: state}
	return provider.ListIssues(ctx, repo.FullName, opts)
}

// GetReleases lists releases for a repository.
func (s *Service) GetReleases(ctx context.Context, repoID uuid.UUID) ([]models.GitRelease, error) {
	repo, err := s.repoRepo.GetByID(ctx, repoID)
	if err != nil {
		return nil, err
	}

	conn, err := s.connRepo.GetByID(ctx, repo.ConnectionID)
	if err != nil {
		return nil, err
	}

	provider, err := s.getProvider(conn)
	if err != nil {
		return nil, err
	}

	return provider.ListReleases(ctx, repo.FullName)
}

// GetLatestRelease gets the latest release for a repository.
func (s *Service) GetLatestRelease(ctx context.Context, repoID uuid.UUID) (*models.GitRelease, error) {
	repo, err := s.repoRepo.GetByID(ctx, repoID)
	if err != nil {
		return nil, err
	}

	conn, err := s.connRepo.GetByID(ctx, repo.ConnectionID)
	if err != nil {
		return nil, err
	}

	provider, err := s.getProvider(conn)
	if err != nil {
		return nil, err
	}

	return provider.GetLatestRelease(ctx, repo.FullName)
}

// ============================================================================
// Templates
// ============================================================================

// GetGitignoreTemplates returns available gitignore templates.
func (s *Service) GetGitignoreTemplates(ctx context.Context, connID uuid.UUID) ([]string, error) {
	conn, err := s.connRepo.GetByID(ctx, connID)
	if err != nil {
		return nil, err
	}

	provider, err := s.getProvider(conn)
	if err != nil {
		return nil, err
	}

	return provider.ListGitignoreTemplates(ctx)
}

// GetLicenseTemplates returns available license templates.
func (s *Service) GetLicenseTemplates(ctx context.Context, connID uuid.UUID) ([]gitprovider.LicenseTemplate, error) {
	conn, err := s.connRepo.GetByID(ctx, connID)
	if err != nil {
		return nil, err
	}

	provider, err := s.getProvider(conn)
	if err != nil {
		return nil, err
	}

	return provider.ListLicenseTemplates(ctx)
}

// ============================================================================
// Stats
// ============================================================================

// Stats returns aggregated statistics.
type Stats struct {
	Connections       int
	ActiveConnections int
	Repositories      int
	ByProvider        map[models.GitProviderType]int
}

// GetStats returns statistics.
func (s *Service) GetStats(ctx context.Context) (*Stats, error) {
	connStats, err := s.connRepo.GetStats(ctx)
	if err != nil {
		return nil, err
	}

	repoStats, err := s.repoRepo.GetStats(ctx)
	if err != nil {
		return nil, err
	}

	return &Stats{
		Connections:       connStats.TotalConnections,
		ActiveConnections: connStats.ActiveConnections,
		Repositories:      repoStats.TotalRepos,
		ByProvider:        connStats.ByProvider,
	}, nil
}

// ============================================================================
// Internal helpers
// ============================================================================

// getProvider creates the appropriate provider for a connection.
func (s *Service) getProvider(conn *models.GitConnection) (gitprovider.Provider, error) {
	token, err := s.encryptor.DecryptString(conn.APITokenEncrypted)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decrypt API token")
	}

	return gitprovider.NewProvider(conn.ProviderType, conn.URL, token)
}

func strPtr(s string) *string {
	return &s
}
