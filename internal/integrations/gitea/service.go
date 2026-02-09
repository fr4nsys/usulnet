// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package gitea

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// Service provides Gitea integration functionality.
type Service struct {
	connRepo    *postgres.GiteaConnectionRepository
	repoRepo    *postgres.GiteaRepositoryRepository
	webhookRepo *postgres.GiteaWebhookRepository
	encryptor   *crypto.AESEncryptor
	logger      *logger.Logger
}

// NewService creates a new Gitea integration service.
func NewService(
	connRepo *postgres.GiteaConnectionRepository,
	repoRepo *postgres.GiteaRepositoryRepository,
	webhookRepo *postgres.GiteaWebhookRepository,
	encryptor *crypto.AESEncryptor,
	log *logger.Logger,
) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		connRepo:    connRepo,
		repoRepo:    repoRepo,
		webhookRepo: webhookRepo,
		encryptor:   encryptor,
		logger:      log.Named("gitea"),
	}
}

// ============================================================================
// Connection Management
// ============================================================================

// CreateConnectionInput holds input for creating a Gitea connection.
type CreateConnectionInput struct {
	HostID        uuid.UUID
	Name          string
	URL           string
	APIToken      string
	WebhookSecret string
	CreatedBy     uuid.UUID
}

// CreateConnection creates and tests a new Gitea connection.
func (s *Service) CreateConnection(ctx context.Context, input *CreateConnectionInput) (*models.GiteaConnection, error) {
	if input.Name == "" {
		return nil, errors.New(errors.CodeBadRequest, "name is required")
	}
	if input.URL == "" {
		return nil, errors.New(errors.CodeBadRequest, "URL is required")
	}
	if input.APIToken == "" {
		return nil, errors.New(errors.CodeBadRequest, "API token is required")
	}

	// Normalise URL
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

	conn := &models.GiteaConnection{
		ID:                     uuid.New(),
		HostID:                 input.HostID,
		Name:                   input.Name,
		URL:                    input.URL,
		APITokenEncrypted:      encToken,
		WebhookSecretEncrypted: encWebhookSecret,
		Status:                 models.GiteaStatusPending,
		AutoSync:               true,
		SyncIntervalMinutes:    30,
		CreatedBy:              &input.CreatedBy,
	}

	if err := s.connRepo.Create(ctx, conn); err != nil {
		return nil, err
	}

	// Test connection in background (non-blocking)
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := s.testAndUpdateStatus(bgCtx, conn); err != nil {
			s.logger.Error("initial connection test failed", "id", conn.ID, "error", err)
		}
	}()

	s.logger.Info("gitea connection created", "id", conn.ID, "name", conn.Name, "url", conn.URL)
	return conn, nil
}

// GetConnection retrieves a connection by ID.
func (s *Service) GetConnection(ctx context.Context, id uuid.UUID) (*models.GiteaConnection, error) {
	return s.connRepo.GetByID(ctx, id)
}

// ListConnections returns all connections for a host.
func (s *Service) ListConnections(ctx context.Context, hostID uuid.UUID) ([]*models.GiteaConnection, error) {
	return s.connRepo.ListByHost(ctx, hostID)
}

// ListAllConnections returns all connections.
func (s *Service) ListAllConnections(ctx context.Context) ([]*models.GiteaConnection, error) {
	return s.connRepo.ListAll(ctx)
}

// DeleteConnection removes a connection and all associated data (cascade).
func (s *Service) DeleteConnection(ctx context.Context, id uuid.UUID) error {
	// The foreign keys have ON DELETE CASCADE, so deleting the connection
	// will automatically remove repos and webhooks.
	if err := s.connRepo.Delete(ctx, id); err != nil {
		return err
	}
	s.logger.Info("gitea connection deleted", "id", id)
	return nil
}

// TestConnection tests connectivity and updates status.
func (s *Service) TestConnection(ctx context.Context, id uuid.UUID) (*TestResult, error) {
	conn, err := s.connRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	result := &TestResult{}

	token, err := s.encryptor.DecryptString(conn.APITokenEncrypted)
	if err != nil {
		result.Success = false
		result.Error = "failed to decrypt API token"
		return result, nil
	}

	client := NewClient(conn.URL, token)

	// Test version
	ver, err := client.GetVersion(ctx)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("connection failed: %v", err)
		s.connRepo.UpdateStatus(ctx, id, models.GiteaStatusError, strPtr(result.Error))
		return result, nil
	}
	result.Version = ver.Version

	// Test auth
	user, err := client.GetCurrentUser(ctx)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("authentication failed: %v", err)
		s.connRepo.UpdateStatus(ctx, id, models.GiteaStatusError, strPtr(result.Error))
		return result, nil
	}
	result.Success = true
	result.Username = user.Login
	result.IsAdmin = user.IsAdmin

	giteaVer := ver.Version
	s.connRepo.UpdateStatus(ctx, id, models.GiteaStatusConnected, nil)
	// Update version separately
	s.connRepo.UpdateVersion(ctx, id, &giteaVer)

	return result, nil
}

// TestResult holds the result of a connection test.
type TestResult struct {
	Success  bool   `json:"success"`
	Version  string `json:"version,omitempty"`
	Username string `json:"username,omitempty"`
	IsAdmin  bool   `json:"is_admin,omitempty"`
	Error    string `json:"error,omitempty"`
}

// testAndUpdateStatus tests a connection and updates its status in DB.
func (s *Service) testAndUpdateStatus(ctx context.Context, conn *models.GiteaConnection) error {
	token, err := s.encryptor.DecryptString(conn.APITokenEncrypted)
	if err != nil {
		return err
	}

	client := NewClient(conn.URL, token)

	ver, err := client.GetVersion(ctx)
	if err != nil {
		errMsg := fmt.Sprintf("connection failed: %v", err)
		return s.connRepo.UpdateStatus(ctx, conn.ID, models.GiteaStatusError, &errMsg)
	}

	_, err = client.GetCurrentUser(ctx)
	if err != nil {
		errMsg := fmt.Sprintf("auth failed: %v", err)
		return s.connRepo.UpdateStatus(ctx, conn.ID, models.GiteaStatusError, &errMsg)
	}

	giteaVer := ver.Version
	s.connRepo.UpdateVersion(ctx, conn.ID, &giteaVer)
	return s.connRepo.UpdateStatus(ctx, conn.ID, models.GiteaStatusConnected, nil)
}

// ============================================================================
// Repository Sync
// ============================================================================

// SyncRepositories fetches all repos from a Gitea connection and upserts them.
// Returns the number of repos synced.
func (s *Service) SyncRepositories(ctx context.Context, connectionID uuid.UUID) (int, error) {
	conn, err := s.connRepo.GetByID(ctx, connectionID)
	if err != nil {
		return 0, err
	}

	token, err := s.encryptor.DecryptString(conn.APITokenEncrypted)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternal, "failed to decrypt token")
	}

	client := NewClient(conn.URL, token)

	apiRepos, err := client.ListAllRepos(ctx)
	if err != nil {
		errMsg := fmt.Sprintf("sync failed: %v", err)
		s.connRepo.UpdateStatus(ctx, connectionID, models.GiteaStatusError, &errMsg)
		return 0, errors.Wrap(err, errors.CodeInternal, "failed to list repos from Gitea")
	}

	now := time.Now()
	activeGiteaIDs := make([]int64, 0, len(apiRepos))

	for _, ar := range apiRepos {
		activeGiteaIDs = append(activeGiteaIDs, ar.ID)

		var desc *string
		if ar.Description != "" {
			desc = &ar.Description
		}

		repo := &models.GiteaRepository{
			ConnectionID:  connectionID,
			GiteaID:       ar.ID,
			FullName:      ar.FullName,
			Description:   desc,
			CloneURL:      ar.CloneURL,
			HTMLURL:       ar.HTMLURL,
			DefaultBranch: ar.DefaultBranch,
			IsPrivate:     ar.Private,
			IsFork:        ar.Fork,
			IsArchived:    ar.Archived,
			StarsCount:    ar.Stars,
			ForksCount:    ar.Forks,
			OpenIssues:    ar.OpenIssues,
			SizeKB:        ar.Size,
			LastSyncAt:    &now,
		}

		if err := s.repoRepo.Upsert(ctx, repo); err != nil {
			s.logger.Error("failed to upsert repo", "full_name", ar.FullName, "error", err)
			continue
		}
	}

	// Remove repos no longer in Gitea
	removed, _ := s.repoRepo.DeleteStale(ctx, connectionID, activeGiteaIDs)
	if removed > 0 {
		s.logger.Info("removed stale repos", "count", removed, "connection_id", connectionID)
	}

	// Update sync state
	if err := s.connRepo.UpdateSyncState(ctx, connectionID, len(apiRepos)); err != nil {
		return len(apiRepos), err
	}

	s.logger.Info("repos synced", "connection_id", connectionID, "count", len(apiRepos))
	return len(apiRepos), nil
}

// ListRepositories returns synced repos for a connection.
func (s *Service) ListRepositories(ctx context.Context, connectionID uuid.UUID) ([]*models.GiteaRepository, error) {
	return s.repoRepo.ListByConnection(ctx, connectionID)
}

// ============================================================================
// Webhooks
// ============================================================================

// RegisterWebhook creates a webhook on a Gitea repository pointing back to usulnet.
// callbackURL is the full public URL for the webhook receiver (e.g. https://usulnet.example.com/webhooks/gitea).
func (s *Service) RegisterWebhook(ctx context.Context, connID, repoID uuid.UUID, callbackURL string) error {
	conn, err := s.connRepo.GetByID(ctx, connID)
	if err != nil {
		return err
	}

	repo, err := s.repoRepo.GetByID(ctx, repoID)
	if err != nil {
		return err
	}

	token, err := s.encryptor.DecryptString(conn.APITokenEncrypted)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to decrypt API token")
	}

	var secret string
	if conn.WebhookSecretEncrypted != nil && *conn.WebhookSecretEncrypted != "" {
		secret, err = s.encryptor.DecryptString(*conn.WebhookSecretEncrypted)
		if err != nil {
			return errors.Wrap(err, errors.CodeInternal, "failed to decrypt webhook secret")
		}
	}

	parts := strings.SplitN(repo.FullName, "/", 2)
	if len(parts) != 2 {
		return errors.New(errors.CodeInternal, "invalid repo full_name: "+repo.FullName)
	}

	client := NewClient(conn.URL, token)

	opts := CreateWebhookOptions{
		Type: "gitea",
		Config: WebhookConfig{
			URL:         callbackURL,
			ContentType: "json",
			Secret:      secret,
		},
		Events: []string{"push", "release", "create", "delete"},
		Active: true,
	}

	if err := client.CreateRepoWebhook(ctx, parts[0], parts[1], opts); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to create webhook on Gitea")
	}

	s.logger.Info("webhook registered on Gitea repo",
		"connection_id", connID, "repo", repo.FullName, "callback", callbackURL)
	return nil
}

// HandleWebhook stores and processes a webhook event.
func (s *Service) HandleWebhook(ctx context.Context, connectionID uuid.UUID, eventType, deliveryID string, payload []byte) error {
	evt := &models.GiteaWebhookEvent{
		ID:           uuid.New(),
		ConnectionID: connectionID,
		EventType:    eventType,
		Payload:      payload,
		ReceivedAt:   time.Now(),
	}
	if deliveryID != "" {
		evt.DeliveryID = &deliveryID
	}

	// Try to resolve repository_id from payload
	repoID := s.resolveRepoFromPayload(ctx, connectionID, payload)
	if repoID != nil {
		evt.RepositoryID = repoID
	}

	if err := s.webhookRepo.Create(ctx, evt); err != nil {
		return err
	}

	// Process synchronously for now (push events trigger repo sync)
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s.processWebhookEvent(bgCtx, evt)
	}()

	return nil
}

// ValidateWebhookSignature checks the HMAC-SHA256 signature of a webhook.
func ValidateWebhookSignature(secret string, body []byte, signature string) bool {
	if secret == "" || signature == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}

// GetWebhookSecret decrypts and returns the webhook secret for a connection.
func (s *Service) GetWebhookSecret(ctx context.Context, connectionID uuid.UUID) (string, error) {
	conn, err := s.connRepo.GetByID(ctx, connectionID)
	if err != nil {
		return "", err
	}
	if conn.WebhookSecretEncrypted == nil || *conn.WebhookSecretEncrypted == "" {
		return "", nil
	}
	return s.encryptor.DecryptString(*conn.WebhookSecretEncrypted)
}

// ListWebhookEvents returns recent webhook events for a connection.
func (s *Service) ListWebhookEvents(ctx context.Context, connectionID uuid.UUID, limit int) ([]*models.GiteaWebhookEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	return s.webhookRepo.ListByConnection(ctx, connectionID, limit)
}

// resolveRepoFromPayload tries to extract the gitea repo ID from webhook JSON.
func (s *Service) resolveRepoFromPayload(ctx context.Context, connectionID uuid.UUID, payload []byte) *uuid.UUID {
	var partial struct {
		Repository struct {
			ID int64 `json:"id"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(payload, &partial); err != nil || partial.Repository.ID == 0 {
		return nil
	}

	repo, err := s.repoRepo.GetByGiteaID(ctx, connectionID, partial.Repository.ID)
	if err != nil || repo == nil {
		return nil
	}
	return &repo.ID
}

// processWebhookEvent handles a webhook event asynchronously.
func (s *Service) processWebhookEvent(ctx context.Context, evt *models.GiteaWebhookEvent) {
	var result, processError string

	switch evt.EventType {
	case models.GiteaEventPush:
		// On push, update last_commit info for the repo
		if evt.RepositoryID != nil {
			result = "success"
			var pushPayload WebhookPushPayload
			if err := json.Unmarshal(evt.Payload, &pushPayload); err == nil && pushPayload.After != "" {
				// Could update last_commit_sha here if needed
				s.logger.Debug("push event processed", "repo_id", evt.RepositoryID, "after", pushPayload.After)
			}
		} else {
			result = "skipped"
		}

	case models.GiteaEventRelease:
		result = "success"
		s.logger.Debug("release event received", "connection_id", evt.ConnectionID)

	default:
		result = "skipped"
	}

	if err := s.webhookRepo.MarkProcessed(ctx, evt.ID, result, processError); err != nil {
		s.logger.Error("failed to mark webhook processed", "id", evt.ID, "error", err)
	}
}

// ============================================================================
// Helpers
// ============================================================================

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// clientForConn builds a Gitea API client from a connection ID.
func (s *Service) clientForConn(ctx context.Context, connID uuid.UUID) (*Client, *models.GiteaConnection, error) {
	conn, err := s.connRepo.GetByID(ctx, connID)
	if err != nil {
		return nil, nil, err
	}

	token, err := s.encryptor.DecryptString(conn.APITokenEncrypted)
	if err != nil {
		return nil, nil, errors.Wrap(err, errors.CodeInternal, "failed to decrypt API token")
	}

	return NewClient(conn.URL, token), conn, nil
}

// clientForRepo builds a Gitea API client from a repo ID, returning the owner/repo split.
func (s *Service) clientForRepo(ctx context.Context, repoID uuid.UUID) (*Client, *models.GiteaRepository, string, string, error) {
	repo, err := s.repoRepo.GetByID(ctx, repoID)
	if err != nil {
		return nil, nil, "", "", err
	}

	client, _, err := s.clientForConn(ctx, repo.ConnectionID)
	if err != nil {
		return nil, nil, "", "", err
	}

	parts := strings.SplitN(repo.FullName, "/", 2)
	if len(parts) != 2 {
		return nil, nil, "", "", errors.New(errors.CodeInternal, "invalid repo full_name: "+repo.FullName)
	}

	return client, repo, parts[0], parts[1], nil
}

// ============================================================================
// Repository Access
// ============================================================================

// GetRepository returns a single synced repository by ID.
func (s *Service) GetRepository(ctx context.Context, repoID uuid.UUID) (*models.GiteaRepository, error) {
	return s.repoRepo.GetByID(ctx, repoID)
}

// ============================================================================
// File Operations (proxy to Gitea API)
// ============================================================================

// ListFiles returns directory contents at a path in a repository.
func (s *Service) ListFiles(ctx context.Context, repoID uuid.UUID, path, ref string) ([]APIContentEntry, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}
	return client.ListContents(ctx, owner, repo, path, ref)
}

// GetFileContent returns the raw content of a file in a repository.
func (s *Service) GetFileContent(ctx context.Context, repoID uuid.UUID, path, ref string) ([]byte, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}
	return client.GetRawFile(ctx, owner, repo, path, ref)
}

// UpdateFile creates or updates a file in a repository.
func (s *Service) UpdateFile(ctx context.Context, repoID uuid.UUID, path, ref, content, message string) error {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return err
	}

	// Get current SHA for updates (empty for new files)
	sha, _ := client.GetFileSHA(ctx, owner, repo, path, ref)

	encoded := base64Encode([]byte(content))

	opts := UpdateFileOptions{
		Content: encoded,
		Message: message,
		Branch:  ref,
		SHA:     sha,
	}

	return client.UpdateFile(ctx, owner, repo, path, opts)
}

// ListBranches returns branches for a repository.
func (s *Service) ListBranches(ctx context.Context, repoID uuid.UUID) ([]APIBranch, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}
	return client.ListBranches(ctx, owner, repo)
}

// ListCommits returns recent commits for a branch in a repository.
func (s *Service) ListCommits(ctx context.Context, repoID uuid.UUID, ref string, limit int) ([]APICommitListItem, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}
	return client.ListCommits(ctx, owner, repo, ref, limit)
}

// ============================================================================
// Tier 1: Repository Management
// ============================================================================

// CreateRepositoryInput holds input for creating a new repository.
type CreateRepositoryInput struct {
	ConnectionID  uuid.UUID
	Name          string
	Description   string
	Private       bool
	AutoInit      bool
	Gitignore     string // e.g., "Go", "Python"
	License       string // e.g., "MIT", "Apache-2.0"
	DefaultBranch string
}

// CreateRepository creates a new repository on the Gitea server.
func (s *Service) CreateRepository(ctx context.Context, input *CreateRepositoryInput) (*models.GiteaRepository, error) {
	if input.Name == "" {
		return nil, errors.New(errors.CodeBadRequest, "repository name is required")
	}

	client, conn, err := s.clientForConn(ctx, input.ConnectionID)
	if err != nil {
		return nil, err
	}

	opts := CreateRepoOptions{
		Name:          input.Name,
		Description:   input.Description,
		Private:       input.Private,
		AutoInit:      input.AutoInit,
		Gitignores:    input.Gitignore,
		License:       input.License,
		DefaultBranch: input.DefaultBranch,
	}

	apiRepo, err := client.CreateUserRepository(ctx, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to create repository")
	}

	// Save to our database
	var desc *string
	if apiRepo.Description != "" {
		desc = &apiRepo.Description
	}
	now := time.Now()

	repo := &models.GiteaRepository{
		ID:            uuid.New(),
		ConnectionID:  conn.ID,
		GiteaID:       apiRepo.ID,
		FullName:      apiRepo.FullName,
		Description:   desc,
		HTMLURL:       apiRepo.HTMLURL,
		CloneURL:      apiRepo.CloneURL,
		DefaultBranch: apiRepo.DefaultBranch,
		IsPrivate:     apiRepo.Private,
		IsFork:        apiRepo.Fork,
		IsArchived:    apiRepo.Archived,
		StarsCount:    apiRepo.Stars,
		ForksCount:    apiRepo.Forks,
		OpenIssues:    apiRepo.OpenIssues,
		SizeKB:        apiRepo.Size,
		LastSyncAt:    &now,
		CreatedAt:     now,
	}

	if err := s.repoRepo.Upsert(ctx, repo); err != nil {
		s.logger.Warn("created repo on Gitea but failed to save locally", "repo", apiRepo.FullName, "error", err)
	}

	return repo, nil
}

// EditRepositoryInput holds input for editing a repository.
type EditRepositoryInput struct {
	RepoID        uuid.UUID
	Name          *string
	Description   *string
	Private       *bool
	Archived      *bool
	DefaultBranch *string
	HasIssues     *bool
	HasWiki       *bool
	HasPRs        *bool
}

// EditRepository updates repository settings.
func (s *Service) EditRepository(ctx context.Context, input *EditRepositoryInput) (*models.GiteaRepository, error) {
	client, dbRepo, owner, repoName, err := s.clientForRepo(ctx, input.RepoID)
	if err != nil {
		return nil, err
	}

	opts := EditRepoOptions{
		Name:            input.Name,
		Description:     input.Description,
		Private:         input.Private,
		Archived:        input.Archived,
		DefaultBranch:   input.DefaultBranch,
		HasIssues:       input.HasIssues,
		HasWiki:         input.HasWiki,
		HasPullRequests: input.HasPRs,
	}

	apiRepo, err := client.EditRepository(ctx, owner, repoName, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to edit repository")
	}

	// Update local database
	dbRepo.FullName = apiRepo.FullName
	if apiRepo.Description != "" {
		dbRepo.Description = &apiRepo.Description
	} else {
		dbRepo.Description = nil
	}
	dbRepo.IsPrivate = apiRepo.Private
	dbRepo.IsArchived = apiRepo.Archived
	now := time.Now()
	dbRepo.LastSyncAt = &now

	if err := s.repoRepo.Upsert(ctx, dbRepo); err != nil {
		s.logger.Warn("edited repo on Gitea but failed to update locally", "repo", apiRepo.FullName, "error", err)
	}

	return dbRepo, nil
}

// DeleteRepository permanently deletes a repository from Gitea and local DB.
func (s *Service) DeleteRepository(ctx context.Context, repoID uuid.UUID) error {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return err
	}

	if err := client.DeleteRepository(ctx, owner, repo); err != nil {
		return errors.Wrap(err, errors.CodeExternal, "failed to delete repository on Gitea")
	}

	// Remove from local DB
	if err := s.repoRepo.Delete(ctx, repoID); err != nil {
		s.logger.Warn("deleted repo on Gitea but failed to remove locally", "repoID", repoID, "error", err)
	}

	return nil
}

// ============================================================================
// Tier 1: Branch Management
// ============================================================================

// CreateBranch creates a new branch in a repository.
func (s *Service) CreateBranch(ctx context.Context, repoID uuid.UUID, newBranch, sourceBranch string) (*APIBranch, error) {
	if newBranch == "" {
		return nil, errors.New(errors.CodeBadRequest, "new branch name is required")
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	opts := CreateBranchOptions{
		NewBranchName: newBranch,
		OldBranchName: sourceBranch,
	}

	branch, err := client.CreateBranch(ctx, owner, repo, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to create branch")
	}

	return branch, nil
}

// DeleteBranch deletes a branch from a repository.
func (s *Service) DeleteBranch(ctx context.Context, repoID uuid.UUID, branch string) error {
	if branch == "" {
		return errors.New(errors.CodeBadRequest, "branch name is required")
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return err
	}

	if err := client.DeleteBranch(ctx, owner, repo, branch); err != nil {
		return errors.Wrap(err, errors.CodeExternal, "failed to delete branch")
	}

	return nil
}

// GetBranch returns details for a specific branch.
func (s *Service) GetBranch(ctx context.Context, repoID uuid.UUID, branch string) (*APIBranch, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.GetBranch(ctx, owner, repo, branch)
}

// ============================================================================
// Tier 1: Tag Management
// ============================================================================

// ListTags returns all tags for a repository.
func (s *Service) ListTags(ctx context.Context, repoID uuid.UUID, page, limit int) ([]APITag, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.ListTags(ctx, owner, repo, page, limit)
}

// CreateTag creates a new tag in a repository.
func (s *Service) CreateTag(ctx context.Context, repoID uuid.UUID, tagName, target, message string) (*APITag, error) {
	if tagName == "" {
		return nil, errors.New(errors.CodeBadRequest, "tag name is required")
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	opts := CreateTagOptions{
		TagName: tagName,
		Target:  target,
		Message: message,
	}

	tag, err := client.CreateTag(ctx, owner, repo, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to create tag")
	}

	return tag, nil
}

// DeleteTag deletes a tag from a repository.
func (s *Service) DeleteTag(ctx context.Context, repoID uuid.UUID, tag string) error {
	if tag == "" {
		return errors.New(errors.CodeBadRequest, "tag name is required")
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return err
	}

	if err := client.DeleteTag(ctx, owner, repo, tag); err != nil {
		return errors.Wrap(err, errors.CodeExternal, "failed to delete tag")
	}

	return nil
}

// ============================================================================
// Tier 1: Commit & Diff
// ============================================================================

// GetCommit returns details for a specific commit including changed files.
func (s *Service) GetCommit(ctx context.Context, repoID uuid.UUID, sha string) (*APICommitListItem, error) {
	if sha == "" {
		return nil, errors.New(errors.CodeBadRequest, "commit SHA is required")
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.GetCommit(ctx, owner, repo, sha)
}

// ListCommitsFiltered returns commits with filtering options.
func (s *Service) ListCommitsFiltered(ctx context.Context, repoID uuid.UUID, opts CommitListOptions) ([]APICommitListItem, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.ListCommitsFiltered(ctx, owner, repo, opts)
}

// Compare compares two refs (branches, tags, or commits).
func (s *Service) Compare(ctx context.Context, repoID uuid.UUID, base, head string) (*APICompare, error) {
	if base == "" || head == "" {
		return nil, errors.New(errors.CodeBadRequest, "base and head refs are required")
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	basehead := base + "..." + head
	return client.Compare(ctx, owner, repo, basehead)
}

// GetDiff returns raw diff between two refs.
func (s *Service) GetDiff(ctx context.Context, repoID uuid.UUID, base, head string) ([]byte, error) {
	if base == "" || head == "" {
		return nil, errors.New(errors.CodeBadRequest, "base and head refs are required")
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	basehead := base + "..." + head
	return client.GetDiff(ctx, owner, repo, basehead)
}

// ============================================================================
// Tier 1: Templates (for repo creation UI)
// ============================================================================

// ListGitignoreTemplates returns available gitignore templates.
func (s *Service) ListGitignoreTemplates(ctx context.Context, connectionID uuid.UUID) ([]string, error) {
	client, _, err := s.clientForConn(ctx, connectionID)
	if err != nil {
		return nil, err
	}

	return client.ListGitignoreTemplates(ctx)
}

// ListLicenseTemplates returns available license templates.
func (s *Service) ListLicenseTemplates(ctx context.Context, connectionID uuid.UUID) ([]APILicenseTemplate, error) {
	client, _, err := s.clientForConn(ctx, connectionID)
	if err != nil {
		return nil, err
	}

	return client.ListLicenseTemplates(ctx)
}

// ============================================================================
// Tier 2: Pull Requests
// ============================================================================

// ListPullRequests returns pull requests for a repository.
func (s *Service) ListPullRequests(ctx context.Context, repoID uuid.UUID, opts PRListOptions) ([]APIPullRequest, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.ListPullRequests(ctx, owner, repo, opts)
}

// GetPullRequest returns a single pull request.
func (s *Service) GetPullRequest(ctx context.Context, repoID uuid.UUID, number int64) (*APIPullRequest, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.GetPullRequest(ctx, owner, repo, number)
}

// CreatePullRequest creates a new pull request.
func (s *Service) CreatePullRequest(ctx context.Context, repoID uuid.UUID, opts CreatePullRequestOptions) (*APIPullRequest, error) {
	if opts.Title == "" {
		return nil, errors.New(errors.CodeBadRequest, "PR title is required")
	}
	if opts.Head == "" || opts.Base == "" {
		return nil, errors.New(errors.CodeBadRequest, "head and base branches are required")
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	pr, err := client.CreatePullRequest(ctx, owner, repo, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to create pull request")
	}

	return pr, nil
}

// EditPullRequest updates a pull request.
func (s *Service) EditPullRequest(ctx context.Context, repoID uuid.UUID, number int64, opts EditPullRequestOptions) (*APIPullRequest, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	pr, err := client.EditPullRequest(ctx, owner, repo, number, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to edit pull request")
	}

	return pr, nil
}

// MergePullRequest merges a pull request.
func (s *Service) MergePullRequest(ctx context.Context, repoID uuid.UUID, number int64, opts MergePullRequestOptions) error {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return err
	}

	if err := client.MergePullRequest(ctx, owner, repo, number, opts); err != nil {
		return errors.Wrap(err, errors.CodeExternal, "failed to merge pull request")
	}

	return nil
}

// GetPullRequestDiff returns the diff for a pull request.
func (s *Service) GetPullRequestDiff(ctx context.Context, repoID uuid.UUID, number int64) ([]byte, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.GetPullRequestDiff(ctx, owner, repo, number)
}

// ListPRReviews returns reviews for a pull request.
func (s *Service) ListPRReviews(ctx context.Context, repoID uuid.UUID, number int64) ([]APIPRReview, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.ListPRReviews(ctx, owner, repo, number)
}

// CreatePRReview creates a review on a pull request.
func (s *Service) CreatePRReview(ctx context.Context, repoID uuid.UUID, number int64, opts CreatePRReviewOptions) (*APIPRReview, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	review, err := client.CreatePRReview(ctx, owner, repo, number, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to create review")
	}

	return review, nil
}

// ListPRComments returns comments on a pull request.
func (s *Service) ListPRComments(ctx context.Context, repoID uuid.UUID, number int64) ([]APIComment, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.ListPRComments(ctx, owner, repo, number)
}

// ============================================================================
// Tier 2: Issues
// ============================================================================

// ListIssues returns issues for a repository.
func (s *Service) ListIssues(ctx context.Context, repoID uuid.UUID, opts IssueListOptions) ([]APIIssue, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.ListIssues(ctx, owner, repo, opts)
}

// GetIssue returns a single issue.
func (s *Service) GetIssue(ctx context.Context, repoID uuid.UUID, number int64) (*APIIssue, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.GetIssue(ctx, owner, repo, number)
}

// CreateIssue creates a new issue.
func (s *Service) CreateIssue(ctx context.Context, repoID uuid.UUID, opts CreateIssueOptions) (*APIIssue, error) {
	if opts.Title == "" {
		return nil, errors.New(errors.CodeBadRequest, "issue title is required")
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	issue, err := client.CreateIssue(ctx, owner, repo, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to create issue")
	}

	return issue, nil
}

// EditIssue updates an issue.
func (s *Service) EditIssue(ctx context.Context, repoID uuid.UUID, number int64, opts EditIssueOptions) (*APIIssue, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	issue, err := client.EditIssue(ctx, owner, repo, number, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to edit issue")
	}

	return issue, nil
}

// ListIssueComments returns comments on an issue.
func (s *Service) ListIssueComments(ctx context.Context, repoID uuid.UUID, number int64) ([]APIComment, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.ListIssueComments(ctx, owner, repo, number)
}

// CreateIssueComment creates a comment on an issue.
func (s *Service) CreateIssueComment(ctx context.Context, repoID uuid.UUID, number int64, body string) (*APIComment, error) {
	if body == "" {
		return nil, errors.New(errors.CodeBadRequest, "comment body is required")
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	opts := CreateCommentOptions{Body: body}
	comment, err := client.CreateIssueComment(ctx, owner, repo, number, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to create comment")
	}

	return comment, nil
}

// EditIssueComment updates a comment.
func (s *Service) EditIssueComment(ctx context.Context, repoID uuid.UUID, commentID int64, body string) (*APIComment, error) {
	if body == "" {
		return nil, errors.New(errors.CodeBadRequest, "comment body is required")
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	opts := CreateCommentOptions{Body: body}
	comment, err := client.EditIssueComment(ctx, owner, repo, commentID, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to edit comment")
	}

	return comment, nil
}

// DeleteIssueComment deletes a comment.
func (s *Service) DeleteIssueComment(ctx context.Context, repoID uuid.UUID, commentID int64) error {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return err
	}

	if err := client.DeleteIssueComment(ctx, owner, repo, commentID); err != nil {
		return errors.Wrap(err, errors.CodeExternal, "failed to delete comment")
	}

	return nil
}

// ListLabels returns labels for a repository.
func (s *Service) ListLabels(ctx context.Context, repoID uuid.UUID) ([]APILabel, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.ListLabels(ctx, owner, repo)
}

// ListMilestones returns milestones for a repository.
func (s *Service) ListMilestones(ctx context.Context, repoID uuid.UUID, state string) ([]APIMilestone, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.ListMilestones(ctx, owner, repo, state)
}

// ============================================================================
// Tier 2: Collaborators
// ============================================================================

// ListCollaborators returns collaborators for a repository.
func (s *Service) ListCollaborators(ctx context.Context, repoID uuid.UUID) ([]APICollaborator, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.ListCollaborators(ctx, owner, repo)
}

// IsCollaborator checks if a user is a collaborator.
func (s *Service) IsCollaborator(ctx context.Context, repoID uuid.UUID, username string) (bool, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return false, err
	}

	return client.IsCollaborator(ctx, owner, repo, username)
}

// AddCollaborator adds a user as a collaborator.
func (s *Service) AddCollaborator(ctx context.Context, repoID uuid.UUID, username, permission string) error {
	if username == "" {
		return errors.New(errors.CodeBadRequest, "username is required")
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return err
	}

	opts := AddCollaboratorOptions{Permission: permission}
	if err := client.AddCollaborator(ctx, owner, repo, username, opts); err != nil {
		return errors.Wrap(err, errors.CodeExternal, "failed to add collaborator")
	}

	return nil
}

// RemoveCollaborator removes a collaborator from a repository.
func (s *Service) RemoveCollaborator(ctx context.Context, repoID uuid.UUID, username string) error {
	if username == "" {
		return errors.New(errors.CodeBadRequest, "username is required")
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return err
	}

	if err := client.RemoveCollaborator(ctx, owner, repo, username); err != nil {
		return errors.Wrap(err, errors.CodeExternal, "failed to remove collaborator")
	}

	return nil
}

// GetCollaboratorPermission returns the permission level for a collaborator.
func (s *Service) GetCollaboratorPermission(ctx context.Context, repoID uuid.UUID, username string) (*APIPermissions, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.GetCollaboratorPermission(ctx, owner, repo, username)
}

// ListRepoTeams returns teams with access to a repository.
func (s *Service) ListRepoTeams(ctx context.Context, repoID uuid.UUID) ([]APITeam, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.ListRepoTeams(ctx, owner, repo)
}

// ============================================================================
// Tier 3: Webhooks
// ============================================================================

// ListHooks returns webhooks for a repository.
func (s *Service) ListHooks(ctx context.Context, repoID uuid.UUID) ([]APIHook, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.ListHooks(ctx, owner, repo)
}

// GetHook returns a single webhook.
func (s *Service) GetHook(ctx context.Context, repoID uuid.UUID, hookID int64) (*APIHook, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.GetHook(ctx, owner, repo, hookID)
}

// CreateHook creates a webhook.
func (s *Service) CreateHook(ctx context.Context, repoID uuid.UUID, opts CreateHookOptions) (*APIHook, error) {
	if opts.Type == "" {
		opts.Type = "gitea"
	}
	if opts.Config == nil || opts.Config["url"] == "" {
		return nil, errors.New(errors.CodeBadRequest, "webhook URL is required in config")
	}
	if len(opts.Events) == 0 {
		return nil, errors.New(errors.CodeBadRequest, "at least one event is required")
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	hook, err := client.CreateHook(ctx, owner, repo, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to create webhook")
	}

	return hook, nil
}

// EditHook updates a webhook.
func (s *Service) EditHook(ctx context.Context, repoID uuid.UUID, hookID int64, opts EditHookOptions) (*APIHook, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	hook, err := client.EditHook(ctx, owner, repo, hookID, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to update webhook")
	}

	return hook, nil
}

// DeleteHook deletes a webhook.
func (s *Service) DeleteHook(ctx context.Context, repoID uuid.UUID, hookID int64) error {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return err
	}

	if err := client.DeleteHook(ctx, owner, repo, hookID); err != nil {
		return errors.Wrap(err, errors.CodeExternal, "failed to delete webhook")
	}

	return nil
}

// TestHook tests a webhook.
func (s *Service) TestHook(ctx context.Context, repoID uuid.UUID, hookID int64) error {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return err
	}

	if err := client.TestHook(ctx, owner, repo, hookID); err != nil {
		return errors.Wrap(err, errors.CodeExternal, "failed to test webhook")
	}

	return nil
}

// ============================================================================
// Tier 3: Deploy Keys
// ============================================================================

// ListDeployKeys returns deploy keys for a repository.
func (s *Service) ListDeployKeys(ctx context.Context, repoID uuid.UUID) ([]APIDeployKey, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.ListDeployKeys(ctx, owner, repo)
}

// GetDeployKey returns a single deploy key.
func (s *Service) GetDeployKey(ctx context.Context, repoID uuid.UUID, keyID int64) (*APIDeployKey, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.GetDeployKey(ctx, owner, repo, keyID)
}

// CreateDeployKey creates a deploy key.
func (s *Service) CreateDeployKey(ctx context.Context, repoID uuid.UUID, opts CreateDeployKeyOptions) (*APIDeployKey, error) {
	if opts.Title == "" {
		return nil, errors.New(errors.CodeBadRequest, "deploy key title is required")
	}
	if opts.Key == "" {
		return nil, errors.New(errors.CodeBadRequest, "SSH public key is required")
	}
	// Basic SSH key format validation
	if !strings.HasPrefix(opts.Key, "ssh-") && !strings.HasPrefix(opts.Key, "ecdsa-") {
		return nil, errors.New(errors.CodeBadRequest, "invalid SSH public key format")
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	key, err := client.CreateDeployKey(ctx, owner, repo, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to create deploy key")
	}

	return key, nil
}

// DeleteDeployKey deletes a deploy key.
func (s *Service) DeleteDeployKey(ctx context.Context, repoID uuid.UUID, keyID int64) error {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return err
	}

	if err := client.DeleteDeployKey(ctx, owner, repo, keyID); err != nil {
		return errors.Wrap(err, errors.CodeExternal, "failed to delete deploy key")
	}

	return nil
}

// ============================================================================
// Tier 3: Releases
// ============================================================================

// ListReleases returns releases for a repository.
func (s *Service) ListReleases(ctx context.Context, repoID uuid.UUID, page, limit int) ([]APIRelease, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 50 {
		limit = 20
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.ListReleases(ctx, owner, repo, page, limit)
}

// GetRelease returns a single release.
func (s *Service) GetRelease(ctx context.Context, repoID uuid.UUID, releaseID int64) (*APIRelease, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.GetRelease(ctx, owner, repo, releaseID)
}

// GetReleaseByTag returns a release by tag name.
func (s *Service) GetReleaseByTag(ctx context.Context, repoID uuid.UUID, tag string) (*APIRelease, error) {
	if tag == "" {
		return nil, errors.New(errors.CodeBadRequest, "tag name is required")
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.GetReleaseByTag(ctx, owner, repo, tag)
}

// GetLatestRelease returns the latest release.
func (s *Service) GetLatestRelease(ctx context.Context, repoID uuid.UUID) (*APIRelease, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.GetLatestRelease(ctx, owner, repo)
}

// CreateRelease creates a release.
func (s *Service) CreateRelease(ctx context.Context, repoID uuid.UUID, opts CreateReleaseOptions) (*APIRelease, error) {
	if opts.TagName == "" {
		return nil, errors.New(errors.CodeBadRequest, "tag name is required")
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	release, err := client.CreateRelease(ctx, owner, repo, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to create release")
	}

	return release, nil
}

// EditRelease updates a release.
func (s *Service) EditRelease(ctx context.Context, repoID uuid.UUID, releaseID int64, opts EditReleaseOptions) (*APIRelease, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	release, err := client.EditRelease(ctx, owner, repo, releaseID, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to update release")
	}

	return release, nil
}

// DeleteRelease deletes a release.
func (s *Service) DeleteRelease(ctx context.Context, repoID uuid.UUID, releaseID int64) error {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return err
	}

	if err := client.DeleteRelease(ctx, owner, repo, releaseID); err != nil {
		return errors.Wrap(err, errors.CodeExternal, "failed to delete release")
	}

	return nil
}

// ListReleaseAssets returns assets for a release.
func (s *Service) ListReleaseAssets(ctx context.Context, repoID uuid.UUID, releaseID int64) ([]APIReleaseAsset, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.ListReleaseAssets(ctx, owner, repo, releaseID)
}

// DeleteReleaseAsset deletes a release asset.
func (s *Service) DeleteReleaseAsset(ctx context.Context, repoID uuid.UUID, releaseID, assetID int64) error {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return err
	}

	if err := client.DeleteReleaseAsset(ctx, owner, repo, releaseID, assetID); err != nil {
		return errors.Wrap(err, errors.CodeExternal, "failed to delete release asset")
	}

	return nil
}

// ============================================================================
// Tier 3: Actions / CI Status
// ============================================================================

// ListWorkflows returns workflows for a repository.
func (s *Service) ListWorkflows(ctx context.Context, repoID uuid.UUID) ([]APIWorkflow, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.ListWorkflows(ctx, owner, repo)
}

// ListActionRuns returns workflow runs for a repository.
func (s *Service) ListActionRuns(ctx context.Context, repoID uuid.UUID, opts ActionRunListOptions) ([]APIActionRun, error) {
	if opts.Page < 1 {
		opts.Page = 1
	}
	if opts.Limit < 1 || opts.Limit > 50 {
		opts.Limit = 20
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.ListActionRuns(ctx, owner, repo, opts)
}

// GetActionRun returns a single workflow run.
func (s *Service) GetActionRun(ctx context.Context, repoID uuid.UUID, runID int64) (*APIActionRun, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.GetActionRun(ctx, owner, repo, runID)
}

// ListActionJobs returns jobs for a workflow run.
func (s *Service) ListActionJobs(ctx context.Context, repoID uuid.UUID, runID int64) ([]APIActionJob, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.ListActionJobs(ctx, owner, repo, runID)
}

// GetActionJobLogs returns logs for a job.
func (s *Service) GetActionJobLogs(ctx context.Context, repoID uuid.UUID, jobID int64) ([]byte, error) {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	logs, err := client.GetActionJobLogs(ctx, owner, repo, jobID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to get job logs")
	}

	return logs, nil
}

// CancelActionRun cancels a workflow run.
func (s *Service) CancelActionRun(ctx context.Context, repoID uuid.UUID, runID int64) error {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return err
	}

	if err := client.CancelActionRun(ctx, owner, repo, runID); err != nil {
		return errors.Wrap(err, errors.CodeExternal, "failed to cancel workflow run")
	}

	return nil
}

// RerunActionRun reruns a workflow run.
func (s *Service) RerunActionRun(ctx context.Context, repoID uuid.UUID, runID int64) error {
	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return err
	}

	if err := client.RerunActionRun(ctx, owner, repo, runID); err != nil {
		return errors.Wrap(err, errors.CodeExternal, "failed to rerun workflow")
	}

	return nil
}

// GetCombinedStatus returns the combined status for a commit.
func (s *Service) GetCombinedStatus(ctx context.Context, repoID uuid.UUID, ref string) (*APICombinedStatus, error) {
	if ref == "" {
		return nil, errors.New(errors.CodeBadRequest, "commit ref is required")
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.GetCombinedStatus(ctx, owner, repo, ref)
}

// ListCommitStatuses returns statuses for a commit.
func (s *Service) ListCommitStatuses(ctx context.Context, repoID uuid.UUID, ref string, page, limit int) ([]APICommitStatus, error) {
	if ref == "" {
		return nil, errors.New(errors.CodeBadRequest, "commit ref is required")
	}
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 50 {
		limit = 20
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return client.ListCommitStatuses(ctx, owner, repo, ref, page, limit)
}

// CreateCommitStatus creates a status for a commit.
func (s *Service) CreateCommitStatus(ctx context.Context, repoID uuid.UUID, sha string, opts CreateStatusOptions) (*APICommitStatus, error) {
	if sha == "" {
		return nil, errors.New(errors.CodeBadRequest, "commit SHA is required")
	}
	validStates := map[string]bool{"pending": true, "success": true, "error": true, "failure": true}
	if !validStates[opts.State] {
		return nil, errors.New(errors.CodeBadRequest, "state must be pending, success, error, or failure")
	}

	client, _, owner, repo, err := s.clientForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	status, err := client.CreateCommitStatus(ctx, owner, repo, sha, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to create commit status")
	}

	return status, nil
}

// base64Encode encodes bytes to standard base64.
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
