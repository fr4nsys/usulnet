// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// GHCRClient implements RegistryClient for GitHub Container Registry
type GHCRClient struct {
	httpClient *http.Client
	token      string
	logger     *logger.Logger
}

// GHCRConfig holds configuration for GHCR client
type GHCRConfig struct {
	// Timeout for HTTP requests
	Timeout time.Duration

	// Token is the GitHub token (PAT or GITHUB_TOKEN)
	// Required for private packages, optional for public
	Token string
}

// NewGHCRClient creates a new GHCR client
func NewGHCRClient(config *GHCRConfig, log *logger.Logger) *GHCRClient {
	timeout := 30 * time.Second
	token := ""

	if config != nil {
		if config.Timeout > 0 {
			timeout = config.Timeout
		}
		token = config.Token
	}

	return &GHCRClient{
		httpClient: &http.Client{
			Timeout: timeout,
		},
		token:  token,
		logger: log.Named("ghcr"),
	}
}

// SupportsRegistry returns true for GHCR
func (c *GHCRClient) SupportsRegistry(registry string) bool {
	return registry == "ghcr.io"
}

// GetLatestVersion gets the latest version info for an image from GHCR
func (c *GHCRClient) GetLatestVersion(ctx context.Context, ref *models.ImageRef) (*models.ImageVersion, error) {
	tags, err := c.ListTags(ctx, ref, 100)
	if err != nil {
		return nil, err
	}

	if len(tags) == 0 {
		return nil, errors.New(errors.CodeNotFound, "no tags found")
	}

	currentTag := ref.Tag
	if currentTag == "" {
		currentTag = "latest"
	}

	currentVariant := extractVariant(currentTag)
	currentMajor := extractMajorVersion(currentTag)

	if currentTag == "latest" {
		latestTag := findHighestSemverTag(tags, "", -1)
		if latestTag == "" {
			return nil, nil
		}
		digest, _ := c.GetDigest(ctx, &models.ImageRef{
			Registry: ref.Registry, Namespace: ref.Namespace,
			Repository: ref.Repository, Tag: latestTag,
		})
		return &models.ImageVersion{
			Tag: latestTag, Digest: digest, CheckedAt: time.Now(),
		}, nil
	}

	latestTag := findHighestSemverTag(tags, currentVariant, currentMajor)
	if latestTag == "" || latestTag == currentTag {
		latestTag = findHighestSemverTag(tags, currentVariant, -1)
	}
	if latestTag == "" || latestTag == currentTag {
		return nil, nil
	}
	if !isNewerTag(latestTag, currentTag) {
		return nil, nil
	}

	digest, err := c.GetDigest(ctx, &models.ImageRef{
		Registry: ref.Registry, Namespace: ref.Namespace,
		Repository: ref.Repository, Tag: latestTag,
	})
	if err != nil {
		c.logger.Debug("Failed to get digest", "tag", latestTag, "error", err)
	}

	return &models.ImageVersion{
		Tag: latestTag, Digest: digest, CheckedAt: time.Now(),
	}, nil
}

// GetDigest gets the digest for a specific tag
func (c *GHCRClient) GetDigest(ctx context.Context, ref *models.ImageRef) (string, error) {
	// Get token for GHCR
	token, err := c.getAuthToken(ctx, ref)
	if err != nil {
		return "", err
	}

	// Build manifest URL
	manifestURL := fmt.Sprintf(
		"https://ghcr.io/v2/%s/%s/manifests/%s",
		ref.Namespace,
		ref.Repository,
		ref.Tag,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, manifestURL, nil)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "failed to create request")
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.oci.image.manifest.v1+json",
	}, ", "))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeExternal, "failed to fetch manifest")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New(errors.CodeExternal, "manifest not found").
			WithDetail("status", resp.StatusCode)
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	return digest, nil
}

// ListTags lists available tags for an image
func (c *GHCRClient) ListTags(ctx context.Context, ref *models.ImageRef, limit int) ([]string, error) {
	token, err := c.getAuthToken(ctx, ref)
	if err != nil {
		return nil, err
	}

	tagsURL := fmt.Sprintf(
		"https://ghcr.io/v2/%s/%s/tags/list",
		ref.Namespace,
		ref.Repository,
	)

	if limit > 0 {
		tagsURL += fmt.Sprintf("?n=%d", limit)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tagsURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to create request")
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to list tags")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.New(errors.CodeExternal, "failed to list tags").
			WithDetail("status", resp.StatusCode).
			WithDetail("body", string(body))
	}

	var result struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode response")
	}

	return result.Tags, nil
}

// getAuthToken gets an auth token for GHCR
func (c *GHCRClient) getAuthToken(ctx context.Context, ref *models.ImageRef) (string, error) {
	scope := fmt.Sprintf("repository:%s/%s:pull", ref.Namespace, ref.Repository)
	authURL := fmt.Sprintf(
		"https://ghcr.io/token?scope=%s",
		scope,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "failed to create auth request")
	}

	// If we have a configured token, use it for private repos
	if c.token != "" {
		req.SetBasicAuth("token", c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeExternal, "failed to get auth token")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New(errors.CodeExternal, "auth failed").
			WithDetail("status", resp.StatusCode)
	}

	var result struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "failed to decode auth response")
	}

	return result.Token, nil
}

// ============================================================================
// GitHub Releases API Client
// ============================================================================

// GitHubReleasesClient fetches release information from GitHub
type GitHubReleasesClient struct {
	httpClient *http.Client
	token      string
	logger     *logger.Logger
}

// NewGitHubReleasesClient creates a new GitHub releases client
func NewGitHubReleasesClient(token string, log *logger.Logger) *GitHubReleasesClient {
	return &GitHubReleasesClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		token:  token,
		logger: log.Named("github-releases"),
	}
}

// GitHubRelease represents a GitHub release
type GitHubRelease struct {
	ID          int64     `json:"id"`
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	HTMLURL     string    `json:"html_url"`
	Author      struct {
		Login string `json:"login"`
	} `json:"author"`
}

// GetLatestRelease gets the latest release for a repository
func (c *GitHubReleasesClient) GetLatestRelease(ctx context.Context, owner, repo string) (*GitHubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)

	release, err := c.fetchRelease(ctx, url)
	if err != nil {
		// If no releases, try tags
		c.logger.Debug("No releases found, trying tags", "owner", owner, "repo", repo)
		return nil, err
	}

	return release, nil
}

// GetReleaseByTag gets a specific release by tag
func (c *GitHubReleasesClient) GetReleaseByTag(ctx context.Context, owner, repo, tag string) (*GitHubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s", owner, repo, tag)
	return c.fetchRelease(ctx, url)
}

// ListReleases lists releases for a repository
func (c *GitHubReleasesClient) ListReleases(ctx context.Context, owner, repo string, perPage int) ([]*GitHubRelease, error) {
	if perPage <= 0 {
		perPage = 30
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases?per_page=%d", owner, repo, perPage)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to create request")
	}

	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to fetch releases")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(errors.CodeExternal, "failed to list releases").
			WithDetail("status", resp.StatusCode)
	}

	var releases []*GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode response")
	}

	return releases, nil
}

// fetchRelease fetches a single release
func (c *GitHubReleasesClient) fetchRelease(ctx context.Context, url string) (*GitHubRelease, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to create request")
	}

	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to fetch release")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New(errors.CodeNotFound, "release not found")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(errors.CodeExternal, "failed to fetch release").
			WithDetail("status", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode response")
	}

	return &release, nil
}

// setHeaders sets common headers for GitHub API requests
func (c *GitHubReleasesClient) setHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

// ToChangelog converts a GitHub release to a Changelog model
func (r *GitHubRelease) ToChangelog() *models.Changelog {
	return &models.Changelog{
		Version:      r.TagName,
		Title:        r.Name,
		Body:         r.Body,
		URL:          r.HTMLURL,
		PublishedAt:  &r.PublishedAt,
		IsPrerelease: r.Prerelease,
		IsDraft:      r.Draft,
		Author:       r.Author.Login,
	}
}

// ============================================================================
// Generic OCI Registry Client
// ============================================================================

// GenericRegistryClient implements RegistryClient for generic OCI registries
type GenericRegistryClient struct {
	httpClient *http.Client
	registries []string
	username   string
	password   string
	logger     *logger.Logger
}

// GenericRegistryConfig holds configuration for generic registry client
type GenericRegistryConfig struct {
	Timeout    time.Duration
	Registries []string // List of supported registries
	Username   string
	Password   string
}

// NewGenericRegistryClient creates a new generic registry client
func NewGenericRegistryClient(config *GenericRegistryConfig, log *logger.Logger) *GenericRegistryClient {
	timeout := 30 * time.Second
	if config != nil && config.Timeout > 0 {
		timeout = config.Timeout
	}

	registries := []string{}
	username := ""
	password := ""

	if config != nil {
		registries = config.Registries
		username = config.Username
		password = config.Password
	}

	return &GenericRegistryClient{
		httpClient: &http.Client{
			Timeout: timeout,
		},
		registries: registries,
		username:   username,
		password:   password,
		logger:     log.Named("generic-registry"),
	}
}

// SupportsRegistry returns true if registry is in the configured list
func (c *GenericRegistryClient) SupportsRegistry(registry string) bool {
	for _, r := range c.registries {
		if r == registry {
			return true
		}
	}
	return false
}

// GetLatestVersion gets the latest version info
func (c *GenericRegistryClient) GetLatestVersion(ctx context.Context, ref *models.ImageRef) (*models.ImageVersion, error) {
	tags, err := c.ListTags(ctx, ref, 100)
	if err != nil {
		return nil, err
	}

	if len(tags) == 0 {
		return nil, errors.New(errors.CodeNotFound, "no tags found")
	}

	sortedTags := sortTagsBySemver(tags)

	var latestTag string
	for _, tag := range sortedTags {
		if tag == "latest" {
			continue
		}
		latestTag = tag
		break
	}

	if latestTag == "" {
		latestTag = "latest"
	}

	digest, _ := c.GetDigest(ctx, &models.ImageRef{
		Registry:   ref.Registry,
		Namespace:  ref.Namespace,
		Repository: ref.Repository,
		Tag:        latestTag,
	})

	return &models.ImageVersion{
		Tag:       latestTag,
		Digest:    digest,
		CheckedAt: time.Now(),
	}, nil
}

// GetDigest gets the digest for a specific tag
func (c *GenericRegistryClient) GetDigest(ctx context.Context, ref *models.ImageRef) (string, error) {
	manifestURL := fmt.Sprintf(
		"https://%s/v2/%s/%s/manifests/%s",
		ref.Registry,
		ref.Namespace,
		ref.Repository,
		ref.Tag,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, manifestURL, nil)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "failed to create request")
	}

	if c.username != "" && c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.oci.image.manifest.v1+json",
	}, ", "))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeExternal, "failed to fetch manifest")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New(errors.CodeExternal, "manifest not found").
			WithDetail("status", resp.StatusCode)
	}

	return resp.Header.Get("Docker-Content-Digest"), nil
}

// ListTags lists available tags
func (c *GenericRegistryClient) ListTags(ctx context.Context, ref *models.ImageRef, limit int) ([]string, error) {
	tagsURL := fmt.Sprintf(
		"https://%s/v2/%s/%s/tags/list",
		ref.Registry,
		ref.Namespace,
		ref.Repository,
	)

	if limit > 0 {
		tagsURL += fmt.Sprintf("?n=%d", limit)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tagsURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to create request")
	}

	if c.username != "" && c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to list tags")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(errors.CodeExternal, "failed to list tags").
			WithDetail("status", resp.StatusCode)
	}

	var result struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode response")
	}

	return result.Tags, nil
}
