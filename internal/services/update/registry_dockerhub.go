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
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// DockerHubClient implements RegistryClient for Docker Hub
type DockerHubClient struct {
	httpClient *http.Client
	authToken  string
	logger     *logger.Logger
}

// DockerHubConfig holds configuration for Docker Hub client
type DockerHubConfig struct {
	// Timeout for HTTP requests
	Timeout time.Duration

	// Username for Docker Hub (optional, for private repos)
	Username string

	// Password/Token for Docker Hub
	Password string
}

// NewDockerHubClient creates a new Docker Hub client
func NewDockerHubClient(config *DockerHubConfig, log *logger.Logger) *DockerHubClient {
	timeout := 30 * time.Second
	if config != nil && config.Timeout > 0 {
		timeout = config.Timeout
	}

	client := &DockerHubClient{
		httpClient: &http.Client{
			Timeout: timeout,
		},
		logger: log.Named("dockerhub"),
	}

	return client
}

// SupportsRegistry returns true for Docker Hub registries
func (c *DockerHubClient) SupportsRegistry(registry string) bool {
	switch registry {
	case "docker.io", "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com", "":
		return true
	}
	return false
}

// GetLatestVersion gets the latest version info for an image from Docker Hub
// using variant-aware filtering (e.g. redis:7-alpine only compares against 7.x-alpine tags)
func (c *DockerHubClient) GetLatestVersion(ctx context.Context, ref *models.ImageRef) (*models.ImageVersion, error) {
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

	// Parse current tag to extract variant and major version channel
	currentVariant := extractVariant(currentTag)
	currentMajor := extractMajorVersion(currentTag)

	c.logger.Debug("Version detection",
		"image", ref.Repository,
		"currentTag", currentTag,
		"variant", currentVariant,
		"majorChannel", currentMajor,
		"totalTags", len(tags),
	)

	// If current tag is "latest", find highest semver without variant restriction
	if currentTag == "latest" {
		latestTag := findHighestSemverTag(tags, "", -1)
		if latestTag == "" {
			return nil, nil
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

	// Find highest tag matching same variant + same major version channel
	latestTag := findHighestSemverTag(tags, currentVariant, currentMajor)

	// Fallback: same variant, any major version
	if latestTag == "" || latestTag == currentTag {
		latestTag = findHighestSemverTag(tags, currentVariant, -1)
	}

	// No newer tag found
	if latestTag == "" || latestTag == currentTag {
		return nil, nil
	}

	// Verify it's actually newer
	if !isNewerTag(latestTag, currentTag) {
		return nil, nil
	}

	c.logger.Debug("Found newer version",
		"image", ref.Repository,
		"current", currentTag,
		"latest", latestTag,
	)

	digest, err := c.GetDigest(ctx, &models.ImageRef{
		Registry:   ref.Registry,
		Namespace:  ref.Namespace,
		Repository: ref.Repository,
		Tag:        latestTag,
	})
	if err != nil {
		c.logger.Debug("Failed to get digest for latest tag", "tag", latestTag, "error", err)
	}

	return &models.ImageVersion{
		Tag:       latestTag,
		Digest:    digest,
		CheckedAt: time.Now(),
	}, nil
}

// GetDigest gets the digest for a specific tag
func (c *DockerHubClient) GetDigest(ctx context.Context, ref *models.ImageRef) (string, error) {
	// Get auth token first
	token, err := c.getAuthToken(ctx, ref)
	if err != nil {
		return "", err
	}

	// Build manifest URL
	manifestURL := fmt.Sprintf(
		"https://registry-1.docker.io/v2/%s/%s/manifests/%s",
		ref.Namespace,
		ref.Repository,
		ref.Tag,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, manifestURL, nil)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "failed to create request")
	}

	req.Header.Set("Authorization", "Bearer "+token)
	// Request manifest list or image manifest
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
	if digest == "" {
		digest = resp.Header.Get("Etag")
		digest = strings.Trim(digest, `"`)
	}

	return digest, nil
}

// ListTags lists available tags for an image
func (c *DockerHubClient) ListTags(ctx context.Context, ref *models.ImageRef, limit int) ([]string, error) {
	// Get auth token first
	token, err := c.getAuthToken(ctx, ref)
	if err != nil {
		return nil, err
	}

	// Build tags URL
	tagsURL := fmt.Sprintf(
		"https://registry-1.docker.io/v2/%s/%s/tags/list",
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

// getAuthToken gets an auth token for Docker Hub API
func (c *DockerHubClient) getAuthToken(ctx context.Context, ref *models.ImageRef) (string, error) {
	scope := fmt.Sprintf("repository:%s/%s:pull", ref.Namespace, ref.Repository)
	authURL := fmt.Sprintf(
		"https://auth.docker.io/token?service=registry.docker.io&scope=%s",
		url.QueryEscape(scope),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "failed to create auth request")
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
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "failed to decode auth response")
	}

	token := result.Token
	if token == "" {
		token = result.AccessToken
	}

	return token, nil
}

// ============================================================================
// Docker Hub API Types
// ============================================================================

// DockerHubTagsResponse represents the Docker Hub tags API response
type DockerHubTagsResponse struct {
	Count    int             `json:"count"`
	Next     string          `json:"next"`
	Previous string          `json:"previous"`
	Results  []DockerHubTag  `json:"results"`
}

// DockerHubTag represents a single tag from Docker Hub
type DockerHubTag struct {
	Name        string             `json:"name"`
	FullSize    int64              `json:"full_size"`
	LastUpdated time.Time          `json:"last_updated"`
	Images      []DockerHubImage   `json:"images"`
}

// DockerHubImage represents image details within a tag
type DockerHubImage struct {
	Architecture string    `json:"architecture"`
	Digest       string    `json:"digest"`
	OS           string    `json:"os"`
	Size         int64     `json:"size"`
	LastPushed   time.Time `json:"last_pushed"`
}

// GetTagsFromHubAPI gets tags using the Docker Hub API (not registry API)
// This provides more information like last_updated
func (c *DockerHubClient) GetTagsFromHubAPI(ctx context.Context, namespace, repository string, page, pageSize int) (*DockerHubTagsResponse, error) {
	if pageSize <= 0 {
		pageSize = 25
	}
	if page <= 0 {
		page = 1
	}

	apiURL := fmt.Sprintf(
		"https://hub.docker.com/v2/repositories/%s/%s/tags?page=%d&page_size=%d&ordering=-last_updated",
		namespace,
		repository,
		page,
		pageSize,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to create request")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to fetch tags")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(errors.CodeExternal, "failed to fetch tags").
			WithDetail("status", resp.StatusCode)
	}

	var result DockerHubTagsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode response")
	}

	return &result, nil
}

// GetLatestSemverTag finds the latest semantic version tag
func (c *DockerHubClient) GetLatestSemverTag(ctx context.Context, ref *models.ImageRef) (string, error) {
	tags, err := c.ListTags(ctx, ref, 100)
	if err != nil {
		return "", err
	}

	// Filter and sort semver tags
	semverTags := make([]string, 0)
	for _, tag := range tags {
		if IsSemver(tag) && !IsPrerelease(tag) {
			semverTags = append(semverTags, tag)
		}
	}

	if len(semverTags) == 0 {
		return "", errors.New(errors.CodeNotFound, "no semver tags found")
	}

	// Sort by version (descending)
	sort.Slice(semverTags, func(i, j int) bool {
		return CompareSemver(semverTags[i], semverTags[j]) > 0
	})

	return semverTags[0], nil
}

