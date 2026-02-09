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
	"regexp"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// SourceInfo contains information about the source repository
type SourceInfo struct {
	Type       string // "github" or "gitlab"
	URL        string
	Owner      string
	Repository string
}

// DetectSource detects the source repository from container labels
func DetectSource(labels map[string]string) *SourceInfo {
	if labels == nil {
		return nil
	}

	// Check OCI labels first (standard)
	if source, ok := labels["org.opencontainers.image.source"]; ok {
		return parseSourceURL(source)
	}

	// Check legacy labels
	if source, ok := labels["org.label-schema.vcs-url"]; ok {
		return parseSourceURL(source)
	}

	// Check common vendor labels
	if source, ok := labels["com.docker.source"]; ok {
		return parseSourceURL(source)
	}

	return nil
}

// parseSourceURL parses a source URL and extracts owner/repo information
func parseSourceURL(sourceURL string) *SourceInfo {
	if sourceURL == "" {
		return nil
	}

	// Parse the URL
	u, err := url.Parse(sourceURL)
	if err != nil {
		return nil
	}

	// Remove .git suffix if present
	path := strings.TrimSuffix(u.Path, ".git")
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")

	if len(parts) < 2 {
		return nil
	}

	owner := parts[0]
	repo := parts[1]

	// Determine type based on host
	var sourceType string
	switch {
	case strings.Contains(u.Host, "github"):
		sourceType = "github"
	case strings.Contains(u.Host, "gitlab"):
		sourceType = "gitlab"
	default:
		// Default to github for unknown hosts
		sourceType = "github"
	}

	return &SourceInfo{
		Type:       sourceType,
		URL:        sourceURL,
		Owner:      owner,
		Repository: repo,
	}
}

// ChangelogFetcher fetches changelogs from various sources
type ChangelogFetcher struct {
	httpClient   *http.Client
	githubToken  string
	gitlabToken  string
	cacheRepo    ChangelogCacheRepository
	logger       *logger.Logger
}

// ChangelogFetcherConfig holds configuration for the changelog fetcher
type ChangelogFetcherConfig struct {
	Timeout     time.Duration
	GitHubToken string
	GitLabToken string
}

// ChangelogCacheRepository interface for caching changelogs
type ChangelogCacheRepository interface {
	Get(ctx context.Context, image, version string) (*models.Changelog, error)
	Set(ctx context.Context, image, version string, changelog *models.Changelog, expiresAt time.Time) error
}

// NewChangelogFetcher creates a new changelog fetcher
func NewChangelogFetcher(config *ChangelogFetcherConfig, cacheRepo ChangelogCacheRepository, log *logger.Logger) *ChangelogFetcher {
	timeout := 30 * time.Second
	githubToken := ""
	gitlabToken := ""

	if config != nil {
		if config.Timeout > 0 {
			timeout = config.Timeout
		}
		githubToken = config.GitHubToken
		gitlabToken = config.GitLabToken
	}

	return &ChangelogFetcher{
		httpClient: &http.Client{
			Timeout: timeout,
		},
		githubToken: githubToken,
		gitlabToken: gitlabToken,
		cacheRepo:   cacheRepo,
		logger:      log.Named("changelog"),
	}
}

// FetchChangelog fetches a changelog for the given image and version
func (f *ChangelogFetcher) FetchChangelog(ctx context.Context, image, version string, labels map[string]string) (*models.Changelog, error) {
	log := f.logger.With("image", image, "version", version)

	// Check cache first
	if f.cacheRepo != nil {
		if cached, err := f.cacheRepo.Get(ctx, image, version); err == nil && cached != nil {
			log.Debug("Using cached changelog")
			return cached, nil
		}
	}

	// Try to detect source from labels
	source := DetectSource(labels)
	if source == nil {
		// Try to infer from image name
		source = f.inferSourceFromImage(image)
	}

	if source == nil {
		log.Debug("Could not determine source repository")
		return nil, errors.New(errors.CodeNotFound, "source repository not found")
	}

	var changelog *models.Changelog
	var err error

	switch source.Type {
	case "github":
		changelog, err = f.fetchFromGitHub(ctx, source.Owner, source.Repository, version)
	case "gitlab":
		changelog, err = f.fetchFromGitLab(ctx, source.Owner, source.Repository, version)
	default:
		return nil, errors.New(errors.CodeNotSupported, "unsupported source type").
			WithDetail("type", source.Type)
	}

	if err != nil {
		return nil, err
	}

	// Cache the result
	if f.cacheRepo != nil && changelog != nil {
		expiresAt := time.Now().Add(24 * time.Hour)
		if cacheErr := f.cacheRepo.Set(ctx, image, version, changelog, expiresAt); cacheErr != nil {
			log.Debug("Failed to cache changelog", "error", cacheErr)
		}
	}

	return changelog, nil
}

// FetchLatestChangelog fetches the latest changelog for an image
func (f *ChangelogFetcher) FetchLatestChangelog(ctx context.Context, image string, labels map[string]string) (*models.Changelog, error) {
	source := DetectSource(labels)
	if source == nil {
		source = f.inferSourceFromImage(image)
	}

	if source == nil {
		return nil, errors.New(errors.CodeNotFound, "source repository not found")
	}

	switch source.Type {
	case "github":
		return f.fetchLatestFromGitHub(ctx, source.Owner, source.Repository)
	case "gitlab":
		return f.fetchLatestFromGitLab(ctx, source.Owner, source.Repository)
	default:
		return nil, errors.New(errors.CodeNotSupported, "unsupported source type")
	}
}

// ============================================================================
// GitHub
// ============================================================================

// fetchFromGitHub fetches changelog from GitHub releases
func (f *ChangelogFetcher) fetchFromGitHub(ctx context.Context, owner, repo, version string) (*models.Changelog, error) {
	// Normalize version tag
	tags := []string{version}
	if !strings.HasPrefix(version, "v") {
		tags = append(tags, "v"+version)
	} else {
		tags = append(tags, strings.TrimPrefix(version, "v"))
	}

	for _, tag := range tags {
		apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s", owner, repo, tag)

		release, err := f.fetchGitHubRelease(ctx, apiURL)
		if err == nil {
			return f.githubReleaseToChangelog(release), nil
		}
	}

	return nil, errors.New(errors.CodeNotFound, "release not found on GitHub")
}

// fetchLatestFromGitHub fetches the latest release from GitHub
func (f *ChangelogFetcher) fetchLatestFromGitHub(ctx context.Context, owner, repo string) (*models.Changelog, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)

	release, err := f.fetchGitHubRelease(ctx, apiURL)
	if err != nil {
		return nil, err
	}

	return f.githubReleaseToChangelog(release), nil
}

type githubRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	HTMLURL     string    `json:"html_url"`
	Prerelease  bool      `json:"prerelease"`
	Draft       bool      `json:"draft"`
	PublishedAt time.Time `json:"published_at"`
	Author      struct {
		Login string `json:"login"`
	} `json:"author"`
}

func (f *ChangelogFetcher) fetchGitHubRelease(ctx context.Context, apiURL string) (*githubRelease, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to create request")
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	if f.githubToken != "" {
		req.Header.Set("Authorization", "Bearer "+f.githubToken)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to fetch release")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New(errors.CodeNotFound, "release not found")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.New(errors.CodeExternal, "failed to fetch release").
			WithDetail("status", resp.StatusCode).
			WithDetail("body", string(body))
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode response")
	}

	return &release, nil
}

func (f *ChangelogFetcher) githubReleaseToChangelog(release *githubRelease) *models.Changelog {
	return &models.Changelog{
		Version:      release.TagName,
		Title:        release.Name,
		Body:         release.Body,
		URL:          release.HTMLURL,
		PublishedAt:  &release.PublishedAt,
		IsPrerelease: release.Prerelease,
		IsDraft:      release.Draft,
		Author:       release.Author.Login,
	}
}

// ============================================================================
// GitLab
// ============================================================================

// fetchFromGitLab fetches changelog from GitLab releases
func (f *ChangelogFetcher) fetchFromGitLab(ctx context.Context, namespace, project, version string) (*models.Changelog, error) {
	projectPath := url.PathEscape(namespace + "/" + project)

	// Normalize version tag
	tags := []string{version}
	if !strings.HasPrefix(version, "v") {
		tags = append(tags, "v"+version)
	} else {
		tags = append(tags, strings.TrimPrefix(version, "v"))
	}

	for _, tag := range tags {
		apiURL := fmt.Sprintf(
			"https://gitlab.com/api/v4/projects/%s/releases/%s",
			projectPath,
			url.PathEscape(tag),
		)

		release, err := f.fetchGitLabRelease(ctx, apiURL)
		if err == nil {
			return f.gitlabReleaseToChangelog(release), nil
		}
	}

	return nil, errors.New(errors.CodeNotFound, "release not found on GitLab")
}

// fetchLatestFromGitLab fetches the latest release from GitLab
func (f *ChangelogFetcher) fetchLatestFromGitLab(ctx context.Context, namespace, project string) (*models.Changelog, error) {
	projectPath := url.PathEscape(namespace + "/" + project)
	apiURL := fmt.Sprintf(
		"https://gitlab.com/api/v4/projects/%s/releases?per_page=1",
		projectPath,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to create request")
	}

	if f.gitlabToken != "" {
		req.Header.Set("PRIVATE-TOKEN", f.gitlabToken)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to fetch releases")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(errors.CodeExternal, "failed to fetch releases").
			WithDetail("status", resp.StatusCode)
	}

	var releases []gitlabRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode response")
	}

	if len(releases) == 0 {
		return nil, errors.New(errors.CodeNotFound, "no releases found")
	}

	return f.gitlabReleaseToChangelog(&releases[0]), nil
}

type gitlabRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	ReleasedAt  time.Time `json:"released_at"`
	Links       struct {
		Self string `json:"self"`
	} `json:"_links"`
	Author struct {
		Username string `json:"username"`
	} `json:"author"`
}

func (f *ChangelogFetcher) fetchGitLabRelease(ctx context.Context, apiURL string) (*gitlabRelease, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to create request")
	}

	if f.gitlabToken != "" {
		req.Header.Set("PRIVATE-TOKEN", f.gitlabToken)
	}

	resp, err := f.httpClient.Do(req)
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

	var release gitlabRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decode response")
	}

	return &release, nil
}

func (f *ChangelogFetcher) gitlabReleaseToChangelog(release *gitlabRelease) *models.Changelog {
	return &models.Changelog{
		Version:      release.TagName,
		Title:        release.Name,
		Body:         release.Description,
		URL:          release.Links.Self,
		PublishedAt:  &release.ReleasedAt,
		IsPrerelease: false, // GitLab doesn't have this concept
		IsDraft:      false,
		Author:       release.Author.Username,
	}
}

// ============================================================================
// Source Inference
// ============================================================================

// inferSourceFromImage tries to infer the source repository from the image name
func (f *ChangelogFetcher) inferSourceFromImage(image string) *SourceInfo {
	// Parse image reference
	ref, err := ParseImageRef(image)
	if err != nil {
		return nil
	}

	// GHCR images often map to GitHub repos
	if ref.Registry == "ghcr.io" {
		return &SourceInfo{
			Type:       "github",
			URL:        fmt.Sprintf("https://github.com/%s/%s", ref.Namespace, ref.Repository),
			Owner:      ref.Namespace,
			Repository: ref.Repository,
		}
	}

	// Docker Hub official images
	if ref.Registry == "docker.io" && ref.Namespace == "library" {
		// Official images usually have repos like docker-library/nginx
		return &SourceInfo{
			Type:       "github",
			URL:        fmt.Sprintf("https://github.com/docker-library/%s", ref.Repository),
			Owner:      "docker-library",
			Repository: ref.Repository,
		}
	}

	// Docker Hub user images - try namespace/repo on GitHub
	if ref.Registry == "docker.io" {
		return &SourceInfo{
			Type:       "github",
			URL:        fmt.Sprintf("https://github.com/%s/%s", ref.Namespace, ref.Repository),
			Owner:      ref.Namespace,
			Repository: ref.Repository,
		}
	}

	return nil
}

// ============================================================================
// Changelog Parsing
// ============================================================================

var (
	// Regex patterns for parsing CHANGELOG.md
	headerRegex     = regexp.MustCompile(`^##\s*\[?v?(\d+\.\d+\.\d+[^\]]*)\]?`)
	changeTypeRegex = regexp.MustCompile(`^###\s*(.+)$`)
	bulletRegex     = regexp.MustCompile(`^\s*[-*]\s+(.+)$`)
)

// ChangelogEntry represents a parsed changelog entry
type ChangelogEntry struct {
	Version string
	Date    string
	Changes map[string][]string // Type -> Changes
}

// ParseChangelogMD parses a CHANGELOG.md file
func ParseChangelogMD(content string) []ChangelogEntry {
	entries := make([]ChangelogEntry, 0)
	var currentEntry *ChangelogEntry
	currentType := "Changed"

	lines := strings.Split(content, "\n")

	for _, line := range lines {
		// Check for version header
		if matches := headerRegex.FindStringSubmatch(line); len(matches) > 1 {
			if currentEntry != nil {
				entries = append(entries, *currentEntry)
			}
			currentEntry = &ChangelogEntry{
				Version: matches[1],
				Changes: make(map[string][]string),
			}
			currentType = "Changed"
			continue
		}

		if currentEntry == nil {
			continue
		}

		// Check for change type header
		if matches := changeTypeRegex.FindStringSubmatch(line); len(matches) > 1 {
			currentType = matches[1]
			continue
		}

		// Check for bullet point
		if matches := bulletRegex.FindStringSubmatch(line); len(matches) > 1 {
			if currentEntry.Changes[currentType] == nil {
				currentEntry.Changes[currentType] = make([]string, 0)
			}
			currentEntry.Changes[currentType] = append(currentEntry.Changes[currentType], matches[1])
		}
	}

	// Don't forget the last entry
	if currentEntry != nil {
		entries = append(entries, *currentEntry)
	}

	return entries
}

// FindChangelogEntry finds a specific version in parsed changelog
func FindChangelogEntry(entries []ChangelogEntry, version string) *ChangelogEntry {
	normalizedVersion := strings.TrimPrefix(version, "v")

	for _, entry := range entries {
		entryVersion := strings.TrimPrefix(entry.Version, "v")
		if entryVersion == normalizedVersion {
			return &entry
		}
	}

	return nil
}

// FormatChangelogEntry formats a changelog entry as markdown
func FormatChangelogEntry(entry *ChangelogEntry) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("## %s\n\n", entry.Version))

	// Order: Added, Changed, Deprecated, Removed, Fixed, Security
	order := []string{"Added", "Changed", "Deprecated", "Removed", "Fixed", "Security"}

	for _, changeType := range order {
		changes, ok := entry.Changes[changeType]
		if !ok || len(changes) == 0 {
			continue
		}

		sb.WriteString(fmt.Sprintf("### %s\n", changeType))
		for _, change := range changes {
			sb.WriteString(fmt.Sprintf("- %s\n", change))
		}
		sb.WriteString("\n")
	}

	// Any other types not in the standard order
	for changeType, changes := range entry.Changes {
		found := false
		for _, t := range order {
			if t == changeType {
				found = true
				break
			}
		}
		if found || len(changes) == 0 {
			continue
		}

		sb.WriteString(fmt.Sprintf("### %s\n", changeType))
		for _, change := range changes {
			sb.WriteString(fmt.Sprintf("- %s\n", change))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
