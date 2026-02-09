// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package update

import (
	"sort"
	"fmt"
	"context"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// RegistryClient interface for interacting with container registries
type RegistryClient interface {
	// GetLatestVersion gets the latest version info for an image
	GetLatestVersion(ctx context.Context, ref *models.ImageRef) (*models.ImageVersion, error)
	
	// GetDigest gets the digest for a specific tag
	GetDigest(ctx context.Context, ref *models.ImageRef) (string, error)
	
	// ListTags lists available tags for an image
	ListTags(ctx context.Context, ref *models.ImageRef, limit int) ([]string, error)
	
	// SupportsRegistry returns true if this client supports the given registry
	SupportsRegistry(registry string) bool
}

// VersionCache interface for caching version information
type VersionCache interface {
	Get(ctx context.Context, image, tag string) (*models.ImageVersion, bool)
	Set(ctx context.Context, image, tag string, version *models.ImageVersion, ttl time.Duration)
	Delete(ctx context.Context, image, tag string)
}

// CheckerConfig holds configuration for the version checker
type CheckerConfig struct {
	// CacheTTL is how long to cache version information
	CacheTTL time.Duration
	
	// CheckTimeout is the timeout for checking a single image
	CheckTimeout time.Duration
	
	// MaxConcurrent is the maximum number of concurrent checks
	MaxConcurrent int
	
	// IncludePrerelease includes prerelease versions in checks
	IncludePrerelease bool
	
	// SkipLocalImages skips images that appear to be locally built
	SkipLocalImages bool
}

// DefaultCheckerConfig returns the default checker configuration
func DefaultCheckerConfig() *CheckerConfig {
	return &CheckerConfig{
		CacheTTL:          6 * time.Hour,
		CheckTimeout:      30 * time.Second,
		MaxConcurrent:     5,
		IncludePrerelease: false,
		SkipLocalImages:   true,
	}
}

// Checker checks for available updates
type Checker struct {
	config    *CheckerConfig
	clients   []RegistryClient
	cache     VersionCache
	logger    *logger.Logger
	
	// Concurrency control
	semaphore chan struct{}
}

// NewChecker creates a new version checker
func NewChecker(config *CheckerConfig, cache VersionCache, log *logger.Logger) *Checker {
	if config == nil {
		config = DefaultCheckerConfig()
	}
	
	maxConcurrent := config.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 5
	}
	
	return &Checker{
		config:    config,
		clients:   make([]RegistryClient, 0),
		cache:     cache,
		logger:    log.Named("checker"),
		semaphore: make(chan struct{}, maxConcurrent),
	}
}

// RegisterClient registers a registry client
func (c *Checker) RegisterClient(client RegistryClient) {
	c.clients = append(c.clients, client)
}

// CheckContainer checks if a container has an update available
func (c *Checker) CheckContainer(ctx context.Context, containerID, containerName, image string) (*models.AvailableUpdate, error) {
	log := c.logger.With("container_id", containerID, "image", image)
	
	// Parse image reference
	ref, err := ParseImageRef(image)
	if err != nil {
		log.Debug("Failed to parse image reference", "error", err)
		return nil, errors.Wrap(err, errors.CodeInvalidInput, "failed to parse image")
	}
	
	// Skip local images if configured
	if c.config.SkipLocalImages && isLocalImage(ref) {
		log.Debug("Skipping local image")
		return nil, nil
	}
	
	// Check cache first
	if c.cache != nil {
		if cached, ok := c.cache.Get(ctx, ref.FullName(), ref.Tag); ok {
			return c.buildAvailableUpdate(containerID, containerName, ref, cached), nil
		}
	}
	
	// Acquire semaphore
	select {
	case c.semaphore <- struct{}{}:
		defer func() { <-c.semaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	
	// Find appropriate client
	client := c.findClient(ref.Registry)
	if client == nil {
		log.Debug("No registry client available", "registry", ref.Registry)
		return nil, errors.New(errors.CodeNotSupported, "unsupported registry").
			WithDetail("registry", ref.Registry)
	}
	
	// Create timeout context
	checkCtx, cancel := context.WithTimeout(ctx, c.config.CheckTimeout)
	defer cancel()
	
	// Get latest version
	latest, err := client.GetLatestVersion(checkCtx, ref)
	if err != nil {
		log.Debug("Failed to get latest version", "error", err)
		return nil, errors.Wrap(err, errors.CodeExternal, "failed to check registry")
	}
	
	// Cache the result
	if c.cache != nil && latest != nil {
		c.cache.Set(ctx, ref.FullName(), ref.Tag, latest, c.config.CacheTTL)
	}
	
	return c.buildAvailableUpdate(containerID, containerName, ref, latest), nil
}

// CheckContainers checks multiple containers for updates
func (c *Checker) CheckContainers(ctx context.Context, containers []ContainerInfo) (*models.UpdateCheckResult, error) {
	result := &models.UpdateCheckResult{
		CheckedAt:       time.Now(),
		TotalContainers: len(containers),
		Updates:         make([]models.AvailableUpdate, 0),
		SkippedImages:   make([]string, 0),
	}
	
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	for _, container := range containers {
		wg.Add(1)
		go func(ct ContainerInfo) {
			defer wg.Done()
			
			update, err := c.CheckContainer(ctx, ct.ID, ct.Name, ct.Image)
			
			mu.Lock()
			defer mu.Unlock()
			
			if err != nil {
				result.Errors++
				result.SkippedImages = append(result.SkippedImages, ct.Image)
				return
			}
			
			result.CheckedCount++
			
			if update != nil && update.NeedsUpdate() {
				result.UpdatesAvailable++
				result.Updates = append(result.Updates, *update)
			}
		}(container)
	}
	
	wg.Wait()
	return result, nil
}

// ContainerInfo holds basic container information for checking
type ContainerInfo struct {
	ID     string
	Name   string
	Image  string
	Digest string // Current digest if known
}

// buildAvailableUpdate builds an AvailableUpdate from check results
func (c *Checker) buildAvailableUpdate(containerID, containerName string, ref *models.ImageRef, latest *models.ImageVersion) *models.AvailableUpdate {
	if latest == nil {
		return nil
	}
	
	return &models.AvailableUpdate{
		ContainerID:    containerID,
		ContainerName:  containerName,
		Image:          ref.FullNameWithTag(),
		CurrentVersion: ref.Tag,
		CurrentDigest:  ref.Digest,
		LatestVersion:  latest.Tag,
		LatestDigest:   latest.Digest,
		CheckedAt:      time.Now(),
	}
}

// findClient finds a registry client that supports the given registry
func (c *Checker) findClient(registry string) RegistryClient {
	for _, client := range c.clients {
		if client.SupportsRegistry(registry) {
			return client
		}
	}
	return nil
}

// isLocalImage checks if an image appears to be locally built
func isLocalImage(ref *models.ImageRef) bool {
	// No registry and no namespace usually means local
	if ref.Registry == "" && ref.Namespace == "" {
		return true
	}
	
	// localhost or local registry
	if strings.HasPrefix(ref.Registry, "localhost") || strings.HasPrefix(ref.Registry, "127.0.0.1") {
		return true
	}
	
	// SHA256 digest without tag often means local build
	if ref.Tag == "" && ref.Digest != "" && strings.HasPrefix(ref.Digest, "sha256:") {
		return true
	}
	
	return false
}

// ============================================================================
// Image Reference Parsing
// ============================================================================

// Common registries
const (
	RegistryDockerHub = "docker.io"
	RegistryGHCR      = "ghcr.io"
	RegistryGCR       = "gcr.io"
	RegistryQuay      = "quay.io"
	RegistryECR       = "amazonaws.com"
	RegistryACR       = "azurecr.io"
)

var (
	// Regex patterns for parsing image references
	digestRegex = regexp.MustCompile(`@(sha256:[a-fA-F0-9]{64})$`)
	tagRegex    = regexp.MustCompile(`:([^:@/]+)$`)
	
	// Semver-like pattern for detecting version tags
	semverRegex = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$`)
	
	// Pattern for prerelease tags
	prereleaseRegex = regexp.MustCompile(`(?i)(alpha|beta|rc|dev|preview|snapshot|nightly|canary)`)
)

// ParseImageRef parses a Docker image reference into its components
func ParseImageRef(image string) (*models.ImageRef, error) {
	if image == "" {
		return nil, errors.New(errors.CodeInvalidInput, "empty image reference")
	}
	
	ref := &models.ImageRef{}
	remaining := image
	
	// Extract digest if present
	if matches := digestRegex.FindStringSubmatch(remaining); len(matches) > 1 {
		ref.Digest = matches[1]
		remaining = strings.TrimSuffix(remaining, "@"+matches[1])
	}
	
	// Extract tag if present
	if matches := tagRegex.FindStringSubmatch(remaining); len(matches) > 1 {
		ref.Tag = matches[1]
		remaining = strings.TrimSuffix(remaining, ":"+matches[1])
	}
	
	// Default tag to "latest" if no tag or digest
	if ref.Tag == "" && ref.Digest == "" {
		ref.Tag = "latest"
	}
	
	// Parse registry/namespace/repository
	parts := strings.Split(remaining, "/")
	
	switch len(parts) {
	case 1:
		// Just repository name (e.g., "nginx")
		// Assumes Docker Hub library
		ref.Registry = RegistryDockerHub
		ref.Namespace = "library"
		ref.Repository = parts[0]
		
	case 2:
		// namespace/repository or registry/repository
		if isRegistry(parts[0]) {
			ref.Registry = normalizeRegistry(parts[0])
			ref.Repository = parts[1]
		} else {
			ref.Registry = RegistryDockerHub
			ref.Namespace = parts[0]
			ref.Repository = parts[1]
		}
		
	case 3:
		// registry/namespace/repository
		ref.Registry = normalizeRegistry(parts[0])
		ref.Namespace = parts[1]
		ref.Repository = parts[2]
		
	default:
		// registry/namespace/.../repository
		ref.Registry = normalizeRegistry(parts[0])
		ref.Namespace = strings.Join(parts[1:len(parts)-1], "/")
		ref.Repository = parts[len(parts)-1]
	}
	
	return ref, nil
}

// isRegistry checks if a string looks like a registry hostname
func isRegistry(s string) bool {
	// Contains a dot (domain) or port
	if strings.Contains(s, ".") || strings.Contains(s, ":") {
		return true
	}
	
	// Known registries without dots
	knownRegistries := []string{"localhost"}
	for _, r := range knownRegistries {
		if s == r {
			return true
		}
	}
	
	return false
}

// normalizeRegistry normalizes a registry hostname
func normalizeRegistry(registry string) string {
	// Normalize Docker Hub variants
	switch registry {
	case "docker.io", "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com":
		return RegistryDockerHub
	}
	return registry
}

// IsPrerelease checks if a tag appears to be a prerelease version
func IsPrerelease(tag string) bool {
	if prereleaseRegex.MatchString(tag) {
		return true
	}
	
	// Check semver prerelease suffix
	if matches := semverRegex.FindStringSubmatch(tag); len(matches) > 4 && matches[4] != "" {
		return true
	}
	
	return false
}

// IsSemver checks if a tag follows semantic versioning
func IsSemver(tag string) bool {
	return semverRegex.MatchString(tag)
}

// CompareSemver compares two semver strings
// Returns: -1 if a < b, 0 if a == b, 1 if a > b
func CompareSemver(a, b string) int {
	// Strip 'v' prefix
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")
	
	aParts := parseSemverParts(a)
	bParts := parseSemverParts(b)
	
	// Compare major.minor.patch
	for i := 0; i < 3; i++ {
		if aParts[i] < bParts[i] {
			return -1
		}
		if aParts[i] > bParts[i] {
			return 1
		}
	}
	
	// Equal base versions
	return 0
}

// parseSemverParts extracts major, minor, patch from semver
func parseSemverParts(version string) [3]int {
	var parts [3]int
	
	// Remove prerelease/build metadata
	if idx := strings.IndexAny(version, "-+"); idx != -1 {
		version = version[:idx]
	}
	
	segments := strings.Split(version, ".")
	for i := 0; i < len(segments) && i < 3; i++ {
		var num int
		fmt.Sscanf(segments[i], "%d", &num)
		parts[i] = num
	}
	
	return parts
}

// ExtractSourceRepo attempts to extract the source repository URL from image labels
func ExtractSourceRepo(labels map[string]string) string {
	// Try common label conventions
	keys := []string{
		"org.opencontainers.image.source",
		"org.label-schema.vcs-url",
		"maintainer.url",
		"source",
		"vcs-url",
	}
	
	for _, key := range keys {
		if url, ok := labels[key]; ok && url != "" {
			return url
		}
	}
	
	return ""
}

// ============================================================================
// In-Memory Cache Implementation
// ============================================================================

// MemoryVersionCache is a simple in-memory cache for version information
type MemoryVersionCache struct {
	cache map[string]*cacheEntry
	mu    sync.RWMutex
}

type cacheEntry struct {
	version   *models.ImageVersion
	expiresAt time.Time
}

// NewMemoryVersionCache creates a new in-memory version cache
func NewMemoryVersionCache() *MemoryVersionCache {
	c := &MemoryVersionCache{
		cache: make(map[string]*cacheEntry),
	}
	
	// Start cleanup goroutine
	go c.cleanup()
	
	return c
}

func (c *MemoryVersionCache) cacheKey(image, tag string) string {
	return image + ":" + tag
}

// Get retrieves a cached version
func (c *MemoryVersionCache) Get(ctx context.Context, image, tag string) (*models.ImageVersion, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	key := c.cacheKey(image, tag)
	entry, ok := c.cache[key]
	if !ok {
		return nil, false
	}
	
	if time.Now().After(entry.expiresAt) {
		return nil, false
	}
	
	return entry.version, true
}

// Set stores a version in the cache
func (c *MemoryVersionCache) Set(ctx context.Context, image, tag string, version *models.ImageVersion, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	key := c.cacheKey(image, tag)
	c.cache[key] = &cacheEntry{
		version:   version,
		expiresAt: time.Now().Add(ttl),
	}
}

// Delete removes a version from the cache
func (c *MemoryVersionCache) Delete(ctx context.Context, image, tag string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	key := c.cacheKey(image, tag)
	delete(c.cache, key)
}

// cleanup periodically removes expired entries
func (c *MemoryVersionCache) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.cache {
			if now.After(entry.expiresAt) {
				delete(c.cache, key)
			}
		}
		c.mu.Unlock()
	}
}

// ============================================================================
// Database-backed Cache Implementation
// ============================================================================

// DBVersionCache uses the database for caching version information
type DBVersionCache struct {
	repo   VersionCacheRepository
	logger *logger.Logger
}

// VersionCacheRepository interface for database operations
type VersionCacheRepository interface {
	GetVersion(ctx context.Context, image, tag string) (*models.ImageVersion, error)
	SetVersion(ctx context.Context, image, tag string, version *models.ImageVersion, expiresAt time.Time) error
	DeleteVersion(ctx context.Context, image, tag string) error
	DeleteExpired(ctx context.Context) (int64, error)
}

// NewDBVersionCache creates a database-backed version cache
func NewDBVersionCache(repo VersionCacheRepository, log *logger.Logger) *DBVersionCache {
	return &DBVersionCache{
		repo:   repo,
		logger: log.Named("version-cache"),
	}
}

// Get retrieves a cached version from the database
func (c *DBVersionCache) Get(ctx context.Context, image, tag string) (*models.ImageVersion, bool) {
	version, err := c.repo.GetVersion(ctx, image, tag)
	if err != nil {
		return nil, false
	}
	return version, version != nil
}

// Set stores a version in the database cache
func (c *DBVersionCache) Set(ctx context.Context, image, tag string, version *models.ImageVersion, ttl time.Duration) {
	expiresAt := time.Now().Add(ttl)
	if err := c.repo.SetVersion(ctx, image, tag, version, expiresAt); err != nil {
		c.logger.Debug("Failed to cache version", "image", image, "tag", tag, "error", err)
	}
}

// Delete removes a version from the database cache
func (c *DBVersionCache) Delete(ctx context.Context, image, tag string) {
	if err := c.repo.DeleteVersion(ctx, image, tag); err != nil {
		c.logger.Debug("Failed to delete cached version", "image", image, "tag", tag, "error", err)
	}
}

// Cleanup removes expired entries
func (c *DBVersionCache) Cleanup(ctx context.Context) (int64, error) {
	return c.repo.DeleteExpired(ctx)
}

// ============================================================================
// Update Check Helpers
// ============================================================================

// ShouldSkipImage determines if an image should be skipped during update checks
func ShouldSkipImage(image string, skipPatterns []string) bool {
	for _, pattern := range skipPatterns {
		if matched, _ := regexp.MatchString(pattern, image); matched {
			return true
		}
	}
	return false
}

// FilterUpdates filters available updates based on criteria
func FilterUpdates(updates []models.AvailableUpdate, includePrerelease bool) []models.AvailableUpdate {
	filtered := make([]models.AvailableUpdate, 0, len(updates))
	
	for _, update := range updates {
		// Skip prereleases if not included
		if !includePrerelease && update.IsPrerelease {
			continue
		}
		
		// Only include if actually needs update
		if update.NeedsUpdate() {
			filtered = append(filtered, update)
		}
	}
	
	return filtered
}

// GroupUpdatesByHost groups updates by host ID
func GroupUpdatesByHost(updates []models.AvailableUpdate, getHostID func(containerID string) uuid.UUID) map[uuid.UUID][]models.AvailableUpdate {
	grouped := make(map[uuid.UUID][]models.AvailableUpdate)
	
	for _, update := range updates {
		hostID := getHostID(update.ContainerID)
		grouped[hostID] = append(grouped[hostID], update)
	}
	
	return grouped
}

// sortTagsBySemver sorts tags with semver tags first (newest first)
func sortTagsBySemver(tags []string) []string {
	sorted := make([]string, len(tags))
	copy(sorted, tags)

	sort.Slice(sorted, func(i, j int) bool {
		// Both semver
		if IsSemver(sorted[i]) && IsSemver(sorted[j]) {
			return CompareSemver(sorted[i], sorted[j]) > 0
		}
		// Only first is semver
		if IsSemver(sorted[i]) {
			return true
		}
		// Only second is semver
		if IsSemver(sorted[j]) {
			return false
		}
		// Neither is semver - alphabetical
		return sorted[i] > sorted[j]
	})

	return sorted
}

// isNumeric checks if a string contains only digits
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
