// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package update

import (
	"context"
	"sync"
	"time"

	"github.com/fr4nsys/usulnet/internal/models"
)

// MemoryChangelogCache implements ChangelogCacheRepository with in-memory storage.
type MemoryChangelogCache struct {
	cache map[string]*changelogCacheEntry
	mu    sync.RWMutex
}

type changelogCacheEntry struct {
	changelog *models.Changelog
	expiresAt time.Time
}

// NewMemoryChangelogCache creates a new in-memory changelog cache.
func NewMemoryChangelogCache() *MemoryChangelogCache {
	c := &MemoryChangelogCache{
		cache: make(map[string]*changelogCacheEntry),
	}
	go c.cleanup()
	return c
}

func (c *MemoryChangelogCache) cacheKey(image, version string) string {
	return image + ":" + version
}

func (c *MemoryChangelogCache) Get(ctx context.Context, image, version string) (*models.Changelog, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := c.cacheKey(image, version)
	entry, ok := c.cache[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, nil
	}
	return entry.changelog, nil
}

func (c *MemoryChangelogCache) Set(ctx context.Context, image, version string, changelog *models.Changelog, expiresAt time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[c.cacheKey(image, version)] = &changelogCacheEntry{
		changelog: changelog,
		expiresAt: expiresAt,
	}
	return nil
}

func (c *MemoryChangelogCache) cleanup() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for k, v := range c.cache {
			if now.After(v.expiresAt) {
				delete(c.cache, k)
			}
		}
		c.mu.Unlock()
	}
}
