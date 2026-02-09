// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// UserSnippet represents a user-owned code snippet or file stored in the editor.
type UserSnippet struct {
	ID          uuid.UUID      `json:"id" db:"id"`
	UserID      uuid.UUID      `json:"user_id" db:"user_id"`
	Name        string         `json:"name" db:"name"`
	Path        string         `json:"path" db:"path"` // Virtual folder path
	Language    string         `json:"language" db:"language"`
	Content     string         `json:"content" db:"content"`
	Description *string        `json:"description,omitempty" db:"description"`
	Tags        pq.StringArray `json:"tags,omitempty" db:"tags"`
	IsPublic    bool           `json:"is_public" db:"is_public"`
	CreatedAt   time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at" db:"updated_at"`
}

// FullPath returns the complete virtual path including filename.
func (s *UserSnippet) FullPath() string {
	if s.Path == "" {
		return s.Name
	}
	return s.Path + s.Name
}

// UserSnippetListItem is a lighter version for list views (without full content).
type UserSnippetListItem struct {
	ID          uuid.UUID      `json:"id" db:"id"`
	Name        string         `json:"name" db:"name"`
	Path        string         `json:"path" db:"path"`
	Language    string         `json:"language" db:"language"`
	Description *string        `json:"description,omitempty" db:"description"`
	Tags        pq.StringArray `json:"tags,omitempty" db:"tags"`
	ContentSize int            `json:"content_size"` // Computed field
	UpdatedAt   time.Time      `json:"updated_at" db:"updated_at"`
}

// CreateSnippetInput holds input for creating a snippet.
type CreateSnippetInput struct {
	Name        string   `json:"name" validate:"required,max=255"`
	Path        string   `json:"path" validate:"max=1024"`
	Language    string   `json:"language" validate:"max=50"`
	Content     string   `json:"content"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// UpdateSnippetInput holds input for updating a snippet.
type UpdateSnippetInput struct {
	Name        *string  `json:"name,omitempty" validate:"omitempty,max=255"`
	Path        *string  `json:"path,omitempty" validate:"omitempty,max=1024"`
	Language    *string  `json:"language,omitempty" validate:"omitempty,max=50"`
	Content     *string  `json:"content,omitempty"`
	Description *string  `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// SnippetListOptions holds options for listing snippets.
type SnippetListOptions struct {
	Path     string // Filter by virtual path prefix
	Language string // Filter by language
	Search   string // Full text search
	Limit    int
	Offset   int
}
