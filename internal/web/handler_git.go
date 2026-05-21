// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	giteasvc "github.com/fr4nsys/usulnet/internal/integrations/gitea"
	"github.com/fr4nsys/usulnet/internal/models"
	gitsvc "github.com/fr4nsys/usulnet/internal/services/git"
)

// ============================================================================
// List Page (unified view for all providers)
// ============================================================================

// GitListTempl renders the unified repositories page
func (h *Handler) GitListTempl(w http.ResponseWriter, r *http.Request) {
	// Reuse the existing GiteaTempl which already shows all connections
	h.GiteaTempl(w, r)
}

// ============================================================================
// Connection Management
// ============================================================================

// gitCreateConnectionForm captures the inputs of the Git connection
// creation form. provider_type drives a per-provider URL default
// that is filled in after binding.
type gitCreateConnectionForm struct {
	ProviderType  string `form:"provider_type" validate:"required,oneof=github gitlab gitea"`
	Name          string `form:"name" validate:"required"`
	URL           string `form:"url"`
	APIToken      string `form:"api_token" validate:"required"`
	WebhookSecret string `form:"webhook_secret"`
}

// GitCreateConnection creates a new Git connection (any provider)
func (h *Handler) GitCreateConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var form gitCreateConnectionForm
	if msg := BindForm(r, &form); msg != "" {
		h.setFlash(w, r, "error", msg)
		http.Redirect(w, r, "/integrations/git", http.StatusSeeOther)
		return
	}

	providerType := form.ProviderType
	name := form.Name
	url := form.URL
	apiToken := form.APIToken
	webhookSecret := form.WebhookSecret

	// Per-provider URL defaults. Gitea has no canonical URL so it
	// remains an explicit field; the others get a sensible default.
	switch providerType {
	case "github":
		if url == "" {
			url = "https://api.github.com"
		}
	case "gitlab":
		if url == "" {
			url = "https://gitlab.com"
		}
	case "gitea":
		if url == "" {
			h.setFlash(w, r, "error", "Server URL is required for Gitea")
			http.Redirect(w, r, "/integrations/git", http.StatusSeeOther)
			return
		}
	}

	// Normalize URL
	url = strings.TrimSuffix(url, "/")

	// Get current host
	hostID := h.getDefaultHostID(r)
	if hostID == uuid.Nil {
		h.setFlash(w, r, "error", "No host selected")
		http.Redirect(w, r, "/integrations/git", http.StatusSeeOther)
		return
	}

	// Use unified Git service if available
	if gitSvc := h.services.Git(); gitSvc != nil {
		userID := h.getUserID(r)
		input := &gitsvc.CreateConnectionInput{
			HostID:        hostID,
			ProviderType:  models.GitProviderType(providerType),
			Name:          name,
			URL:           url,
			APIToken:      apiToken,
			WebhookSecret: webhookSecret,
		}
		if userID != nil {
			input.CreatedBy = *userID
		}

		conn, err := gitSvc.CreateConnection(ctx, input)
		if err != nil {
			h.setFlash(w, r, "error", fmt.Sprintf("Failed to create connection: %v", err))
			http.Redirect(w, r, "/integrations/git", http.StatusSeeOther)
			return
		}

		// Test and sync
		if _, err := gitSvc.TestConnection(ctx, conn.ID); err != nil {
			h.setFlash(w, r, "warning", fmt.Sprintf("Connection created but test failed: %v", err))
		} else {
			if _, err := gitSvc.SyncRepositories(ctx, conn.ID); err != nil {
				h.setFlash(w, r, "warning", fmt.Sprintf("Connection created but sync failed: %v", err))
			} else {
				h.setFlash(w, r, "success", "Connection created and synced successfully")
			}
		}

		http.Redirect(w, r, "/integrations/git", http.StatusSeeOther)
		return
	}

	// Fallback to legacy Gitea service
	giteaSvc := h.services.Gitea()
	if giteaSvc == nil {
		h.setFlash(w, r, "error", "No Git service configured")
		http.Redirect(w, r, "/integrations/git", http.StatusSeeOther)
		return
	}

	user := GetUserFromContext(r.Context())
	var createdBy uuid.UUID
	if user != nil {
		if parsed, err := uuid.Parse(user.ID); err == nil {
			createdBy = parsed
		}
	}

	giteaInput := &giteasvc.CreateConnectionInput{
		HostID:        hostID,
		Name:          name,
		URL:           url,
		APIToken:      apiToken,
		WebhookSecret: webhookSecret,
		CreatedBy:     createdBy,
	}

	conn, err := giteaSvc.CreateConnection(ctx, giteaInput)
	if err != nil {
		h.setFlash(w, r, "error", fmt.Sprintf("Failed to create connection: %v", err))
		http.Redirect(w, r, "/integrations/git", http.StatusSeeOther)
		return
	}

	// Best-effort test and sync
	if _, err := giteaSvc.TestConnection(ctx, conn.ID); err != nil {
		h.setFlash(w, r, "warning", fmt.Sprintf("Connection created but test failed: %v", err))
	} else if _, err := giteaSvc.SyncRepositories(ctx, conn.ID); err != nil {
		h.setFlash(w, r, "warning", fmt.Sprintf("Connection created but sync failed: %v", err))
	} else {
		h.setFlash(w, r, "success", "Connection created and synced successfully")
	}

	http.Redirect(w, r, "/integrations/git", http.StatusSeeOther)
}

// GitTestConnection tests a Git connection
func (h *Handler) GitTestConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	connID, err := uuid.Parse(idStr)
	if err != nil {
		h.setFlash(w, r, "error", "Invalid connection ID")
		http.Redirect(w, r, "/integrations/git", http.StatusSeeOther)
		return
	}

	// Use unified Git service if available
	if gitSvc := h.services.Git(); gitSvc != nil {
		result, err := gitSvc.TestConnection(ctx, connID)
		if err != nil {
			h.setFlash(w, r, "error", fmt.Sprintf("Connection test failed: %v", err))
		} else if !result.Success {
			h.setFlash(w, r, "error", fmt.Sprintf("Connection test failed: %s", result.Error))
		} else {
			h.setFlash(w, r, "success", fmt.Sprintf("Connection test successful (version: %s)", result.Version))
		}
		http.Redirect(w, r, "/integrations/git", http.StatusSeeOther)
		return
	}

	// Fallback to Gitea service
	if giteaSvc := h.services.Gitea(); giteaSvc != nil {
		if _, err := giteaSvc.TestConnection(ctx, connID); err != nil {
			h.setFlash(w, r, "error", fmt.Sprintf("Connection test failed: %v", err))
		} else {
			h.setFlash(w, r, "success", "Connection test successful")
		}
	} else {
		h.setFlash(w, r, "error", "No Git service configured")
	}

	http.Redirect(w, r, "/integrations/git", http.StatusSeeOther)
}

// GitSyncRepos syncs repositories for a connection
func (h *Handler) GitSyncRepos(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	connID, err := uuid.Parse(idStr)
	if err != nil {
		h.setFlash(w, r, "error", "Invalid connection ID")
		http.Redirect(w, r, "/integrations/git", http.StatusSeeOther)
		return
	}

	// Use unified Git service if available
	if gitSvc := h.services.Git(); gitSvc != nil {
		count, err := gitSvc.SyncRepositories(ctx, connID)
		if err != nil {
			h.setFlash(w, r, "error", fmt.Sprintf("Sync failed: %v", err))
		} else {
			h.setFlash(w, r, "success", fmt.Sprintf("Synced %d repositories", count))
		}
		http.Redirect(w, r, "/integrations/git", http.StatusSeeOther)
		return
	}

	// Fallback to Gitea service
	if giteaSvc := h.services.Gitea(); giteaSvc != nil {
		count, err := giteaSvc.SyncRepositories(ctx, connID)
		if err != nil {
			h.setFlash(w, r, "error", fmt.Sprintf("Sync failed: %v", err))
		} else {
			h.setFlash(w, r, "success", fmt.Sprintf("Synced %d repositories", count))
		}
	} else {
		h.setFlash(w, r, "error", "No Git service configured")
	}

	http.Redirect(w, r, "/integrations/git", http.StatusSeeOther)
}

// GitDeleteConnection deletes a Git connection
func (h *Handler) GitDeleteConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	connID, err := uuid.Parse(idStr)
	if err != nil {
		h.setFlash(w, r, "error", "Invalid connection ID")
		http.Redirect(w, r, "/integrations/git", http.StatusSeeOther)
		return
	}

	// Use unified Git service if available
	if gitSvc := h.services.Git(); gitSvc != nil {
		if err := gitSvc.DeleteConnection(ctx, connID); err != nil {
			h.setFlash(w, r, "error", fmt.Sprintf("Failed to delete: %v", err))
		} else {
			h.setFlash(w, r, "success", "Connection deleted")
		}
		http.Redirect(w, r, "/integrations/git", http.StatusSeeOther)
		return
	}

	// Fallback to Gitea service
	if giteaSvc := h.services.Gitea(); giteaSvc != nil {
		if err := giteaSvc.DeleteConnection(ctx, connID); err != nil {
			h.setFlash(w, r, "error", fmt.Sprintf("Failed to delete: %v", err))
		} else {
			h.setFlash(w, r, "success", "Connection deleted")
		}
	} else {
		h.setFlash(w, r, "error", "No Git service configured")
	}

	http.Redirect(w, r, "/integrations/git", http.StatusSeeOther)
}

// GitTemplates returns gitignore and license templates
func (h *Handler) GitTemplates(w http.ResponseWriter, r *http.Request) {
	// Delegate to existing Gitea handler
	h.GiteaTemplates(w, r)
}

// ============================================================================
// Repository Management
// ============================================================================

// GitCreateRepo creates a new repository
func (h *Handler) GitCreateRepo(w http.ResponseWriter, r *http.Request) {
	// Delegate to Gitea for now
	h.GiteaCreateRepo(w, r)
}

// GitRepoDetail shows repository details
func (h *Handler) GitRepoDetail(w http.ResponseWriter, r *http.Request) {
	h.GiteaRepoDetail(w, r)
}

// GitRepoFiles lists repository files
func (h *Handler) GitRepoFiles(w http.ResponseWriter, r *http.Request) {
	h.GiteaRepoFiles(w, r)
}

// GitFileContent gets file content
func (h *Handler) GitFileContent(w http.ResponseWriter, r *http.Request) {
	h.GiteaFileContent(w, r)
}

// GitFileSave saves file content
func (h *Handler) GitFileSave(w http.ResponseWriter, r *http.Request) {
	h.GiteaFileSave(w, r)
}

// GitEditRepo edits repository settings
func (h *Handler) GitEditRepo(w http.ResponseWriter, r *http.Request) {
	h.GiteaEditRepo(w, r)
}

// GitDeleteRepo deletes a repository
func (h *Handler) GitDeleteRepo(w http.ResponseWriter, r *http.Request) {
	h.GiteaDeleteRepo(w, r)
}

// ============================================================================
// Branches
// ============================================================================

// GitListBranches lists branches
func (h *Handler) GitListBranches(w http.ResponseWriter, r *http.Request) {
	h.GiteaListBranches(w, r)
}

// GitCreateBranch creates a new branch
func (h *Handler) GitCreateBranch(w http.ResponseWriter, r *http.Request) {
	h.GiteaCreateBranch(w, r)
}

// GitDeleteBranch deletes a branch
func (h *Handler) GitDeleteBranch(w http.ResponseWriter, r *http.Request) {
	h.GiteaDeleteBranch(w, r)
}

// ============================================================================
// Tags
// ============================================================================

// GitListTags lists tags
func (h *Handler) GitListTags(w http.ResponseWriter, r *http.Request) {
	h.GiteaListTags(w, r)
}

// ============================================================================
// Commits
// ============================================================================

// GitListCommits lists commits
func (h *Handler) GitListCommits(w http.ResponseWriter, r *http.Request) {
	h.GiteaListCommitsFiltered(w, r)
}

// GitGetCommit gets a commit
func (h *Handler) GitGetCommit(w http.ResponseWriter, r *http.Request) {
	h.GiteaGetCommit(w, r)
}

// ============================================================================
// Pull Requests
// ============================================================================

// GitListPRs lists pull requests
func (h *Handler) GitListPRs(w http.ResponseWriter, r *http.Request) {
	h.GiteaListPRs(w, r)
}

// GitCreatePR creates a pull request
func (h *Handler) GitCreatePR(w http.ResponseWriter, r *http.Request) {
	h.GiteaCreatePR(w, r)
}

// GitGetPR gets a pull request
func (h *Handler) GitGetPR(w http.ResponseWriter, r *http.Request) {
	h.GiteaGetPR(w, r)
}

// GitMergePR merges a pull request
func (h *Handler) GitMergePR(w http.ResponseWriter, r *http.Request) {
	h.GiteaMergePR(w, r)
}

// ============================================================================
// Issues
// ============================================================================

// GitListIssues lists issues
func (h *Handler) GitListIssues(w http.ResponseWriter, r *http.Request) {
	h.GiteaListIssues(w, r)
}

// GitCreateIssue creates an issue
func (h *Handler) GitCreateIssue(w http.ResponseWriter, r *http.Request) {
	h.GiteaCreateIssue(w, r)
}

// GitGetIssue gets an issue
func (h *Handler) GitGetIssue(w http.ResponseWriter, r *http.Request) {
	h.GiteaGetIssue(w, r)
}

// ============================================================================
// Releases
// ============================================================================

// GitListReleases lists releases
func (h *Handler) GitListReleases(w http.ResponseWriter, r *http.Request) {
	h.GiteaListReleases(w, r)
}

// GitGetLatestRelease gets the latest release
func (h *Handler) GitGetLatestRelease(w http.ResponseWriter, r *http.Request) {
	h.GiteaGetLatestRelease(w, r)
}

// ============================================================================
